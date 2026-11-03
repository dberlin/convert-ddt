/* Native, read-only bounded content sampling for the actual-pool validator. */
#include "validate_pool.h"

#include <sys/dmu.h>
#include <sys/dmu_objset.h>
#include <sys/dbuf.h>
#include <sys/dnode.h>
#include <sys/dsl_dataset.h>
#include <sys/dsl_dir.h>
#include <sys/dsl_pool.h>
#include <sys/sa.h>
#include <sys/zap.h>
#include <sys/zfs_znode.h>
#include <sys/zfs_sa.h>
#include <sys/zvol.h>

#include <jansson.h>
#include <openssl/evp.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <inttypes.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define VC_MAX_INVENTORY 262144U
#define VC_MAX_VIEWS 32768U
#define VC_QUEUE 128U
#define VC_DEFAULT_SAMPLES 25000U
#define VC_MAX_SAMPLES 50000U
#define VC_SAMPLE_BYTES (1024U * 1024U)
#define VC_MAX_MANIFEST (256U * 1024U * 1024U)
#define VC_MAX_WORKERS 256U

/* Every integer identity is a decimal string: no JSON double precision loss. */
typedef struct vc_identity {
    uint64_t object, guid, head, creation;
    unsigned type;
    boolean_t snapshot, selected, locked;
    char name[ZFS_MAX_DATASET_NAME_LEN];
} vc_identity_t;

typedef struct vc_sample {
    uint64_t object, size, generation, offset, length;
    blkptr_t bp;
    char sha256[65];
} vc_sample_t;

typedef struct vc_view {
    size_t identity;
    unsigned count, capacity, directory_entries;
    boolean_t exhausted, locked;
    vc_sample_t *samples;
} vc_view_t;

typedef struct vc_state {
    vp_pool_t pool;
    pthread_mutex_t inventory_lock, queue_lock;
    pthread_cond_t queue_read, queue_write;
    vc_identity_t *inventory;
    size_t inventory_count, inventory_capacity;
    vc_view_t *views;
    size_t view_count;
    size_t queue[VC_QUEUE], queue_start, queue_count;
    uint64_t *namespace_queue;
    size_t namespace_start, namespace_count, namespace_pending;
    boolean_t queue_closed, expect;
    atomic_int error;
    atomic_bool finished;
    atomic_uint_fast64_t entries, tasks, bytes, directories, task_total;
    atomic_uint_fast64_t heads, expected_heads;
    atomic_uint_fast64_t samples_reserved, samples_completed;
    atomic_uint_fast64_t objects_examined, bps_examined;
    uint64_t sample_target;
    struct timespec started;
} vc_state_t;

static volatile sig_atomic_t interrupted;
static const char vc_tag;

static void
vc_signal(int sig)
{
    interrupted = sig;
}

static void
vc_fail(vc_state_t *s, int error, const char *operation, uint64_t object)
{
    int zero = 0;
    if (error == 0)
        error = EIO;
    if (atomic_compare_exchange_strong(&s->error, &zero, error)) {
        /* Diagnostics remain JSON-lines, even on native read failures. */
        fprintf(stderr, "{\"phase\":\"error\",\"operation\":\"%s\","
            "\"object\":\"%" PRIu64 "\",\"errno\":%d}\n",
            operation, object, error);
    }
    pthread_mutex_lock(&s->queue_lock);
    pthread_cond_broadcast(&s->queue_read);
    pthread_cond_broadcast(&s->queue_write);
    pthread_mutex_unlock(&s->queue_lock);
}

static boolean_t
vc_stopped(vc_state_t *s)
{
    return (interrupted != 0 || atomic_load(&s->error) != 0);
}

static double
vc_elapsed(vc_state_t *s)
{
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return ((double)(now.tv_sec - s->started.tv_sec) +
        (double)(now.tv_nsec - s->started.tv_nsec) / 1e9);
}

static void *
vc_progress(void *arg)
{
    vc_state_t *s = arg;
    uint64_t previous = 0, previous_samples = 0;
    double last = 0;
    for (;;) {
        if (!atomic_load(&s->finished)) {
            struct timespec delay = { .tv_sec = 1 };
            nanosleep(&delay, NULL);
        }
        /* Snapshot completion before the counters so even a sub-second run
         * publishes its terminal totals, without racing the final heartbeat. */
        boolean_t finished = atomic_load(&s->finished);
        if (interrupted)
            vc_fail(s, ECANCELED, "signal", 0);
        double elapsed = vc_elapsed(s);
        uint64_t bytes = atomic_load(&s->bytes);
        uint64_t samples = atomic_load(&s->samples_completed);
        double interval = elapsed - last;
        double rate = interval > 0 ?
            (double)(samples - previous_samples) / interval : 0;
        double average = elapsed > 0 ? (double)samples / elapsed : 0;
        fprintf(stderr, "{\"phase\":\"content\",\"entries\":%" PRIuFAST64
            ",\"tasks_completed\":%" PRIuFAST64
            ",\"tasks_total\":%" PRIuFAST64
            ",\"samples_completed\":%" PRIu64
            ",\"sample_target\":%" PRIu64
            ",\"objects_examined\":%" PRIuFAST64
            ",\"bps_examined\":%" PRIuFAST64
            ",\"bytes\":%" PRIu64 ",\"directory_entries\":%" PRIuFAST64
            ",\"elapsed_seconds\":%.3f,\"bytes_per_second\":%.3f,"
            "\"samples_per_second\":%.3f,\"eta_seconds\":",
            atomic_load(&s->entries), atomic_load(&s->tasks),
            atomic_load(&s->task_total), samples, s->sample_target,
            atomic_load(&s->objects_examined), atomic_load(&s->bps_examined),
            bytes, atomic_load(&s->directories), elapsed,
            interval > 0 ? (double)(bytes - previous) / interval : 0, rate);
        if (average > 0)
            fprintf(stderr, "%.3f", (double)(s->sample_target - samples) /
                average);
        else
            fputs("null", stderr);
        fputs("}\n", stderr);
        fflush(stderr);
        previous = bytes;
        previous_samples = samples;
        last = elapsed;
        if (finished)
            break;
    }
    return (NULL);
}

static int
vc_add_identity(vc_state_t *s, dsl_dataset_t *ds, uint64_t head,
    unsigned type, boolean_t locked, boolean_t selected, size_t *index)
{
    vc_identity_t value = { .object = ds->ds_object,
        .guid = dsl_dataset_phys(ds)->ds_guid, .head = head,
        .creation = dsl_dataset_phys(ds)->ds_creation_txg,
        .type = type, .snapshot = dsl_dataset_is_snapshot(ds),
        .selected = selected, .locked = locked };
    dsl_dataset_name(ds, value.name);
    pthread_mutex_lock(&s->inventory_lock);
    if (s->inventory_count == VC_MAX_INVENTORY) {
        pthread_mutex_unlock(&s->inventory_lock);
        return (E2BIG);
    }
    if (s->inventory_count == s->inventory_capacity) {
        size_t capacity = s->inventory_capacity == 0 ? 1024 :
            s->inventory_capacity * 2;
        vc_identity_t *items = realloc(s->inventory,
            capacity * sizeof (*items));
        if (items == NULL) {
            pthread_mutex_unlock(&s->inventory_lock);
            return (ENOMEM);
        }
        s->inventory = items;
        s->inventory_capacity = capacity;
    }
    *index = s->inventory_count;
    s->inventory[s->inventory_count++] = value;
    pthread_mutex_unlock(&s->inventory_lock);
    atomic_fetch_add(&s->entries, 1);
    return (0);
}

/* Namespace tasks never wait for queue space while producing children. A fixed
 * capacity bounds metadata fan-out; exceeding the declared view bound fails. */
static int
vc_enqueue_directory(vc_state_t *s, uint64_t object)
{
    int error = 0;
    pthread_mutex_lock(&s->queue_lock);
    if (s->namespace_count == VC_MAX_VIEWS)
        error = E2BIG;
    else if (vc_stopped(s))
        error = ECANCELED;
    else {
        size_t slot = (s->namespace_start + s->namespace_count) % VC_MAX_VIEWS;
        s->namespace_queue[slot] = object;
        s->namespace_count++;
        s->namespace_pending++;
        pthread_cond_signal(&s->queue_read);
    }
    pthread_mutex_unlock(&s->queue_lock);
    return (error);
}

/* Check native ZAP counts and visit every non-internal child, without treating
 * cursor I/O errors as end-of-directory. Hidden $MOS/$ORIGIN are not ZPL views. */
static int
vc_count_children(vc_state_t *s, dsl_pool_t *dp, dsl_dataset_t *head)
{
    uint64_t map = dsl_dir_phys(head->ds_dir)->dd_child_dir_zapobj;
    uint64_t expected, seen = 0, visible = 0;
    int error = zap_count(dp->dp_meta_objset, map, &expected);
    if (error != 0)
        return (error);
    zap_cursor_t cursor;
    zap_attribute_t *attribute = zap_attribute_alloc();
    zap_cursor_init(&cursor, dp->dp_meta_objset, map);
    while ((error = zap_cursor_retrieve(&cursor, attribute)) == 0) {
        if (vc_stopped(s)) {
            error = ECANCELED;
            break;
        }
        if (attribute->za_integer_length != sizeof (uint64_t) ||
            attribute->za_num_integers != 1) {
            error = EINVAL;
            break;
        }
        seen++;
        if (attribute->za_name[0] != '$') {
            error = vc_enqueue_directory(s, attribute->za_first_integer);
            if (error != 0)
                break;
            visible++;
        }
        zap_cursor_advance(&cursor);
    }
    zap_cursor_fini(&cursor);
    zap_attribute_free(attribute);
    if (error != ENOENT)
        return (error);
    if (seen != expected)
        return (EIO);
    atomic_fetch_add(&s->expected_heads, visible);
    atomic_fetch_add(&s->heads, 1);
    return (0);
}

/* Called by the bounded namespace workers with pool config held. */
static int
vc_inventory_head(dsl_pool_t *dp, dsl_dataset_t *head, void *arg)
{
    vc_state_t *s = arg;
    if (vc_stopped(s))
        return (ECANCELED);
    objset_t *os;
    int error = dmu_objset_from_ds(head, &os);
    if (error != 0)
        return (error);
    unsigned type = dmu_objset_type(os);
    if (type != DMU_OST_ZFS && type != DMU_OST_ZVOL)
        return (ENOTSUP);
    error = vc_count_children(s, dp, head);
    if (error != 0)
        return (error);
    boolean_t locked = os->os_encrypted;
    size_t index;
    error = vc_add_identity(s, head, head->ds_object, type, locked,
        B_TRUE, &index);
    if (error != 0)
        return (error);

    uint64_t snapmap = dsl_dataset_phys(head)->ds_snapnames_zapobj;
    if (snapmap == 0)
        return (0);
    uint64_t native_count, seen = 0, chosen_object = UINT64_MAX;
    size_t chosen_index = SIZE_MAX;
    error = zap_count(dp->dp_meta_objset, snapmap, &native_count);
    if (error != 0)
        return (error);
    zap_cursor_t cursor;
    zap_attribute_t *attribute = zap_attribute_alloc();
    zap_cursor_init(&cursor, dp->dp_meta_objset, snapmap);
    while ((error = zap_cursor_retrieve(&cursor, attribute)) == 0) {
        if (vc_stopped(s)) {
            error = ECANCELED;
            break;
        }
        if (attribute->za_integer_length != sizeof (uint64_t) ||
            attribute->za_num_integers != 1) {
            error = EINVAL;
            break;
        }
        dsl_dataset_t *snapshot;
        error = dsl_dataset_hold_obj(dp, attribute->za_first_integer,
            &vc_tag, &snapshot);
        if (error != 0)
            break;
        if (!dsl_dataset_is_snapshot(snapshot))
            error = EINVAL;
        else
            error = vc_add_identity(s, snapshot, head->ds_object, type,
                locked, B_FALSE, &index);
        dsl_dataset_rele(snapshot, &vc_tag);
        if (error != 0)
            break;
        if (type == DMU_OST_ZFS && attribute->za_first_integer <
            chosen_object) {
            chosen_object = attribute->za_first_integer;
            chosen_index = index;
        }
        seen++;
        zap_cursor_advance(&cursor);
    }
    zap_cursor_fini(&cursor);
    zap_attribute_free(attribute);
    if (error == ENOENT)
        error = seen == native_count ? 0 : EIO;
    if (error == 0 && chosen_index != SIZE_MAX) {
        pthread_mutex_lock(&s->inventory_lock);
        s->inventory[chosen_index].selected = B_TRUE;
        pthread_mutex_unlock(&s->inventory_lock);
    }
    return (error);
}

static void *
vc_inventory_worker(void *arg)
{
    vc_state_t *s = arg;
    dsl_pool_t *dp = s->pool.spa->spa_dsl_pool;
    for (;;) {
        pthread_mutex_lock(&s->queue_lock);
        while (s->namespace_count == 0 && s->namespace_pending != 0 &&
            !vc_stopped(s))
            pthread_cond_wait(&s->queue_read, &s->queue_lock);
        if (vc_stopped(s) || s->namespace_pending == 0) {
            pthread_mutex_unlock(&s->queue_lock);
            break;
        }
        uint64_t object = s->namespace_queue[s->namespace_start];
        s->namespace_start = (s->namespace_start + 1) % VC_MAX_VIEWS;
        s->namespace_count--;
        pthread_mutex_unlock(&s->queue_lock);
        dsl_pool_config_enter(dp, &vc_tag);
        dsl_dir_t *directory = NULL;
        dsl_dataset_t *head = NULL;
        int error = dsl_dir_hold_obj(dp, object, NULL, &vc_tag, &directory);
        if (error == 0 && directory->dd_myname[0] == '$')
            error = EINVAL;
        if (error == 0)
            error = dsl_dataset_hold_obj(dp,
                dsl_dir_phys(directory)->dd_head_dataset_obj, &vc_tag, &head);
        if (error == 0)
            error = vc_inventory_head(dp, head, s);
        if (head != NULL)
            dsl_dataset_rele(head, &vc_tag);
        if (directory != NULL)
            dsl_dir_rele(directory, &vc_tag);
        dsl_pool_config_exit(dp, &vc_tag);
        if (error != 0)
            vc_fail(s, error, "inventory", object);
        pthread_mutex_lock(&s->queue_lock);
        s->namespace_pending--;
        if (s->namespace_pending == 0)
            pthread_cond_broadcast(&s->queue_read);
        pthread_mutex_unlock(&s->queue_lock);
    }
    return (NULL);
}

static int
vc_inventory(vc_state_t *s, unsigned workers)
{
    s->namespace_queue = calloc(VC_MAX_VIEWS, sizeof (*s->namespace_queue));
    if (s->namespace_queue == NULL)
        return (ENOMEM);
    int error = vc_enqueue_directory(s, s->pool.spa->spa_dsl_pool->dp_root_dir_obj);
    if (error != 0) {
        free(s->namespace_queue);
        s->namespace_queue = NULL;
        return (error);
    }
    pthread_t threads[VC_MAX_WORKERS];
    unsigned started = 0;
    for (; started < workers; started++) {
        error = pthread_create(&threads[started], NULL, vc_inventory_worker, s);
        if (error != 0) {
            vc_fail(s, error, "inventory_worker", 0);
            break;
        }
    }
    for (unsigned i = 0; i < started; i++)
        pthread_join(threads[i], NULL);
    free(s->namespace_queue);
    s->namespace_queue = NULL;
    return (atomic_load(&s->error));
}

static int
vc_identity_compare(const void *a, const void *b)
{
    const vc_identity_t *left = a, *right = b;
    return ((left->object > right->object) - (left->object < right->object));
}

static int
vc_file_attributes(objset_t *os, sa_attr_type_t *table, uint64_t object,
    uint64_t *mode, uint64_t *size, uint64_t *generation)
{
    sa_handle_t *handle;
    int error = sa_handle_get(os, object, NULL, SA_HDL_PRIVATE, &handle);
    if (error != 0)
        return (error);
    error = sa_lookup(handle, table[ZPL_MODE], mode, sizeof (*mode));
    if (error == 0)
        error = sa_lookup(handle, table[ZPL_SIZE], size, sizeof (*size));
    if (error == 0)
        error = sa_lookup(handle, table[ZPL_GEN], generation,
            sizeof (*generation));
    if (error == 0) {
        dmu_object_info_t info;
        sa_object_info(handle, &info);
        if ((S_ISREG(*mode) && info.doi_type != DMU_OT_PLAIN_FILE_CONTENTS) ||
            (S_ISDIR(*mode) && info.doi_type != DMU_OT_DIRECTORY_CONTENTS))
            error = EINVAL;
    }
    sa_handle_destroy(handle);
    return (error);
}

/* A no-read L0 hold resolves only dnode/indirect metadata. Never call
 * dbuf_read() on this hold: ordinary payload must not enter discovery. */
static int
vc_block_pointer(dnode_t *dn, uint64_t offset, blkptr_t *bp)
{
    dmu_buf_impl_t *db = NULL;
    rw_enter(&dn->dn_struct_rwlock, RW_READER);
    int error = dbuf_hold_impl(dn, 0, dbuf_whichblock(dn, 0, offset),
        B_FALSE, B_FALSE, &vc_tag, &db);
    rw_exit(&dn->dn_struct_rwlock);
    if (error != 0)
        return (error);
    db_lock_type_t lock = dmu_buf_lock_parent(db, RW_READER, &vc_tag);
    if (db->db_blkptr == NULL)
        memset(bp, 0, sizeof (*bp));
    else
        *bp = *db->db_blkptr;
    dmu_buf_unlock_parent(db, lock, &vc_tag);
    dbuf_rele(db, &vc_tag);
    return (0);
}

static boolean_t
vc_dedup_pointer(const blkptr_t *bp, unsigned type)
{
    return (!BP_IS_HOLE(bp) && !BP_IS_EMBEDDED(bp) &&
        BP_GET_DEDUP(bp) && BP_GET_LEVEL(bp) == 0 &&
        BP_GET_TYPE(bp) == type && DVA_IS_VALID(&bp->blk_dva[0]) &&
        BP_GET_LSIZE(bp) >= SPA_MINBLOCKSIZE &&
        BP_GET_LSIZE(bp) <= SPA_MAXBLOCKSIZE);
}

static boolean_t
vc_range_valid(const vc_sample_t *sample, unsigned type)
{
    if (!vc_dedup_pointer(&sample->bp, type))
        return (B_FALSE);
    uint64_t blocksize = BP_GET_LSIZE(&sample->bp);
    return (sample->object != 0 && sample->offset < sample->size &&
        sample->offset % blocksize == 0 && sample->length != 0 &&
        sample->length == MIN((uint64_t)VC_SAMPLE_BYTES,
        MIN(blocksize, sample->size - sample->offset)));
}

static int
vc_view_grow(vc_view_t *view, unsigned needed)
{
    if (needed <= view->capacity)
        return (0);
    unsigned capacity = view->capacity ? view->capacity * 2 : 16;
    capacity = MAX(capacity, needed);
    capacity = MIN(capacity, VC_MAX_SAMPLES);
    vc_sample_t *samples = realloc(view->samples, capacity * sizeof (*samples));
    if (samples == NULL)
        return (ENOMEM);
    view->samples = samples;
    view->capacity = capacity;
    return (0);
}

static int
vc_hash_sample(vc_state_t *s, objset_t *os, vc_sample_t *sample,
    unsigned char *buffer, EVP_MD_CTX *digest, boolean_t expect)
{
    unsigned type = dmu_objset_type(os) == DMU_OST_ZFS ?
        DMU_OT_PLAIN_FILE_CONTENTS : DMU_OT_ZVOL;
    if (!vc_range_valid(sample, type))
        return (EINVAL);
    if (vc_stopped(s))
        return (ECANCELED);
    dnode_t *dn;
    int error = dnode_hold(os, sample->object, &vc_tag, &dn);
    if (error != 0)
        return (error);
    blkptr_t bp;
    error = vc_block_pointer(dn, sample->offset, &bp);
    if (error == 0 && (dn->dn_datablksz != BP_GET_LSIZE(&sample->bp) ||
        memcmp(&bp, &sample->bp, sizeof (bp)) != 0)) {
        error = ECKSUM;
        vc_fail(s, error, "sample_bp_identity", sample->object);
    }
    dnode_rele(dn, &vc_tag);
    if (error == 0)
        error = dmu_read(os, sample->object, sample->offset,
            sample->length, buffer, DMU_READ_NO_PREFETCH);
    if (error != 0)
        return (error);
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned length;
    if (EVP_DigestInit_ex(digest, EVP_sha256(), NULL) != 1 ||
        EVP_DigestUpdate(digest, buffer, sample->length) != 1 ||
        EVP_DigestFinal_ex(digest, hash, &length) != 1 || length != 32)
        return (EIO);
    char hex[65];
    for (unsigned i = 0; i < 32; i++)
        snprintf(hex + 2 * i, 3, "%02x", hash[i]);
    if (expect && strcmp(sample->sha256, hex) != 0) {
        vc_fail(s, ECKSUM, "sample_content_hash", sample->object);
        return (ECKSUM);
    }
    memcpy(sample->sha256, hex, sizeof (hex));
    atomic_fetch_add(&s->bytes, sample->length);
    atomic_fetch_add(&s->samples_completed, 1);
    return (0);
}

/* The CAS budget counts logical references, not unique physical allocations.
 * One view belongs to one worker, so its growing array needs no extra lock. */
static int
vc_discover_object(vc_state_t *s, objset_t *os, vc_view_t *view,
    uint64_t object, uint64_t size, uint64_t generation,
    unsigned char *buffer, EVP_MD_CTX *digest)
{
    dnode_t *dn;
    int error = dnode_hold(os, object, &vc_tag, &dn);
    if (error != 0)
        return (error);
    unsigned type = dmu_objset_type(os) == DMU_OST_ZFS ?
        DMU_OT_PLAIN_FILE_CONTENTS : DMU_OT_ZVOL;
    uint64_t offset = 0;
    while (offset < size && !vc_stopped(s) &&
        atomic_load(&s->samples_reserved) < s->sample_target) {
        /* minlvl=1 searches BPs, never the level-zero data they describe. */
        error = dnode_next_offset(dn, 0, &offset, 1, 1, 0);
        if (error == ESRCH) {
            error = 0;
            break;
        }
        if (error != 0 || offset >= size)
            break;
        blkptr_t bp;
        error = vc_block_pointer(dn, offset, &bp);
        if (error != 0)
            break;
        atomic_fetch_add(&s->bps_examined, 1);
        uint64_t blocksize = dn->dn_datablksz;
        if (blocksize == 0 || offset % blocksize != 0) {
            error = EINVAL;
            break;
        }
        if (vc_dedup_pointer(&bp, type)) {
            vc_sample_t sample = { .object = object, .size = size,
                .generation = generation, .offset = offset, .bp = bp,
                .length = MIN((uint64_t)VC_SAMPLE_BYTES,
                MIN(blocksize, size - offset)) };
            if (!vc_range_valid(&sample, type) ||
                BP_GET_LSIZE(&bp) != blocksize) {
                error = EINVAL;
                break;
            }
            uint_fast64_t reserved = atomic_load(&s->samples_reserved);
            while (reserved < s->sample_target &&
                !atomic_compare_exchange_weak(&s->samples_reserved,
                &reserved, reserved + 1))
                ;
            if (reserved == s->sample_target)
                break;
            error = vc_view_grow(view, view->count + 1);
            if (error == 0)
                error = vc_hash_sample(s, os, &sample, buffer, digest, B_FALSE);
            if (error != 0)
                break;
            view->samples[view->count++] = sample;
        }
        if (offset > UINT64_MAX - blocksize)
            break;
        offset += blocksize;
    }
    dnode_rele(dn, &vc_tag);
    return (vc_stopped(s) && error == 0 ? ECANCELED : error);
}

static int
vc_filesystem(vc_state_t *s, objset_t *os, vc_view_t *view,
    unsigned char *buffer, EVP_MD_CTX *digest)
{
    if ((s->expect && view->count == 0) || (!s->expect &&
        atomic_load(&s->samples_reserved) == s->sample_target))
        return (0);
    uint64_t version, sa_object = 0;
    int error = zap_lookup(os, MASTER_NODE_OBJ, ZPL_VERSION_STR,
        8, 1, &version);
    if (error != 0)
        return (error);
    if (version >= ZPL_VERSION_SA) {
        error = zap_lookup(os, MASTER_NODE_OBJ, ZFS_SA_ATTRS, 8, 1,
            &sa_object);
        if (error != 0)
            return (error);
    }
    sa_attr_type_t *table;
    error = sa_setup(os, sa_object, zfs_attr_table, ZPL_END, &table);
    if (error != 0)
        return (error);
    if (s->expect) {
        for (unsigned i = 0; i < view->count && error == 0; i++) {
            vc_sample_t *sample = &view->samples[i];
            uint64_t mode, size, generation;
            error = vc_file_attributes(os, table, sample->object, &mode,
                &size, &generation);
            if (error == 0 && (!S_ISREG(mode) || size != sample->size ||
                generation != sample->generation))
                error = EINVAL;
            if (error == 0)
                error = vc_hash_sample(s, os, sample, buffer, digest, B_TRUE);
        }
        sa_tear_down(os);
        return (error);
    }

    uint64_t object = 0;
    while (!vc_stopped(s) &&
        atomic_load(&s->samples_reserved) < s->sample_target) {
        error = dmu_object_next(os, &object, B_FALSE, 0);
        if (error == ESRCH) {
            error = 0;
            view->exhausted = B_TRUE;
            break;
        }
        if (error != 0)
            break;
        atomic_fetch_add(&s->objects_examined, 1);
        dmu_object_info_t info;
        error = dmu_object_info(os, object, &info);
        if (error != 0)
            break;
        if (info.doi_type != DMU_OT_PLAIN_FILE_CONTENTS)
            continue;
        uint64_t mode, size, generation;
        error = vc_file_attributes(os, table, object, &mode, &size, &generation);
        if (error != 0)
            break;
        if (S_ISREG(mode))
            error = vc_discover_object(s, os, view, object, size, generation,
                buffer, digest);
        if (error != 0)
            break;
    }
    sa_tear_down(os);
    return (error);
}

static int
vc_zvol(vc_state_t *s, objset_t *os, vc_view_t *view,
    unsigned char *buffer, EVP_MD_CTX *digest)
{
    uint64_t size;
    int error = zap_lookup(os, ZVOL_ZAP_OBJ, "size", 8, 1, &size);
    if (error != 0)
        return (error);
    dmu_object_info_t info;
    error = dmu_object_info(os, ZVOL_OBJ, &info);
    if (error != 0 || info.doi_type != DMU_OT_ZVOL)
        return (error != 0 ? error : EINVAL);
    if (!s->expect) {
        atomic_fetch_add(&s->objects_examined, 1);
        return (vc_discover_object(s, os, view, ZVOL_OBJ, size, 0,
            buffer, digest));
    }
    for (unsigned i = 0; i < view->count; i++) {
        vc_sample_t *sample = &view->samples[i];
        if (sample->object != ZVOL_OBJ || sample->size != size ||
            sample->generation != 0)
            return (EINVAL);
        error = vc_hash_sample(s, os, sample, buffer, digest, s->expect);
        if (error != 0)
            return (error);
    }
    return (0);
}

static void *
vc_worker(void *arg)
{
    vc_state_t *s = arg;
    unsigned char *buffer = malloc(VC_SAMPLE_BYTES);
    EVP_MD_CTX *digest = EVP_MD_CTX_new();
    if (buffer == NULL || digest == NULL) {
        free(buffer);
        EVP_MD_CTX_free(digest);
        vc_fail(s, ENOMEM, "worker_buffer", 0);
        return (NULL);
    }
    for (;;) {
        pthread_mutex_lock(&s->queue_lock);
        while (s->queue_count == 0 && !s->queue_closed && !vc_stopped(s))
            pthread_cond_wait(&s->queue_read, &s->queue_lock);
        if (vc_stopped(s) || s->queue_count == 0) {
            pthread_mutex_unlock(&s->queue_lock);
            break;
        }
        size_t index = s->queue[s->queue_start];
        s->queue_start = (s->queue_start + 1) % VC_QUEUE;
        s->queue_count--;
        pthread_cond_signal(&s->queue_write);
        pthread_mutex_unlock(&s->queue_lock);
        vc_view_t *view = &s->views[index];
        vc_identity_t *id = &s->inventory[view->identity];
        dsl_pool_t *dp = s->pool.spa->spa_dsl_pool;
        dsl_pool_config_enter(dp, &vc_tag);
        dsl_dataset_t *ds = NULL;
        objset_t *os = NULL;
        int error = dsl_dataset_hold_obj(dp, id->object, &vc_tag, &ds);
        if (error == 0)
            error = dmu_objset_from_ds(ds, &os);
        if (error == 0 && (dmu_objset_type(os) != id->type ||
            (boolean_t)os->os_encrypted != id->locked))
            error = EINVAL;
        if (error == 0 && !id->locked) {
            error = id->type == DMU_OST_ZFS ?
                vc_filesystem(s, os, view, buffer, digest) :
                vc_zvol(s, os, view, buffer, digest);
        }
        if (ds != NULL)
            dsl_dataset_rele(ds, &vc_tag);
        dsl_pool_config_exit(dp, &vc_tag);
        if (error != 0) {
            vc_fail(s, error, "read_view", id->object);
            break;
        }
        view->locked = id->locked;
        atomic_fetch_add(&s->tasks, 1);
    }
    EVP_MD_CTX_free(digest);
    free(buffer);
    return (NULL);
}

static json_t *
vc_integer(uint64_t value)
{
    char text[32];
    snprintf(text, sizeof (text), "%" PRIu64, value);
    return (json_string(text));
}

static boolean_t
vc_parse_integer(json_t *value, uint64_t *result)
{
    if (!json_is_string(value))
        return (B_FALSE);
    const char *text = json_string_value(value);
    if (json_string_length(value) != strlen(text) || *text == '\0' ||
        (*text == '0' && text[1] != '\0'))
        return (B_FALSE);
    uint64_t number = 0;
    for (const unsigned char *p = (const unsigned char *)text; *p; p++) {
        if (*p < '0' || *p > '9' || number > (UINT64_MAX - (*p - '0')) / 10)
            return (B_FALSE);
        number = number * 10 + (*p - '0');
    }
    *result = number;
    return (B_TRUE);
}

static char *
vc_name_hex(const char *name)
{
    size_t length = strlen(name);
    char *hex = malloc(length * 2 + 1);
    if (hex == NULL)
        return (NULL);
    for (size_t i = 0; i < length; i++)
        snprintf(hex + 2 * i, 3, "%02x", (unsigned char)name[i]);
    hex[length * 2] = '\0';
    return (hex);
}

static json_t *
vc_identity_json(const vc_identity_t *id)
{
    char *hex = vc_name_hex(id->name);
    if (hex == NULL)
        return (NULL);
    json_t *value = json_pack("{s:o,s:o,s:o,s:o,s:s,s:b,s:s,s:b,s:b}",
        "objset_id", vc_integer(id->object), "guid", vc_integer(id->guid),
        "head_id", vc_integer(id->head), "creation_txg", vc_integer(id->creation),
        "type", id->type == DMU_OST_ZFS ? "filesystem" : "zvol",
        "snapshot", id->snapshot, "name_hex", hex,
        "selected", id->selected, "locked", id->locked);
    free(hex);
    return (value);
}

static boolean_t
vc_keys(json_t *value, const char *const *keys, size_t count)
{
    if (!json_is_object(value) || json_object_size(value) != count)
        return (B_FALSE);
    for (size_t i = 0; i < count; i++)
        if (json_object_get(value, keys[i]) == NULL)
            return (B_FALSE);
    return (B_TRUE);
}

static int
vc_read_manifest(const char *path, json_t **result)
{
    *result = NULL;
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0)
        return (errno);
    struct stat st;
    int error = fstat(fd, &st) != 0 ? errno : 0;
    if (error == 0 && (!S_ISREG(st.st_mode) || st.st_size <= 0 ||
        (uint64_t)st.st_size > VC_MAX_MANIFEST))
        error = E2BIG;
    char *buffer = NULL;
    size_t size = error == 0 ? (size_t)st.st_size : 0;
    if (error == 0 && (buffer = malloc(size)) == NULL)
        error = ENOMEM;
    size_t done = 0;
    while (error == 0 && done < size) {
        if (interrupted) {
            error = ECANCELED;
            break;
        }
        ssize_t got = read(fd, buffer + done, size - done);
        if (got < 0 && errno == EINTR)
            continue;
        if (got <= 0) {
            error = got == 0 ? EINVAL : errno;
            break;
        }
        done += (size_t)got;
    }
    if (error == 0) {
        char extra;
        ssize_t got;
        do {
            got = read(fd, &extra, 1);
        } while (got < 0 && errno == EINTR && !interrupted);
        if (got != 0)
            error = got < 0 ? errno : E2BIG;
    }
    close(fd);
    if (error == 0) {
        json_error_t parse_error;
        *result = json_loadb(buffer, size, JSON_REJECT_DUPLICATES, &parse_error);
        if (*result == NULL)
            error = EINVAL;
    }
    free(buffer);
    return (error);
}

static json_t *
vc_limits_json(void)
{
    return (json_pack("{s:i,s:i,s:i,s:i}",
        "bytes_per_sample", VC_SAMPLE_BYTES, "sample_count", VC_MAX_SAMPLES,
        "inventory_objects", VC_MAX_INVENTORY, "selected_views", VC_MAX_VIEWS));
}

/* All 128 native BP bytes, as sixteen precision-safe words, preserve DVAs,
 * checksum, properties, physical/logical births and encryption fields. */
_Static_assert(sizeof (blkptr_t) == 16 * sizeof (uint64_t), "BP word schema");

static json_t *
vc_bp_json(const blkptr_t *bp)
{
    uint64_t words[16];
    memcpy(words, bp, sizeof (words));
    json_t *values = json_array();
    if (values == NULL)
        return (NULL);
    for (unsigned i = 0; i < 16; i++) {
        if (json_array_append_new(values, vc_integer(words[i]))) {
            json_decref(values);
            return (NULL);
        }
    }
    return (json_pack("{s:b,s:o}", "dedup", B_TRUE, "words", values));
}

static boolean_t
vc_parse_bp(json_t *value, blkptr_t *bp)
{
    static const char *const keys[] = { "dedup", "words" };
    json_t *values = json_object_get(value, "words");
    if (!vc_keys(value, keys, 2) ||
        !json_is_true(json_object_get(value, "dedup")) ||
        !json_is_array(values) || json_array_size(values) != 16)
        return (B_FALSE);
    uint64_t words[16];
    for (unsigned i = 0; i < 16; i++)
        if (!vc_parse_integer(json_array_get(values, i), &words[i]))
            return (B_FALSE);
    memcpy(bp, words, sizeof (words));
    return (B_TRUE);
}

static int
vc_load_expect(vc_state_t *s, const char *path, uint64_t guid)
{
    json_t *root;
    int error = vc_read_manifest(path, &root);
    if (error != 0)
        return (error);
    static const char *const root_keys[] = { "format", "pool_guid", "complete",
        "limits", "inventory", "views", "sample_bytes", "sample_count",
        "sample_target" };
    error = EINVAL;
    json_t *format = json_object_get(root, "format");
    uint64_t expected_guid, sample_bytes, sample_count, sample_target;
    if (!vc_keys(root, root_keys, 9) || !json_is_string(format) ||
        json_string_length(format) != strlen("validate-content-v2") ||
        strcmp(json_string_value(format), "validate-content-v2") != 0 ||
        !json_is_true(json_object_get(root, "complete")) ||
        !vc_parse_integer(json_object_get(root, "pool_guid"), &expected_guid) ||
        expected_guid != guid ||
        !vc_parse_integer(json_object_get(root, "sample_bytes"), &sample_bytes) ||
        !vc_parse_integer(json_object_get(root, "sample_count"), &sample_count) ||
        !vc_parse_integer(json_object_get(root, "sample_target"), &sample_target) ||
        sample_count != s->sample_target || sample_target != s->sample_target)
        goto out;
    json_t *limits = vc_limits_json();
    boolean_t matching_limits = limits != NULL &&
        json_equal(limits, json_object_get(root, "limits"));
    json_decref(limits);
    if (!matching_limits)
        goto out;
    json_t *inventory = json_object_get(root, "inventory");
    json_t *views = json_object_get(root, "views");
    if (!json_is_array(inventory) || json_array_size(inventory) !=
        s->inventory_count || !json_is_array(views) ||
        json_array_size(views) != s->view_count)
        goto out;
    for (size_t i = 0; i < s->inventory_count; i++) {
        json_t *actual = vc_identity_json(&s->inventory[i]);
        boolean_t equal = actual != NULL &&
            json_equal(actual, json_array_get(inventory, i));
        json_decref(actual);
        if (!equal)
            goto out;
    }
    uint64_t total_bytes = 0, total_samples = 0;
    for (size_t i = 0; i < s->view_count; i++) {
        vc_view_t *view = &s->views[i];
        vc_identity_t *id = &s->inventory[view->identity];
        json_t *value = json_array_get(views, i);
        static const char *const view_keys[] = { "objset_id", "status",
            "directory_entries", "search_exhausted", "samples" };
        uint64_t object;
        json_t *status = json_object_get(value, "status");
        json_t *directory_entries = json_object_get(value, "directory_entries");
        json_t *exhausted = json_object_get(value, "search_exhausted");
        json_t *samples = json_object_get(value, "samples");
        if (!vc_keys(value, view_keys, 5) ||
            !vc_parse_integer(json_object_get(value, "objset_id"), &object) ||
            object != id->object || !json_is_string(status) ||
            json_string_length(status) != (id->locked ? 6U : 2U) ||
            strcmp(json_string_value(status), id->locked ? "locked" : "ok") ||
            !json_is_integer(directory_entries) ||
            json_integer_value(directory_entries) != 0 ||
            !json_is_boolean(exhausted) || !json_is_array(samples))
            goto out;
        view->directory_entries = json_integer_value(directory_entries);
        view->exhausted = json_is_true(exhausted);
        view->locked = id->locked;
        size_t count = json_array_size(samples);
        if (count > s->sample_target - total_samples)
            goto out;
        if ((id->locked && (count || view->exhausted)) ||
            (id->type == DMU_OST_ZVOL && view->exhausted))
            goto out;
        if (count != 0) {
            view->samples = calloc(count, sizeof (*view->samples));
            if (view->samples == NULL) {
                error = ENOMEM;
                goto out;
            }
        }
        view->count = view->capacity = (unsigned)count;
        total_samples += count;
        for (unsigned j = 0; j < view->count; j++) {
            vc_sample_t *sample = &view->samples[j];
            json_t *item = json_array_get(samples, j);
            static const char *const sample_keys[] = { "object", "object_size",
                "generation", "offset", "length", "sha256", "bp" };
            json_t *hash = json_object_get(item, "sha256");
            if (!vc_keys(item, sample_keys, 7) ||
                !vc_parse_integer(json_object_get(item, "object"), &sample->object) ||
                !vc_parse_integer(json_object_get(item, "object_size"), &sample->size) ||
                !vc_parse_integer(json_object_get(item, "generation"), &sample->generation) ||
                !vc_parse_integer(json_object_get(item, "offset"), &sample->offset) ||
                !vc_parse_integer(json_object_get(item, "length"), &sample->length) ||
                !vc_parse_bp(json_object_get(item, "bp"), &sample->bp) ||
                !vc_range_valid(sample, id->type == DMU_OST_ZFS ?
                DMU_OT_PLAIN_FILE_CONTENTS : DMU_OT_ZVOL) ||
                (id->type == DMU_OST_ZVOL && (sample->object != ZVOL_OBJ ||
                sample->generation != 0)) || !json_is_string(hash) ||
                json_string_length(hash) != 64)
                goto out;
            /* Canonical object/offset order rejects duplicate logical ranges
             * without a quadratic search or per-entry allocation. */
            if (j != 0) {
                const vc_sample_t *previous = &view->samples[j - 1];
                if (sample->object < previous->object ||
                    (sample->object == previous->object &&
                    (sample->offset <= previous->offset ||
                    sample->size != previous->size ||
                    sample->generation != previous->generation)))
                    goto out;
            }
            const char *text = json_string_value(hash);
            for (unsigned k = 0; k < 64; k++)
                if (!((text[k] >= '0' && text[k] <= '9') ||
                    (text[k] >= 'a' && text[k] <= 'f')))
                    goto out;
            memcpy(sample->sha256, text, 65);
            total_bytes += sample->length;
        }
    }
    if (total_bytes != sample_bytes || total_samples != s->sample_target)
        goto out;
    s->expect = B_TRUE;
    error = 0;
out:
    json_decref(root);
    return (error);
}

static int
vc_report(vc_state_t *s, const char *path, uint64_t guid)
{
    json_t *root = json_object(), *inventory = json_array(), *views = json_array();
    if (root == NULL || inventory == NULL || views == NULL) {
        json_decref(root); json_decref(inventory); json_decref(views);
        return (ENOMEM);
    }
    int error = ENOMEM;
    if (json_object_set_new(root, "format", json_string("validate-content-v2")) ||
        json_object_set_new(root, "pool_guid", vc_integer(guid)) ||
        json_object_set_new(root, "complete", json_true()) ||
        json_object_set_new(root, "sample_bytes", vc_integer(atomic_load(&s->bytes))) ||
        json_object_set_new(root, "sample_count",
        vc_integer(atomic_load(&s->samples_completed))) ||
        json_object_set_new(root, "sample_target", vc_integer(s->sample_target)) ||
        json_object_set_new(root, "limits", vc_limits_json()))
        goto out;
    for (size_t i = 0; i < s->inventory_count; i++)
        if (json_array_append_new(inventory, vc_identity_json(&s->inventory[i])))
            goto out;
    for (size_t i = 0; i < s->view_count; i++) {
        vc_view_t *view = &s->views[i];
        json_t *samples = json_array();
        if (samples == NULL)
            goto out;
        for (unsigned j = 0; j < view->count; j++) {
            vc_sample_t *sample = &view->samples[j];
            json_t *item = json_pack("{s:o,s:o,s:o,s:o,s:o,s:s,s:o}",
                "object", vc_integer(sample->object),
                "object_size", vc_integer(sample->size),
                "generation", vc_integer(sample->generation),
                "offset", vc_integer(sample->offset),
                "length", vc_integer(sample->length), "sha256", sample->sha256,
                "bp", vc_bp_json(&sample->bp));
            if (item == NULL || json_array_append_new(samples, item)) {
                json_decref(samples);
                goto out;
            }
        }
        json_t *value = json_pack("{s:o,s:s,s:i,s:b,s:o}",
            "objset_id", vc_integer(s->inventory[view->identity].object),
            "status", view->locked ? "locked" : "ok",
            "directory_entries", view->directory_entries,
            "search_exhausted", view->exhausted, "samples", samples);
        if (value == NULL || json_array_append_new(views, value))
            goto out;
    }
    if (json_object_set(root, "inventory", inventory) ||
        json_object_set(root, "views", views))
        goto out;
    size_t length = strlen(path);
    char *temporary = malloc(length + 16);
    if (temporary == NULL)
        goto out;
    snprintf(temporary, length + 16, "%s.XXXXXX", path);
    int fd = mkstemp(temporary);
    if (fd < 0) {
        error = errno;
        free(temporary);
        goto out;
    }
    error = 0;
    if (json_dumpfd(root, fd, JSON_COMPACT | JSON_SORT_KEYS) != 0 ||
        fsync(fd) != 0)
        error = errno != 0 ? errno : EIO;
    if (close(fd) != 0 && error == 0)
        error = errno;
    if (error == 0 && !vc_stopped(s) && rename(temporary, path) != 0)
        error = errno;
    else if (vc_stopped(s) && error == 0)
        error = ECANCELED;
    if (error != 0)
        unlink(temporary);
    free(temporary);
out:
    json_decref(root); json_decref(inventory); json_decref(views);
    return (error);
}

static int
vc_argument(const char *text, uint64_t *value)
{
    if (*text == '\0' || (*text == '0' && text[1] != '\0'))
        return (EINVAL);
    uint64_t number = 0;
    for (; *text != '\0'; text++) {
        if (*text < '0' || *text > '9' ||
            number > (UINT64_MAX - (*text - '0')) / 10)
            return (EINVAL);
        number = number * 10 + (*text - '0');
    }
    *value = number;
    return (0);
}

int
main(int argc, char **argv)
{
    uint64_t guid = 0, arc = 256ULL * 1024 * 1024;
    long cpus = sysconf(_SC_NPROCESSORS_ONLN);
    uint64_t workers = cpus > 0 ? (uint64_t)cpus : 1;
    if (workers > 32)
        workers = 32;
    uint64_t sample_target = VC_DEFAULT_SAMPLES;
    const char *search = NULL, *output = NULL, *expect = NULL;
    for (int i = 1; i < argc; i += 2) {
        if (i + 1 == argc)
            goto usage;
        if (!strcmp(argv[i], "--pool-guid")) {
            if (vc_argument(argv[i + 1], &guid)) goto usage;
        } else if (!strcmp(argv[i], "--workers")) {
            if (vc_argument(argv[i + 1], &workers)) goto usage;
        } else if (!strcmp(argv[i], "--sample-count")) {
            if (vc_argument(argv[i + 1], &sample_target)) goto usage;
        } else if (!strcmp(argv[i], "--arc-max-bytes")) {
            if (vc_argument(argv[i + 1], &arc)) goto usage;
        } else if (!strcmp(argv[i], "--search-dir"))
            search = argv[i + 1];
        else if (!strcmp(argv[i], "--output"))
            output = argv[i + 1];
        else if (!strcmp(argv[i], "--expect"))
            expect = argv[i + 1];
        else
            goto usage;
    }
    if (guid == 0 || workers == 0 || workers > VC_MAX_WORKERS || arc == 0 ||
        sample_target == 0 || sample_target > VC_MAX_SAMPLES ||
        search == NULL || output == NULL || (expect && !strcmp(output, expect)))
        goto usage;
    vc_state_t state = { .inventory_lock = PTHREAD_MUTEX_INITIALIZER,
        .queue_lock = PTHREAD_MUTEX_INITIALIZER,
        .queue_read = PTHREAD_COND_INITIALIZER,
        .queue_write = PTHREAD_COND_INITIALIZER, .sample_target = sample_target };
    clock_gettime(CLOCK_MONOTONIC, &state.started);
    atomic_init(&state.expected_heads, 1);
    struct sigaction action = { .sa_handler = vc_signal };
    sigemptyset(&action.sa_mask);
    sigaction(SIGINT, &action, NULL);
    sigaction(SIGTERM, &action, NULL);
    int error = vp_open(&state.pool, guid, search, arc);
    if (error != 0) {
        fprintf(stderr, "{\"phase\":\"error\",\"operation\":\"open_pool\",\"errno\":%d}\n", error);
        return (1);
    }
    pthread_t progress;
    error = pthread_create(&progress, NULL, vc_progress, &state);
    if (error != 0) {
        vp_close(&state.pool);
        return (1);
    }
    error = vc_inventory(&state, (unsigned)workers);
    if (error != 0)
        vc_fail(&state, error, "inventory", 0);
    if (!vc_stopped(&state) && atomic_load(&state.heads) !=
        atomic_load(&state.expected_heads))
        vc_fail(&state, EIO, "namespace_count", 0);
    if (!vc_stopped(&state)) {
        qsort(state.inventory, state.inventory_count,
            sizeof (*state.inventory), vc_identity_compare);
        for (size_t i = 0; i < state.inventory_count; i++) {
            if (i && state.inventory[i - 1].object == state.inventory[i].object) {
                vc_fail(&state, EINVAL, "duplicate_objset", state.inventory[i].object);
                break;
            }
            state.view_count += state.inventory[i].selected;
        }
        if (state.inventory_count == 0 || state.view_count > VC_MAX_VIEWS)
            vc_fail(&state, E2BIG, "inventory_bounds", 0);
    }
    atomic_store(&state.task_total, state.view_count);
    if (!vc_stopped(&state)) {
        state.views = calloc(state.view_count, sizeof (*state.views));
        if (state.views == NULL)
            vc_fail(&state, ENOMEM, "view_allocation", 0);
        else {
            size_t n = 0;
            for (size_t i = 0; i < state.inventory_count; i++)
                if (state.inventory[i].selected)
                    state.views[n++].identity = i;
        }
    }
    if (!vc_stopped(&state) && expect != NULL) {
        error = vc_load_expect(&state, expect, guid);
        if (error != 0)
            vc_fail(&state, error, "expect_manifest", 0);
    }
    pthread_t threads[VC_MAX_WORKERS];
    unsigned started = 0;
    if (!vc_stopped(&state)) {
        for (; started < workers; started++) {
            error = pthread_create(&threads[started], NULL, vc_worker, &state);
            if (error != 0) {
                vc_fail(&state, error, "create_worker", 0);
                break;
            }
        }
        for (size_t i = 0; i < state.view_count && !vc_stopped(&state); i++) {
            pthread_mutex_lock(&state.queue_lock);
            while (state.queue_count == VC_QUEUE && !vc_stopped(&state))
                pthread_cond_wait(&state.queue_write, &state.queue_lock);
            if (!vc_stopped(&state)) {
                size_t slot = (state.queue_start + state.queue_count) % VC_QUEUE;
                state.queue[slot] = i;
                state.queue_count++;
                pthread_cond_signal(&state.queue_read);
            }
            pthread_mutex_unlock(&state.queue_lock);
        }
    }
    pthread_mutex_lock(&state.queue_lock);
    state.queue_closed = B_TRUE;
    pthread_cond_broadcast(&state.queue_read);
    pthread_mutex_unlock(&state.queue_lock);
    for (unsigned i = 0; i < started; i++)
        pthread_join(threads[i], NULL);
    if (!vc_stopped(&state) && atomic_load(&state.tasks) != state.view_count)
        vc_fail(&state, EIO, "incomplete_tasks", 0);
    if (!vc_stopped(&state) && atomic_load(&state.samples_completed) !=
        state.sample_target)
        vc_fail(&state, ENOSPC, "insufficient_dedup_samples", 0);
    if (!vc_stopped(&state)) {
        error = vc_report(&state, output, guid);
        if (error != 0)
            vc_fail(&state, error, "publish_report", 0);
    }
    atomic_store(&state.finished, B_TRUE);
    pthread_join(progress, NULL);
    vp_close(&state.pool);
    for (size_t i = 0; i < state.view_count && state.views != NULL; i++)
        free(state.views[i].samples);
    free(state.views);
    free(state.inventory);
    pthread_cond_destroy(&state.queue_read);
    pthread_cond_destroy(&state.queue_write);
    pthread_mutex_destroy(&state.queue_lock);
    pthread_mutex_destroy(&state.inventory_lock);
    return (interrupted ? 128 + interrupted : atomic_load(&state.error) ? 1 : 0);
usage:
    fprintf(stderr, "Usage: validate-content --pool-guid DECIMAL --search-dir DIR "
        "--output PATH [--workers N] [--arc-max-bytes N] "
        "[--sample-count 1..50000] [--expect PATH]\n");
    return (2);
}
