/* SPDX-License-Identifier: CDDL-1.0 */
#include "dedup_fdt_plan.h"
#include "dedup_fdt_index.h"
#include "dedup_fdt_native.h"
#include "dedup_fdt_sort.h"
#include "dedup_fdt_workers.h"
#include "rebuild_ddt_quota.h"
#include "rebuild_phase.h"
#include <sys/dmu_tx.h>
#include <sys/ddt_impl.h>
#include <sys/dsl_pool.h>
#include <sys/dsl_dataset.h>
#include <sys/dsl_dir.h>
#include <sys/dsl_crypt.h>
#include <sys/dsl_synctask.h>
#include <sys/spa_impl.h>
#include <sys/zio_checksum.h>
#include <sys/zfeature.h>
#include <pthread.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>

static int
df_compare_chunk(void *left, void *right, size_t size, void *arg)
{
    (void)arg;
    return (memcmp(left, right, size));
}

static int
df_compare(abd_t *left, abd_t *right, size_t size)
{
    return (abd_iterate_func2(left, right, 0, 0, size, df_compare_chunk, NULL));
}

/* Native identity deliberately excludes logical birth, which belongs to an
 * occurrence's historical owner, not to its physical allocation. */
typedef struct df_identity { uint64_t birth, dva[2]; } df_identity_t;
typedef struct df_alias_key {
    df_identity_t physical;
    uint64_t owner, logical_birth, type;
} df_alias_key_t;
typedef struct df_content_key {
    zio_cksum_t digest;
    uint64_t domain, type, byteorder, logical_size;
} df_content_key_t;
typedef struct df_fdt_key { uint64_t checksum; ddt_key_t key; } df_fdt_key_t;
typedef struct df_source {
    blkptr_t bp;
    zbookmark_phys_t bookmark;
    zio_cksum_t digest;
    zio_cksum_t stored_checksum;
    uint64_t domain, allocations, frees, post_allocations, post_frees;
    uint64_t native_ddt, native_brt, group;
    boolean_t selected, unselected, authentic, hashed, new_allocation;
    boolean_t latent_zil;
    boolean_t has_fdt;
    boolean_t unselected_live;
    boolean_t tree_view;
} df_source_t;
typedef struct df_group {
    uint64_t representative, best, members, max_copies;
    uint64_t max_source, eligible_max, eligible_copies, anchor;
    blkptr_t canonical;
    boolean_t allocate, skipped;
} df_group_t;
typedef struct df_fdt_value {
    ddt_univ_phys_t physical;
    uint64_t reserved_group;
    boolean_t existing;
} df_fdt_value_t;
typedef struct df_dataset {
    uint64_t object, domain;
    boolean_t selected;
    dsl_dataset_phys_t original;
} df_dataset_t;
typedef struct df_flat_record {
    uint64_t checksum;
    ddt_key_t key;
    ddt_univ_phys_t physical;
} df_flat_record_t;
typedef struct df_brt_record {
    blkptr_t bp;
    uint64_t before, after;
} df_brt_record_t;
struct dedup_fdt_plan {
    spa_t *spa;
    int directory;
    dedup_fdt_options_t options;
    dedup_fdt_index_t sources, groups, aliases, fdt;
    abd_t *buffers[64];
    dedup_fdt_workers_t *workers;
    unsigned buffer_count, effective_workers;
    uint64_t buffer_reservation, read_window, read_sequence, completed_reads;
    uint64_t outstanding_reads;
    uint64_t read_pass, cpu_tasks, cpu_batch_elapsed_ns;
    uint64_t candidate_comparisons, native_anchor_comparisons;
    df_dataset_t *datasets;
    boolean_t needs_claim;
    size_t dataset_count;
    uint64_t references, flat_count, max_size, total_hash_bytes;
    uint64_t output_flat_count, output_brt_count;
    dedup_fdt_file_t flat_output, brt_output;
    boolean_t ready;
    uint64_t metadata_space;
    boolean_t space_overflow;
    uint64_t projected_stage_bytes, projected_retire_bytes, index_bytes;
    uint64_t dataset_reservation;
    pthread_mutex_t progress_lock;
    struct timespec started, last_progress;
    dedup_fdt_counters_t counters;
};
static uint64_t df_next_read_pass;
static df_identity_t
df_identity(const blkptr_t *bp)
{
    df_identity_t key = { .birth = BP_GET_PHYSICAL_BIRTH(bp),
        .dva = { BP_IDENTITY(bp)->dva_word[0], BP_IDENTITY(bp)->dva_word[1] } };
    return (key);
}
static boolean_t
df_same_allocation(const blkptr_t *a, const blkptr_t *b)
{
    df_identity_t x = df_identity(a), y = df_identity(b);
    return (memcmp(&x, &y, sizeof (x)) == 0);
}
static df_dataset_t *
df_dataset(dedup_fdt_plan_t *p, uint64_t object)
{
    for (size_t i = 0; i < p->dataset_count; i++)
        if (p->datasets[i].object == object)
            return (&p->datasets[i]);
    return (NULL);
}
static boolean_t
df_selected(dedup_fdt_plan_t *p, uint64_t object)
{
    df_dataset_t *dataset = df_dataset(p, object);
    return (dataset != NULL && dataset->selected);
}
static int
df_collect_datasets(dedup_fdt_plan_t *p)
{
    dsl_pool_t *dp = spa_get_dsl(p->spa);
    for (size_t i = 0; i < p->options.dataset_count; i++) {
        const char *name = p->options.datasets[i];
        if (strchr(name, '@') != NULL || strchr(name, '#') != NULL)
            return (EINVAL);
        dsl_dataset_t *dataset;
        dsl_pool_config_enter(dp, p);
        int error = dsl_dataset_hold(dp, name, p, &dataset);
        dsl_pool_config_exit(dp, p);
        if (error != 0)
            return (error);
        dsl_dataset_rele(dataset, p);
    }
    uint64_t object = 0;
    int error;
    while ((error = dmu_object_next(dp->dp_meta_objset, &object, B_FALSE, 0)) == 0) {
        dmu_object_info_t info;
        error = dmu_object_info(dp->dp_meta_objset, object, &info);
        if (error != 0)
            return (error);
        if (info.doi_bonus_type != DMU_OT_DSL_DATASET)
            continue;
        dsl_dataset_t *dataset;
        dsl_pool_config_enter(dp, p);
        error = dsl_dataset_hold_obj(dp, object, p, &dataset);
        dsl_pool_config_exit(dp, p);
        if (error != 0)
            return (error);
        char name[ZFS_MAX_DATASET_NAME_LEN];
        dsl_dataset_name(dataset, name);
        df_dataset_t value = { .object = object,
            .original = *dsl_dataset_phys(dataset) };
        for (size_t i = 0; i < p->options.dataset_count; i++) {
            size_t n = strlen(p->options.datasets[i]);
            if (strncmp(name, p->options.datasets[i], n) == 0 &&
                (name[n] == 0 || name[n] == '/' || name[n] == '@'))
                value.selected = B_TRUE;
        }
        if (dataset->ds_dir->dd_crypto_obj != 0) {
            dsl_crypto_key_t *key;
            error = spa_keystore_lookup_key(p->spa, object, p, &key);
            if (error == 0) {
                value.domain = key->dck_key.zk_guid;
                spa_keystore_dsl_key_rele(p->spa, key, p);
            }
        }
        dsl_dataset_rele(dataset, p);
        if (error != 0)
            return (error);
        if (p->dataset_count == SIZE_MAX/sizeof (*p->datasets))
            return (EOVERFLOW);
        error = dedup_fdt_memory_reserve(p->options.resources, sizeof (value));
        if (error != 0)
            return (error);
        p->dataset_reservation += sizeof (value);
        df_dataset_t *next = realloc(p->datasets,
            (p->dataset_count+1)*sizeof (*p->datasets));
        if (next == NULL)
            return (ENOMEM);
        p->datasets = next;
        p->datasets[p->dataset_count++] = value;
    }
    return (error == ESRCH ? 0 : error);
}
static int
df_map(void *arg, uint64_t owner, const blkptr_t *source, blkptr_t *out)
{
    dedup_fdt_plan_t *p = arg;
    *out = *source;
    if (!p->ready)
        return (ENOENT);
    df_identity_t key = df_identity(source);
    df_source_t value;
    uint64_t slot;
    int error = dedup_fdt_index_find(&p->sources, &key, &value, &slot, 0);
    if (error != 0 || value.group == 0)
        return (error != 0 ? error : ENOENT);
    df_group_t group;
    error = dedup_fdt_index_read(&p->groups, value.group, NULL, &group);
    if (error != 0)
        return (error);
    if (group.members < 2 || group.skipped)
        return (ENOENT);
    if (!df_selected(p, owner))
        return (0); /* physical unselected source remains ordinary/FDT as was */
    *out = group.canonical;
    BP_SET_TYPE(out, BP_GET_TYPE(source));
    /* BP_SET_BIRTH changes logical birth before evaluating its physical
     * argument; resolve canonical physical birth before modifying the BP. */
    uint64_t physical_birth = BP_GET_PHYSICAL_BIRTH(out);
    BP_SET_BIRTH(out, BP_GET_BIRTH(source), physical_birth);
    BP_SET_FILL(out, BP_GET_FILL(source));
    BP_SET_REWRITE(out, 0);
    return (0);
}
static int
df_variant(void *arg, uint64_t owner, const blkptr_t *source,
    blkptr_t *out, boolean_t save)
{
    dedup_fdt_plan_t *p = arg;
    df_alias_key_t key = { .physical = df_identity(source), .owner = owner,
        .logical_birth = BP_GET_BIRTH(source), .type = BP_GET_TYPE(source) };
    uint64_t slot;
    if (save) {
        blkptr_t previous;
        int error = dedup_fdt_index_find(&p->aliases, &key, &previous, &slot, 0);
        if (error == 0)
            return (memcmp(&previous, out, sizeof (previous)) == 0 ? 0 : ESTALE);
        if (error != ENOENT)
            return (error);
        previous = *out;
        error = dedup_fdt_index_find(&p->aliases, &key, &previous, &slot, 1);
        if (error == 0 && memcmp(source, out, sizeof (*out)) != 0)
            p->counters.aliases++;
        return (error);
    }
    return (dedup_fdt_index_find(&p->aliases, &key, out, &slot, 0));
}
static int
df_count(void *arg, uint64_t owner, const zbookmark_phys_t *bookmark,
    const blkptr_t *bp, unsigned flags)
{
    (void)owner, (void)bookmark, (void)flags;
    dedup_fdt_plan_t *p = arg;
    if (p->references == UINT64_MAX)
        return (EOVERFLOW);
    p->references++;
    (void)bp;
    return (0);
}
static int
df_flat_count(void *arg, enum zio_checksum checksum, const ddt_key_t *key,
    const ddt_univ_phys_t *physical)
{
    (void)checksum, (void)key, (void)physical;
    dedup_fdt_plan_t *p = arg;
    if (p->flat_count == UINT64_MAX)
        return (EOVERFLOW);
    p->flat_count++;
    return (0);
}
static int
df_flat_inventory(void *arg, enum zio_checksum checksum,
    const ddt_key_t *key, const ddt_univ_phys_t *physical)
{
    dedup_fdt_plan_t *p = arg;
    df_fdt_key_t identity = { .checksum = checksum, .key = *key };
    df_fdt_value_t value = { .physical = *physical, .existing = B_TRUE };
    uint64_t slot;
    int error = dedup_fdt_index_find(&p->fdt, &identity, &value, &slot, 1);
    if (error != 0)
        return (error);
    if (physical->ddp_flat.ddp_phys_birth == 0)
        return (0);
    blkptr_t bp;
    ddt_bp_create(checksum, key, physical, DDT_PHYS_FLAT, &bp);
    df_identity_t allocation = df_identity(&bp);
    df_source_t source = { .bp = bp, .native_ddt = physical->ddp_flat.ddp_refcnt,
        .has_fdt = B_TRUE };
    error = dedup_fdt_index_find(&p->sources, &allocation, &source, &slot, 1);
    if (error == 0 && (source.native_ddt != physical->ddp_flat.ddp_refcnt ||
        BP_GET_CHECKSUM(&source.bp) != checksum ||
        memcmp(&source.bp.blk_cksum, &key->ddk_cksum, sizeof (zio_cksum_t)) != 0))
        error = EINVAL;
    return (error);
}
static int
df_inventory(void *arg, uint64_t owner, const zbookmark_phys_t *bookmark,
    const blkptr_t *bp, unsigned flags)
{
    dedup_fdt_plan_t *p = arg;
    if (rebuild_interrupted())
        return (EINTR);
    df_identity_t key = df_identity(bp);
    df_source_t source = { .bp = *bp };
    uint64_t slot;
    int error = dedup_fdt_index_find(&p->sources, &key, &source, &slot, 1);
    if (error != 0)
        return (error);
    if ((flags & REBUILD_DATA_ZIL) && !(flags & REBUILD_DATA_OWNER))
        source.latent_zil = B_TRUE;
    if (source.native_ddt != 0 && !BP_GET_DEDUP(bp))
        return (ECKSUM);
    boolean_t selected = df_selected(p, owner);
    if (!selected)
        source.unselected = B_TRUE;
    if (flags & REBUILD_DATA_OWNER) {
        uint64_t *count = flags & REBUILD_DATA_FREE ? &source.frees :
            &source.allocations;
        if (*count == UINT64_MAX)
            return (EOVERFLOW);
        (*count)++;
        if (!selected)
            source.unselected = B_TRUE;
    }
    if (!(flags & REBUILD_DATA_AUXILIARY)) {
        if (!(flags & REBUILD_DATA_ZIL))
            source.tree_view = B_TRUE;
        df_dataset_t *dataset = df_dataset(p, owner);
        uint64_t domain = BP_USES_CRYPT(bp) ? dataset->domain : 0;
        if (source.authentic && source.domain != domain)
            return (ECKSUM);
        source.domain = domain;
        if (!selected)
            source.unselected_live = B_TRUE;
        if (source.authentic &&
            (BP_GET_LSIZE(bp) != BP_GET_LSIZE(&source.bp) ||
            BP_GET_PSIZE(bp) != BP_GET_PSIZE(&source.bp) ||
            DMU_OT_BYTESWAP(BP_GET_TYPE(bp)) != DMU_OT_BYTESWAP(BP_GET_TYPE(&source.bp)) ||
            BP_GET_BYTEORDER(bp) != BP_GET_BYTEORDER(&source.bp) ||
            BP_USES_CRYPT(bp) != BP_USES_CRYPT(&source.bp)))
            return (ECKSUM);
        if (source.authentic) {
            if (source.native_ddt == 0 &&
                BP_GET_NDVAS(bp) != BP_GET_NDVAS(&source.bp))
                return (ECKSUM);
            unsigned common = MIN(BP_GET_NDVAS(bp), BP_GET_NDVAS(&source.bp));
            for (unsigned i = 0; i < common; i++)
                if (!DVA_EQUAL(&bp->blk_dva[i], &source.bp.blk_dva[i]))
                    return (ECKSUM);
            if (BP_GET_CHECKSUM(bp) != BP_GET_CHECKSUM(&source.bp) ||
                memcmp(&bp->blk_cksum, &source.bp.blk_cksum,
                sizeof (zio_cksum_t)) != 0 ||
                (BP_IS_ENCRYPTED(bp) && (BP_GET_IV2(bp) != BP_GET_IV2(&source.bp) ||
                memcmp(&bp->blk_dva[2], &source.bp.blk_dva[2], sizeof (dva_t)) != 0)))
                return (ECKSUM);
        }
        /* Keep a full authenticated occurrence, never a stripped BPOBJ BP. */
        if (!source.authentic || (selected && !source.selected) ||
            (selected && BP_GET_NDVAS(bp) > BP_GET_NDVAS(&source.bp))) {
            source.bp = *bp;
            if (bookmark != NULL)
                source.bookmark = *bookmark;
            source.authentic = B_TRUE;
        }
        if (!selected)
            source.unselected = B_TRUE;
        if (selected) {
            if (BP_USES_CRYPT(bp) && domain == 0)
                return (ECKSUM);
            source.selected = B_TRUE;
            source.bookmark = *bookmark;
        }
    }
    error = dedup_fdt_index_write(&p->sources, slot, &source);
    dedup_fdt_plan_progress(p, "inventory", B_FALSE);
    return (error);
}
static int
df_sources_check(dedup_fdt_plan_t *p)
{
    for (uint64_t slot = 1; slot <= p->sources.capacity; slot++) {
        df_source_t source;
        int error = dedup_fdt_index_read(&p->sources, slot, NULL, &source);
        if (error == ENOENT)
            continue;
        if (error != 0)
            return (error);
        if (source.frees > source.allocations)
            return (EINVAL);
        uint64_t owners = source.allocations-source.frees, observed = 0;
        if (source.has_fdt && source.native_ddt == 0 && owners != 0)
            return (ESTALE);
        if (owners == 0 && source.native_ddt == 0) {
            if (source.tree_view)
                return (ESTALE);
            source.selected = B_FALSE;
            if (!source.has_fdt) {
                source.native_brt = 0;
                error = dedup_fdt_index_write(&p->sources, slot, &source);
                if (error != 0)
                    return (error);
                continue;
            }
        }
        error = rebuild_native_brt_refcount(p->spa, &source.bp, &source.native_brt);
        if (error != 0)
            return (error);
        if (source.native_ddt != 0) {
            if (source.native_ddt != owners || source.native_brt != 0)
                return (ESTALE);
            if (source.authentic) {
                df_fdt_key_t key = { .checksum = BP_GET_CHECKSUM(&source.bp) };
                ddt_key_fill(&key.key, &source.bp);
                df_fdt_value_t value;
                uint64_t fdt_slot;
                error = dedup_fdt_index_find(&p->fdt, &key, &value, &fdt_slot, 0);
                if (error != 0)
                    return (error);
                ddt_bp_fill(&value.physical, DDT_PHYS_FLAT, &source.bp,
                    BP_GET_BIRTH(&source.bp));
            }
        } else if (owners != 0 && source.native_brt != owners-1) {
            return (ESTALE);
        } else if (owners == 0 && source.native_brt != 0) {
            return (ESTALE);
        }
        if (source.authentic && BP_GET_DEDUP(&source.bp)) {
            error = rebuild_native_ddt_refcount(p->spa, &source.bp, &observed);
            if (error != 0 || observed != source.native_ddt)
                return (error != 0 ? error : ESTALE);
        }
        if (source.selected) {
            if (!source.authentic || owners == 0 ||
                BP_GET_LEVEL(&source.bp) != 0 ||
                (BP_USES_CRYPT(&source.bp) && !BP_IS_ENCRYPTED(&source.bp)))
                return (ENOTSUP);
            p->counters.candidate_allocations++;
            if (p->total_hash_bytes > UINT64_MAX-BP_GET_LSIZE(&source.bp))
                return (EOVERFLOW);
            p->total_hash_bytes += BP_GET_LSIZE(&source.bp);
            p->max_size = MAX(p->max_size, BP_GET_LSIZE(&source.bp));
        }
        error = dedup_fdt_index_write(&p->sources, slot, &source);
        if (error != 0)
            return (error);
    }
    return (0);
}
/* Compact source descriptors, rather than payloads or one heap entry per
 * block, are externally sorted by actual top-level allocation location. */
typedef struct df_read_order {
    uint64_t vdev, offset, birth, slot, tag;
} df_read_order_t;
typedef struct df_read_item {
    df_read_order_t order;
    df_source_t source;
    abd_t *buffer;
    dedup_fdt_read_request_t request;
} df_read_item_t;

static df_read_order_t
df_order(const blkptr_t *bp, uint64_t slot, uint64_t tag)
{
    const dva_t *dva = BP_IDENTITY(bp);
    return ((df_read_order_t) { DVA_GET_VDEV(dva), DVA_GET_OFFSET(dva),
        BP_GET_PHYSICAL_BIRTH(bp), slot, tag });
}

static int
df_order_compare(const void *left, const void *right)
{
    const df_read_order_t *a = left, *b = right;
#define DF_ORDER_FIELD(field) \
    if (a->field != b->field) return (a->field < b->field ? -1 : 1)
    DF_ORDER_FIELD(vdev);
    DF_ORDER_FIELD(offset);
    DF_ORDER_FIELD(birth);
    DF_ORDER_FIELD(slot);
    DF_ORDER_FIELD(tag);
#undef DF_ORDER_FIELD
    return (0);
}

static int
df_sort_open(dedup_fdt_plan_t *p, dedup_fdt_sort_t **out)
{
    uint64_t bytes = MIN(dedup_fdt_resources_work_limit(p->options.resources) / 16,
        8ULL << 20);
    return (dedup_fdt_sort_open(p->options.resources, p->directory,
        sizeof (df_read_order_t), bytes, df_order_compare, out));
}

static int
df_buffers_open(dedup_fdt_plan_t *p)
{
    unsigned count = MAX(2u, p->options.workers);
    /* Do not spend the entire work budget on pinned payloads: coherent index
     * pages and merge descriptors must still have an evictable working set. */
    uint64_t target = dedup_fdt_resources_work_limit(p->options.resources) / 2;
    while (count > 2 && p->max_size > target / count)
        count--;
    int error;
    while ((error = dedup_fdt_memory_reserve(p->options.resources,
        p->max_size * count)) != 0 && count > 2)
        count--;
    if (error != 0)
        return (error);
    p->buffer_reservation = p->max_size * count;
    p->buffer_count = count;
    p->effective_workers = MIN(p->options.workers, count);
    for (unsigned i = 0; i < count; i++)
        p->buffers[i] = abd_alloc_for_io(p->max_size, B_FALSE);
    error = dedup_fdt_workers_open(p->options.resources, p->effective_workers,
        &p->workers);
    if (error == 0)
        p->effective_workers = dedup_fdt_workers_count(p->workers);
    return (error);
}

static void
df_buffers_close(dedup_fdt_plan_t *p)
{
    dedup_fdt_workers_close(p->workers);
    p->workers = NULL;
    for (unsigned i = 0; i < p->buffer_count; i++) {
        abd_free(p->buffers[i]);
        p->buffers[i] = NULL;
    }
    p->buffer_count = 0;
    dedup_fdt_memory_release(p->options.resources, p->buffer_reservation);
    p->buffer_reservation = 0;
}

/* Ordered native submissions, bounded by the admitted reusable buffers.
 * All started I/O is drained on every error before a buffer can be reused. */
static int
df_read_window(dedup_fdt_plan_t *p, df_read_item_t *items, unsigned count,
    boolean_t raw, const char *phase)
{
    qsort(items, count, sizeof (*items), df_order_compare);
    uint64_t window = ++p->read_window;
    int error = 0;
    for (unsigned base = 0; base < count && error == 0;) {
        unsigned started = 0;
        unsigned limit = MIN(count - base, p->effective_workers);
        for (; started < limit; started++) {
            df_read_item_t *item = &items[base + started];
            if (rebuild_interrupted()) { error = EINTR; break; }
            error = dedup_fdt_read_start(p->spa, &item->source.bp,
                &item->source.bookmark, item->buffer, raw, phase,
                p->read_pass, window,
                ++p->read_sequence, p->buffer_count, &item->request);
            if (error != 0)
                break;
            p->outstanding_reads++;
        }
        dedup_fdt_plan_progress(p, phase, B_FALSE);
        for (unsigned i = 0; i < started; i++) {
            df_read_item_t *item = &items[base + i];
            int e = dedup_fdt_read_wait(&item->request);
            if (error == 0)
                error = e;
            p->completed_reads++;
            p->outstanding_reads--;
            if (e == 0)
                p->counters.read_bytes += raw ? BP_GET_PSIZE(&item->source.bp) :
                    BP_GET_LSIZE(&item->source.bp);
        }
        base += started;
    }
    dedup_fdt_plan_progress(p, phase, B_FALSE);
    return (error);
}

static void
df_cpu_run(dedup_fdt_plan_t *p, unsigned count,
    void (*function)(void *, unsigned), void *arg)
{
    if (count == 0)
        return;
    struct timespec before, after;
    clock_gettime(CLOCK_MONOTONIC, &before);
    dedup_fdt_workers_run(p->workers, count, function, arg);
    clock_gettime(CLOCK_MONOTONIC, &after);
    p->cpu_tasks += count;
    p->cpu_batch_elapsed_ns += (uint64_t)(after.tv_sec - before.tv_sec) *
        1000000000 + after.tv_nsec - before.tv_nsec;
}

typedef struct df_hash_work {
    spa_t *spa;
    df_read_item_t *items;
    boolean_t raw;
} df_hash_work_t;

static void
df_hash_cpu(void *arg, unsigned index)
{
    df_hash_work_t *work = arg;
    df_read_item_t *item = &work->items[index];
    df_source_t *source = &item->source;
    if (work->raw) {
        blkptr_t canonical;
        dedup_fdt_stored_checksum(work->spa, &source->bp, item->buffer, &canonical);
        source->stored_checksum = canonical.blk_cksum;
    } else {
        dedup_fdt_fingerprint(work->spa, item->buffer,
            BP_GET_LSIZE(&source->bp), &source->digest);
        source->hashed = B_TRUE;
        /* Checked logical ZIO already authenticated this stored BLAKE3. */
        if (BP_GET_CHECKSUM(&source->bp) == ZIO_CHECKSUM_BLAKE3)
            source->stored_checksum = source->bp.blk_cksum;
    }
}

typedef struct df_compare_work {
    abd_t *left, *right;
    uint64_t size;
    int result;
} df_compare_work_t;

static void
df_compare_cpu(void *arg, unsigned index)
{
    df_compare_work_t *work = arg;
    work[index].result = df_compare(work[index].left, work[index].right,
        work[index].size);
}

static int
df_compare_batch(dedup_fdt_plan_t *p, df_compare_work_t *work, unsigned count)
{
    df_cpu_run(p, count, df_compare_cpu, work);
    for (unsigned i = 0; i < count; i++)
        if (work[i].result != 0)
            return (ECKSUM);
    return (0);
}

static int
df_hash_sources(dedup_fdt_plan_t *p)
{
    if (p->counters.candidate_allocations == 0)
        return (0);
    dedup_fdt_sort_t *sort = NULL;
    int error = df_sort_open(p, &sort);
    for (uint64_t slot = 1; error == 0 && slot <= p->sources.capacity; slot++) {
        df_source_t source;
        error = dedup_fdt_index_read(&p->sources, slot, NULL, &source);
        if (error == ENOENT) { error = 0; continue; }
        if (error == 0 && source.selected) {
            df_read_order_t order = df_order(&source.bp, slot, 0);
            error = dedup_fdt_sort_add(sort, &order);
        }
    }
    if (error == 0)
        error = dedup_fdt_sort_finish(sort);
    boolean_t end = B_FALSE;
    while (error == 0 && !end) {
        df_read_item_t items[64];
        unsigned count = 0;
        while (count < p->buffer_count) {
            df_read_item_t *item = &items[count];
            error = dedup_fdt_sort_next(sort, &item->order);
            if (error == ENOENT) { error = 0; end = B_TRUE; break; }
            if (error != 0)
                break;
            error = dedup_fdt_index_read(&p->sources, item->order.slot,
                NULL, &item->source);
            if (error != 0)
                break;
            item->buffer = p->buffers[count++];
        }
        if (error == 0)
            error = df_read_window(p, items, count, B_FALSE, "hashing");
        df_hash_work_t work = { .spa = p->spa, .items = items };
        if (error == 0)
            df_cpu_run(p, count, df_hash_cpu, &work);
        for (unsigned i = 0; error == 0 && i < count; i++)
            p->counters.logical_hashed_bytes += BP_GET_LSIZE(&items[i].source.bp);
        /* Non-BLAKE3 stored checksums are computed in the same physical window.
         * Keep logical fingerprints in the source rows, never payload maps. */
        df_read_item_t raw_items[64];
        unsigned raw_count = 0;
        for (unsigned i = 0; error == 0 && i < count; i++)
            if (BP_GET_CHECKSUM(&items[i].source.bp) != ZIO_CHECKSUM_BLAKE3)
                raw_items[raw_count++] = items[i];
        if (error == 0 && raw_count != 0)
            error = df_read_window(p, raw_items, raw_count, B_TRUE,
                "stored-checksum");
        work.items = raw_items;
        work.raw = B_TRUE;
        if (error == 0)
            df_cpu_run(p, raw_count, df_hash_cpu, &work);
        for (unsigned i = 0; error == 0 && i < raw_count; i++) {
            for (unsigned j = 0; j < count; j++)
                if (items[j].order.slot == raw_items[i].order.slot)
                    items[j].source.stored_checksum =
                        raw_items[i].source.stored_checksum;
        }
        for (unsigned i = 0; error == 0 && i < count; i++)
            error = dedup_fdt_index_write(&p->sources, items[i].order.slot,
                &items[i].source);
    }
    dedup_fdt_sort_close(sort);
    return (error);
}
static boolean_t
df_better(const df_source_t *candidate, const df_source_t *best)
{
    if (candidate->native_ddt != 0 && best->native_ddt == 0)
        return (B_TRUE);
    if (candidate->native_ddt == 0 && best->native_ddt != 0)
        return (B_FALSE);
    return (BP_GET_NDVAS(&candidate->bp) > BP_GET_NDVAS(&best->bp));
}
typedef struct df_compare_pair {
    uint64_t source, representative, size;
} df_compare_pair_t;

static int
df_verify_window(dedup_fdt_plan_t *p, df_read_item_t *items, unsigned count,
    df_compare_pair_t *pairs, unsigned pair_count, const char *phase)
{
    int error = df_read_window(p, items, count, B_FALSE, phase);
    df_compare_work_t work[64];
    for (unsigned i = 0; error == 0 && i < pair_count; i++) {
        abd_t *left = NULL, *right = NULL;
        for (unsigned j = 0; j < count; j++) {
            if (items[j].order.slot == pairs[i].source)
                left = items[j].buffer;
            if (items[j].order.slot == pairs[i].representative)
                right = items[j].buffer;
        }
        if (left == NULL || right == NULL)
            return (EINVAL);
        work[i] = (df_compare_work_t) { .left = left, .right = right,
            .size = pairs[i].size };
    }
    if (error == 0)
        error = df_compare_batch(p, work, pair_count);
    if (error != 0) {
        fprintf(stderr, "dedup-fdt: %s positive logical-byte comparison "
            "failed: %d\n", phase, error);
        return (error);
    }
    for (unsigned i = 0; i < pair_count; i++) {
        p->counters.verified_bytes += pairs[i].size;
        if (strcmp(phase, "anchors") == 0)
            p->native_anchor_comparisons++;
        else
            p->candidate_comparisons++;
    }
    return (error);
}

static int
df_verify_sources(dedup_fdt_plan_t *p, boolean_t anchors)
{
    dedup_fdt_sort_t *sort = NULL;
    int error = df_sort_open(p, &sort);
    uint64_t capacity = anchors ? p->groups.capacity : p->sources.capacity;
    for (uint64_t slot = 1; error == 0 && slot <= capacity; slot++) {
        df_source_t source;
        df_group_t group;
        uint64_t source_slot;
        if (anchors) {
            error = dedup_fdt_index_read(&p->groups, slot, NULL, &group);
            if (error == ENOENT) { error = 0; continue; }
            if (error != 0)
                break;
            if (group.anchor == 0 || group.skipped)
                continue;
            source_slot = group.anchor;
            error = dedup_fdt_index_read(&p->sources, source_slot, NULL, &source);
        } else {
            source_slot = slot;
            error = dedup_fdt_index_read(&p->sources, slot, NULL, &source);
            if (error == ENOENT) { error = 0; continue; }
            if (error != 0)
                break;
            if (!source.selected || source.group == 0)
                continue;
            error = dedup_fdt_index_read(&p->groups, source.group, NULL, &group);
            if (error == 0 && (group.members < 2 ||
                group.representative == source_slot))
                continue;
        }
        if (error == 0) {
            df_read_order_t order = df_order(&source.bp, source_slot,
                group.representative);
            error = dedup_fdt_sort_add(sort, &order);
        }
    }
    if (error == 0)
        error = dedup_fdt_sort_finish(sort);
    boolean_t end = B_FALSE, pending = B_FALSE;
    df_read_order_t order;
    while (error == 0 && !end) {
        df_read_item_t items[64];
        df_compare_pair_t pairs[64];
        unsigned count = 0, pair_count = 0;
        while (pair_count < 64) {
            if (!pending) {
                error = dedup_fdt_sort_next(sort, &order);
                if (error == ENOENT) { error = 0; end = B_TRUE; break; }
                if (error != 0)
                    break;
            }
            pending = B_TRUE;
            uint64_t read_slots[2] = {order.slot, order.tag};
            unsigned needed = 0;
            for (unsigned i = 0; i < 2; i++) {
                boolean_t present = B_FALSE;
                for (unsigned j = 0; j < count; j++)
                    present |= items[j].order.slot == read_slots[i];
                needed += !present;
            }
            if (count + needed > p->buffer_count)
                break;
            uint64_t size = 0;
            for (unsigned i = 0; error == 0 && i < 2; i++) {
                boolean_t present = B_FALSE;
                for (unsigned j = 0; j < count; j++)
                    if (items[j].order.slot == read_slots[i]) {
                        present = B_TRUE;
                        size = BP_GET_LSIZE(&items[j].source.bp);
                    }
                if (present)
                    continue;
                df_read_item_t *item = &items[count];
                error = dedup_fdt_index_read(&p->sources, read_slots[i],
                    NULL, &item->source);
                if (error == 0) {
                    item->order = df_order(&item->source.bp, read_slots[i], 0);
                    item->buffer = p->buffers[count++];
                    size = BP_GET_LSIZE(&item->source.bp);
                }
            }
            if (error != 0)
                break;
            pairs[pair_count++] = (df_compare_pair_t) {order.slot, order.tag, size};
            pending = B_FALSE;
        }
        if (error == 0 && count != 0)
            error = df_verify_window(p, items, count, pairs, pair_count,
                anchors ? "anchors" : "verifying");
    }
    dedup_fdt_sort_close(sort);
    return (error);
}

/* A native stored key is an index hint, never proof of logical equality.
 * Resolve only that key's already-inventoried authenticated occurrence; do
 * not fingerprint or scan unrelated unselected payloads. */
static int
df_choose_group(dedup_fdt_plan_t *p, uint64_t slot, df_group_t *group)
{
    df_source_t best;
    uint64_t chosen = group->best != 0 ? group->best : group->max_source;
    int error = dedup_fdt_index_read(&p->sources, chosen, NULL, &best);
    if (error != 0)
        return (error);
    if (BP_GET_NDVAS(&best.bp) < group->max_copies &&
        group->eligible_copies == group->max_copies) {
        chosen = group->eligible_max;
        error = dedup_fdt_index_read(&p->sources, chosen, NULL, &best);
        if (error != 0)
            return (error);
    }
    group->allocate = group->best == 0 ||
        BP_GET_NDVAS(&best.bp) < group->max_copies;
    if (group->allocate) {
        chosen = group->max_source;
        error = dedup_fdt_index_read(&p->sources, chosen, NULL, &best);
        if (error != 0)
            return (error);
    }
    group->best = chosen;
    if (best.native_ddt != 0 && !group->allocate) {
        group->canonical = best.bp;
        BP_SET_DEDUP(&group->canonical, 1);
    } else {
        group->canonical = best.bp;
        group->canonical.blk_cksum = best.stored_checksum;
        BP_SET_CHECKSUM(&group->canonical, ZIO_CHECKSUM_BLAKE3);
        BP_SET_DEDUP(&group->canonical, 1);
    }
    df_fdt_key_t key = { .checksum = BP_GET_CHECKSUM(&group->canonical) };
    ddt_key_fill(&key.key, &group->canonical);
    df_fdt_value_t value = {0};
    uint64_t fdt_slot;
    error = dedup_fdt_index_find(&p->fdt, &key, &value, &fdt_slot, 0);
    if (error == ENOENT) {
        if (group->members < 2)
            return (0);
        boolean_t admitted;
        error = rebuild_native_ddt_admit(p->spa, key.checksum,
            &key.key, 0, 0, &admitted, NULL);
        if (error != 0)
            return (error);
        if (!admitted) {
            group->skipped = B_TRUE;
            return (dedup_fdt_index_write(&p->groups, slot, group));
        }
        value.reserved_group = slot;
        error = dedup_fdt_index_find(&p->fdt, &key, &value, &fdt_slot, 1);
    }
    if (error != 0)
        return (error);
    if (value.existing && value.physical.ddp_flat.ddp_phys_birth != 0 &&
        (group->allocate || value.physical.ddp_flat.ddp_phys_birth !=
        BP_GET_PHYSICAL_BIRTH(&group->canonical) ||
        !DVA_EQUAL(&value.physical.ddp_flat.ddp_dva[0],
        BP_IDENTITY(&group->canonical)))) {
        df_identity_t identity = {
            .birth = value.physical.ddp_flat.ddp_phys_birth,
            .dva = { value.physical.ddp_flat.ddp_dva[0].dva_word[0],
            value.physical.ddp_flat.ddp_dva[0].dva_word[1] } };
        df_source_t anchor, representative;
        uint64_t anchor_slot;
        error = dedup_fdt_index_find(&p->sources, &identity, &anchor,
            &anchor_slot, 0);
        if (error == 0)
            error = dedup_fdt_index_read(&p->sources, group->representative,
                NULL, &representative);
        if (error != 0)
            return (error);
        ddt_key_t anchor_key;
        ddt_key_fill(&anchor_key, &anchor.bp);
        if (!anchor.authentic || !anchor.has_fdt || anchor.native_ddt == 0 ||
            !BP_GET_DEDUP(&anchor.bp) ||
            BP_GET_CHECKSUM(&anchor.bp) != key.checksum ||
            memcmp(&anchor_key, &key.key, sizeof (anchor_key)) != 0 ||
            anchor.domain != representative.domain ||
            BP_GET_LSIZE(&anchor.bp) != BP_GET_LSIZE(&representative.bp) ||
            DMU_OT_BYTESWAP(BP_GET_TYPE(&anchor.bp)) !=
            DMU_OT_BYTESWAP(BP_GET_TYPE(&representative.bp)) ||
            BP_GET_BYTEORDER(&anchor.bp) != BP_GET_BYTEORDER(&representative.bp) ||
            BP_USES_CRYPT(&anchor.bp) != BP_USES_CRYPT(&representative.bp) ||
            BP_IS_ENCRYPTED(&anchor.bp) != BP_IS_ENCRYPTED(&representative.bp) ||
            BP_GET_NDVAS(&anchor.bp) < group->max_copies ||
            (anchor.group != 0 && anchor.group != slot)) {
            fprintf(stderr, "dedup-fdt: matching native FDT key has "
                "incompatible canonical ownership or representation\n");
            return (ECKSUM);
        }
        /* Positive payload comparison is deferred into the externally ordered
         * anchor/representative stream. No history mapping is enabled yet. */
        group->anchor = anchor_slot;
        if (anchor.group == 0) {
            group->members++;
            anchor.group = slot;
            error = dedup_fdt_index_write(&p->sources, anchor_slot, &anchor);
            if (error != 0)
                return (error);
        }
        group->best = anchor_slot;
        group->canonical = anchor.bp;
        BP_SET_DEDUP(&group->canonical, 1);
        group->allocate = B_FALSE;
    }
    if (group->members < 2)
        return (0);
    ddt_univ_phys_t checked = {0};
    unsigned copies = BP_GET_NDVAS(&group->canonical);
    ddt_phys_extend(&checked, copies, &group->canonical);
    checked.ddp_trad[copies].ddp_refcnt = 1;
    error = rebuild_bridge_check(p->spa, &key.key, &checked, key.checksum);
    if (error != 0) {
        fprintf(stderr, "dedup-fdt: native canonical key admission "
            "failed: %d\n", error);
        return (error);
    }
    if ((value.existing && value.physical.ddp_flat.ddp_phys_birth != 0 &&
        (group->allocate || value.physical.ddp_flat.ddp_phys_birth !=
        BP_GET_PHYSICAL_BIRTH(&group->canonical) ||
        !DVA_EQUAL(&value.physical.ddp_flat.ddp_dva[0],
        BP_IDENTITY(&group->canonical)))) ||
        (value.reserved_group != 0 && value.reserved_group != slot)) {
        fprintf(stderr, "dedup-fdt: native FDT key reservation conflicts "
            "with another canonical group\n");
        return (ECKSUM);
    }
    value.reserved_group = slot;
    error = dedup_fdt_index_write(&p->fdt, fdt_slot, &value);
    if (error == 0)
        error = dedup_fdt_index_write(&p->groups, slot, group);
    return (error);
}

static int
df_groups(dedup_fdt_plan_t *p)
{
    if (p->counters.candidate_allocations == 0)
        return (0);
    /* Membership is coordinator-only scratch. No mapping is enabled until
     * every candidate has passed the bounded positive-comparison pass. */
    int error = 0;
    for (uint64_t slot = 1; error == 0 && slot <= p->sources.capacity; slot++) {
        df_source_t source;
        error = dedup_fdt_index_read(&p->sources, slot, NULL, &source);
        if (error == ENOENT) { error = 0; continue; }
        if (error != 0 || !source.selected)
            continue;
        if (!source.hashed) { error = EINVAL; break; }
        df_content_key_t key = { .digest = source.digest, .domain = source.domain,
            .type = DMU_OT_BYTESWAP(BP_GET_TYPE(&source.bp)),
            .byteorder = BP_GET_BYTEORDER(&source.bp),
            .logical_size = BP_GET_LSIZE(&source.bp) };
        df_group_t group = { .representative = slot };
        uint64_t group_slot;
        error = dedup_fdt_index_find(&p->groups, &key, &group, &group_slot, 1);
        if (error != 0)
            break;
        group.members++;
        if (BP_GET_NDVAS(&source.bp) > group.max_copies) {
            group.max_copies = BP_GET_NDVAS(&source.bp);
            group.max_source = slot;
        }
        if (source.native_ddt != 0 || !source.unselected) {
            if (BP_GET_NDVAS(&source.bp) > group.eligible_copies) {
                group.eligible_copies = BP_GET_NDVAS(&source.bp);
                group.eligible_max = slot;
            }
            boolean_t choose = group.best == 0;
            if (!choose) {
                df_source_t best;
                error = dedup_fdt_index_read(&p->sources, group.best, NULL, &best);
                if (error != 0)
                    break;
                choose = df_better(&source, &best);
            }
            if (choose)
                group.best = slot;
        }
        source.group = group_slot;
        error = dedup_fdt_index_write(&p->groups, group_slot, &group);
        if (error == 0)
            error = dedup_fdt_index_write(&p->sources, slot, &source);
        dedup_fdt_plan_progress(p, "verifying", B_FALSE);
    }
    if (error == 0)
        error = df_verify_sources(p, B_FALSE);
    if (error != 0)
        return (error);
    for (uint64_t slot = 1; slot <= p->groups.capacity; slot++) {
        df_group_t group;
        error = dedup_fdt_index_read(&p->groups, slot, NULL, &group);
        if (error == ENOENT) { error = 0; continue; }
        if (error != 0)
            break;
        error = df_choose_group(p, slot, &group);
        if (error != 0)
            break;
        if (group.members < 2)
            continue;
        if (group.skipped) {
            p->counters.skipped_groups++;
            p->counters.skipped_blocks += group.members;
            continue;
        }
        p->counters.duplicate_groups++;
        p->counters.changed_allocations += group.members-(!group.allocate);
        p->counters.new_canonicals += group.allocate;
    }
    if (error == 0)
        error = df_verify_sources(p, B_TRUE);
    if (error != 0)
        return (error);
    for (uint64_t slot = 1; slot <= p->sources.capacity; slot++) {
        df_source_t source;
        error = dedup_fdt_index_read(&p->sources, slot, NULL, &source);
        if (error == ENOENT)
            continue;
        if (error != 0)
            return (error);
        if (!source.latent_zil || source.group == 0)
            continue;
        df_group_t group;
        error = dedup_fdt_index_read(&p->groups, source.group, NULL, &group);
        if (error != 0)
            return (error);
        if (group.members > 1 && !group.skipped) {
            fprintf(stderr, "dedup-fdt: affected non-release ZIL reference; "
                "resolve claim/replay before offline data remapping\n");
            return (ENOTSUP);
        }
    }
    p->ready = B_TRUE;
    return (0);
}

static void
df_metadata(void *arg, const blkptr_t *bp)
{
    dedup_fdt_plan_t *p = arg;
    p->counters.metadata_visits++;
    if (!BP_IS_HOLE(bp) && !BP_IS_EMBEDDED(bp)) {
        uint64_t bytes = bp_get_dsize(p->spa, bp);
        if (bytes > (UINT64_MAX-p->metadata_space)/4)
            p->space_overflow = B_TRUE;
        else
            p->metadata_space += bytes*4;
    }
    dedup_fdt_plan_progress(p, "metadata", p->counters.metadata_visits == 1);
}

static void
df_root(void *arg, const blkptr_t *before, const blkptr_t *after)
{
    dedup_fdt_plan_t *p = arg;
    if (memcmp(before, after, sizeof (*before)) != 0)
        p->counters.rewritten_roots++;
}

int
dedup_fdt_plan_history(dedup_fdt_plan_t *p, spa_t *spa, uint64_t stage,
    rebuild_history_t **out)
{
    p->spa = spa;
    dsl_pool_t *dp = spa_get_dsl(spa);
    for (size_t i = 0; i < p->dataset_count; i++) {
        dsl_dataset_t *ds;
        dsl_pool_config_enter(dp, p);
        int error = dsl_dataset_hold_obj(dp, p->datasets[i].object, p, &ds);
        dsl_pool_config_exit(dp, p);
        if (error != 0)
            return (error);
        boolean_t same = memcmp(dsl_dataset_phys(ds), &p->datasets[i].original,
            sizeof (p->datasets[i].original)) == 0;
        dsl_dataset_rele(ds, p);
        if (!same)
            return (ESTALE);
    }
    int error = rebuild_history_open_resources(spa, stage,
        p->options.batch_size, p->options.resources, out);
    if (error != 0)
        return (error);
    rebuild_history_data_ops_t ops = { .rhd_map = df_map,
        .rhd_variant = df_variant, .rhd_metadata = df_metadata,
        .rhd_root = df_root, .rhd_arg = p,
        .rhd_resources = p->options.resources };
    error = rebuild_history_set_data_ops(*out, &ops);
    if (error == 0)
        error = rebuild_history_check(*out);
    if (error != 0) {
        rebuild_history_close(*out);
        *out = NULL;
    }
    return (error);
}

/*
 * Read-only admission estimate. Native assigned tasks still reserve their
 * exact allocation work and can abort safely on a later allocator/I/O error.
 * Retirements cannot fund staging: predecessor data stays allocated until
 * after the single publication TXG.
 */
static int
df_budget(dedup_fdt_plan_t *p)
{
    const dedup_fdt_index_t *indices[] = {
        &p->sources, &p->groups, &p->aliases, &p->fdt };
    for (size_t i = 0; i < sizeof (indices)/sizeof (*indices); i++) {
        uint64_t bytes = indices[i]->capacity*indices[i]->stride;
        if (bytes > UINT64_MAX-p->index_bytes)
            return (EOVERFLOW);
        p->index_bytes += bytes;
    }
    if (p->counters.duplicate_groups == 0)
        return (0);
    if (p->space_overflow || p->metadata_space > UINT64_MAX-(32ULL<<20))
        return (EOVERFLOW);
    uint64_t need = p->metadata_space+(32ULL<<20);
    uint64_t entries = p->flat_count+p->counters.duplicate_groups;
    if (entries > (UINT64_MAX-need)/4096)
        return (EOVERFLOW);
    need += entries*4096;
    if (p->counters.candidate_allocations > (UINT64_MAX-need)/512)
        return (EOVERFLOW);
    need += p->counters.candidate_allocations*512;
    for (uint64_t slot = 1; slot <= p->groups.capacity; slot++) {
        df_group_t group;
        int error = dedup_fdt_index_read(&p->groups, slot, NULL, &group);
        if (error == ENOENT)
            continue;
        if (error != 0)
            return (error);
        if (group.members < 2 || group.skipped || !group.allocate)
            continue;
        uint64_t bytes = bp_get_dsize(p->spa, &group.canonical);
        if (bytes > UINT64_MAX-need)
            return (EOVERFLOW);
        need += bytes;
    }
    for (uint64_t slot = 1; slot <= p->sources.capacity; slot++) {
        df_source_t source;
        int error = dedup_fdt_index_read(&p->sources, slot, NULL, &source);
        if (error == ENOENT)
            continue;
        if (error != 0)
            return (error);
        if (source.group == 0 || source.unselected)
            continue;
        df_group_t group;
        error = dedup_fdt_index_read(&p->groups, source.group, NULL, &group);
        if (error != 0)
            return (error);
        if (group.members < 2 || group.skipped || (!group.allocate &&
            df_same_allocation(&source.bp, &group.canonical)))
            continue;
        uint64_t bytes = bp_get_dsize(p->spa, &source.bp);
        if (bytes > UINT64_MAX-p->projected_retire_bytes)
            return (EOVERFLOW);
        p->projected_retire_bytes += bytes;
    }
    p->projected_stage_bytes = need;
    dsl_pool_t *dp = spa_get_dsl(p->spa);
    uint64_t quota = dsl_pool_unreserved_space(dp, ZFS_SPACE_CHECK_NORMAL);
    uint64_t used = dsl_dir_phys(dp->dp_root_dir)->dd_used_bytes;
    if (used > quota || need > quota-used) {
        fprintf(stderr, "dedup-fdt: estimated staging needs %llu bytes; "
            "native unreserved headroom is %llu bytes\n", (u_longlong_t)need,
            (u_longlong_t)(used <= quota ? quota-used : 0));
        return (ENOSPC);
    }
    return (0);
}

int
dedup_fdt_plan_create(spa_t *spa, int directory,
    const dedup_fdt_options_t *options, dedup_fdt_plan_t **out)
{
    if (options == NULL || options->workers == 0 || options->workers > 64 ||
        options->dataset_count == 0 || options->batch_size == 0 ||
        options->resources == NULL)
        return (EINVAL);
    int error = dedup_fdt_memory_reserve(options->resources,
        sizeof (dedup_fdt_plan_t));
    if (error != 0)
        return (error);
    dedup_fdt_plan_t *p = calloc(1, sizeof (*p));
    if (p == NULL) {
        dedup_fdt_memory_release(options->resources, sizeof (*p));
        return (ENOMEM);
    }
    p->sources.file.fd = p->groups.file.fd = p->aliases.file.fd =
        p->fdt.file.fd = -1;
    p->flat_output.fd = p->brt_output.fd = -1;
    p->options = *options;
    p->read_pass = __atomic_add_fetch(&df_next_read_pass, 1, __ATOMIC_RELAXED);
    p->spa = spa;
    p->directory = directory;
    pthread_mutex_init(&p->progress_lock, NULL);
    clock_gettime(CLOCK_MONOTONIC, &p->started);
    p->last_progress = p->started;
    rebuild_history_t *history = NULL;
    rebuild_bridge_t *native_view = NULL;
    error = rebuild_bridge_open(spa, 0, options->batch_size, &native_view);
    if (error == 0)
        error = rebuild_bridge_set_source(native_view, NULL, NULL, 0);
    if (error == 0)
        error = rebuild_bridge_validate(native_view);
    rebuild_bridge_close(native_view);
    if (error == 0)
        error = df_collect_datasets(p);
    if (error == 0)
        error = dedup_fdt_plan_history(p, spa, 0, &history);
    if (error == 0)
        error = rebuild_bridge_foreach_flat(spa, df_flat_count, p);
    if (error == 0)
        error = rebuild_history_foreach_data(history, B_FALSE, df_count, p);
    if (error == 0 && p->references > (UINT64_MAX-p->flat_count)/2)
        error = EOVERFLOW;
    uint64_t allocations = error == 0 ? 2*p->references+p->flat_count : 0;
    if (error == 0)
        error = dedup_fdt_index_create(options->resources, directory, "dedup-fdt.sources",
            allocations, sizeof (df_identity_t), sizeof (df_source_t), &p->sources);
    if (error == 0)
        error = dedup_fdt_index_create(options->resources, directory, "dedup-fdt.aliases",
            p->references, sizeof (df_alias_key_t), sizeof (blkptr_t), &p->aliases);
    if (error == 0)
        error = dedup_fdt_index_create(options->resources, directory, "dedup-fdt.content",
            p->references, sizeof (df_content_key_t), sizeof (df_group_t), &p->groups);
    if (error == 0)
        error = dedup_fdt_index_create(options->resources, directory, "dedup-fdt.fdt",
            p->references+p->flat_count, sizeof (df_fdt_key_t),
            sizeof (df_fdt_value_t), &p->fdt);
    if (error == 0)
        error = rebuild_bridge_foreach_flat(spa, df_flat_inventory, p);
    if (error == 0)
        error = rebuild_history_foreach_data(history, B_FALSE, df_inventory, p);
    if (error == 0)
        error = df_sources_check(p);
    if (error == 0 && p->counters.candidate_allocations != 0)
        error = df_buffers_open(p);
    if (error == 0)
        error = df_hash_sources(p);
    if (error == 0)
        error = df_groups(p);
    df_buffers_close(p);
    if (error == 0)
        p->needs_claim = rebuild_history_needs_claim(history);
    rebuild_history_close(history);
    if (error == 0)
        error = df_budget(p);
    if (error == 0)
        error = dedup_fdt_index_sync(&p->sources);
    if (error == 0)
        error = dedup_fdt_index_sync(&p->groups);
    if (error == 0)
        error = dedup_fdt_index_sync(&p->fdt);
    if (error != 0) {
        dedup_fdt_plan_close(p);
        return (error);
    }
    p->ready = B_TRUE;
    *out = p;
    return (0);
}

/* Native quota admission precedes canonical DATA allocations and every
 * historical mapping. The returned bridge owns the same measured shadow
 * objects later populated with exact post-history counts. */
int
dedup_fdt_plan_admit(dedup_fdt_plan_t *p, spa_t *spa, uint64_t stage,
    rebuild_bridge_t **bridge_out)
{
    if (p == NULL || !p->ready || spa == NULL || stage == 0 ||
        bridge_out == NULL || *bridge_out != NULL)
        return (EINVAL);
    p->spa = spa;
    int error = rebuild_bridge_admit_open(spa, stage, p->options.batch_size,
        bridge_out);
    if (error != 0)
        return (error);
    p->counters.duplicate_groups = 0;
    p->counters.changed_allocations = 0;
    p->counters.new_canonicals = 0;
    p->counters.skipped_groups = 0;
    p->counters.skipped_blocks = 0;
    for (uint64_t slot = 1; slot <= p->groups.capacity; slot++) {
        df_group_t group;
        error = dedup_fdt_index_read(&p->groups, slot, NULL, &group);
        if (error == ENOENT) { error = 0; continue; }
        if (error != 0)
            return (error);
        if (group.members < 2)
            continue;
        df_fdt_key_t key = { .checksum = BP_GET_CHECKSUM(&group.canonical) };
        ddt_key_fill(&key.key, &group.canonical);
        ddt_univ_phys_t flat = {0};
        ddt_phys_extend(&flat, DDT_PHYS_FLAT, &group.canonical);
        flat.ddp_flat.ddp_refcnt = group.members;
        flat.ddp_flat.ddp_class_start = gethrestime_sec();
        boolean_t admitted;
        error = rebuild_bridge_admit(*bridge_out, key.checksum, &key.key,
            &flat, &admitted);
        if (error != 0)
            return (error); /* I/O/corruption/ENOSPC are never quota skips. */
        group.skipped = !admitted;
        df_fdt_value_t value = {0};
        uint64_t fdt_slot;
        error = dedup_fdt_index_find(&p->fdt, &key, &value, &fdt_slot,
            admitted);
        if (error == ENOENT && !admitted)
            error = 0;
        else if (error == 0) {
            if (admitted && value.reserved_group != 0 &&
                value.reserved_group != slot)
                return (ECKSUM);
            value.reserved_group = admitted ? slot : 0;
            error = dedup_fdt_index_write(&p->fdt, fdt_slot, &value);
        }
        if (error == 0)
            error = dedup_fdt_index_write(&p->groups, slot, &group);
        if (error != 0)
            return (error);
        if (admitted) {
            p->counters.duplicate_groups++;
            p->counters.changed_allocations += group.members - !group.allocate;
            p->counters.new_canonicals += group.allocate;
        } else {
            p->counters.skipped_groups++;
            p->counters.skipped_blocks += group.members;
        }
        dedup_fdt_plan_progress(p, "native-quota", B_FALSE);
    }
    /* Erase rejected anchors/candidates explicitly so post-history canonical
     * and retirement classification cannot mistake them for published ones. */
    for (uint64_t slot = 1; slot <= p->sources.capacity; slot++) {
        df_source_t source;
        error = dedup_fdt_index_read(&p->sources, slot, NULL, &source);
        if (error == ENOENT) { error = 0; continue; }
        if (error != 0)
            return (error);
        if (source.group == 0)
            continue;
        df_group_t group;
        error = dedup_fdt_index_read(&p->groups, source.group, NULL, &group);
        if (error != 0)
            return (error);
        if (group.skipped) {
            source.group = 0;
            error = dedup_fdt_index_write(&p->sources, slot, &source);
            if (error != 0)
                return (error);
        }
    }
    return (0);
}

typedef struct df_allocate_task {
    dedup_fdt_plan_t *plan;
    uint64_t ledger;
    df_source_t source;
    blkptr_t template, canonical;
    abd_t *raw;
    int error;
} df_allocate_task_t;

static void
df_allocate_sync(void *arg, dmu_tx_t *tx)
{
    df_allocate_task_t *task = arg;
    task->error = dedup_fdt_data_allocate(task->plan->spa, task->ledger,
        &task->template, task->raw, &task->source.bookmark, task->source.domain,
        tx, &task->canonical);
}

int
dedup_fdt_plan_allocate(dedup_fdt_plan_t *p, uint64_t ledger)
{
    if (p == NULL || !p->ready || ledger == 0)
        return (EINVAL);
    if (p->counters.new_canonicals == 0)
        return (0);
    dedup_fdt_sort_t *sort = NULL;
    int error = df_sort_open(p, &sort);
    for (uint64_t slot = 1; error == 0 && slot <= p->groups.capacity; slot++) {
        df_group_t group;
        error = dedup_fdt_index_read(&p->groups, slot, NULL, &group);
        if (error == ENOENT) { error = 0; continue; }
        if (error != 0)
            break;
        if (group.members < 2 || group.skipped || !group.allocate)
            continue;
        df_source_t source;
        error = dedup_fdt_index_read(&p->sources, group.best, NULL, &source);
        if (error == 0) {
            df_read_order_t order = df_order(&source.bp, group.best, slot);
            error = dedup_fdt_sort_add(sort, &order);
        }
    }
    if (error == 0)
        error = dedup_fdt_sort_finish(sort);
    if (error == 0)
        error = df_buffers_open(p);
    boolean_t end = B_FALSE;
    while (error == 0 && !end) {
        df_read_item_t items[64];
        df_allocate_task_t tasks[32];
        df_group_t groups[32];
        uint64_t slots[32];
        unsigned count = 0;
        while (count < p->buffer_count / 2) {
            df_read_item_t *item = &items[count];
            error = dedup_fdt_sort_next(sort, &item->order);
            if (error == ENOENT) { error = 0; end = B_TRUE; break; }
            if (error != 0)
                break;
            error = dedup_fdt_index_read(&p->sources, item->order.slot,
                NULL, &item->source);
            if (error != 0)
                break;
            item->buffer = p->buffers[count++];
        }
        if (error == 0)
            error = df_read_window(p, items, count, B_TRUE, "canonical-source");
        /* Source reads can overlap. Assigned-TXG allocations and durable DATA
         * ledger insertion remain serialized and precede all readbacks. */
        for (unsigned i = 0; error == 0 && i < count; i++) {
            slots[i] = items[i].order.tag;
            error = dedup_fdt_index_read(&p->groups, slots[i], NULL, &groups[i]);
            if (error != 0)
                break;
            tasks[i] = (df_allocate_task_t) { .plan = p, .ledger = ledger,
                .raw = items[i].buffer, .source = items[i].source,
                .template = groups[i].canonical };
            error = dsl_sync_task(spa_name(p->spa), NULL, df_allocate_sync,
                &tasks[i], 16, ZFS_SPACE_CHECK_NORMAL);
            if (error == 0)
                error = tasks[i].error;
            if (error != 0)
                break;
            ddt_key_t before, after;
            ddt_key_fill(&before, &groups[i].canonical);
            ddt_key_fill(&after, &tasks[i].canonical);
            if (memcmp(&before, &after, sizeof (before)) != 0 ||
                (BP_IS_ENCRYPTED(&groups[i].canonical) &&
                BP_GET_IV2(&groups[i].canonical) !=
                BP_GET_IV2(&tasks[i].canonical)))
                error = ECKSUM;
        }
        for (unsigned i = 0; error == 0 && i < count; i++) {
            items[i] = (df_read_item_t) {
                .order = df_order(&tasks[i].source.bp, i * 2 + 1, 0),
                .source = tasks[i].source, .buffer = p->buffers[i] };
            df_source_t canonical = { .bp = tasks[i].canonical,
                .bookmark = tasks[i].source.bookmark };
            /* Unpublished canonical is owned by DATA ledger, not live DDT. */
            BP_SET_DEDUP(&canonical.bp, 0);
            items[count + i] = (df_read_item_t) {
                .order = df_order(&canonical.bp, i * 2 + 2, 0),
                .source = canonical, .buffer = p->buffers[count + i] };
        }
        if (error == 0)
            error = df_read_window(p, items, 2 * count, B_FALSE,
                "canonical-readback");
        df_compare_work_t comparisons[32];
        for (unsigned i = 0; error == 0 && i < count; i++)
            comparisons[i] = (df_compare_work_t) { .left = p->buffers[i],
                .right = p->buffers[count + i],
                .size = BP_GET_LSIZE(&tasks[i].canonical) };
        if (error == 0)
            error = df_compare_batch(p, comparisons, count);
        for (unsigned i = 0; error == 0 && i < count; i++) {
            uint64_t size = BP_GET_LSIZE(&tasks[i].canonical);
            p->counters.verified_bytes += size;
            groups[i].canonical = tasks[i].canonical;
            error = dedup_fdt_index_write(&p->groups, slots[i], &groups[i]);
            df_source_t source = { .bp = tasks[i].canonical,
                .bookmark = tasks[i].source.bookmark,
                .domain = tasks[i].source.domain, .new_allocation = B_TRUE,
                .authentic = B_TRUE, .group = slots[i] };
            BP_SET_DEDUP(&source.bp, 0);
            df_identity_t identity = df_identity(&source.bp);
            uint64_t new_slot;
            if (error == 0)
                error = dedup_fdt_index_find(&p->sources, &identity, &source,
                    &new_slot, 1);
        }
        dedup_fdt_plan_progress(p, "allocating", B_FALSE);
    }
    /* On failure all new allocations remain durable ledger-owned. No history
     * BP was published, and the existing abort path drains that ledger. */
    df_buffers_close(p);
    dedup_fdt_sort_close(sort);
    return (error);
}

static int
df_post_owner(void *arg, uint64_t owner, const zbookmark_phys_t *bookmark,
    const blkptr_t *bp, unsigned flags)
{
    dedup_fdt_plan_t *p = arg;
    df_identity_t key = df_identity(bp);
    df_source_t source;
    uint64_t slot;
    int error = dedup_fdt_index_find(&p->sources, &key, &source, &slot, 0);
    if (error != 0) {
        fprintf(stderr, "dedup-fdt: prepared source lookup owner=%llu "
            "flags=%u object=%llu level=%lld blkid=%llu birth=%llu "
            "physical_birth=%llu type=%u dedup=%u "
            "dva0=%016llx:%016llx error=%d\n", (u_longlong_t)owner, flags,
            (u_longlong_t)(bookmark != NULL ? bookmark->zb_object : 0),
            (long long)(bookmark != NULL ? bookmark->zb_level : 0),
            (u_longlong_t)(bookmark != NULL ? bookmark->zb_blkid : 0),
            (u_longlong_t)BP_GET_BIRTH(bp),
            (u_longlong_t)BP_GET_PHYSICAL_BIRTH(bp),
            (unsigned)BP_GET_TYPE(bp), (unsigned)BP_GET_DEDUP(bp),
            (u_longlong_t)key.dva[0], (u_longlong_t)key.dva[1], error);
        return (error);
    }
    if (!(flags & REBUILD_DATA_AUXILIARY) && df_selected(p, owner) &&
        source.group != 0) {
        df_group_t group;
        error = dedup_fdt_index_read(&p->groups, source.group, NULL, &group);
        if (error != 0)
            return (error);
        if (group.members > 1 && !group.skipped) {
            blkptr_t expected = group.canonical;
            BP_SET_TYPE(&expected, BP_GET_TYPE(bp));
            BP_SET_FILL(&expected, BP_GET_FILL(bp));
            BP_SET_BIRTH(&expected, BP_GET_BIRTH(bp),
                BP_GET_PHYSICAL_BIRTH(&group.canonical));
            BP_SET_REWRITE(&expected, 0);
            if (memcmp(&expected, bp, sizeof (*bp)) != 0)
                return (ESTALE);
        }
    }
    if (flags & REBUILD_DATA_OWNER) {
        uint64_t *count = flags & REBUILD_DATA_FREE ? &source.post_frees :
            &source.post_allocations;
        if (*count == UINT64_MAX)
            return (EOVERFLOW);
        (*count)++;
        error = dedup_fdt_index_write(&p->sources, slot, &source);
    }
    return (error);
}


typedef struct df_retire_task {
    dedup_fdt_plan_t *plan;
    uint64_t ledger;
    dedup_fdt_data_record_t record;
    int error;
} df_retire_task_t;

static void
df_retire_sync(void *arg, dmu_tx_t *tx)
{
    df_retire_task_t *task = arg;
    task->error = dedup_fdt_data_retire(task->plan->spa, task->ledger,
        &task->record, tx);
}

int
dedup_fdt_plan_prepared(dedup_fdt_plan_t *p, rebuild_history_t *history,
    uint64_t retirement_ledger)
{
    if (p == NULL || history == NULL || retirement_ledger == 0 ||
        p->flat_output.fd >= 0 || p->brt_output.fd >= 0)
        return (EINVAL);
    int error = rebuild_history_foreach_data(history, B_TRUE, df_post_owner, p);
    if (error != 0)
        return (error);
    error = dedup_fdt_file_create(p->options.resources, p->directory,
        "dedup-fdt.flat", &p->flat_output);
    if (error == 0)
        error = dedup_fdt_file_create(p->options.resources, p->directory,
            "dedup-fdt.brt", &p->brt_output);
    if (error != 0)
        return (error);
    for (uint64_t slot = 1; slot <= p->sources.capacity; slot++) {
        df_source_t source;
        error = dedup_fdt_index_read(&p->sources, slot, NULL, &source);
        if (error == ENOENT)
            continue;
        if (error != 0)
            return (error);
        if (source.post_frees > source.post_allocations)
            return (EINVAL);
        uint64_t owners = source.post_allocations-source.post_frees;
        boolean_t canonical = source.new_allocation;
        df_group_t group = {0};
        if (source.group != 0) {
            error = dedup_fdt_index_read(&p->groups, source.group, NULL, &group);
            if (error != 0)
                return (error);
            canonical |= group.members > 1 && !group.skipped &&
                df_same_allocation(&source.bp, &group.canonical);
        }
        if (source.unselected_live && owners == 0 &&
            source.allocations != source.frees)
            return (ESTALE);
        if (canonical && owners == 0)
            return (ESTALE);
        if (source.native_ddt != 0 && !canonical &&
            (source.group == 0 || group.members < 2)) {
            if (owners != source.native_ddt)
                return (ESTALE);
        } else if (source.native_ddt != 0 || canonical) {
            const blkptr_t *bp = canonical && !source.new_allocation ?
                &group.canonical : &source.bp;
            df_fdt_key_t key = { .checksum = BP_GET_CHECKSUM(bp) };
            ddt_key_fill(&key.key, bp);
            df_fdt_value_t value;
            uint64_t fdt_slot;
            error = dedup_fdt_index_find(&p->fdt, &key, &value, &fdt_slot, 0);
            if (error != 0) {
                fprintf(stderr, "dedup-fdt: prepared FDT key lookup "
                    "source_slot=%llu group=%llu native_ddt=%llu "
                    "new_allocation=%u canonical=%u checksum=%u "
                    "physical_birth=%llu error=%d\n", (u_longlong_t)slot,
                    (u_longlong_t)source.group, (u_longlong_t)source.native_ddt,
                    (unsigned)source.new_allocation, (unsigned)canonical,
                    (unsigned)key.checksum,
                    (u_longlong_t)BP_GET_PHYSICAL_BIRTH(bp), error);
                return (error);
            }
            if (owners == 0) {
                /* A changed-to-zero predecessor has exactly ONE release
                 * owner: our typed retirement ledger, not a native log. */
                memset(&value.physical, 0, sizeof (value.physical));
            } else {
                memset(&value.physical, 0, sizeof (value.physical));
                ddt_phys_extend(&value.physical, DDT_PHYS_FLAT, bp);
                value.physical.ddp_flat.ddp_refcnt = owners;
                value.physical.ddp_flat.ddp_class_start = gethrestime_sec();
            }
            error = dedup_fdt_index_write(&p->fdt, fdt_slot, &value);
            if (error != 0)
                return (error);
        }
        uint64_t extra = source.native_ddt != 0 || canonical || owners == 0 ?
            0 : owners-1;
        if (extra != source.native_brt) {
            df_brt_record_t record = { .bp = source.bp,
                .before = source.native_brt, .after = extra };
            BP_SET_DEDUP(&record.bp, 0);
            error = dedup_fdt_file_resize(&p->brt_output,
                (p->output_brt_count + 1) * sizeof (record));
            if (error == 0)
                error = dedup_fdt_file_pwrite(&p->brt_output, &record,
                    sizeof (record), p->output_brt_count * sizeof (record));
            if (error != 0)
                return (error);
            p->output_brt_count++;
        }
        if (owners == 0 && source.allocations != source.frees &&
            !source.new_allocation) {
            if (source.group == 0 || group.members < 2 || group.skipped)
                return (ESTALE);
            df_retire_task_t task = { .plan = p, .ledger = retirement_ledger,
                .record = { .dfr_bp = source.bp, .dfr_bookmark = source.bookmark,
                .dfr_domain = source.domain, .dfr_source_ddt = source.native_ddt,
                .dfr_source_brt = source.native_brt, .dfr_remaining = 0,
                .dfr_audit_txg = p->spa->spa_uberblock.ub_txg } };
            BP_SET_DEDUP(&task.record.dfr_bp, 0);
            error = dsl_sync_task(spa_name(p->spa), NULL, df_retire_sync,
                &task, 8, ZFS_SPACE_CHECK_NORMAL);
            if (error == 0)
                error = task.error;
            if (error != 0)
                return (error);
        }
    }
    for (uint64_t slot = 1; slot <= p->fdt.capacity; slot++) {
        df_fdt_key_t key;
        df_fdt_value_t value;
        error = dedup_fdt_index_read(&p->fdt, slot, &key, &value);
        if (error == ENOENT)
            continue;
        if (error != 0)
            return (error);
        if (!value.existing && value.reserved_group == 0)
            continue; /* rejected provisional key never enters final shadow */
        df_flat_record_t record = { .checksum = key.checksum, .key = key.key,
            .physical = value.physical };
        error = dedup_fdt_file_resize(&p->flat_output,
            (p->output_flat_count + 1) * sizeof (record));
        if (error == 0)
            error = dedup_fdt_file_pwrite(&p->flat_output, &record,
                sizeof (record), p->output_flat_count * sizeof (record));
        if (error != 0)
            return (error);
        p->output_flat_count++;
    }
    error = dedup_fdt_file_sync(&p->flat_output);
    if (error == 0)
        error = dedup_fdt_file_sync(&p->brt_output);
    if (error != 0)
        return (error);
    p->counters.fdt_entries = p->output_flat_count;
    return (dedup_fdt_index_sync(&p->aliases));
}

static int
df_flat_read(void *arg, uint64_t index, enum zio_checksum *checksum,
    ddt_key_t *key, ddt_univ_phys_t *physical, int *canonical)
{
    dedup_fdt_plan_t *p = arg;
    df_flat_record_t record;
    if (index >= p->output_flat_count)
        return (EINVAL);
    int error = dedup_fdt_file_pread(&p->flat_output, &record,
        sizeof (record), index * sizeof (record));
    if (error != 0)
        return (error);
    *checksum = record.checksum;
    *key = record.key;
    *physical = record.physical;
    *canonical = DDT_PHYS_FLAT;
    return (0);
}

static int
df_brt_read(void *arg, uint64_t index, blkptr_t *bp,
    uint64_t *before, uint64_t *after)
{
    dedup_fdt_plan_t *p = arg;
    df_brt_record_t record;
    if (index >= p->output_brt_count)
        return (EINVAL);
    int error = dedup_fdt_file_pread(&p->brt_output, &record,
        sizeof (record), index * sizeof (record));
    if (error != 0)
        return (error);
    *bp = record.bp;
    *before = record.before;
    *after = record.after;
    return (0);
}

int
dedup_fdt_plan_bridge(dedup_fdt_plan_t *p, rebuild_bridge_t *bridge)
{
    if (p == NULL || p->flat_output.fd < 0 || p->brt_output.fd < 0)
        return (EINVAL);
    return (rebuild_bridge_set_flat_source(bridge, df_flat_read, p,
        p->output_flat_count, df_brt_read, p, p->output_brt_count));
}

static void
df_json_resources(dedup_fdt_plan_t *p)
{
    printf(",\"effective_workers\":%u,\"outstanding_reads\":%llu,"
        "\"completed_reads\":%llu,\"read_window\":%llu,"
        "\"read_pass\":%llu,\"cpu_tasks\":%llu,\"cpu_batch_elapsed_ns\":%llu,"
        "\"candidate_comparisons\":%llu,\"native_anchor_comparisons\":%llu,"
        "\"native_quota_skipped_groups\":%llu,"
        "\"native_quota_skipped_blocks\":%llu,\"resources\":{",
        p->effective_workers, (u_longlong_t)p->outstanding_reads,
        (u_longlong_t)p->completed_reads, (u_longlong_t)p->read_window,
        (u_longlong_t)p->read_pass, (u_longlong_t)p->cpu_tasks,
        (u_longlong_t)p->cpu_batch_elapsed_ns,
        (u_longlong_t)p->candidate_comparisons,
        (u_longlong_t)p->native_anchor_comparisons,
        (u_longlong_t)p->counters.skipped_groups,
        (u_longlong_t)p->counters.skipped_blocks);
    dedup_fdt_resource_stats_t stats;
    dedup_fdt_resources_stats(p->options.resources, &stats);
    printf("\"memory_max\":%llu", (u_longlong_t)stats.memory_max);
#define DF_RESOURCE_FIELD(field) \
    printf(",\"" #field "\":%llu", (u_longlong_t)stats.field)
    DF_RESOURCE_FIELD(disk_max);
    DF_RESOURCE_FIELD(work_limit);
    DF_RESOURCE_FIELD(arc_limit);
    DF_RESOURCE_FIELD(headroom);
    DF_RESOURCE_FIELD(workspace_bytes);
    DF_RESOURCE_FIELD(workspace_peak);
    DF_RESOURCE_FIELD(cache_bytes);
    DF_RESOURCE_FIELD(cache_peak);
    DF_RESOURCE_FIELD(scratch_bytes);
    DF_RESOURCE_FIELD(scratch_peak);
    DF_RESOURCE_FIELD(cache_hits);
    DF_RESOURCE_FIELD(cache_misses);
    DF_RESOURCE_FIELD(cache_evictions);
    DF_RESOURCE_FIELD(disk_read_bytes);
    DF_RESOURCE_FIELD(disk_write_bytes);
#undef DF_RESOURCE_FIELD
    putchar('}');
}

void
dedup_fdt_plan_progress(dedup_fdt_plan_t *p, const char *phase, boolean_t force)
{
    if (pthread_mutex_trylock(&p->progress_lock) != 0)
        return;
    struct timespec now, wall;
    clock_gettime(CLOCK_MONOTONIC, &now);
    double elapsed = now.tv_sec-p->started.tv_sec+
        (now.tv_nsec-p->started.tv_nsec)/1e9;
    double interval = now.tv_sec-p->last_progress.tv_sec+
        (now.tv_nsec-p->last_progress.tv_nsec)/1e9;
    if (!force && interval < 1.0) {
        pthread_mutex_unlock(&p->progress_lock);
        return;
    }
    p->last_progress = now;
    clock_gettime(CLOCK_REALTIME, &wall);
    uint64_t hashed = __atomic_load_n(&p->counters.logical_hashed_bytes, __ATOMIC_RELAXED);
    uint64_t read_bytes = __atomic_load_n(&p->counters.read_bytes, __ATOMIC_RELAXED);
    double rate = elapsed > 0 ? hashed/elapsed : 0;
    printf("{\"event\":\"progress\",\"phase\":\"%s\",\"timestamp\":%lld.%09ld,"
        "\"metadata_visits\":%llu,\"candidate_allocations\":%llu,"
        "\"logical_hashed_bytes\":%llu,\"read_bytes\":%llu,\"verified_bytes\":%llu,"
        "\"duplicate_groups\":%llu,\"aliases\":%llu,\"rewritten_roots\":%llu,"
        "\"fdt_entries\":%llu,\"retired_bytes\":%llu,\"rate_bytes_per_second\":%.3f,"
        "\"eta_seconds\":", phase, (long long)wall.tv_sec, wall.tv_nsec,
        (u_longlong_t)p->counters.metadata_visits,
        (u_longlong_t)p->counters.candidate_allocations, (u_longlong_t)hashed,
        (u_longlong_t)read_bytes, (u_longlong_t)p->counters.verified_bytes,
        (u_longlong_t)p->counters.duplicate_groups, (u_longlong_t)p->counters.aliases,
        (u_longlong_t)p->counters.rewritten_roots, (u_longlong_t)p->counters.fdt_entries,
        (u_longlong_t)p->counters.retired_bytes, rate);
    if (strcmp(phase, "hashing") == 0 && rate > 0 && hashed <= p->total_hash_bytes)
        printf("%.3f", (p->total_hash_bytes-hashed)/rate);
    else
        printf("null");
    df_json_resources(p);
    puts("}");
    fflush(stdout);
    pthread_mutex_unlock(&p->progress_lock);
}

static void
df_json_string(const char *value)
{
    putchar('"');
    for (const unsigned char *p = (const unsigned char *)value; *p != 0; p++) {
        if (*p == '"' || *p == '\\')
            printf("\\%c", *p);
        else if (*p < 0x20)
            printf("\\u%04x", *p);
        else
            putchar(*p);
    }
    putchar('"');
}

void
dedup_fdt_plan_result(dedup_fdt_plan_t *p, const char *status)
{
    dedup_fdt_plan_progress(p, status, B_TRUE);
    size_t selected = 0;
    for (size_t i = 0; i < p->dataset_count; i++)
        selected += p->datasets[i].selected != B_FALSE;
    printf("{\"event\":\"complete\",\"status\":\"%s\",\"changed_allocations\":%llu,"
        "\"new_canonicals\":%llu,\"duplicate_groups\":%llu,\"logical_hashed_bytes\":%llu,"
        "\"verified_bytes\":%llu,\"retired_bytes\":%llu,"
        "\"projected_staging_bytes\":%llu,\"projected_retirement_bytes\":%llu,"
        "\"index_bytes\":%llu,\"candidate_allocations\":%llu,"
        "\"selected_dataset_objects\":%llu,\"requested_datasets\":[", status,
        (u_longlong_t)p->counters.changed_allocations,
        (u_longlong_t)p->counters.new_canonicals,
        (u_longlong_t)p->counters.duplicate_groups,
        (u_longlong_t)p->counters.logical_hashed_bytes,
        (u_longlong_t)p->counters.verified_bytes,
        (u_longlong_t)p->counters.retired_bytes,
        (u_longlong_t)p->projected_stage_bytes,
        (u_longlong_t)p->projected_retire_bytes,
        (u_longlong_t)p->index_bytes,
        (u_longlong_t)p->counters.candidate_allocations,
        (u_longlong_t)selected);
    for (size_t i = 0; i < p->options.dataset_count; i++) {
        if (i != 0)
            putchar(',');
        df_json_string(p->options.datasets[i]);
    }
    putchar(']');
    df_json_resources(p);
    puts("}");
    fflush(stdout);
}

void
dedup_fdt_plan_close(dedup_fdt_plan_t *p)
{
    if (p == NULL)
        return;
    dedup_fdt_index_close(&p->sources);
    dedup_fdt_index_close(&p->groups);
    dedup_fdt_index_close(&p->aliases);
    dedup_fdt_index_close(&p->fdt);
    dedup_fdt_file_close(&p->flat_output);
    dedup_fdt_file_close(&p->brt_output);
    df_buffers_close(p);
    dedup_fdt_memory_release(p->options.resources, p->dataset_reservation);
    free(p->datasets);
    pthread_mutex_destroy(&p->progress_lock);
    dedup_fdt_memory_release(p->options.resources, sizeof (*p));
    free(p);
}

boolean_t
dedup_fdt_plan_has_changes(const dedup_fdt_plan_t *p)
{
    return (p != NULL && p->counters.duplicate_groups != 0);
}

boolean_t
dedup_fdt_plan_needs_claim(const dedup_fdt_plan_t *p)
{
    return (p != NULL && p->needs_claim);
}

void
dedup_fdt_plan_retired(dedup_fdt_plan_t *p, uint64_t bytes)
{
    if (p == NULL)
        return;
    p->counters.retired_bytes = bytes;
    dedup_fdt_plan_progress(p, "retiring", B_FALSE);
}
