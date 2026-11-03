/* SPDX-License-Identifier: CDDL-1.0
 * Offline OpenZFS 2.4.4 DDT conversion using libzpool.
 */
#include <sys/zfs_context.h>
#include <sys/spa.h>
#include <sys/spa_impl.h>
#include <sys/arc_impl.h>
#include <sys/ddt.h>
#include <sys/ddt_impl.h>
#include <sys/dmu.h>
#include <sys/dmu_tx.h>
#include <sys/dnode.h>
#include <sys/dsl_pool.h>
#include <sys/dsl_scan.h>
#include <sys/dsl_synctask.h>
#include <sys/vdev_impl.h>
#include <sys/zap.h>
#include <sys/zap_impl.h>
#include <sys/zap_leaf.h>
#include <sys/zfeature.h>
#include <sys/zfs_ioctl.h>
#include <sys/zio_checksum.h>
#include <sys/zio_compress.h>
#include <libzutil.h>
#include <getopt.h>
#include <sys/file.h>
#include <sys/mman.h>
#include <signal.h>
#include <pthread.h>
#include <sched.h>
#include <time.h>
#include "ddt_transform.h"
#include "ddt_physical.h"

#define STAGE_KEY "org.convert-ddt:staging"
#define STAGE_FORMAT 1
#define MAX_TABLES ZIO_CHECKSUM_FUNCTIONS
#define MAX_WORKERS 64
#define MAX_READ_BATCH_ENTRIES 1000000
#define READER_MEMORY_LIMIT (1ULL << 30)

static volatile sig_atomic_t stopping;
static const char *tag = "convert-ddt";

typedef struct table {
    ddt_t *ddt;
    uint64_t objects[DDT_CLASSES];
    uint64_t counts[DDT_CLASSES];
    ddt_histogram_t hist[DDT_CLASSES];
    ddt_object_t stats[DDT_CLASSES];
    unsigned int stores[DDT_CLASSES];
} table_t;

typedef struct conversion {
    spa_t *spa;
    table_t tables[MAX_TABLES];
    size_t ntables;
    uint64_t stage;
    uint64_t flags;
    uint64_t timestamp;
    size_t batch_size;
    size_t read_batch_entries;
    unsigned int workers;
    dp_plan_t plan;
    dp_store_t stores[MAX_TABLES * DDT_CLASSES];
    size_t nstores;
    taskq_t *readers;
} conversion_t;

typedef struct entry_index {
    uint64_t hash;
    size_t index;
} entry_index_t;

typedef struct batch {
    conversion_t *c;
    dnode_t *dn;
    ddt_lightweight_entry_t *entries;
    const entry_index_t *order;
    size_t count;
} batch_t;

typedef struct reclaim {
    conversion_t *c;
    char name[ZAP_MAXNAMELEN];
    uint64_t object;
    uint64_t offset;
    uint64_t length;
} reclaim_t;

static int
problem(int error, const char *message)
{
    fprintf(stderr, "convert-ddt: %s: %s\n", message, strerror(error));
    return (error);
}

static void
on_signal(int sig)
{
    (void) sig;
    stopping = 1;
}

/* Match kernel pools by GUID so renaming preserves imported-pool exclusion. */
static int
reject_kernel_pool(uint64_t guid)
{
    int fd = open(ZFS_DEV, O_RDWR | O_CLOEXEC);
    if (fd < 0)
        return (problem(errno, "cannot open kernel ZFS control device"));
    size_t size = 128 * 1024;
    void *buffer = NULL;
    zfs_cmd_t *zc = calloc(1, sizeof (*zc));
    int error = 0;
    nvlist_t *configs = NULL;
    if (zc == NULL) {
        close(fd);
        return (ENOMEM);
    }
    for (;;) {
        free(buffer);
        buffer = malloc(size);
        if (buffer == NULL) { error = ENOMEM; break; }
        zc->zc_nvlist_dst = (uintptr_t)buffer;
        zc->zc_nvlist_dst_size = size;
        zc->zc_cookie = 0;
        if (ioctl(fd, ZFS_IOC_POOL_CONFIGS, zc) == 0) {
            error = nvlist_unpack(buffer, zc->zc_nvlist_dst_size,
                &configs, 0);
            break;
        }
        error = errno;
        if (error != ENOMEM)
            break;
        if (zc->zc_nvlist_dst_size <= size ||
            zc->zc_nvlist_dst_size > 128 * 1024 * 1024) {
            error = EOVERFLOW;
            break;
        }
        size = zc->zc_nvlist_dst_size;
    }
    if (error == 0) {
        for (nvpair_t *p = nvlist_next_nvpair(configs, NULL); p != NULL;
            p = nvlist_next_nvpair(configs, p)) {
            nvlist_t *pool = NULL;
            uint64_t found;
            if (nvpair_value_nvlist(p, &pool) != 0 ||
                nvlist_lookup_uint64(pool, ZPOOL_CONFIG_POOL_GUID,
                &found) != 0) {
                error = EINVAL;
                break;
            }
            if (found == guid) {
                error = EBUSY;
                break;
            }
        }
    }
    nvlist_free(configs);
    free(buffer);
    free(zc);
    close(fd);
    return (error ? problem(error,
        "kernel pool exclusion failed (target must be exported)") : 0);
}

/* The loaded uberblock TXG selects each leaf's committed configuration,
 * excluding label updates from an incomplete export. */
static int
exported_leaf_labels(vdev_t *vd)
{
    for (uint64_t i = 0; i < vd->vdev_children; i++) {
        int error = exported_leaf_labels(vd->vdev_child[i]);
        if (error) return (error);
    }
    if (!vd->vdev_ops->vdev_op_leaf)
        return (0);
    nvlist_t *label = vdev_label_read_config(vd,
        vd->vdev_spa->spa_uberblock.ub_txg);
    uint64_t state, guid, leaf_guid, txg;
    int error = 0;
    if (label == NULL ||
        nvlist_lookup_uint64(label, ZPOOL_CONFIG_POOL_STATE, &state) ||
        state != POOL_STATE_EXPORTED ||
        nvlist_lookup_uint64(label, ZPOOL_CONFIG_POOL_GUID, &guid) ||
        guid != spa_guid(vd->vdev_spa) ||
        nvlist_lookup_uint64(label, ZPOOL_CONFIG_GUID, &leaf_guid) ||
        leaf_guid != vd->vdev_guid ||
        nvlist_lookup_uint64(label, ZPOOL_CONFIG_POOL_TXG, &txg) || txg == 0)
        error = problem(EINVAL, "selected on-disk leaf label is not cleanly exported");
    nvlist_free(label);
    return (error);
}

static int
quiescent(spa_t *spa)
{
    dsl_scan_t *scan = spa_get_dsl(spa)->dp_scan;
    if (scan->scn_phys.scn_state == DSS_SCANNING ||
        dsl_errorscrub_active(scan) || spa_has_checkpoint(spa) ||
        spa_feature_is_active(spa, SPA_FEATURE_POOL_CHECKPOINT) ||
        spa->spa_vdev_removal != NULL || spa->spa_raidz_expand != NULL ||
        spa->spa_condensing_indirect != NULL)
        return (problem(EBUSY, "scan/checkpoint/removal/expansion/condense present"));
    if (spa->spa_root_vdev->vdev_state != VDEV_STATE_HEALTHY)
        return (problem(ENXIO, "pool is not fully healthy"));
    for (uint64_t i = 0; i < spa->spa_root_vdev->vdev_children; i++)
        if (vdev_rebuild_active(spa->spa_root_vdev->vdev_child[i]))
            return (problem(EBUSY, "sequential resilver is active"));
    if (!spa_feature_is_enabled(spa, SPA_FEATURE_FAST_DEDUP))
        return (problem(ENOTSUP, "enable feature@fast_dedup before exporting"));
    return (0);
}
/* Pinned OpenZFS 2.4.4 ddt_zap.c format, with caller-owned storage.
 * In particular, the uncompressed native path returns before byteswapping. */
static int
decode_phys(uchar_t *buffer, size_t size, ddt_univ_phys_t *phys, size_t psize)
{
    if (size < 2 || size > psize + 1)
        return (EINVAL);
    unsigned int compression = buffer[0] & 0x7f;
    if (compression >= ZIO_COMPRESS_FUNCTIONS)
        return (EINVAL);
    memset(phys, 0, sizeof (*phys));
    if (zio_compress_table[compression].ci_decompress == NULL) {
        if (compression != ZIO_COMPRESS_OFF || size != psize + 1)
            return (EINVAL);
        memcpy(phys, buffer + 1, psize);
        return (0);
    }
    abd_t source, destination;
    abd_get_from_buf_struct(&source, buffer + 1, size - 1);
    abd_get_from_buf_struct(&destination, phys, psize);
    int error = zio_decompress_data(compression, &source, &destination,
        size - 1, psize, NULL);
    abd_free(&destination);
    abd_free(&source);
    if (!error && (((buffer[0] & 0x80) != 0) != (ZFS_HOST_BYTEORDER != 0)))
        byteswap_uint64_array(phys, psize);
    return (error);
}

typedef enum read_mode { READ_PREFLIGHT, READ_COPY, READ_BACK } read_mode_t;
typedef struct physical_scan physical_scan_t;
typedef struct physical_worker {
    physical_scan_t *scan;
    ddt_histogram_t histogram;
    uint64_t count, leaf_count, hash;
    uint32_t cd;
    size_t block, offset, capacity, produced;
    boolean_t active, exhausted;
} physical_worker_t;

struct physical_scan {
    conversion_t *c;
    table_t *table;
    int class, error;
    read_mode_t mode;
    dnode_t *destination;
    ddt_lightweight_entry_t *entries;
    physical_worker_t *workers;
    unsigned int nworkers, running;
    size_t next_block;
    uint64_t entries_done, blocks_done, total_blocks;
    pthread_mutex_t mutex;
    pthread_cond_t changed;
};

/* Pinned native zap_idx_to_blk/zap_table_load semantics, including the
 * larger in-progress pointer table's native I/O error check. */
static int
physical_pointer(zap_t *zap, uint64_t index, uint64_t *block)
{
    zap_table_phys_t *table = &zap_f_phys(zap)->zap_ptrtbl;
    if (table->zt_shift > 48 || index >= (1ULL << table->zt_shift))
        return (EINVAL);
    if (table->zt_numblks == 0) {
        if (table->zt_shift != ZAP_EMBEDDED_PTRTBL_SHIFT(zap))
            return (EINVAL);
        *block = ZAP_EMBEDDED_PTRTBL_ENT(zap, index);
        return (0);
    }
    unsigned int shift = FZAP_BLOCK_SHIFT(zap);
    uint64_t perblock = 1ULL << (shift - 3);
    dmu_buf_t *db;
    int error = dmu_buf_hold_by_dnode(zap->zap_dnode,
        (table->zt_blk + index / perblock) << shift, tag, &db,
        DMU_READ_NO_PREFETCH);
    if (error)
        return (error);
    *block = ((uint64_t *)db->db_data)[index % perblock];
    dmu_buf_rele(db, tag);
    if (table->zt_nextblk) {
        error = dmu_buf_hold_by_dnode(zap->zap_dnode,
            (table->zt_nextblk + index * 2 / perblock) << shift,
            tag, &db, DMU_READ_NO_PREFETCH);
        if (!error)
            dmu_buf_rele(db, tag);
    }
    return (error);
}

static int
physical_registered(zap_t *zap, const dp_leaf_t *leaf, boolean_t *registered)
{
    *registered = B_FALSE;
    uint64_t flags = zap_getflags(zap);
    if (zap->zap_ismicro || zap_hashbits(zap) != 48 ||
        (flags & (ZAP_FLAG_HASH64 | ZAP_FLAG_UINT64_KEY)) !=
        (ZAP_FLAG_HASH64 | ZAP_FLAG_UINT64_KEY) ||
        zap_f_phys(zap)->zap_block_type != ZBT_HEADER ||
        zap_f_phys(zap)->zap_magic != ZAP_MAGIC)
        return (EINVAL);
    unsigned int shift = zap_f_phys(zap)->zap_ptrtbl.zt_shift;
    if (shift > 48 || shift < leaf->prefix_len)
        return (EINVAL);
    uint64_t first_index = leaf->hash_start >> (48 - shift);
    uint64_t last_index = (leaf->hash_end - 1) >> (48 - shift);
    uint64_t first, last;
    int error = physical_pointer(zap, first_index, &first);
    if (!error)
        error = physical_pointer(zap, last_index, &last);
    if (error)
        return (error);
    if (first == leaf->blkid && last == leaf->blkid) {
        *registered = B_TRUE;
        return (0);
    }
    /* Skip a stale physical leaf only after every pointer in its claimed
     * prefix proves it is unregistered. Partial registration is corruption. */
    for (uint64_t i = first_index; i <= last_index; i++) {
        uint64_t found;
        error = physical_pointer(zap, i, &found);
        if (error || found == leaf->blkid)
            return (error ? error : EINVAL);
    }
    return (0);
}

static int
physical_entry(zap_t *zap, zap_entry_handle_t *handle,
    ddt_lightweight_entry_t *entry)
{
    struct zap_leaf_entry *native =
        ZAP_LEAF_ENTRY(handle->zeh_leaf, *handle->zeh_chunkp);
    if (native->le_name_numints != sizeof (entry->ddlwe_key) / 8 ||
        handle->zeh_integer_size != 1 || handle->zeh_num_integers < 2 ||
        handle->zeh_num_integers > DDT_TRAD_PHYS_SIZE + 1)
        return (EINVAL);
    int error = zap_entry_read_name(zap, handle, sizeof (entry->ddlwe_key),
        (char *)&entry->ddlwe_key);
    uchar_t buffer[DDT_TRAD_PHYS_SIZE + 1];
    if (!error)
        error = zap_entry_read(handle, 1, handle->zeh_num_integers, buffer);
    if (!error)
        error = decode_phys(buffer, handle->zeh_num_integers,
            &entry->ddlwe_phys, DDT_TRAD_PHYS_SIZE);
    return (error);
}

static void
physical_worker(void *arg)
{
    physical_worker_t *worker = arg;
    physical_scan_t *scan = worker->scan;
    conversion_t *c = scan->c;
    unsigned int store = scan->table->stores[scan->class];
    int error = 0;
    worker->produced = 0;
    ddt_t view = { .ddt_spa = c->spa, .ddt_flags = DDT_FLAG_FLAT };
    spa_config_enter(c->spa, SCL_VDEV, tag, RW_READER);
    while (!error && !stopping &&
        !__atomic_load_n(&scan->error, __ATOMIC_RELAXED) &&
        (scan->mode != READ_COPY || worker->produced < worker->capacity)) {
        if (!worker->active) {
            do {
                worker->block = __atomic_fetch_add(&scan->next_block, 1,
                    __ATOMIC_RELAXED);
            } while (worker->block < c->plan.nblocks &&
                c->plan.blocks[worker->block].store != store);
            if (worker->block >= c->plan.nblocks) {
                worker->exhausted = B_TRUE;
                break;
            }
            worker->leaf_count = 0;
        }
        dp_leaf_t leaf = { 0 };
        error = dp_leaf_open(&c->plan, &c->plan.blocks[worker->block], &leaf);
        if (error)
            break;
        zap_t *zap = NULL;
        boolean_t registered = B_FALSE;
        if (leaf.is_leaf) {
            dp_store_t *source = &c->stores[store - 1];
            error = zap_lockdir(source->os, source->object, NULL, RW_READER,
                B_TRUE, B_FALSE, tag, &zap);
            if (!error)
                error = physical_registered(zap, &leaf, &registered);
        }
        boolean_t completed = !leaf.is_leaf || !registered;
        if (!error && registered) {
            /* The source is immutable until publication. Decode its native
             * checksummed DBUF directly, not through random per-key lookups. */
            zap_leaf_t native = {
                .l_blkid = leaf.blkid,
                .l_bs = highbit64(leaf.db->db.db_size) - 1,
                .l_dbuf = &leaf.db->db
            };
            if (!worker->active) {
                worker->hash = leaf.hash_start << 16;
                worker->cd = 0;
            }
            worker->active = B_TRUE;
            for (;;) {
                zap_entry_handle_t handle;
                int found = zap_leaf_lookup_closest(&native, worker->hash,
                    worker->cd, &handle);
                if (found == ENOENT) {
                    if (worker->leaf_count != leaf.nentries)
                        error = EINVAL;
                    completed = B_TRUE;
                    break;
                }
                if (found) { error = found; break; }
                uint64_t hash = handle.zeh_hash >> 16;
                if (hash < leaf.hash_start || hash >= leaf.hash_end ||
                    handle.zeh_hash < worker->hash ||
                    (handle.zeh_hash == worker->hash &&
                    handle.zeh_cd < worker->cd) ||
                    handle.zeh_cd >= zap_maxcd(zap)) {
                    error = EINVAL;
                    break;
                }
                ddt_lightweight_entry_t local;
                ddt_lightweight_entry_t *entry = scan->mode == READ_COPY ?
                    &scan->entries[worker->offset + worker->produced] : &local;
                error = physical_entry(zap, &handle, entry);
                ddt_univ_phys_t flat;
                if (!error)
                    error = ddt_convert_phys(&entry->ddlwe_phys, &flat,
                        c->timestamp);
                if (!error && (scan->class == DDT_CLASS_DITTO ||
                    ((scan->class == DDT_CLASS_UNIQUE) !=
                    (flat.ddp_flat.ddp_refcnt == 1))))
                    error = ENOTSUP;
                if (error)
                    break;
                entry->ddlwe_type = DDT_TYPE_ZAP;
                entry->ddlwe_class = scan->class;
                entry->ddlwe_phys = flat;
                if (scan->mode == READ_BACK) {
                    uchar_t buffer[DDT_FLAT_PHYS_SIZE + 1];
                    uint64_t size;
                    ddt_univ_phys_t actual;
                    error = zap_lookup_length_uint64_by_dnode(scan->destination,
                        (uint64_t *)&entry->ddlwe_key,
                        sizeof (entry->ddlwe_key) / 8, 1, sizeof (buffer),
                        buffer, &size);
                    if (!error)
                        error = decode_phys(buffer, size, &actual,
                            DDT_FLAT_PHYS_SIZE);
                    if (!error && memcmp(&flat.ddp_flat, &actual.ddp_flat,
                        DDT_FLAT_PHYS_SIZE))
                        error = EINVAL;
                }
                if (error)
                    break;
                ddt_histogram_add_entry(&view, &worker->histogram, entry);
                worker->count++;
                worker->leaf_count++;
                __atomic_fetch_add(&scan->entries_done, 1, __ATOMIC_RELAXED);
                worker->hash = handle.zeh_hash;
                worker->cd = handle.zeh_cd + 1;
                if (worker->leaf_count > leaf.nentries) { error = EINVAL; break; }
                if (stopping) { error = EINTR; break; }
                if (scan->mode == READ_COPY &&
                    ++worker->produced == worker->capacity) {
                    /* Only cookie/count state crosses a writer TXG boundary. */
                    found = zap_leaf_lookup_closest(&native, worker->hash,
                        worker->cd, &handle);
                    if (found == ENOENT) {
                        completed = B_TRUE;
                        if (worker->leaf_count != leaf.nentries)
                            error = EINVAL;
                    } else if (found) {
                        error = found;
                    }
                    break;
                }
            }
        }
        if (zap != NULL)
            zap_unlockdir(zap, tag);
        dp_leaf_close(&leaf);
        if (completed && !error) {
            worker->active = B_FALSE;
            __atomic_fetch_add(&scan->blocks_done, 1, __ATOMIC_RELAXED);
        }
    }
    spa_config_exit(c->spa, SCL_VDEV, tag);
    if (stopping)
        error = EINTR;
    pthread_mutex_lock(&scan->mutex);
    if (error && !__atomic_load_n(&scan->error, __ATOMIC_RELAXED))
        __atomic_store_n(&scan->error, error, __ATOMIC_RELAXED);
    scan->running--;
    pthread_cond_signal(&scan->changed);
    pthread_mutex_unlock(&scan->mutex);
}

static void
entry_progress(physical_scan_t *scan, uint64_t count, hrtime_t started)
{
    static const char *phases[] = {
        "flat-preflight", "flat-copy", "flat-readback"
    };
    uint64_t total = scan->table->counts[scan->class];
    double seconds = (gethrtime() - started) / (double)NANOSEC;
    double rate = seconds > 0 ? count / seconds : 0;
    char eta[64] = "null";
    if (count == total)
        snprintf(eta, sizeof (eta), "0");
    else if (rate > 0 && count < total)
        snprintf(eta, sizeof (eta), "%.1f", (total - count) / rate);
    fprintf(stderr, "{\"timestamp\":%llu,\"phase\":\"%s\","
        "\"checksum\":\"%s\",\"class\":%d,\"entries\":%llu,"
        "\"total_entries\":%llu,\"elapsed_seconds\":%.3f,"
        "\"entries_per_second\":%.3f,\"eta_seconds\":%s,"
        "\"read_order\":\"physical\",\"physical_blocks\":%llu,"
        "\"total_physical_blocks\":%llu}\n",
        (u_longlong_t)gethrestime_sec(), phases[scan->mode],
        zio_checksum_table[scan->table->ddt->ddt_checksum].ci_name, scan->class,
        (u_longlong_t)count, (u_longlong_t)total, seconds, rate, eta,
        (u_longlong_t)__atomic_load_n(&scan->blocks_done, __ATOMIC_RELAXED),
        (u_longlong_t)scan->total_blocks);
}

static int
physical_scan_init(physical_scan_t *scan, conversion_t *c, table_t *table, int class,
    read_mode_t mode, dnode_t *destination, ddt_lightweight_entry_t *entries)
{
    *scan = (physical_scan_t) {
        .c = c, .table = table, .class = class, .mode = mode,
        .destination = destination, .entries = entries,
        .nworkers = MIN(c->workers, c->read_batch_entries)
    };
    for (size_t i = 0; i < c->plan.nblocks; i++)
        if (c->plan.blocks[i].store == table->stores[class])
            scan->total_blocks++;
    scan->workers = calloc(scan->nworkers, sizeof (*scan->workers));
    if (scan->workers == NULL)
        return (ENOMEM);
    int error = pthread_mutex_init(&scan->mutex, NULL);
    if (error) { free(scan->workers); return (error); }
    error = pthread_cond_init(&scan->changed, NULL);
    if (error) {
        pthread_mutex_destroy(&scan->mutex);
        free(scan->workers);
        return (error);
    }
    for (unsigned int i = 0; i < scan->nworkers; i++) {
        physical_worker_t *worker = &scan->workers[i];
        worker->scan = scan;
        worker->offset = c->read_batch_entries * i / scan->nworkers;
        worker->capacity = c->read_batch_entries * (i + 1) / scan->nworkers -
            worker->offset;
    }
    return (0);
}

static int
scan_run(physical_scan_t *scan, hrtime_t started)
{
    pthread_mutex_lock(&scan->mutex);
    for (unsigned int i = 0; i < scan->nworkers; i++) {
        scan->running++;
        if (taskq_dispatch(scan->c->readers, physical_worker, &scan->workers[i],
            TQ_SLEEP) == TASKQID_INVALID) {
            scan->running--;
            __atomic_store_n(&scan->error, ENOMEM, __ATOMIC_RELAXED);
            break;
        }
    }
    while (scan->running) {
        struct timespec deadline;
        clock_gettime(CLOCK_REALTIME, &deadline);
        deadline.tv_sec++;
        (void) pthread_cond_timedwait(&scan->changed, &scan->mutex, &deadline);
        entry_progress(scan,
            __atomic_load_n(&scan->entries_done, __ATOMIC_RELAXED), started);
    }
    pthread_mutex_unlock(&scan->mutex);
    taskq_wait(scan->c->readers);
    return (__atomic_load_n(&scan->error, __ATOMIC_RELAXED));
}

static int
scan_finish(physical_scan_t *scan, ddt_histogram_t *histogram)
{
    uint64_t count = 0;
    memset(histogram, 0, sizeof (*histogram));
    for (unsigned int i = 0; i < scan->nworkers; i++) {
        count += scan->workers[i].count;
        ddt_histogram_add(histogram, &scan->workers[i].histogram);
    }
    int error = scan->error;
    if (!error && (count != scan->table->counts[scan->class] ||
        scan->blocks_done != scan->total_blocks ||
        memcmp(histogram,
        &scan->table->ddt->ddt_histogram[DDT_TYPE_ZAP][scan->class],
        sizeof (*histogram))))
        error = EINVAL;
    pthread_cond_destroy(&scan->changed);
    pthread_mutex_destroy(&scan->mutex);
    free(scan->workers);
    return (error);
}

static int
inspect_class(conversion_t *c, table_t *table, int class)
{
    physical_scan_t scan;
    int error = physical_scan_init(&scan, c, table, class, READ_PREFLIGHT, NULL, NULL);
    if (error)
        return (error);
    hrtime_t started = gethrtime();
    entry_progress(&scan, 0, started);
    error = scan_run(&scan, started);
    entry_progress(&scan, scan.entries_done, started);
    int final_error = scan_finish(&scan, &table->hist[class]);
    if (!error)
        error = final_error;
    if (error)
        return (problem(error, "flat-layout physical preflight failed"));
    printf("eligible %s class=%d entries=%llu workers=%u physical_blocks=%llu\n",
        zio_checksum_table[table->ddt->ddt_checksum].ci_name, class,
        (u_longlong_t)table->counts[class], scan.nworkers,
        (u_longlong_t)scan.total_blocks);
    return (0);
}


static int
inspect(conversion_t *c)
{
    int error = quiescent(c->spa);
    if (error)
        return (error);
    for (int checksum = 0; checksum < ZIO_CHECKSUM_FUNCTIONS; checksum++) {
        ddt_t *ddt = c->spa->spa_ddt[checksum];
        if (ddt == NULL || ddt->ddt_version == DDT_VERSION_UNCONFIGURED)
            continue;
        printf("table %s version=%llu flags=%llu\n",
            zio_checksum_table[checksum].ci_name,
            (u_longlong_t)ddt->ddt_version, (u_longlong_t)ddt->ddt_flags);
        if (ddt->ddt_version == DDT_VERSION_FDT) {
            if ((ddt->ddt_flags & c->flags) == c->flags)
                continue;
            return (problem(ENOTSUP,
                "existing version-1 table has a different layout; not a legacy table"));
        }
        if (ddt->ddt_version != DDT_VERSION_LEGACY || ddt->ddt_flags != 0 ||
            ddt->ddt_dir_object != DMU_POOL_DIRECTORY_OBJECT ||
            !avl_is_empty(&ddt->ddt_tree) ||
            !avl_is_empty(&ddt->ddt_repair_tree))
            return (problem(EINVAL, "unexpected legacy DDT state"));
        table_t *t = &c->tables[c->ntables++];
        t->ddt = ddt;
        for (int cl = 0; cl < DDT_CLASSES; cl++) {
            if (ddt->ddt_object[DDT_TYPE_ZAP][cl] == 0)
                continue;
            error = ddt_object_count(ddt, DDT_TYPE_ZAP, cl, &t->counts[cl]);
            if (error)
                return (problem(error, "cannot count source DDT"));
            if (!(c->flags & DDT_FLAG_FLAT)) {
                t->hist[cl] = ddt->ddt_histogram[DDT_TYPE_ZAP][cl];
                continue;
            }
            c->stores[c->nstores] = (dp_store_t) {
                .spa = c->spa, .os = ddt->ddt_os,
                .dn = ddt->ddt_object_dnode[DDT_TYPE_ZAP][cl],
                .object = ddt->ddt_object[DDT_TYPE_ZAP][cl]
            };
            t->stores[cl] = ++c->nstores;
        }
    }
    if (!(c->flags & DDT_FLAG_FLAT) || c->nstores == 0)
        return (0);
    /* Reserve both index arrays (qsort may allocate a full-size scratch
     * array), payloads, worker state, and fixed taskq bookkeeping together.
     * Native ARC/DBUF memory is managed separately by libzpool. */
    uint64_t reserved = sizeof (*c) + c->read_batch_entries *
        (sizeof (ddt_lightweight_entry_t) + 2 * sizeof (entry_index_t)) +
        c->workers * sizeof (physical_worker_t) + (16ULL << 20);
    if (reserved >= READER_MEMORY_LIMIT)
        return (problem(ENOMEM, "physical reader fixed memory exceeds 1 GiB"));
    error = dp_plan_build(&c->plan, c->stores, c->nstores, c->workers,
        READER_MEMORY_LIMIT - reserved, &stopping);
    if (error)
        return (problem(error, "cannot build physical DDT metadata plan"));
    fprintf(stderr, "physical DDT plan blocks=%llu logical_bytes=%llu "
        "plan_memory_bytes=%llu reserved_memory_bytes=%llu\n",
        (u_longlong_t)c->plan.nblocks, (u_longlong_t)c->plan.logical_bytes,
        (u_longlong_t)c->plan.allocation_bytes, (u_longlong_t)reserved);
    c->readers = taskq_create("ddt_physical_read", c->workers, maxclsyspri,
        c->workers, c->workers, TASKQ_PREPOPULATE);
    if (c->readers == NULL)
        return (ENOMEM);
    for (size_t i = 0; i < c->ntables; i++) {
        table_t *t = &c->tables[i];
        for (int cl = 0; cl < DDT_CLASSES; cl++) {
            if (t->stores[cl] && (error = inspect_class(c, t, cl)) != 0)
                return (error);
        }
    }
    return (0);
}

static void
object_key(ddt_t *ddt, int cl, char *key, size_t size)
{
    snprintf(key, size, "obj-%d-%d", ddt->ddt_checksum, cl);
}

static void
create_stage(void *arg, dmu_tx_t *tx)
{
    conversion_t *c = arg;
    objset_t *os = c->spa->spa_meta_objset;
    c->stage = zap_create_link(os, DMU_OTN_ZAP_METADATA,
        DMU_POOL_DIRECTORY_OBJECT, STAGE_KEY, tx);
    uint64_t format = STAGE_FORMAT, guid = spa_guid(c->spa);
    VERIFY0(zap_add(os, c->stage, "format", 8, 1, &format, tx));
    VERIFY0(zap_add(os, c->stage, "pool_guid", 8, 1, &guid, tx));
    for (size_t i = 0; i < c->ntables; i++) {
        table_t *t = &c->tables[i];
        for (int cl = 0; cl < DDT_CLASSES; cl++) {
            if (t->ddt->ddt_object[DDT_TYPE_ZAP][cl] == 0)
                continue;
            boolean_t prehash = zio_checksum_table[t->ddt->ddt_checksum].ci_flags &
                ZCHECKSUM_FLAG_DEDUP;
            VERIFY0(ddt_zap_ops.ddt_op_create(os, &t->objects[cl], tx, prehash));
            char key[64];
            object_key(t->ddt, cl, key, sizeof (key));
            VERIFY0(zap_add(os, c->stage, key, 8, 1, &t->objects[cl], tx));
        }
    }
}

static void
copy_batch(void *arg, dmu_tx_t *tx)
{
    batch_t *batch = arg;
    for (size_t i = 0; i < batch->count; i++) {
        ddt_lightweight_entry_t *entry =
            &batch->entries[batch->order[i].index];
        VERIFY0(ddt_zap_ops.ddt_op_update(batch->dn, &entry->ddlwe_key,
            &entry->ddlwe_phys, DDT_FLAT_PHYS_SIZE, tx));
    }
}

static int
compare_entry_index(const void *left, const void *right)
{
    const entry_index_t *a = left, *b = right;
    if (a->hash != b->hash)
        return (a->hash < b->hash ? -1 : 1);
    return (a->index < b->index ? -1 : a->index != b->index);
}

/* Native HASH64 ZAP hashes use the high 48 bits. Strong checksum staging
 * ZAPs use the first key word directly; other ZAPs use their NEW salt, not
 * the legacy object's cursor hash. This is zap_micro.c's uint64-key path. */
static uint64_t
destination_hash(const ddt_key_t *key, uint64_t flags, uint64_t salt)
{
    const uint64_t *words = (const uint64_t *)key;
    uint64_t hash = words[0];
    if (!(flags & ZAP_FLAG_PRE_HASHED_KEY)) {
        hash = salt;
        for (size_t i = 0; i < sizeof (*key) / 8; i++) {
            uint64_t word = words[i];
            for (unsigned int j = 0; j < 8; j++, word >>= 8)
                hash = (hash >> 8) ^ zfs_crc64_table[(hash ^ word) & 0xff];
        }
    }
    return (hash & ~((1ULL << 16) - 1));
}

static int
copy_tables(conversion_t *c)
{
    ddt_lightweight_entry_t *entries =
        calloc(c->read_batch_entries, sizeof (*entries));
    entry_index_t *order = calloc(c->read_batch_entries, sizeof (*order));
    if (entries == NULL || order == NULL) {
        free(entries);
        free(order);
        return (ENOMEM);
    }
    int error = 0;
    for (size_t i = 0; i < c->ntables && !error; i++) {
        table_t *t = &c->tables[i];
        for (int cl = 0; cl < DDT_CLASSES && !error; cl++) {
            if (!t->objects[cl])
                continue;
            dnode_t *dn;
            error = dnode_hold(c->spa->spa_meta_objset, t->objects[cl], tag, &dn);
            if (error)
                break;
            zap_t *destination;
            error = zap_lockdir(c->spa->spa_meta_objset, t->objects[cl],
                NULL, RW_READER, B_TRUE, B_FALSE, tag, &destination);
            uint64_t salt = 0, flags = 0;
            if (!error) {
                salt = destination->zap_salt;
                flags = zap_getflags(destination);
                if (destination->zap_ismicro || zap_hashbits(destination) != 48 ||
                    (flags & (ZAP_FLAG_HASH64 | ZAP_FLAG_UINT64_KEY)) !=
                    (ZAP_FLAG_HASH64 | ZAP_FLAG_UINT64_KEY))
                    error = EINVAL;
                zap_unlockdir(destination, tag);
            }
            physical_scan_t scan;
            if (!error)
                error = physical_scan_init(&scan, c, t, cl, READ_COPY, dn, entries);
            if (error) {
                dnode_rele(dn, tag);
                break;
            }
            uint64_t copied = 0;
            hrtime_t started = gethrtime();
            entry_progress(&scan, 0, started);
            boolean_t exhausted = B_FALSE;
            while (!error && !exhausted) {
                error = scan_run(&scan, started);
                if (error)
                    break;
                size_t produced = 0;
                exhausted = B_TRUE;
                for (unsigned int w = 0; w < scan.nworkers; w++) {
                    physical_worker_t *worker = &scan.workers[w];
                    exhausted &= worker->exhausted;
                    for (size_t j = 0; j < worker->produced; j++) {
                        size_t index = worker->offset + j;
                        order[produced++] = (entry_index_t) {
                            .hash = destination_hash(&entries[index].ddlwe_key,
                                flags, salt), .index = index
                        };
                    }
                }
                /* Sort only compact indexes, never entry payloads. Every
                 * producer has exited SCL_VDEV and released all ZAP/DBUF holds
                 * before any native syncing update or TXG wait starts. */
                qsort(order, produced, sizeof (*order), compare_entry_index);
                for (size_t offset = 0; offset < produced && !error;
                    offset += c->batch_size) {
                    if (stopping) { error = EINTR; break; }
                    batch_t batch = {
                        .c = c, .dn = dn, .entries = entries,
                        .order = order + offset,
                        .count = MIN(c->batch_size, produced - offset)
                    };
                    error = dsl_sync_task(spa_name(c->spa), NULL, copy_batch,
                        &batch, batch.count * 8, ZFS_SPACE_CHECK_NORMAL);
                    if (!error)
                        copied += batch.count;
                }
                entry_progress(&scan, copied, started);
            }
            ddt_histogram_t histogram;
            int final_error = scan_finish(&scan, &histogram);
            if (!error)
                error = final_error;
            if (!error && copied != t->counts[cl])
                error = EINVAL;
            if (!error) {
                /* Independent second physical source pass checks every staged
                 * native value and reconciles counts AND histograms again. */
                error = physical_scan_init(&scan, c, t, cl, READ_BACK, dn, NULL);
                if (!error) {
                    started = gethrtime();
                    entry_progress(&scan, 0, started);
                    error = scan_run(&scan, started);
                    entry_progress(&scan, scan.entries_done, started);
                    final_error = scan_finish(&scan, &histogram);
                    if (!error)
                        error = final_error;
                }
            }
            uint64_t count = 0;
            if (!error)
                error = ddt_zap_ops.ddt_op_count(dn, &count);
            if (!error && count != copied)
                error = EINVAL;
            dnode_rele(dn, tag);
            dmu_object_info_t info;
            if (!error)
                error = dmu_object_info(c->spa->spa_meta_objset,
                    t->objects[cl], &info);
            if (!error) {
                t->stats[cl].ddo_count = count;
                t->stats[cl].ddo_dspace = info.doi_physical_blocks_512 << 9;
                t->stats[cl].ddo_mspace =
                    info.doi_fill_count * info.doi_data_block_size;
            }
        }
    }
    free(order);
    free(entries);
    return (error ? problem(error, "shadow table physical copy/readback stopped") : 0);
}

static int
publish_check(void *arg, dmu_tx_t *tx)
{
    (void) tx;
    conversion_t *c = arg;
    if (stopping)
        return (EINTR);
    for (size_t i = 0; i < c->ntables; i++) {
        ddt_t *ddt = c->tables[i].ddt;
        if (ddt->ddt_version != DDT_VERSION_LEGACY ||
            !avl_is_empty(&ddt->ddt_tree) || !avl_is_empty(&ddt->ddt_repair_tree))
            return (EBUSY);
    }
    return (0);
}

/* Every authoritative link, format flag, and feature reference changes in one TXG. */
static void
publish_tables(void *arg, dmu_tx_t *tx)
{
    conversion_t *c = arg;
    objset_t *os = c->spa->spa_meta_objset;
    for (size_t i = 0; i < c->ntables; i++) {
        table_t *t = &c->tables[i];
        ddt_t *ddt = t->ddt;
        char dirname[DDT_NAMELEN];
        snprintf(dirname, sizeof (dirname), DMU_POOL_DDT_DIR,
            zio_checksum_table[ddt->ddt_checksum].ci_name);
        uint64_t dir = zap_create_link(os, DMU_OTN_ZAP_METADATA,
            DMU_POOL_DIRECTORY_OBJECT, dirname, tx);
        uint64_t version = DDT_VERSION_FDT;
        VERIFY0(zap_add(os, dir, DDT_DIR_VERSION, 8, 1, &version, tx));
        VERIFY0(zap_add(os, dir, DDT_DIR_FLAGS, 8, 1, &c->flags, tx));
        for (int cl = 0; cl < DDT_CLASSES; cl++) {
            uint64_t old = ddt->ddt_object[DDT_TYPE_ZAP][cl];
            if (!old)
                continue;
            char name[DDT_NAMELEN];
            ddt_object_name(ddt, DDT_TYPE_ZAP, cl, name);
            uint64_t object = (c->flags & DDT_FLAG_FLAT) ? t->objects[cl] : old;
            VERIFY0(zap_add(os, dir, name, 8, 1, &object, tx));
            VERIFY0(zap_remove(os, DMU_POOL_DIRECTORY_OBJECT, name, tx));
            if (c->flags & DDT_FLAG_FLAT) {
                char key[64];
                object_key(ddt, cl, key, sizeof (key));
                VERIFY0(zap_update(os, c->stage, key, 8, 1, &old, tx));
                dnode_rele(ddt->ddt_object_dnode[DDT_TYPE_ZAP][cl], ddt);
                ddt->ddt_object[DDT_TYPE_ZAP][cl] = object;
                VERIFY0(dnode_hold(os, object, ddt,
                    &ddt->ddt_object_dnode[DDT_TYPE_ZAP][cl]));
                ddt->ddt_histogram[DDT_TYPE_ZAP][cl] = t->hist[cl];
                ddt->ddt_histogram_cache[DDT_TYPE_ZAP][cl] = t->hist[cl];
                ddt->ddt_object_stats[DDT_TYPE_ZAP][cl] = t->stats[cl];
                VERIFY0(zap_update(os, c->spa->spa_ddt_stat_object, name, 8,
                    sizeof (ddt_histogram_t) / 8, &t->hist[cl], tx));
            }
        }
        ddt->ddt_dir_object = dir;
        ddt->ddt_version = version;
        ddt->ddt_flags = c->flags;
        spa_feature_incr(c->spa, SPA_FEATURE_FAST_DEDUP, tx);
    }
    c->spa->spa_dedup_dspace = ~0ULL;
    c->spa->spa_dedup_dsize = ~0ULL;
}

static void
reclaim_range(void *arg, dmu_tx_t *tx)
{
    reclaim_t *r = arg;
    VERIFY0(dmu_free_range(r->c->spa->spa_meta_objset, r->object,
        r->offset, r->length, tx));
}

static void
reclaim_object(void *arg, dmu_tx_t *tx)
{
    reclaim_t *r = arg;
    objset_t *os = r->c->spa->spa_meta_objset;
    VERIFY0(dmu_object_free(os, r->object, tx));
    VERIFY0(zap_remove(os, r->c->stage, r->name, tx));
}

static void
remove_stage(void *arg, dmu_tx_t *tx)
{
    conversion_t *c = arg;
    VERIFY0(zap_destroy(c->spa->spa_meta_objset, c->stage, tx));
    VERIFY0(zap_remove(c->spa->spa_meta_objset, DMU_POOL_DIRECTORY_OBJECT,
        STAGE_KEY, tx));
    c->stage = 0;
}

static void
reclaim_progress(const reclaim_t *r, uint64_t total, uint64_t remaining,
    hrtime_t started, const char *state)
{
    uint64_t done = total - remaining;
    double seconds = (gethrtime() - started) / (double)NANOSEC;
    double rate = seconds > 0 ? done / seconds : 0;
    char eta[64] = "null";
    if (strcmp(state, "complete") == 0)
        snprintf(eta, sizeof (eta), "0");
    else if (remaining && rate > 0)
        snprintf(eta, sizeof (eta), "%.1f", remaining / rate);
    fprintf(stderr, "{\"timestamp\":%llu,\"phase\":\"stage-reclaim\","
        "\"object\":\"%llu\",\"state\":\"%s\",\"bytes\":%llu,"
        "\"total_bytes\":%llu,\"elapsed_seconds\":%.3f,"
        "\"bytes_per_second\":%.3f,\"eta_seconds\":%s}\n",
        (u_longlong_t)gethrestime_sec(), (u_longlong_t)r->object, state,
        (u_longlong_t)done, (u_longlong_t)total, seconds, rate, eta);
    fflush(stderr);
}

/* Discard staged copies because intervening imports can change source tables. */
static int
cleanup_stage(conversion_t *c)
{
    objset_t *os = c->spa->spa_meta_objset;
    int error = zap_lookup(os, DMU_POOL_DIRECTORY_OBJECT, STAGE_KEY, 8, 1, &c->stage);
    if (error == ENOENT)
        return (0);
    if (error)
        return (error);
    uint64_t format, guid;
    if (zap_lookup(os, c->stage, "format", 8, 1, &format) ||
        zap_lookup(os, c->stage, "pool_guid", 8, 1, &guid) ||
        format != STAGE_FORMAT || guid != spa_guid(c->spa))
        return (problem(EINVAL, "unrecognized staging metadata; refusing cleanup"));
    for (;;) {
        zap_cursor_t cursor;
        zap_attribute_t *attr = zap_attribute_alloc();
        reclaim_t r = { .c = c };
        zap_cursor_init(&cursor, os, c->stage);
        while ((error = zap_cursor_retrieve(&cursor, attr)) == 0) {
            if (strncmp(attr->za_name, "obj-", 4) == 0) {
                strlcpy(r.name, attr->za_name, sizeof (r.name));
                if (attr->za_integer_length != 8 || attr->za_num_integers != 1)
                    error = EINVAL;
                else
                    r.object = attr->za_first_integer;
                break;
            }
            if (strcmp(attr->za_name, "format") && strcmp(attr->za_name, "pool_guid")) {
                error = EINVAL;
                break;
            }
            zap_cursor_advance(&cursor);
        }
        zap_cursor_fini(&cursor);
        zap_attribute_free(attr);
        if (error == ENOENT)
            break;
        if (error)
            return (error);
        if (!r.object)
            return (EINVAL);
        /* Reclamation is restricted to objects outside authoritative DDTs. */
        for (int ck = 0; ck < ZIO_CHECKSUM_FUNCTIONS; ck++) {
            ddt_t *ddt = c->spa->spa_ddt[ck];
            if (ddt == NULL) continue;
            for (int cl = 0; cl < DDT_CLASSES; cl++)
                if (ddt->ddt_object[DDT_TYPE_ZAP][cl] == r.object)
                    return (problem(EINVAL, "staging points at live DDT object"));
        }
        dmu_object_info_t info;
        error = dmu_object_info(os, r.object, &info);
        if (error || info.doi_type != DMU_OT_DDT_ZAP)
            return (problem(error ? error : EINVAL, "invalid staging object type"));
        /* MOS objects require assigned syncing transactions. Retain the stage
         * link until range reclamation and object destruction commit. */
        printf("reclaiming staging object=%llu\n", (u_longlong_t)r.object);
        uint64_t end = info.doi_max_offset;
        uint64_t total = end;
        hrtime_t started = gethrtime();
        reclaim_progress(&r, total, end, started, "freeing-ranges");
        while (end && !error) {
            r.offset = P2ALIGN_TYPED(end - 1, 64ULL << 20, uint64_t);
            r.length = end - r.offset;
            error = dsl_sync_task(spa_name(c->spa), NULL, reclaim_range,
                &r, 64, ZFS_SPACE_CHECK_DESTROY);
            end = r.offset;
            if (!error)
                reclaim_progress(&r, total, end, started,
                    end ? "freeing-ranges" : "destroying-object");
            if (stopping && !error) error = EINTR;
        }
        if (!error)
            error = dsl_sync_task(spa_name(c->spa), NULL, reclaim_object,
                &r, 8, ZFS_SPACE_CHECK_DESTROY);
        if (error)
            return (error);
        reclaim_progress(&r, total, 0, started, "complete");
        if (stopping)
            return (EINTR);
    }
    return (dsl_sync_task(spa_name(c->spa), NULL, remove_stage,
        c, 8, ZFS_SPACE_CHECK_DESTROY));
}

static int
parse_uint(const char *text, uint64_t *result)
{
    if (*text == '\0') return (EINVAL);
    for (const char *s = text; *s; s++)
        if (*s < '0' || *s > '9') return (EINVAL);
    errno = 0;
    char *end;
    *result = strtoull(text, &end, 10);
    return (errno || *end || *result == 0 ? EINVAL : 0);
}
static unsigned int
default_workers(void)
{
    cpu_set_t affinity;
    if (sched_getaffinity(0, sizeof (affinity), &affinity) == 0) {
        unsigned int count = CPU_COUNT(&affinity);
        if (count > 0)
            return (MIN(count, MAX_WORKERS));
    }
    long count = sysconf(_SC_NPROCESSORS_ONLN);
    return (count > 0 ? MIN(count, MAX_WORKERS) : 1);
}

/* A registered-object census, NOT entry eligibility validation. Admission
 * callers compare these exact identities/counts to their passed baseline. */
static int
describe_state(conversion_t *c)
{
    int error = quiescent(c->spa);
    if (error)
        return (error);
    int stage = zap_contains(c->spa->spa_meta_objset,
        DMU_POOL_DIRECTORY_OBJECT, STAGE_KEY);
    if (stage != 0 && stage != ENOENT)
        return (problem(stage, "cannot inspect registered staging state"));
    printf("{\"format\":\"convert-ddt-state-v1\",\"pool_guid\":\"%llu\","
        "\"exported\":true,\"staging_present\":%s,\"tables\":[",
        (u_longlong_t)spa_guid(c->spa), stage == 0 ? "true" : "false");
    boolean_t first_table = B_TRUE;
    for (int checksum = 0; checksum < ZIO_CHECKSUM_FUNCTIONS; checksum++) {
        ddt_t *ddt = c->spa->spa_ddt[checksum];
        if (ddt == NULL || ddt->ddt_version == DDT_VERSION_UNCONFIGURED)
            continue;
        printf("%s{\"checksum\":%d,\"version\":%llu,\"flags\":%llu,"
            "\"stores\":[", first_table ? "" : ",", checksum,
            (u_longlong_t)ddt->ddt_version, (u_longlong_t)ddt->ddt_flags);
        first_table = B_FALSE;
        boolean_t first_store = B_TRUE;
        for (int type = 0; type < DDT_TYPES; type++) {
            for (int cl = 0; cl < DDT_CLASSES; cl++) {
                uint64_t object = ddt->ddt_object[type][cl], count;
                if (object == 0)
                    continue;
                error = ddt_object_count(ddt, type, cl, &count);
                if (error)
                    return (problem(error, "cannot census registered DDT store"));
                printf("%s{\"type\":%d,\"class\":%d,\"object\":\"%llu\","
                    "\"count\":\"%llu\"}", first_store ? "" : ",", type, cl,
                    (u_longlong_t)object, (u_longlong_t)count);
                first_store = B_FALSE;
            }
        }
        fputs("]}", stdout);
    }
    puts("]}");
    return (0);
}


static void
usage(FILE *out)
{
    fputs("Usage: convert-ddt (--describe | --check | --convert --fenced)\n"
        "  --pool-guid DECIMAL --search-dir DIRECTORY [--journal-only]\n"
        "  [--batch-size 1..65536] [--read-batch-entries 1..1000000] [--workers 1..64]\n"
        "Export the pool first. --fenced asserts exclusive access, with automatic\n"
        "imports and other administrators fenced for the entire operation.\n"
        "Default: version=1 FLAT|LOG. --journal-only: version=1 LOG, traditional entries.\n"
        "--describe emits a readonly registered-state JSON census, not eligibility proof.\n"
        "--workers bounds physical metadata readers (default: CPU affinity, at most 64).\n"
        "--read-batch-entries bounds source payloads (default: 1000000); reader/sort\n"
        "structures together are limited to 1 GiB, separately from native ARC.\n"
        "Requires OpenZFS 2.4.4.\n", out);
}

int
main(int argc, char **argv)
{
    boolean_t convert = B_FALSE, check = B_FALSE, describe = B_FALSE;
    boolean_t fenced = B_FALSE;
    uint64_t guid = 0, batch_size = 1024, workers = default_workers();
    uint64_t read_batch_entries = MAX_READ_BATCH_ENTRIES;
    char *search = NULL;
    uint64_t flags = DDT_FLAG_FLAT | DDT_FLAG_LOG;
    static const struct option options[] = {
        {"check", no_argument, NULL, 'c'}, {"convert", no_argument, NULL, 'w'},
        {"describe", no_argument, NULL, 's'},
        {"fenced", no_argument, NULL, 'f'}, {"pool-guid", required_argument, NULL, 'g'},
        {"search-dir", required_argument, NULL, 'd'},
        {"journal-only", no_argument, NULL, 'j'},
        {"batch-size", required_argument, NULL, 'b'},
        {"read-batch-entries", required_argument, NULL, 'r'},
        {"workers", required_argument, NULL, 'p'},
        {"help", no_argument, NULL, 'h'}, {NULL, 0, NULL, 0}
    };
    int opt;
    while ((opt = getopt_long(argc, argv, "", options, NULL)) != -1) {
        switch (opt) {
        case 'c': check = B_TRUE; break;
        case 's': describe = B_TRUE; break;
        case 'w': convert = B_TRUE; break;
        case 'f': fenced = B_TRUE; break;
        case 'g': if (parse_uint(optarg, &guid)) { usage(stderr); return (2); } break;
        case 'd': search = optarg; break;
        case 'j': flags = DDT_FLAG_LOG; break;
        case 'b': if (parse_uint(optarg, &batch_size) || batch_size > 65536)
            { usage(stderr); return (2); } break;
        case 'r':
            if (parse_uint(optarg, &read_batch_entries) ||
                read_batch_entries > MAX_READ_BATCH_ENTRIES)
                { usage(stderr); return (2); }
            break;
        case 'p': if (parse_uint(optarg, &workers) || workers > MAX_WORKERS)
            { usage(stderr); return (2); } break;
        case 'h': usage(stdout); return (0);
        default: usage(stderr); return (2);
        }
    }
    if (optind != argc || (int)check + (int)convert + (int)describe != 1 ||
        !guid || !search || (convert && !fenced)) { usage(stderr); return (2); }
    if (geteuid() != 0) return (problem(EPERM, "root required"));
    if (getenv("ZFS_HOSTID") != NULL)
        return (problem(EINVAL, "ZFS_HOSTID override is not permitted"));
    FILE *version_file = fopen("/sys/module/zfs/version", "r");
    char version[128];
    if (version_file == NULL || fgets(version, sizeof (version), version_file) == NULL)
        return (problem(ENODEV, "cannot identify kernel ZFS version"));
    fclose(version_file);
    if (strncmp(version, "2.4.4", 5) || (version[5] != '-' && version[5] != '\n' && version[5] != '\0'))
        return (problem(ENOTSUP, "this binary requires OpenZFS 2.4.4"));
    char lockpath[128];
    snprintf(lockpath, sizeof (lockpath), "/run/lock/convert-ddt-%llu.lock",
        (u_longlong_t)guid);
    int lockfd = open(lockpath, O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (lockfd < 0 || flock(lockfd, LOCK_EX | LOCK_NB) != 0)
        return (problem(errno, "cannot acquire converter lock"));
    int error = reject_kernel_pool(guid);
    if (error) { close(lockfd); return (1); }
    setvbuf(stdout, NULL, _IOLBF, 0);
    struct sigaction action = { .sa_handler = on_signal };
    sigemptyset(&action.sa_mask);
    sigaction(SIGINT, &action, NULL);
    sigaction(SIGTERM, &action, NULL);
    /* Keep source tables stable by deferring scans and asynchronous frees. */
    if (handle_tunable_option("zfs_import_defer_txgs=4294967295", B_TRUE))
        return (problem(EINVAL, "cannot defer background DDT mutations"));
    /* Start with an immutable empty cache in a private userspace SPA namespace. */
    int cachefd = memfd_create("convert-ddt-cache", MFD_CLOEXEC | MFD_ALLOW_SEALING);
    if (cachefd < 0 || fcntl(cachefd, F_ADD_SEALS,
        F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL) != 0) {
        int cache_error = errno;
        if (cachefd >= 0) close(cachefd);
        close(lockfd);
        return (problem(cache_error, "cannot create private configuration cache"));
    }
    char cachepath[64];
    snprintf(cachepath, sizeof (cachepath), "/proc/self/fd/%d", cachefd);
    spa_config_path = cachepath;
    kernel_init(SPA_MODE_READ);
    /* Retain metadata between full-table passes; libzpool's pressure model
     * is randomized for stress tests, not based on this process's RAM. */
    zfs_arc_min = arc_c_max;
    arc_tuning_update(B_FALSE);
    nvlist_t *config = NULL, *props = fnvlist_alloc();
    char target[32];
    snprintf(target, sizeof (target), "%llu", (u_longlong_t)guid);
    importargs_t args = { .path = &search, .paths = 1, .guid = guid, .scan = B_TRUE };
    libpc_handle_t handle = { .lpc_ops = &libzpool_config_ops, .lpc_printerr = B_TRUE };
    spa_t *spa = NULL;
    char *pool = NULL;
    boolean_t imported = B_FALSE, writeable = B_FALSE;
    conversion_t *c = calloc(1, sizeof (*c));
    if (c == NULL) { error = ENOMEM; goto out; }
    error = zpool_find_config(&handle, target, &config, &args);
    if (error) { problem(error, "cannot discover exported target pool"); goto out; }
    uint64_t discovered, state;
    const char *name;
    if (nvlist_lookup_uint64(config, ZPOOL_CONFIG_POOL_GUID, &discovered) ||
        discovered != guid ||
        nvlist_lookup_uint64(config, ZPOOL_CONFIG_POOL_STATE, &state) ||
        state != POOL_STATE_EXPORTED ||
        nvlist_lookup_string(config, ZPOOL_CONFIG_POOL_NAME, &name)) {
        error = problem(EINVAL, "target identity/export state mismatch"); goto out;
    }
    pool = strdup(name);
    if (pool == NULL) { error = ENOMEM; goto out; }
    error = reject_kernel_pool(guid);
    if (error) goto out;
    fnvlist_add_string(props, "cachefile", "none");
    fnvlist_add_uint64(props, "readonly", 1);
    error = spa_import(pool, config, props, ZFS_IMPORT_NORMAL);
    if (error) { problem(error, "normal userspace import failed"); goto out; }
    imported = B_TRUE;
    error = spa_open(pool, &spa, tag);
    if (error) { problem(error, "cannot open userspace pool"); goto out; }
    if (spa_guid(spa) != guid) { error = EINVAL; goto out; }
    spa_config_enter(spa, SCL_STATE_ALL, tag, RW_WRITER);
    error = exported_leaf_labels(spa->spa_root_vdev);
    spa_config_exit(spa, SCL_STATE_ALL, tag);
    if (error) goto out;
    error = zap_contains(spa->spa_meta_objset, DMU_POOL_DIRECTORY_OBJECT,
        "org.rebuild-ddt:staging");
    if (error != ENOENT) {
        error = problem(error == 0 ? EBUSY : error,
            "unfinished legacy rebuild maintenance; recovery is required before conversion");
        goto out;
    }
    if (convert) {
        /* Check maintenance state before writable import starts background workers. */
        error = quiescent(spa);
        if (error || stopping) { if (!error) error = EINTR; goto out; }
        spa_close(spa, tag);
        spa = NULL;
        kernel_fini();
        imported = B_FALSE;
        kernel_init(SPA_MODE_READ | SPA_MODE_WRITE);
        zfs_arc_min = arc_c_max;
        arc_tuning_update(B_FALSE);
        VERIFY0(nvlist_remove_all(props, "readonly"));
        error = reject_kernel_pool(guid);
        if (error) goto out;
        error = spa_import(pool, config, props, ZFS_IMPORT_NORMAL);
        if (error) { problem(error, "normal writable import failed"); goto out; }
        imported = writeable = B_TRUE;
        error = spa_open(pool, &spa, tag);
        if (error) { problem(error, "cannot open writable pool"); goto out; }
        if (spa_guid(spa) != guid) { error = EINVAL; goto out; }
        spa_async_suspend(spa);
        txg_wait_synced(spa_get_dsl(spa), 0);
    }
    c->spa = spa;
    if (describe) {
        error = describe_state(c);
        goto out;
    }
    c->flags = flags;
    c->timestamp = gethrestime_sec();
    c->batch_size = batch_size;
    c->read_batch_entries = read_batch_entries;
    c->workers = workers;
    error = inspect(c);
    if (error) goto out;
    if (check) {
        printf("check complete: %zu legacy table(s) eligible for %s\n",
            c->ntables, flags & DDT_FLAG_FLAT ? "FLAT|LOG" : "LOG (traditional phys)");
        goto out;
    }
    error = cleanup_stage(c);
    if (error) goto out;
    if (!c->ntables) {
        puts("no legacy tables need conversion");
        goto out;
    }
    if (flags & DDT_FLAG_FLAT) {
        error = dsl_sync_task(pool, NULL, create_stage, c, 128, ZFS_SPACE_CHECK_NORMAL);
        if (!error) error = copy_tables(c);
        if (error) goto out;
    }
    /* Plans reference legacy source object identities. Drop all of them
     * before publication replaces DDT dnodes or reclamation frees old stores. */
    if (c->readers != NULL) {
        taskq_destroy(c->readers);
        c->readers = NULL;
    }
    dp_plan_fini(&c->plan);
    error = quiescent(c->spa);
    if (error) goto out;
    error = dsl_sync_task(pool, publish_check, publish_tables, c, 128, ZFS_SPACE_CHECK_NORMAL);
    if (error) { problem(error, "atomic publication failed"); goto out; }
    printf("published %zu table(s): version=1 flags=%llu\n", c->ntables,
        (u_longlong_t)flags);
    if (flags & DDT_FLAG_FLAT)
        error = cleanup_stage(c);
out:
    if (c != NULL) {
        if (c->readers != NULL)
            taskq_destroy(c->readers);
        dp_plan_fini(&c->plan);
    }
    if (spa != NULL) {
        if (writeable) txg_wait_synced(spa_get_dsl(spa), 0);
        spa_close(spa, tag);
    }
    if (imported && writeable) {
        int export_error = spa_export(pool, NULL, B_FALSE, B_FALSE);
        if (export_error) {
            problem(export_error, "export failed; do not import elsewhere until resolved");
            error = export_error;
        } else {
            puts("pool cleanly exported");
        }
    }
    nvlist_free(config);
    nvlist_free(props);
    free(pool);
    free(c);
    kernel_fini();
    close(cachefd);
    close(lockfd);
    if (error == EINTR || stopping) return (130);
    if (error) return (1);
    if (!describe)
        puts("conversion command completed");
    return (0);
}
