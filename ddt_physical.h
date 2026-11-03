/* SPDX-License-Identifier: CDDL-1.0
 * Native, bounded physical-address planning for quiescent DDT ZAP objects.
 * Callers retain the dnodes and guarantee no source-object mutation until
 * every plan and leaf hold has been released. This is not an entry decoder.
 */
#ifndef CONVERT_DDT_PHYSICAL_H
#define CONVERT_DDT_PHYSICAL_H

#include <sys/arc.h>
#include <sys/dbuf.h>
#include <sys/dnode.h>
#include <sys/dmu_objset.h>
#include <sys/zap_impl.h>
#include <sys/zap_leaf.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define DP_HASH_SPACE (1ULL << 48)
#define DP_MAX_WORKERS 64
#define DP_DISPATCH_BLOCKS 8
/* Reserve glibc qsort's linear scratch and its small stack fallback. */
#define DP_SORT_RESERVE 4096

typedef struct dp_block {
    uint64_t offset, blkid;
    uint32_t vdev, store; /* one-based store; zero is a verified hole */
} dp_block_t;
_Static_assert(sizeof (dp_block_t) == 24, "compact physical block descriptor");

typedef struct dp_store {
    spa_t *spa;
    objset_t *os;
    dnode_t *dn;
    uint64_t object;
    uint64_t blocksize, nblocks, logical_bytes;
    size_t base, first_task, ntasks;
    unsigned int epbs, levels;
} dp_store_t;

typedef struct dp_plan {
    dp_block_t *blocks;
    size_t nblocks, capacity, nstores;
    dp_store_t *stores; /* borrowed, as are all dnode holds */
    uint64_t logical_bytes, hole_bytes, allocation_bytes, peak_bytes;
    uint64_t planning_tasks, planned_tasks;
    volatile sig_atomic_t *cancel;
    pthread_mutex_t mutex;
    size_t next_task;
    int error;
    boolean_t mutex_ready;
} dp_plan_t;

typedef struct dp_leaf {
    boolean_t is_leaf;
    uint64_t blkid, hash_start, hash_end, nentries;
    unsigned int prefix_len;
    dmu_buf_impl_t *db;
} dp_leaf_t;

static inline boolean_t
dp_cancelled(const dp_plan_t *plan)
{
    return (plan->cancel != NULL && *plan->cancel != 0);
}

static int
dp_store_geometry(dp_store_t *store)
{
    dnode_t *dn = store->dn;
    if (dn == NULL || store->spa == NULL || store->os == NULL)
        return (EINVAL);
    rw_enter(&dn->dn_struct_rwlock, RW_READER);
    uint64_t maxblkid = dn->dn_maxblkid;
    uint64_t blocksize = dn->dn_datablksz;
    unsigned int shift = dn->dn_datablkshift;
    unsigned int levels = dn->dn_nlevels, indirect_shift = dn->dn_indblkshift;
    if (dn->dn_dbuf != NULL) rw_enter(&dn->dn_dbuf->db_rwlock, RW_READER);
    unsigned int nblkptr = dn->dn_phys->dn_nblkptr;
    boolean_t synced = levels == dn->dn_phys->dn_nlevels &&
        maxblkid == dn->dn_phys->dn_maxblkid;
    if (dn->dn_dbuf != NULL) rw_exit(&dn->dn_dbuf->db_rwlock);
    rw_exit(&dn->dn_struct_rwlock);
    if (blocksize == 0 || blocksize > DMU_MAX_ACCESS || shift >= 64 ||
        (shift != 0 && blocksize != (1ULL << shift)) ||
        (shift == 0 && maxblkid != 0)) return (EINVAL);
    if (!synced || levels == 0 || levels > DN_MAX_LEVELS ||
        indirect_shift < DN_MIN_INDBLKSHIFT ||
        indirect_shift > DN_MAX_INDBLKSHIFT || nblkptr == 0 ||
        nblkptr > DN_MAX_NBLKPTR) return (ENOTSUP);
    unsigned int epbs = indirect_shift - SPA_BLKPTRSHIFT;
    unsigned int top_shift = (levels - 1) * epbs;
    if (top_shift >= 64 ||
        (unsigned __int128)maxblkid >= ((unsigned __int128)nblkptr << top_shift) ||
        maxblkid == UINT64_MAX || maxblkid + 1 > UINT64_MAX / blocksize)
        return (EOVERFLOW);
    store->blocksize = blocksize;
    store->nblocks = maxblkid + 1;
    store->logical_bytes = store->nblocks * blocksize;
    store->epbs = epbs;
    store->levels = levels;
    uint64_t tasks = levels == 1 ? 1 : (maxblkid >> epbs) + 1;
    if (tasks > SIZE_MAX) return (EOVERFLOW);
    store->ntasks = (size_t)tasks;
    return (0);
}

static int
dp_record_pointer(dp_plan_t *plan, size_t s, uint64_t blkid,
    const blkptr_t *bp, uint64_t *holes)
{
    dp_store_t *store = &plan->stores[s];
    if (BP_IS_HOLE(bp)) {
        *holes += store->blocksize;
        return (0);
    }
    if (BP_IS_EMBEDDED(bp)) return (ENOTSUP);
    if (BP_GET_LEVEL(bp) != 0 || BP_GET_LSIZE(bp) != store->blocksize ||
        BP_GET_TYPE(bp) != store->dn->dn_type ||
        !DVA_IS_VALID(&bp->blk_dva[0])) return (EINVAL);
    dp_block_t *block = &plan->blocks[store->base + (size_t)blkid];
    block->offset = DVA_GET_OFFSET(&bp->blk_dva[0]);
    block->vdev = DVA_GET_VDEV(&bp->blk_dva[0]);
    block->blkid = blkid;
    block->store = (uint32_t)s + 1;
    return (0);
}

static int
dp_plan_indirect(dp_plan_t *plan, size_t s, uint64_t indirect, uint64_t *holes)
{
    dp_store_t *store = &plan->stores[s];
    dnode_t *dn = store->dn;
    int error = 0;
    rw_enter(&dn->dn_struct_rwlock, RW_READER);
    if (store->levels == 1) {
        if (dn->dn_dbuf != NULL) rw_enter(&dn->dn_dbuf->db_rwlock, RW_READER);
        for (uint64_t b = 0; b < store->nblocks && !error; b++)
            error = dp_record_pointer(plan, s, b, &dn->dn_phys->dn_blkptr[b], holes);
        if (dn->dn_dbuf != NULL) rw_exit(&dn->dn_dbuf->db_rwlock);
        rw_exit(&dn->dn_struct_rwlock);
        return (error);
    }
    dmu_buf_impl_t *db = NULL;
    error = dbuf_hold_impl(dn, 1, indirect, B_FALSE, B_FALSE, plan, &db);
    rw_exit(&dn->dn_struct_rwlock);
    if (error) return (error);
    error = dbuf_read(db, NULL, DB_RF_CANFAIL | DMU_READ_NO_PREFETCH);
    if (!error) {
        uint64_t first = indirect << store->epbs;
        uint64_t count = MIN(1ULL << store->epbs, store->nblocks - first);
        rw_enter(&db->db_rwlock, RW_READER);
        if (db->db.db_data == NULL ||
            db->db.db_size != (1ULL << (store->epbs + SPA_BLKPTRSHIFT))) {
            error = EINVAL;
        } else {
            const blkptr_t *bps = db->db.db_data;
            for (uint64_t b = 0; b < count && !error; b++)
                error = dp_record_pointer(plan, s, first + b, &bps[b], holes);
        }
        rw_exit(&db->db_rwlock);
    }
    dbuf_rele(db, plan);
    return (error);
}

static void *
dp_plan_worker(void *arg)
{
    dp_plan_t *plan = arg;
    for (;;) {
        pthread_mutex_lock(&plan->mutex);
        size_t first = plan->next_task;
        size_t count = MIN((size_t)DP_DISPATCH_BLOCKS,
            (size_t)plan->planning_tasks - first);
        plan->next_task += count;
        pthread_mutex_unlock(&plan->mutex);
        if (count == 0 || dp_cancelled(plan) ||
            __atomic_load_n(&plan->error, __ATOMIC_RELAXED)) break;
        for (size_t t = first; t < first + count; t++) {
            if (dp_cancelled(plan) ||
                __atomic_load_n(&plan->error, __ATOMIC_RELAXED)) break;
            size_t s = 0;
            while (s < plan->nstores && t >= plan->stores[s].first_task +
                plan->stores[s].ntasks) s++;
            uint64_t holes = 0;
            int error = s == plan->nstores ? EINVAL : dp_plan_indirect(plan, s,
                t - plan->stores[s].first_task, &holes);
            if (error) {
                int expected = 0;
                __atomic_compare_exchange_n(&plan->error, &expected, error,
                    B_FALSE, __ATOMIC_RELAXED, __ATOMIC_RELAXED);
                break;
            }
            __atomic_fetch_add(&plan->hole_bytes, holes, __ATOMIC_RELAXED);
            __atomic_fetch_add(&plan->planned_tasks, 1, __ATOMIC_RELAXED);
        }
    }
    return (NULL);
}

static int
dp_block_compare(const void *a, const void *b)
{
    const dp_block_t *x = a, *y = b;
    if (x->vdev != y->vdev) return (x->vdev < y->vdev ? -1 : 1);
    if (x->offset != y->offset) return (x->offset < y->offset ? -1 : 1);
    if (x->store != y->store) return (x->store < y->store ? -1 : 1);
    return (x->blkid < y->blkid ? -1 : x->blkid != y->blkid);
}

/* Produce a single indexed execution sequence: ascending physical offsets
 * per vdev, interleaved in bounded quanta so no vdev starves another. */
static int
dp_plan_sort(dp_plan_t *plan, uint64_t budget)
{
    if (plan->nblocks < 2) return (0);
    qsort(plan->blocks, plan->nblocks, sizeof (*plan->blocks), dp_block_compare);
    if (dp_cancelled(plan)) return (EINTR);
    size_t runs = 1;
    for (size_t b = 1; b < plan->nblocks; b++)
        if (plan->blocks[b].vdev != plan->blocks[b - 1].vdev) runs++;
    if (runs == 1) return (0);
    typedef struct dp_run { size_t next, end; } dp_run_t;
    uint64_t scratch_bytes = plan->nblocks * sizeof (dp_block_t);
    uint64_t run_bytes = runs * sizeof (dp_run_t);
    if (plan->allocation_bytes > budget ||
        scratch_bytes > budget - plan->allocation_bytes ||
        run_bytes > budget - plan->allocation_bytes - scratch_bytes)
        return (E2BIG);
    plan->peak_bytes = MAX(plan->peak_bytes,
        plan->allocation_bytes + scratch_bytes + run_bytes);
    dp_block_t *scratch = malloc((size_t)scratch_bytes);
    dp_run_t *run = calloc(runs, sizeof (*run));
    if (scratch == NULL || run == NULL) {
        free(scratch);
        free(run);
        return (ENOMEM);
    }
    size_t r = 0;
    for (size_t b = 1; b <= plan->nblocks; b++) {
        if (b != plan->nblocks &&
            plan->blocks[b].vdev == plan->blocks[b - 1].vdev) continue;
        run[r].end = b;
        if (++r < runs) run[r].next = b;
    }
    size_t out = 0;
    while (out < plan->nblocks && !dp_cancelled(plan)) {
        for (r = 0; r < runs; r++) {
            size_t count = MIN((size_t)DP_DISPATCH_BLOCKS,
                run[r].end - run[r].next);
            memcpy(&scratch[out], &plan->blocks[run[r].next],
                count * sizeof (*scratch));
            run[r].next += count;
            out += count;
        }
    }
    if (!dp_cancelled(plan))
        memcpy(plan->blocks, scratch, (size_t)scratch_bytes);
    free(run);
    free(scratch);
    return (dp_cancelled(plan) ? EINTR : 0);
}

static void
dp_plan_fini(dp_plan_t *plan)
{
    free(plan->blocks);
    if (plan->mutex_ready) pthread_mutex_destroy(&plan->mutex);
    plan->blocks = NULL;
    plan->mutex_ready = B_FALSE;
}

/* Budget covers retained descriptors, qsort scratch, fair-dispatch scratch,
 * and bounded planner bookkeeping. Native ARC/dbuf caching is separate. The
 * caller supplies a zero-initialized plan and calls fini even on failure.
 * Fini preserves progress counters; zero again before another build. */
static int
dp_plan_build(dp_plan_t *plan, dp_store_t *stores, size_t nstores,
    unsigned int workers, uint64_t budget, volatile sig_atomic_t *cancel)
{
    if (plan->blocks != NULL || plan->mutex_ready) return (EBUSY);
    if (workers == 0 || workers > DP_MAX_WORKERS || nstores > UINT32_MAX ||
        (nstores != 0 && stores == NULL)) return (EINVAL);
    plan->stores = stores;
    plan->nstores = nstores;
    plan->cancel = cancel;
    int error = pthread_mutex_init(&plan->mutex, NULL);
    if (error) return (error);
    plan->mutex_ready = B_TRUE;
    for (size_t s = 0; s < nstores; s++) {
        dp_store_t *store = &stores[s];
        error = dp_store_geometry(store);
        if (error) return (error);
        if (store->nblocks > SIZE_MAX - plan->capacity ||
            store->ntasks > SIZE_MAX - plan->planning_tasks ||
            store->logical_bytes > UINT64_MAX - plan->logical_bytes)
            return (EOVERFLOW);
        store->base = plan->capacity;
        store->first_task = (size_t)plan->planning_tasks;
        plan->capacity += (size_t)store->nblocks;
        plan->planning_tasks += store->ntasks;
        plan->logical_bytes += store->logical_bytes;
    }
    if (plan->capacity > SIZE_MAX / sizeof (dp_block_t)) return (EOVERFLOW);
    uint64_t bytes = plan->capacity * sizeof (dp_block_t);
    uint64_t fixed = sizeof (*plan) + DP_MAX_WORKERS * sizeof (pthread_t) +
        nstores * sizeof (dp_store_t) + DP_SORT_RESERVE;
    if (fixed > budget || bytes > (budget - fixed) / 2) return (E2BIG);
    plan->allocation_bytes = bytes + fixed;
    plan->peak_bytes = plan->allocation_bytes + bytes;
    if (plan->capacity != 0) {
        plan->blocks = calloc(plan->capacity, sizeof (*plan->blocks));
        if (plan->blocks == NULL) return (ENOMEM);
    }
    pthread_t threads[DP_MAX_WORKERS];
    unsigned int started = 0;
    workers = (unsigned int)MIN((uint64_t)workers, plan->planning_tasks);
    while (started < workers && !dp_cancelled(plan) &&
        !__atomic_load_n(&plan->error, __ATOMIC_RELAXED)) {
        error = pthread_create(&threads[started], NULL, dp_plan_worker, plan);
        if (error) {
            __atomic_store_n(&plan->error, error, __ATOMIC_RELAXED);
            break;
        }
        started++;
    }
    for (unsigned int w = 0; w < started; w++) pthread_join(threads[w], NULL);
    error = __atomic_load_n(&plan->error, __ATOMIC_RELAXED);
    if (!error && dp_cancelled(plan)) error = EINTR;
    if (!error && plan->planned_tasks != plan->planning_tasks) error = EIO;
    if (error) return (error);
    for (size_t b = 0; b < plan->capacity; b++) {
        if (dp_cancelled(plan)) return (EINTR);
        if (plan->blocks[b].store == 0) continue;
        if (b != plan->nblocks) plan->blocks[plan->nblocks] = plan->blocks[b];
        plan->nblocks++;
    }
    return (dp_plan_sort(plan, budget));
}

/* ARC's identity remains primary DVA + birth. Restrict replica choice while
 * retaining native checksums; an unreadable primary fails, not a fake warm. */
static int
dp_primary_hold(const dp_plan_t *plan, const dp_block_t *block,
    dmu_buf_impl_t **dbp)
{
    *dbp = NULL;
    if (block->store == 0 || block->store > plan->nstores) return (EINVAL);
    dp_store_t *store = &plan->stores[block->store - 1];
    if (block->blkid >= store->nblocks) return (EINVAL);
    dmu_buf_impl_t *db = NULL;
    rw_enter(&store->dn->dn_struct_rwlock, RW_READER);
    int error = dbuf_hold_impl(store->dn, 0, block->blkid,
        B_FALSE, B_FALSE, plan, &db);
    rw_exit(&store->dn->dn_struct_rwlock);
    if (error) return (error);
    blkptr_t bp;
    mutex_enter(&db->db_mtx);
    if (db->db_blkptr == NULL) error = EINVAL;
    else bp = *db->db_blkptr;
    mutex_exit(&db->db_mtx);
    if (!error && (BP_IS_HOLE(&bp) || BP_IS_EMBEDDED(&bp) ||
        BP_GET_LEVEL(&bp) != 0 || BP_GET_LSIZE(&bp) != store->blocksize ||
        BP_GET_TYPE(&bp) != store->dn->dn_type ||
        !DVA_IS_VALID(&bp.blk_dva[0]) ||
        DVA_GET_VDEV(&bp.blk_dva[0]) != block->vdev ||
        DVA_GET_OFFSET(&bp.blk_dva[0]) != block->offset)) error = EINVAL;
    if (!error) {
        memset(&bp.blk_dva[1], 0, sizeof (bp.blk_dva) - sizeof (bp.blk_dva[0]));
        arc_flags_t flags = ARC_FLAG_WAIT | ARC_FLAG_NO_BUF;
        zbookmark_phys_t bookmark = {
            .zb_objset = DMU_META_OBJSET, .zb_object = store->object,
            .zb_level = 0, .zb_blkid = block->blkid
        };
        error = arc_read(NULL, store->spa, &bp, NULL, NULL,
            ZIO_PRIORITY_SYNC_READ, ZIO_FLAG_CANFAIL | ZIO_FLAG_DONT_RETRY,
            &flags, &bookmark);
    }
    if (error) dbuf_rele(db, plan);
    else *dbp = db;
    return (error);
}

static inline int
dp_primary_read(const dp_plan_t *plan, const dp_block_t *block)
{
    dmu_buf_impl_t *db = NULL;
    int error = dp_primary_hold(plan, block, &db);
    if (db != NULL) dbuf_rele(db, plan);
    return (error);
}

static inline void
dp_leaf_close(dp_leaf_t *leaf)
{
    if (leaf->db != NULL) dbuf_rele(leaf->db, leaf);
    memset(leaf, 0, sizeof (*leaf));
}

/* The returned DBUF is checksum verified and natively byteswapped. Header
 * ranges use 48-bit hash-cookie units, never full hashes (whose upper bound
 * would wrap to zero). Registered mapping remains the consumer's obligation,
 * including for empty/stale leaves, before native ZAP entry traversal. */
static inline int
dp_leaf_open(const dp_plan_t *plan, const dp_block_t *block, dp_leaf_t *leaf)
{
    memset(leaf, 0, sizeof (*leaf));
    if (dp_cancelled(plan)) return (EINTR);
    dmu_buf_impl_t *db = NULL;
    int error = dp_primary_hold(plan, block, &db);
    if (error) return (error);
    /* Transfer the native hold's tag; both tags must match their release. */
    dbuf_add_ref(db, leaf);
    dbuf_rele(db, plan);
    leaf->db = db;
    leaf->blkid = block->blkid;
    error = dbuf_read(db, NULL, DB_RF_CANFAIL | DMU_READ_NO_PREFETCH);
    if (!error) {
        rw_enter(&db->db_rwlock, RW_READER);
        if (db->db.db_data == NULL || db->db.db_size < sizeof (zap_leaf_phys_t)) {
            error = EINVAL;
        } else {
            const zap_leaf_phys_t *phys = db->db.db_data;
            if (phys->l_hdr.lh_block_type == ZBT_MICRO) {
                error = ENOTSUP;
            } else if (phys->l_hdr.lh_block_type == ZBT_LEAF) {
                unsigned int len = phys->l_hdr.lh_prefix_len;
                uint64_t prefix = phys->l_hdr.lh_prefix;
                unsigned int bs = highbit64(db->db.db_size) - 1;
                if (block->blkid == 0 || bs < 5 || bs >= 31 ||
                    db->db.db_size != (1ULL << bs) ||
                    phys->l_hdr.lh_magic != ZAP_LEAF_MAGIC || len > 48 ||
                    (len <= 48 && prefix >= (1ULL << len)) ||
                    phys->l_hdr.lh_nentries > ZAP_LEAF_NUMCHUNKS_BS(bs) ||
                    phys->l_hdr.lh_nfree > ZAP_LEAF_NUMCHUNKS_BS(bs)) {
                    error = EINVAL;
                } else {
                    leaf->is_leaf = B_TRUE;
                    leaf->prefix_len = len;
                    leaf->hash_start = prefix << (48 - len);
                    leaf->hash_end = (prefix + 1) << (48 - len);
                    leaf->nentries = phys->l_hdr.lh_nentries;
                }
            }
        }
        rw_exit(&db->db_rwlock);
    }
    if (error) dp_leaf_close(leaf);
    return (error);
}

#endif /* CONVERT_DDT_PHYSICAL_H */
