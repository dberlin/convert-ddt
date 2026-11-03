/* SPDX-License-Identifier: CDDL-1.0
 * Supplies the pinned ddt.o and exposes only the native operations needed for
 * ownership transfer. No zio_free(), refcount decref or data retirement here.
 */
#include "module/zfs/ddt.c"
#include "rebuild_bridge.h"
#include "rebuild_phase.h"
#include "rebuild_ddt_quota.h"

int
rebuild_native_ddt_admit(spa_t *spa, enum zio_checksum checksum,
    const ddt_key_t *key, uint64_t staged_dsize,
    uint64_t staged_class_dsize, boolean_t *admit, boolean_t *existing)
{
    if (spa == NULL || key == NULL || admit == NULL ||
        !DDT_CHECKSUM_VALID(checksum))
        return (EINVAL);
    *admit = B_FALSE;
    if (existing != NULL)
        *existing = B_FALSE;
    ddt_t *ddt = spa->spa_ddt[checksum];
    if (ddt != NULL && ddt->ddt_version != DDT_VERSION_UNCONFIGURED) {
        if ((ddt->ddt_version != DDT_VERSION_LEGACY &&
            ddt->ddt_version != DDT_VERSION_FDT) ||
            (ddt->ddt_flags & ~DDT_FLAG_MASK) != 0)
            return (ENOTSUP);
        ddt_enter(ddt);
        ddt_entry_t *live = avl_find(&ddt->ddt_tree, key, NULL);
        if (live != NULL) {
            int error = !(live->dde_flags & DDE_FLAG_LOADED) ? EBUSY : 0;
            boolean_t present = !(live->dde_flags & DDE_FLAG_OVERQUOTA) &&
                !(live->dde_type == DDT_TYPES &&
                live->dde_class == DDT_CLASSES);
            ddt_exit(ddt);
            if (error != 0)
                return (error);
            if (present) {
                if (existing != NULL)
                    *existing = B_TRUE;
                *admit = B_TRUE;
                return (0);
            }
        } else {
            ddt_lightweight_entry_t entry = { .ddlwe_key = *key };
            boolean_t present = (ddt->ddt_flags & DDT_FLAG_LOG) &&
                ddt_log_find_key(ddt, key, &entry, NULL);
            ddt_exit(ddt);
            if (present) {
                if (existing != NULL)
                    *existing = B_TRUE;
                *admit = B_TRUE;
                return (0);
            }
        }
        rw_enter(&ddt->ddt_objects_lock, RW_READER);
        for (ddt_type_t type = 0; type < DDT_TYPES; type++) {
            for (ddt_class_t class = 0; class < DDT_CLASSES; class++) {
                if (ddt->ddt_object_dnode[type][class] == NULL)
                    continue;
                int error = ddt_object_contains(ddt, type, class, key);
                if (error == ENOENT)
                    continue;
                rw_exit(&ddt->ddt_objects_lock);
                if (error == 0) {
                    *admit = B_TRUE;
                    if (existing != NULL)
                        *existing = B_TRUE;
                }
                return (error);
            }
        }
        rw_exit(&ddt->ddt_objects_lock);
    }
    /* Always apply the pinned source-current gate, including automatic
     * zero-capacity classes and recent allocation-fallback TXGs. Private
     * shadow compaction cannot turn a native refusal into an admission. */
    if (ddt_over_quota(spa))
        return (0);
    if (staged_dsize == 0 && staged_class_dsize == 0) {
        *admit = B_TRUE;
        return (0);
    }
    metaslab_class_t *mc = spa_has_dedup(spa) ? spa_dedup_class(spa) :
        (spa_special_has_ddt(spa) ? spa_special_class(spa) : NULL);
    uint64_t allocated = mc != NULL ? metaslab_class_get_alloc(mc) : 0;
    if (UINT64_MAX - allocated < staged_class_dsize)
        allocated = UINT64_MAX;
    else
        allocated += staged_class_dsize;
    *admit = !rebuild_ddt_quota_exceeded(spa->spa_dedup_table_quota,
        ddt_get_ddt_dsize(spa), staged_dsize, spa_syncing_txg(spa),
        spa->spa_dedup_class_full_txg, dedup_class_wait_txgs, allocated,
        mc != NULL ? metaslab_class_get_space(mc) : 0);
    return (0);
}

int
rebuild_native_ddt_match(spa_t *spa, enum zio_checksum checksum,
    const ddt_key_t *key, const ddt_univ_phys_t *phys)
{
    ddt_t *ddt = spa->spa_ddt[checksum];
    if (ddt == NULL || ddt->ddt_flags != 0 ||
        ddt->ddt_version != DDT_VERSION_LEGACY)
        return (ENOTSUP);
    if (!avl_is_empty(&ddt->ddt_tree) ||
        !avl_is_empty(&ddt->ddt_repair_tree))
        return (EBUSY);
    int found = 0;
    for (ddt_type_t type = 0; type < DDT_TYPES; type++) {
        for (ddt_class_t class = 0; class < DDT_CLASSES; class++) {
            dnode_t *dn = ddt->ddt_object_dnode[type][class];
            if (dn == NULL)
                continue;
            ddt_univ_phys_t current;
            int error = ddt_ops[type]->ddt_op_lookup(dn, key,
                &current, DDT_TRAD_PHYS_SIZE);
            if (error == ENOENT)
                continue;
            if (error != 0)
                return (error);
            if (found++ != 0 ||
                memcmp(&current, phys, DDT_TRAD_PHYS_SIZE) != 0)
                return (ESTALE);
        }
    }
    return (found == 1 ? 0 : ENOENT);
}

/* Native ddt_entry_lookup_is_valid() prefix test and ddt_phys_select()
 * identity/birth test, applied to a physical snapshot rather than allocating
 * or rehydrating a flexible live DDE.
 */
static uint64_t
rebuild_ddt_snapshot_refcount(const ddt_t *ddt, const ddt_univ_phys_t *phys,
    const blkptr_t *bp)
{
    uint_t copies = BP_GET_NDVAS(bp);
    const dva_t *prefix = ddt->ddt_flags & DDT_FLAG_FLAT ?
        phys->ddp_flat.ddp_dva : phys->ddp_trad[copies].ddp_dva;
    for (uint_t d = 0; d < copies; d++)
        if (!DVA_EQUAL(&prefix[d], &bp->blk_dva[d]))
            return (0);
    unsigned start = ddt->ddt_flags & DDT_FLAG_FLAT ?
        DDT_PHYS_FLAT : DDT_PHYS_DITTO;
    unsigned end = ddt->ddt_flags & DDT_FLAG_FLAT ?
        DDT_PHYS_FLAT+1 : DDT_PHYS_MAX;
    for (unsigned v = start; v < end; v++) {
        const dva_t *dvas = v == DDT_PHYS_FLAT ?
            phys->ddp_flat.ddp_dva : phys->ddp_trad[v].ddp_dva;
        if (DVA_EQUAL(BP_IDENTITY(bp), &dvas[0]) &&
            BP_GET_PHYSICAL_BIRTH(bp) == ddt_phys_birth(phys, v))
            return (ddt_phys_refcnt(phys, v));
    }
    return (0);
}

int
rebuild_native_ddt_refcount(spa_t *spa, const blkptr_t *bp, uint64_t *out)
{
    if (spa == NULL || bp == NULL || out == NULL)
        return (EINVAL);
    *out = 0;
    if (BP_IS_HOLE(bp) || BP_IS_EMBEDDED(bp))
        return (0);
    enum zio_checksum checksum = BP_GET_CHECKSUM(bp);
    if (!DDT_CHECKSUM_VALID(checksum))
        return (BP_GET_DEDUP(bp) ? EINVAL : 0);
    if ((BP_USES_CRYPT(bp) && !BP_IS_ENCRYPTED(bp)) ||
        BP_GET_NDVAS(bp) == 0 || BP_GET_NDVAS(bp) >= DDT_PHYS_MAX)
        return (EINVAL);
    ddt_t *ddt = spa->spa_ddt[checksum];
    if (ddt == NULL || ddt->ddt_version == DDT_VERSION_UNCONFIGURED)
        return (0);
    if ((ddt->ddt_version != DDT_VERSION_LEGACY &&
        ddt->ddt_version != DDT_VERSION_FDT) ||
        (ddt->ddt_flags & ~DDT_FLAG_MASK) != 0 ||
        (ddt->ddt_version == DDT_VERSION_LEGACY && ddt->ddt_flags != 0))
        return (ENOTSUP);
    ddt_lightweight_entry_t snapshot = {0};
    ddt_key_fill(&snapshot.ddlwe_key, bp);
    boolean_t found = B_FALSE;
    ddt_enter(ddt);
    ddt_entry_t *live = avl_find(&ddt->ddt_tree, &snapshot.ddlwe_key, NULL);
    if (live != NULL) {
        if (live->dde_flags & DDE_FLAG_OVERQUOTA) {
            ddt_exit(ddt);
            return (0);
        }
        if (!(live->dde_flags & DDE_FLAG_LOADED)) {
            ddt_exit(ddt);
            return (EBUSY);
        }
        memcpy(&snapshot.ddlwe_phys, live->dde_phys, DDT_PHYS_SIZE(ddt));
        found = B_TRUE;
    } else if (ddt->ddt_flags & DDT_FLAG_LOG) {
        found = ddt_log_find_key(ddt, &snapshot.ddlwe_key, &snapshot, NULL);
    }
    ddt_exit(ddt);
    if (!found) {
        rw_enter(&ddt->ddt_objects_lock, RW_READER);
        for (ddt_type_t type = 0; type < DDT_TYPES && !found; type++) {
            for (ddt_class_t class = 0; class < DDT_CLASSES; class++) {
                dnode_t *dn = ddt->ddt_object_dnode[type][class];
                if (dn == NULL)
                    continue;
                int error = ddt_ops[type]->ddt_op_lookup(dn,
                    &snapshot.ddlwe_key, &snapshot.ddlwe_phys,
                    DDT_PHYS_SIZE(ddt));
                if (error == ENOENT)
                    continue;
                if (error != 0) {
                    rw_exit(&ddt->ddt_objects_lock);
                    return (error);
                }
                found = B_TRUE;
                break;
            }
        }
        rw_exit(&ddt->ddt_objects_lock);
    }
    if (found)
        *out = rebuild_ddt_snapshot_refcount(ddt, &snapshot.ddlwe_phys, bp);
    return (0);
}


int
rebuild_native_ddt_stage(spa_t *spa, enum zio_checksum checksum,
    uint64_t dir, uint64_t stats, ddt_t **out)
{
    ddt_t *ddt = ddt_table_alloc(spa, checksum);
    int error = 0;
    if (dir != 0) {
        ddt->ddt_version = DDT_VERSION_FDT;
        ddt->ddt_flags = DDT_FLAG_FLAT | DDT_FLAG_LOG;
        ddt->ddt_dir_object = dir;
        uint64_t saved = spa->spa_ddt_stat_object;
        spa->spa_ddt_stat_object = stats;
        for (ddt_type_t type = 0; type < DDT_TYPES && error == 0; type++) {
            for (ddt_class_t class = 0; class < DDT_CLASSES; class++) {
                error = ddt_object_load(ddt, type, class);
                if (error == ENOENT)
                    error = 0;
                if (error != 0)
                    break;
            }
        }
        spa->spa_ddt_stat_object = saved;
        if (error == 0)
            error = ddt_log_load(ddt);
        if (error == ENOENT)
            error = 0;
    }
    if (error != 0) {
        ddt_table_free(ddt);
        return (error);
    }
    memcpy(ddt->ddt_histogram_cache, ddt->ddt_histogram,
        sizeof (ddt->ddt_histogram_cache));
    *out = ddt;
    return (0);
}

void
rebuild_native_ddt_release(ddt_t *ddt)
{
    if (ddt != NULL)
        ddt_table_free(ddt);
}

void
rebuild_native_ddt_adopt(spa_t *spa, enum zio_checksum checksum, ddt_t *ddt)
{
    ddt_table_free(spa->spa_ddt[checksum]);
    spa->spa_ddt[checksum] = ddt;
}

/* No ddt_lookup()/walk_init(): those rehydrate entries, change histograms,
 * or request a log flush. Native log trees were already merged on import.
 */
int
rebuild_bridge_foreach_flat(spa_t *spa, rebuild_bridge_flat_callback_t callback,
    void *arg)
{
    if (spa == NULL || callback == NULL)
        return (EINVAL);
    /* Validate every table before emitting anything. */
    for (enum zio_checksum c = 0; c < ZIO_CHECKSUM_FUNCTIONS; c++) {
        ddt_t *ddt = spa->spa_ddt[c];
        if (ddt == NULL)
            continue;
        if (!avl_is_empty(&ddt->ddt_tree) ||
            !avl_is_empty(&ddt->ddt_repair_tree))
            return (EBUSY);
        if (ddt->ddt_version == DDT_VERSION_UNCONFIGURED)
            continue;
        if (ddt->ddt_version != DDT_VERSION_FDT ||
            ddt->ddt_flags != (DDT_FLAG_FLAT|DDT_FLAG_LOG))
            return (ENOTSUP);
    }
    for (enum zio_checksum c = 0; c < ZIO_CHECKSUM_FUNCTIONS; c++) {
        ddt_t *ddt = spa->spa_ddt[c];
        if (ddt == NULL || ddt->ddt_version == DDT_VERSION_UNCONFIGURED)
            continue;
        for (ddt_type_t type = 0; type < DDT_TYPES; type++) {
            for (ddt_class_t class = 0; class < DDT_CLASSES; class++) {
                uint64_t cursor = 0;
                for (;;) {
                    if (rebuild_interrupted())
                        return (EINTR);
                    ddt_lightweight_entry_t entry = {0};
                    int error = ddt_object_walk(ddt, type, class,
                        &cursor, &entry);
                    if (error == ENOENT)
                        break;
                    if (error != 0)
                        return (error);
                    /* A stored key must not occupy two storage objects.
                     * Check predecessors rather than allocate a key set.
                     */
                    for (ddt_type_t prior_type = 0;
                        prior_type <= type; prior_type++) {
                        ddt_class_t limit = prior_type == type ?
                            class : DDT_CLASSES;
                        for (ddt_class_t prior = 0; prior < limit; prior++) {
                            error = ddt_object_contains(ddt, prior_type,
                                prior, &entry.ddlwe_key);
                            if (error != ENOENT)
                                return (error != 0 ? error : EEXIST);
                        }
                    }
                    /* Logs are emitted separately, exactly once per key. */
                    if (ddt_log_find_key(ddt, &entry.ddlwe_key, NULL, NULL))
                        continue;
                    error = callback(arg, c, &entry.ddlwe_key,
                        &entry.ddlwe_phys);
                    if (error != 0)
                        return (error);
                }
            }
        }
        ddt_log_t *logs[2] = { ddt->ddt_log_active, ddt->ddt_log_flushing };
        for (unsigned n = 0; n < 2; n++) {
            avl_tree_t *tree = &logs[n]->ddl_tree;
            for (ddt_log_entry_t *log = avl_first(tree); log != NULL;
                log = AVL_NEXT(tree, log)) {
                if (rebuild_interrupted())
                    return (EINTR);
                if (n == 1 && avl_find(&logs[0]->ddl_tree,
                    &log->ddle_key, NULL) != NULL)
                    continue;
                ddt_lightweight_entry_t entry;
                DDT_LOG_ENTRY_TO_LIGHTWEIGHT(ddt, log, &entry);
                int error = callback(arg, c, &entry.ddlwe_key,
                    &entry.ddlwe_phys);
                if (error != 0)
                    return (error);
            }
        }
    }
    return (0);
}
