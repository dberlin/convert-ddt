/* SPDX-License-Identifier: CDDL-1.0
 * Compile this in place of the archive's brt.o, before libzpool.a.  Keeping
 * the complete pinned translation unit preserves its private caches and ABI.
 */
#include "module/zfs/brt.c"
#include "rebuild_bridge.h"

int
rebuild_native_brt_load(spa_t *spa, uint64_t id, uint64_t object,
    brt_vdev_t **out)
{
    brt_vdev_t *bv = kmem_zalloc(sizeof (*bv), KM_SLEEP);
    rw_init(&bv->bv_lock, NULL, RW_DEFAULT, NULL);
    rw_init(&bv->bv_mos_entries_lock, NULL, RW_DEFAULT, NULL);
    mutex_init(&bv->bv_pending_lock, NULL, MUTEX_DEFAULT, NULL);
    avl_create(&bv->bv_tree, brt_entry_compare, sizeof (brt_entry_t),
        offsetof(brt_entry_t, bre_node));
    for (int i = 0; i < TXG_SIZE; i++)
        avl_create(&bv->bv_pending_tree[i], brt_entry_compare,
            sizeof (brt_entry_t), offsetof(brt_entry_t, bre_node));
    bv->bv_vdevid = id;
    bv->bv_mos_brtvdev = object;
    rw_enter(&bv->bv_lock, RW_WRITER);
    int error = object != 0 ? brt_vdev_load(spa, bv) : 0;
    rw_exit(&bv->bv_lock);
    if (error != 0) {
        rebuild_native_brt_close(bv);
        return (error);
    }
    *out = bv;
    return (0);
}

void
rebuild_native_brt_close(brt_vdev_t *bv)
{
    if (bv == NULL)
        return;
    if (bv->bv_mos_entries_dnode != NULL)
        dnode_rele(bv->bv_mos_entries_dnode, bv);
    rw_enter(&bv->bv_lock, RW_WRITER);
    if (bv->bv_initiated)
        brt_vdev_dealloc(bv);
    rw_exit(&bv->bv_lock);
    for (int i = 0; i < TXG_SIZE; i++)
        avl_destroy(&bv->bv_pending_tree[i]);
    avl_destroy(&bv->bv_tree);
    mutex_destroy(&bv->bv_pending_lock);
    rw_destroy(&bv->bv_mos_entries_lock);
    rw_destroy(&bv->bv_lock);
    kmem_free(bv, sizeof (*bv));
}

static int
rebuild_brt_count_encoded(spa_t *spa, brt_vdev_t *bv,
    const blkptr_t *bp, uint64_t *count, boolean_t fixed)
{
    *count = 0;
    if (bv == NULL || bv->bv_mos_entries == 0)
        return (0);
    if (!avl_is_empty(&bv->bv_tree))
        return (EBUSY);
    for (int i = 0; i < TXG_SIZE; i++)
        if (!avl_is_empty(&bv->bv_pending_tree[i]))
            return (EBUSY);
    brt_entry_t entry;
    entry.bre_bp = *bp;
    entry.bre_count = 0;
    uint64_t offset = DVA_GET_OFFSET(&bp->blk_dva[0]);
    int error;
    if (fixed == brt_has_endian_fixed(spa)) {
        error = brt_entry_lookup(spa, bv, &entry);
    } else {
        error = zap_lookup_uint64_by_dnode(bv->bv_mos_entries_dnode,
            &offset, BRT_KEY_WORDS, fixed ? sizeof (entry.bre_count) : 1,
            fixed ? 1 : sizeof (entry.bre_count),
            &entry.bre_count);
    }
    if (error != 0 && error != ENOENT)
        return (error);
    *count = entry.bre_count;
    return (0);
}

int
rebuild_native_brt_count(spa_t *spa, brt_vdev_t *bv,
    const blkptr_t *bp, uint64_t *count)
{
    return (rebuild_brt_count_encoded(spa, bv, bp, count,
        brt_has_endian_fixed(spa)));
}

int
rebuild_native_brt_refcount(spa_t *spa, const blkptr_t *bp, uint64_t *out)
{
    if (spa == NULL || bp == NULL || out == NULL)
        return (EINVAL);
    *out = 0;
    if (BP_IS_HOLE(bp) || BP_IS_EMBEDDED(bp))
        return (0);
    brt_entry_t search;
    uint64_t vdevid;
    brt_entry_fill(bp, &search, &vdevid);
    brt_vdev_t *bv = brt_vdev(spa, vdevid, B_FALSE);
    if (bv == NULL)
        return (0);
    rw_enter(&bv->bv_lock, RW_READER);
    if (!bv->bv_initiated) {
        rw_exit(&bv->bv_lock);
        return (0);
    }
    brt_entry_t *live = avl_find(&bv->bv_tree, &search, NULL);
    if (live != NULL) {
        *out = live->bre_count;
        rw_exit(&bv->bv_lock);
        return (0);
    }
    rw_exit(&bv->bv_lock);
    int error = brt_entry_lookup(spa, bv, &search);
    if (error == ENOENT)
        return (0);
    if (error != 0)
        return (error);
    *out = search.bre_count;
    return (0);
}

static int
rebuild_brt_check_encoded(spa_t *spa, brt_vdev_t *bv,
    const blkptr_t *bp, uint64_t oldcount, uint64_t newcount, boolean_t fixed)
{
    uint64_t current;
    int error = rebuild_brt_count_encoded(spa, bv, bp, &current, fixed);
    if (error != 0)
        return (error);
    if (current != oldcount)
        return (ESTALE);
    uint64_t dsize = bp_get_dsize(spa, bp);
    uint64_t delta = oldcount > newcount ? oldcount-newcount :
        newcount-oldcount;
    if (delta != 0 && dsize > UINT64_MAX / delta)
        return (EOVERFLOW);
    if (bv != NULL) {
        if (newcount > oldcount &&
            bv->bv_savedspace > UINT64_MAX - dsize * delta)
            return (EOVERFLOW);
        if (oldcount > newcount && bv->bv_savedspace < dsize * delta)
            return (EINVAL);
        uint64_t idx = DVA_GET_OFFSET(&bp->blk_dva[0]) /
            spa->spa_brt_rangesize;
        if (oldcount == 0 && newcount != 0) {
            if (bv->bv_usedspace > UINT64_MAX - dsize ||
                bv->bv_totalcount == UINT64_MAX)
                return (EOVERFLOW);
            if (idx < bv->bv_size &&
                brt_vdev_entcount_get(bv, idx) == UINT16_MAX)
                return (EOVERFLOW);
        }
        if (oldcount != 0 && newcount == 0 &&
            (bv->bv_usedspace < dsize || bv->bv_totalcount == 0 ||
            idx >= bv->bv_size || brt_vdev_entcount_get(bv, idx) == 0))
            return (EINVAL);
    }
    return (0);
}


int
rebuild_native_brt_set_encoded(spa_t *spa, brt_vdev_t *bv,
    const blkptr_t *bp, uint64_t oldcount, uint64_t newcount,
    boolean_t fixed, dmu_tx_t *tx)
{
    if (!dmu_tx_is_syncing(tx) ||
        dmu_tx_get_txg(tx) != spa_syncing_txg(spa))
        return (EINVAL);
    int error = rebuild_brt_check_encoded(spa, bv, bp, oldcount, newcount, fixed);
    if (error != 0 || oldcount == newcount)
        return (error);
    brt_entry_t entry = { .bre_bp = *bp, .bre_count = oldcount,
        .bre_pcount = 1 };
    uint64_t dsize = bp_get_dsize(spa, bp);
    if (newcount > oldcount) {
        brt_vdev_addref(spa, bv, &entry, dsize, newcount-oldcount);
    } else {
        uint64_t delta = oldcount-newcount;
        rw_enter(&bv->bv_lock, RW_WRITER);
        /* Native decref accounts one final region removal, not delta of them. */
        if (delta > 1) {
            entry.bre_count = 1;
            brt_vdev_decref(spa, bv, &entry, dsize * (delta-1));
        }
        entry.bre_count = newcount;
        brt_vdev_decref(spa, bv, &entry, dsize);
        rw_exit(&bv->bv_lock);
    }
    if ((oldcount == 0) != (newcount == 0)) {
        uint64_t idx = BRE_OFFSET(&entry)/spa->spa_brt_rangesize;
        /* Native sync currently rewrites the entire vdev region array.
         * Persist only this changed uint16_t, preserving its native-managed
         * byte order, to keep the assigned task bounded by the batch size.
         */
        dmu_write(spa->spa_meta_objset, bv->bv_mos_brtvdev,
            idx*sizeof (uint16_t), sizeof (uint16_t), &bv->bv_entcount[idx],
            tx, DMU_READ_NO_PREFETCH | DMU_UNCACHEDIO);
        BT_CLEAR(bv->bv_bitmap, idx/BRT_BLOCKSIZE/8);
    }
    entry.bre_count = newcount;
    if (fixed == brt_has_endian_fixed(spa)) {
        brt_sync_entry(spa, bv->bv_mos_entries_dnode, &entry, tx);
        return (0);
    }
    /* First use of block_cloning_endian is staged before activating it. */
    uint64_t offset = BRE_OFFSET(&entry);
    if (newcount == 0)
        return (zap_remove_uint64_by_dnode(bv->bv_mos_entries_dnode,
            &offset, BRT_KEY_WORDS, tx));
    return (zap_update_uint64_by_dnode(bv->bv_mos_entries_dnode,
        &offset, BRT_KEY_WORDS, fixed ? sizeof (newcount) : 1,
        fixed ? 1 : sizeof (newcount), &newcount, tx));
}


void
rebuild_native_brt_flush(spa_t *spa, brt_vdev_t *bv, dmu_tx_t *tx)
{
    if (bv->bv_meta_dirty) {
        /* Every changed region element was already written by set_encoded. */
        bv->bv_entcount_dirty = B_FALSE;
        brt_vdev_sync(spa, bv, tx);
    }
}

void
rebuild_native_brt_adopt(spa_t *spa, brt_vdev_t **vdevs, uint64_t count)
{
    brt_vdevs_free(spa);
    spa->spa_brt_vdevs = vdevs;
    spa->spa_brt_nvdevs = count;
}
