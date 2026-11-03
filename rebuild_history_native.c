/* SPDX-License-Identifier: CDDL-1.0 */
#include "rebuild_history_native.h"

#include <sys/dmu_tx.h>
#include <sys/dmu_objset.h>
#include <sys/dsl_pool.h>
#include <sys/spa_impl.h>
#include <sys/zio_compress.h>
#include <sys/zio_checksum.h>
#include <sys/zio_crypt.h>
#include <sys/dnode.h>

/* Holds cross helper boundaries; a function-local FTAG would not match. */
static const char rh_ledger_tag[] = "rebuild-history-ledger";
#undef FTAG
#define FTAG ((void *)rh_ledger_tag)

#define RH_LEDGER_VERSION 3
#define RH_LEDGER_ABORT 1
#define RH_LEDGER_RETIRE 2

typedef struct rh_ledger_phys {
    uint64_t rhl_version;
    uint64_t rhl_count;
    uint64_t rhl_cursor;
    uint64_t rhl_drain_mode;
    uint64_t rhl_alloc[3];
    uint64_t rhl_retired[3];
    uint64_t rhl_published;
} rh_ledger_phys_t;

static int rh_ledger_note(spa_t *, rh_ledger_phys_t *,
    const rebuild_history_record_t *);
static int rh_ledger_tally(spa_t *, uint64_t *, const blkptr_t *, boolean_t);
static void rh_ledger_charge(spa_t *, const blkptr_t *, boolean_t);
static int rh_raw_objset_equal(const void *, const void *, size_t);

static int
rh_tx_check(spa_t *spa, dmu_tx_t *tx)
{
    if (spa == NULL || tx == NULL || !dmu_tx_is_syncing(tx) ||
        dmu_tx_pool(tx) != spa_get_dsl(spa))
        return (EINVAL);
    return (0);
}

static int
rh_ledger_hold(spa_t *spa, uint64_t object, dmu_buf_t **dbp)
{
    dmu_object_info_t doi;
    objset_t *mos = spa_get_dsl(spa)->dp_meta_objset;
    int error = dmu_object_info(mos, object, &doi);
    if (error != 0)
        return (error);
    if (doi.doi_type != DMU_OTN_UINT64_METADATA ||
        doi.doi_bonus_type != DMU_OTN_UINT64_METADATA ||
        doi.doi_bonus_size != sizeof (rh_ledger_phys_t))
        return (EINVAL);
    error = dmu_bonus_hold(mos, object, FTAG, dbp);
    if (error != 0)
        return (error);
    rh_ledger_phys_t *phys = (*dbp)->db_data;
    if (phys->rhl_version != RH_LEDGER_VERSION ||
        phys->rhl_cursor > phys->rhl_count ||
        phys->rhl_count > UINT64_MAX / sizeof (rebuild_history_record_t) ||
        phys->rhl_drain_mode > RH_LEDGER_RETIRE ||
        phys->rhl_published > 1 ||
        (phys->rhl_drain_mode == 0 && phys->rhl_cursor != 0)) {
        dmu_buf_rele(*dbp, FTAG);
        return (EINVAL);
    }
    return (0);
}

int
rebuild_history_ledger_create(spa_t *spa, dmu_tx_t *tx, uint64_t *object)
{
    int error = rh_tx_check(spa, tx);
    if (error != 0 || object == NULL)
        return (error != 0 ? error : EINVAL);
    objset_t *mos = spa_get_dsl(spa)->dp_meta_objset;
    uint64_t obj = dmu_object_alloc(mos, DMU_OTN_UINT64_METADATA,
        SPA_OLD_MAXBLOCKSIZE, DMU_OTN_UINT64_METADATA,
        sizeof (rh_ledger_phys_t), tx);
    dmu_buf_t *db;
    error = dmu_bonus_hold(mos, obj, FTAG, &db);
    if (error != 0) {
        (void) dmu_object_free(mos, obj, tx);
        return (error);
    }
    dmu_buf_will_dirty(db, tx);
    rh_ledger_phys_t *phys = db->db_data;
    memset(phys, 0, sizeof (*phys));
    phys->rhl_version = RH_LEDGER_VERSION;
    phys->rhl_count = 0;
    phys->rhl_cursor = 0;
    phys->rhl_drain_mode = 0;
    dmu_buf_rele(db, FTAG);
    *object = obj;
    return (0);
}

int
rebuild_history_ledger_count(spa_t *spa, uint64_t object, uint64_t *count)
{
    if (spa == NULL || count == NULL)
        return (EINVAL);
    dmu_buf_t *db;
    int error = rh_ledger_hold(spa, object, &db);
    if (error != 0)
        return (error);
    *count = ((rh_ledger_phys_t *)db->db_data)->rhl_count;
    dmu_buf_rele(db, FTAG);
    return (0);
}

int
rebuild_history_ledger_read(spa_t *spa, uint64_t object, uint64_t index,
    rebuild_history_record_t *record)
{
    if (spa == NULL || record == NULL)
        return (EINVAL);
    dmu_buf_t *db;
    int error = rh_ledger_hold(spa, object, &db);
    if (error != 0)
        return (error);
    rh_ledger_phys_t *phys = db->db_data;
    if (index >= phys->rhl_count) {
        dmu_buf_rele(db, FTAG);
        return (ENOENT);
    }
    error = dmu_read(spa_get_dsl(spa)->dp_meta_objset, object,
        index * sizeof (*record), sizeof (*record), record,
        DMU_READ_NO_PREFETCH);
    dmu_buf_rele(db, FTAG);
    return (error);
}

int
rebuild_history_cow_write_ex(spa_t *spa, const blkptr_t *oldbp, abd_t *payload,
    const zio_prop_t *properties, const zbookmark_phys_t *bookmark,
    uint64_t ledger, dmu_tx_t *tx,
    const rebuild_history_write_options_t *options, blkptr_t *published,
    rebuild_history_delta_t *delta)
{
    int error = rh_tx_check(spa, tx);
    if (error != 0)
        return (error);
    if (oldbp == NULL || payload == NULL || properties == NULL ||
        bookmark == NULL || published == NULL || delta == NULL ||
        options == NULL || options->rhw_logical_birth == 0 ||
        options->rhw_logical_birth > dmu_tx_get_txg(tx))
        return (EINVAL);
    if (BP_IS_HOLE(oldbp) || BP_IS_REDACTED(oldbp) ||
        !BP_IS_METADATA(oldbp) ||
        (!BP_IS_EMBEDDED(oldbp) && BP_GET_DEDUP(oldbp)) ||
        BP_GET_LOGICAL_BIRTH(oldbp) == 0 ||
        BP_GET_LOGICAL_BIRTH(oldbp) >= dmu_tx_get_txg(tx))
        return (EINVAL);
    if (properties->zp_type != BP_GET_TYPE(oldbp) ||
        properties->zp_level != BP_GET_LEVEL(oldbp) ||
        properties->zp_encrypt != BP_USES_CRYPT(oldbp) ||
        properties->zp_byteorder != (options->rhw_original_raw != NULL &&
        BP_GET_TYPE(oldbp) == DMU_OT_DNODE ? BP_GET_BYTEORDER(oldbp) :
        ZFS_HOST_BYTEORDER) ||
        (!BP_IS_EMBEDDED(oldbp) &&
        properties->zp_copies != BP_GET_NDVAS(oldbp)) ||
        properties->zp_copies == 0 ||
        properties->zp_copies > spa_max_replication(spa) ||
        properties->zp_gang_copies == 0 ||
        properties->zp_checksum <= ZIO_CHECKSUM_ON ||
        properties->zp_checksum >= ZIO_CHECKSUM_FUNCTIONS ||
        properties->zp_compress <= ZIO_COMPRESS_ON ||
        properties->zp_compress >= ZIO_COMPRESS_FUNCTIONS ||
        properties->zp_dedup || properties->zp_dedup_verify ||
        properties->zp_nopwrite || properties->zp_brtwrite ||
        properties->zp_rewrite || properties->zp_direct_write)
        return (EINVAL);
    uint64_t lsize = BP_GET_LSIZE(oldbp);
    if (abd_get_size(payload) < lsize || abd_cmp_zero(payload, lsize) == 0)
        return (EINVAL);
    zio_flag_t flags = ZIO_FLAG_CANFAIL;
    if (options->rhw_original_raw != NULL) {
        boolean_t dnode = BP_GET_TYPE(oldbp) == DMU_OT_DNODE;
        boolean_t objset = BP_GET_TYPE(oldbp) == DMU_OT_OBJSET;
        if ((!dnode && !objset) || BP_GET_LEVEL(oldbp) != 0 ||
            !BP_USES_CRYPT(oldbp) || BP_GET_PSIZE(oldbp) != lsize ||
            abd_get_size(options->rhw_original_raw) < lsize)
            return (EINVAL);
        void *before = abd_borrow_buf_copy(options->rhw_original_raw, lsize);
        void *after = abd_borrow_buf_copy(payload, lsize);
        error = dnode ? rebuild_history_portable_dnode_equal(before, after, lsize) :
            rh_raw_objset_equal(before, after, lsize);
        abd_return_buf(options->rhw_original_raw, before, lsize);
        abd_return_buf(payload, after, lsize);
        if (error != 0)
            return (error);
        if (dnode) {
            uint8_t salt[ZIO_DATA_SALT_LEN], iv[ZIO_DATA_IV_LEN];
            uint8_t mac[ZIO_DATA_MAC_LEN];
            zio_crypt_decode_params_bp(oldbp, salt, iv);
            zio_crypt_decode_mac_bp(oldbp, mac);
            if (memcmp(properties->zp_salt, salt, sizeof (salt)) != 0 ||
                memcmp(properties->zp_iv, iv, sizeof (iv)) != 0 ||
                memcmp(properties->zp_mac, mac, sizeof (mac)) != 0)
                return (EINVAL);
        }
        flags |= ZIO_FLAG_RAW_ENCRYPT;
    }

    dmu_buf_t *db;
    error = rh_ledger_hold(spa, ledger, &db);
    if (error != 0)
        return (error);
    rh_ledger_phys_t *phys = db->db_data;
    if (phys->rhl_drain_mode != 0 ||
        phys->rhl_count == UINT64_MAX / sizeof (rebuild_history_record_t)) {
        error = phys->rhl_drain_mode != 0 ? EBUSY : EOVERFLOW;
        dmu_buf_rele(db, FTAG);
        return (error);
    }

    rebuild_history_record_t record = {0};
    record.rhr_original = *oldbp;
    record.rhr_bookmark = *bookmark;
    record.rhr_retire_original = options->rhw_retire_original;
    /*
     * A zero output BP is intentional: never let sync-to-convergence turn
     * this operation into an in-place rewrite of an already allocated BP.
     * No ordinary DMU born/killed callback is installed for historical data.
     */
    error = zio_wait(zio_write(NULL, spa, dmu_tx_get_txg(tx),
        &record.rhr_allocation, payload, lsize, lsize, properties,
        NULL, NULL, NULL, NULL, ZIO_PRIORITY_SYNC_WRITE,
        flags, bookmark));
    if (error != 0) {
        dmu_buf_rele(db, FTAG);
        return (error);
    }

    record.rhr_published = record.rhr_allocation;
    if (BP_IS_EMBEDDED(&record.rhr_published)) {
        BP_SET_LOGICAL_BIRTH(&record.rhr_published,
            options->rhw_logical_birth);
    } else {
        BP_SET_BIRTH(&record.rhr_published, options->rhw_logical_birth,
            BP_GET_PHYSICAL_BIRTH(&record.rhr_allocation));
        BP_SET_REWRITE(&record.rhr_published, 0);
        BP_SET_FILL(&record.rhr_published, BP_GET_FILL(oldbp));
    }
    if (options->rhw_original_raw != NULL && BP_GET_TYPE(oldbp) == DMU_OT_DNODE &&
        rebuild_history_portable_bp_equal(oldbp,
        &record.rhr_published) != 0) {
        zio_free(spa, dmu_tx_get_txg(tx), &record.rhr_allocation);
        dmu_buf_rele(db, FTAG);
        return (ECKSUM);
    }

    /*
     * Full records, not bpobj_enqueue(): that routine deliberately loses
     * non-DDT checksums and fill/IV bits. The allocation BP retains the
     * actual allocation TXG for safe abort/checkpoint free classification.
     * Both this record and its allocation commit in this assigned TXG.
     */
    objset_t *mos = spa_get_dsl(spa)->dp_meta_objset;
    dmu_buf_will_dirty(db, tx);
    error = rh_ledger_note(spa, phys, &record);
    if (error != 0) {
        if (!BP_IS_EMBEDDED(&record.rhr_allocation))
            zio_free(spa, dmu_tx_get_txg(tx), &record.rhr_allocation);
        dmu_buf_rele(db, FTAG);
        return (error);
    }
    dmu_write(mos, ledger, phys->rhl_count * sizeof (record),
        sizeof (record), &record, tx, DMU_READ_NO_PREFETCH);
    dmu_buf_will_dirty(db, tx);
    phys->rhl_count++;
    rh_ledger_charge(spa, &record.rhr_allocation, B_TRUE);
    dmu_buf_rele(db, FTAG);

    delta->rhd_used = (int64_t)bp_get_dsize_sync(spa,
        &record.rhr_published) - (int64_t)bp_get_dsize_sync(spa, oldbp);
    delta->rhd_compressed = (int64_t)BP_GET_PSIZE(&record.rhr_published) -
        (int64_t)BP_GET_PSIZE(oldbp);
    delta->rhd_uncompressed = (int64_t)BP_GET_UCSIZE(&record.rhr_published) -
        (int64_t)BP_GET_UCSIZE(oldbp);
    *published = record.rhr_published;
    return (0);
}

int
rebuild_history_ledger_visit(spa_t *spa, uint64_t object,
    boolean_t published, rebuild_history_owner_f *visit, void *arg)
{
    if (spa == NULL || visit == NULL)
        return (EINVAL);
    dmu_buf_t *db;
    int error = rh_ledger_hold(spa, object, &db);
    if (error != 0)
        return (error);
    rh_ledger_phys_t *phys = db->db_data;
    uint64_t mode = published ? RH_LEDGER_RETIRE : RH_LEDGER_ABORT;
    if (phys->rhl_drain_mode != 0 && phys->rhl_drain_mode != mode) {
        dmu_buf_rele(db, FTAG);
        return (EINVAL);
    }
    for (uint64_t i = phys->rhl_cursor; i < phys->rhl_count; i++) {
        rebuild_history_record_t record;
        error = dmu_read(spa_get_dsl(spa)->dp_meta_objset, object,
            i * sizeof (record), sizeof (record), &record,
            DMU_READ_NO_PREFETCH);
        if (error != 0)
            break;
        const blkptr_t *bp = published ? &record.rhr_original :
            &record.rhr_allocation;
        if ((published && !record.rhr_retire_original) ||
            BP_IS_EMBEDDED(bp))
            continue;
        error = visit(bp, arg);
        if (error != 0)
            break;
    }
    dmu_buf_rele(db, FTAG);
    return (error);
}

int
rebuild_history_ledger_drain(spa_t *spa, uint64_t object,
    boolean_t published, size_t limit, dmu_tx_t *tx, boolean_t *done)
{
    int error = rh_tx_check(spa, tx);
    if (error != 0 || done == NULL || limit == 0)
        return (error != 0 ? error : EINVAL);
    *done = B_FALSE;
    dmu_buf_t *db;
    error = rh_ledger_hold(spa, object, &db);
    if (error != 0)
        return (error);
    rh_ledger_phys_t *phys = db->db_data;
    if (phys->rhl_published != published) {
        dmu_buf_rele(db, FTAG);
        return (EINVAL);
    }
    uint64_t mode = published ? RH_LEDGER_RETIRE : RH_LEDGER_ABORT;
    if (phys->rhl_drain_mode != 0 && phys->rhl_drain_mode != mode) {
        dmu_buf_rele(db, FTAG);
        return (EINVAL);
    }
    for (size_t n = 0; n < limit && phys->rhl_cursor < phys->rhl_count;
        n++) {
        rebuild_history_record_t record;
        error = dmu_read(spa_get_dsl(spa)->dp_meta_objset, object,
            phys->rhl_cursor * sizeof (record), sizeof (record),
            &record, DMU_READ_NO_PREFETCH);
        if (error != 0)
            break;
        const blkptr_t *bp = published ? &record.rhr_original :
            &record.rhr_allocation;
        if (BP_IS_HOLE(bp) || BP_IS_REDACTED(bp) ||
            !BP_IS_METADATA(bp) ||
            (!BP_IS_EMBEDDED(bp) && BP_GET_DEDUP(bp))) {
            error = EINVAL;
            break;
        }
        /*
         * zio_free is gang-aware and frees just this allocation. Its
         * normal deferred-free pipeline and this cursor share the TXG.
         */
        if ((!published || record.rhr_retire_original) &&
            !BP_IS_EMBEDDED(bp)) {
            zio_free(spa, dmu_tx_get_txg(tx), bp);
            rh_ledger_charge(spa, bp, B_FALSE);
        }
        dmu_buf_will_dirty(db, tx);
        phys->rhl_drain_mode = mode;
        phys->rhl_cursor++;
    }
    if (error == 0) {
        *done = (phys->rhl_cursor == phys->rhl_count);
        if (*done) {
            dmu_buf_will_dirty(db, tx);
            phys->rhl_drain_mode = mode;
        }
    }
    dmu_buf_rele(db, FTAG);
    return (error);
}

int
rebuild_history_ledger_destroy(spa_t *spa, uint64_t object, dmu_tx_t *tx)
{
    int error = rh_tx_check(spa, tx);
    if (error != 0)
        return (error);
    dmu_buf_t *db;
    error = rh_ledger_hold(spa, object, &db);
    if (error != 0)
        return (error);
    rh_ledger_phys_t *phys = db->db_data;
    boolean_t empty = phys->rhl_cursor == phys->rhl_count;
    dmu_buf_rele(db, FTAG);
    if (!empty)
        return (EBUSY);
    return (dmu_object_free(spa_get_dsl(spa)->dp_meta_objset, object, tx));
}

int
rebuild_history_cow_write(spa_t *spa, const blkptr_t *oldbp, abd_t *payload,
    const zio_prop_t *properties, const zbookmark_phys_t *bookmark,
    uint64_t ledger, dmu_tx_t *tx, blkptr_t *published,
    rebuild_history_delta_t *delta)
{
    if (oldbp == NULL)
        return (EINVAL);
    rebuild_history_write_options_t options = {
        .rhw_logical_birth = BP_GET_BIRTH(oldbp),
        .rhw_retire_original = B_TRUE,
        .rhw_original_raw = NULL
    };
    return (rebuild_history_cow_write_ex(spa, oldbp, payload, properties,
        bookmark, ledger, tx, &options, published, delta));
}

/* Exact current-version portable authentication masks from zio_crypt.c. */
int
rebuild_history_portable_bp_equal(const blkptr_t *before,
    const blkptr_t *after)
{
    if (BP_IS_HOLE(before) || BP_IS_HOLE(after))
        return (BP_IS_HOLE(before) == BP_IS_HOLE(after) ? 0 : ECKSUM);
    if (BP_IS_EMBEDDED(before) || BP_IS_EMBEDDED(after) ||
        !BP_USES_CRYPT(before) || !BP_USES_CRYPT(after))
        return (EINVAL);
    blkptr_t a = *before, b = *after;
    if (BP_GET_LEVEL(&a) != 0) {
        BP_SET_BYTEORDER(&a, 0);
        BP_SET_COMPRESS(&a, 0);
        BP_SET_PSIZE(&a, SPA_MINBLOCKSIZE);
    }
    if (BP_GET_LEVEL(&b) != 0) {
        BP_SET_BYTEORDER(&b, 0);
        BP_SET_COMPRESS(&b, 0);
        BP_SET_PSIZE(&b, SPA_MINBLOCKSIZE);
    }
    BP_SET_DEDUP(&a, 0);
    BP_SET_DEDUP(&b, 0);
    BP_SET_CHECKSUM(&a, 0);
    BP_SET_CHECKSUM(&b, 0);
    if (a.blk_prop != b.blk_prop)
        return (ECKSUM);
    uint8_t ma[ZIO_DATA_MAC_LEN], mb[ZIO_DATA_MAC_LEN];
    zio_crypt_decode_mac_bp(&a, ma);
    zio_crypt_decode_mac_bp(&b, mb);
    return (memcmp(ma, mb, sizeof (ma)) == 0 ? 0 : ECKSUM);
}

int
rebuild_history_portable_dnode_equal(const void *before, const void *after,
    size_t size)
{
    if (before == NULL || after == NULL || size == 0 ||
        (size & (DNODE_MIN_SIZE - 1)) != 0)
        return (EINVAL);
    for (size_t offset = 0; offset < size; ) {
        const dnode_phys_t *a = (const void *)((const char *)before + offset);
        const dnode_phys_t *b = (const void *)((const char *)after + offset);
        size_t slots = (size_t)a->dn_extra_slots + 1;
        if (slots > (size - offset) / DNODE_MIN_SIZE ||
            a->dn_extra_slots != b->dn_extra_slots ||
            a->dn_nblkptr > DN_MAX_NBLKPTR ||
            b->dn_nblkptr != a->dn_nblkptr)
            return (EINVAL);
        size_t bytes = slots * DNODE_MIN_SIZE;
        if (a->dn_type == DMU_OT_NONE) {
            if (memcmp(a, b, bytes) != 0)
                return (ECKSUM);
            offset += bytes;
            continue;
        }
        dnode_phys_t ca, cb;
        size_t core = offsetof(dnode_phys_t, dn_blkptr);
        memcpy(&ca, a, core);
        memcpy(&cb, b, core);
        ca.dn_flags &= DNODE_CRYPT_PORTABLE_FLAGS_MASK;
        cb.dn_flags &= DNODE_CRYPT_PORTABLE_FLAGS_MASK;
        ca.dn_used = cb.dn_used = 0;
        if (memcmp(&ca, &cb, core) != 0)
            return (ECKSUM);
        size_t bp_end = core + a->dn_nblkptr * sizeof (blkptr_t);
        size_t bonus_end = bytes;
        if (a->dn_flags & DNODE_FLAG_SPILL_BLKPTR)
            bonus_end -= sizeof (blkptr_t);
        if (bp_end > bonus_end)
            return (EINVAL);
        for (unsigned i = 0; i < a->dn_nblkptr; i++) {
            int error = rebuild_history_portable_bp_equal(&a->dn_blkptr[i],
                &b->dn_blkptr[i]);
            if (error != 0)
                return (error);
        }
        if (memcmp((const char *)a + bp_end, (const char *)b + bp_end,
            bonus_end - bp_end) != 0)
            return (ECKSUM);
        if (a->dn_flags & DNODE_FLAG_SPILL_BLKPTR) {
            int error = rebuild_history_portable_bp_equal(DN_SPILL_BLKPTR(a),
                DN_SPILL_BLKPTR(b));
            if (error != 0)
                return (error);
        }
        offset += bytes;
    }
    return (0);
}

int
rebuild_history_ledger_set_retire(spa_t *spa, uint64_t object, uint64_t index,
    boolean_t retire, dmu_tx_t *tx)
{
    int error = rh_tx_check(spa, tx);
    if (error != 0)
        return (error);
    dmu_buf_t *db;
    error = rh_ledger_hold(spa, object, &db);
    if (error != 0)
        return (error);
    rh_ledger_phys_t *phys = db->db_data;
    if (phys->rhl_published || phys->rhl_drain_mode != 0 ||
        index >= phys->rhl_count) {
        dmu_buf_rele(db, FTAG);
        return (EINVAL);
    }
    rebuild_history_record_t record;
    objset_t *mos = spa_get_dsl(spa)->dp_meta_objset;
    error = dmu_read(mos, object, index * sizeof (record), sizeof (record),
        &record, DMU_READ_NO_PREFETCH);
    if (error == 0 && record.rhr_retire_original != retire) {
        dmu_buf_will_dirty(db, tx);
        error = rh_ledger_tally(spa, phys->rhl_retired,
            &record.rhr_original, retire);
        if (error == 0) {
            record.rhr_retire_original = retire;
            dmu_write(mos, object, index * sizeof (record), sizeof (record),
                &record, tx, DMU_READ_NO_PREFETCH);
        }
    }
    dmu_buf_rele(db, FTAG);
    return (error);
}

int
rebuild_history_ledger_append(spa_t *spa, uint64_t object,
    const rebuild_history_record_t *record, dmu_tx_t *tx, uint64_t *index)
{
    int error = rh_tx_check(spa, tx);
    if (error != 0 || record == NULL || index == NULL)
        return (error != 0 ? error : EINVAL);
    if (BP_IS_HOLE(&record->rhr_allocation) ||
        BP_IS_EMBEDDED(&record->rhr_allocation) ||
        !BP_IS_METADATA(&record->rhr_allocation) ||
        BP_GET_DEDUP(&record->rhr_allocation) ||
        BP_GET_BIRTH(&record->rhr_allocation) != dmu_tx_get_txg(tx) ||
        record->rhr_retire_original > 1)
        return (EINVAL);
    dmu_buf_t *db;
    error = rh_ledger_hold(spa, object, &db);
    if (error != 0)
        return (error);
    rh_ledger_phys_t *phys = db->db_data;
    if (phys->rhl_drain_mode != 0 ||
        phys->rhl_count == UINT64_MAX / sizeof (*record)) {
        dmu_buf_rele(db, FTAG);
        return (EOVERFLOW);
    }
    dmu_buf_will_dirty(db, tx);
    error = rh_ledger_note(spa, phys, record);
    if (error != 0) {
        dmu_buf_rele(db, FTAG);
        return (error);
    }
    *index = phys->rhl_count;
    dmu_write(spa_get_dsl(spa)->dp_meta_objset, object,
        *index * sizeof (*record), sizeof (*record), record, tx,
        DMU_READ_NO_PREFETCH);
    dmu_buf_will_dirty(db, tx);
    phys->rhl_count++;
    rh_ledger_charge(spa, &record->rhr_allocation, B_TRUE);
    dmu_buf_rele(db, FTAG);
    return (0);
}

static void
rh_ledger_amounts(spa_t *spa, const blkptr_t *bp, uint64_t amount[3])
{
    /* ZIL allocations are not charged in native DSL referenced/MOS space. */
    if (BP_GET_TYPE(bp) == DMU_OT_INTENT_LOG) {
        amount[0] = amount[1] = amount[2] = 0;
        return;
    }
    amount[0] = bp_get_dsize_sync(spa, bp);
    amount[1] = BP_GET_PSIZE(bp);
    amount[2] = BP_GET_UCSIZE(bp);
}

static int
rh_ledger_tally(spa_t *spa, uint64_t total[3], const blkptr_t *bp,
    boolean_t add)
{
    uint64_t amount[3], updated[3];
    rh_ledger_amounts(spa, bp, amount);
    for (unsigned i = 0; i < 3; i++) {
        if ((add && total[i] > UINT64_MAX - amount[i]) ||
            (!add && total[i] < amount[i]))
            return (EOVERFLOW);
        updated[i] = add ? total[i] + amount[i] : total[i] - amount[i];
    }
    memcpy(total, updated, sizeof (updated));
    return (0);
}

static int
rh_ledger_note(spa_t *spa, rh_ledger_phys_t *phys,
    const rebuild_history_record_t *record)
{
    if (phys->rhl_published)
        return (EBUSY);
    rh_ledger_phys_t updated = *phys;
    int error = rh_ledger_tally(spa, updated.rhl_alloc,
        &record->rhr_allocation, B_TRUE);
    if (error == 0 && record->rhr_retire_original)
        error = rh_ledger_tally(spa, updated.rhl_retired,
            &record->rhr_original, B_TRUE);
    if (error == 0)
        *phys = updated;
    return (error);
}

static void
rh_ledger_charge(spa_t *spa, const blkptr_t *bp, boolean_t add)
{
    uint64_t amount[3];
    rh_ledger_amounts(spa, bp, amount);
    int64_t used = (int64_t)amount[0], comp = (int64_t)amount[1];
    int64_t uncomp = (int64_t)amount[2];
    dsl_pool_mos_diduse_space(spa_get_dsl(spa), add ? used : -used,
        add ? comp : -comp, add ? uncomp : -uncomp);
}

int
rebuild_history_ledger_publish_hold(spa_t *spa, uint64_t object,
    dmu_buf_t **dbp, rebuild_history_delta_t *delta)
{
    if (spa == NULL || dbp == NULL || delta == NULL)
        return (EINVAL);
    int error = rh_ledger_hold(spa, object, dbp);
    if (error != 0)
        return (error);
    rh_ledger_phys_t *phys = (*dbp)->db_data;
    if (phys->rhl_published || phys->rhl_drain_mode || phys->rhl_cursor) {
        dmu_buf_rele(*dbp, FTAG);
        *dbp = NULL;
        return (EBUSY);
    }
    int64_t differences[3];
    for (unsigned i = 0; i < 3; i++) {
        uint64_t retired = phys->rhl_retired[i], allocated = phys->rhl_alloc[i];
        uint64_t magnitude = retired >= allocated ? retired - allocated :
            allocated - retired;
        if (magnitude > INT64_MAX) {
            dmu_buf_rele(*dbp, FTAG);
            *dbp = NULL;
            return (EOVERFLOW);
        }
        differences[i] = retired >= allocated ? (int64_t)magnitude :
            -(int64_t)magnitude;
    }
    delta->rhd_used = differences[0];
    delta->rhd_compressed = differences[1];
    delta->rhd_uncompressed = differences[2];
    return (0);
}

void
rebuild_history_ledger_publish_held(spa_t *spa, dmu_buf_t *db,
    const rebuild_history_delta_t *delta, dmu_tx_t *tx)
{
    rh_ledger_phys_t *phys = db->db_data;
    dmu_buf_will_dirty(db, tx);
    phys->rhl_published = 1;
    dsl_pool_mos_diduse_space(spa_get_dsl(spa), delta->rhd_used,
        delta->rhd_compressed, delta->rhd_uncompressed);
}

void
rebuild_history_ledger_publish_rele(dmu_buf_t *db)
{
    if (db != NULL)
        dmu_buf_rele(db, FTAG);
}

static int
rh_raw_objset_equal(const void *before, const void *after, size_t size)
{
    if (size != OBJSET_PHYS_SIZE_V1 && size != OBJSET_PHYS_SIZE_V2 &&
        size != OBJSET_PHYS_SIZE_V3)
        return (EINVAL);
    const objset_phys_t *a = before, *b = after;
    int error = rebuild_history_portable_dnode_equal(&a->os_meta_dnode,
        &b->os_meta_dnode, sizeof (dnode_phys_t));
    size_t end = MIN(size, offsetof(objset_phys_t, os_userused_dnode));
    if (error == 0 && memcmp((const char *)a + sizeof (dnode_phys_t),
        (const char *)b + sizeof (dnode_phys_t),
        end - sizeof (dnode_phys_t)) != 0)
        error = ECKSUM;
    if (error == 0 && size >= OBJSET_PHYS_SIZE_V2)
        error = rebuild_history_portable_dnode_equal(&a->os_userused_dnode,
            &b->os_userused_dnode, sizeof (dnode_phys_t));
    if (error == 0 && size >= OBJSET_PHYS_SIZE_V2)
        error = rebuild_history_portable_dnode_equal(&a->os_groupused_dnode,
            &b->os_groupused_dnode, sizeof (dnode_phys_t));
    if (error == 0 && size >= OBJSET_PHYS_SIZE_V3)
        error = rebuild_history_portable_dnode_equal(&a->os_projectused_dnode,
            &b->os_projectused_dnode, sizeof (dnode_phys_t));
    if (error == 0 && size >= OBJSET_PHYS_SIZE_V3) {
        size_t padding = offsetof(objset_phys_t, os_pad1);
        if (memcmp((const char *)a + padding, (const char *)b + padding,
            size - padding) != 0)
            error = ECKSUM;
    }
    return (error);
}
