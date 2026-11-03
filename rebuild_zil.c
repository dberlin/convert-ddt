/* SPDX-License-Identifier: CDDL-1.0 */
#include "rebuild_zil.h"
#include "rebuild_phase.h"
#include <sys/arc.h>
#include <sys/dmu_tx.h>
#include <sys/dsl_crypt.h>
#include <sys/dsl_pool.h>
#include <sys/dsl_synctask.h>
#include <sys/metaslab.h>
#include <sys/spa_impl.h>
#include <sys/zil_impl.h>
#include <sys/zio_checksum.h>
#include <sys/zio_crypt.h>
#include <sys/zio_compress.h>
#include <sys/zio_impl.h>
#include <stdlib.h>

typedef struct rz_block {
    blkptr_t old;
    void *data;
    size_t offset;
    boolean_t replaced;
} rz_block_t;

typedef struct rz_ref {
    rebuild_zil_ref_t ref;
    size_t block, offset;
} rz_ref_t;

struct rebuild_zil {
    objset_t *os;
    zil_header_t header;
    rz_block_t *blocks;
    rz_ref_t *refs;
    size_t nblocks, blockcap, nrefs, refcap;
    int callback_error;
    uint64_t records;
    boolean_t cutoff, prepared;
};

static int
rz_grow(void **array, size_t *capacity, size_t count, size_t width)
{
    if (count < *capacity)
        return (0);
    size_t n = *capacity == 0 ? 16 : *capacity * 2;
    if (n <= *capacity || n > SIZE_MAX / width)
        return (EOVERFLOW);
    void *p = realloc(*array, n * width);
    if (p == NULL)
        return (ENOMEM);
    *array = p;
    *capacity = n;
    return (0);
}

static int
rz_block(zilog_t *zilog, const blkptr_t *bp, void *arg, uint64_t claim)
{
    (void)zilog;
    rebuild_zil_t *z = arg;
    if (rebuild_interrupted())
        return (z->callback_error = EINTR);
    if (claim == 0 && BP_GET_BIRTH(bp) >=
        spa_min_claim_txg(dmu_objset_spa(z->os))) {
        z->cutoff = B_TRUE;
        return (-1);
    }
    int error = rz_grow((void **)&z->blocks, &z->blockcap,
        z->nblocks, sizeof (*z->blocks));
    if (error != 0)
        return (z->callback_error = error);
    rz_block_t *b = &z->blocks[z->nblocks++];
    *b = (rz_block_t){ .old = *bp,
        .offset = BP_GET_CHECKSUM(bp) == ZIO_CHECKSUM_ZILOG2 ?
        sizeof (zil_chain_t) : 0 };
    return (0);
}

static int
rz_ref_add(rebuild_zil_t *z, const blkptr_t *bp, const lr_t *lr,
    uint64_t object, uint64_t offset, size_t bp_offset,
    rebuild_zil_role_t role, boolean_t release)
{
    if (BP_IS_HOLE(bp))
        return (0);
    int error = rz_grow((void **)&z->refs, &z->refcap,
        z->nrefs, sizeof (*z->refs));
    if (error != 0)
        return (error);
    rz_ref_t *r = &z->refs[z->nrefs++];
    *r = (rz_ref_t){ .block = z->nblocks - 1, .offset = bp_offset,
        .ref = { .rzr_bp = *bp, .rzr_record_seq = lr->lrc_seq,
        .rzr_role = role, .rzr_release = release } };
    SET_BOOKMARK(&r->ref.rzr_bookmark, dmu_objset_id(z->os), object,
        ZB_ZIL_LEVEL, offset);
    return (0);
}

static int
rz_record(zilog_t *zilog, const lr_t *lr, void *arg, uint64_t claim)
{
    rebuild_zil_t *z = arg;
    rz_block_t *b = &z->blocks[z->nblocks - 1];
    int error = 0;
    if (z->records == UINT64_MAX)
        return (z->callback_error = EOVERFLOW);
    z->records++;
    if (lr->lrc_txtype == TX_WRITE) {
        if (lr->lrc_reclen < sizeof (lr_write_t))
            return (z->callback_error = ECKSUM);
        const lr_write_t *w = (const void *)lr;
        const blkptr_t *bp = &w->lr_blkptr;
        boolean_t release = claim != 0 && BP_GET_BIRTH(bp) >= claim &&
            zil_bp_tree_add(zilog, bp) == 0 && !BP_IS_HOLE(bp);
        uint64_t blkid = BP_IS_HOLE(bp) ? 0 :
            w->lr_offset / BP_GET_LSIZE(bp);
        error = rz_ref_add(z, bp, lr, w->lr_foid, blkid,
            b->offset + offsetof(lr_write_t, lr_blkptr),
            REBUILD_ZIL_WRITE, release);
    } else if (lr->lrc_txtype == TX_CLONE_RANGE) {
        if (lr->lrc_reclen < sizeof (lr_clone_range_t))
            return (z->callback_error = ECKSUM);
        const lr_clone_range_t *c = (const void *)lr;
        if (c->lr_nbps > (lr->lrc_reclen -
            offsetof(lr_clone_range_t, lr_bps)) / sizeof (blkptr_t))
            return (z->callback_error = ECKSUM);
        for (uint64_t i = 0; error == 0 && i < c->lr_nbps; i++) {
            error = rz_ref_add(z, &c->lr_bps[i], lr, c->lr_foid, i,
                b->offset + offsetof(lr_clone_range_t, lr_bps) +
                i * sizeof (blkptr_t), REBUILD_ZIL_CLONE, claim != 0);
        }
    }
    b->offset += lr->lrc_reclen;
    if (error != 0)
        z->callback_error = error;
    return (error);
}

int
rebuild_zil_open(objset_t *os, const zil_header_t *header,
    rebuild_zil_t **out)
{
    if (os == NULL || header == NULL || out == NULL)
        return (EINVAL);
    *out = NULL;
    rebuild_zil_t *z = calloc(1, sizeof (*z));
    if (z == NULL)
        return (ENOMEM);
    z->os = os;
    z->header = *header;
    zilog_t *log = zil_alloc(os, &z->header);
    int error = zil_parse(log, rz_block, rz_record, z,
        header->zh_claim_txg, B_TRUE);
    zil_free(log);
    if (z->callback_error != 0)
        error = z->callback_error;
    else if (z->cutoff)
        error = 0;
    /* An unclaimed chain normally ends at an allocated, unwritten LWB. */
    else if (header->zh_claim_txg == 0 && error == ECKSUM)
        error = 0;
    if (error != 0) {
        rebuild_zil_close(z);
        return (error);
    }
    *out = z;
    return (0);
}
boolean_t
rebuild_zil_has_records(const rebuild_zil_t *z)
{
    return (z != NULL && z->records != 0);
}


int
rebuild_zil_visit(rebuild_zil_t *z, rebuild_zil_visit_f *visit, void *arg)
{
    if (z == NULL || visit == NULL)
        return (EINVAL);
    for (size_t i = 0; i < z->nblocks; i++) {
        if (rebuild_interrupted())
            return (EINTR);
        rebuild_zil_ref_t ref = { .rzr_bp = z->blocks[i].old,
            .rzr_role = REBUILD_ZIL_BLOCK, .rzr_release = B_TRUE,
            .rzr_replaced = z->blocks[i].replaced };
        SET_BOOKMARK(&ref.rzr_bookmark,
            ref.rzr_bp.blk_cksum.zc_word[ZIL_ZC_OBJSET],
            ZB_ZIL_OBJECT, ZB_ZIL_LEVEL,
            ref.rzr_bp.blk_cksum.zc_word[ZIL_ZC_SEQ]);
        int error = visit(&ref, arg);
        if (error != 0)
            return (error);
    }
    for (size_t i = 0; i < z->nrefs; i++) {
        if (rebuild_interrupted())
            return (EINTR);
        int error = visit(&z->refs[i].ref, arg);
        if (error != 0)
            return (error);
    }
    return (0);
}

static int
rz_load(rebuild_zil_t *z, rz_block_t *b)
{
    if (b->data != NULL)
        return (0);
    arc_buf_t *buf = NULL;
    arc_flags_t flags = ARC_FLAG_WAIT;
    zbookmark_phys_t bookmark;
    SET_BOOKMARK(&bookmark, b->old.blk_cksum.zc_word[ZIL_ZC_OBJSET],
        ZB_ZIL_OBJECT, ZB_ZIL_LEVEL,
        b->old.blk_cksum.zc_word[ZIL_ZC_SEQ]);
    int error = arc_read(NULL, dmu_objset_spa(z->os), &b->old,
        arc_getbuf_func, &buf, ZIO_PRIORITY_SYNC_READ, ZIO_FLAG_CANFAIL,
        &flags, &bookmark);
    if (error == 0) {
        size_t size = BP_GET_LSIZE(&b->old);
        b->data = malloc(size);
        if (b->data == NULL)
            error = ENOMEM;
        else
            memcpy(b->data, buf->b_data, size);
    }
    if (buf != NULL)
        arc_buf_destroy(buf, &buf);
    return (error);
}

static int
rz_foreign_write(spa_t *spa, blkptr_t *bp, abd_t *plain, void *foreign,
    uint64_t size, const zbookmark_phys_t *bookmark)
{
    enum zio_checksum algorithm = BP_GET_CHECKSUM(bp);
    size_t used = size;
    if (algorithm == ZIO_CHECKSUM_ZILOG2) {
        uint64_t nused = BSWAP_64(((zil_chain_t *)foreign)->zc_nused);
        if (nused < sizeof (zil_chain_t) || nused > size)
            return (ECKSUM);
        used = P2ROUNDUP_TYPED(nused, ZIL_MIN_BLKSZ, uint64_t);
        if (used > size)
            return (ECKSUM);
    }
    void *cipher = NULL;
    abd_t *wire = plain;
    if (BP_USES_CRYPT(bp)) {
        uint8_t salt[ZIO_DATA_SALT_LEN], iv[ZIO_DATA_IV_LEN];
        uint8_t mac[ZIO_DATA_MAC_LEN];
        boolean_t no_crypt;
        zio_crypt_decode_params_bp(bp, salt, iv);
        cipher = zio_buf_alloc(size);
        wire = abd_get_from_buf(cipher, size);
        int error = spa_do_crypt_abd(B_TRUE, spa, bookmark,
            DMU_OT_INTENT_LOG, B_FALSE, B_TRUE, salt, iv, mac, size,
            plain, wire, &no_crypt);
        if (error != 0) {
            abd_free(wire);
            zio_buf_free(cipher, size);
            return (error);
        }
        zio_crypt_encode_mac_zil(cipher, mac);
        foreign = cipher;
    }
    zio_eck_t *eck = algorithm == ZIO_CHECKSUM_ZILOG2 ?
        &((zil_chain_t *)foreign)->zc_eck :
        (zio_eck_t *)((char *)foreign + size) - 1;
    zio_cksum_t saved = eck->zec_cksum;
    eck->zec_magic = BSWAP_64(ZEC_MAGIC);
    eck->zec_cksum = bp->blk_cksum;
    byteswap_uint64_array(&eck->zec_cksum, sizeof (zio_cksum_t));
    zio_cksum_t checksum;
    zio_checksum_table[algorithm].ci_func[ZIO_CHECKSUM_BYTESWAP](
        wire, used, NULL, &checksum);
    if (BP_USES_CRYPT(bp)) {
        checksum.zc_word[0] ^= checksum.zc_word[2];
        checksum.zc_word[1] ^= checksum.zc_word[3];
    }
    byteswap_uint64_array(&checksum, sizeof (checksum));
    if (BP_USES_CRYPT(bp)) {
        checksum.zc_word[2] = saved.zc_word[2];
        checksum.zc_word[3] = saved.zc_word[3];
    }
    eck->zec_cksum = checksum;
    /*
     * Native generation emits host-endian ZECs. The foreign inverse of
     * zio_checksum_error_impl() above and native crypto have already run.
     * Only allocation-independent vdev dispatch remains in this ZIO.
     */
    zio_t *io = zio_rewrite(NULL, spa, 0, bp, wire, size, NULL, NULL,
        ZIO_PRIORITY_SYNC_WRITE, ZIO_FLAG_CANFAIL,
        (zbookmark_phys_t *)bookmark);
    io->io_pipeline &= ~(ZIO_STAGE_ENCRYPT | ZIO_STAGE_CHECKSUM_GENERATE);
    io->io_orig_pipeline = io->io_pipeline;
    int error = zio_wait(io);
    if (cipher != NULL) {
        abd_free(wire);
        zio_buf_free(cipher, size);
    }
    return (error);
}

int
rebuild_zil_cow_write(objset_t *os, const blkptr_t *old, abd_t *payload,
    const zbookmark_phys_t *bookmark, rebuild_zil_append_f *append,
    void *arg, dmu_tx_t *tx, blkptr_t *out, rebuild_history_delta_t *delta)
{
    if (os == NULL || old == NULL || payload == NULL || bookmark == NULL ||
        append == NULL || tx == NULL || out == NULL || delta == NULL)
        return (EINVAL);
    spa_t *spa = dmu_objset_spa(os);
    uint64_t size = BP_GET_LSIZE(old);
    if (!dmu_tx_is_syncing(tx) || dmu_tx_pool(tx) != spa_get_dsl(spa) ||
        BP_GET_TYPE(old) != DMU_OT_INTENT_LOG || BP_GET_LEVEL(old) != 0 ||
        BP_IS_HOLE(old) || BP_GET_DEDUP(old) ||
        size < sizeof (zil_chain_t) || abd_get_size(payload) < size ||
        bookmark->zb_objset != old->blk_cksum.zc_word[ZIL_ZC_OBJSET] ||
        (BP_GET_CHECKSUM(old) != ZIO_CHECKSUM_ZILOG &&
        BP_GET_CHECKSUM(old) != ZIO_CHECKSUM_ZILOG2) ||
        BP_IS_ENCRYPTED(old) != os->os_encrypted)
        return (EINVAL);
    rebuild_history_record_t record = { .rhr_original = *old,
        .rhr_bookmark = *bookmark, .rhr_retire_original = B_FALSE };
    blkptr_t *bp = &record.rhr_allocation;
    uint8_t salt[ZIO_DATA_SALT_LEN], iv[ZIO_DATA_IV_LEN];
    int error = 0;
    if (os->os_encrypted) {
        error = spa_crypt_get_salt(spa, bookmark->zb_objset, salt);
        if (error == 0)
            error = zio_crypt_generate_iv(iv);
        if (error != 0)
            return (error);
    }
    BP_SET_TYPE(bp, DMU_OT_INTENT_LOG);
    BP_SET_LEVEL(bp, 0);
    BP_SET_LSIZE(bp, size);
    BP_SET_PSIZE(bp, size);
    BP_SET_COMPRESS(bp, ZIO_COMPRESS_OFF);
    BP_SET_CHECKSUM(bp, BP_GET_CHECKSUM(old));
    BP_SET_BYTEORDER(bp, BP_GET_BYTEORDER(old));
    /*
     * zio_alloc_zil() is an open-TXG allocator. This assigned-TXG owner
     * instead uses the same native metaslab core as syncing COW writes.
     * Normal-class space remains durable with the ledger's MOS owner.
     */
    zio_alloc_list_t allocations;
    metaslab_trace_init(&allocations);
    int allocator = bookmark->zb_objset % spa->spa_alloc_count;
    error = metaslab_alloc(spa, spa_normal_class(spa), size, bp, 1,
        dmu_tx_get_txg(tx), NULL, METASLAB_ZIL, &allocations, allocator,
        NULL);
    metaslab_trace_fini(&allocations);
    if (error != 0)
        return (error);
    if (os->os_encrypted) {
        BP_SET_CRYPT(bp, B_TRUE);
        zio_crypt_encode_params_bp(bp, salt, iv);
    }
    bp->blk_cksum = old->blk_cksum;
    /* Preserve replay-vector byteorder, including strings and inline data. */
    abd_t *write_abd = payload;
    void *swapped = NULL;
    if (BP_SHOULD_BYTESWAP(old)) {
        swapped = zio_buf_alloc(size);
        abd_copy_to_buf(swapped, payload, size);
        byteswap_uint64_array(swapped, size);
        write_abd = abd_get_from_buf(swapped, size);
    }
    if (swapped != NULL)
        error = rz_foreign_write(spa, bp, write_abd, swapped, size,
            bookmark);
    else
        error = zio_wait(zio_rewrite(NULL, spa, 0, bp, write_abd, size,
            NULL, NULL, ZIO_PRIORITY_SYNC_WRITE, ZIO_FLAG_CANFAIL,
            (zbookmark_phys_t *)bookmark));
    if (swapped != NULL) {
        abd_free(write_abd);
        zio_buf_free(swapped, size);
    }
    if (error == 0) {
        record.rhr_published = *bp;
        error = append(arg, &record, tx);
    }
    if (error != 0) {
        zio_free(spa, dmu_tx_get_txg(tx), bp);
        return (error);
    }
    delta->rhd_used = (int64_t)bp_get_dsize_sync(spa, bp) -
        (int64_t)bp_get_dsize_sync(spa, old);
    delta->rhd_compressed = (int64_t)BP_GET_PSIZE(bp) -
        (int64_t)BP_GET_PSIZE(old);
    delta->rhd_uncompressed = (int64_t)BP_GET_UCSIZE(bp) -
        (int64_t)BP_GET_UCSIZE(old);
    *out = *bp;
    return (0);
}

typedef struct rz_write {
    rebuild_zil_t *z;
    rz_block_t *block;
    rebuild_zil_append_f *append;
    void *arg;
    blkptr_t result;
    int error;
} rz_write_t;

static void
rz_write_sync(void *arg, dmu_tx_t *tx)
{
    rz_write_t *w = arg;
    zbookmark_phys_t bookmark;
    SET_BOOKMARK(&bookmark,
        w->block->old.blk_cksum.zc_word[ZIL_ZC_OBJSET],
        ZB_ZIL_OBJECT, ZB_ZIL_LEVEL,
        w->block->old.blk_cksum.zc_word[ZIL_ZC_SEQ]);
    abd_t *payload = abd_get_from_buf(w->block->data,
        BP_GET_LSIZE(&w->block->old));
    rebuild_history_delta_t delta;
    w->error = rebuild_zil_cow_write(w->z->os, &w->block->old, payload,
        &bookmark, w->append, w->arg, tx, &w->result, &delta);
    abd_free(payload);
}

static int
rz_prepare(rebuild_zil_t *z, rebuild_zil_transform_f *transform,
    void *transform_arg, rebuild_zil_append_f *append, void *append_arg,
    zil_header_t *out, boolean_t data_remap)
{
    if (z == NULL || transform == NULL || append == NULL || out == NULL ||
        z->prepared)
        return (EINVAL);
    /* A failed preparation is aborted through its persisted allocation ledger. */
    z->prepared = B_TRUE;
    size_t last = SIZE_MAX;
    for (size_t i = 0; i < z->nrefs; i++) {
        if (rebuild_interrupted())
            return (EINTR);
        rz_ref_t *r = &z->refs[i];
        if (!r->ref.rzr_release)
            continue;
        blkptr_t replacement;
        int error = transform(transform_arg, dmu_objset_id(z->os),
            &r->ref.rzr_bp, &replacement);
        if (error != 0)
            return (error);
        if (memcmp(&replacement, &r->ref.rzr_bp, sizeof (replacement)) == 0)
            continue;
        blkptr_t a = replacement, b = r->ref.rzr_bp;
        if (data_remap) {
            if (BP_IS_HOLE(&a) || BP_IS_EMBEDDED(&a) || BP_IS_REDACTED(&a) ||
                BP_IS_METADATA(&a) || BP_GET_LEVEL(&a) != BP_GET_LEVEL(&b) ||
                BP_GET_BIRTH(&a) != BP_GET_BIRTH(&b) ||
                BP_GET_LSIZE(&a) != BP_GET_LSIZE(&b) ||
                BP_GET_TYPE(&a) != BP_GET_TYPE(&b) ||
                BP_GET_BYTEORDER(&a) != BP_GET_BYTEORDER(&b) ||
                BP_USES_CRYPT(&a) != BP_USES_CRYPT(&b) ||
                BP_GET_NDVAS(&a) < BP_GET_NDVAS(&b))
                return (EINVAL);
        } else {
            /* Default legacy policy changes D/checksum, not allocation. */
            BP_SET_DEDUP(&a, BP_GET_DEDUP(&b));
            BP_SET_CHECKSUM(&a, BP_GET_CHECKSUM(&b));
            a.blk_cksum = b.blk_cksum;
            if (memcmp(&a, &b, sizeof (a)) != 0)
                return (EINVAL);
        }
        rz_block_t *block = &z->blocks[r->block];
        error = rz_load(z, block);
        if (error != 0)
            return (error);
        if (r->offset > BP_GET_LSIZE(&block->old) - sizeof (blkptr_t))
            return (ECKSUM);
        memcpy((char *)block->data + r->offset, &replacement,
            sizeof (replacement));
        last = r->block;
    }
    *out = z->header;
    if (last == SIZE_MAX)
        return (0);
    blkptr_t next = {{{{0}}}};
    for (size_t n = last + 1; n != 0; n--) {
        if (rebuild_interrupted())
            return (EINTR);
        rz_block_t *b = &z->blocks[n - 1];
        int error = rz_load(z, b);
        if (error != 0)
            return (error);
        size_t size = BP_GET_LSIZE(&b->old);
        zil_chain_t *chain = BP_GET_CHECKSUM(&b->old) ==
            ZIO_CHECKSUM_ZILOG2 ? b->data :
            (zil_chain_t *)((char *)b->data + size) - 1;
        if (n != last + 1)
            chain->zc_next_blk = next;
        chain->zc_eck.zec_cksum = b->old.blk_cksum;
        rz_write_t w = { .z = z, .block = b, .append = append,
            .arg = append_arg };
        error = dsl_sync_task(spa_name(dmu_objset_spa(z->os)), NULL,
            rz_write_sync, &w, 16, ZFS_SPACE_CHECK_NORMAL);
        if (error == 0)
            error = w.error;
        if (error != 0)
            return (error);
        next = w.result;
        b->replaced = B_TRUE;
    }
    out->zh_log = next;
    return (0);
}

int
rebuild_zil_prepare(rebuild_zil_t *z, rebuild_zil_transform_f *transform,
    void *transform_arg, rebuild_zil_append_f *append, void *append_arg,
    zil_header_t *out)
{
    return (rz_prepare(z, transform, transform_arg, append, append_arg,
        out, B_FALSE));
}

int
rebuild_zil_prepare_data(rebuild_zil_t *z, rebuild_zil_transform_f *transform,
    void *transform_arg, rebuild_zil_append_f *append, void *append_arg,
    zil_header_t *out)
{
    return (rz_prepare(z, transform, transform_arg, append, append_arg,
        out, B_TRUE));
}

void
rebuild_zil_close(rebuild_zil_t *z)
{
    if (z == NULL)
        return;
    for (size_t i = 0; i < z->nblocks; i++)
        free(z->blocks[i].data);
    free(z->blocks);
    free(z->refs);
    free(z);
}
