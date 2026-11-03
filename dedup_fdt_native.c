/* SPDX-License-Identifier: CDDL-1.0 */
#include "dedup_fdt_native.h"
#include "rebuild_bridge.h"
#include <sys/dmu_tx.h>
#include <sys/dsl_pool.h>
#include <sys/spa_impl.h>
#include <sys/zio_checksum.h>
#include <sys/zio_compress.h>
#include <sys/zio_crypt.h>
#include <sys/blake3.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#define DF_DATA_MAGIC 0x4446445444415441ULL
#define DF_DATA_VERSION 1
static const char df_data_tag[] = "dedup-fdt-data";
typedef struct df_data_phys {
    uint64_t magic, version, kind, count, cursor, published, mode;
    /* Exact data sizes stay durable (including semantic UCSIZE) so existing
     * unpublished ledgers remain recoverable without an on-disk migration. */
    uint64_t amounts[3], retired_bytes;
} df_data_phys_t;

static int
df_tx(spa_t *spa, dmu_tx_t *tx)
{
    return (spa != NULL && tx != NULL && dmu_tx_is_syncing(tx) &&
        dmu_tx_pool(tx) == spa_get_dsl(spa) ? 0 : EINVAL);
}
static int
df_hold(spa_t *spa, uint64_t object, dmu_buf_t **out)
{
    dmu_object_info_t info;
    objset_t *mos = spa_get_dsl(spa)->dp_meta_objset;
    int error = dmu_object_info(mos, object, &info);
    if (error != 0)
        return (error);
    if (info.doi_type != DMU_OTN_UINT64_METADATA ||
        info.doi_bonus_type != DMU_OTN_UINT64_METADATA ||
        info.doi_bonus_size != sizeof (df_data_phys_t))
        return (EINVAL);
    error = dmu_bonus_hold(mos, object, df_data_tag, out);
    if (error != 0)
        return (error);
    df_data_phys_t *p = (*out)->db_data;
    if (p->magic != DF_DATA_MAGIC || p->version != DF_DATA_VERSION ||
        (p->kind != DEDUP_FDT_NEW_DATA && p->kind != DEDUP_FDT_RETIRE_DATA) ||
        p->published > 1 || p->mode > 2 || p->cursor > p->count ||
        p->count > INT64_MAX/sizeof (dedup_fdt_data_record_t) ||
        (p->mode == 0 && p->cursor != 0)) {
        dedup_fdt_data_rele(*out);
        *out = NULL;
        return (EINVAL);
    }
    for (unsigned i = 0; i < 3; i++)
        if (p->amounts[i] > INT64_MAX) {
            dedup_fdt_data_rele(*out);
            *out = NULL;
            return (EINVAL);
        }
    return (0);
}
int
dedup_fdt_data_validate(spa_t *spa, uint64_t object,
    dedup_fdt_ledger_kind_t kind, boolean_t published)
{
    if (spa == NULL || object == 0 ||
        (kind != DEDUP_FDT_NEW_DATA && kind != DEDUP_FDT_RETIRE_DATA))
        return (EINVAL);
    dmu_buf_t *db;
    int error = df_hold(spa, object, &db);
    if (error != 0)
        return (error);
    const df_data_phys_t *p = db->db_data;
    if (p->kind != kind || p->published != published ||
        (p->mode != 0 && p->mode != (published ? 2 : 1)))
        error = EINVAL;
    dedup_fdt_data_rele(db);
    return (error);
}
static boolean_t
df_valid_data(const blkptr_t *bp)
{
    return (!BP_IS_HOLE(bp) && !BP_IS_EMBEDDED(bp) && !BP_IS_REDACTED(bp) &&
        !BP_IS_METADATA(bp) && BP_GET_LEVEL(bp) == 0 &&
        BP_GET_PHYSICAL_BIRTH(bp) != 0 && BP_GET_NDVAS(bp) != 0);
}
static void
df_charge(spa_t *spa, const uint64_t *amounts, boolean_t add)
{
    /* The ledger owns opaque stored RAW bytes, not an OBJSET with user-data
     * compression semantics. MOS's placeholder contract requires compressed
     * == uncompressed (dsl_pool_mos_diduse_space). Keep allocation dsize and
     * charge PSIZE in BOTH placeholder dimensions; logical UCSIZE remains
     * solely in the data records/history's user-dataset accounting.
     *
     * All transitions use this one projection: NEW append adds, publication
     * removes NEW/adds RETIRE atomically, abort removes NEW, and published
     * retirement removes RETIRE in the same TXG as its cursor/native free. */
    int64_t sign = add ? 1 : -1;
    int64_t stored = sign*(int64_t)amounts[1];
    dsl_pool_mos_diduse_space(spa_get_dsl(spa), sign*(int64_t)amounts[0],
        stored, stored);
}
static void
df_amounts(spa_t *spa, const blkptr_t *bp, uint64_t *amounts)
{
    amounts[0] = bp_get_dsize_sync(spa, bp);
    amounts[1] = BP_GET_PSIZE(bp);
    amounts[2] = BP_GET_UCSIZE(bp);
}
int
dedup_fdt_data_create(spa_t *spa, dedup_fdt_ledger_kind_t kind,
    dmu_tx_t *tx, uint64_t *out)
{
    int error = df_tx(spa, tx);
    if (error != 0 || out == NULL ||
        (kind != DEDUP_FDT_NEW_DATA && kind != DEDUP_FDT_RETIRE_DATA))
        return (error != 0 ? error : EINVAL);
    objset_t *mos = spa_get_dsl(spa)->dp_meta_objset;
    uint64_t object = dmu_object_alloc(mos, DMU_OTN_UINT64_METADATA,
        SPA_OLD_MAXBLOCKSIZE, DMU_OTN_UINT64_METADATA, sizeof (df_data_phys_t), tx);
    dmu_buf_t *db;
    error = dmu_bonus_hold(mos, object, df_data_tag, &db);
    if (error != 0) {
        (void)dmu_object_free(mos, object, tx);
        return (error);
    }
    dmu_buf_will_dirty(db, tx);
    df_data_phys_t *p = db->db_data;
    memset(p, 0, sizeof (*p));
    p->magic = DF_DATA_MAGIC;
    p->version = DF_DATA_VERSION;
    p->kind = kind;
    dedup_fdt_data_rele(db);
    *out = object;
    return (0);
}
static int
df_append(spa_t *spa, uint64_t object, dmu_buf_t *db,
    const dedup_fdt_data_record_t *record, dmu_tx_t *tx)
{
    df_data_phys_t *p = db->db_data;
    if (p->published || p->mode ||
        p->count >= INT64_MAX/sizeof (*record) || !df_valid_data(&record->dfr_bp) ||
        BP_GET_DEDUP(&record->dfr_bp))
        return (EINVAL);
    uint64_t amounts[3];
    df_amounts(spa, &record->dfr_bp, amounts);
    for (unsigned i = 0; i < 3; i++)
        if (amounts[i] > INT64_MAX-p->amounts[i])
            return (EOVERFLOW);
    dmu_write(spa_get_dsl(spa)->dp_meta_objset, object,
        p->count*sizeof (*record), sizeof (*record), record, tx,
        DMU_READ_NO_PREFETCH);
    dmu_buf_will_dirty(db, tx);
    p->count++;
    for (unsigned i = 0; i < 3; i++)
        p->amounts[i] += amounts[i];
    return (0);
}
int
dedup_fdt_data_retire(spa_t *spa, uint64_t object,
    const dedup_fdt_data_record_t *record, dmu_tx_t *tx)
{
    int error = df_tx(spa, tx);
    if (error != 0 || record == NULL || record->dfr_remaining != 0 ||
        record->dfr_audit_txg == 0 || record->dfr_audit_txg > dmu_tx_get_txg(tx))
        return (error != 0 ? error : EINVAL);
    dmu_buf_t *db;
    error = df_hold(spa, object, &db);
    if (error != 0)
        return (error);
    if (((df_data_phys_t *)db->db_data)->kind != DEDUP_FDT_RETIRE_DATA)
        error = EINVAL;
    else
        error = df_append(spa, object, db, record, tx);
    dedup_fdt_data_rele(db);
    return (error);
}
int
dedup_fdt_data_allocate(spa_t *spa, uint64_t object, const blkptr_t *source,
    abd_t *payload, const zbookmark_phys_t *bookmark, uint64_t domain,
    dmu_tx_t *tx, blkptr_t *out)
{
    int error = df_tx(spa, tx);
    if (error != 0 || source == NULL || payload == NULL || bookmark == NULL ||
        out == NULL || !df_valid_data(source) ||
        BP_GET_CHECKSUM(source) != ZIO_CHECKSUM_BLAKE3 ||
        abd_get_size(payload) < BP_GET_PSIZE(source))
        return (error != 0 ? error : EINVAL);
    dmu_buf_t *db;
    error = df_hold(spa, object, &db);
    if (error != 0)
        return (error);
    df_data_phys_t *p = db->db_data;
    if (p->kind != DEDUP_FDT_NEW_DATA || p->published || p->mode) {
        dedup_fdt_data_rele(db);
        return (EINVAL);
    }
    zio_prop_t props = {0};
    props.zp_type = BP_GET_TYPE(source);
    props.zp_storage_type = props.zp_type;
    props.zp_level = 0;
    props.zp_checksum = ZIO_CHECKSUM_BLAKE3;
    props.zp_compress = BP_GET_COMPRESS(source);
    props.zp_copies = BP_GET_NDVAS(source);
    props.zp_gang_copies = props.zp_copies;
    props.zp_encrypt = BP_USES_CRYPT(source);
    props.zp_byteorder = BP_GET_BYTEORDER(source);
    if (BP_IS_ENCRYPTED(source)) {
        zio_crypt_decode_params_bp(source, props.zp_salt, props.zp_iv);
        zio_crypt_decode_mac_bp(source, props.zp_mac);
    }
    dedup_fdt_data_record_t record = { .dfr_bookmark = *bookmark,
        .dfr_domain = domain };
    uint64_t size = BP_GET_LSIZE(source), physical = BP_GET_PSIZE(source);
    /* Copy a verified stored representation. This preserves exact encoding,
     * crypto tuple and the preflight-proven final key, even with random IVs.
     * It does not invoke or take a native live DDT/BRT reference. */
    error = zio_wait(zio_write(NULL, spa, dmu_tx_get_txg(tx), &record.dfr_bp,
        payload, size, physical, &props, NULL, NULL, NULL, NULL,
        ZIO_PRIORITY_SYNC_WRITE, ZIO_FLAG_CANFAIL | ZIO_FLAG_RAW, bookmark));
    if (error == 0 && df_valid_data(&record.dfr_bp))
        BP_SET_FILL(&record.dfr_bp, BP_GET_FILL(source));
    if (error == 0 && !df_valid_data(&record.dfr_bp))
        error = EINVAL;
    if (error == 0) {
        zio_cksum_t generated = source->blk_cksum;
        if (BP_SHOULD_BYTESWAP(source))
            for (unsigned i = 0; i < (BP_USES_CRYPT(source) ? 2u : 4u); i++)
                generated.zc_word[i] = BSWAP_64(generated.zc_word[i]);
        if (memcmp(&generated, &record.dfr_bp.blk_cksum, sizeof (generated)) != 0)
            error = ECKSUM;
        else {
            /* Native RAW writes compute ci_func[0]. Restore the exact source
             * representation byteorder and its verified STORED checksum,
             * never a logical-content digest. Raw bytes did not transform. */
            BP_SET_BYTEORDER(&record.dfr_bp, BP_GET_BYTEORDER(source));
            record.dfr_bp.blk_cksum = source->blk_cksum;
        }
    }
    if (error == 0)
        error = df_append(spa, object, db, &record, tx);
    if (error != 0) {
        if (df_valid_data(&record.dfr_bp))
            zio_free(spa, dmu_tx_get_txg(tx), &record.dfr_bp);
    } else {
        uint64_t amounts[3];
        df_amounts(spa, &record.dfr_bp, amounts);
        df_charge(spa, amounts, B_TRUE);
        *out = record.dfr_bp;
        BP_SET_DEDUP(out, 1);
    }
    dedup_fdt_data_rele(db);
    return (error);
}
int
dedup_fdt_data_hold(spa_t *spa, uint64_t object, dmu_buf_t **out)
{
    int error = df_hold(spa, object, out);
    if (error != 0)
        return (error);
    df_data_phys_t *p = (*out)->db_data;
    if (p->published || p->mode || p->cursor) {
        dedup_fdt_data_rele(*out);
        *out = NULL;
        return (EBUSY);
    }
    return (0);
}
void
dedup_fdt_data_publish(spa_t *spa, dmu_buf_t *db, dmu_tx_t *tx)
{
    VERIFY0(df_tx(spa, tx));
    df_data_phys_t *p = db->db_data;
    VERIFY0(p->published);
    dmu_buf_will_dirty(db, tx);
    p->published = 1;
    /* Transfer ownership from staged MOS to user canonical, or from obsolete
     * user allocation to retirement MOS. Drain reverses the latter charge. */
    df_charge(spa, p->amounts, p->kind == DEDUP_FDT_RETIRE_DATA);
}
void
dedup_fdt_data_rele(dmu_buf_t *db)
{
    if (db != NULL)
        dmu_buf_rele(db, df_data_tag);
}
int
dedup_fdt_data_drain(spa_t *spa, uint64_t object, boolean_t published,
    size_t limit, dmu_tx_t *tx, boolean_t *done, uint64_t *retired)
{
    int error = df_tx(spa, tx);
    if (error != 0 || limit == 0 || done == NULL || retired == NULL)
        return (error != 0 ? error : EINVAL);
    *done = B_FALSE;
    dmu_buf_t *db;
    error = df_hold(spa, object, &db);
    if (error != 0)
        return (error);
    df_data_phys_t *p = db->db_data;
    uint64_t mode = published ? 2 : 1;
    if (p->published != published || (p->mode != 0 && p->mode != mode)) {
        dedup_fdt_data_rele(db);
        return (EINVAL);
    }
    boolean_t release = published ? p->kind == DEDUP_FDT_RETIRE_DATA :
        p->kind == DEDUP_FDT_NEW_DATA;
    for (size_t n = 0; n < limit && p->cursor < p->count; n++) {
        dedup_fdt_data_record_t record;
        error = dmu_read(spa_get_dsl(spa)->dp_meta_objset, object,
            p->cursor*sizeof (record), sizeof (record), &record,
            DMU_READ_NO_PREFETCH);
        if (error != 0)
            break;
        if (!df_valid_data(&record.dfr_bp) || BP_GET_DEDUP(&record.dfr_bp) ||
            (p->kind == DEDUP_FDT_RETIRE_DATA &&
            (record.dfr_remaining != 0 || record.dfr_audit_txg == 0))) {
            error = EINVAL;
            break;
        }
        if (release) {
            uint64_t ddt, brt;
            error = rebuild_native_ddt_refcount(spa, &record.dfr_bp, &ddt);
            if (error == 0)
                error = rebuild_native_brt_refcount(spa, &record.dfr_bp, &brt);
            if (error != 0 || ddt != 0 || brt != 0) {
                if (error == 0)
                    error = ESTALE;
                break;
            }
            uint64_t amounts[3];
            df_amounts(spa, &record.dfr_bp, amounts);
            zio_free(spa, dmu_tx_get_txg(tx), &record.dfr_bp);
            df_charge(spa, amounts, B_FALSE);
            dmu_buf_will_dirty(db, tx);
            if (published)
                p->retired_bytes += amounts[0];
        }
        dmu_buf_will_dirty(db, tx);
        p->mode = mode;
        p->cursor++;
    }
    *retired = p->retired_bytes;
    if (error == 0) {
        *done = p->cursor == p->count;
        dmu_buf_will_dirty(db, tx);
        p->mode = mode;
    }
    dedup_fdt_data_rele(db);
    return (error);
}
int
dedup_fdt_data_destroy(spa_t *spa, uint64_t object, dmu_tx_t *tx)
{
    int error = df_tx(spa, tx);
    if (error != 0)
        return (error);
    dmu_buf_t *db;
    error = df_hold(spa, object, &db);
    if (error != 0)
        return (error);
    df_data_phys_t *p = db->db_data;
    boolean_t drained = p->cursor == p->count && p->mode != 0;
    dedup_fdt_data_rele(db);
    return (drained ? dmu_object_free(spa_get_dsl(spa)->dp_meta_objset,
        object, tx) : EBUSY);
}
/* Trace native checked-ZIO submission and completion, not the executor's
 * configured-worker boundary. */
static pthread_mutex_t df_trace_lock = PTHREAD_MUTEX_INITIALIZER;
static void
df_read_trace(dedup_fdt_read_request_t *request, const char *event, int error)
{
    const char *path = getenv("DEDUP_FDT_READ_TRACE");
    if (path == NULL || *path == '\0')
        return;
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    const dva_t *dva = BP_IDENTITY(&request->bp);
    char line[768];
    int length = snprintf(line, sizeof (line),
        "{\"event\":\"%s\",\"phase\":\"%s\",\"pass\":%llu,\"window\":%llu,"
        "\"seq\":%llu,\"top_vdev\":%llu,\"offset\":%llu,"
        "\"birth\":%llu,\"thread\":%llu,\"time_ns\":%llu,"
        "\"window_limit\":%llu,\"raw\":%s,\"error\":%d}\n",
        event, request->phase, (u_longlong_t)request->pass,
        (u_longlong_t)request->window,
        (u_longlong_t)request->seq, (u_longlong_t)DVA_GET_VDEV(dva),
        (u_longlong_t)DVA_GET_OFFSET(dva),
        (u_longlong_t)BP_GET_PHYSICAL_BIRTH(&request->bp),
        (u_longlong_t)(uintptr_t)pthread_self(),
        (u_longlong_t)((uint64_t)now.tv_sec * 1000000000 + now.tv_nsec),
        (u_longlong_t)request->window_limit, request->raw ? "true" : "false",
        error);
    if (length <= 0 || (size_t)length >= sizeof (line))
        return;
    pthread_mutex_lock(&df_trace_lock);
    int fd = open(path, O_CREAT | O_WRONLY | O_APPEND | O_CLOEXEC, 0600);
    if (fd >= 0) {
        size_t done = 0;
        while (done < (size_t)length) {
            ssize_t n = write(fd, line + done, length - done);
            if (n < 0 && errno == EINTR)
                continue;
            if (n <= 0)
                break;
            done += n;
        }
        close(fd);
    }
    pthread_mutex_unlock(&df_trace_lock);
}

static void
df_read_done(zio_t *zio)
{
    dedup_fdt_read_request_t *request = zio->io_private;
    df_read_trace(request, "complete", zio->io_error);
    pthread_mutex_lock(&request->lock);
    request->error = zio->io_error;
    request->done = B_TRUE;
    pthread_cond_signal(&request->ready);
    pthread_mutex_unlock(&request->lock);
}

int
dedup_fdt_read_start(spa_t *spa, const blkptr_t *bp,
    const zbookmark_phys_t *bookmark, abd_t *buffer, boolean_t raw,
    const char *phase, uint64_t pass, uint64_t window, uint64_t seq,
    uint64_t window_limit, dedup_fdt_read_request_t *request)
{
    uint64_t size = raw ? BP_GET_PSIZE(bp) : BP_GET_LSIZE(bp);
    if (!df_valid_data(bp) || abd_get_size(buffer) < size)
        return (EINVAL);
    *request = (dedup_fdt_read_request_t) { .bp = *bp, .raw = raw,
        .phase = phase, .pass = pass, .window = window, .seq = seq,
        .window_limit = window_limit };
    pthread_mutex_init(&request->lock, NULL);
    pthread_cond_init(&request->ready, NULL);
    zio_t *zio = zio_read(NULL, spa, &request->bp, buffer, size,
        df_read_done, request, ZIO_PRIORITY_SYNC_READ,
        ZIO_FLAG_CANFAIL | ZIO_FLAG_SPECULATIVE | (raw ? ZIO_FLAG_RAW : 0),
        bookmark);
    df_read_trace(request, "submit", 0);
    zio_nowait(zio);
    return (0);
}

int
dedup_fdt_read_wait(dedup_fdt_read_request_t *request)
{
    pthread_mutex_lock(&request->lock);
    while (!request->done)
        pthread_cond_wait(&request->ready, &request->lock);
    int error = request->error;
    pthread_mutex_unlock(&request->lock);
    pthread_cond_destroy(&request->ready);
    pthread_mutex_destroy(&request->lock);
    return (error);
}

void
dedup_fdt_stored_checksum(spa_t *spa, const blkptr_t *bp, abd_t *raw,
    blkptr_t *out)
{
    *out = *bp;
    zio_t zio = { .io_spa = spa, .io_bp = out };
    zio_checksum_compute(&zio, ZIO_CHECKSUM_BLAKE3, raw, BP_GET_PSIZE(bp));
    if (BP_SHOULD_BYTESWAP(bp))
        for (unsigned i = 0; i < (BP_USES_CRYPT(bp) ? 2u : 4u); i++)
            out->blk_cksum.zc_word[i] = BSWAP_64(out->blk_cksum.zc_word[i]);
    BP_SET_CHECKSUM(out, ZIO_CHECKSUM_BLAKE3);
    BP_SET_DEDUP(out, 1);
}
static int
df_fingerprint_part(void *data, size_t size, void *arg)
{
    Blake3_Update(arg, data, size);
    return (0);
}

void
dedup_fdt_fingerprint(spa_t *spa, abd_t *buffer, uint64_t size,
    zio_cksum_t *digest)
{
    (void)spa;
    BLAKE3_CTX context;
    Blake3_Init(&context);
    (void)abd_iterate_func(buffer, 0, size, df_fingerprint_part, &context);
    Blake3_Final(&context, (uint8_t *)digest);
}
