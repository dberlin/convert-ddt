/* SPDX-License-Identifier: CDDL-1.0
 * Offline ownership transfer for the exact OpenZFS 2.4.4 native ABI.
 * Shadow copies contain MOS metadata only, never user block allocations.
 */
#include <sys/zfs_context.h>
#include <sys/spa.h>
#include <sys/spa_impl.h>
#include <sys/ddt_impl.h>
#include <sys/dnode.h>
#include <sys/dsl_pool.h>
#include <sys/dsl_synctask.h>
#include <sys/vdev_impl.h>
#include <sys/zap.h>
#include <sys/zfeature.h>
#include <sys/zio_checksum.h>
#include <sys/zio_compress.h>
#include <stdio.h>
#include <limits.h>
#include "rebuild_bridge.h"
#include "rebuild_phase.h"
#include "rebuild_ddt_quota.h"

#define RB_COPY_SIZE (1U << 20)
#define RB_FREE_SIZE (8ULL << 20)
#define RB_KEY_SIZE 96
/* Private ledger flag; never passed to a native DMU object operation. */
#define RB_UNUSED_OBJECT (1ULL << 63)
_Static_assert(DN_MAX_OBJECT < RB_UNUSED_OBJECT, "native object id overlaps ledger flag");

typedef struct rb_record {
    uint64_t checksum;
    ddt_key_t key;
    ddt_univ_phys_t phys;
    int64_t canonical;
} rb_record_t;

typedef struct rb_vdev {
    uint64_t object, entries;
    uint64_t old_object, old_entries;
    uint64_t projected_saved, projected_used;
    brt_vdev_t *native;
    boolean_t needed;
} rb_vdev_t;

typedef struct rb_table {
    boolean_t used;
    uint64_t count;
    uint64_t dir;
    uint64_t old_dir;
    uint64_t objects[DDT_CLASSES];
    uint64_t final_count[DDT_CLASSES];
    uint64_t old_objects[DDT_CLASSES];
    ddt_t *view;
    ddt_t *replacement;
} rb_table_t;

typedef struct rb_publish_hold {
    dmu_buf_t **buffers;
    int count;
} rb_publish_hold_t;

struct rebuild_bridge {
    spa_t *spa;
    objset_t *os;
    uint64_t stage;
    size_t batch;
    rebuild_bridge_reader_t reader;
    void *reader_arg;
    boolean_t source_set;
    uint64_t count;
    uint64_t nvdevs;
    rb_vdev_t *vdevs;
    brt_vdev_t **replacement_vdevs;
    rb_table_t tables[ZIO_CHECKSUM_FUNCTIONS];
    uint64_t stats, old_stats, seen;
    unsigned target;
    boolean_t fixed_endian;
    boolean_t prepared;
    boolean_t published;
    rb_publish_hold_t *publication_holds;
    size_t publication_hold_count;
    rb_publish_hold_t inline_publication_holds[3];
    uint64_t publication_txg;
    boolean_t publication_endian;
    boolean_t flat_mutation;
    boolean_t admission_base;
    rebuild_bridge_brt_reader_t brt_reader;
    void *brt_arg;
    uint64_t brt_count;
};

static void
rb_publish_release(rebuild_bridge_t *b)
{
    for (size_t i = 0; i < b->publication_hold_count; i++) {
        rb_publish_hold_t *hold = &b->publication_holds[i];
        if (hold->buffers != NULL)
            dmu_buf_rele_array(hold->buffers, hold->count, b);
    }
    if (b->publication_holds != b->inline_publication_holds)
        free(b->publication_holds);
    else
        memset(b->inline_publication_holds, 0,
            sizeof (b->inline_publication_holds));
    b->publication_holds = NULL;
    b->publication_hold_count = 0;
    b->publication_txg = 0;
}

static int
rb_publish_pin(rebuild_bridge_t *b)
{
    const uint64_t objects[] = { DMU_POOL_DIRECTORY_OBJECT,
        b->spa->spa_feat_for_read_obj, b->spa->spa_feat_for_write_obj };
    struct {
        uint64_t length, chunk;
    } ranges[sizeof (objects)/sizeof (*objects)];
    size_t total = 0;
    for (size_t i = 0; i < sizeof (objects)/sizeof (*objects); i++) {
        dmu_object_info_t info;
        int error = dmu_object_info(b->os, objects[i], &info);
        if (error != 0)
            return (error);
        if (info.doi_data_block_size == 0 ||
            info.doi_data_block_size > DMU_MAX_ACCESS)
            return (EINVAL);
        ranges[i].length = MAX(info.doi_max_offset,
            (uint64_t)info.doi_data_block_size);
        ranges[i].chunk = (uint64_t)DMU_MAX_ACCESS/
            info.doi_data_block_size*info.doi_data_block_size;
        if (ranges[i].chunk/info.doi_data_block_size > INT_MAX)
            return (EOVERFLOW);
        uint64_t chunks = (ranges[i].length-1)/ranges[i].chunk+1;
        if (chunks > SIZE_MAX/sizeof (*b->publication_holds)-total)
            return (EOVERFLOW);
        total += (size_t)chunks;
    }
    b->publication_holds = total <= sizeof (b->inline_publication_holds)/
        sizeof (*b->inline_publication_holds) ? b->inline_publication_holds :
        calloc(total, sizeof (*b->publication_holds));
    if (b->publication_holds == NULL)
        return (ENOMEM);
    b->publication_hold_count = total;
    size_t index = 0;
    for (size_t i = 0; i < sizeof (objects)/sizeof (*objects); i++) {
        for (uint64_t offset = 0; offset < ranges[i].length;) {
            uint64_t length = MIN(ranges[i].chunk, ranges[i].length-offset);
            dmu_buf_t **buffers = NULL;
            int count = 0;
            int error = dmu_buf_hold_array(b->os, objects[i], offset, length,
                B_TRUE, b, &count, &buffers, DMU_READ_NO_PREFETCH);
            if (error != 0)
                return (error);
            b->publication_holds[index].buffers = buffers;
            b->publication_holds[index++].count = count;
            offset += length;
        }
    }
    return (0);
}

typedef struct rb_work {
    rebuild_bridge_t *bridge;
    void (*function)(struct rb_work *, dmu_tx_t *);
    int error;
    unsigned operation;
    boolean_t reclaim;
    uint64_t object, offset, length, value;
    dmu_object_info_t info;
    char key[RB_KEY_SIZE];
    void *data;
    rb_record_t *records;
    size_t count;
} rb_work_t;

static void
rb_dispatch(void *arg, dmu_tx_t *tx)
{
    rb_work_t *work = arg;
    work->function(work, tx);
}

static int
rb_run(rb_work_t *work, void (*function)(rb_work_t *, dmu_tx_t *), int space)
{
    if (rebuild_interrupted())
        return (EINTR);
    work->function = function;
    work->error = 0;
    int error = dsl_sync_task(spa_name(work->bridge->spa), NULL,
        rb_dispatch, work, space, work->reclaim ?
        ZFS_SPACE_CHECK_DESTROY : ZFS_SPACE_CHECK_NORMAL);
    return (error != 0 ? error : work->error);
}

static void
rb_name(char *key, unsigned phase, const char *kind, uint64_t index)
{
    (void) snprintf(key, RB_KEY_SIZE, "bridgex-%u-%s-%llu", phase,
        kind, (u_longlong_t)index);
}

static int
rb_get(rebuild_bridge_t *b, const char *key, uint64_t *value)
{
    *value = 0;
    return (zap_lookup(b->os, b->stage, key, sizeof (*value), 1, value));
}

static int
rb_put(rebuild_bridge_t *b, const char *key, uint64_t value, dmu_tx_t *tx)
{
    return (zap_update(b->os, b->stage, key, sizeof (value), 1, &value, tx));
}

static brt_vdev_t *
rb_live_vdev(spa_t *spa, uint64_t id)
{
    return (id < spa->spa_brt_nvdevs ? spa->spa_brt_vdevs[id] : NULL);
}

static int
rb_key_check(const ddt_key_t *key, enum zio_checksum checksum)
{
    if (key == NULL || checksum < 0 || checksum >= ZIO_CHECKSUM_FUNCTIONS ||
        zio_checksum_table[checksum].ci_func[0] == NULL ||
        (key->ddk_prop >> 40) != 0 ||
        DDK_GET_COMPRESS(key) >= ZIO_COMPRESS_FUNCTIONS ||
        DDK_GET_LSIZE(key) > SPA_MAXBLOCKSIZE ||
        DDK_GET_PSIZE(key) > SPA_MAXBLOCKSIZE)
        return (EINVAL);
    return (0);
}

/* Structural validation deliberately does not interpret encrypted DVA[2]:
 * that slot contains authentication data, not another physical allocation.
 */
static int
rb_check_phys(spa_t *spa, const ddt_key_t *key,
    const ddt_univ_phys_t *phys, enum zio_checksum checksum,
    boolean_t allow_pending)
{
    if (spa == NULL || phys == NULL)
        return (EINVAL);
    int error = rb_key_check(key, checksum);
    if (error != 0)
        return (error);
    const uint8_t *ditto = (const void *)&phys->ddp_trad[DDT_PHYS_DITTO];
    for (size_t i = 0; i < sizeof (phys->ddp_trad[0]); i++)
        if (ditto[i] != 0)
            return (ENOTSUP);
    boolean_t present = B_FALSE;
    uint64_t total = 0, referenced_dsize = 0;
    spa_config_enter(spa, SCL_VDEV, FTAG, RW_READER);
    for (int slot = 1; slot < DDT_PHYS_MAX && error == 0; slot++) {
        uint64_t refs = phys->ddp_trad[slot].ddp_refcnt;
        uint64_t birth = phys->ddp_trad[slot].ddp_phys_birth;
        const dva_t *dvas = phys->ddp_trad[slot].ddp_dva;
        if (birth == 0) {
            if (refs != 0 || memcmp(&phys->ddp_trad[slot],
                &(ddt_univ_phys_t){0}.ddp_trad[slot],
                sizeof (phys->ddp_trad[slot])) != 0)
                error = EINVAL;
            continue;
        }
        if (refs == 0 && !allow_pending) {
            error = ENOTSUP; /* unfreed allocation with no release edge */
            break;
        }
        if (total > UINT64_MAX - refs) {
            error = EOVERFLOW;
            break;
        }
        total += refs;
        present = B_TRUE;
        if (ddt_phys_dva_count(phys, slot, DDK_GET_CRYPT(key)) != slot) {
            error = EINVAL;
            break;
        }
        uint64_t dsize = 0;
        for (int d = 0; d < slot; d++) {
            if (DVA_GET_GANG(&dvas[d])) {
                error = ENOTSUP;
                break;
            }
            vdev_t *vd = vdev_lookup_top(spa, DVA_GET_VDEV(&dvas[d]));
            uint64_t offset = DVA_GET_OFFSET(&dvas[d]);
            uint64_t asize = DVA_GET_ASIZE(&dvas[d]);
            if (!DVA_IS_VALID(&dvas[d]) || vd == NULL ||
                asize > vdev_get_min_asize(vd) ||
                offset > vdev_get_min_asize(vd) - asize) {
                error = EINVAL;
                break;
            }
            for (int s = 1; s <= slot && error == 0; s++) {
                int end = s == slot ? d : s;
                if (phys->ddp_trad[s].ddp_phys_birth == 0)
                    continue;
                for (int n = 0; n < end; n++) {
                    const dva_t *other = &phys->ddp_trad[s].ddp_dva[n];
                    if (DVA_GET_VDEV(other) == DVA_GET_VDEV(&dvas[d]) &&
                        offset < DVA_GET_OFFSET(other)+DVA_GET_ASIZE(other) &&
                        DVA_GET_OFFSET(other) < offset+asize)
                        error = EINVAL;
                }
            }
            uint64_t size = dva_get_dsize_sync(spa, &dvas[d]);
            if (dsize > UINT64_MAX-size) {
                error = EOVERFLOW;
                break;
            }
            dsize += size;
        }
        if (refs != 0 && (dsize > UINT64_MAX/refs ||
            DDK_GET_LSIZE(key) > UINT64_MAX/refs ||
            DDK_GET_PSIZE(key) > UINT64_MAX/refs))
            error = EOVERFLOW;
        if (error == 0) {
            uint64_t referenced = dsize*refs;
            if (referenced_dsize > UINT64_MAX-referenced)
                error = EOVERFLOW;
            else
                referenced_dsize += referenced;
        }
    }
    spa_config_exit(spa, SCL_VDEV, FTAG);
    if (total != 0 && (DDK_GET_LSIZE(key) > UINT64_MAX/total ||
        DDK_GET_PSIZE(key) > UINT64_MAX/total))
        return (EOVERFLOW);
    return (error != 0 ? error : (present ? 0 : EINVAL));
}

int
rebuild_bridge_check(spa_t *spa, const ddt_key_t *key,
    const ddt_univ_phys_t *phys, enum zio_checksum checksum)
{
    return (rb_check_phys(spa, key, phys, checksum, B_FALSE));
}

static int
rb_validate_flat(void *arg, enum zio_checksum checksum,
    const ddt_key_t *key, const ddt_univ_phys_t *flat)
{
    spa_t *spa = arg;
    int error = rb_key_check(key, checksum);
    if (error != 0)
        return (error);
    if (flat->ddp_flat.ddp_phys_birth == 0) {
        if (flat->ddp_flat.ddp_refcnt != 0)
            return (EINVAL);
        for (int d = 0; d < SPA_DVAS_PER_BP; d++)
            if (flat->ddp_flat.ddp_dva[d].dva_word[0] != 0 ||
                flat->ddp_flat.ddp_dva[d].dva_word[1] != 0)
                return (EINVAL);
        return (0); /* real cleared journal record, not a physical group */
    }
    int copies = ddt_phys_dva_count(flat, DDT_PHYS_FLAT, DDK_GET_CRYPT(key));
    if (copies < 1 || copies >= DDT_PHYS_MAX)
        return (EINVAL);
    ddt_univ_phys_t traditional = {0};
    memcpy(traditional.ddp_trad[copies].ddp_dva, flat->ddp_flat.ddp_dva,
        sizeof (flat->ddp_flat.ddp_dva));
    traditional.ddp_trad[copies].ddp_refcnt = flat->ddp_flat.ddp_refcnt;
    traditional.ddp_trad[copies].ddp_phys_birth = flat->ddp_flat.ddp_phys_birth;
    error = rb_check_phys(spa, key, &traditional, checksum, B_TRUE);
    if (error != 0)
        return (error);
    blkptr_t bp;
    ddt_bp_create(checksum, key, flat, DDT_PHYS_FLAT, &bp);
    BP_SET_DEDUP(&bp, 0);
    uint64_t count;
    error = rebuild_native_brt_count(spa,
        rb_live_vdev(spa, DVA_GET_VDEV(&bp.blk_dva[0])), &bp, &count);
    if (error != 0)
        return (error);
    return (count == 0 ? 0 : ESTALE); /* never D1 plus BRT */
}

static void
rb_bp(const rb_record_t *r, int slot, blkptr_t *bp)
{
    ddt_bp_create(r->checksum, &r->key, &r->phys, slot, bp);
    BP_SET_DEDUP(bp, 0);
}


int
rebuild_bridge_open(spa_t *spa, uint64_t stage, size_t batch,
    rebuild_bridge_t **out)
{
    if (spa == NULL || out == NULL || batch == 0 || batch > 65536)
        return (EINVAL);
    rebuild_bridge_t *b = calloc(1, sizeof (*b));
    if (b == NULL)
        return (ENOMEM);
    b->spa = spa;
    b->os = spa->spa_meta_objset;
    b->stage = stage;
    b->batch = MIN(batch, 4096);
    b->nvdevs = spa->spa_root_vdev->vdev_children;
    b->vdevs = calloc(b->nvdevs, sizeof (*b->vdevs));
    if (b->vdevs == NULL) {
        rebuild_bridge_close(b);
        return (ENOMEM);
    }
    for (unsigned c = 0; c < ZIO_CHECKSUM_FUNCTIONS; c++) {
        ddt_t *ddt = spa->spa_ddt[c];
        if (ddt != NULL && ddt->ddt_version == DDT_VERSION_LEGACY)
            b->tables[c].used = B_TRUE;
    }
    *out = b;
    return (0);
}

int
rebuild_bridge_admit_open(spa_t *spa, uint64_t stage, size_t batch,
    rebuild_bridge_t **out)
{
    if (stage == 0)
        return (EINVAL);
    int error = rebuild_bridge_open(spa, stage, batch, out);
    if (error != 0)
        return (error);
    rebuild_bridge_t *b = *out;
    b->admission_base = B_TRUE;
    b->flat_mutation = B_TRUE;
    b->target = 2;
    /* The caller has just created the durable stage. Never adopt unrelated
     * or interrupted shadows; those must go through ordinary recovery. */
    zap_cursor_t cursor;
    zap_attribute_t *attribute = zap_attribute_alloc();
    zap_cursor_init(&cursor, b->os, stage);
    while ((error = zap_cursor_retrieve(&cursor, attribute)) == 0) {
        if (strncmp(attribute->za_name, "bridgex-", 8) == 0) {
            error = EBUSY;
            break;
        }
        zap_cursor_advance(&cursor);
    }
    zap_cursor_fini(&cursor);
    zap_attribute_free(attribute);
    if (error == ENOENT)
        error = 0;
    if (error != 0) {
        rebuild_bridge_close(b);
        *out = NULL;
    }
    return (error);
}

static void
rb_admit_write(rb_work_t *w, dmu_tx_t *tx)
{
    rebuild_bridge_t *b = w->bridge;
    const rb_record_t *r = w->records;
    rb_table_t *t = &b->tables[r->checksum];
    ddt_class_t cl = r->phys.ddp_flat.ddp_refcnt > 1 ?
        DDT_CLASS_DUPLICATE : DDT_CLASS_UNIQUE;
    if (t->objects[cl] == 0) {
        w->error = ddt_zap_ops.ddt_op_create(b->os, &t->objects[cl], tx,
            zio_checksum_table[r->checksum].ci_flags & ZCHECKSUM_FLAG_DEDUP);
        if (w->error != 0)
            return;
        char key[RB_KEY_SIZE];
        rb_name(key, 2, "new-ddt", r->checksum * DDT_CLASSES + cl);
        w->error = rb_put(b, key, t->objects[cl], tx);
        if (w->error != 0) {
            int cleanup = dmu_object_free(b->os, t->objects[cl], tx);
            if (cleanup != 0)
                w->error = cleanup;
            t->objects[cl] = 0;
            return;
        }
    }
    dnode_t *dn;
    w->error = dnode_hold(b->os, t->objects[cl], FTAG, &dn);
    if (w->error != 0)
        return;
    w->error = ddt_zap_ops.ddt_op_update(dn, &r->key, &r->phys,
        DDT_FLAT_PHYS_SIZE, tx);
    dnode_rele(dn, FTAG);
    if (w->error == 0)
        t->used = B_TRUE;
}

int
rebuild_bridge_admit(rebuild_bridge_t *b, enum zio_checksum checksum,
    const ddt_key_t *key, const ddt_univ_phys_t *flat, boolean_t *admit)
{
    if (b == NULL || !b->admission_base || b->source_set || b->prepared ||
        key == NULL || flat == NULL || admit == NULL ||
        flat->ddp_flat.ddp_refcnt == 0 || flat->ddp_flat.ddp_phys_birth == 0 ||
        rb_key_check(key, checksum) != 0 || b->spa->spa_ddt[checksum] == NULL)
        return (EINVAL);
    *admit = B_FALSE;
    /* Disabled native quota needs no per-key shadow transaction. Final
     * preparation still writes and validates every admitted output row. */
    if (b->spa->spa_dedup_table_quota == 0) {
        *admit = B_TRUE;
        return (0);
    }
    uint64_t staged = 0;
    for (unsigned c = 0; c < ZIO_CHECKSUM_FUNCTIONS; c++) {
        for (unsigned cl = 0; cl < DDT_CLASSES; cl++) {
            if (b->tables[c].objects[cl] == 0)
                continue;
            dmu_object_info_t info;
            int error = dmu_object_info(b->os, b->tables[c].objects[cl], &info);
            if (error != 0)
                return (error);
            if (info.doi_physical_blocks_512 > (UINT64_MAX - staged) >> 9)
                return (EOVERFLOW);
            staged += info.doi_physical_blocks_512 << 9;
        }
    }
    /* Class allocation already includes committed private shadows. Adding
     * them a second time would incorrectly double-charge automatic quota.
     * Literal DDT accounting, however, only includes live table roots. */
    boolean_t existing;
    int error = rebuild_native_ddt_admit(b->spa, checksum, key, staged, 0,
        admit, &existing);
    if (error != 0 || !*admit || existing)
        return (error);
    rb_record_t record = { .checksum = checksum, .key = *key, .phys = *flat };
    rb_work_t w = { .bridge = b, .records = &record, .count = 1 };
    /* dsl_sync_task waits for this TXG to commit, so the next group's
     * physical allocation measurement includes this actual native write. */
    return (rb_run(&w, rb_admit_write, 80));
}

static int
rb_read(rebuild_bridge_t *b, uint64_t index, rb_record_t *record)
{
    enum zio_checksum checksum;
    int canonical;
    int error = b->reader(b->reader_arg, index, &checksum,
        &record->key, &record->phys, &canonical);
    if (error == 0) {
        record->checksum = checksum;
        record->canonical = canonical;
    }
    return (error);
}

int
rebuild_bridge_set_source(rebuild_bridge_t *b, rebuild_bridge_reader_t reader,
    void *arg, uint64_t count)
{
    if (b == NULL || b->prepared || b->source_set ||
        (count != 0 && reader == NULL))
        return (EINVAL);
    b->reader = reader;
    b->reader_arg = arg;
    b->source_set = B_TRUE;
    b->count = count;
    for (uint64_t index = 0; index < count; index++) {
        if (rebuild_interrupted())
            return (EINTR);
        rb_record_t r;
        int error = rb_read(b, index, &r);
        if (error != 0)
            return (error);
        error = rebuild_bridge_check(b->spa, &r.key, &r.phys, r.checksum);
        if (error != 0)
            return (error);
        if (r.canonical < 1 || r.canonical >= DDT_PHYS_MAX ||
            r.phys.ddp_trad[r.canonical].ddp_refcnt == 0)
            return (EINVAL);
        b->tables[r.checksum].used = B_TRUE;
        b->tables[r.checksum].count++;
        for (int s = 1; s < DDT_PHYS_MAX; s++)
            if (r.phys.ddp_trad[s].ddp_refcnt > 1)
                b->vdevs[DVA_GET_VDEV(
                    &r.phys.ddp_trad[s].ddp_dva[0])].needed = B_TRUE;
    }
    return (0);
}

int
rebuild_bridge_set_flat_source(rebuild_bridge_t *b,
    rebuild_bridge_reader_t reader, void *arg, uint64_t count,
    rebuild_bridge_brt_reader_t brt_reader, void *brt_arg, uint64_t brt_count)
{
    if (b == NULL || b->source_set || b->prepared ||
        (count != 0 && reader == NULL) ||
        (brt_count != 0 && brt_reader == NULL))
        return (EINVAL);
    for (unsigned c = 0; c < ZIO_CHECKSUM_FUNCTIONS; c++) {
        ddt_t *ddt = b->spa->spa_ddt[c];
        if (ddt == NULL)
            continue;
        if (ddt->ddt_version != DDT_VERSION_UNCONFIGURED &&
            (ddt->ddt_version != DDT_VERSION_FDT ||
            ddt->ddt_flags != (DDT_FLAG_FLAT | DDT_FLAG_LOG)))
            return (ENOTSUP);
        b->tables[c].used |= ddt->ddt_version == DDT_VERSION_FDT;
    }
    b->flat_mutation = B_TRUE;
    b->reader = reader;
    b->reader_arg = arg;
    b->count = count;
    b->brt_reader = brt_reader;
    b->brt_arg = brt_arg;
    b->brt_count = brt_count;
    for (uint64_t i = 0; i < count; i++) {
        rb_record_t record;
        int error = rb_read(b, i, &record);
        if (error != 0)
            return (error);
        if (record.checksum >= ZIO_CHECKSUM_FUNCTIONS ||
            record.canonical != DDT_PHYS_FLAT)
            return (EINVAL);
        error = rb_key_check(&record.key, record.checksum);
        if (error != 0)
            return (error);
        b->tables[record.checksum].used = B_TRUE;
        b->tables[record.checksum].count++;
    }
    for (uint64_t i = 0; i < brt_count; i++) {
        blkptr_t bp;
        uint64_t before, after;
        int error = brt_reader(brt_arg, i, &bp, &before, &after);
        if (error != 0)
            return (error);
        uint64_t id = DVA_GET_VDEV(BP_IDENTITY(&bp));
        if (id >= b->nvdevs || BP_IS_HOLE(&bp) || BP_IS_EMBEDDED(&bp))
            return (EINVAL);
        b->vdevs[id].needed |= before != 0 || after != 0;
    }
    b->source_set = B_TRUE;
    return (0);
}

static int
rb_flat_match(rebuild_bridge_t *b, const rb_record_t *r)
{
    ddt_t *ddt = b->spa->spa_ddt[r->checksum];
    if (ddt == NULL || ddt->ddt_version != DDT_VERSION_FDT ||
        ddt->ddt_flags != (DDT_FLAG_FLAT|DDT_FLAG_LOG))
        return (ESTALE);
    if (!avl_is_empty(&ddt->ddt_tree) ||
        !avl_is_empty(&ddt->ddt_log_active->ddl_tree) ||
        !avl_is_empty(&ddt->ddt_log_flushing->ddl_tree))
        return (EBUSY);
    unsigned found = 0;
    for (int cl = 0; cl < DDT_CLASSES; cl++) {
        dnode_t *dn = ddt->ddt_object_dnode[DDT_TYPE_DEFAULT][cl];
        if (dn == NULL)
            continue;
        ddt_univ_phys_t flat;
        int error = ddt_zap_ops.ddt_op_lookup(dn, &r->key,
            &flat, DDT_FLAT_PHYS_SIZE);
        if (error == ENOENT)
            continue;
        if (error != 0)
            return (error);
        if (found++ != 0 ||
            cl != (r->phys.ddp_trad[r->canonical].ddp_refcnt > 1 ?
            DDT_CLASS_DUPLICATE : DDT_CLASS_UNIQUE) ||
            flat.ddp_flat.ddp_refcnt != r->phys.ddp_trad[r->canonical].ddp_refcnt ||
            flat.ddp_flat.ddp_phys_birth !=
            r->phys.ddp_trad[r->canonical].ddp_phys_birth ||
            memcmp(flat.ddp_flat.ddp_dva,
            r->phys.ddp_trad[r->canonical].ddp_dva,
            sizeof (flat.ddp_flat.ddp_dva)) != 0)
            return (ESTALE);
    }
    return (found == 1 ? 0 : ESTALE);
}

int
rebuild_bridge_validate(rebuild_bridge_t *b)
{
    if (b == NULL || !b->source_set)
        return (EINVAL);
    if (b->flat_mutation) {
        int error = rebuild_bridge_foreach_flat(b->spa, rb_validate_flat, b->spa);
        for (uint64_t i = 0; error == 0 && i < b->brt_count; i++) {
            blkptr_t bp;
            uint64_t before, after, observed;
            error = b->brt_reader(b->brt_arg, i, &bp, &before, &after);
            if (error == 0)
                error = rebuild_native_brt_refcount(b->spa, &bp, &observed);
            if (error == 0 && observed != before)
                error = ESTALE;
        }
        return (error);
    }
    boolean_t migration = b->count != 0;
    for (unsigned c = 0; c < ZIO_CHECKSUM_FUNCTIONS; c++)
        migration |= b->tables[c].used;
    if (!migration)
        return (rebuild_bridge_foreach_flat(b->spa, rb_validate_flat, b->spa));
    if (!spa_feature_is_enabled(b->spa, SPA_FEATURE_BLOCK_CLONING) ||
        !spa_feature_is_enabled(b->spa, SPA_FEATURE_FAST_DEDUP))
        return (ENOTSUP);
    int error = 0;
    for (uint64_t id = 0; id < b->spa->spa_brt_nvdevs; id++) {
        brt_vdev_t *v = b->spa->spa_brt_vdevs[id];
        if (!avl_is_empty(&v->bv_tree))
            return (EBUSY);
        for (int i = 0; i < TXG_SIZE; i++)
            if (!avl_is_empty(&v->bv_pending_tree[i]))
                return (EBUSY);
    }
    uint64_t phase = REBUILD_INVENTORY;
    if (b->stage != 0 && (error = rb_get(b, "phase", &phase)) != 0)
        return (error);
    boolean_t legacy = phase < REBUILD_BRIDGE_PUBLISHED;
    for (uint64_t id = 0; id < b->nvdevs; id++) {
        b->vdevs[id].projected_saved = 0;
        b->vdevs[id].projected_used = 0;
    }
    rb_record_t r;
    for (uint64_t index = 0; index < b->count; index++) {
        if (rebuild_interrupted())
            return (EINTR);
        error = rb_read(b, index, &r);
        if (error != 0)
            return (error);
        if (legacy) {
            error = rebuild_native_ddt_match(b->spa, r.checksum,
                &r.key, &r.phys);
            if (error != 0)
                return (error);
        }
        if (phase >= REBUILD_FLAT_PUBLISHED) {
            error = rb_flat_match(b, &r);
            if (error != 0)
                return (error);
        }
        for (int s = 1; s < DDT_PHYS_MAX; s++) {
            uint64_t refs = r.phys.ddp_trad[s].ddp_refcnt;
            if (refs == 0)
                continue;
            blkptr_t bp;
            rb_bp(&r, s, &bp);
            uint64_t count;
            uint64_t id = DVA_GET_VDEV(&bp.blk_dva[0]);
            brt_vdev_t *live = rb_live_vdev(b->spa, id);
            error = rebuild_native_brt_count(b->spa, live, &bp, &count);
            uint64_t expected = legacy ||
                (phase >= REBUILD_FLAT_PUBLISHED && s == r.canonical) ?
                0 : refs-1;
            if (error != 0 || count != expected)
                return (error != 0 ? error : ESTALE);
            if (phase >= REBUILD_FLAT_PUBLISHED || refs < 2 ||
                (!legacy && s != r.canonical))
                continue;
            rb_vdev_t *v = &b->vdevs[id];
            uint64_t size = bp_get_dsize(b->spa, &bp);
            uint64_t saved = size*(refs-1);
            if (v->projected_saved > UINT64_MAX-saved ||
                v->projected_used > UINT64_MAX-size)
                return (EOVERFLOW);
            v->projected_saved += saved;
            v->projected_used += size;
            if (legacy) {
                if (live != NULL &&
                    (live->bv_savedspace > UINT64_MAX-v->projected_saved ||
                    live->bv_usedspace > UINT64_MAX-v->projected_used))
                    return (EOVERFLOW);
            } else if (live == NULL ||
                live->bv_savedspace < v->projected_saved ||
                live->bv_usedspace < v->projected_used) {
                return (ESTALE);
            }
        }
    }
    if (legacy) {
        for (unsigned c = 0; c < ZIO_CHECKSUM_FUNCTIONS; c++) {
            ddt_t *ddt = b->spa->spa_ddt[c];
            if (ddt == NULL)
                continue;
            uint64_t total = 0;
            for (int cl = 0; cl < DDT_CLASSES; cl++) {
                uint64_t n = 0;
                if (ddt->ddt_object[DDT_TYPE_DEFAULT][cl] == 0)
                    continue;
                error = ddt_zap_ops.ddt_op_count(
                    ddt->ddt_object_dnode[DDT_TYPE_DEFAULT][cl], &n);
                if (error != 0 || total > UINT64_MAX-n)
                    return (error != 0 ? error : EOVERFLOW);
                total += n;
            }
            if (ddt->ddt_version == DDT_VERSION_LEGACY &&
                total != b->tables[c].count)
                return (EINVAL); /* inventory must cover every legacy key */
        }
    }
    return (0);
}

/* Allocate and persist the reachability key in the SAME assigned task. */
static void
rb_allocate(rb_work_t *w, dmu_tx_t *tx)
{
    rebuild_bridge_t *b = w->bridge;
    if (w->operation == 1) {
        w->object = zap_create_flags(b->os, 0,
            ZAP_FLAG_HASH64 | ZAP_FLAG_UINT64_KEY,
            DMU_OTN_ZAP_METADATA, 13, 13, DMU_OT_NONE, 0, tx);
    } else if (w->operation == 2) {
        w->object = zap_create(b->os, DMU_OT_DDT_STATS,
            DMU_OT_NONE, 0, tx);
    } else {
        w->object = dmu_object_alloc(b->os, w->info.doi_type,
            w->info.doi_data_block_size, w->info.doi_bonus_type,
            w->info.doi_bonus_size, tx);
    }
    if (w->object == 0) {
        w->error = ENOSPC;
        return;
    }
    w->error = rb_put(b, w->key, w->object, tx);
    if (w->error != 0) {
        /* Allocation and its failed ledger insertion are still one TXG. */
        int cleanup = dmu_object_free(b->os, w->object, tx);
        if (cleanup != 0)
            w->error = cleanup;
        w->object = 0;
        return;
    }
    if (w->info.doi_bonus_size == 0)
        return;
    dmu_buf_t *db;
    w->error = dmu_bonus_hold(b->os, w->object, FTAG, &db);
    if (w->error != 0)
        return;
    dmu_buf_will_dirty(db, tx);
    memcpy(db->db_data, w->data, w->info.doi_bonus_size);
    dmu_buf_rele(db, FTAG);
}

static void
rb_write(rb_work_t *w, dmu_tx_t *tx)
{
    dmu_write(w->bridge->os, w->object, w->offset, w->length,
        w->data, tx, DMU_READ_NO_PREFETCH | DMU_UNCACHEDIO);
}

static int
rb_object(rebuild_bridge_t *b, const char *kind, uint64_t index,
    uint64_t source, unsigned operation, uint64_t *out)
{
    rb_work_t w = { .bridge = b, .operation = operation };
    rb_name(w.key, b->target, kind, index);
    uint8_t bonus[DN_OLD_MAX_BONUSLEN];
    if (source != 0) {
        int error = dmu_object_info(b->os, source, &w.info);
        if (error != 0)
            return (error);
        if (w.info.doi_bonus_size > sizeof (bonus))
            return (ENOTSUP);
        if (w.info.doi_bonus_size != 0) {
            dmu_buf_t *db;
            error = dmu_bonus_hold(b->os, source, FTAG, &db);
            if (error != 0)
                return (error);
            memcpy(bonus, db->db_data, w.info.doi_bonus_size);
            dmu_buf_rele(db, FTAG);
            w.data = bonus;
        }
        w.operation = 0;
    }
    int error = rb_run(&w, rb_allocate, 8);
    if (error != 0)
        return (error);
    *out = w.object;
    if (source == 0)
        return (0);
    void *buffer = malloc(RB_COPY_SIZE);
    if (buffer == NULL)
        return (ENOMEM);
    w.data = buffer;
    for (w.offset = 0; w.offset < w.info.doi_max_offset;) {
        w.length = MIN(RB_COPY_SIZE, w.info.doi_max_offset-w.offset);
        error = dmu_read(b->os, source, w.offset, w.length, buffer,
            DMU_READ_NO_PREFETCH | DMU_UNCACHEDIO);
        if (error == 0)
            error = rb_run(&w, rb_write, 256);
        if (error != 0)
            break;
        w.offset += w.length;
    }
    free(buffer);
    return (error);
}

static void
rb_save_roots(rb_work_t *w, dmu_tx_t *tx)
{
    rebuild_bridge_t *b = w->bridge;
    char key[RB_KEY_SIZE];
    b->old_stats = b->spa->spa_ddt_stat_object;
    rb_name(key, b->target, "old-stats", 0);
    w->error = rb_put(b, key, b->old_stats, tx);
    for (uint64_t id = 0; id < b->nvdevs && w->error == 0; id++) {
        brt_vdev_t *live = rb_live_vdev(b->spa, id);
        rb_vdev_t *v = &b->vdevs[id];
        v->old_object = live != NULL ? live->bv_mos_brtvdev : 0;
        v->old_entries = live != NULL ? live->bv_mos_entries : 0;
        if (v->old_object == 0)
            continue;
        v->needed = B_TRUE;
        rb_name(key, b->target, "old-brtv", id);
        w->error = rb_put(b, key, v->old_object, tx);
        if (w->error == 0) {
            rb_name(key, b->target, "old-brte", id);
            w->error = rb_put(b, key, v->old_entries, tx);
        }
    }
    for (unsigned c = 0; c < ZIO_CHECKSUM_FUNCTIONS && w->error == 0; c++) {
        if (!b->tables[c].used)
            continue;
        ddt_t *ddt = b->spa->spa_ddt[c];
        if (b->flat_mutation) {
            b->tables[c].old_dir = ddt->ddt_dir_object;
            rb_name(key, b->target, "old-ddir", c);
            w->error = rb_put(b, key, ddt->ddt_dir_object, tx);
            for (unsigned log = 0; log < 2 && w->error == 0; log++) {
                rb_name(key, b->target, "old-dlog", 2*c+log);
                w->error = rb_put(b, key, ddt->ddt_log[log].ddl_object, tx);
            }
            if (w->error != 0)
                return;
        }
        for (int cl = 0; cl < DDT_CLASSES; cl++) {
            uint64_t object = ddt->ddt_object[DDT_TYPE_DEFAULT][cl];
            b->tables[c].old_objects[cl] = object;
            if (object == 0)
                continue;
            rb_name(key, b->target, "old-ddt", c*DDT_CLASSES+cl);
            w->error = rb_put(b, key, object, tx);
            if (w->error != 0)
                break;
        }
    }
}

static void
rb_blank_brt(rb_work_t *w, dmu_tx_t *tx)
{
    rebuild_bridge_t *b = w->bridge;
    rb_vdev_t *v = &b->vdevs[w->value];
    vdev_t *vd = vdev_lookup_top(b->spa, w->value);
    brt_vdev_phys_t phys = {
        .bvp_mos_entries = v->entries,
        .bvp_size = (vdev_get_min_asize(vd)-1)/b->spa->spa_brt_rangesize+1,
        .bvp_byteorder = BRT_NATIVE_BYTEORDER,
        .bvp_rangesize = b->spa->spa_brt_rangesize
    };
    w->info.doi_type = DMU_OTN_UINT64_METADATA;
    w->info.doi_data_block_size = BRT_BLOCKSIZE;
    w->info.doi_bonus_type = DMU_OTN_UINT64_METADATA;
    w->info.doi_bonus_size = sizeof (phys);
    w->data = &phys;
    w->operation = 0;
    rb_allocate(w, tx);
    v->object = w->object;
}

static void
rb_fix_brt_entry_root(rb_work_t *w, dmu_tx_t *tx)
{
    dmu_buf_t *db;
    w->error = dmu_bonus_hold(w->bridge->os, w->object, FTAG, &db);
    if (w->error != 0)
        return;
    dmu_buf_will_dirty(db, tx);
    ((brt_vdev_phys_t *)db->db_data)->bvp_mos_entries = w->value;
    dmu_buf_rele(db, FTAG);
}

static int
rb_prepare_brt(rebuild_bridge_t *b)
{
    for (uint64_t id = 0; id < b->nvdevs; id++) {
        rb_vdev_t *v = &b->vdevs[id];
        if (!v->needed)
            continue;
        int error = rb_object(b, "new-brte", id, v->old_entries, 1,
            &v->entries);
        if (error != 0)
            return (error);
        if (v->old_object != 0) {
            error = rb_object(b, "new-brtv", id, v->old_object, 0,
                &v->object);
            if (error != 0)
                return (error);
            rb_work_t w = { .bridge = b, .object = v->object,
                .value = v->entries };
            error = rb_run(&w, rb_fix_brt_entry_root, 4);
        } else {
            rb_work_t w = { .bridge = b, .value = id };
            rb_name(w.key, b->target, "new-brtv", id);
            error = rb_run(&w, rb_blank_brt, 8);
        }
        if (error != 0)
            return (error);
        error = rebuild_native_brt_load(b->spa, id, v->object, &v->native);
        if (error != 0)
            return (error);
    }
    return (0);
}

static void
rb_stats_and_dirs(rb_work_t *w, dmu_tx_t *tx)
{
    rebuild_bridge_t *b = w->bridge;
    for (unsigned c = 0; c < ZIO_CHECKSUM_FUNCTIONS && w->error == 0; c++) {
        rb_table_t *t = &b->tables[c];
        if (!t->used)
            continue;
        ddt_t *ddt = b->spa->spa_ddt[c];
        for (int cl = 0; cl < DDT_CLASSES; cl++) {
            char name[DDT_NAMELEN];
            ddt_object_name(ddt, DDT_TYPE_DEFAULT, cl, name);
            int error = zap_remove(b->os, b->stats, name, tx);
            if (error != 0 && error != ENOENT) {
                w->error = error;
                return;
            }
        }
        if (b->target != 2)
            continue;
        t->dir = zap_create(b->os, DMU_OTN_ZAP_METADATA, DMU_OT_NONE, 0, tx);
        char key[RB_KEY_SIZE];
        rb_name(key, b->target, "new-ddir", c);
        w->error = rb_put(b, key, t->dir, tx);
        if (w->error != 0) {
            int cleanup = dmu_object_free(b->os, t->dir, tx);
            if (cleanup != 0)
                w->error = cleanup;
            t->dir = 0;
            return;
        }
        uint64_t version = DDT_VERSION_FDT, flags = DDT_FLAG_FLAT|DDT_FLAG_LOG;
        if (w->error == 0)
            w->error = zap_add(b->os, t->dir, DDT_DIR_VERSION,
                sizeof (version), 1, &version, tx);
        if (w->error == 0)
            w->error = zap_add(b->os, t->dir, DDT_DIR_FLAGS,
                sizeof (flags), 1, &flags, tx);
        if (b->admission_base) {
            ddt_histogram_t empty = {0};
            for (unsigned cl = 0; cl < DDT_CLASSES && w->error == 0; cl++) {
                if (t->objects[cl] == 0)
                    continue;
                char name[DDT_NAMELEN];
                ddt_object_name(ddt, DDT_TYPE_DEFAULT, cl, name);
                w->error = zap_add(b->os, t->dir, name, 8, 1,
                    &t->objects[cl], tx);
                if (w->error == 0)
                    w->error = zap_update(b->os, b->stats, name, 8,
                        sizeof (empty) / 8, &empty, tx);
            }
        }
    }
}

static void
rb_apply_records(rb_work_t *w, dmu_tx_t *tx)
{
    rebuild_bridge_t *b = w->bridge;
    for (size_t n = 0; n < w->count && w->error == 0; n++) {
        rb_record_t *r = &w->records[n];
        uint64_t identity[1+sizeof (ddt_key_t)/sizeof (uint64_t)];
        identity[0] = r->checksum;
        memcpy(identity+1, &r->key, sizeof (r->key));
        uint64_t one = 1;
        w->error = zap_add_uint64(b->os, b->seen, identity,
            sizeof (identity)/sizeof (*identity), sizeof (one), 1, &one, tx);
        if (w->error != 0)
            return;
        for (int s = 1; !b->flat_mutation && s < DDT_PHYS_MAX; s++) {
            uint64_t refs = r->phys.ddp_trad[s].ddp_refcnt;
            if (refs < 2 || (b->target == 2 && s != r->canonical))
                continue;
            blkptr_t bp;
            rb_bp(r, s, &bp);
            rb_vdev_t *v = &b->vdevs[DVA_GET_VDEV(&bp.blk_dva[0])];
            w->error = rebuild_native_brt_set_encoded(b->spa, v->native,
                &bp, b->target == 1 ? 0 : refs-1,
                b->target == 1 ? refs-1 : 0, b->fixed_endian, tx);
            if (w->error != 0)
                return;
        }
        if (b->target != 2)
            continue;
        rb_table_t *t = &b->tables[r->checksum];
        if (b->admission_base) {
            /* Admission rows are provisional only. Final source rows are
             * unique (seen above), so remove the provisional class before
             * adding its exact final BP/refcount or pending-free log entry.
             * Their histograms start empty and are built exactly once here. */
            for (unsigned prior = 0; prior < DDT_CLASSES; prior++) {
                if (t->objects[prior] == 0)
                    continue;
                dnode_t *dn;
                w->error = dnode_hold(b->os, t->objects[prior], FTAG, &dn);
                if (w->error != 0)
                    return;
                int error = ddt_zap_ops.ddt_op_remove(dn, &r->key, tx);
                dnode_rele(dn, FTAG);
                if (error != 0 && error != ENOENT) {
                    w->error = error;
                    return;
                }
            }
        }
        ddt_lightweight_entry_t entry = { .ddlwe_key = r->key };
        ddt_univ_phys_t *flat = &entry.ddlwe_phys;
        if (b->flat_mutation) {
            *flat = r->phys;
            if (flat->ddp_flat.ddp_phys_birth == 0)
                continue; /* effective cleared journal record */
            if (flat->ddp_flat.ddp_refcnt == 0) {
                /* Preserve native pending-free ownership in a native log,
                 * never as a private-retirement record or stored zero row. */
                ddt_log_update_t update = {0};
                entry.ddlwe_type = DDT_TYPES;
                entry.ddlwe_class = DDT_CLASSES;
                ddt_log_begin(t->view, 1, tx, &update);
                ddt_log_entry(t->view, &entry, &update);
                ddt_log_commit(t->view, &update);
                for (unsigned log = 0; log < 2; log++) {
                    char key[RB_KEY_SIZE];
                    rb_name(key, b->target, "new-dlog", 2*r->checksum+log);
                    w->error = rb_put(b, key,
                        t->view->ddt_log[log].ddl_object, tx);
                    if (w->error != 0)
                        return;
                }
                continue;
            }
        } else {
            memcpy(flat->ddp_flat.ddp_dva, r->phys.ddp_trad[r->canonical].ddp_dva,
                sizeof (flat->ddp_flat.ddp_dva));
            flat->ddp_flat.ddp_refcnt = r->phys.ddp_trad[r->canonical].ddp_refcnt;
            flat->ddp_flat.ddp_phys_birth =
                r->phys.ddp_trad[r->canonical].ddp_phys_birth;
            flat->ddp_flat.ddp_class_start = gethrestime_sec();
        }
        ddt_class_t cl = flat->ddp_flat.ddp_refcnt > 1 ?
            DDT_CLASS_DUPLICATE : DDT_CLASS_UNIQUE;
        char name[DDT_NAMELEN], key[RB_KEY_SIZE];
        ddt_object_name(b->spa->spa_ddt[r->checksum], DDT_TYPE_DEFAULT,
            cl, name);
        if (t->objects[cl] == 0) {
            w->error = ddt_zap_ops.ddt_op_create(b->os, &t->objects[cl], tx,
                zio_checksum_table[r->checksum].ci_flags & ZCHECKSUM_FLAG_DEDUP);
            if (w->error != 0)
                return;
            rb_name(key, b->target, "new-ddt", r->checksum*DDT_CLASSES+cl);
            w->error = rb_put(b, key, t->objects[cl], tx);
            if (w->error != 0) {
                int cleanup = dmu_object_free(b->os, t->objects[cl], tx);
                if (cleanup != 0)
                    w->error = cleanup;
                t->objects[cl] = 0;
                return;
            }
            if (w->error == 0)
                w->error = zap_add(b->os, t->dir, name, sizeof (uint64_t),
                    1, &t->objects[cl], tx);
            if (w->error != 0)
                return;
        }
        dnode_t *dn;
        w->error = dnode_hold(b->os, t->objects[cl], FTAG, &dn);
        if (w->error != 0)
            return;
        w->error = ddt_zap_ops.ddt_op_update(dn, &r->key,
            flat, DDT_FLAT_PHYS_SIZE, tx);
        dnode_rele(dn, FTAG);
        if (w->error != 0)
            return;
        ddt_histogram_add_entry(t->view,
            &t->view->ddt_histogram[DDT_TYPE_DEFAULT][cl], &entry);
        if (b->admission_base) {
            if (t->final_count[cl] == UINT64_MAX) {
                w->error = EOVERFLOW;
                return;
            }
            t->final_count[cl]++;
        }
    }
    for (uint64_t id = 0; id < b->nvdevs; id++)
        if (b->vdevs[id].native != NULL)
            rebuild_native_brt_flush(b->spa, b->vdevs[id].native, tx);
}

static void
rb_finish(rb_work_t *w, dmu_tx_t *tx)
{
    rebuild_bridge_t *b = w->bridge;
    if (b->target == 2) {
        for (unsigned c = 0; c < ZIO_CHECKSUM_FUNCTIONS; c++) {
            rb_table_t *t = &b->tables[c];
            if (!t->used)
                continue;
            for (int cl = 0; cl < DDT_CLASSES; cl++) {
                if (t->objects[cl] == 0)
                    continue;
                if (b->admission_base) {
                    dnode_t *dn;
                    uint64_t count;
                    w->error = dnode_hold(b->os, t->objects[cl], FTAG, &dn);
                    if (w->error != 0)
                        return;
                    w->error = ddt_zap_ops.ddt_op_count(dn, &count);
                    dnode_rele(dn, FTAG);
                    if (w->error == 0 && count != t->final_count[cl])
                        w->error = ECKSUM;
                    if (w->error != 0)
                        return;
                }
                char name[DDT_NAMELEN];
                ddt_object_name(b->spa->spa_ddt[c], DDT_TYPE_DEFAULT, cl, name);
                if (b->admission_base)
                    w->error = zap_update(b->os, b->stats, name,
                        sizeof (uint64_t),
                        sizeof (ddt_histogram_t)/sizeof (uint64_t),
                        &t->view->ddt_histogram[DDT_TYPE_DEFAULT][cl], tx);
                else
                    w->error = zap_add(b->os, b->stats, name,
                        sizeof (uint64_t),
                        sizeof (ddt_histogram_t)/sizeof (uint64_t),
                        &t->view->ddt_histogram[DDT_TYPE_DEFAULT][cl], tx);
                if (w->error != 0)
                    return;
            }
        }
    }
    /* Mark unused shadow BRT objects during preparation, not publication.
     * Inline flags avoid duplicate object references even if a task fails
     * between the two updates. Prepublication recovery frees either form.
     */
    for (uint64_t id = 0; id < b->nvdevs; id++) {
        rb_vdev_t *v = &b->vdevs[id];
        if (v->native == NULL || v->native->bv_totalcount != 0)
            continue;
        char key[RB_KEY_SIZE];
        rb_name(key, b->target, "new-brtv", id);
        w->error = rb_put(b, key, v->object | RB_UNUSED_OBJECT, tx);
        if (w->error != 0)
            return;
        rb_name(key, b->target, "new-brte", id);
        w->error = rb_put(b, key, v->entries | RB_UNUSED_OBJECT, tx);
        if (w->error != 0)
            return;
    }
    char key[RB_KEY_SIZE];
    rb_name(key, b->target, "ready", 0);
    w->error = rb_put(b, key, 1, tx);
    if (w->error != 0)
        return;
    /* Preload native replacements before publication: no publication I/O. */
    for (unsigned c = 0; c < ZIO_CHECKSUM_FUNCTIONS; c++) {
        rb_table_t *t = &b->tables[c];
        if (!t->used)
            continue;
        w->error = rebuild_native_ddt_stage(b->spa, c,
            b->target == 2 ? t->dir : 0, b->stats, &t->replacement);
        if (w->error != 0)
            return;
    }
}

static void
rb_apply_brt_records(rb_work_t *w, dmu_tx_t *tx)
{
    rebuild_bridge_t *b = w->bridge;
    for (size_t i = 0; i < w->count && w->error == 0; i++) {
        blkptr_t bp;
        uint64_t before, after;
        w->error = b->brt_reader(b->brt_arg, w->offset+i,
            &bp, &before, &after);
        if (w->error != 0)
            return;
        rb_vdev_t *v = &b->vdevs[DVA_GET_VDEV(BP_IDENTITY(&bp))];
        if (before == 0 && after == 0)
            continue;
        if (v->native == NULL) {
            w->error = EINVAL;
            return;
        }
        w->error = rebuild_native_brt_set_encoded(b->spa, v->native, &bp,
            before, after, b->fixed_endian, tx);
    }
    for (uint64_t id = 0; id < b->nvdevs; id++)
        if (b->vdevs[id].native != NULL)
            rebuild_native_brt_flush(b->spa, b->vdevs[id].native, tx);
}

int
rebuild_bridge_prepare(rebuild_bridge_t *b, boolean_t flat)
{
    if (b == NULL || b->stage == 0 || b->prepared)
        return (EINVAL);
    int error = rebuild_bridge_validate(b);
    if (error != 0)
        return (error);
    uint64_t phase;
    error = rb_get(b, "phase", &phase);
    if (error != 0)
        return (error);
    if ((!flat && phase != REBUILD_INVENTORY && phase != REBUILD_BRIDGE_PREPARED) ||
        (flat && !b->flat_mutation &&
        phase != REBUILD_LEGACY_RETIRED && phase != REBUILD_FLAT_PREPARED) ||
        (b->flat_mutation && (!flat || phase >= REBUILD_FLAT_PUBLISHED)))
        return (EINVAL);
    /* An interrupted preparation is disposable; no live root was changed. */
    error = b->admission_base ? 0 : rebuild_bridge_recover(b);
    if (error != 0)
        return (error);
    b->target = flat ? 2 : 1;
    if (flat && !b->flat_mutation) {
        /* Empty legacy tables were retired by phase one. They must stay
         * unconfigured, exactly as on a reopen with an empty manifest.
         */
        for (unsigned c = 0; c < ZIO_CHECKSUM_FUNCTIONS; c++)
            if (b->tables[c].count == 0)
                b->tables[c].used = B_FALSE;
    }
    b->fixed_endian = spa_feature_is_active(b->spa,
        SPA_FEATURE_BLOCK_CLONING_ENDIAN) ||
        (!spa_feature_is_active(b->spa, SPA_FEATURE_BLOCK_CLONING) &&
        spa_feature_is_enabled(b->spa, SPA_FEATURE_BLOCK_CLONING_ENDIAN));
    rb_work_t w = { .bridge = b };
    error = rb_run(&w, rb_save_roots, 64);
    if (error != 0)
        return (error);
    error = rb_object(b, "new-stats", 0, b->old_stats, 2, &b->stats);
    if (error == 0)
        error = rb_object(b, "discard-seen", 0, 0, 1, &b->seen);
    if (error == 0)
        error = rb_prepare_brt(b);
    if (error != 0)
        return (error);
    if (flat && !b->flat_mutation) {
        for (unsigned c = 0; c < ZIO_CHECKSUM_FUNCTIONS; c++) {
            rb_table_t *t = &b->tables[c];
            if (!t->used)
                continue;
            t->view = calloc(1, sizeof (*t->view));
            if (t->view == NULL)
                return (ENOMEM);
            t->view->ddt_spa = b->spa;
            t->view->ddt_os = b->os;
            t->view->ddt_flags = DDT_FLAG_FLAT|DDT_FLAG_LOG;
        }
    }
    error = rb_run(&w, rb_stats_and_dirs, 64);
    if (error != 0)
        return (error);
    if (b->flat_mutation) {
        for (unsigned c = 0; c < ZIO_CHECKSUM_FUNCTIONS; c++) {
            rb_table_t *table = &b->tables[c];
            if (!table->used)
                continue;
            error = rebuild_native_ddt_stage(b->spa, c,
                table->dir, b->stats, &table->view);
            if (error != 0)
                return (error);
        }
    }
    if (b->flat_mutation) {
        for (uint64_t first = 0; first < b->brt_count; first += w.count) {
            w.offset = first;
            w.count = MIN((uint64_t)b->batch, b->brt_count-first);
            error = rb_run(&w, rb_apply_brt_records, (int)(w.count*16+64));
            if (error != 0)
                return (error);
        }
    }
    size_t capacity = (size_t)MIN((uint64_t)b->batch, b->count);
    rb_record_t *records = capacity != 0 ?
        malloc(capacity*sizeof (*records)) : NULL;
    if (capacity != 0 && records == NULL)
        return (ENOMEM);
    w.records = records;
    for (uint64_t first = 0; first < b->count; first += w.count) {
        w.count = MIN((uint64_t)b->batch, b->count-first);
        for (size_t n = 0; n < w.count; n++) {
            error = rb_read(b, first+n, &records[n]);
            if (error != 0)
                break;
        }
        if (error == 0)
            error = rb_run(&w, rb_apply_records, (int)(w.count*16+64));
        if (error != 0)
            break;
    }
    free(records);
    if (error == 0)
        error = rb_run(&w, rb_finish, 64);
    if (error != 0)
        return (error);
    b->replacement_vdevs = kmem_zalloc(
        b->nvdevs*sizeof (*b->replacement_vdevs), KM_SLEEP);
    for (uint64_t id = 0; id < b->nvdevs; id++) {
        rb_vdev_t *v = &b->vdevs[id];
        if (v->native != NULL && v->native->bv_totalcount != 0) {
            b->replacement_vdevs[id] = v->native;
            v->native = NULL;
        } else {
            error = rebuild_native_brt_load(b->spa, id, 0,
                &b->replacement_vdevs[id]);
            if (error != 0)
                return (error);
        }
    }
    b->prepared = B_TRUE;
    return (0);
}

static int
rb_root_matches(rebuild_bridge_t *b, const char *name, uint64_t expected)
{
    uint64_t object;
    int error = zap_lookup(b->os, DMU_POOL_DIRECTORY_OBJECT, name,
        sizeof (object), 1, &object);
    if (error == ENOENT)
        return (expected == 0 ? 0 : ESTALE);
    if (error != 0)
        return (error);
    return (object == expected ? 0 : ESTALE);
}

static void
rb_root_set(rebuild_bridge_t *b, const char *name, uint64_t object,
    dmu_tx_t *tx)
{
    if (object != 0) {
        VERIFY0(zap_update(b->os, DMU_POOL_DIRECTORY_OBJECT, name,
            sizeof (object), 1, &object, tx));
    } else {
        VERIFY0(zap_remove(b->os, DMU_POOL_DIRECTORY_OBJECT, name, tx));
    }
}

static int
rb_publication_validate(rebuild_bridge_t *b, boolean_t flat)
{
    if (b == NULL || !b->prepared || b->published ||
        b->target != (flat ? 2U : 1U) || b->replacement_vdevs == NULL)
        return (EINVAL);
    char name[RB_KEY_SIZE];
    int error = rb_root_matches(b, DMU_POOL_DDT_STATS, b->old_stats);
    if (error != 0)
        return (error);
    for (uint64_t id = 0; id < b->nvdevs; id++) {
        snprintf(name, sizeof (name), "%s%llu", BRT_OBJECT_VDEV_PREFIX,
            (u_longlong_t)id);
        rb_vdev_t *v = &b->vdevs[id];
        brt_vdev_t *replacement = b->replacement_vdevs[id];
        if (replacement == NULL || replacement->bv_meta_dirty ||
            replacement->bv_entcount_dirty ||
            !avl_is_empty(&replacement->bv_tree) ||
            (replacement->bv_mos_brtvdev != 0 &&
            (replacement->bv_mos_brtvdev != v->object ||
            replacement->bv_mos_entries != v->entries)))
            return (EINVAL);
        brt_vdev_t *current = rb_live_vdev(b->spa, id);
        if (current != NULL) {
            if (current->bv_meta_dirty || !avl_is_empty(&current->bv_tree))
                return (EBUSY);
            for (int n = 0; n < TXG_SIZE; n++)
                if (!avl_is_empty(&current->bv_pending_tree[n]))
                    return (EBUSY);
        }
        error = rb_root_matches(b, name, b->vdevs[id].old_object);
        if (error != 0)
            return (error);
    }
    for (unsigned c = 0; c < ZIO_CHECKSUM_FUNCTIONS; c++) {
        rb_table_t *t = &b->tables[c];
        if (!t->used)
            continue;
        if (t->replacement == NULL)
            return (EINVAL);
        ddt_t *ddt = b->spa->spa_ddt[c];
        if (!avl_is_empty(&ddt->ddt_tree) ||
            !avl_is_empty(&ddt->ddt_repair_tree))
            return (EBUSY);
        for (int cl = 0; cl < DDT_CLASSES; cl++) {
            if (b->flat_mutation) {
                if (ddt->ddt_object[DDT_TYPE_DEFAULT][cl] != t->old_objects[cl])
                    return (ESTALE);
            } else {
                ddt_object_name(ddt, DDT_TYPE_DEFAULT, cl, name);
                error = rb_root_matches(b, name, t->old_objects[cl]);
                if (error != 0)
                    return (error);
            }
        }
        snprintf(name, sizeof (name), DMU_POOL_DDT_DIR,
            zio_checksum_table[c].ci_name);
        error = rb_root_matches(b, name, b->flat_mutation ? t->old_dir : 0);
        if (error != 0)
            return (error);
    }
    uint64_t old_brt = 0, add_brt = 0, add_flat = 0;
    for (uint64_t id = 0; id < b->nvdevs; id++) {
        old_brt += b->vdevs[id].old_object != 0;
        add_brt += b->vdevs[id].old_object == 0 &&
            b->replacement_vdevs[id]->bv_mos_brtvdev != 0;
    }
    if (flat)
        for (unsigned c = 0; c < ZIO_CHECKSUM_FUNCTIONS; c++)
            add_flat += b->tables[c].used && b->tables[c].old_dir == 0;
    const spa_feature_t features[] = { SPA_FEATURE_BLOCK_CLONING,
        SPA_FEATURE_FAST_DEDUP, SPA_FEATURE_BLOCK_CLONING_ENDIAN };
    for (size_t n = 0; n < sizeof (features)/sizeof (*features); n++) {
        spa_feature_t feature = features[n];
        if (feature == SPA_FEATURE_BLOCK_CLONING_ENDIAN &&
            !spa_feature_is_enabled(b->spa, feature))
            continue;
        uint64_t on_disk;
        error = feature_get_refcount_from_disk(b->spa,
            &spa_feature_table[feature], &on_disk);
        if (error != 0)
            return (error);
        if (on_disk != b->spa->spa_feat_refcount_cache[feature])
            return (ESTALE);
        uint64_t additions = feature == SPA_FEATURE_FAST_DEDUP ?
            add_flat : add_brt;
        if (on_disk > UINT64_MAX-additions)
            return (EOVERFLOW);
        if (feature == SPA_FEATURE_BLOCK_CLONING && on_disk != old_brt)
            return (ESTALE);
        if (feature == SPA_FEATURE_BLOCK_CLONING_ENDIAN &&
            on_disk != 0 && on_disk != old_brt)
            return (ESTALE);
    }
    boolean_t endian = spa_feature_is_active(b->spa,
        SPA_FEATURE_BLOCK_CLONING_ENDIAN);
    boolean_t target_endian = endian ||
        (!spa_feature_is_active(b->spa, SPA_FEATURE_BLOCK_CLONING) &&
        spa_feature_is_enabled(b->spa, SPA_FEATURE_BLOCK_CLONING_ENDIAN));
    return (target_endian == b->fixed_endian ? 0 : ESTALE);
}

int
rebuild_bridge_publish_check(rebuild_bridge_t *b, boolean_t flat, dmu_tx_t *tx)
{
    if (b == NULL || tx == NULL)
        return (EINVAL);
    rb_publish_release(b);
    boolean_t syncing = dmu_tx_is_syncing(tx);
    int error = syncing ? rb_publish_pin(b) : 0;
    if (error == 0)
        error = rb_publication_validate(b, flat);
    if (error != 0) {
        rb_publish_release(b);
        return (error);
    }
    if (syncing) {
        b->publication_txg = dmu_tx_get_txg(tx);
        b->publication_endian = spa_feature_is_active(b->spa,
            SPA_FEATURE_BLOCK_CLONING_ENDIAN);
    }
    return (0);
}

int
rebuild_bridge_publish(rebuild_bridge_t *b, boolean_t flat, dmu_tx_t *tx)
{
    VERIFY(b != NULL && b->prepared && !b->published);
    VERIFY(dmu_tx_is_syncing(tx));
    VERIFY(b->target == (flat ? 2U : 1U));
    VERIFY(b->publication_txg == dmu_tx_get_txg(tx));
    char name[RB_KEY_SIZE];
    boolean_t endian = b->publication_endian;
    for (uint64_t id = 0; id < b->nvdevs; id++) {
        rb_vdev_t *v = &b->vdevs[id];
        boolean_t live = b->replacement_vdevs[id]->bv_mos_brtvdev != 0;
        snprintf(name, sizeof (name), "%s%llu", BRT_OBJECT_VDEV_PREFIX,
            (u_longlong_t)id);
        if (live || v->old_object != 0)
            rb_root_set(b, name, live ? v->object : 0, tx);
        if (live && v->old_object == 0) {
            spa_feature_incr(b->spa, SPA_FEATURE_BLOCK_CLONING, tx);
            if (b->fixed_endian)
                spa_feature_incr(b->spa, SPA_FEATURE_BLOCK_CLONING_ENDIAN, tx);
        } else if (!live && v->old_object != 0) {
            spa_feature_decr(b->spa, SPA_FEATURE_BLOCK_CLONING, tx);
            if (endian)
                spa_feature_decr(b->spa, SPA_FEATURE_BLOCK_CLONING_ENDIAN, tx);
        }
    }
    for (unsigned c = 0; c < ZIO_CHECKSUM_FUNCTIONS; c++) {
        rb_table_t *t = &b->tables[c];
        if (!t->used)
            continue;
        for (int cl = 0; cl < DDT_CLASSES; cl++) {
            if (!b->flat_mutation && t->old_objects[cl] != 0) {
                ddt_object_name(b->spa->spa_ddt[c], DDT_TYPE_DEFAULT, cl, name);
                rb_root_set(b, name, 0, tx);
            }
        }
        if (flat) {
            snprintf(name, sizeof (name), DMU_POOL_DDT_DIR,
                zio_checksum_table[c].ci_name);
            rb_root_set(b, name, t->dir, tx);
            if (!b->flat_mutation || t->old_dir == 0)
                spa_feature_incr(b->spa, SPA_FEATURE_FAST_DEDUP, tx);
        }
    }
    rb_root_set(b, DMU_POOL_DDT_STATS, b->stats, tx);
    b->spa->spa_ddt_stat_object = b->stats;
    rebuild_native_brt_adopt(b->spa, b->replacement_vdevs, b->nvdevs);
    b->replacement_vdevs = NULL;
    for (unsigned c = 0; c < ZIO_CHECKSUM_FUNCTIONS; c++) {
        rb_table_t *t = &b->tables[c];
        if (t->replacement == NULL)
            continue;
        rebuild_native_ddt_adopt(b->spa, c, t->replacement);
        t->replacement = NULL;
    }
    b->spa->spa_dedup_dspace = b->spa->spa_dedup_dsize = UINT64_MAX;
    b->published = B_TRUE;
    rb_publish_release(b);
    return (0);
}

static void
rb_reclaim_range(rb_work_t *w, dmu_tx_t *tx)
{
    w->error = dmu_free_range(w->bridge->os, w->object,
        w->offset, w->length, tx);
}

static void
rb_reclaim_object(rb_work_t *w, dmu_tx_t *tx)
{
    if (w->object != 0)
        w->error = dmu_object_free(w->bridge->os, w->object, tx);
    if (w->error == 0)
        w->error = zap_remove(w->bridge->os, w->bridge->stage, w->key, tx);
}

static int
rb_reclaim(rebuild_bridge_t *b, const char *key, uint64_t object)
{
    rb_work_t w = { .bridge = b, .object = object, .reclaim = B_TRUE };
    strlcpy(w.key, key, sizeof (w.key));
    if (object != 0) {
        dmu_object_info_t info;
        int error = dmu_object_info(b->os, object, &info);
        if (error != 0)
            return (error);
        uint64_t end = info.doi_max_offset;
        while (end != 0) {
            w.offset = P2ALIGN_TYPED(end-1, RB_FREE_SIZE, uint64_t);
            w.length = end-w.offset;
            error = rb_run(&w, rb_reclaim_range, 64);
            if (error != 0)
                return (error);
            end = w.offset;
        }
    }
    return (rb_run(&w, rb_reclaim_object, 8));
}

int
rebuild_bridge_recover(rebuild_bridge_t *b)
{
    if (b == NULL || b->stage == 0)
        return (b == NULL ? EINVAL : 0);
    uint64_t phase;
    int error = rb_get(b, "phase", &phase);
    if (error != 0)
        return (error);
    rb_publish_release(b);
    for (uint64_t id = 0; id < b->nvdevs; id++) {
        rebuild_native_brt_close(b->vdevs[id].native);
        b->vdevs[id].native = NULL;
    }
    if (b->replacement_vdevs != NULL) {
        for (uint64_t id = 0; id < b->nvdevs; id++)
            rebuild_native_brt_close(b->replacement_vdevs[id]);
        kmem_free(b->replacement_vdevs,
            b->nvdevs*sizeof (*b->replacement_vdevs));
        b->replacement_vdevs = NULL;
    }
    for (unsigned c = 0; c < ZIO_CHECKSUM_FUNCTIONS; c++) {
        rb_table_t *t = &b->tables[c];
        rebuild_native_ddt_release(t->replacement);
        t->replacement = NULL;
        if (b->flat_mutation)
            rebuild_native_ddt_release(t->view);
        else
            free(t->view);
        t->view = NULL;
        t->dir = 0;
        memset(t->objects, 0, sizeof (t->objects));
        memset(t->old_objects, 0, sizeof (t->old_objects));
    }
    b->prepared = b->published = B_FALSE;
    for (;;) {
        zap_cursor_t cursor;
        zap_attribute_t *attribute = zap_attribute_alloc();
        zap_cursor_init(&cursor, b->os, b->stage);
        char key[RB_KEY_SIZE] = {0};
        uint64_t object = 0;
        boolean_t free_object = B_FALSE;
        while ((error = zap_cursor_retrieve(&cursor, attribute)) == 0) {
            if (strncmp(attribute->za_name, "bridgex-", 8) != 0 ||
                (attribute->za_name[8] != '1' && attribute->za_name[8] != '2') ||
                attribute->za_name[9] != '-') {
                zap_cursor_advance(&cursor);
                continue;
            }
            unsigned target = attribute->za_name[8]-'0';
            boolean_t published = target == 1 ?
                phase >= REBUILD_BRIDGE_PUBLISHED : phase >= REBUILD_FLAT_PUBLISHED;
            const char *suffix = attribute->za_name+10; /* after bridgex-N- */
            boolean_t old = strncmp(suffix, "old-", 4) == 0;
            boolean_t new = strncmp(suffix, "new-", 4) == 0;
            boolean_t discard = strncmp(suffix, "discard-", 8) == 0;
            boolean_t unused = (attribute->za_first_integer & RB_UNUSED_OBJECT) != 0;
            if (unused && (!new ||
                (attribute->za_first_integer & ~RB_UNUSED_OBJECT) == 0)) {
                error = EINVAL;
                break;
            }
            free_object = discard || (old && published) ||
                (new && (!published || unused));
            object = free_object ?
                attribute->za_first_integer & ~RB_UNUSED_OBJECT : 0;
            strlcpy(key, attribute->za_name, sizeof (key));
            break;
        }
        zap_cursor_fini(&cursor);
        zap_attribute_free(attribute);
        if (key[0] == '\0')
            return (error == ENOENT ? 0 : error);
        error = rb_reclaim(b, key, object);
        if (error != 0)
            return (error);
    }
}

void
rebuild_bridge_close(rebuild_bridge_t *b)
{
    if (b == NULL)
        return;
    rb_publish_release(b);
    if (b->vdevs != NULL) {
        for (uint64_t id = 0; id < b->nvdevs; id++)
            rebuild_native_brt_close(b->vdevs[id].native);
        free(b->vdevs);
    }
    if (b->replacement_vdevs != NULL) {
        for (uint64_t id = 0; id < b->nvdevs; id++)
            rebuild_native_brt_close(b->replacement_vdevs[id]);
        kmem_free(b->replacement_vdevs,
            b->nvdevs*sizeof (*b->replacement_vdevs));
    }
    for (unsigned c = 0; c < ZIO_CHECKSUM_FUNCTIONS; c++) {
        rebuild_native_ddt_release(b->tables[c].replacement);
        if (b->flat_mutation)
            rebuild_native_ddt_release(b->tables[c].view);
        else
            free(b->tables[c].view);
    }
    free(b);
}
