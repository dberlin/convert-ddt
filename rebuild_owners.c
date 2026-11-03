/* SPDX-License-Identifier: CDDL-1.0 */
#include "rebuild_owners.h"
#include "rebuild_phase.h"

#include <sys/spa_impl.h>
#include <sys/dmu_objset.h>
#include <sys/dmu_tx.h>
#include <sys/dsl_pool.h>
#include <sys/dsl_dataset.h>
#include <sys/dsl_dir.h>
#include <sys/dsl_deadlist.h>
#include <sys/dsl_synctask.h>
#include <sys/dmu_traverse.h>
#include <sys/bpobj.h>
#include <sys/bptree.h>
#include <sys/zap.h>
#include <sys/zfeature.h>

/* Each allocation, including BPOBJ subobject arrays, is independently owned
 * by these ZAPs. Recovery frees MOS object data, never the BPs stored in it. */
#define RO_NEW "owners-new"
#define RO_OLD "owners-old"
#define RO_PHASE "owners-phase"
#define RO_READY "owners-ready"
#define RO_PUBLISHED "owners-published"
#define RO_DEFERRED "owners-deferred-original"
#define RO_RESTORED "owners-deferred-restored"
#define RO_EMPTY "owners-empty-refs"
#define RO_EMPTY_DONE "owners-empty-retired"
#define RO_EMPTY_NEW "owners-empty-new-refs"
#define RO_CLEAN "owners-cleanup"
#define RO_CLEAN_END "owners-cleanup-end"
#define RO_DEFERRED_ARRAY "owners-deferred-array"
#define RO_NAME 256

typedef enum ro_kind {
    RO_DEAD, RO_REMAP, RO_LIVE, RO_FREE, RO_OBSOLETE, RO_TREE,
    RO_DELETED_ROOT, RO_DELETED, RO_SYNC, RO_SCALAR
} ro_kind_t;

typedef struct ro_hold {
    dmu_buf_t **buffers;
    int count;
    dedup_fdt_resources_t *resources;
    uint64_t reservation;
} ro_hold_t;

typedef struct ro_link {
    list_node_t node;
    ro_kind_t kind;
    uint64_t parent, owner, oldobj, newobj;
    char key[RO_NAME];
    rebuild_owners_space_t before, after;
    dsl_dataset_t *dataset;
    dsl_dir_t *dir;
    dmu_buf_t *newbonus;
    dmu_object_info_t newinfo;
    ro_hold_t parent_zap;
} ro_link_t;

typedef struct ro_insert {
    list_node_t node;
    uint64_t owner;
    blkptr_t bp;
    boolean_t live, freed;
} ro_insert_t;

struct rebuild_owners {
    spa_t *spa;
    objset_t *os;
    uint64_t stage, newledger, oldledger, phase, emptyrefs, newemptyrefs;
    size_t batch;
    rebuild_owners_transform_f *transform;
    void *arg;
    list_t links, inserts;
    rebuild_owners_role_t role;
    uint64_t deferred_array, checked_txg;
    ro_hold_t stage_zap, pool_zap;
    boolean_t prepared, published, initialized, begun, checked;
    dedup_fdt_resources_t *resources;
    dedup_fdt_file_t insert_file;
    uint64_t insert_count;
    int allocation_error;
};

typedef struct ro_work {
    rebuild_owners_t *o;
    void (*func)(struct ro_work *, dmu_tx_t *);
    int error;
    uint64_t source, object, parent, offset, value;
    dmu_object_info_t info;
    blkptr_t *bps;
    size_t count;
    ro_link_t *link;
    void *data;
    size_t length;
} ro_work_t;

static int
ro_get(rebuild_owners_t *o, const char *key, uint64_t *value)
{
    *value = 0;
    return (zap_lookup(o->os, o->stage, key, sizeof (*value), 1, value));
}

static int
ro_put(rebuild_owners_t *o, const char *key, uint64_t value, dmu_tx_t *tx)
{
    return (zap_update(o->os, o->stage, key, sizeof (value), 1, &value, tx));
}

static int
ro_track(rebuild_owners_t *o, uint64_t ledger, uint64_t object,
    dmu_tx_t *tx)
{
    if (object == 0)
        return (EINVAL);
    char key[20];
    uint64_t record[2] = { object, UINT64_MAX };
    (void) snprintf(key, sizeof (key), "%llx", (u_longlong_t)object);
    return (zap_update(o->os, ledger, key, sizeof (uint64_t), 2,
        record, tx));
}

static void
ro_dispatch(void *arg, dmu_tx_t *tx)
{
    ro_work_t *w = arg;
    w->func(w, tx);
}

static int
ro_run(ro_work_t *w, void (*func)(ro_work_t *, dmu_tx_t *), int space)
{
    if (rebuild_interrupted())
        return (EINTR);
    w->func = func;
    w->error = 0;
    int error = dsl_sync_task(spa_name(w->o->spa), NULL, ro_dispatch,
        w, space, ZFS_SPACE_CHECK_RESERVED);
    return (error != 0 ? error : w->error);
}

static rebuild_owners_role_t
ro_role(ro_kind_t kind)
{
    switch (kind) {
    case RO_REMAP: return (REBUILD_OWNER_REMAP);
    case RO_LIVE:
    case RO_DELETED: return (REBUILD_OWNER_LIVELIST);
    case RO_FREE: return (REBUILD_OWNER_PENDINGFREE);
    case RO_OBSOLETE: return (REBUILD_OWNER_OBSOLETE);
    case RO_TREE: return (REBUILD_OWNER_DESTROYED);
    case RO_SYNC: return (REBUILD_OWNER_DEFERRED);
    default: return (REBUILD_OWNER_DEADLIST);
    }
}

rebuild_owners_role_t
rebuild_owners_role(const rebuild_owners_t *o)
{
    return (o->role);
}

static void *
ro_memory_alloc(rebuild_owners_t *o, size_t bytes)
{
    if (o->resources != NULL) {
        o->allocation_error = dedup_fdt_memory_reserve(o->resources, bytes);
        if (o->allocation_error != 0)
            return (NULL);
    }
    return (kmem_zalloc(bytes, KM_SLEEP));
}

/* Work windows shrink before refusing resources; a full cache is evictable,
 * and a large configured batch must not become a minimum RAM requirement. */
static void *
ro_window_alloc(rebuild_owners_t *o, size_t unit, size_t *bytes)
{
    for (;;) {
        *bytes = o->batch * unit;
        void *data = ro_memory_alloc(o, *bytes);
        if (data != NULL || o->batch == 1)
            return (data);
        o->batch = MAX((size_t)1, o->batch / 2);
    }
}

static void
ro_memory_free(rebuild_owners_t *o, void *data, size_t bytes)
{
    kmem_free(data, bytes);
    if (o->resources != NULL)
        dedup_fdt_memory_release(o->resources, bytes);
}

static ro_link_t *
ro_add(rebuild_owners_t *o, ro_kind_t kind, uint64_t parent,
    uint64_t owner, uint64_t object, const char *key)
{
    ro_link_t *l = ro_memory_alloc(o, sizeof (*l));
    if (l == NULL)
        return (NULL);
    l->kind = kind;
    l->parent = parent;
    l->owner = owner;
    l->oldobj = object;
    if (key != NULL)
        (void) strlcpy(l->key, key, sizeof (l->key));
    list_insert_tail(&o->links, l);
    return (l);
}

static int
ro_optional(rebuild_owners_t *o, ro_kind_t kind, uint64_t parent,
    uint64_t owner, const char *key)
{
    uint64_t object;
    int error = zap_lookup(o->os, parent, key, sizeof (object), 1, &object);
    if (error == ENOENT)
        return (0);
    if (error != 0)
        return (error);
    if (object == 0)
        return (ECKSUM);
    if (ro_add(o, kind, parent, owner, object, key) == NULL)
        return (o->allocation_error);
    return (0);
}

static int
ro_inventory(rebuild_owners_t *o)
{
    uint64_t object = 0;
    int error;
    while ((error = dmu_object_next(o->os, &object, B_FALSE, 0)) == 0) {
        dmu_object_info_t info;
        dmu_buf_t *db;
        if (rebuild_interrupted())
            return (EINTR);
        if ((error = dmu_object_info(o->os, object, &info)) != 0)
            return (error);
        if (info.doi_bonus_type != DMU_OT_DSL_DATASET &&
            info.doi_bonus_type != DMU_OT_DSL_DIR)
            continue;
        if ((error = dmu_bonus_hold(o->os, object, o, &db)) != 0)
            return (error);
        if (info.doi_bonus_type == DMU_OT_DSL_DATASET) {
            dsl_dataset_phys_t *ds = db->db_data;
            if (ds->ds_deadlist_obj != 0)
                (void) ro_add(o, RO_DEAD, object, object,
                    ds->ds_deadlist_obj, NULL);
            dmu_buf_rele(db, o);
            if (o->allocation_error != 0)
                return (o->allocation_error);
            error = info.doi_type == DMU_OTN_ZAP_METADATA ?
                ro_optional(o, RO_REMAP, object, object,
                DS_FIELD_REMAP_DEADLIST) : 0;
        } else {
            uint64_t head = ((dsl_dir_phys_t *)db->db_data)->
                dd_head_dataset_obj;
            dmu_buf_rele(db, o);
            error = info.doi_type == DMU_OTN_ZAP_METADATA ?
                ro_optional(o, RO_LIVE, object, head,
                DD_FIELD_LIVELIST) : 0;
        }
        if (error != 0)
            return (error);
    }
    if (error != ESRCH)
        return (error);
    static const struct {
        ro_kind_t kind;
        const char *key;
    } roots[] = {
        { RO_FREE, DMU_POOL_FREE_BPOBJ },
        { RO_OBSOLETE, DMU_POOL_OBSOLETE_BPOBJ },
        { RO_TREE, DMU_POOL_BPTREE_OBJ },
        { RO_DELETED_ROOT, DMU_POOL_DELETED_CLONES },
        { RO_SYNC, DMU_POOL_SYNC_BPOBJ }
    };
    for (size_t i = 0; i < ARRAY_SIZE(roots); i++) {
        error = ro_optional(o, roots[i].kind, DMU_POOL_DIRECTORY_OBJECT,
            roots[i].kind == RO_TREE ? ZB_DESTROYED_OBJSET : 0,
            roots[i].key);
        if (error != 0)
            return (error);
    }
    for (ro_link_t *l = list_head(&o->links); l != NULL;
        l = list_next(&o->links, l)) {
        if (l->kind != RO_DELETED_ROOT)
            continue;
        zap_cursor_t zc;
        zap_attribute_t *za = zap_attribute_alloc();
        zap_cursor_init(&zc, o->os, l->oldobj);
        while ((error = zap_cursor_retrieve(&zc, za)) == 0) {
            if (za->za_integer_length != sizeof (uint64_t) ||
                za->za_num_integers != 1 || za->za_first_integer == 0) {
                error = ECKSUM;
                break;
            }
            if (ro_add(o, RO_DELETED, l->oldobj, 0,
                za->za_first_integer, za->za_name) == NULL) {
                error = o->allocation_error;
                break;
            }
            zap_cursor_advance(&zc);
        }
        zap_cursor_fini(&zc);
        zap_attribute_free(za);
        if (error != ENOENT)
            return (error);
    }
    return (0);
}

int
rebuild_owners_open_resources(spa_t *spa, uint64_t stage, size_t batch,
    rebuild_owners_transform_f *transform, void *arg,
    dedup_fdt_resources_t *resources, rebuild_owners_t **out)
{
    if (spa == NULL || batch == 0 || transform == NULL ||
        out == NULL || batch > INT_MAX / sizeof (blkptr_t))
        return (EINVAL);
    *out = NULL;
    rebuild_owners_t *o = kmem_zalloc(sizeof (*o), KM_SLEEP);
    o->spa = spa;
    o->os = spa->spa_meta_objset;
    o->stage = stage;
    o->batch = batch;
    o->transform = transform;
    o->arg = arg;
    list_create(&o->links, sizeof (ro_link_t), offsetof(ro_link_t, node));
    list_create(&o->inserts, sizeof (ro_insert_t), offsetof(ro_insert_t, node));
    /* Stage zero inventories live owners for read-only eligibility checks. */
    int error = resources != NULL ?
        rebuild_owners_set_resources(o, resources) : 0;
    if (error == 0 && stage != 0)
        error = ro_get(o, "phase", &o->phase);
    if (error == 0 && stage != 0) {
        int e = ro_get(o, RO_NEW, &o->newledger);
        if (e == 0) {
            o->initialized = B_TRUE;
            error = ro_get(o, RO_OLD, &o->oldledger);
        } else if (e != ENOENT) {
            error = e;
        }
    }
    /* Root publication is atomic. Inventory only its current live hierarchy,
     * never either raw staging ledger's objects. An unpublished recovery also
     * owns the detached original deferred queue until it is restored. */
    if (error == 0)
        error = ro_inventory(o);
    if (error == 0 && o->initialized) {
        uint64_t published, restored;
        error = ro_get(o, RO_PUBLISHED, &published);
        if (error == 0)
            error = ro_get(o, RO_RESTORED, &restored);
        if (error == 0 && !published && !restored)
            error = ro_optional(o, RO_SYNC, o->stage, 0, RO_DEFERRED);
    }
    if (error != 0) {
        rebuild_owners_close(o);
        return (error);
    }
    *out = o;
    return (0);
}

int
rebuild_owners_open(spa_t *spa, uint64_t stage, size_t batch,
    rebuild_owners_transform_f *transform, void *arg, rebuild_owners_t **out)
{
    return (rebuild_owners_open_resources(spa, stage, batch, transform, arg,
        NULL, out));
}

static void
ro_initialize(ro_work_t *w, dmu_tx_t *tx)
{
    rebuild_owners_t *o = w->o;
    uint64_t phase;
    w->error = ro_get(o, "phase", &phase);
    if (w->error != 0)
        return;
    if (phase != o->phase || (phase != REBUILD_INVENTORY &&
        phase != REBUILD_BRIDGE_PREPARED && phase != REBUILD_LEGACY_RETIRED &&
        phase != REBUILD_FLAT_PREPARED)) {
        w->error = EBUSY;
        return;
    }
    o->newledger = zap_create(o->os, DMU_OTN_ZAP_METADATA,
        DMU_OT_NONE, 0, tx);
    o->oldledger = zap_create(o->os, DMU_OTN_ZAP_METADATA,
        DMU_OT_NONE, 0, tx);
    if ((w->error = ro_put(o, RO_NEW, o->newledger, tx)) != 0 ||
        (w->error = ro_put(o, RO_OLD, o->oldledger, tx)) != 0 ||
        (w->error = ro_put(o, RO_PHASE, phase, tx)) != 0 ||
        (w->error = ro_put(o, RO_EMPTY, 0, tx)) != 0 ||
        (w->error = ro_put(o, RO_EMPTY_NEW, 0, tx)) != 0 ||
        (w->error = ro_put(o, RO_READY, 0, tx)) != 0 ||
        (w->error = ro_put(o, RO_PUBLISHED, 0, tx)) != 0 ||
        (w->error = ro_put(o, RO_RESTORED, 0, tx)) != 0 ||
        (w->error = ro_put(o, RO_EMPTY_DONE, 0, tx)) != 0 ||
        (w->error = ro_put(o, RO_CLEAN, 0, tx)) != 0 ||
        (w->error = ro_put(o, RO_CLEAN_END, UINT64_MAX, tx)) != 0)
        return;
    o->initialized = B_TRUE;
    /* The maintenance --wrap=bpobj_iterate gate MUST be active before RW
     * import. Quarantine the preexisting queue, while native syncing keeps
     * accumulating newly generated MOS frees on a separate active queue. */
    for (ro_link_t *l = list_head(&o->links); l != NULL;
        l = list_next(&o->links, l)) {
        if (l->kind != RO_SYNC)
            continue;
        bpobj_t *active = &o->spa->spa_deferred_bpobj;
        if (active->bpo_object != l->oldobj) {
            w->error = EBUSY;
            return;
        }
        uint64_t replacement = bpobj_alloc(o->os, 1 << 14, tx);
        dmu_object_set_compress(o->os, replacement, ZIO_COMPRESS_OFF, tx);
        if ((w->error = ro_put(o, RO_DEFERRED, l->oldobj, tx)) != 0 ||
            (w->error = zap_update(o->os, DMU_POOL_DIRECTORY_OBJECT,
            DMU_POOL_SYNC_BPOBJ, sizeof (replacement), 1,
            &replacement, tx)) != 0)
            return;
        bpobj_close(active);
        w->error = bpobj_open(active, o->os, replacement);
        return;
    }
}

int
rebuild_owners_begin(rebuild_owners_t *o)
{
    if (o == NULL || o->stage == 0 || o->initialized)
        return (EINVAL);
    ro_work_t w = { .o = o };
    int error = ro_run(&w, ro_initialize, 8);
    if (error == 0)
        o->begun = B_TRUE;
    return (error);
}

static void
ro_alloc(ro_work_t *w, dmu_tx_t *tx)
{
    rebuild_owners_t *o = w->o;
    if (w->info.doi_type == DMU_OT_BPOBJ)
        w->object = bpobj_alloc(o->os, w->info.doi_data_block_size, tx);
    else if (w->info.doi_type == DMU_OT_DEADLIST)
        w->object = dsl_deadlist_alloc(o->os, tx);
    else if (w->link != NULL && w->link->kind == RO_TREE)
        w->object = bptree_alloc(o->os, tx);
    else
        w->object = zap_create(o->os, DMU_OTN_ZAP_METADATA,
            DMU_OT_NONE, 0, tx);
    w->error = ro_track(o, o->newledger, w->object, tx);
    if (w->error == 0 && w->source != 0 &&
        w->source != spa_get_dsl(o->spa)->dp_empty_bpobj)
        w->error = ro_track(o, o->oldledger, w->source, tx);
}

static int ro_dead_enqueue(rebuild_owners_t *, dsl_deadlist_t *,
    const blkptr_t *, boolean_t, dmu_tx_t *);

static void
ro_enqueue(ro_work_t *w, dmu_tx_t *tx)
{
    if (w->parent != 0) {
        dsl_deadlist_t dl = { 0 };
        w->error = dsl_deadlist_open(&dl, w->o->os, w->object);
        if (w->error != 0)
            return;
        for (size_t i = 0; i < w->count; i++) {
            w->error = ro_dead_enqueue(w->o, &dl, &w->bps[i],
                BP_GET_FREE(&w->bps[i]), tx);
            if (w->error != 0)
                break;
        }
        dsl_deadlist_close(&dl);
        return;
    }
    bpobj_t bpo = { 0 };
    w->error = bpobj_open(&bpo, w->o->os, w->object);
    if (w->error != 0)
        return;
    for (size_t i = 0; i < w->count; i++) {
        boolean_t freed = BP_GET_FREE(&w->bps[i]);
        if (freed && !bpo.bpo_havefreed) {
            w->error = ENOTSUP;
            break;
        }
        bpobj_enqueue(&bpo, &w->bps[i], freed, tx);
    }
    bpobj_close(&bpo);
}

/* Preserve the original subobject topology/order instead of allowing native
 * bpobj_enqueue_subobj's coalescing to retire objects underneath the durable
 * ledger. Direct records and their FREE counters are written by native
 * bpobj_enqueue; these are precisely the non-coalescing native link steps. */
static void
ro_attach(ro_work_t *w, dmu_tx_t *tx)
{
    rebuild_owners_t *o = w->o;
    bpobj_t parent = { 0 }, child = { 0 };
    if ((w->error = bpobj_open(&parent, o->os, w->parent)) != 0)
        return;
    if ((w->error = bpobj_open(&child, o->os, w->object)) != 0)
        goto out;
    if (!parent.bpo_havesubobj || !parent.bpo_havecomp) {
        w->error = ENOTSUP;
        goto out;
    }
    uint64_t used, comp, uncomp;
    if ((w->error = bpobj_space(&child, &used, &comp, &uncomp)) != 0)
        goto out;
    dmu_buf_will_dirty(parent.bpo_dbuf, tx);
    if (parent.bpo_phys->bpo_subobjs == 0) {
        parent.bpo_phys->bpo_subobjs = dmu_object_alloc(o->os,
            DMU_OT_BPOBJ_SUBOBJ, SPA_OLD_MAXBLOCKSIZE, DMU_OT_NONE, 0, tx);
        w->error = ro_track(o, o->newledger,
            parent.bpo_phys->bpo_subobjs, tx);
        if (w->error != 0)
            goto out;
    }
    dmu_write(o->os, parent.bpo_phys->bpo_subobjs,
        parent.bpo_phys->bpo_num_subobjs * sizeof (uint64_t),
        sizeof (w->object), &w->object, tx, DMU_READ_NO_PREFETCH);
    parent.bpo_phys->bpo_num_subobjs++;
    parent.bpo_phys->bpo_bytes += used;
    parent.bpo_phys->bpo_comp += comp;
    parent.bpo_phys->bpo_uncomp += uncomp;
out:
    bpobj_close(&child);
    bpobj_close(&parent);
}

typedef struct ro_frame {
    list_node_t node;
    uint64_t oldobj, newobj, subarray, nsub, next;
} ro_frame_t;

static int
ro_copy_direct(rebuild_owners_t *o, ro_link_t *l, uint64_t source,
    uint64_t destination, uint64_t *subarray, uint64_t *nsub,
    boolean_t routed)
{
    bpobj_t original = { 0 };
    int error = bpobj_open(&original, o->os, source);
    if (error != 0)
        return (error);
    uint64_t count = original.bpo_phys->bpo_num_blkptrs;
    *subarray = original.bpo_havesubobj ?
        original.bpo_phys->bpo_subobjs : 0;
    *nsub = original.bpo_havesubobj ?
        original.bpo_phys->bpo_num_subobjs : 0;
    bpobj_close(&original);
    if (count == 0)
        return (0);
    size_t bytes;
    blkptr_t *bps = ro_window_alloc(o, sizeof (*bps), &bytes);
    if (bps == NULL)
        return (o->allocation_error);
    for (uint64_t offset = 0; offset < count; ) {
        size_t n = MIN(o->batch, count - offset);
        if (rebuild_interrupted()) {
            error = EINTR;
            break;
        }
        error = dmu_read(o->os, source, offset * sizeof (*bps),
            n * sizeof (*bps), bps, DMU_READ_NO_PREFETCH);
        if (error != 0)
            break;
        for (size_t i = 0; i < n; i++) {
            blkptr_t next;
            boolean_t freed = BP_GET_FREE(&bps[i]);
            o->role = ro_role(l->kind);
            error = o->transform(o->arg, l->owner, &bps[i], &next);
            if (error != 0)
                break;
            if (BP_IS_HOLE(&next) || BP_IS_REDACTED(&next)) {
                error = EINVAL;
                break;
            }
            BP_SET_FREE(&next, freed);
            bps[i] = next;
        }
        if (error != 0)
            break;
        ro_work_t w = { .o = o, .object = destination,
            .bps = bps, .count = n, .parent = routed ? destination : 0 };
        error = ro_run(&w, ro_enqueue,
            2 + (n * sizeof (*bps) >> SPA_MINBLOCKSHIFT));
        if (error != 0)
            break;
        offset += n;
    }
    ro_memory_free(o, bps, bytes);
    return (error);
}

static void
ro_record_old(ro_work_t *w, dmu_tx_t *tx)
{
    if (w->source != spa_get_dsl(w->o->spa)->dp_empty_bpobj)
        w->error = ro_track(w->o, w->o->oldledger, w->source, tx);
}

static int
ro_clone_bpobj(rebuild_owners_t *o, ro_link_t *l, uint64_t source,
    uint64_t *destination, boolean_t routed)
{
    list_t stack;
    list_create(&stack, sizeof (ro_frame_t), offsetof(ro_frame_t, node));
    ro_frame_t *root = ro_memory_alloc(o, sizeof (*root));
    if (root == NULL) {
        list_destroy(&stack);
        return (o->allocation_error);
    }
    root->oldobj = source;
    list_insert_head(&stack, root);
    int error = 0;
    while (!list_is_empty(&stack)) {
        ro_frame_t *f = list_head(&stack);
        if (f->newobj == 0) {
            ro_work_t w = { .o = o, .source = f->oldobj };
            if ((error = dmu_object_info(o->os, f->oldobj,
                &w.info)) != 0)
                break;
            if (w.info.doi_type != DMU_OT_BPOBJ) {
                error = ECKSUM;
                break;
            }
            if (routed) {
                error = ro_run(&w, ro_record_old, 1);
                f->newobj = *destination;
            } else {
                error = ro_run(&w, ro_alloc, 4);
                f->newobj = w.object;
            }
            if (error != 0)
                break;
            if (routed) {
                bpobj_t original = { 0 };
                error = bpobj_open(&original, o->os, f->oldobj);
                if (error != 0)
                    break;
                f->subarray = original.bpo_havesubobj ?
                    original.bpo_phys->bpo_subobjs : 0;
                f->nsub = original.bpo_havesubobj ?
                    original.bpo_phys->bpo_num_subobjs : 0;
                bpobj_close(&original);
            } else if ((error = ro_copy_direct(o, l, f->oldobj,
                f->newobj, &f->subarray, &f->nsub, B_FALSE)) != 0) {
                break;
            }
            if (f->subarray != 0) {
                w.source = f->subarray;
                if ((error = ro_run(&w, ro_record_old, 1)) != 0)
                    break;
            } else if (f->nsub != 0) {
                error = ECKSUM;
                break;
            }
        }
        if (f->next < f->nsub) {
            uint64_t child;
            error = dmu_read(o->os, f->subarray,
                f->next * sizeof (child), sizeof (child), &child,
                DMU_READ_NO_PREFETCH);
            if (error != 0)
                break;
            /* A malformed graph must not turn into an infinite walk. */
            for (ro_frame_t *p = list_head(&stack); p != NULL;
                p = list_next(&stack, p)) {
                if (p->oldobj == child) {
                    error = ECKSUM;
                    break;
                }
            }
            if (error != 0)
                break;
            f->next++;
            ro_frame_t *c = ro_memory_alloc(o, sizeof (*c));
            if (c == NULL) {
                error = o->allocation_error;
                break;
            }
            c->oldobj = child;
            list_insert_head(&stack, c);
            continue;
        }
        /* Reverse of native's backwards direct-then-subobjects walk:
         * ascending subobjects first, then ascending direct records. */
        if (routed && (error = ro_copy_direct(o, l, f->oldobj,
            f->newobj, &f->subarray, &f->nsub, B_TRUE)) != 0)
            break;
        (void) list_remove_head(&stack);
        ro_frame_t *parent = list_head(&stack);
        if (parent == NULL)
            *destination = f->newobj;
        else if (!routed) {
            ro_work_t w = { .o = o, .parent = parent->newobj,
                .object = f->newobj };
            error = ro_run(&w, ro_attach, 4);
        }
        ro_memory_free(o, f, sizeof (*f));
        if (error != 0)
            break;
    }
    ro_frame_t *f;
    while ((f = list_remove_head(&stack)) != NULL)
        ro_memory_free(o, f, sizeof (*f));
    list_destroy(&stack);
    return (error);
}

static void
ro_key(ro_work_t *w, dmu_tx_t *tx)
{
    rebuild_owners_t *o = w->o;
    dsl_deadlist_t dl = { 0 };
    w->error = dsl_deadlist_open(&dl, o->os, w->object);
    if (w->error != 0)
        return;
    dsl_deadlist_add_key(&dl, w->value, tx);
    dsl_deadlist_entry_t find = { .dle_mintxg = w->value };
    dsl_deadlist_entry_t *entry = avl_find(&dl.dl_tree, &find, NULL);
    uint64_t empty = spa_get_dsl(o->spa)->dp_empty_bpobj;
    if (entry->dle_bpobj.bpo_object == empty) {
        o->newemptyrefs++;
        w->error = ro_put(o, RO_EMPTY_NEW, o->newemptyrefs, tx);
    } else {
        w->error = ro_track(o, o->newledger,
            entry->dle_bpobj.bpo_object, tx);
    }
    if (w->error == 0 && w->source == empty) {
        o->emptyrefs++;
        w->error = ro_put(o, RO_EMPTY, o->emptyrefs, tx);
    }
    dsl_deadlist_close(&dl);
}

static int
ro_dead_space(rebuild_owners_t *o, uint64_t object,
    uint64_t min, uint64_t max, rebuild_owners_space_t *space)
{
    dsl_deadlist_t dl = { 0 };
    int error = dsl_deadlist_open(&dl, o->os, object);
    if (error != 0)
        return (error);
    dsl_deadlist_space_range(&dl, min, max, &space->used,
        &space->compressed, &space->uncompressed);
    dsl_deadlist_close(&dl);
    return (0);
}

static int
ro_clone_deadlist(rebuild_owners_t *o, ro_link_t *l)
{
    dmu_object_info_t info;
    int error = dmu_object_info(o->os, l->oldobj, &info);
    if (error != 0)
        return (error);
    if ((error = ro_dead_space(o, l->oldobj, 0, UINT64_MAX,
        &l->before)) != 0)
        return (error);
    if (info.doi_type == DMU_OT_BPOBJ) {
        error = ro_clone_bpobj(o, l, l->oldobj, &l->newobj, B_FALSE);
    } else if (info.doi_type == DMU_OT_DEADLIST) {
        ro_work_t w = { .o = o, .source = l->oldobj, .info = info };
        if ((error = ro_run(&w, ro_alloc, 4)) != 0)
            return (error);
        l->newobj = w.object;
        zap_cursor_t zc;
        zap_attribute_t *za = zap_attribute_alloc();
        zap_cursor_init(&zc, o->os, l->oldobj);
        while ((error = zap_cursor_retrieve(&zc, za)) == 0) {
            w.object = l->newobj;
            if (za->za_integer_length != sizeof (uint64_t) ||
                za->za_num_integers != 1) {
                error = ECKSUM;
                break;
            }
            w.source = za->za_first_integer;
            w.value = zfs_strtonum(za->za_name, NULL);
            if ((error = ro_run(&w, ro_key, 4)) != 0)
                break;
            zap_cursor_advance(&zc);
        }
        zap_cursor_fini(&zc);
        /* za is reused for the record-routing pass below. */
        if (error == ENOENT)
            error = 0;
        if (error == 0) {
            /* All original keys must exist BEFORE routing transformed BPs.
             * Native insertion selects the correct birth bucket, including
             * contextual promotions across a snapshot/bookmark boundary. */
            zap_cursor_init(&zc, o->os, l->oldobj);
            while ((error = zap_cursor_retrieve(&zc, za)) == 0) {
                uint64_t destination = l->newobj;
                error = ro_clone_bpobj(o, l, za->za_first_integer,
                    &destination, B_TRUE);
                if (error != 0)
                    break;
                zap_cursor_advance(&zc);
            }
            zap_cursor_fini(&zc);
            if (error == ENOENT)
                error = 0;
        }
        zap_attribute_free(za);
    } else {
        return (ECKSUM);
    }
    if (error != 0)
        return (error);
    return (ro_dead_space(o, l->newobj, 0, UINT64_MAX, &l->after));
}

static int
ro_bpo_space(rebuild_owners_t *o, uint64_t object,
    rebuild_owners_space_t *space)
{
    bpobj_t bpo = { 0 };
    int error = bpobj_open(&bpo, o->os, object);
    if (error != 0)
        return (error);
    error = bpobj_space(&bpo, &space->used, &space->compressed,
        &space->uncompressed);
    bpobj_close(&bpo);
    return (error);
}

int
rebuild_owners_foreach_destroyed_root(rebuild_owners_t *o,
    rebuild_owners_destroyed_f *func, void *arg)
{
    if (o == NULL || func == NULL)
        return (EINVAL);
    for (ro_link_t *l = list_head(&o->links); l != NULL;
        l = list_next(&o->links, l)) {
        if (l->kind != RO_TREE)
            continue;
        dmu_buf_t *db;
        int error = dmu_bonus_hold(o->os, l->oldobj, o, &db);
        if (error != 0)
            return (error);
        bptree_phys_t phys = *(bptree_phys_t *)db->db_data;
        dmu_buf_rele(db, o);
        for (uint64_t i = phys.bt_begin; i < phys.bt_end; i++) {
            bptree_entry_phys_t entry;
            if (rebuild_interrupted())
                return (EINTR);
            error = dmu_read(o->os, l->oldobj, i * sizeof (entry),
                sizeof (entry), &entry, DMU_READ_NO_PREFETCH);
            if (error == 0)
                error = func(arg, &entry.be_bp, entry.be_birth_txg,
                    &entry.be_zb);
            if (error != 0)
                return (error);
        }
    }
    return (0);
}

typedef struct ro_visit {
    rebuild_owners_t *o;
    ro_link_t *link;
    rebuild_owners_visit_f *func;
    void *arg;
    int error;
} ro_visit_t;

static int
ro_visit_bp(void *arg, const blkptr_t *bp, boolean_t freed, dmu_tx_t *tx)
{
    (void) tx;
    ro_visit_t *v = arg;
    if (rebuild_interrupted())
        return (EINTR);
    v->o->role = ro_role(v->link->kind);
    return (v->func(v->arg, v->link->owner, v->o->role, bp, freed));
}

static int
ro_visit_bucket(void *arg, dsl_deadlist_entry_t *entry)
{
    ro_visit_t *v = arg;
    v->error = bpobj_iterate_nofree(&entry->dle_bpobj, ro_visit_bp, v, NULL);
    return (v->error);
}

static int
ro_visit_tree(void *arg, const blkptr_t *bp, dmu_tx_t *tx)
{
    return (ro_visit_bp(arg, bp, B_FALSE, tx));
}

static int
ro_foreach(rebuild_owners_t *o, boolean_t prepared,
    rebuild_owners_visit_f *func, void *arg)
{
    if (o == NULL || func == NULL || (prepared && (!o->prepared || o->published)))
        return (EINVAL);
    ro_visit_t v = { .o = o, .func = func, .arg = arg };
    for (ro_link_t *l = list_head(&o->links); l != NULL;
        l = list_next(&o->links, l)) {
        if (l->kind == RO_DELETED_ROOT || l->kind == RO_SCALAR)
            continue;
        uint64_t object = prepared ? l->newobj : l->oldobj;
        if (prepared && object == 0)
            continue;
        v.link = l;
        v.error = 0;
        if (l->kind == RO_TREE) {
            v.error = bptree_iterate(o->os, object, B_FALSE,
                ro_visit_tree, &v, NULL);
        } else if (l->kind == RO_FREE || l->kind == RO_OBSOLETE ||
            l->kind == RO_SYNC) {
            bpobj_t bpo = { 0 };
            v.error = bpobj_open(&bpo, o->os, object);
            if (v.error == 0) {
                v.error = bpobj_iterate_nofree(&bpo, ro_visit_bp, &v, NULL);
                bpobj_close(&bpo);
            }
        } else {
            dsl_deadlist_t dl = { 0 };
            v.error = dsl_deadlist_open(&dl, o->os, object);
            if (v.error == 0) {
                if (dl.dl_oldfmt)
                    v.error = bpobj_iterate_nofree(&dl.dl_bpobj,
                        ro_visit_bp, &v, NULL);
                else
                    dsl_deadlist_iterate(&dl, ro_visit_bucket, &v);
                dsl_deadlist_close(&dl);
            }
        }
        if (v.error != 0)
            return (v.error);
    }
    return (0);
}

int
rebuild_owners_foreach_source(rebuild_owners_t *o,
    rebuild_owners_visit_f *func, void *arg)
{
    return (ro_foreach(o, B_FALSE, func, arg));
}

int
rebuild_owners_foreach_prepared(rebuild_owners_t *o,
    rebuild_owners_visit_f *func, void *arg)
{
    return (ro_foreach(o, B_TRUE, func, arg));
}

typedef struct ro_tree_delta {
    rebuild_owners_t *o;
    int64_t used, comp, uncomp;
} ro_tree_delta_t;

static int
ro_tree_delta(void *arg, const blkptr_t *bp, dmu_tx_t *tx)
{
    (void) tx;
    ro_tree_delta_t *d = arg;
    blkptr_t next;
    d->o->role = REBUILD_OWNER_DESTROYED;
    int error = d->o->transform(d->o->arg, ZB_DESTROYED_OBJSET, bp, &next);
    if (error != 0)
        return (error);
    if (BP_IS_HOLE(&next) || BP_IS_REDACTED(&next))
        return (EINVAL);
    d->used += (int64_t)bp_get_dsize(d->o->spa, &next) -
        (int64_t)bp_get_dsize(d->o->spa, bp);
    d->comp += (int64_t)BP_GET_PSIZE(&next) - (int64_t)BP_GET_PSIZE(bp);
    d->uncomp += (int64_t)BP_GET_UCSIZE(&next) - (int64_t)BP_GET_UCSIZE(bp);
    return (rebuild_interrupted() ? EINTR : 0);
}

static void
ro_write(ro_work_t *w, dmu_tx_t *tx)
{
    dmu_write(w->o->os, w->object, w->offset, w->length, w->data, tx,
        DMU_READ_NO_PREFETCH);
}

static void
ro_bonus(ro_work_t *w, dmu_tx_t *tx)
{
    dmu_buf_t *db;
    w->error = dmu_bonus_hold(w->o->os, w->object, w->o, &db);
    if (w->error != 0)
        return;
    dmu_buf_will_dirty(db, tx);
    memcpy(db->db_data, w->data, w->length);
    dmu_buf_rele(db, w->o);
}

static int
ro_clone_tree(rebuild_owners_t *o, ro_link_t *l)
{
    dmu_buf_t *db;
    int error = dmu_bonus_hold(o->os, l->oldobj, o, &db);
    if (error != 0)
        return (error);
    bptree_phys_t phys = *(bptree_phys_t *)db->db_data;
    dmu_buf_rele(db, o);
    if (phys.bt_begin > phys.bt_end)
        return (ECKSUM);
    l->before = (rebuild_owners_space_t){ phys.bt_bytes,
        phys.bt_comp, phys.bt_uncomp };
    ro_tree_delta_t delta = { .o = o };
    /* Native nofree traversal honors every entry's minimum birth and resume
     * bookmark, and therefore NEVER reads/frees the already-freed prefix. */
    error = bptree_iterate(o->os, l->oldobj, B_FALSE, ro_tree_delta,
        &delta, NULL);
    if (error != 0)
        return (error);
    phys.bt_bytes += delta.used;
    phys.bt_comp += delta.comp;
    phys.bt_uncomp += delta.uncomp;
    l->after = (rebuild_owners_space_t){ phys.bt_bytes,
        phys.bt_comp, phys.bt_uncomp };
    ro_work_t w = { .o = o, .source = l->oldobj, .link = l };
    if ((error = ro_run(&w, ro_alloc, 4)) != 0)
        return (error);
    l->newobj = w.object;
    size_t bytes;
    bptree_entry_phys_t *entries = ro_window_alloc(o, sizeof (*entries), &bytes);
    if (entries == NULL)
        return (o->allocation_error);
    for (uint64_t i = phys.bt_begin; i < phys.bt_end; ) {
        size_t count = MIN(o->batch, phys.bt_end - i);
        error = dmu_read(o->os, l->oldobj, i * sizeof (*entries),
            count * sizeof (*entries), entries, DMU_READ_NO_PREFETCH);
        if (error != 0)
            break;
        for (size_t j = 0; j < count; j++) {
            blkptr_t next;
            o->role = REBUILD_OWNER_DESTROYED;
            error = o->transform(o->arg, ZB_DESTROYED_OBJSET,
                &entries[j].be_bp, &next);
            if (error != 0)
                break;
            entries[j].be_bp = next;
        }
        if (error != 0)
            break;
        w.offset = i * sizeof (*entries);
        w.length = count * sizeof (*entries);
        w.data = entries;
        error = ro_run(&w, ro_write,
            2 + (w.length >> SPA_MINBLOCKSHIFT));
        if (error != 0)
            break;
        i += count;
    }
    ro_memory_free(o, entries, bytes);
    if (error != 0)
        return (error);
    /* Keep absolute begin/end indexes and unmodified resume bookmarks. */
    w.data = &phys;
    w.length = sizeof (phys);
    return (ro_run(&w, ro_bonus, 1));
}
int
rebuild_owners_set_resources(rebuild_owners_t *o,
    dedup_fdt_resources_t *resources)
{
    if (o == NULL || resources == NULL || !list_is_empty(&o->inserts))
        return (EINVAL);
    if (o->resources != NULL)
        return (o->resources == resources ? 0 : EINVAL);
    uint64_t bytes = 0;
    for (ro_link_t *l = list_head(&o->links); l != NULL;
        l = list_next(&o->links, l)) {
        if (bytes > UINT64_MAX - sizeof (*l))
            return (EOVERFLOW);
        bytes += sizeof (*l);
    }
    int error = dedup_fdt_memory_reserve(resources, bytes);
    if (error != 0)
        return (error);
    o->insert_file.fd = -1;
    error = dedup_fdt_file_create(resources, -1, "history-inserts",
        &o->insert_file);
    if (error == 0)
        o->resources = resources;
    else
        dedup_fdt_memory_release(resources, bytes);
    return (error);
}


static int
ro_insert(rebuild_owners_t *o, uint64_t owner, const blkptr_t *bp,
    boolean_t live, boolean_t freed)
{
    if (o == NULL || bp == NULL || (o->initialized && !o->begun) ||
        o->prepared || BP_IS_HOLE(bp) || BP_IS_REDACTED(bp))
        return (EINVAL);
    boolean_t found = B_FALSE;
    for (ro_link_t *l = list_head(&o->links); l != NULL;
        l = list_next(&o->links, l)) {
        if (l->owner == owner && l->kind == (live ? RO_LIVE : RO_DEAD)) {
            found = B_TRUE;
            break;
        }
    }
    if (!found)
        return (ENOENT);
    if (o->resources != NULL) {
        ro_insert_t item = { .owner = owner, .bp = *bp,
            .live = live, .freed = freed };
        if (o->insert_count >= UINT64_MAX / sizeof (item))
            return (EOVERFLOW);
        uint64_t offset = o->insert_count * sizeof (item);
        int error = dedup_fdt_file_resize(&o->insert_file,
            offset + sizeof (item));
        if (error == 0)
            error = dedup_fdt_file_pwrite(&o->insert_file, &item,
                sizeof (item), offset);
        if (error == 0)
            o->insert_count++;
        return (error);
    }
    ro_insert_t *i = kmem_zalloc(sizeof (*i), KM_SLEEP);
    i->owner = owner;
    i->bp = *bp;
    i->live = live;
    i->freed = freed;
    list_insert_tail(&o->inserts, i);
    return (0);
}

int
rebuild_owners_insert_dead(rebuild_owners_t *o, uint64_t owner,
    const blkptr_t *bp)
{
    return (ro_insert(o, owner, bp, B_FALSE, B_FALSE));
}

int
rebuild_owners_insert_livelist(rebuild_owners_t *o, uint64_t owner,
    const blkptr_t *bp, boolean_t freed)
{
    return (ro_insert(o, owner, bp, B_TRUE, freed));
}

static int
ro_dead_enqueue(rebuild_owners_t *o, dsl_deadlist_t *dl,
    const blkptr_t *bp, boolean_t freed, dmu_tx_t *tx)
{
    boolean_t added = B_FALSE, wasempty = B_FALSE;
    dsl_deadlist_entry_t *target = NULL;
    if (!dl->dl_oldfmt) {
        dsl_deadlist_entry_t *first = dsl_deadlist_first(dl);
        uint64_t birth = BP_GET_BIRTH(bp);
        if (birth == 0)
            return (EINVAL);
        if (first == NULL || first->dle_mintxg >= birth) {
            dsl_deadlist_add_key(dl, birth - 1, tx);
            added = B_TRUE;
        }
        dsl_deadlist_entry_t find = { .dle_mintxg = birth };
        avl_index_t where;
        target = avl_find(&dl->dl_tree, &find, &where);
        target = target == NULL ?
            avl_nearest(&dl->dl_tree, where, AVL_BEFORE) :
            AVL_PREV(&dl->dl_tree, target);
        wasempty = target->dle_bpobj.bpo_object ==
            spa_get_dsl(o->spa)->dp_empty_bpobj;
    }
    dsl_deadlist_insert(dl, bp, freed, tx);
    if (added || wasempty) {
        int error = ro_track(o, o->newledger,
            target->dle_bpobj.bpo_object, tx);
        if (error != 0)
            return (error);
        if (!added && wasempty) {
            o->newemptyrefs--;
            return (ro_put(o, RO_EMPTY_NEW, o->newemptyrefs, tx));
        }
    }
    return (0);
}

static void
ro_insert_sync(ro_work_t *w, dmu_tx_t *tx)
{
    ro_insert_t *i = w->data;
    dsl_deadlist_t dl = { 0 };
    w->error = dsl_deadlist_open(&dl, w->o->os, w->object);
    if (w->error != 0)
        return;
    w->error = ro_dead_enqueue(w->o, &dl, &i->bp, i->freed, tx);
    dsl_deadlist_close(&dl);
}

static void
ro_deleted_add(ro_work_t *w, dmu_tx_t *tx)
{
    w->error = zap_add_int(w->o->os, w->parent, w->object, tx);
}

static void
ro_prepare_deferred_array(ro_work_t *w, dmu_tx_t *tx)
{
    rebuild_owners_t *o = w->o;
    o->deferred_array = dmu_object_alloc(o->os, DMU_OT_BPOBJ_SUBOBJ,
        SPA_OLD_MAXBLOCKSIZE, DMU_OT_NONE, 0, tx);
    w->error = ro_track(o, o->newledger, o->deferred_array, tx);
    if (w->error != 0)
        return;
    dmu_write(o->os, o->deferred_array, 0, sizeof (w->object),
        &w->object, tx, DMU_READ_NO_PREFETCH);
    w->error = ro_put(o, RO_DEFERRED_ARRAY, o->deferred_array, tx);
}

static void
ro_ready(ro_work_t *w, dmu_tx_t *tx)
{
    w->error = ro_put(w->o, RO_READY, 1, tx);
}

int
rebuild_owners_prepare(rebuild_owners_t *o)
{
    if (o == NULL || o->prepared || (o->initialized && !o->begun))
        return (EINVAL);
    ro_work_t w = { .o = o };
    int error = o->begun ? 0 : rebuild_owners_begin(o);
    if (error != 0)
        return (error);
    ro_link_t *deleted = NULL;
    for (ro_link_t *l = list_head(&o->links); l != NULL;
        l = list_next(&o->links, l)) {
        if (l->kind == RO_DELETED_ROOT) {
            w.source = l->oldobj;
            memset(&w.info, 0, sizeof (w.info));
            w.link = l;
            if ((error = ro_run(&w, ro_alloc, 4)) != 0)
                return (error);
            l->newobj = w.object;
            deleted = l;
        } else if (l->kind == RO_TREE) {
            error = ro_clone_tree(o, l);
        } else if (l->kind == RO_FREE || l->kind == RO_OBSOLETE ||
            l->kind == RO_SYNC) {
            error = ro_bpo_space(o, l->oldobj, &l->before);
            if (error == 0)
                error = ro_clone_bpobj(o, l, l->oldobj, &l->newobj, B_FALSE);
            if (error == 0)
                error = ro_bpo_space(o, l->newobj, &l->after);
        } else {
            error = ro_clone_deadlist(o, l);
            if (error == 0 && l->kind == RO_DELETED) {
                if (deleted == NULL)
                    return (ECKSUM);
                w.parent = deleted->newobj;
                w.object = l->newobj;
                error = ro_run(&w, ro_deleted_add, 2);
            }
        }
        if (error != 0)
            return (error);
    }
    ro_insert_t *queued = list_head(&o->inserts);
    for (uint64_t row = 0; o->resources != NULL ?
        row < o->insert_count : queued != NULL; row++) {
        ro_insert_t item, *i = queued;
        if (o->resources != NULL) {
            error = dedup_fdt_file_pread(&o->insert_file, &item,
                sizeof (item), row * sizeof (item));
            if (error != 0)
                return (error);
            i = &item;
        } else {
            queued = list_next(&o->inserts, queued);
        }
        for (ro_link_t *l = list_head(&o->links); l != NULL;
            l = list_next(&o->links, l)) {
            if (l->owner != i->owner ||
                l->kind != (i->live ? RO_LIVE : RO_DEAD))
                continue;
            w.object = l->newobj;
            w.data = i;
            if ((error = ro_run(&w, ro_insert_sync, 4)) != 0)
                return (error);
            if ((error = ro_dead_space(o, l->newobj, 0, UINT64_MAX,
                &l->after)) != 0)
                return (error);
            break;
        }
    }
    if (o->resources != NULL) {
        dedup_fdt_file_close(&o->insert_file);
        o->insert_count = 0;
    }
    for (ro_link_t *l = list_head(&o->links); l != NULL;
        l = list_next(&o->links, l)) {
        if (l->kind != RO_SYNC)
            continue;
        w.object = l->newobj;
        if ((error = ro_run(&w, ro_prepare_deferred_array, 4)) != 0)
            return (error);
    }
    if ((error = ro_run(&w, ro_ready, 1)) == 0)
        o->prepared = B_TRUE;
    return (error);
}

int
rebuild_owners_range(rebuild_owners_t *o, uint64_t owner,
    boolean_t remap, uint64_t min, uint64_t max,
    rebuild_owners_space_t *before, rebuild_owners_space_t *after)
{
    if (o == NULL || !o->prepared || before == NULL || after == NULL ||
        min > max)
        return (EINVAL);
    for (ro_link_t *l = list_head(&o->links); l != NULL;
        l = list_next(&o->links, l)) {
        if (l->owner != owner || l->kind != (remap ? RO_REMAP : RO_DEAD))
            continue;
        int error = ro_dead_space(o, l->oldobj, min, max, before);
        if (error == 0)
            error = ro_dead_space(o, l->newobj, min, max, after);
        return (error);
    }
    if (!remap) {
        dmu_buf_t *db;
        int error = dmu_bonus_hold(o->os, owner, o, &db);
        if (error != 0)
            return (error);
        uint64_t object = ((dsl_dataset_phys_t *)db->db_data)->ds_deadlist_obj;
        dmu_buf_rele(db, o);
        if (object == 0) {
            *before = (rebuild_owners_space_t){ 0 };
            *after = (rebuild_owners_space_t){ 0 };
            return (0);
        }
    }
    return (ENOENT);
}

int
rebuild_owners_snapshot_unique(rebuild_owners_t *o, uint64_t owner,
    uint64_t *before, uint64_t *after)
{
    if (o == NULL || before == NULL || after == NULL)
        return (EINVAL);
    dmu_buf_t *db;
    int error = dmu_bonus_hold(o->os, owner, o, &db);
    if (error != 0)
        return (error);
    dsl_dataset_phys_t phys = *(dsl_dataset_phys_t *)db->db_data;
    dmu_buf_rele(db, o);
    if (phys.ds_next_snap_obj == 0) {
        if (BP_IS_HOLE(&phys.ds_bp) && phys.ds_referenced_bytes == 0 &&
            phys.ds_unique_bytes == 0) {
            *before = *after = 0;
            return (0);
        }
        return (EINVAL);
    }
    rebuild_owners_space_t oldspace, newspace;
    error = rebuild_owners_range(o, phys.ds_next_snap_obj, B_FALSE,
        phys.ds_prev_snap_txg, UINT64_MAX, &oldspace, &newspace);
    if (error == 0) {
        *before = oldspace.used;
        *after = newspace.used;
    }
    return (error);
}

static int
ro_check_link(rebuild_owners_t *o, ro_link_t *l)
{
    uint64_t current;
    int error;
    if (l->kind == RO_SYNC) {
        error = ro_get(o, RO_DEFERRED, &current);
    } else if (l->kind == RO_DEAD) {
        dmu_buf_t *db;
        error = dmu_bonus_hold(o->os, l->parent, o, &db);
        if (error != 0)
            return (error);
        current = ((dsl_dataset_phys_t *)db->db_data)->ds_deadlist_obj;
        dmu_buf_rele(db, o);
    } else {
        error = zap_lookup(o->os, l->parent, l->key,
            sizeof (current), 1, &current);
    }
    if (error != 0)
        return (error);
    if (current != l->oldobj)
        return (EBUSY);
    return (l->kind != RO_SCALAR && l->newobj == 0 ? EINVAL : 0);
}

static void
ro_release_hold(ro_hold_t *hold, const void *tag)
{
    if (hold->buffers != NULL)
        dmu_buf_rele_array(hold->buffers, hold->count, tag);
    hold->buffers = NULL;
    hold->count = 0;
    if (hold->resources != NULL)
        dedup_fdt_memory_release(hold->resources, hold->reservation);
    hold->resources = NULL;
    hold->reservation = 0;
}

static void
ro_clear_preflight(rebuild_owners_t *o)
{
    o->checked = B_FALSE;
    o->checked_txg = 0;
    for (ro_link_t *l = list_head(&o->links); l != NULL;
        l = list_next(&o->links, l)) {
        ro_release_hold(&l->parent_zap, l);
        if (l->newbonus != NULL)
            dmu_buf_rele(l->newbonus, l);
        l->newbonus = NULL;
        if (l->dataset != NULL)
            dsl_dataset_rele(l->dataset, o);
        l->dataset = NULL;
        if (l->dir != NULL)
            dsl_dir_rele(l->dir, o);
        l->dir = NULL;
    }
    ro_release_hold(&o->stage_zap, o);
    ro_release_hold(&o->pool_zap, o);
}

/* These existing, fixed-width ZAP values are updated without growth at
 * publication. Retain their data buffers so leaf lookup cannot initiate I/O
 * after the caller has dirtied its first historical root. */
static int
ro_hold_zap(rebuild_owners_t *o, uint64_t object, const void *tag,
    ro_hold_t *hold)
{
    dmu_object_info_t info;
    int error = dmu_object_info(o->os, object, &info);
    if (error != 0)
        return (error);
    if (info.doi_max_offset == 0)
        return (ECKSUM);
    /* Publication pins these buffers across native ARC eviction. Lease their
     * payloads and pointer array before holding them, rather than treating
     * an arbitrarily large metadata ZAP as fixed native overhead. */
    if (o->resources != NULL) {
        uint64_t block = info.doi_data_block_size;
        if (block == 0 || info.doi_max_offset > UINT64_MAX-(block-1))
            return (EOVERFLOW);
        uint64_t count = (info.doi_max_offset+block-1)/block;
        if (count > UINT64_MAX/(block+sizeof (dmu_buf_t *)))
            return (EOVERFLOW);
        uint64_t bytes = count*(block+sizeof (dmu_buf_t *));
        error = dedup_fdt_memory_reserve(o->resources, bytes);
        if (error != 0)
            return (error);
        hold->resources = o->resources;
        hold->reservation = bytes;
    }
    error = dmu_buf_hold_array(o->os, object, 0, info.doi_max_offset,
        B_TRUE, tag, &hold->count, &hold->buffers, DMU_READ_NO_PREFETCH);
    if (error != 0)
        ro_release_hold(hold, tag);
    return (error);
}

static int
ro_hold_link(rebuild_owners_t *o, ro_link_t *l)
{
    if (l->kind == RO_DELETED)
        return (0);
    if (l->kind == RO_SCALAR)
        return (ro_hold_zap(o, l->parent, l, &l->parent_zap));
    int error = dmu_bonus_hold(o->os, l->newobj, l, &l->newbonus);
    if (error != 0)
        return (error);
    dmu_object_info_from_db(l->newbonus, &l->newinfo);
    dsl_pool_t *dp = spa_get_dsl(o->spa);
    if (l->kind == RO_DEAD || l->kind == RO_REMAP) {
        error = dsl_dataset_hold_obj(dp, l->owner, o, &l->dataset);
        if (error != 0)
            return (error);
    } else if (l->kind == RO_LIVE) {
        error = dsl_dir_hold_obj(dp, l->parent, NULL, o, &l->dir);
        if (error != 0)
            return (error);
    }
    if (l->kind == RO_REMAP || l->kind == RO_LIVE)
        return (ro_hold_zap(o, l->parent, l, &l->parent_zap));
    if (l->kind == RO_SYNC) {
        bpobj_t *active = &o->spa->spa_deferred_bpobj;
        /* Since begin(), native syncing only appends direct new MOS frees
         * to this queue. No source subtree may be attached before publish. */
        if (!active->bpo_havesubobj || !active->bpo_havecomp ||
            active->bpo_phys->bpo_subobjs != 0 ||
            active->bpo_phys->bpo_num_subobjs != 0 ||
            l->newinfo.doi_type != DMU_OT_BPOBJ || o->deferred_array == 0)
            return (EBUSY);
    }
    return (0);
}

static int
ro_check_locked(rebuild_owners_t *o)
{
    if (o == NULL || !o->prepared || o->published)
        return (EINVAL);
    ro_clear_preflight(o);
    uint64_t phase, ready;
    int error = ro_get(o, "phase", &phase);
    if (error != 0)
        return (error);
    if ((phase == REBUILD_INVENTORY || phase == REBUILD_BRIDGE_PREPARED) !=
        (o->phase == REBUILD_INVENTORY || o->phase == REBUILD_BRIDGE_PREPARED) ||
        phase >= REBUILD_FLAT_PUBLISHED || phase == REBUILD_BRIDGE_PUBLISHED)
        return (EBUSY);
    if ((error = ro_get(o, RO_READY, &ready)) != 0 || ready != 1)
        return (error != 0 ? error : EINVAL);
    for (ro_link_t *l = list_head(&o->links); l != NULL;
        l = list_next(&o->links, l)) {
        if ((error = ro_check_link(o, l)) != 0 ||
            (error = ro_hold_link(o, l)) != 0) {
            ro_clear_preflight(o);
            return (error);
        }
    }
    if ((error = ro_hold_zap(o, o->stage, o, &o->stage_zap)) != 0 ||
        (error = ro_hold_zap(o, DMU_POOL_DIRECTORY_OBJECT, o,
        &o->pool_zap)) != 0) {
        ro_clear_preflight(o);
        return (error);
    }
    o->checked = dsl_pool_sync_context(spa_get_dsl(o->spa));
    o->checked_txg = o->checked ? o->spa->spa_syncing_txg : 0;
    return (0);
}

int
rebuild_owners_check(rebuild_owners_t *o)
{
    if (o == NULL)
        return (EINVAL);
    dsl_pool_t *dp = spa_get_dsl(o->spa);
    boolean_t enter = !dsl_pool_config_held(dp);
    if (enter)
        dsl_pool_config_enter(dp, o);
    int error = ro_check_locked(o);
    if (enter)
        dsl_pool_config_exit(dp, o);
    return (error);
}

int
rebuild_owners_stage_scalar(rebuild_owners_t *o, uint64_t object,
    const char *key, uint64_t expected, uint64_t replacement)
{
    if (o == NULL || !o->prepared || o->published || object == 0 ||
        key == NULL || key[0] == 0)
        return (EINVAL);
    if (strlen(key) >= RO_NAME)
        return (ENAMETOOLONG);
    for (ro_link_t *l = list_head(&o->links); l != NULL;
        l = list_next(&o->links, l)) {
        if (l->parent == object && strcmp(l->key, key) == 0)
            return (EEXIST);
    }
    ro_clear_preflight(o);
    ro_link_t *l = ro_add(o, RO_SCALAR, object, 0, expected, key);
    if (l == NULL)
        return (o->allocation_error);
    l->newobj = replacement;
    return (0);
}

/* Exact 2.4.4 bpobj_open/dsl_deadlist_open initialization, using bonus
 * buffers already read and retained by preflight. Transfer tagged refs to
 * the native live view, rather than performing a fallible lazy reopen. */
static void
ro_bind_bpobj(bpobj_t *bpo, rebuild_owners_t *o, ro_link_t *l)
{
    bpobj_close(bpo);
    memset(bpo, 0, sizeof (*bpo));
    mutex_init(&bpo->bpo_lock, NULL, MUTEX_DEFAULT, NULL);
    bpo->bpo_os = o->os;
    bpo->bpo_object = l->newobj;
    bpo->bpo_epb = l->newinfo.doi_data_block_size >> SPA_BLKPTRSHIFT;
    bpo->bpo_havecomp = l->newinfo.doi_bonus_size > BPOBJ_SIZE_V0;
    bpo->bpo_havesubobj = l->newinfo.doi_bonus_size > BPOBJ_SIZE_V1;
    bpo->bpo_havefreed = l->newinfo.doi_bonus_size > BPOBJ_SIZE_V2;
    dmu_buf_add_ref(l->newbonus, bpo);
    bpo->bpo_dbuf = l->newbonus;
    bpo->bpo_phys = l->newbonus->db_data;
}

static void
ro_bind_deadlist(dsl_deadlist_t *dl, rebuild_owners_t *o, ro_link_t *l)
{
    if (dsl_deadlist_is_open(dl))
        dsl_deadlist_close(dl);
    memset(dl, 0, sizeof (*dl));
    mutex_init(&dl->dl_lock, NULL, MUTEX_DEFAULT, NULL);
    dl->dl_os = o->os;
    dl->dl_object = l->newobj;
    if (l->newinfo.doi_type == DMU_OT_BPOBJ) {
        dl->dl_oldfmt = B_TRUE;
        ro_bind_bpobj(&dl->dl_bpobj, o, l);
    } else {
        dmu_buf_add_ref(l->newbonus, dl);
        dl->dl_dbuf = l->newbonus;
        dl->dl_phys = l->newbonus->db_data;
    }
}

static void
ro_refresh(rebuild_owners_t *o, ro_link_t *l)
{
    dsl_pool_t *dp = spa_get_dsl(o->spa);
    if (l->kind == RO_FREE)
        ro_bind_bpobj(&dp->dp_free_bpobj, o, l);
    else if (l->kind == RO_OBSOLETE)
        ro_bind_bpobj(&dp->dp_obsolete_bpobj, o, l);
    else if (l->kind == RO_TREE)
        dp->dp_bptree_obj = l->newobj;
    else if (l->kind == RO_DELETED_ROOT)
        o->spa->spa_livelists_to_delete = l->newobj;
    else if (l->kind == RO_DEAD)
        ro_bind_deadlist(&l->dataset->ds_deadlist, o, l);
    else if (l->kind == RO_REMAP)
        ro_bind_deadlist(&l->dataset->ds_remap_deadlist, o, l);
    else if (l->kind == RO_LIVE)
        ro_bind_deadlist(&l->dir->dd_livelist, o, l);
}

int
rebuild_owners_publish(rebuild_owners_t *o, dmu_tx_t *tx)
{
    if (o == NULL || tx == NULL || !dmu_tx_is_syncing(tx) ||
        tx->tx_pool != spa_get_dsl(o->spa) || !o->prepared || o->published ||
        !o->checked || o->checked_txg != tx->tx_txg)
        return (EINVAL);
    int error;
    for (ro_link_t *l = list_head(&o->links); l != NULL;
        l = list_next(&o->links, l)) {
        if (l->kind == RO_DELETED)
            continue;
        if (l->kind == RO_SYNC) {
            /* Do not replace the active queue: it owns every MOS free
             * generated by all staging TXGs after quarantine. */
            bpobj_t *active = &o->spa->spa_deferred_bpobj;
            const bpobj_phys_t *shadow = l->newbonus->db_data;
            /* Exact native non-coalescing subobject ownership transfer.
             * Array contents were written in a bounded preparation task;
             * preserve all late direct MOS frees already in active. */
            dmu_buf_will_dirty(active->bpo_dbuf, tx);
            active->bpo_phys->bpo_subobjs = o->deferred_array;
            active->bpo_phys->bpo_num_subobjs = 1;
            active->bpo_phys->bpo_bytes += shadow->bpo_bytes;
            active->bpo_phys->bpo_comp += shadow->bpo_comp;
            active->bpo_phys->bpo_uncomp += shadow->bpo_uncomp;
        } else if (l->kind == RO_DEAD) {
            dmu_buf_t *db = l->dataset->ds_dbuf;
            dmu_buf_will_dirty(db, tx);
            ((dsl_dataset_phys_t *)db->db_data)->ds_deadlist_obj = l->newobj;
        } else {
            error = zap_update(o->os, l->parent, l->key,
                sizeof (l->newobj), 1, &l->newobj, tx);
            if (error != 0)
                return (error);
        }
        ro_refresh(o, l);
    }
    dsl_dir_t *free_dir = spa_get_dsl(o->spa)->dp_free_dir;
    if (free_dir != NULL) {
        int64_t used = 0, comp = 0, uncomp = 0;
        for (ro_link_t *l = list_head(&o->links); l != NULL;
            l = list_next(&o->links, l)) {
            if (l->kind != RO_FREE && l->kind != RO_TREE &&
                l->kind != RO_DELETED)
                continue;
            used += (int64_t)l->after.used - (int64_t)l->before.used;
            comp += (int64_t)l->after.compressed -
                (int64_t)l->before.compressed;
            uncomp += (int64_t)l->after.uncompressed -
                (int64_t)l->before.uncompressed;
        }
        dsl_dir_diduse_space(free_dir, DD_USED_HEAD, used, comp, uncomp, tx);
    }
    error = ro_put(o, RO_PUBLISHED, 1, tx);
    if (error == 0) {
        o->published = B_TRUE;
        ro_clear_preflight(o);
    }
    return (error);
}

static void
ro_restore_deferred(ro_work_t *w, dmu_tx_t *tx)
{
    rebuild_owners_t *o = w->o;
    uint64_t restored, original;
    int error = ro_get(o, RO_RESTORED, &restored);
    if (error == 0 && restored == 1)
        return;
    if (error != 0 && error != ENOENT) {
        w->error = error;
        return;
    }
    error = ro_get(o, RO_DEFERRED, &original);
    if (error == ENOENT)
        return;
    if (error != 0) {
        w->error = error;
        return;
    }
    if (o->spa->spa_deferred_bpobj.bpo_object != original)
        bpobj_enqueue_subobj(&o->spa->spa_deferred_bpobj, original, tx);
    w->error = ro_put(o, RO_RESTORED, 1, tx);
}

/* Free only a bounded interval of the containing MOS object's data. The
 * stored BPs are opaque bytes here, NEVER leaf-free requests. A zero cursor
 * gets a separate subsequent TXG for the final dnode/bonus retirement. */
static int
ro_release_data(rebuild_owners_t *o, uint64_t object, uint64_t *end,
    dmu_tx_t *tx, boolean_t *done)
{
    dmu_object_info_t info;
    int error = dmu_object_info(o->os, object, &info);
    if (error != 0)
        return (error);
    *done = B_FALSE;
    if (*end == UINT64_MAX)
        *end = info.doi_max_offset;
    if (*end == 0) {
        error = dmu_object_free(o->os, object, tx);
        if (error == 0)
            *done = B_TRUE;
        return (error);
    }
    uint64_t limit = o->batch * (uint64_t)info.doi_data_block_size;
    uint64_t begin = *end > limit ? *end - limit : 0;
    error = dmu_free_range(o->os, object, begin, *end - begin, tx);
    if (error == 0)
        *end = begin;
    return (error);
}

static void
ro_drain(ro_work_t *w, dmu_tx_t *tx)
{
    rebuild_owners_t *o = w->o;
    zap_cursor_t zc;
    zap_attribute_t *za = zap_attribute_alloc();
    zap_cursor_init(&zc, o->os, w->object);
    for (size_t i = 0; i < (w->source ? o->batch : 1); i++) {
        int error = zap_cursor_retrieve(&zc, za);
        if (error == ENOENT)
            break;
        if (error != 0) {
            w->error = error;
            break;
        }
        if (w->source) {
            /* Opposite-side ownership survives; discard ledger edges only. */
            w->error = zap_remove(o->os, w->object, za->za_name, tx);
        } else {
            uint64_t record[2];
            w->error = zap_lookup(o->os, w->object, za->za_name,
                sizeof (uint64_t), 2, record);
            if (w->error != 0)
                break;
            boolean_t done;
            w->error = ro_release_data(o, record[0], &record[1], tx, &done);
            if (w->error != 0)
                break;
            if (done)
                w->error = zap_remove(o->os, w->object, za->za_name, tx);
            else
                w->error = zap_update(o->os, w->object, za->za_name,
                    sizeof (uint64_t), 2, record, tx);
        }
        if (w->error != 0)
            break;
        zap_cursor_advance(&zc);
    }
    zap_cursor_fini(&zc);
    zap_attribute_free(za);
}

static void
ro_cleanup_start(ro_work_t *w, dmu_tx_t *tx)
{
    w->error = ro_put(w->o, RO_CLEAN, 1, tx);
}

static void
ro_cleanup_ledgers(ro_work_t *w, dmu_tx_t *tx)
{
    rebuild_owners_t *o = w->o;
    uint64_t phase, end;
    if ((w->error = ro_get(o, RO_CLEAN, &phase)) != 0 ||
        (w->error = ro_get(o, RO_CLEAN_END, &end)) != 0)
        return;
    if (phase != 1 && phase != 2) {
        w->error = ECKSUM;
        return;
    }
    boolean_t done;
    w->error = ro_release_data(o, phase == 1 ? o->newledger : o->oldledger,
        &end, tx, &done);
    if (w->error != 0)
        return;
    if (done) {
        phase++;
        end = UINT64_MAX;
    }
    if ((w->error = ro_put(o, RO_CLEAN_END, end, tx)) == 0)
        w->error = ro_put(o, RO_CLEAN, phase, tx);
    w->value = phase;
}

static void
ro_empty_retire(ro_work_t *w, dmu_tx_t *tx)
{
    rebuild_owners_t *o = w->o;
    uint64_t total, done = 0;
    if ((w->error = ro_get(o, w->source ? RO_EMPTY : RO_EMPTY_NEW,
        &total)) != 0)
        return;
    int error = ro_get(o, RO_EMPTY_DONE, &done);
    if (error != 0 && error != ENOENT) {
        w->error = error;
        return;
    }
    if (done > total) {
        w->error = ECKSUM;
        return;
    }
    size_t n = MIN(o->batch, total - done);
    for (size_t i = 0; i < n; i++)
        bpobj_decr_empty(o->os, tx);
    done += n;
    w->value = total - done;
    w->error = ro_put(o, RO_EMPTY_DONE, done, tx);
}

static void
ro_finish(ro_work_t *w, dmu_tx_t *tx)
{
    rebuild_owners_t *o = w->o;
    /* Both ledger objects have already been drained in bounded ranges. */
    static const char *keys[] = { RO_NEW, RO_OLD, RO_PHASE, RO_READY,
        RO_PUBLISHED, RO_DEFERRED, RO_RESTORED, RO_EMPTY, RO_EMPTY_DONE,
        RO_EMPTY_NEW, RO_CLEAN, RO_CLEAN_END, RO_DEFERRED_ARRAY };
    for (size_t i = 0; i < ARRAY_SIZE(keys); i++) {
        int error = zap_remove(o->os, o->stage, keys[i], tx);
        if (error != 0 && error != ENOENT) {
            w->error = error;
            return;
        }
    }
    o->newledger = o->oldledger = 0;
    o->initialized = B_FALSE;
}

int
rebuild_owners_recover(rebuild_owners_t *o)
{
    if (o == NULL)
        return (EINVAL);
    if (!o->initialized)
        return (0);
    ro_clear_preflight(o);
    uint64_t initial, phase, published = 0;
    int error = ro_get(o, RO_PHASE, &initial);
    if (error == 0)
        error = ro_get(o, "phase", &phase);
    if (error != 0)
        return (error);
    error = ro_get(o, RO_PUBLISHED, &published);
    if (error != 0 && error != ENOENT)
        return (error);
    boolean_t phase_published = initial <= REBUILD_BRIDGE_PREPARED ?
        phase >= REBUILD_BRIDGE_PUBLISHED : phase >= REBUILD_FLAT_PUBLISHED;
    if ((published != 0) != phase_published)
        return (ECKSUM);
    ro_work_t w = { .o = o };
    uint64_t cleanup;
    if ((error = ro_get(o, RO_CLEAN, &cleanup)) != 0)
        return (error);
    if (cleanup > 3)
        return (ECKSUM);
    if (cleanup == 0) {
        if (!published && (error = ro_run(&w, ro_restore_deferred, 4)) != 0)
            return (error);
        /* Drain retire-side metadata, then discard opposite-side ledger
         * edges WITHOUT touching the objects they continue to own. */
        for (unsigned side = 0; side < 2; side++) {
            uint64_t ledger = (published != (side != 0)) ?
                o->oldledger : o->newledger;
            uint64_t count;
            for (;;) {
                if ((error = zap_count(o->os, ledger, &count)) != 0)
                    return (error);
                if (count == 0)
                    break;
                w.object = ledger;
                w.source = side;
                if ((error = ro_run(&w, ro_drain, 2)) != 0)
                    return (error);
            }
        }
        w.source = published;
        do {
            if ((error = ro_run(&w, ro_empty_retire, 2)) != 0)
                return (error);
        } while (w.value != 0);
        if ((error = ro_run(&w, ro_cleanup_start, 1)) != 0)
            return (error);
        cleanup = 1;
    }
    /* Once this state begins the ledgers are raw MOS data, no longer ZAPs.
     * Stage-owned cursors remain readable across every recovery import. */
    while (cleanup < 3) {
        if ((error = ro_run(&w, ro_cleanup_ledgers, 2)) != 0)
            return (error);
        cleanup = w.value;
    }
    return (ro_run(&w, ro_finish, 2));
}

void
rebuild_owners_close(rebuild_owners_t *o)
{
    if (o == NULL)
        return;
    ro_clear_preflight(o);
    ro_link_t *l;
    while ((l = list_remove_head(&o->links)) != NULL) {
        ro_memory_free(o, l, sizeof (*l));
    }
    ro_insert_t *i;
    while ((i = list_remove_head(&o->inserts)) != NULL)
        kmem_free(i, sizeof (*i));
    list_destroy(&o->links);
    list_destroy(&o->inserts);
    if (o->resources != NULL)
        dedup_fdt_file_close(&o->insert_file);
    kmem_free(o, sizeof (*o));
}

int
rebuild_owners_foreach_identity(rebuild_owners_t *o,
    rebuild_owners_identity_f *visit, void *arg)
{
    if (o == NULL || visit == NULL || o->begun)
        return (EINVAL);
    for (ro_link_t *link = list_head(&o->links); link != NULL;
        link = list_next(&o->links, link)) {
        if (link->kind == RO_SCALAR)
            continue;
        int error = visit(arg, link->parent, link->owner, ro_role(link->kind),
            link->key, link->oldobj);
        if (error != 0)
            return (error);
    }
    return (0);
}
