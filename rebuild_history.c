/* SPDX-License-Identifier: CDDL-1.0 */
#include "rebuild_history.h"
#include "rebuild_history_native.h"
#include "dedup_fdt_traverse_native.h"
#include "rebuild_phase.h"
#include "rebuild_quota.h"
#include "rebuild_owners.h"
#include "rebuild_zil.h"
#include <sys/u8_textprep.h>
#include "rebuild_bridge.h"
#include <sys/brt.h>
#include <sys/ddt_impl.h>
#include <sys/arc.h>
#include <sys/avl.h>
#include <sys/dmu_objset.h>
#include <sys/dmu_traverse.h>
#include <sys/dmu_tx.h>
#include <sys/dnode.h>
#include <sys/dsl_dataset.h>
#include <sys/dsl_dir.h>
#include <sys/dsl_bookmark.h>
#include <sys/dsl_crypt.h>
#include <sys/dsl_pool.h>
#include <sys/dsl_synctask.h>
#include <sys/spa_impl.h>
#include <sys/zap.h>
#include <sys/zio_crypt.h>
#include <sys/zio_checksum.h>
#include <sys/zio_compress.h>
#include <sys/zfeature.h>
#include <stdlib.h>
#include <stdio.h>

#define RH_LEDGER_KEY "hist-ledger"
#define RH_ROOTS_KEY "hist-roots"
#define RH_FLAT_KEY "hist-flat"
#define RH_READY_KEY "hist-ready"

typedef struct rh_group {
    avl_node_t link;
    blkptr_t bp;
    ddt_key_t key;
    enum zio_checksum checksum;
    boolean_t canonical;
    uint64_t expected;
} rh_group_t;

typedef struct rh_quota {
    avl_node_t link;
    uint64_t id;
    unsigned which;
    int64_t delta;
    unsigned found;
} rh_quota_t;

typedef struct rh_member {
    struct rh_member *next;
    uint64_t dsobj;
} rh_member_t;

typedef struct rh_variant {
    struct rh_variant *next;
    blkptr_t bp;
    rebuild_history_delta_t own;
    int64_t object_delta;
    void *payload;
    size_t size;
    uint64_t payload_offset;
    boolean_t payload_spilled;
    uint64_t ledger_index;
    boolean_t allocated;
    uint64_t birth_owner;
    rh_member_t *members;
} rh_variant_t;

typedef struct rh_node {
    avl_node_t link;
    blkptr_t old;
    rh_variant_t *variants;
    boolean_t original_survives;
    uint64_t embedded_event;
    zbookmark_phys_t embedded_bookmark;
} rh_node_t;

typedef struct rh_birth_delta {
    uint64_t birth;
    rebuild_history_delta_t delta;
} rh_birth_delta_t;

typedef struct rh_bookmark_change {
    struct rh_bookmark_change *next;
    dsl_bookmark_node_t *node;
    zfs_bookmark_phys_t before, after;
} rh_bookmark_change_t;

typedef struct rh_seen {
    avl_node_t link;
    zbookmark_phys_t bookmark;
} rh_seen_t;

typedef struct rh_location {
    avl_node_t link;
    zbookmark_phys_t bookmark;
    rh_node_t *node;
    rh_variant_t *variant;
} rh_location_t;

typedef struct rh_root {
    dsl_dataset_t *ds;
    dsl_dataset_phys_t original;
    blkptr_t prepared;
    rebuild_history_delta_t delta;
    uint64_t unique;
    avl_tree_t quotas;
    objset_t *os;
    boolean_t destroyed;
    uint64_t destroyed_birth;
    zbookmark_phys_t resume;
    rh_birth_delta_t *births;
    size_t nbirths, birth_capacity;
    dedup_fdt_resources_t *resources;
    dedup_fdt_file_t birth_file;
    uint64_t bookmark_old, bookmark_new;
    rh_bookmark_change_t *bookmarks;
    zil_header_t prepared_zil;
    boolean_t zil_prepared;
    avl_tree_t seen;
    rebuild_owners_space_t dead_before, dead_after;
    avl_tree_t locations;
    rebuild_history_delta_t dead_delta, head_delta;
    int64_t refreservation_delta;
    uint64_t referenced, compressed, uncompressed;
    boolean_t data_features[SPA_FEATURES];
} rh_root_t;

typedef struct rh_root_record {
    uint64_t dsobj;
    dsl_dataset_phys_t original;
    blkptr_t prepared;
    uint64_t referenced, compressed, uncompressed, unique;
    uint64_t bookmark_old, bookmark_new;
} rh_root_record_t;

struct rebuild_history {
    spa_t *spa;
    uint64_t stage, ledger, roots_object;
    size_t batch;
    avl_tree_t groups, nodes;
    rh_root_t **roots;
    size_t nroots, capacity;
    rebuild_owners_t *owners;
    rh_root_t *active;
    boolean_t flat, prepared, checking;
    dmu_buf_t *ledger_dbuf;
    rebuild_history_delta_t ledger_transfer;
    uint64_t checked_txg;
    unsigned actual_policy;
    boolean_t complete_candidate;
    rebuild_history_data_ops_t data;
    uint64_t data_birth;
    boolean_t needs_claim;
    dedup_fdt_file_t payload_file;
    dedup_fdt_resources_t *root_array_resources;
};

static int
rh_failure(rebuild_history_t *h, rh_root_t *root, const char *step,
    const blkptr_t *bp, const zbookmark_phys_t *bookmark, int error)
{
    if (error != 0 && h->data.rhd_map != NULL)
        fprintf(stderr, "dedup-fdt: history %s owner=%llu prev=%llu "
            "prev_txg=%llu creation_txg=%llu birth=%llu physical_birth=%llu "
            "object=%llu level=%lld error=%d\n", step,
            (u_longlong_t)(root != NULL ? root->ds->ds_object : 0),
            (u_longlong_t)(root != NULL ? root->original.ds_prev_snap_obj : 0),
            (u_longlong_t)(root != NULL ? root->original.ds_prev_snap_txg : 0),
            (u_longlong_t)(root != NULL ? root->original.ds_creation_txg : 0),
            (u_longlong_t)(bp != NULL ? BP_GET_BIRTH(bp) : 0),
            (u_longlong_t)(bp != NULL ? BP_GET_PHYSICAL_BIRTH(bp) : 0),
            (u_longlong_t)(bookmark != NULL ? bookmark->zb_object : 0),
            (long long)(bookmark != NULL ? bookmark->zb_level : 0), error);
    return (error);
}

static int rh_transform(void *, uint64_t, const blkptr_t *, blkptr_t *);
static int rh_visit(spa_t *, zilog_t *, const blkptr_t *,
    const zbookmark_phys_t *, const dnode_phys_t *, void *);
static int rh_event_add(rh_root_t *, spa_t *, const blkptr_t *,
    const blkptr_t *);
static int rh_zil_prepare(rebuild_history_t *, rh_root_t *, boolean_t);
static int rh_ownership_check(rebuild_history_t *);
static int rh_flat_register(void *, enum zio_checksum, const ddt_key_t *,
    const ddt_univ_phys_t *);
static int rh_seen_add(rh_root_t *, const zbookmark_phys_t *);
static int rh_seen_compare(const void *, const void *);
static int rh_map_at(rebuild_history_t *, rh_root_t *, uint64_t,
    const zbookmark_phys_t *, const blkptr_t *, blkptr_t *, int64_t *);
static int rh_get_os(rebuild_history_t *, rh_root_t *);
static int rh_native_ddt_count(rebuild_history_t *, const blkptr_t *, uint64_t *);
static boolean_t rh_can_share(rebuild_history_t *, rh_node_t *,
    rh_variant_t *, rh_root_t *);
static boolean_t rh_payload_equal(const blkptr_t *, const void *,
    const void *, size_t);
static uint64_t rh_max_child_birth(const blkptr_t *, const void *, size_t);
static rh_location_t *rh_location_find(rh_root_t *, const zbookmark_phys_t *);
static int rh_location_add(rh_root_t *, const zbookmark_phys_t *,
    rh_node_t *, rh_variant_t *);
static int rh_embedded_deaths(rebuild_history_t *);
static int rh_unsigned_difference(uint64_t, uint64_t, int64_t *);
static int rh_delta_subtract(int64_t *, int64_t);
static int rh_data_identity(const blkptr_t *, const blkptr_t *);
static boolean_t rh_data_prefix(const blkptr_t *, const blkptr_t *);
static int rh_check_bit(rebuild_history_t *, const blkptr_t *, const rh_group_t *);
static rh_root_t *rh_root_find(rebuild_history_t *, uint64_t);
static int rh_source_policy(rebuild_history_t *);
static int rh_checkpoint_check(spa_t *);
static int rh_data_prepare(rebuild_history_t *, rh_root_t *,
    const blkptr_t *, blkptr_t *);

/* Stable AVL/link identities are the live working set. Unlike cold payloads
 * they cannot be evicted while pointer-dependent history is being prepared;
 * account them explicitly so they never escape the shared memory budget. */
static void *
rh_heap_alloc(dedup_fdt_resources_t *resources, size_t bytes)
{
    if (resources != NULL && dedup_fdt_memory_reserve(resources, bytes) != 0)
        return (NULL);
    return (kmem_zalloc(bytes, KM_SLEEP));
}

static void
rh_heap_free(dedup_fdt_resources_t *resources, void *data, size_t bytes)
{
    kmem_free(data, bytes);
    if (resources != NULL)
        dedup_fdt_memory_release(resources, bytes);
}

static void
rh_payload_free(rebuild_history_t *h, rh_variant_t *v)
{
    if (v->payload == NULL)
        return;
    kmem_free(v->payload, v->size);
    if (h->data.rhd_resources != NULL)
        dedup_fdt_memory_release(h->data.rhd_resources, v->size);
    v->payload = NULL;
}

static int
rh_payload_store(rebuild_history_t *h, rh_variant_t *v)
{
    if (h->data.rhd_resources == NULL || v->payload == NULL)
        return (0);
    if (h->payload_file.fd < 0) {
        int error = dedup_fdt_file_create(h->data.rhd_resources, -1,
            "history-payloads", &h->payload_file);
        if (error != 0)
            return (error);
    }
    uint64_t offset = h->payload_file.size;
    if (v->size > UINT64_MAX - offset)
        return (EOVERFLOW);
    int error = dedup_fdt_file_resize(&h->payload_file, offset + v->size);
    if (error == 0)
        error = dedup_fdt_file_pwrite(&h->payload_file, v->payload,
            v->size, offset);
    if (error != 0)
        return (error);
    v->payload_offset = offset;
    v->payload_spilled = B_TRUE;
    rh_payload_free(h, v);
    return (0);
}

static int
rh_variant_equal(rebuild_history_t *h, const blkptr_t *bp,
    const rh_variant_t *old, const rh_variant_t *v, boolean_t *equal)
{
    *equal = B_FALSE;
    if (old->size != v->size)
        return (0);
    if (!old->payload_spilled) {
        *equal = rh_payload_equal(bp, old->payload, v->payload, v->size);
        return (0);
    }
    int error = dedup_fdt_memory_reserve(h->data.rhd_resources, old->size);
    if (error != 0)
        return (error);
    void *payload = kmem_alloc(old->size, KM_SLEEP);
    error = dedup_fdt_file_pread(&h->payload_file, payload, old->size,
        old->payload_offset);
    if (error == 0)
        *equal = rh_payload_equal(bp, payload, v->payload, v->size);
    kmem_free(payload, old->size);
    dedup_fdt_memory_release(h->data.rhd_resources, old->size);
    return (error);
}

static int
rh_identity(const blkptr_t *a, const blkptr_t *b)
{
    int cmp = TREE_CMP(BP_GET_PHYSICAL_BIRTH(a), BP_GET_PHYSICAL_BIRTH(b));
    if (cmp != 0)
        return (cmp);
    unsigned na = BP_GET_NDVAS(a), nb = BP_GET_NDVAS(b);
    cmp = TREE_CMP(na, nb);
    for (unsigned i = 0; cmp == 0 && i < na; i++) {
        cmp = TREE_CMP(a->blk_dva[i].dva_word[0], b->blk_dva[i].dva_word[0]);
        if (cmp == 0)
            cmp = TREE_CMP(a->blk_dva[i].dva_word[1], b->blk_dva[i].dva_word[1]);
    }
    return (cmp);
}

static int rh_group_cmp(const void *a, const void *b)
{
    return (rh_data_identity(&((const rh_group_t *)a)->bp,
        &((const rh_group_t *)b)->bp));
}
static int rh_node_cmp(const void *a, const void *b)
{
    const rh_node_t *x = a, *y = b;
    int embedded = TREE_CMP(BP_IS_EMBEDDED(&x->old), BP_IS_EMBEDDED(&y->old));
    if (embedded != 0)
        return (embedded);
    if (BP_IS_EMBEDDED(&x->old)) {
        int order = TREE_CMP(x->embedded_event, y->embedded_event);
        if (order == 0)
            order = TREE_CMP(x->embedded_bookmark.zb_object,
                y->embedded_bookmark.zb_object);
        if (order == 0)
            order = TREE_CMP(x->embedded_bookmark.zb_level,
                y->embedded_bookmark.zb_level);
        if (order == 0)
            order = TREE_CMP(x->embedded_bookmark.zb_blkid,
                y->embedded_bookmark.zb_blkid);
        if (order != 0)
            return (order);
        int c = memcmp(&x->old, &y->old, sizeof (blkptr_t));
        return ((c > 0) - (c < 0));
    }
    return (rh_identity(&x->old, &y->old));
}
static int rh_quota_cmp(const void *a, const void *b)
{
    const rh_quota_t *x = a, *y = b;
    int c = TREE_CMP(x->which, y->which);
    return (c != 0 ? c : TREE_CMP(x->id, y->id));
}

static int
rh_add_signed(uint64_t old, int64_t delta, uint64_t *out)
{
    if (delta >= 0) {
        if (old > UINT64_MAX - (uint64_t)delta)
            return (EOVERFLOW);
        *out = old + delta;
    } else {
        uint64_t amount = (uint64_t)(-(delta + 1)) + 1;
        if (old < amount)
            return (ERANGE);
        *out = old - amount;
    }
    return (0);
}
static int
rh_delta_add(int64_t *sum, int64_t add)
{
    if ((add > 0 && *sum > INT64_MAX - add) ||
        (add < 0 && *sum < INT64_MIN - add))
        return (EOVERFLOW);
    *sum += add;
    return (0);
}

static rh_node_t *
rh_find_node(rebuild_history_t *h, const blkptr_t *bp)
{
    rh_node_t key = { .old = *bp };
    return (avl_find(&h->nodes, &key, NULL));
}
static rh_variant_t *
rh_find_variant(rh_node_t *node, uint64_t dsobj)
{
    if (node == NULL)
        return (NULL);
    for (rh_variant_t *v = node->variants; v != NULL; v = v->next)
        for (rh_member_t *m = v->members; m != NULL; m = m->next)
            if (m->dsobj == dsobj || m->dsobj == 0)
                return (v);
    return (NULL);
}
static uint64_t
rh_context(const zbookmark_phys_t *zb)
{
    return (zb->zb_level == ZB_ROOT_LEVEL ||
        (DMU_OBJECT_IS_SPECIAL(zb->zb_object) &&
        zb->zb_object != DMU_META_DNODE_OBJECT) ? zb->zb_objset : 0);
}
static int
rh_member_add(rebuild_history_t *h, rh_variant_t *v, uint64_t dsobj)
{
    for (rh_member_t *m = v->members; m != NULL; m = m->next)
        if (m->dsobj == dsobj)
            return (0);
    rh_member_t *m = rh_heap_alloc(h->data.rhd_resources, sizeof (*m));
    if (m == NULL)
        return (ENOMEM);
    m->dsobj = dsobj;
    m->next = v->members;
    v->members = m;
    return (0);
}

static int
rh_policy(rebuild_history_t *h, const blkptr_t *old, blkptr_t *out)
{
    *out = *old;
    if (h->data.rhd_map != NULL)
        return (0);
    if (BP_IS_HOLE(old) || BP_IS_EMBEDDED(old) || BP_IS_REDACTED(old))
        return (0);
    if (BP_IS_METADATA(old))
        return (BP_GET_DEDUP(old) ? EINVAL : 0);
    rh_group_t key = { .bp = *old };
    rh_group_t *group = avl_find(&h->groups, &key, NULL);
    int bit_error = rh_check_bit(h, old, group);
    if (bit_error != 0)
        return (bit_error);
    if (group == NULL) {
        if (!BP_GET_DEDUP(old))
            return (0);
        /* Native pruning deliberately leaves D=1 on ordinary/BRT owners. */
        uint64_t count;
        int error = rh_native_ddt_count(h, old, &count);
        if (error != 0)
            return (error);
        if (count != 0)
            return (ESTALE);
        BP_SET_DEDUP(out, 0);
        return (0);
    }
    ddt_key_t ddk;
    ddt_key_fill(&ddk, old);
    if (memcmp(&ddk, &group->key, sizeof (ddk)) != 0 ||
        BP_GET_CHECKSUM(old) != group->checksum ||
        !rh_data_prefix(old, &group->bp))
        return (ECKSUM);
    BP_SET_DEDUP(out, h->flat && group->canonical);
    return (0);
}

static int
rh_map(rebuild_history_t *h, uint64_t context, const blkptr_t *old,
    blkptr_t *out, int64_t *object_delta)
{
    *object_delta = 0;
    if (h->data.rhd_map != NULL && !BP_IS_METADATA(old) &&
        !BP_IS_HOLE(old) && !BP_IS_EMBEDDED(old) && !BP_IS_REDACTED(old)) {
        *out = *old;
        int error = h->data.rhd_variant(h->data.rhd_arg, context,
            old, out, B_FALSE);
        if (error == ENOENT)
            return (0);
        if (error == 0) {
            spa_config_enter(h->spa, SCL_VDEV, FTAG, RW_READER);
            *object_delta = (int64_t)bp_get_dsize_sync(h->spa, out) -
                (int64_t)bp_get_dsize_sync(h->spa, old);
            spa_config_exit(h->spa, SCL_VDEV, FTAG);
        }
        return (error);
    }
    int error = rh_policy(h, old, out);
    if (error != 0 || BP_IS_HOLE(old) || BP_IS_REDACTED(old) ||
        !BP_IS_METADATA(old))
        return (error);
    rh_variant_t *v = rh_find_variant(rh_find_node(h, old), context);
    if (v != NULL) {
        *out = v->bp;
        *object_delta = v->object_delta;
    }
    return (0);
}

static int
rh_quota_add(rh_root_t *root, unsigned which, uint64_t id, int64_t delta)
{
    rh_quota_t key = { .id = id, .which = which };
    avl_index_t where;
    rh_quota_t *q = avl_find(&root->quotas, &key, &where);
    if (q == NULL) {
        q = rh_heap_alloc(root->resources, sizeof (*q));
        if (q == NULL)
            return (ENOMEM);
        q->id = id;
        q->which = which;
        avl_insert(&root->quotas, q, where);
    }
    return (rh_delta_add(&q->delta, delta));
}

static int
rh_dnode_patch(rebuild_history_t *h, rh_root_t *root,
    dnode_phys_t *dnp, uint64_t context, uint64_t object, int64_t *object_delta)
{
    *object_delta = 0;
    if (dnp->dn_type == DMU_OT_NONE)
        return (0);
    if (dnp->dn_nblkptr > DN_MAX_NBLKPTR)
        return (EINVAL);
    for (unsigned i = 0; i < dnp->dn_nblkptr; i++) {
        blkptr_t out;
        int64_t delta;
        zbookmark_phys_t bookmark;
        SET_BOOKMARK(&bookmark, root->destroyed ? ZB_DESTROYED_OBJSET :
            root->ds->ds_object, object, dnp->dn_nlevels - 1, i);
        int error = rh_map_at(h, root, context, &bookmark,
            &dnp->dn_blkptr[i], &out, &delta);
        if (error != 0 || (error = rh_delta_add(object_delta, delta)) != 0)
            return (error);
        dnp->dn_blkptr[i] = out;
    }
    if (dnp->dn_flags & DNODE_FLAG_SPILL_BLKPTR) {
        blkptr_t out;
        int64_t delta;
        zbookmark_phys_t bookmark;
        SET_BOOKMARK(&bookmark, root->destroyed ? ZB_DESTROYED_OBJSET :
            root->ds->ds_object, object, 0, DMU_SPILL_BLKID);
        int error = rh_map_at(h, root, context, &bookmark,
            DN_SPILL_BLKPTR(dnp), &out, &delta);
        if (error != 0 || (error = rh_delta_add(object_delta, delta)) != 0)
            return (error);
        *DN_SPILL_BLKPTR(dnp) = out;
    }
    if (*object_delta != 0 && !root->destroyed) {
        uint64_t used;
        int error = rh_add_signed(DN_USED_BYTES(dnp), *object_delta, &used);
        if (error != 0)
            return (error);
        if (dnp->dn_flags & DNODE_FLAG_USED_BYTES)
            dnp->dn_used = used;
        else if ((used & (SPA_MINBLOCKSIZE - 1)) == 0)
            dnp->dn_used = used >> SPA_MINBLOCKSHIFT;
        else {
            dnp->dn_flags |= DNODE_FLAG_USED_BYTES;
            dnp->dn_used = used;
        }
    }
    return (0);
}

typedef struct rh_write_task {
    rebuild_history_t *h;
    rh_root_t *root;
    rh_node_t *node;
    rh_variant_t *variant;
    abd_t *payload, *original;
    zbookmark_phys_t bookmark;
    zio_prop_t properties;
    boolean_t divergent;
    int error;
} rh_write_task_t;

static void
rh_write_sync(void *arg, dmu_tx_t *tx)
{
    rh_write_task_t *w = arg;
    uint64_t birth = BP_GET_BIRTH(&w->node->old);
    if (w->divergent) {
        if (w->root->destroyed) {
            w->error = EINVAL;
            return;
        }
        if (w->root->ds->ds_is_snapshot) {
            birth = MAX(birth, w->root->original.ds_prev_snap_txg + 1);
            if (birth == 0 || birth > w->root->original.ds_creation_txg) {
                w->error = EINVAL;
                return;
            }
        } else {
            birth = dmu_tx_get_txg(tx);
        }
    }
    w->variant->birth_owner = w->divergent && !w->root->destroyed ?
        w->root->ds->ds_object : 0;
    rebuild_history_write_options_t options = {
        .rhw_logical_birth = birth,
        .rhw_retire_original = B_FALSE,
        .rhw_original_raw = w->original
    };
    w->error = rebuild_history_cow_write_ex(w->h->spa, &w->node->old,
        w->payload, &w->properties, &w->bookmark, w->h->ledger, tx,
        &options, &w->variant->bp, &w->variant->own);
}

static int
rh_write_node(rebuild_history_t *h, rh_root_t *root, rh_node_t *node,
    rh_variant_t *variant, arc_buf_t *original,
    const zbookmark_phys_t *bookmark, boolean_t divergent)
{
    rh_write_task_t w = { .h = h, .root = root, .node = node,
        .variant = variant, .bookmark = *bookmark, .divergent = divergent };
    const blkptr_t *bp = &node->old;
    w.payload = abd_get_from_buf(variant->payload, variant->size);
    zio_prop_t *p = &w.properties;
    p->zp_type = BP_GET_TYPE(bp);
    p->zp_storage_type = p->zp_type;
    p->zp_level = BP_GET_LEVEL(bp);
    p->zp_checksum = BP_IS_EMBEDDED(bp) ? ZIO_CHECKSUM_FLETCHER_4 :
        BP_GET_CHECKSUM(bp);
    p->zp_compress = BP_IS_EMBEDDED(bp) ? ZIO_COMPRESS_OFF : BP_GET_COMPRESS(bp);
    p->zp_copies = BP_IS_EMBEDDED(bp) ? 1 : BP_GET_NDVAS(bp);
    p->zp_gang_copies = p->zp_copies;
    p->zp_encrypt = BP_USES_CRYPT(bp);
    p->zp_byteorder = ZFS_HOST_BYTEORDER;
    if (bookmark->zb_level == 0 && DMU_OBJECT_IS_SPECIAL(bookmark->zb_object) &&
        bookmark->zb_object != DMU_META_DNODE_OBJECT)
        p->zp_compress = ZIO_COMPRESS_OFF;
    if ((h->data.rhd_map == NULL || root->destroyed) &&
        BP_IS_ENCRYPTED(bp) && BP_GET_TYPE(bp) == DMU_OT_DNODE &&
        BP_GET_LEVEL(bp) == 0) {
        p->zp_byteorder = BP_GET_BYTEORDER(bp);
        zio_crypt_decode_params_bp(bp, p->zp_salt, p->zp_iv);
        zio_crypt_decode_mac_bp(bp, p->zp_mac);
        w.original = abd_get_from_buf(original->b_data, variant->size);
    }
    if (root->destroyed && BP_USES_CRYPT(bp) &&
        BP_GET_TYPE(bp) == DMU_OT_OBJSET)
        w.original = abd_get_from_buf(original->b_data, variant->size);
    int error = rebuild_history_ledger_count(h->spa, h->ledger,
        &variant->ledger_index);
    if (error == 0)
        error = dsl_sync_task(spa_name(h->spa), NULL, rh_write_sync,
            &w, 16, ZFS_SPACE_CHECK_NORMAL);
    variant->allocated = (error == 0 && w.error == 0);
    if (w.original != NULL)
        abd_free(w.original);
    abd_free(w.payload);
    if (error == 0)
        error = w.error;
    if (error == 0 && (h->data.rhd_map == NULL || root->destroyed) &&
        BP_USES_CRYPT(bp) &&
        !(DMU_OBJECT_IS_SPECIAL(bookmark->zb_object) &&
        bookmark->zb_object != DMU_META_DNODE_OBJECT) &&
        BP_GET_TYPE(bp) != DMU_OT_OBJSET)
        error = rebuild_history_portable_bp_equal(bp, &variant->bp);
    if (error == 0 && (h->data.rhd_map == NULL || root->destroyed) &&
        BP_USES_CRYPT(bp) && BP_GET_TYPE(bp) == DMU_OT_OBJSET) {
        const objset_phys_t *a = original->b_data;
        const objset_phys_t *b = variant->payload;
        if (memcmp(a->os_portable_mac, b->os_portable_mac,
            ZIO_OBJSET_MAC_LEN) != 0)
            error = ECKSUM;
    }
    return (error);
}

static int
rh_prepare_metadata(rebuild_history_t *h, rh_root_t *root,
    const blkptr_t *bp, const zbookmark_phys_t *zb, rh_variant_t **out,
    rh_node_t **outnode)
{
    uint64_t context = h->data.rhd_map != NULL ? zb->zb_objset : rh_context(zb);
    rh_node_t key = { .old = *bp };
    avl_index_t index;
    rh_node_t *node = NULL;
    if (BP_IS_EMBEDDED(bp)) {
        rh_root_t *prev = rh_root_find(h, root->original.ds_prev_snap_obj);
        rh_location_t *location = rh_location_find(prev, zb);
        if (location != NULL &&
            BP_GET_BIRTH(bp) <= root->original.ds_prev_snap_txg &&
            memcmp(&location->node->old, bp, sizeof (*bp)) == 0)
            node = location->node;
        else {
            key.embedded_event = root->ds->ds_object;
            key.embedded_bookmark = *zb;
        }
    }
    if (node == NULL)
        node = avl_find(&h->nodes, &key, &index);
    rh_variant_t *cached = rh_find_variant(node, context);
    if (cached != NULL) {
        *out = cached;
        *outnode = node;
        return (0);
    }
    if (node == NULL) {
        node = rh_heap_alloc(h->data.rhd_resources, sizeof (*node));
        if (node == NULL)
            return (ENOMEM);
        node->old = *bp;
        node->embedded_event = key.embedded_event;
        node->embedded_bookmark = key.embedded_bookmark;
        avl_insert(&h->nodes, node, index);
    }
    if (BP_GET_LEVEL(bp) == 0 && BP_GET_TYPE(bp) != DMU_OT_DNODE &&
        BP_GET_TYPE(bp) != DMU_OT_OBJSET &&
        (root->destroyed || !DMU_OBJECT_IS_SPECIAL(zb->zb_object))) {
        rh_variant_t *unchanged = rh_heap_alloc(h->data.rhd_resources,
            sizeof (*unchanged));
        if (unchanged == NULL)
            return (ENOMEM);
        unchanged->bp = *bp;
        int error = rh_member_add(h, unchanged, context);
        if (error != 0) {
            rh_heap_free(h->data.rhd_resources, unchanged, sizeof (*unchanged));
            return (error);
        }
        unchanged->next = node->variants;
        node->variants = unchanged;
        *out = unchanged;
        *outnode = node;
        return (0);
    }
    arc_buf_t *buffer = NULL;
    arc_flags_t aflags = ARC_FLAG_WAIT;
    zio_flag_t zflags = ZIO_FLAG_CANFAIL;
    if ((h->data.rhd_map == NULL || root->destroyed) && BP_IS_PROTECTED(bp) &&
        (BP_GET_TYPE(bp) == DMU_OT_DNODE || BP_GET_TYPE(bp) == DMU_OT_OBJSET))
        zflags |= ZIO_FLAG_RAW;
    int error = arc_read(NULL, h->spa, bp, arc_getbuf_func, &buffer,
        ZIO_PRIORITY_SYNC_READ, zflags, &aflags, zb);
    if (error != 0)
        return (error);
    rh_variant_t *v = rh_heap_alloc(h->data.rhd_resources, sizeof (*v));
    if (v == NULL) {
        arc_buf_destroy(buffer, &buffer);
        return (ENOMEM);
    }
    v->bp = *bp;
    v->size = BP_GET_LSIZE(bp);
    if (h->data.rhd_resources != NULL) {
        error = dedup_fdt_memory_reserve(h->data.rhd_resources, v->size);
        if (error != 0) {
            arc_buf_destroy(buffer, &buffer);
            rh_heap_free(h->data.rhd_resources, v, sizeof (*v));
            return (error);
        }
    }
    v->payload = kmem_alloc(v->size, KM_SLEEP);
    memcpy(v->payload, buffer->b_data, v->size);
    int64_t children = 0;
    if (BP_GET_LEVEL(bp) > 0) {
        if ((v->size & (sizeof (blkptr_t) - 1)) != 0)
            error = EINVAL;
        for (size_t i = 0; error == 0 && i < v->size / sizeof (blkptr_t); i++) {
            blkptr_t *child = &((blkptr_t *)v->payload)[i], mapped;
            int64_t delta;
            zbookmark_phys_t bookmark;
            SET_BOOKMARK(&bookmark, zb->zb_objset, zb->zb_object,
                zb->zb_level - 1,
                zb->zb_blkid * (v->size / sizeof (blkptr_t)) + i);
            error = rh_map_at(h, root, context, &bookmark,
                child, &mapped, &delta);
            if (error == 0)
                error = rh_delta_add(&children, delta);
            if (error == 0)
                *child = mapped;
        }
    } else if (BP_GET_TYPE(bp) == DMU_OT_DNODE) {
        for (size_t off = 0; error == 0 && off < v->size; ) {
            dnode_phys_t *dnp = (void *)((char *)v->payload + off);
            size_t slots = (size_t)dnp->dn_extra_slots + 1;
            if (slots > (v->size - off) / DNODE_MIN_SIZE) {
                error = EINVAL;
                break;
            }
            int64_t ignored;
            error = rh_dnode_patch(h, root, dnp,
                h->data.rhd_map != NULL ? context : 0,
                zb->zb_blkid * (v->size >> DNODE_SHIFT) +
                (off >> DNODE_SHIFT), &ignored);
            off += slots * DNODE_MIN_SIZE;
        }
    } else if (BP_GET_TYPE(bp) == DMU_OT_OBJSET) {
        objset_phys_t *osp = v->payload;
        if (v->size < OBJSET_PHYS_SIZE_V1)
            error = EINVAL;
        if (error == 0 && root->zil_prepared)
            osp->os_zil_header = root->prepared_zil;
        int64_t ignored;
        if (error == 0)
            error = rh_dnode_patch(h, root, &osp->os_meta_dnode,
                h->data.rhd_map != NULL ? context : 0,
                DMU_META_DNODE_OBJECT, &ignored);
        if (error == 0 && v->size >= OBJSET_PHYS_SIZE_V2)
            error = rh_dnode_patch(h, root, &osp->os_userused_dnode,
                zb->zb_objset, DMU_USERUSED_OBJECT, &ignored);
        if (error == 0 && v->size >= OBJSET_PHYS_SIZE_V2)
            error = rh_dnode_patch(h, root, &osp->os_groupused_dnode,
                zb->zb_objset, DMU_GROUPUSED_OBJECT, &ignored);
        if (error == 0 && v->size >= OBJSET_PHYS_SIZE_V3)
            error = rh_dnode_patch(h, root, &osp->os_projectused_dnode,
                zb->zb_objset, DMU_PROJECTUSED_OBJECT, &ignored);
    } else if (!root->destroyed && DMU_OBJECT_IS_SPECIAL(zb->zb_object)) {
        unsigned which = zb->zb_object == DMU_USERUSED_OBJECT ? 0 :
            zb->zb_object == DMU_GROUPUSED_OBJECT ? 1 :
            zb->zb_object == DMU_PROJECTUSED_OBJECT ? 2 : 3;
        for (rh_quota_t *q = avl_first(&root->quotas); error == 0 && q != NULL;
            q = AVL_NEXT(&root->quotas, q)) {
            if (q->which != which || q->delta == 0)
                continue;
            char id[17];
            (void) snprintf(id, sizeof (id), "%llx", (u_longlong_t)q->id);
            boolean_t found;
            error = rebuild_history_quota_patch(v->payload, v->size,
                id, q->delta, &found);
            if (error == 0 && found && ++q->found != 1)
                error = EINVAL;
        }
    }
    if (error == 0 && (node->variants != NULL ||
        memcmp(v->payload, buffer->b_data, v->size) != 0)) {
        rh_variant_t *same = NULL;
        for (rh_variant_t *old = node->variants; old != NULL; old = old->next) {
            boolean_t equal;
            error = rh_variant_equal(h, bp, old, v, &equal);
            if (error != 0)
                break;
            if (equal && rh_can_share(h, node, old, root)) {
                same = old;
                break;
            }
        }
        if (error != 0) {
            /* Keep the unpublished candidate separate for failure cleanup. */
        } else if (same != NULL) {
            error = rh_member_add(h, same, context);
            if (error == 0) {
                rh_payload_free(h, v);
                rh_heap_free(h->data.rhd_resources, v, sizeof (*v));
                v = same;
            }
        } else {
            boolean_t split = node->variants != NULL;
            boolean_t promote = split || rh_max_child_birth(bp,
                v->payload, v->size) > BP_GET_BIRTH(bp);
            error = rh_write_node(h, root, node, v, buffer, zb, promote);
            if (error == 0) {
                v->object_delta = v->own.rhd_used;
                if (BP_GET_LEVEL(bp) > 0)
                    error = rh_delta_add(&v->object_delta, children);
                rh_variant_t *previous = NULL;
                if (error == 0 && split && !root->destroyed &&
                    BP_GET_BIRTH(bp) <= root->original.ds_prev_snap_txg) {
                    previous = rh_find_variant(node, root->original.ds_prev_snap_obj);
                    if (previous == NULL)
                        error = ESTALE;
                    else
                        error = rebuild_owners_insert_dead(h->owners,
                            root->ds->ds_object, &previous->bp);
                }
                if (error == 0 && !root->destroyed &&
                    dsl_deadlist_is_open(&root->ds->ds_dir->dd_livelist)) {
                    uint64_t head = dsl_dir_phys(root->ds->ds_dir)->
                        dd_head_dataset_obj;
                    uint64_t origin = root->ds->ds_dir->dd_origin_txg;
                    if (previous != NULL && !BP_IS_EMBEDDED(&previous->bp) &&
                        BP_GET_BIRTH(&previous->bp) > origin)
                        error = rebuild_owners_insert_livelist(h->owners,
                            head, &previous->bp, B_TRUE);
                    if (error == 0 && (split || BP_IS_EMBEDDED(bp)) &&
                        !BP_IS_EMBEDDED(&v->bp) && BP_GET_BIRTH(&v->bp) > origin)
                        error = rebuild_owners_insert_livelist(h->owners,
                            head, &v->bp, B_FALSE);
                }
                if (error == 0) {
                    error = rh_member_add(h, v, context);
                    if (error == 0) {
                        v->next = node->variants;
                        node->variants = v;
                    }
                }
            }
        }
    } else if (error == 0) {
        v->object_delta = children;
        error = rh_member_add(h, v, context);
        if (error == 0) {
            v->next = node->variants;
            node->variants = v;
        }
    }
    arc_buf_destroy(buffer, &buffer);
    if (error != 0) {
        rh_payload_free(h, v);
        rh_heap_free(h->data.rhd_resources, v, sizeof (*v));
        return (rh_failure(h, root, "metadata variant", bp, zb, error));
    }
    error = rh_payload_store(h, v);
    if (error != 0)
        return (rh_failure(h, root, "metadata spill", bp, zb, error));
    *out = v;
    *outnode = node;
    return (0);
}

static int
rh_visit(spa_t *spa, zilog_t *zilog, const blkptr_t *bp,
    const zbookmark_phys_t *zb, const dnode_phys_t *dnp, void *arg)
{
    (void)spa, (void)zilog;
    rebuild_history_t *h = arg;
    rh_root_t *root = h->active;
    if (rebuild_interrupted())
        return (EINTR);
    if (zb->zb_level == ZB_ZIL_LEVEL)
        return (0);
    if (zb->zb_level != ZB_DNODE_LEVEL && BP_IS_METADATA(bp) &&
        h->data.rhd_metadata != NULL)
        h->data.rhd_metadata(h->data.rhd_arg, bp);
    if (zb->zb_level == ZB_DNODE_LEVEL) {
        if (h->checking || root->destroyed ||
            DMU_OBJECT_IS_SPECIAL(zb->zb_object))
            return (0);
        size_t bytes = ((size_t)dnp->dn_extra_slots + 1) * DNODE_MIN_SIZE;
        dnode_phys_t *copy = rh_heap_alloc(h->data.rhd_resources, bytes);
        if (copy == NULL)
            return (ENOMEM);
        memcpy(copy, dnp, bytes);
        int64_t delta;
        int error = rh_dnode_patch(h, root, copy,
            h->data.rhd_map != NULL ? zb->zb_objset : 0, zb->zb_object, &delta);
        rh_heap_free(h->data.rhd_resources, copy, bytes);
        if (error != 0 || delta == 0)
            return (error);
        uint64_t uid, gid, project;
        if (root->os == NULL) {
            error = rh_get_os(h, root);
            if (error != 0)
                return (error);
        }
        error = rebuild_history_quota_ids(root->os, zb->zb_object,
            dnp, &uid, &gid, &project);
        if (error == ENOENT)
            return (0);
        if (error != 0)
            return (error);
        error = rh_quota_add(root, 0, uid, delta);
        if (error == 0)
            error = rh_quota_add(root, 1, gid, delta);
        if (error == 0 && spa_feature_is_enabled(h->spa,
            SPA_FEATURE_PROJECT_QUOTA) &&
            OBJSET_BUF_HAS_PROJECTUSED(root->os->os_phys_buf) &&
            root->os->os_phys->os_projectused_dnode.dn_type != DMU_OT_NONE)
            error = rh_quota_add(root, 2, project, delta);
        return (error);
    }
    if (root->destroyed) {
        int error = rh_seen_add(root, zb);
        if (error != 0)
            return (error);
    }
    blkptr_t mapped;
    int error = rh_policy(h, bp, &mapped);
    if (error != 0 || h->checking || BP_IS_HOLE(bp) || BP_IS_REDACTED(bp))
        return (error);
    if (h->data.rhd_map != NULL && root->destroyed) {
        rh_node_t *node = rh_find_node(h, bp);
        if (node != NULL)
            node->original_survives = B_TRUE;
        return (0);
    }
    if (!BP_IS_METADATA(bp)) {
        if (h->data.rhd_map == NULL || BP_IS_EMBEDDED(bp))
            return (0);
        error = rh_data_prepare(h, root, bp, &mapped);
        if (error != 0)
            return (error);
        spa_config_enter(h->spa, SCL_VDEV, FTAG, RW_READER);
        int64_t used_delta = (int64_t)bp_get_dsize_sync(h->spa, &mapped) -
            (int64_t)bp_get_dsize_sync(h->spa, bp);
        spa_config_exit(h->spa, SCL_VDEV, FTAG);
        error = rh_delta_add(&root->delta.rhd_used, used_delta);
        if (error == 0)
            error = rh_delta_add(&root->delta.rhd_compressed,
                (int64_t)BP_GET_PSIZE(&mapped) - (int64_t)BP_GET_PSIZE(bp));
        if (error == 0)
            error = rh_delta_add(&root->delta.rhd_uncompressed,
                (int64_t)BP_GET_UCSIZE(&mapped) - (int64_t)BP_GET_UCSIZE(bp));
        if (error == 0 && !root->destroyed)
            error = rh_event_add(root, h->spa, bp, &mapped);
        return (error);
    }
    if (root->destroyed && BP_IS_EMBEDDED(bp))
        return (0);
    rh_variant_t *v;
    rh_node_t *node;
    error = rh_prepare_metadata(h, root, bp, zb, &v, &node);
    if (error == 0 && BP_IS_EMBEDDED(bp))
        error = rh_location_add(root, zb, node, v);
    if (error == 0)
        error = rh_delta_add(&root->delta.rhd_used, v->own.rhd_used);
    if (error == 0)
        error = rh_delta_add(&root->delta.rhd_compressed, v->own.rhd_compressed);
    if (error == 0)
        error = rh_delta_add(&root->delta.rhd_uncompressed, v->own.rhd_uncompressed);
    if (error == 0 && !root->destroyed)
        error = rh_event_add(root, h->spa, bp, &v->bp);
    if (error == 0 && zb->zb_level == ZB_ROOT_LEVEL) {
        root->prepared = v->bp;
        if (h->data.rhd_root != NULL)
            h->data.rhd_root(h->data.rhd_arg, bp, &v->bp);
    }
    return (error);
}

static rh_root_t *
rh_root_find(rebuild_history_t *h, uint64_t object)
{
    for (size_t i = 0; i < h->nroots; i++)
        if (h->roots[i]->ds != NULL && h->roots[i]->ds->ds_object == object)
            return (h->roots[i]);
    return (NULL);
}

static int
rh_transform(void *arg, uint64_t owner, const blkptr_t *old, blkptr_t *out)
{
    rebuild_history_t *h = arg;
    *out = *old;
    if (BP_IS_HOLE(old) || BP_IS_REDACTED(old) || BP_IS_EMBEDDED(old))
        return (0);
    if (!BP_IS_METADATA(old)) {
        if (h->data.rhd_map != NULL) {
            /* Pool and destroyed owners retain their physical source. */
            if (owner == 0 || owner == ZB_DESTROYED_OBJSET)
                return (0);
            rh_root_t *root = rh_root_find(h, owner);
            rebuild_owners_role_t role = rebuild_owners_role(h->owners);
            if (root != NULL && (role == REBUILD_OWNER_DEADLIST ||
                role == REBUILD_OWNER_REMAP))
                root = rh_root_find(h, root->original.ds_prev_snap_obj);
            while (root != NULL) {
                int error = h->data.rhd_variant(h->data.rhd_arg,
                    root->ds->ds_object, old, out, B_FALSE);
                if (error != 0 && error != ENOENT)
                    return (error);
                if (error == 0 && (role != REBUILD_OWNER_LIVELIST ||
                    BP_GET_BIRTH(out) == BP_GET_BIRTH(old)))
                    return (0);
                root = rh_root_find(h, root->original.ds_prev_snap_obj);
            }
            /* Canceled live-list events may have no surviving tree
             * occurrence. Their ALLOC/FREE pair uses the verified base map;
             * promoted aliases have separately inserted native events. */
            *out = *old;
            int error = h->data.rhd_map(h->data.rhd_arg, owner, old, out);
            return (error == ENOENT ? 0 : error);
        }
        rh_group_t key = { .bp = *old };
        rh_group_t *g = avl_find(&h->groups, &key, NULL);
        int bit_error = rh_check_bit(h, old, g);
        if (bit_error != 0)
            return (bit_error);
        if (g == NULL)
            return (rh_policy(h, old, out));
        if (BP_GET_LSIZE(old) != DDK_GET_LSIZE(&g->key) ||
            BP_GET_PSIZE(old) != DDK_GET_PSIZE(&g->key) ||
            BP_GET_COMPRESS(old) != DDK_GET_COMPRESS(&g->key) ||
            BP_USES_CRYPT(old) != DDK_GET_CRYPT(&g->key))
            return (ECKSUM);
        /* bpobj_enqueue strips checksums only on non-DDT records. */
        if (BP_GET_DEDUP(old) && memcmp(&old->blk_cksum,
            &g->key.ddk_cksum, sizeof (zio_cksum_t)) != 0)
            return (ECKSUM);
        BP_SET_DEDUP(out, h->flat && g->canonical);
        if (BP_GET_DEDUP(out)) {
            out->blk_cksum = g->key.ddk_cksum;
            BP_SET_CHECKSUM(out, g->checksum);
        }
        return (0);
    }
    if (BP_GET_DEDUP(old))
        return (EINVAL);
    rh_node_t *node = rh_find_node(h, old);
    if (node == NULL)
        return (0);
    if (h->data.rhd_map != NULL &&
        (owner == 0 || owner == ZB_DESTROYED_OBJSET)) {
        node->original_survives = B_TRUE;
        return (0);
    }
    rh_variant_t *v = rh_find_variant(node, 0);
    if (v == NULL && owner != 0 && owner != ZB_DESTROYED_OBJSET) {
        rh_root_t *root = rh_root_find(h, owner);
        rebuild_owners_role_t role = rebuild_owners_role(h->owners);
        if (role == REBUILD_OWNER_LIVELIST)
            for (rh_variant_t *base = node->variants; base != NULL; base = base->next)
                if (base->birth_owner == 0) {
                    v = base;
                    break;
                }
        if (root != NULL && role == REBUILD_OWNER_DEADLIST)
            v = rh_find_variant(node, root->original.ds_prev_snap_obj);
        if (v == NULL)
            v = rh_find_variant(node, owner);
    }
    if (v == NULL && node->variants != NULL &&
        node->variants->next == NULL)
        v = node->variants;
    if (v == NULL)
        return (ESTALE);
    *out = v->bp;
    if (!BP_IS_EMBEDDED(old) && !BP_IS_EMBEDDED(out) &&
        rh_identity(old, out) == 0)
        node->original_survives = B_TRUE;
    return (0);
}

static int
rh_root_compare(const void *a, const void *b)
{
    const rh_root_t *x = *(rh_root_t *const *)a;
    const rh_root_t *y = *(rh_root_t *const *)b;
    int c = TREE_CMP(!x->ds->ds_is_snapshot, !y->ds->ds_is_snapshot);
    if (c == 0)
        c = TREE_CMP(x->original.ds_creation_txg, y->original.ds_creation_txg);
    return (c != 0 ? c : TREE_CMP(x->ds->ds_object, y->ds->ds_object));
}

static void
rh_quotas_clear(rh_root_t *root)
{
    void *cookie = NULL;
    rh_quota_t *q;
    while ((q = avl_destroy_nodes(&root->quotas, &cookie)) != NULL)
        rh_heap_free(root->resources, q, sizeof (*q));
}

static void
rh_nodes_clear(rebuild_history_t *h)
{
    void *cookie = NULL;
    rh_node_t *n;
    while ((n = avl_destroy_nodes(&h->nodes, &cookie)) != NULL) {
        rh_variant_t *v = n->variants;
        while (v != NULL) {
            rh_variant_t *next = v->next;
            rh_member_t *m = v->members;
            while (m != NULL) {
                rh_member_t *mn = m->next;
                rh_heap_free(h->data.rhd_resources, m, sizeof (*m));
                m = mn;
            }
            rh_payload_free(h, v);
            rh_heap_free(h->data.rhd_resources, v, sizeof (*v));
            v = next;
        }
        rh_heap_free(h->data.rhd_resources, n, sizeof (*n));
    }
    if (h->data.rhd_resources != NULL)
        dedup_fdt_file_close(&h->payload_file);
}

static void
rh_roots_clear(rebuild_history_t *h)
{
    for (size_t i = 0; i < h->nroots; i++) {
        rh_root_t *r = h->roots[i];
        rh_quotas_clear(r);
        avl_destroy(&r->quotas);
        void *location_cookie = NULL;
        rh_location_t *location;
        while ((location = avl_destroy_nodes(&r->locations,
            &location_cookie)) != NULL)
            rh_heap_free(r->resources, location, sizeof (*location));
        avl_destroy(&r->locations);
        if (r->births != NULL)
            kmem_free(r->births, r->birth_capacity * sizeof (*r->births));
        if (r->resources != NULL)
            dedup_fdt_file_close(&r->birth_file);
        rh_bookmark_change_t *b = r->bookmarks;
        while (b != NULL) {
            rh_bookmark_change_t *next = b->next;
            rh_heap_free(r->resources, b, sizeof (*b));
            b = next;
        }
        if (r->ds != NULL)
            dsl_dataset_rele(r->ds, h);
        rh_heap_free(r->resources, r, sizeof (*r));
    }
    if (h->roots != NULL)
        rh_heap_free(h->root_array_resources, h->roots,
            h->capacity * sizeof (*h->roots));
    h->roots = NULL;
    h->nroots = h->capacity = 0;
}

static int
rh_collect(rebuild_history_t *h)
{
    rh_roots_clear(h);
    dsl_pool_t *dp = spa_get_dsl(h->spa);
    uint64_t object = 0;
    int error;
    while ((error = dmu_object_next(dp->dp_meta_objset, &object,
        B_FALSE, 0)) == 0) {
        dmu_object_info_t info;
        error = dmu_object_info(dp->dp_meta_objset, object, &info);
        if (error != 0)
            return (error);
        if (info.doi_bonus_type != DMU_OT_DSL_DATASET)
            continue;
        rh_root_t *root = rh_heap_alloc(h->data.rhd_resources, sizeof (*root));
        if (root == NULL)
            return (ENOMEM);
        root->resources = h->data.rhd_resources;
        root->birth_file.fd = -1;
        avl_create(&root->quotas, rh_quota_cmp, sizeof (rh_quota_t),
            offsetof(rh_quota_t, link));
        dsl_pool_config_enter(dp, h);
        error = dsl_dataset_hold_obj(dp, object, h, &root->ds);
        dsl_pool_config_exit(dp, h);
        if (error != 0) {
            avl_destroy(&root->quotas);
            rh_heap_free(root->resources, root, sizeof (*root));
            return (error);
        }
        root->original = *dsl_dataset_phys(root->ds);
        root->prepared = root->original.ds_bp;
        if (h->nroots == h->capacity) {
            size_t capacity = h->capacity == 0 ? 32 : h->capacity * 2;
            if (capacity < h->capacity ||
                capacity > SIZE_MAX / sizeof (*h->roots)) {
                dsl_dataset_rele(root->ds, h);
                avl_destroy(&root->quotas);
                rh_heap_free(root->resources, root, sizeof (*root));
                return (EOVERFLOW);
            }
            rh_root_t **array = rh_heap_alloc(h->data.rhd_resources,
                capacity * sizeof (*array));
            if (array == NULL) {
                dsl_dataset_rele(root->ds, h);
                avl_destroy(&root->quotas);
                rh_heap_free(root->resources, root, sizeof (*root));
                return (ENOMEM);
            }
            if (h->roots != NULL) {
                memcpy(array, h->roots, h->nroots * sizeof (*array));
                rh_heap_free(h->root_array_resources, h->roots,
                    h->capacity * sizeof (*array));
            }
            h->roots = array;
            h->root_array_resources = h->data.rhd_resources;
            h->capacity = capacity;
        }
        avl_create(&root->locations, rh_seen_compare, sizeof (rh_location_t),
            offsetof(rh_location_t, link));
        h->roots[h->nroots++] = root;
    }
    if (error != ESRCH)
        return (error);
    size_t sort_bytes = h->nroots * sizeof (*h->roots);
    if (h->data.rhd_resources != NULL) {
        error = dedup_fdt_memory_reserve(h->data.rhd_resources, sort_bytes);
        if (error != 0)
            return (error);
    }
    qsort(h->roots, h->nroots, sizeof (*h->roots), rh_root_compare);
    if (h->data.rhd_resources != NULL)
        dedup_fdt_memory_release(h->data.rhd_resources, sort_bytes);
    return (0);
}

static int
rh_destroyed(void *arg, const blkptr_t *bp, uint64_t birth,
    const zbookmark_phys_t *resume)
{
    rebuild_history_t *h = arg;
    rh_root_t root = { .destroyed = B_TRUE, .prepared = *bp,
        .destroyed_birth = birth, .resume = *resume,
        .resources = h->data.rhd_resources };
    avl_create(&root.quotas, rh_quota_cmp, sizeof (rh_quota_t),
        offsetof(rh_quota_t, link));
    avl_create(&root.seen, rh_seen_compare, sizeof (rh_seen_t),
        offsetof(rh_seen_t, link));
    h->active = &root;
    blkptr_t original = *bp;
    zbookmark_phys_t bookmark = *resume;
    int error = traverse_dataset_destroyed(h->spa, &original, birth,
        &bookmark, TRAVERSE_POST | TRAVERSE_NO_DECRYPT, rh_visit, h);
    h->active = NULL;
    rh_quotas_clear(&root);
    avl_destroy(&root.quotas);
    void *cookie = NULL;
    rh_seen_t *seen;
    while ((seen = avl_destroy_nodes(&root.seen, &cookie)) != NULL)
        rh_heap_free(root.resources, seen, sizeof (*seen));
    avl_destroy(&root.seen);
    return (error);
}

int
rebuild_history_open_resources(spa_t *spa, uint64_t stage, size_t batch,
    dedup_fdt_resources_t *resources, rebuild_history_t **out)
{
    if (spa == NULL || out == NULL || batch == 0)
        return (EINVAL);
    int checkpoint_error = rh_checkpoint_check(spa);
    if (checkpoint_error != 0)
        return (checkpoint_error);
    rebuild_history_t *h = kmem_zalloc(sizeof (*h), KM_SLEEP);
    h->payload_file.fd = -1;
    h->data.rhd_resources = resources;
    h->spa = spa;
    h->stage = stage;
    h->batch = batch;
    avl_create(&h->groups, rh_group_cmp, sizeof (rh_group_t),
        offsetof(rh_group_t, link));
    avl_create(&h->nodes, rh_node_cmp, sizeof (rh_node_t),
        offsetof(rh_node_t, link));
    int error = rebuild_owners_open_resources(spa, stage, batch, rh_transform,
        h, resources, &h->owners);
    if (error == 0)
        error = rh_collect(h);
    if (error != 0) {
        rebuild_history_close(h);
        return (error);
    }
    *out = h;
    return (0);
}

int
rebuild_history_open(spa_t *spa, uint64_t stage, size_t batch,
    rebuild_history_t **out)
{
    return (rebuild_history_open_resources(spa, stage, batch, NULL, out));
}

int
rebuild_history_add(rebuild_history_t *h, enum zio_checksum checksum,
    const ddt_key_t *key, const ddt_univ_phys_t *physical, int canonical)
{
    if (h == NULL || key == NULL || physical == NULL || h->prepared ||
        checksum <= ZIO_CHECKSUM_ON || checksum >= ZIO_CHECKSUM_FUNCTIONS ||
        canonical < DDT_PHYS_SINGLE || canonical > DDT_PHYS_TRIPLE)
        return (EINVAL);
    for (int slot = DDT_PHYS_SINGLE; slot <= DDT_PHYS_TRIPLE; slot++) {
        if (ddt_phys_refcnt(physical, slot) == 0)
            continue;
        rh_group_t *g = kmem_zalloc(sizeof (*g), KM_SLEEP);
        ddt_bp_create(checksum, key, physical, slot, &g->bp);
        g->key = *key;
        g->checksum = checksum;
        g->canonical = slot == canonical;
        g->expected = ddt_phys_refcnt(physical, slot);
        avl_index_t index;
        rh_group_t *old = avl_find(&h->groups, g, &index);
        if (old != NULL) {
            int error = old->canonical == g->canonical &&
                old->checksum == g->checksum &&
                memcmp(&old->key, &g->key, sizeof (*key)) == 0 ? 0 : EINVAL;
            kmem_free(g, sizeof (*g));
            if (error != 0)
                return (error);
        } else {
            avl_insert(&h->groups, g, index);
        }
    }
    return (0);
}

int
rebuild_history_check(rebuild_history_t *h)
{
    if (h == NULL)
        return (EINVAL);
    int error = rh_checkpoint_check(h->spa);
    if (error == 0)
        error = rh_source_policy(h);
    if (error != 0)
        return (error);
    h->complete_candidate = B_TRUE;
    boolean_t all_flat = B_TRUE;
    for (unsigned cs = 0; cs < ZIO_CHECKSUM_FUNCTIONS; cs++) {
        ddt_t *ddt = h->spa->spa_ddt[cs];
        if (ddt != NULL && ddt->ddt_version != DDT_VERSION_UNCONFIGURED &&
            (ddt->ddt_version != DDT_VERSION_FDT ||
            ddt->ddt_flags != (DDT_FLAG_FLAT | DDT_FLAG_LOG)))
            all_flat = B_FALSE;
    }
    if (h->data.rhd_map == NULL && all_flat && avl_numnodes(&h->groups) == 0) {
        int error = rebuild_bridge_foreach_flat(h->spa, rh_flat_register, h);
        if (error != 0)
            return (error);
    }
    h->checking = B_TRUE;
    error = 0;
    for (size_t i = 0; error == 0 && i < h->nroots; i++) {
        rh_root_t *r = h->roots[i];
        if (memcmp(dsl_dataset_phys(r->ds), &r->original,
            sizeof (r->original)) != 0) {
            error = ESTALE;
            break;
        }
        if (r->ds->ds_dir->dd_crypto_obj != 0) {
            uint64_t version = 0;
            error = zap_lookup(spa_get_dsl(h->spa)->dp_meta_objset,
                r->ds->ds_dir->dd_crypto_obj, DSL_CRYPTO_KEY_VERSION,
                sizeof (version), 1, &version);
            if (error == 0 && version != ZIO_CRYPT_KEY_CURRENT_VERSION)
                error = ENOTSUP;
            if (error != 0)
                break;
        }
        h->active = r;
        error = rh_zil_prepare(h, r, B_FALSE);
        if (error == 0)
            error = traverse_dataset(r->ds, 0,
                TRAVERSE_POST | (h->data.rhd_map == NULL ?
                TRAVERSE_NO_DECRYPT : 0), rh_visit, h);
    }
    if (error == 0)
        error = rebuild_owners_foreach_destroyed_root(h->owners, rh_destroyed, h);
    h->active = NULL;
    h->checking = B_FALSE;
    if (error == 0 && h->prepared)
        error = rebuild_owners_check(h->owners);
    if (error == 0 && h->data.rhd_map == NULL)
        error = rh_ownership_check(h);
    return (error);
}

int
rebuild_history_check_complete(rebuild_history_t *h, boolean_t *complete)
{
    if (h == NULL || complete == NULL || h->stage != 0)
        return (EINVAL);
    *complete = B_FALSE;
    int error = rebuild_history_check(h);
    if (error != 0)
        return (error);
    for (unsigned cs = 0; cs < ZIO_CHECKSUM_FUNCTIONS; cs++) {
        ddt_t *ddt = h->spa->spa_ddt[cs];
        if (ddt != NULL && ddt->ddt_version != DDT_VERSION_UNCONFIGURED &&
            (ddt->ddt_version != DDT_VERSION_FDT ||
            ddt->ddt_flags != (DDT_FLAG_FLAT | DDT_FLAG_LOG)))
            return (ENOTSUP);
    }
    *complete = h->complete_candidate;
    return (0);
}

static int
rh_event_add(rh_root_t *r, spa_t *spa, const blkptr_t *old,
    const blkptr_t *replacement)
{
    if (memcmp(old, replacement, sizeof (*old)) == 0)
        return (0);
    if (r->resources != NULL) {
        if (r->nbirths > UINT64_MAX / sizeof (rh_birth_delta_t) - 2)
            return (EOVERFLOW);
        if (r->birth_file.fd < 0) {
            int error = dedup_fdt_file_create(r->resources, -1,
                "history-births", &r->birth_file);
            if (error != 0)
                return (error);
        }
        rh_birth_delta_t items[2];
        spa_config_enter(spa, SCL_VDEV, FTAG, RW_READER);
        items[0] = (rh_birth_delta_t) { .birth = BP_GET_BIRTH(old),
            .delta = { -(int64_t)bp_get_dsize_sync(spa, old),
            -(int64_t)BP_GET_PSIZE(old), -(int64_t)BP_GET_UCSIZE(old) } };
        items[1] = (rh_birth_delta_t) { .birth = BP_GET_BIRTH(replacement),
            .delta = { (int64_t)bp_get_dsize_sync(spa, replacement),
            (int64_t)BP_GET_PSIZE(replacement),
            (int64_t)BP_GET_UCSIZE(replacement) } };
        spa_config_exit(spa, SCL_VDEV, FTAG);
        uint64_t offset = r->nbirths * sizeof (items[0]);
        int error = dedup_fdt_file_resize(&r->birth_file,
            offset + sizeof (items));
        if (error == 0)
            error = dedup_fdt_file_pwrite(&r->birth_file, items,
                sizeof (items), offset);
        if (error == 0)
            r->nbirths += 2;
        return (error);
    }
    if (r->nbirths + 2 > r->birth_capacity) {
        size_t capacity = r->birth_capacity == 0 ? 64 : r->birth_capacity * 2;
        if (capacity < r->birth_capacity ||
            capacity > SIZE_MAX / sizeof (*r->births))
            return (EOVERFLOW);
        rh_birth_delta_t *items = kmem_alloc(capacity * sizeof (*items), KM_SLEEP);
        if (r->births != NULL) {
            memcpy(items, r->births, r->nbirths * sizeof (*items));
            kmem_free(r->births, r->birth_capacity * sizeof (*items));
        }
        r->births = items;
        r->birth_capacity = capacity;
    }
    spa_config_enter(spa, SCL_VDEV, FTAG, RW_READER);
    rh_birth_delta_t *a = &r->births[r->nbirths++];
    *a = (rh_birth_delta_t) { .birth = BP_GET_BIRTH(old), .delta = {
        -(int64_t)bp_get_dsize_sync(spa, old), -(int64_t)BP_GET_PSIZE(old),
        -(int64_t)BP_GET_UCSIZE(old) } };
    rh_birth_delta_t *b = &r->births[r->nbirths++];
    *b = (rh_birth_delta_t) { .birth = BP_GET_BIRTH(replacement), .delta = {
        (int64_t)bp_get_dsize_sync(spa, replacement),
        (int64_t)BP_GET_PSIZE(replacement), (int64_t)BP_GET_UCSIZE(replacement) } };
    spa_config_exit(spa, SCL_VDEV, FTAG);
    return (0);
}
static int rh_birth_compare(const void *a, const void *b)
{
    return (TREE_CMP(((const rh_birth_delta_t *)a)->birth,
        ((const rh_birth_delta_t *)b)->birth));
}
static int
rh_birth_prefix(rh_root_t *r)
{
    if (r->nbirths == 0)
        return (0);
    if (r->resources != NULL) {
        dedup_fdt_file_t temporary = { .fd = -1 };
        int error = dedup_fdt_file_create(r->resources, -1,
            "history-birth-sort", &temporary);
        if (error == 0)
            error = dedup_fdt_file_resize(&temporary, r->birth_file.size);
        /* Bottom-up merge requires only two live events regardless of the
         * history size. Cold pages use the common evictable scratch cache. */
        for (size_t width = 1; error == 0 && width < r->nbirths; ) {
            for (size_t start = 0; error == 0 && start < r->nbirths; ) {
                size_t middle = start + MIN(width, r->nbirths - start);
                size_t end = middle + MIN(width, r->nbirths - middle);
                size_t a = start, b = middle;
                rh_birth_delta_t left, right;
                boolean_t have_left = B_FALSE, have_right = B_FALSE;
                for (size_t dest = start; error == 0 && dest < end; dest++) {
                    if (a < middle && !have_left) {
                        error = dedup_fdt_file_pread(&r->birth_file,
                            &left, sizeof (left), a * sizeof (left));
                        have_left = error == 0;
                    }
                    if (error == 0 && b < end && !have_right) {
                        error = dedup_fdt_file_pread(&r->birth_file,
                            &right, sizeof (right), b * sizeof (right));
                        have_right = error == 0;
                    }
                    if (error != 0)
                        break;
                    boolean_t take_left = a < middle &&
                        (b == end || left.birth <= right.birth);
                    rh_birth_delta_t *item = take_left ? &left : &right;
                    error = dedup_fdt_file_pwrite(&temporary, item,
                        sizeof (*item), dest * sizeof (*item));
                    if (take_left) {
                        a++;
                        have_left = B_FALSE;
                    } else {
                        b++;
                        have_right = B_FALSE;
                    }
                }
                start = end;
            }
            if (error == 0) {
                dedup_fdt_file_t swap = r->birth_file;
                r->birth_file = temporary;
                temporary = swap;
            }
            if (width > r->nbirths / 2)
                break;
            width *= 2;
        }
        dedup_fdt_file_close(&temporary);
        rebuild_history_delta_t sum = {0};
        for (size_t i = 0; error == 0 && i < r->nbirths; i++) {
            rh_birth_delta_t item;
            error = dedup_fdt_file_pread(&r->birth_file, &item,
                sizeof (item), i * sizeof (item));
            if (error == 0)
                error = rh_delta_add(&sum.rhd_used, item.delta.rhd_used);
            if (error == 0)
                error = rh_delta_add(&sum.rhd_compressed,
                    item.delta.rhd_compressed);
            if (error == 0)
                error = rh_delta_add(&sum.rhd_uncompressed,
                    item.delta.rhd_uncompressed);
            item.delta = sum;
            if (error == 0)
                error = dedup_fdt_file_pwrite(&r->birth_file, &item,
                    sizeof (item), i * sizeof (item));
        }
        return (error);
    }
    qsort(r->births, r->nbirths, sizeof (*r->births), rh_birth_compare);
    rebuild_history_delta_t sum = {0};
    for (size_t i = 0; i < r->nbirths; i++) {
        int error = rh_delta_add(&sum.rhd_used, r->births[i].delta.rhd_used);
        if (error == 0)
            error = rh_delta_add(&sum.rhd_compressed,
                r->births[i].delta.rhd_compressed);
        if (error == 0)
            error = rh_delta_add(&sum.rhd_uncompressed,
                r->births[i].delta.rhd_uncompressed);
        if (error != 0)
            return (error);
        r->births[i].delta = sum;
    }
    return (0);
}
static int
rh_birth_query(rh_root_t *r, uint64_t birth, rebuild_history_delta_t *out)
{
    size_t lo = 0, hi = r->nbirths;
    *out = (rebuild_history_delta_t){0};
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        rh_birth_delta_t item;
        if (r->resources != NULL) {
            int error = dedup_fdt_file_pread(&r->birth_file, &item,
                sizeof (item), mid * sizeof (item));
            if (error != 0)
                return (error);
        } else {
            item = r->births[mid];
        }
        if (item.birth <= birth) {
            *out = item.delta;
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    return (0);
}

static int
rh_record(rebuild_history_t *h, rh_root_t *r, rh_root_record_t *out)
{
    memset(out, 0, sizeof (*out));
    out->dsobj = r->ds->ds_object;
    out->original = r->original;
    out->prepared = r->prepared;
    out->unique = r->unique;
    out->bookmark_old = r->bookmark_old;
    out->bookmark_new = r->bookmark_new;
    int error = rh_add_signed(r->original.ds_referenced_bytes,
        r->delta.rhd_used, &out->referenced);
    if (error == 0)
        error = rh_add_signed(r->original.ds_compressed_bytes,
            r->delta.rhd_compressed, &out->compressed);
    if (error == 0)
        error = rh_add_signed(r->original.ds_uncompressed_bytes,
            r->delta.rhd_uncompressed, &out->uncompressed);
    (void)h;
    return (error);
}

typedef enum rh_task_kind {
    RH_TASK_INIT, RH_TASK_ROOT, RH_TASK_RETIRE, RH_TASK_READY,
    RH_TASK_DRAIN, RH_TASK_FREE_BOOKMARK, RH_TASK_FINISH,
    RH_TASK_BOOKMARK_CREATE, RH_TASK_BOOKMARK_COPY
} rh_task_kind_t;
typedef struct rh_task {
    rebuild_history_t *h;
    rh_task_kind_t kind;
    rh_root_t *root;
    uint64_t index, object;
    boolean_t published, done;
    const char *name;
    const void *value;
    size_t count;
    int error;
} rh_task_t;

static void
rh_task_sync(void *arg, dmu_tx_t *tx)
{
    rh_task_t *t = arg;
    rebuild_history_t *h = t->h;
    objset_t *mos = spa_get_dsl(h->spa)->dp_meta_objset;
    if (t->kind == RH_TASK_INIT) {
        h->data_birth = dmu_tx_get_txg(tx);
        t->error = rebuild_history_ledger_create(h->spa, tx, &h->ledger);
        if (t->error != 0)
            return;
        h->roots_object = dmu_object_alloc(mos, DMU_OTN_UINT64_METADATA,
            SPA_OLD_MAXBLOCKSIZE, DMU_OT_NONE, 0, tx);
        uint64_t flat = h->flat, ready = 0, count = h->nroots;
        t->error = zap_update(mos, h->stage, RH_LEDGER_KEY, 8, 1, &h->ledger, tx);
        if (t->error == 0)
            t->error = zap_update(mos, h->stage, RH_ROOTS_KEY, 8, 1,
                &h->roots_object, tx);
        if (t->error == 0)
            t->error = zap_update(mos, h->stage, "hist-count", 8, 1, &count, tx);
        if (t->error == 0)
            t->error = zap_update(mos, h->stage, RH_FLAT_KEY, 8, 1, &flat, tx);
        if (t->error == 0)
            t->error = zap_update(mos, h->stage, RH_READY_KEY, 8, 1, &ready, tx);
    } else if (t->kind == RH_TASK_ROOT ||
        t->kind == RH_TASK_BOOKMARK_CREATE) {
        if (t->kind == RH_TASK_BOOKMARK_CREATE)
            t->root->bookmark_new = zap_create_norm(mos, U8_TEXTPREP_TOUPPER,
                DMU_OTN_ZAP_METADATA, DMU_OT_NONE, 0, tx);
        rh_root_record_t record;
        t->error = rh_record(h, t->root, &record);
        if (t->error == 0)
            dmu_write(mos, h->roots_object, t->index * sizeof (record),
                sizeof (record), &record, tx, DMU_READ_NO_PREFETCH);
    } else if (t->kind == RH_TASK_BOOKMARK_COPY) {
        t->error = zap_update(mos, t->root->bookmark_new, t->name, 8,
            t->count, t->value, tx);
    } else if (t->kind == RH_TASK_RETIRE) {
        t->error = rebuild_history_ledger_set_retire(h->spa, h->ledger,
            t->index, B_TRUE, tx);
    } else if (t->kind == RH_TASK_READY) {
        uint64_t ready = 1;
        t->error = zap_update(mos, h->stage, RH_READY_KEY, 8, 1, &ready, tx);
    } else if (t->kind == RH_TASK_DRAIN) {
        t->error = rebuild_history_ledger_drain(h->spa, h->ledger,
            t->published, h->batch, tx, &t->done);
    } else if (t->kind == RH_TASK_FREE_BOOKMARK) {
        rh_root_record_t record;
        t->error = dmu_read(mos, h->roots_object,
            t->index * sizeof (record), sizeof (record), &record,
            DMU_READ_NO_PREFETCH);
        if (t->error != 0)
            return;
        uint64_t *object = t->published ? &record.bookmark_old :
            &record.bookmark_new;
        if (*object != 0 && record.bookmark_new != 0) {
            t->error = dmu_object_free(mos, *object, tx);
            if (t->error != 0)
                return;
        }
        record.bookmark_old = record.bookmark_new = 0;
        dmu_write(mos, h->roots_object, t->index * sizeof (record),
            sizeof (record), &record, tx, DMU_READ_NO_PREFETCH);
    } else if (t->kind == RH_TASK_FINISH) {
        t->error = rebuild_history_ledger_destroy(h->spa, h->ledger, tx);
        if (t->error == 0)
            t->error = dmu_object_free(mos, h->roots_object, tx);
        if (t->error != 0)
            return;
        const char *keys[] = { RH_LEDGER_KEY, RH_ROOTS_KEY, RH_FLAT_KEY,
            RH_READY_KEY, "hist-count" };
        for (unsigned i = 0; i < sizeof (keys) / sizeof (keys[0]); i++) {
            int error = zap_remove(mos, h->stage, keys[i], tx);
            if (error != 0 && error != ENOENT) {
                t->error = error;
                return;
            }
        }
        h->ledger = h->roots_object = 0;
    }
}

static int
rh_run(rh_task_t *task)
{
    if (rebuild_interrupted())
        return (EINTR);
    int error = dsl_sync_task(spa_name(task->h->spa), NULL, rh_task_sync,
        task, 16, task->kind == RH_TASK_DRAIN ||
        task->kind == RH_TASK_FINISH || task->kind == RH_TASK_FREE_BOOKMARK ?
        ZFS_SPACE_CHECK_DESTROY : ZFS_SPACE_CHECK_NORMAL);
    return (error != 0 ? error : task->error);
}

static int
rh_prepare_bookmarks(rebuild_history_t *h, rh_root_t *head, size_t index)
{
    if (head->ds->ds_is_snapshot || head->ds->ds_bookmarks_obj == 0)
        return (0);
    head->bookmark_old = head->ds->ds_bookmarks_obj;
    for (dsl_bookmark_node_t *bm = avl_first(&head->ds->ds_bookmarks);
        bm != NULL; bm = AVL_NEXT(&head->ds->ds_bookmarks, bm)) {
        if (!(bm->dbn_phys.zbm_flags & ZBM_FLAG_HAS_FBN))
            continue;
        rh_root_t *snap = NULL;
        for (rh_root_t *line = head; line->original.ds_prev_snap_obj != 0; ) {
            line = rh_root_find(h, line->original.ds_prev_snap_obj);
            if (line == NULL)
                return (ESTALE);
            if (line->original.ds_guid == bm->dbn_phys.zbm_guid &&
                line->original.ds_creation_txg == bm->dbn_phys.zbm_creation_txg) {
                snap = line;
                break;
            }
        }
        if ((bm->dbn_phys.zbm_flags & ZBM_FLAG_SNAPSHOT_EXISTS) && snap == NULL)
            return (ESTALE);
        rh_root_t *next = head;
        while (next->original.ds_prev_snap_obj != 0) {
            rh_root_t *prev = rh_root_find(h, next->original.ds_prev_snap_obj);
            if (prev == NULL)
                return (ESTALE);
            if (prev->original.ds_creation_txg <= bm->dbn_phys.zbm_creation_txg)
                break;
            next = prev;
        }
        rebuild_owners_space_t before, after;
        int error = rebuild_owners_range(h->owners, next->ds->ds_object,
            B_FALSE, 0, bm->dbn_phys.zbm_creation_txg, &before, &after);
        if (error != 0)
            return (error);
        rebuild_history_delta_t retained;
        error = rh_birth_query(next, bm->dbn_phys.zbm_creation_txg, &retained);
        if (error != 0)
            return (error);
        zfs_bookmark_phys_t value = bm->dbn_phys;
        int64_t du, dc, dx;
        error = rh_unsigned_difference(after.used, before.used, &du);
        if (error == 0)
            error = rh_unsigned_difference(after.compressed,
                before.compressed, &dc);
        if (error == 0)
            error = rh_unsigned_difference(after.uncompressed,
                before.uncompressed, &dx);
        if (error != 0)
            return (error);
        rebuild_history_delta_t reference = retained;
        if (snap != NULL)
            reference = snap->delta;
        else {
            error = rh_delta_add(&reference.rhd_used, du);
            if (error == 0)
                error = rh_delta_add(&reference.rhd_compressed, dc);
            if (error == 0)
                error = rh_delta_add(&reference.rhd_uncompressed, dx);
        }
        if (error == 0)
            error = rh_add_signed(value.zbm_referenced_bytes_refd,
                reference.rhd_used, &value.zbm_referenced_bytes_refd);
        if (error == 0)
            error = rh_add_signed(value.zbm_compressed_bytes_refd,
                reference.rhd_compressed, &value.zbm_compressed_bytes_refd);
        if (error == 0)
            error = rh_add_signed(value.zbm_uncompressed_bytes_refd,
                reference.rhd_uncompressed, &value.zbm_uncompressed_bytes_refd);
        if (error == 0)
            error = rh_add_signed(value.zbm_referenced_freed_before_next_snap,
                du, &value.zbm_referenced_freed_before_next_snap);
        if (error == 0)
            error = rh_add_signed(value.zbm_compressed_freed_before_next_snap,
                dc, &value.zbm_compressed_freed_before_next_snap);
        if (error == 0)
            error = rh_add_signed(value.zbm_uncompressed_freed_before_next_snap,
                dx, &value.zbm_uncompressed_freed_before_next_snap);
        if (error != 0)
            return (error);
        if (memcmp(&value, &bm->dbn_phys, sizeof (value)) != 0) {
            rh_bookmark_change_t *change = rh_heap_alloc(head->resources,
                sizeof (*change));
            if (change == NULL)
                return (ENOMEM);
            change->node = bm;
            change->before = bm->dbn_phys;
            change->after = value;
            change->next = head->bookmarks;
            head->bookmarks = change;
        }
    }
    if (head->bookmarks == NULL)
        return (0);
    rh_task_t create = { .h = h, .kind = RH_TASK_BOOKMARK_CREATE,
        .root = head, .index = index };
    int error = rh_run(&create);
    if (error != 0)
        return (error);
    objset_t *mos = spa_get_dsl(h->spa)->dp_meta_objset;
    zap_cursor_t cursor;
    zap_attribute_t attr;
    zap_cursor_init(&cursor, mos, head->bookmark_old);
    while ((error = zap_cursor_retrieve(&cursor, &attr)) == 0) {
        zfs_bookmark_phys_t value = {0};
        if (attr.za_integer_length != 8 ||
            attr.za_num_integers > sizeof (value) / 8) {
            error = EINVAL;
            break;
        }
        error = zap_lookup(mos, head->bookmark_old, attr.za_name, 8,
            attr.za_num_integers, &value);
        if (error != 0)
            break;
        for (rh_bookmark_change_t *change = head->bookmarks;
            change != NULL; change = change->next)
            if (strcmp(change->node->dbn_name, attr.za_name) == 0) {
                value = change->after;
                break;
            }
        rh_task_t copy = { .h = h, .kind = RH_TASK_BOOKMARK_COPY,
            .root = head, .name = attr.za_name, .value = &value,
            .count = attr.za_num_integers };
        error = rh_run(&copy);
        if (error != 0)
            break;
        zap_cursor_advance(&cursor);
    }
    zap_cursor_fini(&cursor);
    if (error == ENOENT)
        error = 0;
    if (error == 0)
        error = rebuild_owners_stage_scalar(h->owners, head->ds->ds_object,
            DS_FIELD_BOOKMARK_NAMES, head->bookmark_old, head->bookmark_new);
    return (error);
}

static int
rh_unique_prepare(rebuild_history_t *h)
{
    for (size_t i = 0; i < h->nroots; i++) {
        rh_root_t *r = h->roots[i];
        if (r->ds->ds_is_snapshot) {
            uint64_t old_unique;
            int error = rebuild_owners_snapshot_unique(h->owners,
                r->ds->ds_object, &old_unique, &r->unique);
            if (error != 0)
                return (error);
        } else {
            uint64_t referenced;
            int error = rh_add_signed(r->original.ds_referenced_bytes,
                r->delta.rhd_used, &referenced);
            if (error != 0)
                return (error);
            rh_root_t *prev = rh_root_find(h, r->original.ds_prev_snap_obj);
            uint64_t previous = 0;
            if (prev != NULL) {
                error = rh_add_signed(prev->original.ds_referenced_bytes,
                    prev->delta.rhd_used, &previous);
                if (error != 0)
                    return (error);
            } else if (r->original.ds_prev_snap_obj != 0) {
                return (ESTALE);
            }
            rebuild_owners_space_t old_dead, new_dead;
            error = rebuild_owners_range(h->owners, r->ds->ds_object,
                B_FALSE, 0, UINT64_MAX, &old_dead, &new_dead);
            if (error != 0)
                return (error);
            if (new_dead.used > previous || referenced < previous - new_dead.used)
                return (ERANGE);
            r->unique = referenced - (previous - new_dead.used);
        }
    }
    return (0);
}

static int
rh_retire_prepare(rebuild_history_t *h)
{
    for (rh_node_t *node = avl_first(&h->nodes); node != NULL;
        node = AVL_NEXT(&h->nodes, node)) {
        boolean_t survives = node->original_survives;
        rh_variant_t *allocation = NULL;
        for (rh_variant_t *v = node->variants; v != NULL; v = v->next) {
            if (memcmp(&v->bp, &node->old, sizeof (v->bp)) == 0)
                survives = B_TRUE;
            if (v->allocated)
                allocation = v;
        }
        if (!survives && allocation != NULL) {
            rh_task_t task = { .h = h, .kind = RH_TASK_RETIRE,
                .index = allocation->ledger_index };
            int error = rh_run(&task);
            if (error != 0)
                return (error);
        }
    }
    return (0);
}

int
rebuild_history_prepare(rebuild_history_t *h, boolean_t flat)
{
    if (h == NULL || h->stage == 0 || h->ledger != 0 || h->prepared)
        return (EINVAL);
    int eligibility = rh_checkpoint_check(h->spa);
    if (eligibility == 0)
        eligibility = rh_source_policy(h);
    if (eligibility != 0)
        return (eligibility);
    rebuild_owners_close(h->owners);
    h->owners = NULL;
    int error = rebuild_owners_open_resources(h->spa, h->stage, h->batch,
        rh_transform, h, h->data.rhd_resources, &h->owners);
    if (error != 0)
        return (error);
    error = rebuild_owners_begin(h->owners);
    if (error != 0)
        return (error);
    rh_nodes_clear(h);
    error = rh_collect(h);
    if (error != 0)
        return (error);
    h->flat = flat;
    rh_task_t init = { .h = h, .kind = RH_TASK_INIT };
    error = rh_run(&init);
    for (size_t i = 0; error == 0 && i < h->nroots; i++) {
        rh_root_t *root = h->roots[i];
        h->active = root;
        const char *step = "ZIL preparation";
        error = rh_zil_prepare(h, root, B_TRUE);
        if (error == 0) {
            step = "metadata/data traversal";
            error = traverse_dataset(root->ds, 0,
                TRAVERSE_POST | (h->data.rhd_map == NULL ?
                TRAVERSE_NO_DECRYPT : 0), rh_visit, h);
        }
        for (rh_quota_t *q = avl_first(&root->quotas);
            error == 0 && q != NULL; q = AVL_NEXT(&root->quotas, q))
            if (q->delta != 0 && q->found != 1) {
                if (h->data.rhd_map != NULL)
                    fprintf(stderr, "dedup-fdt: quota unresolved owner=%llu "
                        "which=%u id=%llu delta=%lld found=%u\n",
                        (u_longlong_t)root->ds->ds_object, q->which,
                        (u_longlong_t)q->id, (long long)q->delta, q->found);
                step = "quota resolution";
                error = ENOENT;
            }
        if (error == 0) {
            step = "birth-prefix accounting";
            error = rh_birth_prefix(root);
        }
        if (error == 0) {
            step = "root staging";
            rh_task_t task = { .h = h, .kind = RH_TASK_ROOT,
                .root = root, .index = i };
            error = rh_run(&task);
        }
        if (error != 0)
            (void)rh_failure(h, root, step, &root->original.ds_bp, NULL, error);
    }
    h->active = NULL;
    if (error == 0)
        error = rebuild_owners_foreach_destroyed_root(h->owners, rh_destroyed, h);
    if (error == 0)
        error = rh_embedded_deaths(h);
    if (error == 0)
        error = rebuild_owners_prepare(h->owners);
    if (error == 0)
        error = rh_unique_prepare(h);
    for (size_t i = 0; error == 0 && i < h->nroots; i++) {
        error = rh_prepare_bookmarks(h, h->roots[i], i);
        if (error == 0) {
            rh_task_t task = { .h = h, .kind = RH_TASK_ROOT,
                .root = h->roots[i], .index = i };
            error = rh_run(&task);
        }
    }
    if (error == 0)
        error = rh_retire_prepare(h);
    if (error == 0)
        error = rebuild_owners_stage_scalar(h->owners, h->stage, "phase",
            flat ? REBUILD_FLAT_PREPARED : REBUILD_BRIDGE_PREPARED,
            flat ? REBUILD_FLAT_PUBLISHED : REBUILD_BRIDGE_PUBLISHED);
    if (error == 0) {
        rh_task_t ready = { .h = h, .kind = RH_TASK_READY };
        error = rh_run(&ready);
    }
    if (error == 0)
        h->prepared = B_TRUE;
    return (error);
}

int
rebuild_history_publish_check(rebuild_history_t *h, boolean_t flat, dmu_tx_t *tx)
{
    if (h == NULL || tx == NULL || !h->prepared || h->flat != flat ||
        dmu_tx_pool(tx) != spa_get_dsl(h->spa))
        return (EINVAL);
    int eligibility = rh_checkpoint_check(h->spa);
    if (eligibility != 0)
        return (eligibility);
    h->checked_txg = 0;
    rebuild_history_ledger_publish_rele(h->ledger_dbuf);
    h->ledger_dbuf = NULL;
    for (size_t i = 0; i < h->nroots; i++) {
        rh_root_t *r = h->roots[i];
        if (memcmp(dsl_dataset_phys(r->ds), &r->original,
            sizeof (r->original)) != 0)
            return (ESTALE);
        for (rh_bookmark_change_t *b = r->bookmarks; b != NULL; b = b->next)
            if (memcmp(&b->node->dbn_phys, &b->before, sizeof (b->before)) != 0)
                return (ESTALE);
        rh_root_record_t record;
        int error = rh_record(h, r, &record);
        if (error != 0)
            return (error);
        r->referenced = record.referenced;
        r->compressed = record.compressed;
        r->uncompressed = record.uncompressed;
        for (spa_feature_t f = 0; f < SPA_FEATURES; f++)
            if (r->data_features[f] && !spa_feature_is_enabled(h->spa, f))
                return (ENOTSUP);
        error = rebuild_owners_range(h->owners, r->ds->ds_object, B_FALSE,
            r->ds->ds_dir->dd_origin_txg, UINT64_MAX,
            &r->dead_before, &r->dead_after);
        if (error != 0)
            return (error);
        error = rh_unsigned_difference(r->dead_after.used, r->dead_before.used,
            &r->dead_delta.rhd_used);
        if (error == 0)
            error = rh_unsigned_difference(r->dead_after.compressed,
                r->dead_before.compressed, &r->dead_delta.rhd_compressed);
        if (error == 0)
            error = rh_unsigned_difference(r->dead_after.uncompressed,
                r->dead_before.uncompressed, &r->dead_delta.rhd_uncompressed);
        r->head_delta = r->delta;
        if (error == 0 && !r->ds->ds_is_snapshot) {
            rebuild_history_delta_t inherited;
            error = rh_birth_query(r, r->ds->ds_dir->dd_origin_txg, &inherited);
            if (error == 0)
                error = rh_delta_subtract(&r->head_delta.rhd_used,
                    inherited.rhd_used);
            if (error == 0)
                error = rh_delta_subtract(&r->head_delta.rhd_compressed,
                    inherited.rhd_compressed);
            if (error == 0)
                error = rh_delta_subtract(&r->head_delta.rhd_uncompressed,
                    inherited.rhd_uncompressed);
            uint64_t old_unused = r->ds->ds_reserved -
                MIN(r->ds->ds_reserved, r->original.ds_unique_bytes);
            uint64_t new_unused = r->ds->ds_reserved -
                MIN(r->ds->ds_reserved, r->unique);
            if (error == 0)
                error = rh_unsigned_difference(new_unused, old_unused,
                    &r->refreservation_delta);
        }
        if (error != 0)
            return (error);
    }
    int error = rebuild_owners_check(h->owners);
    if (error == 0)
        error = rebuild_history_ledger_publish_hold(h->spa, h->ledger,
            &h->ledger_dbuf, &h->ledger_transfer);
    if (error == 0 && dmu_tx_is_syncing(tx))
        h->checked_txg = dmu_tx_get_txg(tx);
    return (error);
}

int
rebuild_history_publish(rebuild_history_t *h, boolean_t flat, dmu_tx_t *tx)
{
    if (h == NULL || tx == NULL || !h->prepared || h->flat != flat ||
        !dmu_tx_is_syncing(tx) || h->checked_txg != dmu_tx_get_txg(tx) ||
        h->ledger_dbuf == NULL || dmu_tx_pool(tx) != spa_get_dsl(h->spa))
        return (EINVAL);
    rebuild_history_ledger_publish_held(h->spa, h->ledger_dbuf,
        &h->ledger_transfer, tx);
    /*
     * No error-returning validation remains after this point. All roots,
     * native future-free owners, counters and bookmarks join this TXG;
     * the caller joins the bridge roots and durable phase before commit.
     */
    for (size_t i = 0; i < h->nroots; i++) {
        rh_root_t *r = h->roots[i];
        dsl_dataset_t *ds = r->ds;
        if (ds->ds_objset != NULL) {
            dmu_objset_evict(ds->ds_objset);
            ds->ds_objset = NULL;
        }
        r->os = NULL;
        dmu_buf_will_dirty(ds->ds_dbuf, tx);
        rrw_enter(&ds->ds_bp_rwlock, RW_WRITER, h);
        dsl_dataset_phys(ds)->ds_bp = r->prepared;
        rrw_exit(&ds->ds_bp_rwlock, h);
        dsl_dataset_phys(ds)->ds_referenced_bytes = r->referenced;
        dsl_dataset_phys(ds)->ds_compressed_bytes = r->compressed;
        dsl_dataset_phys(ds)->ds_uncompressed_bytes = r->uncompressed;
        dsl_dataset_phys(ds)->ds_unique_bytes = r->unique;
        for (spa_feature_t f = 0; f < SPA_FEATURES; f++) {
            if (!r->data_features[f] || dsl_dataset_feature_is_active(ds, f))
                continue;
            VERIFY3S(spa_feature_table[f].fi_type, ==, ZFEATURE_TYPE_BOOLEAN);
            dsl_dataset_activate_feature(ds->ds_object, f, (void *)B_TRUE, tx);
            ds->ds_feature[f] = (void *)B_TRUE;
        }

        dsl_dir_diduse_space(ds->ds_dir, DD_USED_SNAP,
            r->dead_delta.rhd_used, r->dead_delta.rhd_compressed,
            r->dead_delta.rhd_uncompressed, tx);
        if (!ds->ds_is_snapshot) {
            dsl_dir_diduse_space(ds->ds_dir, DD_USED_HEAD,
                r->head_delta.rhd_used, r->head_delta.rhd_compressed,
                r->head_delta.rhd_uncompressed, tx);
            dsl_dir_diduse_space(ds->ds_dir, DD_USED_REFRSRV,
                r->refreservation_delta, 0, 0, tx);
        }
        if (r->bookmark_new != 0) {
            ds->ds_bookmarks_obj = r->bookmark_new;
            for (rh_bookmark_change_t *b = r->bookmarks; b != NULL; b = b->next)
                b->node->dbn_phys = b->after;
        }
    }
    VERIFY0(rebuild_owners_publish(h->owners, tx));
    h->prepared = B_FALSE;
    h->checked_txg = 0;
    rebuild_history_ledger_publish_rele(h->ledger_dbuf);
    h->ledger_dbuf = NULL;
    return (0);
}

int
rebuild_history_recover(rebuild_history_t *h)
{
    if (h == NULL)
        return (EINVAL);
    int eligibility = rh_checkpoint_check(h->spa);
    if (eligibility != 0)
        return (eligibility);
    if (h->stage == 0)
        return (0);
    h->checked_txg = 0;
    rebuild_history_ledger_publish_rele(h->ledger_dbuf);
    h->ledger_dbuf = NULL;
    int error = rebuild_owners_recover(h->owners);
    if (error != 0)
        return (error);
    objset_t *mos = spa_get_dsl(h->spa)->dp_meta_objset;
    uint64_t ledger = 0;
    error = zap_lookup(mos, h->stage, RH_LEDGER_KEY, 8, 1, &ledger);
    if (error == ENOENT)
        return (0);
    if (error != 0)
        return (error);
    h->ledger = ledger;
    uint64_t flat, phase, count;
    error = zap_lookup(mos, h->stage, RH_ROOTS_KEY, 8, 1, &h->roots_object);
    if (error == 0)
        error = zap_lookup(mos, h->stage, RH_FLAT_KEY, 8, 1, &flat);
    if (error == 0)
        error = zap_lookup(mos, h->stage, "phase", 8, 1, &phase);
    if (error == 0)
        error = zap_lookup(mos, h->stage, "hist-count", 8, 1, &count);
    if (error != 0)
        return (error);
    boolean_t published = flat ? phase >= REBUILD_FLAT_PUBLISHED :
        phase >= REBUILD_BRIDGE_PUBLISHED;
    for (;;) {
        rh_task_t task = { .h = h, .kind = RH_TASK_DRAIN,
            .published = published };
        error = rh_run(&task);
        if (error != 0)
            return (error);
        if (task.done)
            break;
    }
    for (uint64_t i = 0; i < count; i++) {
        rh_task_t task = { .h = h, .kind = RH_TASK_FREE_BOOKMARK,
            .index = i, .published = published };
        error = rh_run(&task);
        if (error != 0)
            return (error);
    }
    rh_task_t finish = { .h = h, .kind = RH_TASK_FINISH };
    error = rh_run(&finish);
    if (error == 0) {
        h->prepared = B_FALSE;
        rh_nodes_clear(h);
        error = rh_collect(h);
    }
    return (error);
}

void
rebuild_history_close(rebuild_history_t *h)
{
    if (h == NULL)
        return;
    rebuild_history_ledger_publish_rele(h->ledger_dbuf);
    rebuild_owners_close(h->owners);
    rh_nodes_clear(h);
    rh_roots_clear(h);
    void *cookie = NULL;
    rh_group_t *g;
    while ((g = avl_destroy_nodes(&h->groups, &cookie)) != NULL)
        kmem_free(g, sizeof (*g));
    avl_destroy(&h->groups);
    avl_destroy(&h->nodes);
    kmem_free(h, sizeof (*h));
}

static int
rh_zil_inventory(const rebuild_zil_ref_t *ref, void *arg)
{
    rebuild_history_t *h = arg;
    if (ref->rzr_role == REBUILD_ZIL_BLOCK) {
        if (!h->checking && h->active != NULL && h->active->zil_prepared &&
            !ref->rzr_replaced) {
            rh_node_t key = { .old = ref->rzr_bp };
            avl_index_t where;
            rh_node_t *node = avl_find(&h->nodes, &key, &where);
            if (node == NULL) {
                node = rh_heap_alloc(h->data.rhd_resources, sizeof (*node));
                if (node == NULL)
                    return (ENOMEM);
                node->old = ref->rzr_bp;
                avl_insert(&h->nodes, node, where);
            }
            node->original_survives = B_TRUE;
        }
        return (0);
    }
    if (!ref->rzr_release)
        return (0);
    blkptr_t mapped;
    return (rh_policy(h, &ref->rzr_bp, &mapped));
}

static int
rh_zil_transform(void *arg, uint64_t owner, const blkptr_t *old,
    blkptr_t *out)
{
    rebuild_history_t *h = arg;
    if (h->data.rhd_map != NULL) {
        int error = h->data.rhd_map(h->data.rhd_arg, owner, old, out);
        return (error == ENOENT ? (*out = *old, 0) : error);
    }
    return (rh_policy(h, old, out));
}

static int
rh_zil_append(void *arg, const rebuild_history_record_t *source, dmu_tx_t *tx)
{
    rebuild_history_t *h = arg;
    rebuild_history_record_t record = *source;
    record.rhr_retire_original = B_FALSE;
    uint64_t index;
    int error = rebuild_history_ledger_append(h->spa, h->ledger,
        &record, tx, &index);
    if (error != 0)
        return (error);
    rh_node_t key = { .old = record.rhr_original };
    avl_index_t where;
    rh_node_t *node = avl_find(&h->nodes, &key, &where);
    if (node == NULL) {
        node = rh_heap_alloc(h->data.rhd_resources, sizeof (*node));
        if (node == NULL)
            return (ENOMEM);
        node->old = record.rhr_original;
        avl_insert(&h->nodes, node, where);
    }
    rh_variant_t *v = rh_heap_alloc(h->data.rhd_resources, sizeof (*v));
    if (v == NULL)
        return (ENOMEM);
    v->bp = record.rhr_published;
    v->allocated = B_TRUE;
    v->ledger_index = index;
    error = rh_member_add(h, v, 0);
    if (error != 0) {
        rh_heap_free(h->data.rhd_resources, v, sizeof (*v));
        return (error);
    }
    v->next = node->variants;
    node->variants = v;
    return (0);
}

static int
rh_zil_prepare(rebuild_history_t *h, rh_root_t *root, boolean_t write)
{
    if (root->destroyed || root->ds->ds_is_snapshot ||
        BP_IS_HOLE(&root->original.ds_bp))
        return (0);
    if (root->os == NULL) {
        int error = rh_get_os(h, root);
        if (error != 0)
            return (error);
    }
    rebuild_zil_t *plan = NULL;
    int error = rebuild_zil_open(root->os,
        &root->os->os_phys->os_zil_header, &plan);
    if (error == 0 && h->data.rhd_map != NULL && !write &&
        root->os->os_phys->os_zil_header.zh_claim_txg == 0 &&
        !BP_IS_HOLE(&root->os->os_phys->os_zil_header.zh_log)) {
        if (rebuild_zil_has_records(plan)) {
            fprintf(stderr, "dedup-fdt: unclaimed ZIL contains actual "
                "records; replay it before offline deduplication\n");
            error = ENOTSUP;
        } else {
            h->needs_claim = B_TRUE;
        }
    }
    if (error == 0)
        error = rebuild_zil_visit(plan, rh_zil_inventory, h);
    if (error == 0 && write) {
        if (h->data.rhd_map != NULL)
            error = rebuild_zil_prepare_data(plan, rh_zil_transform, h,
                rh_zil_append, h, &root->prepared_zil);
        else
            error = rebuild_zil_prepare(plan, rh_zil_transform, h,
                rh_zil_append, h, &root->prepared_zil);
        root->zil_prepared = (error == 0);
        if (error == 0)
            error = rebuild_zil_visit(plan, rh_zil_inventory, h);
    }
    rebuild_zil_close(plan);
    return (error);
}

static int
rh_flat_register(void *arg, enum zio_checksum checksum, const ddt_key_t *key,
    const ddt_univ_phys_t *physical)
{
    rebuild_history_t *h = arg;
    if (physical->ddp_flat.ddp_phys_birth == 0)
        return (physical->ddp_flat.ddp_refcnt == 0 ? 0 : EINVAL);
    rh_group_t *g = kmem_zalloc(sizeof (*g), KM_SLEEP);
    ddt_bp_create(checksum, key, physical, DDT_PHYS_FLAT, &g->bp);
    g->key = *key;
    g->checksum = checksum;
    g->canonical = B_TRUE;
    g->expected = physical->ddp_flat.ddp_refcnt;
    avl_index_t where;
    if (avl_find(&h->groups, g, &where) != NULL) {
        kmem_free(g, sizeof (*g));
        return (EINVAL);
    }
    avl_insert(&h->groups, g, where);
    return (0);
}

typedef struct rh_owned {
    avl_node_t link;
    blkptr_t bp;
    uint64_t allocations, frees;
    boolean_t different_dvas;
} rh_owned_t;
typedef struct rh_owned_context {
    rebuild_history_t *h;
    avl_tree_t tree;
} rh_owned_context_t;
static int rh_owned_compare(const void *a, const void *b)
{
    return (rh_data_identity(&((const rh_owned_t *)a)->bp,
        &((const rh_owned_t *)b)->bp));
}
static int
rh_owned_add(rh_owned_context_t *ctx, const blkptr_t *bp, boolean_t freed)
{
    if (BP_IS_HOLE(bp) || BP_IS_EMBEDDED(bp) || BP_IS_REDACTED(bp) ||
        BP_IS_METADATA(bp))
        return (0);
    rh_owned_t key = { .bp = *bp };
    avl_index_t where;
    rh_owned_t *value = avl_find(&ctx->tree, &key, &where);
    if (value == NULL) {
        value = kmem_zalloc(sizeof (*value), KM_SLEEP);
        value->bp = *bp;
        avl_insert(&ctx->tree, value, where);
    }
    if (!rh_data_prefix(bp, &value->bp) ||
        !rh_data_prefix(&value->bp, bp))
        value->different_dvas = B_TRUE;
    uint64_t *count = freed ? &value->frees : &value->allocations;
    if (*count == UINT64_MAX)
        return (EOVERFLOW);
    (*count)++;
    return (0);
}
static int
rh_owned_bp(spa_t *spa, zilog_t *zilog, const blkptr_t *bp,
    const zbookmark_phys_t *zb, const dnode_phys_t *dnp, void *arg)
{
    (void)spa, (void)zilog, (void)dnp;
    if (rebuild_interrupted())
        return (EINTR);
    if (zb->zb_level == ZB_DNODE_LEVEL || zb->zb_level == ZB_ZIL_LEVEL)
        return (0);
    return (rh_owned_add(arg, bp, B_FALSE));
}
static int
rh_owned_source(void *arg, uint64_t owner, rebuild_owners_role_t role,
    const blkptr_t *bp, boolean_t freed)
{
    blkptr_t mapped;
    int error = rh_transform(((rh_owned_context_t *)arg)->h,
        owner, bp, &mapped);
    if (error != 0)
        return (error);
    if (role == REBUILD_OWNER_PENDINGFREE || role == REBUILD_OWNER_DEFERRED ||
        role == REBUILD_OWNER_DESTROYED ||
        (role == REBUILD_OWNER_LIVELIST && owner == 0))
        return (rh_owned_add(arg, bp, freed));
    return (0);
}
static int
rh_owned_zil(const rebuild_zil_ref_t *ref, void *arg)
{
    return (ref->rzr_release && ref->rzr_role != REBUILD_ZIL_BLOCK ?
        rh_owned_add(arg, &ref->rzr_bp, B_FALSE) : 0);
}
static int
rh_ownership_check(rebuild_history_t *h)
{
    rh_owned_context_t ctx = { .h = h };
    avl_create(&ctx.tree, rh_owned_compare, sizeof (rh_owned_t),
        offsetof(rh_owned_t, link));
    int error = 0;
    for (size_t i = 0; error == 0 && i < h->nroots; i++) {
        rh_root_t *r = h->roots[i];
        error = traverse_dataset(r->ds, r->original.ds_prev_snap_txg,
            TRAVERSE_POST | TRAVERSE_NO_DECRYPT, rh_owned_bp, &ctx);
        if (error == 0 && !r->ds->ds_is_snapshot &&
            !BP_IS_HOLE(&r->original.ds_bp)) {
            if (r->os == NULL)
                error = rh_get_os(h, r);
            rebuild_zil_t *zil = NULL;
            if (error == 0)
                error = rebuild_zil_open(r->os,
                    &r->os->os_phys->os_zil_header, &zil);
            if (error == 0)
                error = rebuild_zil_visit(zil, rh_owned_zil, &ctx);
            rebuild_zil_close(zil);
        }
    }
    if (error == 0)
        error = rebuild_owners_foreach_source(h->owners, rh_owned_source, &ctx);
    for (rh_group_t *g = avl_first(&h->groups); error == 0 && g != NULL;
        g = AVL_NEXT(&h->groups, g)) {
        rh_owned_t key = { .bp = g->bp };
        rh_owned_t *owned = avl_find(&ctx.tree, &key, NULL);
        uint64_t count = 0;
        if (owned != NULL) {
            if (owned->frees > owned->allocations) {
                error = EINVAL;
                break;
            }
            count = owned->allocations - owned->frees;
        }
        if (count != g->expected) {
            error = EINVAL;
            break;
        }
        if (count == 0)
            continue;
        uint64_t ddt_count, extra;
        error = rh_native_ddt_count(h, &g->bp, &ddt_count);
        if (error == 0)
            error = rebuild_native_brt_refcount(h->spa, &g->bp, &extra);
        if (error != 0)
            break;
        if ((ddt_count != 0 && (ddt_count != count || extra != 0)) ||
            (ddt_count == 0 && (extra != count - 1 ||
            (owned != NULL && owned->different_dvas))))
            error = EINVAL;
    }
    for (rh_owned_t *owned = avl_first(&ctx.tree); error == 0 && owned != NULL;
        owned = AVL_NEXT(&ctx.tree, owned)) {
        if (owned->frees > owned->allocations) {
            error = EINVAL;
            break;
        }
        uint64_t count = owned->allocations - owned->frees;
        rh_group_t key = { .bp = owned->bp };
        if (avl_find(&h->groups, &key, NULL) == NULL && count != 0) {
            uint64_t extra;
            error = rebuild_native_brt_refcount(h->spa, &owned->bp, &extra);
            if (error == 0 && (owned->different_dvas || extra != count - 1))
                error = EINVAL;
        }
    }
    void *cookie = NULL;
    rh_owned_t *owned;
    while ((owned = avl_destroy_nodes(&ctx.tree, &cookie)) != NULL)
        kmem_free(owned, sizeof (*owned));
    avl_destroy(&ctx.tree);
    return (error);
}

static int
rh_seen_compare(const void *a, const void *b)
{
    const zbookmark_phys_t *x = &((const rh_seen_t *)a)->bookmark;
    const zbookmark_phys_t *y = &((const rh_seen_t *)b)->bookmark;
    int c = TREE_CMP(x->zb_object, y->zb_object);
    if (c == 0)
        c = TREE_CMP(x->zb_level, y->zb_level);
    return (c != 0 ? c : TREE_CMP(x->zb_blkid, y->zb_blkid));
}

static int
rh_seen_add(rh_root_t *r, const zbookmark_phys_t *bookmark)
{
    rh_seen_t key = { .bookmark = *bookmark };
    avl_index_t where;
    if (avl_find(&r->seen, &key, &where) == NULL) {
        rh_seen_t *value = rh_heap_alloc(r->resources, sizeof (*value));
        if (value == NULL)
            return (ENOMEM);
        value->bookmark = *bookmark;
        avl_insert(&r->seen, value, where);
    }
    return (0);
}

static int
rh_map_at(rebuild_history_t *h, rh_root_t *root, uint64_t context,
    const zbookmark_phys_t *bookmark, const blkptr_t *old, blkptr_t *out,
    int64_t *delta)
{
    if (root->destroyed) {
        rh_seen_t key = { .bookmark = *bookmark };
        if (avl_find(&root->seen, &key, NULL) == NULL) {
            *out = *old;
            *delta = 0;
            return (0);
        }
    }
    if (BP_IS_EMBEDDED(old) && BP_IS_METADATA(old) && !root->destroyed) {
        rh_location_t *location = rh_location_find(root, bookmark);
        if (location == NULL ||
            memcmp(&location->node->old, old, sizeof (*old)) != 0)
            return (ESTALE);
        *out = location->variant->bp;
        *delta = location->variant->object_delta;
        return (0);
    }
    return (rh_map(h, context, old, out, delta));
}

static int
rh_get_os(rebuild_history_t *h, rh_root_t *r)
{
    if (r->os != NULL)
        return (0);
    dsl_pool_t *dp = spa_get_dsl(h->spa);
    boolean_t held = dsl_pool_config_held(dp);
    if (!held)
        dsl_pool_config_enter(dp, h);
    int error = dmu_objset_from_ds(r->ds, &r->os);
    if (!held)
        dsl_pool_config_exit(dp, h);
    return (error);
}

static int
rh_native_ddt_count(rebuild_history_t *h, const blkptr_t *bp, uint64_t *count)
{
    return (rebuild_native_ddt_refcount(h->spa, bp, count));
}

static boolean_t
rh_can_share(rebuild_history_t *h, rh_node_t *node,
    rh_variant_t *variant, rh_root_t *root)
{
    if (root->destroyed ||
        rh_root_find(h, root->original.ds_prev_snap_obj) == NULL)
        return (B_FALSE);
    /* A prior death cannot be undone by equal bytes later in the lineage. */
    rh_variant_t *previous = rh_find_variant(node,
        root->original.ds_prev_snap_obj);
    return (previous == variant);
}

static boolean_t
rh_payload_equal(const blkptr_t *bp, const void *a, const void *b, size_t size)
{
    if (BP_GET_TYPE(bp) != DMU_OT_OBJSET)
        return (memcmp(a, b, size) == 0);
    size_t begin = offsetof(objset_phys_t, os_portable_mac);
    size_t end = offsetof(objset_phys_t, os_local_mac) + ZIO_OBJSET_MAC_LEN;
    return (size >= end && memcmp(a, b, begin) == 0 &&
        memcmp((const char *)a + end, (const char *)b + end, size - end) == 0);
}

static uint64_t
rh_dnode_max_birth(const dnode_phys_t *dnp)
{
    uint64_t birth = 0;
    if (dnp->dn_type == DMU_OT_NONE)
        return (0);
    for (unsigned i = 0; i < dnp->dn_nblkptr; i++)
        birth = MAX(birth, BP_GET_BIRTH(&dnp->dn_blkptr[i]));
    if (dnp->dn_flags & DNODE_FLAG_SPILL_BLKPTR)
        birth = MAX(birth, BP_GET_BIRTH(DN_SPILL_BLKPTR(dnp)));
    return (birth);
}

static uint64_t
rh_max_child_birth(const blkptr_t *bp, const void *payload, size_t size)
{
    uint64_t birth = 0;
    if (BP_GET_LEVEL(bp) > 0) {
        const blkptr_t *children = payload;
        for (size_t i = 0; i < size / sizeof (*children); i++)
            birth = MAX(birth, BP_GET_BIRTH(&children[i]));
    } else if (BP_GET_TYPE(bp) == DMU_OT_DNODE) {
        for (size_t offset = 0; offset < size; ) {
            const dnode_phys_t *dn = (const void *)((const char *)payload + offset);
            birth = MAX(birth, rh_dnode_max_birth(dn));
            offset += ((size_t)dn->dn_extra_slots + 1) * DNODE_MIN_SIZE;
        }
    } else if (BP_GET_TYPE(bp) == DMU_OT_OBJSET) {
        const objset_phys_t *osp = payload;
        birth = rh_dnode_max_birth(&osp->os_meta_dnode);
        if (size >= OBJSET_PHYS_SIZE_V2) {
            birth = MAX(birth, rh_dnode_max_birth(&osp->os_userused_dnode));
            birth = MAX(birth, rh_dnode_max_birth(&osp->os_groupused_dnode));
        }
        if (size >= OBJSET_PHYS_SIZE_V3)
            birth = MAX(birth, rh_dnode_max_birth(&osp->os_projectused_dnode));
    }
    return (birth);
}

static rh_location_t *
rh_location_find(rh_root_t *root, const zbookmark_phys_t *bookmark)
{
    if (root == NULL || root->destroyed)
        return (NULL);
    rh_location_t key = { .bookmark = *bookmark };
    return (avl_find(&root->locations, &key, NULL));
}

static int
rh_location_add(rh_root_t *root, const zbookmark_phys_t *bookmark,
    rh_node_t *node, rh_variant_t *variant)
{
    rh_location_t key = { .bookmark = *bookmark };
    avl_index_t where;
    if (avl_find(&root->locations, &key, &where) != NULL)
        return (EINVAL);
    rh_location_t *value = rh_heap_alloc(root->resources, sizeof (*value));
    if (value == NULL)
        return (ENOMEM);
    value->bookmark = *bookmark;
    value->node = node;
    value->variant = variant;
    avl_insert(&root->locations, value, where);
    return (0);
}

static int
rh_embedded_deaths(rebuild_history_t *h)
{
    for (size_t i = 0; i < h->nroots; i++) {
        rh_root_t *root = h->roots[i];
        if (!root->ds->ds_is_snapshot || root->original.ds_next_snap_obj == 0)
            continue;
        rh_root_t *next = rh_root_find(h, root->original.ds_next_snap_obj);
        if (next == NULL)
            return (ESTALE);
        for (rh_location_t *location = avl_first(&root->locations);
            location != NULL; location = AVL_NEXT(&root->locations, location)) {
            rh_variant_t *variant = location->variant;
            if (!variant->allocated || BP_IS_EMBEDDED(&variant->bp))
                continue;
            rh_location_t *successor = rh_location_find(next,
                &location->bookmark);
            if (successor != NULL && successor->node == location->node)
                continue;
            int error = rebuild_owners_insert_dead(h->owners,
                next->ds->ds_object, &variant->bp);
            if (error != 0)
                return (error);
            dsl_dir_t *dir = root->ds->ds_dir;
            if (dsl_deadlist_is_open(&dir->dd_livelist) &&
                BP_GET_BIRTH(&variant->bp) > dir->dd_origin_txg) {
                error = rebuild_owners_insert_livelist(h->owners,
                    dsl_dir_phys(dir)->dd_head_dataset_obj, &variant->bp, B_TRUE);
                if (error != 0)
                    return (error);
            }
        }
    }
    return (0);
}

static int
rh_unsigned_difference(uint64_t newer, uint64_t older, int64_t *out)
{
    uint64_t magnitude = newer >= older ? newer - older : older - newer;
    if (magnitude > INT64_MAX)
        return (EOVERFLOW);
    *out = newer >= older ? (int64_t)magnitude : -(int64_t)magnitude;
    return (0);
}

static int
rh_delta_subtract(int64_t *value, int64_t sub)
{
    if (sub == INT64_MIN) {
        if (*value >= 0)
            return (EOVERFLOW);
        *value = (*value + INT64_MAX) + 1;
        return (0);
    }
    return (rh_delta_add(value, -sub));
}

static int
rh_data_identity(const blkptr_t *a, const blkptr_t *b)
{
    int order = TREE_CMP(BP_GET_PHYSICAL_BIRTH(a), BP_GET_PHYSICAL_BIRTH(b));
    if (order == 0)
        order = TREE_CMP(a->blk_dva[0].dva_word[0], b->blk_dva[0].dva_word[0]);
    if (order == 0)
        order = TREE_CMP(a->blk_dva[0].dva_word[1], b->blk_dva[0].dva_word[1]);
    return (order);
}

static boolean_t
rh_data_prefix(const blkptr_t *bp, const blkptr_t *physical)
{
    unsigned count = BP_GET_NDVAS(bp);
    if (count == 0 || count > BP_GET_NDVAS(physical))
        return (B_FALSE);
    for (unsigned i = 0; i < count; i++)
        if (!DVA_EQUAL(&bp->blk_dva[i], &physical->blk_dva[i]))
            return (B_FALSE);
    return (B_TRUE);
}

static int
rh_check_bit(rebuild_history_t *h, const blkptr_t *bp, const rh_group_t *group)
{
    boolean_t canonical = group != NULL && group->canonical;
    if (BP_GET_DEDUP(bp) != canonical)
        h->complete_candidate = B_FALSE;
    if (h->actual_policy == 3 && group != NULL && !BP_GET_DEDUP(bp))
        return (EINVAL);
    if (h->actual_policy == 1 && BP_GET_DEDUP(bp))
        return (EINVAL);
    if (h->actual_policy == 2 && BP_GET_DEDUP(bp) !=
        (group != NULL && group->canonical))
        return (EINVAL);
    return (0);
}

static int
rh_checkpoint_check(spa_t *spa)
{
    /* A discarded checkpoint can still retain its physical allocations. */
    return (spa_has_checkpoint(spa) || spa->spa_checkpoint_txg != 0 ||
        spa_feature_is_active(spa, SPA_FEATURE_POOL_CHECKPOINT) ? ENOTSUP : 0);
}

static int
rh_source_policy(rebuild_history_t *h)
{
    if (h->data.rhd_map != NULL)
        return (0);
    h->actual_policy = 3;
    if (h->stage == 0)
        return (0);
    uint64_t phase;
    int error = zap_lookup(spa_get_dsl(h->spa)->dp_meta_objset,
        h->stage, "phase", 8, 1, &phase);
    if (error != 0)
        return (error);
    if (phase >= REBUILD_FLAT_PUBLISHED)
        h->actual_policy = 2;
    else if (phase >= REBUILD_BRIDGE_PUBLISHED)
        h->actual_policy = 1;
    return (0);
}

int
rebuild_history_set_data_ops(rebuild_history_t *h,
    const rebuild_history_data_ops_t *ops)
{
    if (h == NULL || ops == NULL || ops->rhd_map == NULL ||
        ops->rhd_variant == NULL || h->ledger != 0 || h->prepared ||
        ops->rhd_resources == NULL || avl_numnodes(&h->groups) != 0 ||
        ops->rhd_resources != h->data.rhd_resources)
        return (EINVAL);
    int error = rebuild_owners_set_resources(h->owners, ops->rhd_resources);
    if (error == 0)
        h->data = *ops;
    return (error);
}

/*
 * Data aliases have no new allocation of their own. Keep their contextual
 * BPs in the caller's bounded disk index, not in the metadata DAG's AVL.
 * A divergent inherited allocation has exactly the same birth/death edges
 * as a divergent COW metadata variant; only allocation ownership differs.
 */
static int
rh_data_prepare(rebuild_history_t *h, rh_root_t *root,
    const blkptr_t *old, blkptr_t *out)
{
    *out = *old;
    if (root->destroyed)
        return (0);
    uint64_t owner = root->ds->ds_object;
    int error = h->data.rhd_map(h->data.rhd_arg, owner, old, out);
    if (error == ENOENT)
        return (0);
    if (error != 0)
        return (rh_failure(h, root, "data mapping", old, NULL, error));
    if (BP_IS_HOLE(out) || BP_IS_EMBEDDED(out) || BP_IS_REDACTED(out) ||
        BP_IS_METADATA(out) || BP_GET_LEVEL(old) != BP_GET_LEVEL(out) ||
        BP_GET_TYPE(old) != BP_GET_TYPE(out) ||
        BP_GET_LSIZE(old) != BP_GET_LSIZE(out) ||
        BP_GET_BYTEORDER(old) != BP_GET_BYTEORDER(out) ||
        BP_USES_CRYPT(old) != BP_USES_CRYPT(out) ||
        BP_GET_NDVAS(old) > BP_GET_NDVAS(out) ||
        BP_GET_BIRTH(old) != BP_GET_BIRTH(out))
        return (EINVAL);
    spa_feature_t feature = zio_checksum_to_feature(BP_GET_CHECKSUM(out));
    if (feature != SPA_FEATURE_NONE)
        root->data_features[feature] = B_TRUE;
    feature = zio_compress_to_feature(BP_GET_COMPRESS(out));
    if (feature != SPA_FEATURE_NONE)
        root->data_features[feature] = B_TRUE;

    blkptr_t previous;
    boolean_t inherited = BP_GET_BIRTH(old) <= root->original.ds_prev_snap_txg;
    boolean_t split = B_FALSE;
    if (inherited) {
        error = h->data.rhd_variant(h->data.rhd_arg,
            root->original.ds_prev_snap_obj, old, &previous, B_FALSE);
        if (error != 0)
            return (rh_failure(h, root, "previous contextual data alias",
                old, NULL, error == ENOENT ? ESTALE : error));
        blkptr_t normalized = previous;
        BP_SET_BIRTH(&normalized, BP_GET_BIRTH(old),
            BP_GET_PHYSICAL_BIRTH(&previous));
        split = memcmp(&normalized, out, sizeof (*out)) != 0;
        if (!split) {
            *out = previous;
        } else {
            uint64_t birth = root->ds->ds_is_snapshot ?
                MAX(BP_GET_BIRTH(old), root->original.ds_prev_snap_txg + 1) :
                h->data_birth;
            if (birth == 0 || (root->ds->ds_is_snapshot &&
                birth > root->original.ds_creation_txg))
                return (EINVAL);
            uint64_t physical_birth = BP_GET_PHYSICAL_BIRTH(out);
            BP_SET_BIRTH(out, birth, physical_birth);
            error = rebuild_owners_insert_dead(h->owners, owner, &previous);
            if (error != 0)
                return (rh_failure(h, root, "data deadlist insertion",
                    old, NULL, error));
        }
    }
    if (split && dsl_deadlist_is_open(&root->ds->ds_dir->dd_livelist)) {
        uint64_t head = dsl_dir_phys(root->ds->ds_dir)->dd_head_dataset_obj;
        uint64_t origin = root->ds->ds_dir->dd_origin_txg;
        if (BP_GET_BIRTH(&previous) > origin)
            error = rebuild_owners_insert_livelist(h->owners, head,
                &previous, B_TRUE);
        if (error == 0 && BP_GET_BIRTH(out) > origin)
            error = rebuild_owners_insert_livelist(h->owners, head,
                out, B_FALSE);
        if (error != 0)
            return (rh_failure(h, root, "data livelist insertion",
                old, NULL, error));
    }
    error = h->data.rhd_variant(h->data.rhd_arg, owner, old, out, B_TRUE);
    return (rh_failure(h, root, "contextual data alias store", old, NULL, error));
}

typedef struct rh_data_walk {
    rebuild_history_t *h;
    rebuild_history_data_visit_f *visit;
    void *arg;
    rh_root_t *root;
} rh_data_walk_t;

static int
rh_data_emit(rh_data_walk_t *walk, uint64_t owner,
    const zbookmark_phys_t *bookmark, const blkptr_t *bp, unsigned flags)
{
    if (BP_IS_METADATA(bp) || BP_IS_HOLE(bp) || BP_IS_EMBEDDED(bp) ||
        BP_IS_REDACTED(bp))
        return (0);
    return (walk->visit(walk->arg, owner, bookmark, bp, flags));
}

static int
rh_data_walk_bp(spa_t *spa, zilog_t *zil, const blkptr_t *bp,
    const zbookmark_phys_t *bookmark, const dnode_phys_t *dnode, void *arg)
{
    (void)spa, (void)zil, (void)dnode;
    rh_data_walk_t *walk = arg;
    if (rebuild_interrupted())
        return (EINTR);
    if (bookmark->zb_level != ZB_DNODE_LEVEL &&
        bookmark->zb_level != ZB_ZIL_LEVEL && BP_IS_METADATA(bp) &&
        walk->h->data.rhd_metadata != NULL)
        walk->h->data.rhd_metadata(walk->h->data.rhd_arg, bp);
    if (bookmark->zb_level == ZB_DNODE_LEVEL ||
        bookmark->zb_level == ZB_ZIL_LEVEL || BP_IS_METADATA(bp) ||
        BP_IS_HOLE(bp) || BP_IS_EMBEDDED(bp) || BP_IS_REDACTED(bp))
        return (0);
    uint64_t owner = walk->root->destroyed ? ZB_DESTROYED_OBJSET :
        walk->root->ds->ds_object;
    unsigned flags = walk->root->destroyed ||
        BP_GET_BIRTH(bp) > walk->root->original.ds_prev_snap_txg ?
        REBUILD_DATA_OWNER : 0;
    return (rh_data_emit(walk, owner, bookmark, bp, flags));
}

static int
rh_data_walk_zil(const rebuild_zil_ref_t *ref, void *arg)
{
    rh_data_walk_t *walk = arg;
    if (ref->rzr_role == REBUILD_ZIL_BLOCK)
        return (0);
    uint64_t owner = walk->root->ds->ds_object;
    return (rh_data_emit(walk, owner, &ref->rzr_bookmark, &ref->rzr_bp,
        REBUILD_DATA_ZIL | (ref->rzr_release ? REBUILD_DATA_OWNER : 0)));
}

static int
rh_data_walk_aux(void *arg, uint64_t owner, rebuild_owners_role_t role,
    const blkptr_t *bp, boolean_t freed)
{
    rh_data_walk_t *walk = arg;
    unsigned flags = REBUILD_DATA_AUXILIARY;
    if (role == REBUILD_OWNER_PENDINGFREE || role == REBUILD_OWNER_DEFERRED ||
        role == REBUILD_OWNER_DESTROYED ||
        (role == REBUILD_OWNER_LIVELIST && owner == 0))
        flags |= REBUILD_DATA_OWNER | (freed ? REBUILD_DATA_FREE : 0);
    return (rh_data_emit(walk, owner, NULL, bp, flags));
}


int
rebuild_history_foreach_data(rebuild_history_t *h, boolean_t prepared,
    rebuild_history_data_visit_f *visit, void *arg)
{
    if (h == NULL || visit == NULL || h->data.rhd_map == NULL ||
        (prepared && !h->prepared))
        return (EINVAL);
    rh_data_walk_t walk = { .h = h, .visit = visit, .arg = arg };
    int error = 0;
    for (size_t i = 0; error == 0 && i < h->nroots; i++) {
        rh_root_t *root = walk.root = h->roots[i];
        if (prepared)
            error = dedup_fdt_traverse_root(root->ds, &root->prepared, 0,
                TRAVERSE_POST, rh_data_walk_bp, &walk);
        else
            error = traverse_dataset(root->ds, 0,
                TRAVERSE_POST | TRAVERSE_NO_DECRYPT, rh_data_walk_bp, &walk);
        if (error != 0)
            (void)rh_failure(h, root, prepared ? "prepared data traversal" :
                "source data traversal", prepared ? &root->prepared :
                &root->original.ds_bp, NULL, error);
        if (error == 0 && !root->ds->ds_is_snapshot &&
            !BP_IS_HOLE(&root->original.ds_bp)) {
            error = rh_get_os(h, root);
            rebuild_zil_t *zil = NULL;
            if (error == 0)
                error = rebuild_zil_open(root->os,
                    prepared && root->zil_prepared ? &root->prepared_zil :
                    &root->os->os_phys->os_zil_header, &zil);
            if (error == 0)
                error = rebuild_zil_visit(zil, rh_data_walk_zil, &walk);
            rebuild_zil_close(zil);
            if (error != 0)
                (void)rh_failure(h, root, "ownership ZIL traversal",
                    &root->original.ds_bp, NULL, error);
        }
    }
    if (error == 0) {
        error = prepared ?
            rebuild_owners_foreach_prepared(h->owners, rh_data_walk_aux, &walk) :
            rebuild_owners_foreach_source(h->owners, rh_data_walk_aux, &walk);
        if (error != 0)
            (void)rh_failure(h, NULL, prepared ? "prepared future-free owners" :
                "source future-free owners", NULL, NULL, error);
    }
    return (error);
}

boolean_t
rebuild_history_needs_claim(const rebuild_history_t *h)
{
    return (h != NULL && h->needs_claim);
}
