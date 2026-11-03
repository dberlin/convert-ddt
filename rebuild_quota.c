/* SPDX-License-Identifier: CDDL-1.0 */
#include <sys/zfs_context.h>
#include <sys/dmu_objset.h>
#include <sys/sa_impl.h>
#include <sys/zap_impl.h>
#include <sys/zap_leaf.h>
#include <sys/zfs_project.h>
#include <sys/zfs_znode.h>
#include <sys/zfs_sa.h>

#include "rebuild_quota.h"

/*
 * Match OpenZFS 2.4.4 zpl_get_file_info(), not the mounted ZPL's translated
 * POSIX IDs.  Quota keys contain the complete native 64-bit FUID.  Unlike
 * that callback, this readonly entry point knows and checks the buffer size.
 * The SA offsets below are the native SA_*_OFFSET definitions used by that
 * callback, not an assumed SA attribute registration order.
 */
static int
quota_decode_ids(dmu_object_type_t type, const void *data, size_t size,
    uint64_t *uid, uint64_t *gid, uint64_t *proj)
{
    uint64_t user, group, project = ZFS_DEFAULT_PROJID;

    if (type == DMU_OT_ZNODE) {
        if (size < sizeof (znode_phys_t))
            return (EINVAL);
        const znode_phys_t *zp = data;
        user = zp->zp_uid;
        group = zp->zp_gid;
    } else if (type == DMU_OT_SA) {
        if (size < sizeof (sa_hdr_phys_t))
            return (EINVAL);
        sa_hdr_phys_t header;
        memcpy(&header, data, sizeof (header));
        if (header.sa_magic == 0) {
            /* The native callback's not-yet-populated SA case. */
            user = group = 0;
        } else {
            boolean_t swap = header.sa_magic == BSWAP_32(SA_MAGIC);
            if (swap) {
                header.sa_magic = SA_MAGIC;
                header.sa_layout_info = BSWAP_16(header.sa_layout_info);
            }
            if (header.sa_magic != SA_MAGIC)
                return (EINVAL);
            size_t hdrsize = SA_HDR_SIZE((&header));
            if (hdrsize < sizeof (header) || hdrsize > size ||
                size - hdrsize < SA_FLAGS_OFFSET + sizeof (uint64_t))
                return (EINVAL);
            const uint8_t *attrs = (const uint8_t *)data + hdrsize;
            uint64_t flags;
            memcpy(&user, attrs + SA_UID_OFFSET, sizeof (user));
            memcpy(&group, attrs + SA_GID_OFFSET, sizeof (group));
            memcpy(&flags, attrs + SA_FLAGS_OFFSET, sizeof (flags));
            if (swap) {
                user = BSWAP_64(user);
                group = BSWAP_64(group);
                flags = BSWAP_64(flags);
            }
            if (flags & ZFS_PROJID) {
                if (size - hdrsize < SA_PROJID_OFFSET + sizeof (project))
                    return (EINVAL);
                memcpy(&project, attrs + SA_PROJID_OFFSET,
                    sizeof (project));
                if (swap)
                    project = BSWAP_64(project);
            }
        }
    } else {
        return (EINVAL);
    }
    *uid = user;
    *gid = group;
    *proj = project;
    return (0);
}

int
rebuild_history_quota_ids(objset_t *original, uint64_t object,
    const dnode_phys_t *dnp, uint64_t *uid, uint64_t *gid, uint64_t *proj)
{
    if (original == NULL || dnp == NULL || uid == NULL || gid == NULL ||
        proj == NULL)
        return (EINVAL);
    if (DMU_OBJECT_IS_SPECIAL(object) ||
        dmu_objset_type(original) != DMU_OST_ZFS ||
        !(dnp->dn_flags & DNODE_FLAG_USERUSED_ACCOUNTED))
        return (ENOENT);
    if (dnp->dn_type == DMU_OT_NONE ||
        (dnp->dn_bonustype != DMU_OT_ZNODE && dnp->dn_bonustype != DMU_OT_SA))
        return (EINVAL);
    /* Normal DMU holds decrypt the original bonus/spill using its mapping. */
    dmu_buf_t *bonus = NULL, *spill = NULL;
    int error = dmu_bonus_hold(original, object, FTAG, &bonus);
    if (error != 0)
        return (error == ENOENT ? ESTALE : error);
    if (dmu_get_bonustype(bonus) != dnp->dn_bonustype) {
        error = ESTALE;
        goto out;
    }
    const void *data;
    size_t size;
    if (dnp->dn_bonuslen != 0) {
        if (dnp->dn_bonuslen > bonus->db_size) {
            error = EINVAL;
            goto out;
        }
        data = bonus->db_data;
        size = dnp->dn_bonuslen;
    } else {
        if (dnp->dn_bonustype != DMU_OT_SA ||
            !(dnp->dn_flags & DNODE_FLAG_SPILL_BLKPTR)) {
            error = EINVAL;
            goto out;
        }
        /* Never instantiate a missing spill buffer or use MUST_SUCCEED IO. */
        error = dmu_spill_hold_existing(bonus, FTAG, &spill);
        if (error != 0) {
            if (error == ENOENT)
                error = EINVAL;
            goto out;
        }
        data = spill->db_data;
        size = spill->db_size;
    }
    error = quota_decode_ids(dnp->dn_bonustype, data, size, uid, gid, proj);
out:
    if (spill != NULL)
        dmu_buf_rele(spill, FTAG);
    dmu_buf_rele(bonus, FTAG);
    return (error);
}

static int
quota_increment(uint64_t old, int64_t delta, uint64_t *value)
{
    uint64_t next;
    if (delta < 0) {
        /* Negating INT64_MIN directly would overflow signed arithmetic. */
        uint64_t magnitude = (uint64_t)(-(delta + 1)) + 1;
        if (old < magnitude)
            return (ERANGE);
        next = old - magnitude;
    } else {
        if (old > UINT64_MAX - (uint64_t)delta)
            return (EOVERFLOW);
        next = old + (uint64_t)delta;
    }
    if (old < DNODE_MIN_SIZE || next < DNODE_MIN_SIZE)
        return (ERANGE);
    *value = next;
    return (0);
}

static int
quota_micro_patch(mzap_phys_t *mz, size_t size, const char *name,
    size_t namelen, int64_t delta, boolean_t *found)
{
    if (size < sizeof (*mz) ||
        (size - sizeof (*mz)) % sizeof (mzap_ent_phys_t) != 0 ||
        mz->mz_normflags != 0)
        return (EINVAL);
    size_t count = (size - sizeof (*mz)) / sizeof (mzap_ent_phys_t);
    mzap_ent_phys_t *match = NULL;
    for (size_t i = 0; i < count; i++) {
        mzap_ent_phys_t *entry = &mz->mz_chunk[i];
        if (memcmp(entry->mze_name, name, namelen + 1) != 0)
            continue;
        if (match != NULL)
            return (EINVAL);
        match = entry;
    }
    if (match == NULL)
        return (0);
    uint64_t value;
    int error = quota_increment(match->mze_value, delta, &value);
    if (error != 0)
        return (error);
    match->mze_value = value;
    *found = B_TRUE;
    return (0);
}

static int
quota_leaf_patch(void *data, size_t size, const char *name,
    size_t namelen, int64_t delta, boolean_t *found)
{
    dmu_buf_t db = { 0 };
    zap_leaf_t leaf = { 0 };
    db.db_data = data;
    db.db_size = size;
    leaf.l_dbuf = &db;
    leaf.l_bs = highbit64(size) - 1;
    zap_leaf_phys_t *phys = zap_leaf_phys(&leaf);
    uint_t nchunks = ZAP_LEAF_NUMCHUNKS(&leaf);
    if (phys->l_hdr.lh_magic != ZAP_LEAF_MAGIC || nchunks > UINT16_MAX ||
        phys->l_hdr.lh_nentries > nchunks ||
        phys->l_hdr.lh_nfree > nchunks)
        return (EINVAL);

    uint16_t match = UINT16_MAX;
    for (uint_t i = 0; i < nchunks; i++) {
        struct zap_leaf_entry *entry = ZAP_LEAF_ENTRY(&leaf, i);
        if (entry->le_type != ZAP_CHUNK_ENTRY ||
            entry->le_name_numints != namelen + 1)
            continue;
        /* A quota ID and terminator fit entirely in one native array chunk. */
        if (entry->le_name_chunk >= nchunks)
            return (EINVAL);
        struct zap_leaf_array *array =
            &ZAP_LEAF_CHUNK(&leaf, entry->le_name_chunk).l_array;
        if (array->la_type != ZAP_CHUNK_ARRAY || array->la_next != UINT16_MAX)
            return (EINVAL);
        if (memcmp(array->la_array, name, namelen + 1) != 0)
            continue;
        if (match != UINT16_MAX || entry->le_value_intlen != 8 ||
            entry->le_value_numints != 1 || entry->le_value_chunk >= nchunks)
            return (EINVAL);
        struct zap_leaf_array *value_array =
            &ZAP_LEAF_CHUNK(&leaf, entry->le_value_chunk).l_array;
        if (entry->le_name_chunk == entry->le_value_chunk ||
            value_array->la_type != ZAP_CHUNK_ARRAY ||
            value_array->la_next != UINT16_MAX)
            return (EINVAL);
        match = i;
    }
    if (match == UINT16_MAX)
        return (0);
    if (phys->l_hdr.lh_nentries == 0 || phys->l_hdr.lh_nfree >= nchunks)
        return (EINVAL);

    /* This is the same fake handle native zap_leaf_lookup_closest() returns. */
    struct zap_leaf_entry *entry = ZAP_LEAF_ENTRY(&leaf, match);
    zap_entry_handle_t handle = { 0 };
    handle.zeh_leaf = &leaf;
    handle.zeh_fakechunk = match;
    handle.zeh_chunkp = &handle.zeh_fakechunk;
    handle.zeh_num_integers = entry->le_value_numints;
    handle.zeh_integer_size = entry->le_value_intlen;
    handle.zeh_hash = entry->le_hash;
    handle.zeh_cd = entry->le_cd;
    uint64_t old, value;
    int error = zap_entry_read(&handle, 8, 1, &old);
    if (error != 0)
        return (error);
    error = quota_increment(old, delta, &value);
    if (error != 0)
        return (error);
    if (delta != 0) {
        /* Same-sized scalar replacement cannot need a new chunk or split. */
        error = zap_entry_update(&handle, 8, 1, &value);
        if (error != 0)
            return (error);
    }
    *found = B_TRUE;
    return (0);
}

int
rebuild_history_quota_patch(void *hostleaf, size_t size, const char *uidhex,
    int64_t delta, boolean_t *found)
{
    if (found == NULL)
        return (EINVAL);
    *found = B_FALSE;
    if (hostleaf == NULL || uidhex == NULL || size < SPA_MINBLOCKSIZE ||
        size > SPA_MAXBLOCKSIZE || !ISP2(size))
        return (EINVAL);
    size_t len = strnlen(uidhex, 17);
    if (len == 0 || len > 16 || (len > 1 && uidhex[0] == '0'))
        return (EINVAL);
    for (size_t i = 0; i < len; i++)
        if (!((uidhex[i] >= '0' && uidhex[i] <= '9') ||
            (uidhex[i] >= 'a' && uidhex[i] <= 'f')))
            return (EINVAL);
    uint64_t type;
    memcpy(&type, hostleaf, sizeof (type));
    if (type == ZBT_MICRO)
        return (quota_micro_patch(hostleaf, size, uidhex, len, delta, found));
    if (type == ZBT_LEAF)
        return (quota_leaf_patch(hostleaf, size, uidhex, len, delta, found));
    /* Fat ZAP header and external pointer-table blocks carry no values. */
    return (0);
}
