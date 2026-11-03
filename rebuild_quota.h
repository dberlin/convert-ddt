/* SPDX-License-Identifier: CDDL-1.0 */
#ifndef REBUILD_QUOTA_H
#define REBUILD_QUOTA_H

#include <sys/dmu.h>
#include <sys/dnode.h>

/*
 * Read IDs from the original, readonly, key-mapped objset.  dnp is the
 * original host-byteorder dnode core; its bonus need not be decrypted.
 * ENOENT means this object does not participate in byte accounting (special
 * object, non-ZPL objset, or USERUSED_ACCOUNTED clear).  No outputs change
 * on error.  A retained accounted object's dsize delta is charged unchanged
 * to UID and GID, and to project only when project accounting is enabled.
 * USEROBJUSED_ACCOUNTED never produces an object-count delta here: neither
 * object existence, owner, nor DNODE_MIN_SIZE changes in this operation.
 */
int rebuild_history_quota_ids(objset_t *original, uint64_t object,
    const dnode_phys_t *dnp, uint64_t *uid, uint64_t *gid, uint64_t *proj);

/*
 * Patch one caller-owned, decrypted, host-byteorder quota ZAP payload.
 * uidhex is a canonical native lowercase hexadecimal uint64 ID, NOT an
 * object-count ("obj-...") key.  Unknown blocks, headers, pointer tables,
 * and leaves without this ID succeed with found=false.  A matching scalar
 * uint64 entry is incremented with the native zap_entry_read/update codec.
 * No input bytes change on error.  found is true on a successful match,
 * including delta==0.  No original dbuf is dirtied or written.
 *
 * No-new-entry/no-removal proof: the caller changes only dn_used for existing
 * USERUSED_ACCOUNTED objects, without changing IDs/accounted flags/existence.
 * Each such object already contributes DNODE_MIN_SIZE + old dn_used to its
 * owner, and still contributes at least DNODE_MIN_SIZE after replacement.
 * Therefore its owner entry exists and cannot become zero.  The caller MUST
 * find exactly one matching entry across the original special object's
 * blocks for every nonzero aggregated delta, and reject a missing entry.
 * This routine rejects wraparound and results below DNODE_MIN_SIZE before
 * mutation.  Thus there is never an insertion, deletion, ZAP entry-count
 * change, or object-count-key change to propagate into a ZAP header.
 */
int rebuild_history_quota_patch(void *hostleaf, size_t size,
    const char *uidhex, int64_t delta, boolean_t *found);

#endif /* REBUILD_QUOTA_H */
