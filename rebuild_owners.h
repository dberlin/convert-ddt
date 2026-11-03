/* SPDX-License-Identifier: CDDL-1.0 */
#ifndef REBUILD_OWNERS_H
#define REBUILD_OWNERS_H

#include <sys/spa.h>
#include <sys/dmu.h>
#include <sys/zio.h>
#include "dedup_fdt_resources.h"

typedef struct rebuild_owners rebuild_owners_t;
typedef int rebuild_owners_transform_f(void *, uint64_t, const blkptr_t *,
    blkptr_t *);
typedef struct rebuild_owners_space {
    uint64_t used, compressed, uncompressed;
} rebuild_owners_space_t;

typedef enum rebuild_owners_role {
    REBUILD_OWNER_DEADLIST,
    REBUILD_OWNER_REMAP,
    REBUILD_OWNER_LIVELIST,
    REBUILD_OWNER_PENDINGFREE,
    REBUILD_OWNER_OBSOLETE,
    REBUILD_OWNER_DESTROYED,
    REBUILD_OWNER_DEFERRED
} rebuild_owners_role_t;
typedef int rebuild_owners_destroyed_f(void *, const blkptr_t *, uint64_t,
    const zbookmark_phys_t *);
rebuild_owners_role_t rebuild_owners_role(const rebuild_owners_t *);
int rebuild_owners_foreach_destroyed_root(rebuild_owners_t *,
    rebuild_owners_destroyed_f *, void *);
typedef int rebuild_owners_visit_f(void *, uint64_t, rebuild_owners_role_t,
    const blkptr_t *, boolean_t);
/* Readonly complete future-free manifest, including ALLOC/FREE multiplicity
 * and only the remaining (not already freed) asyncdestroy subtree suffix. */
int rebuild_owners_foreach_source(rebuild_owners_t *,
    rebuild_owners_visit_f *, void *);
/* Actual staged native manifests, including inserted historical ALLOC/FREE
 * edges. No transform callback is applied during this ownership audit. */
int rebuild_owners_foreach_prepared(rebuild_owners_t *,
    rebuild_owners_visit_f *, void *);
typedef int rebuild_owners_identity_f(void *, uint64_t, uint64_t,
    rebuild_owners_role_t, const char *, uint64_t);
/* Stable native owner-link identities for fenced pre-import attestations. */
int rebuild_owners_foreach_identity(rebuild_owners_t *,
    rebuild_owners_identity_f *, void *);
/* Explicit data mode only; legacy rebuild retains its original allocation
 * path. Attach before any additional historical insertion edges. */
int rebuild_owners_set_resources(rebuild_owners_t *,
    dedup_fdt_resources_t *);
/* Additional ownership edges caused by contextual metadata divergence.
 * Inserted BPs are already final, and are not transformed a second time. */
int rebuild_owners_insert_dead(rebuild_owners_t *, uint64_t,
    const blkptr_t *);
int rebuild_owners_insert_livelist(rebuild_owners_t *, uint64_t,
    const blkptr_t *, boolean_t);

/* Call outside syncing context, with maintenance fence and all keys loaded.
 * owner_dsobj is the dataset object; pool BPOBJs use 0 and destroyed trees
 * use ZB_DESTROYED_OBJSET. The callback must resolve the original physical
 * metadata map, including destroyed-tree descendants, not just clear D. */
/* stage == 0 admits read-only inventory only; begin requires durable staging. */
int rebuild_owners_open(spa_t *, uint64_t, size_t,
    rebuild_owners_transform_f *, void *, rebuild_owners_t **);
int rebuild_owners_open_resources(spa_t *, uint64_t, size_t,
    rebuild_owners_transform_f *, void *, dedup_fdt_resources_t *,
    rebuild_owners_t **);
/* First assigned task, BEFORE history ledger/root allocation tasks: detach
 * the original deferred-free owner into durable quarantine. Readonly source
 * iteration and extra ownership-edge insertion remain valid after begin. */
int rebuild_owners_begin(rebuild_owners_t *);
int rebuild_owners_prepare(rebuild_owners_t *);
/* Stage an existing 8-byte MOS ZAP field after prepare, before final check.
 * The caller durably owns any objects named by these scalar values; owners
 * neither tracks nor frees them. Registration invalidates earlier preflight. */
int rebuild_owners_stage_scalar(rebuild_owners_t *, uint64_t, const char *,
    uint64_t, uint64_t);
int rebuild_owners_check(rebuild_owners_t *);
/* check() retains native dataset/directory refs, shadow bonus buffers and
 * existing fixed-width MOS ZAP buffers. Run it in the caller's publication
 * preflight BEFORE the first historical root mutation. Only a syncing check
 * enables publish in that same TXG; open-mode checks only validate/hold.
 * publish consumes preflight without link rechecks or lazy native reopen I/O.
 * Caller publishes roots and durable global phase in this same TXG. */
int rebuild_owners_publish(rebuild_owners_t *, dmu_tx_t *);
/* Discard unpublished shadows or retire published OLD METADATA ONLY.
 * Bounded syncing tasks; never traverses/enqueues/frees leaf allocations. */
int rebuild_owners_recover(rebuild_owners_t *);
void rebuild_owners_close(rebuild_owners_t *);

/* Native deadlist ranges: min < logical birth <= max. On new-format lists,
 * boundaries are retained native snapshot/bookmark keys (or UINT64_MAX).
 * Actual source/shadow totals drive DSL unique, DD_HEAD/SNAP and bookmarks. */
int rebuild_owners_range(rebuild_owners_t *, uint64_t, boolean_t,
    uint64_t, uint64_t, rebuild_owners_space_t *, rebuild_owners_space_t *);
/* For snapshots this uses the PRIMARY NEXT dataset's deadlist over
 * (snapshot.prev_snap_txg, UINT64_MAX], exactly like native DSL accounting.
 * Head unique must be calculated from its referenced/previous/dead totals. */
int rebuild_owners_snapshot_unique(rebuild_owners_t *, uint64_t,
    uint64_t *, uint64_t *);

#endif
