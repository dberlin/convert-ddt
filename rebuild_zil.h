/* SPDX-License-Identifier: CDDL-1.0 */
#ifndef REBUILD_ZIL_H
#define REBUILD_ZIL_H

#include "rebuild_history_native.h"
#include <sys/dmu_objset.h>
#include <sys/zil.h>

typedef struct rebuild_zil rebuild_zil_t;

typedef enum rebuild_zil_role {
    REBUILD_ZIL_BLOCK,
    REBUILD_ZIL_WRITE,
    REBUILD_ZIL_CLONE
} rebuild_zil_role_t;

typedef struct rebuild_zil_ref {
    blkptr_t rzr_bp;
    zbookmark_phys_t rzr_bookmark;
    uint64_t rzr_record_seq;
    rebuild_zil_role_t rzr_role;
    /* Exactly the references consumed by native zil_free_log_record(). */
    boolean_t rzr_release;
    /* This original log-block occurrence is absent from the prepared chain. */
    boolean_t rzr_replaced;
} rebuild_zil_ref_t;

typedef int rebuild_zil_visit_f(const rebuild_zil_ref_t *, void *);
typedef int rebuild_zil_transform_f(void *, uint64_t, const blkptr_t *,
    blkptr_t *);
/* Append the full record in this SAME syncing TXG; do not publish roots. */
typedef int rebuild_zil_append_f(void *, const rebuild_history_record_t *,
    dmu_tx_t *);

/* Original os dataset ID and its loaded native key mapping are required. */
int rebuild_zil_open(objset_t *, const zil_header_t *, rebuild_zil_t **);
int rebuild_zil_visit(rebuild_zil_t *, rebuild_zil_visit_f *, void *);
/* Actual parsed records, excluding allocated/unwritten terminal LWB stubs. */
boolean_t rebuild_zil_has_records(const rebuild_zil_t *);
/* Each COW block and its durable owner commit in one bounded sync task. */
int rebuild_zil_prepare(rebuild_zil_t *, rebuild_zil_transform_f *, void *,
    rebuild_zil_append_f *, void *, zil_header_t *);
/* Verified arbitrary-data policy only. Claim/release eligibility and logical
 * birth remain unchanged, so the same native records own future releases. */
int rebuild_zil_prepare_data(rebuild_zil_t *, rebuild_zil_transform_f *, void *,
    rebuild_zil_append_f *, void *, zil_header_t *);
void rebuild_zil_close(rebuild_zil_t *);

/* Payload is decrypted ARC/host-word-order log data, not raw ciphertext. */
int rebuild_zil_cow_write(objset_t *, const blkptr_t *, abd_t *,
    const zbookmark_phys_t *, rebuild_zil_append_f *, void *, dmu_tx_t *,
    blkptr_t *, rebuild_history_delta_t *);

#endif
