/* SPDX-License-Identifier: CDDL-1.0 */
#ifndef REBUILD_HISTORY_NATIVE_H
#define REBUILD_HISTORY_NATIVE_H

#include <sys/spa.h>
#include <sys/dmu.h>
#include <sys/zio.h>
#include <sys/abd.h>

/*
 * OpenZFS 2.4.4 allocation primitive, not an all-dataset rewrite facade.
 * The ledger object is ordinary MOS metadata. Its referenced allocations
 * MUST additionally be visited with rebuild_history_ledger_visit() by the
 * fenced maintenance importer. A stock importer does not know this owner.
 */
typedef struct rebuild_history_record {
    blkptr_t rhr_original;
    blkptr_t rhr_allocation;
    blkptr_t rhr_published;
    zbookmark_phys_t rhr_bookmark;
    uint64_t rhr_retire_original;
} rebuild_history_record_t;

typedef struct rebuild_history_delta {
    int64_t rhd_used;
    int64_t rhd_compressed;
    int64_t rhd_uncompressed;
} rebuild_history_delta_t;

typedef int rebuild_history_owner_f(const blkptr_t *, void *);

typedef struct rebuild_history_write_options {
    uint64_t rhw_logical_birth;
    boolean_t rhw_retire_original;
    /* Host-order raw DNODE/OBJSET fields with unchanged ciphertext and MACs. */
    abd_t *rhw_original_raw;
} rebuild_history_write_options_t;

/* All mutations require a syncing transaction belonging to spa. */
int rebuild_history_ledger_create(spa_t *, dmu_tx_t *, uint64_t *);
int rebuild_history_ledger_read(spa_t *, uint64_t, uint64_t,
    rebuild_history_record_t *);
int rebuild_history_ledger_count(spa_t *, uint64_t, uint64_t *);
int rebuild_history_ledger_visit(spa_t *, uint64_t, boolean_t,
    rebuild_history_owner_f *, void *);
int rebuild_history_ledger_set_retire(spa_t *, uint64_t, uint64_t,
    boolean_t, dmu_tx_t *);
int rebuild_history_ledger_append(spa_t *, uint64_t,
    const rebuild_history_record_t *, dmu_tx_t *, uint64_t *);
int rebuild_history_ledger_publish_hold(spa_t *, uint64_t, dmu_buf_t **,
    rebuild_history_delta_t *);
void rebuild_history_ledger_publish_held(spa_t *, dmu_buf_t *,
    const rebuild_history_delta_t *, dmu_tx_t *);
void rebuild_history_ledger_publish_rele(dmu_buf_t *);

/*
 * Caller supplies host-byteorder logical metadata, or validated raw
 * DNODE/OBJSET payloads, and the original dataset bookmark. It rejects dedup,
 * nopwrite, BRT, physical-rewrite, and direct-write requests. It allocates new
 * space, persists both BP representations, then returns the historical BP.
 * It neither publishes roots nor frees original allocations. Distinct
 * context-specific replacements may share an original BP, but exactly ONE
 * record may own retirement of that original allocation. Every replacement
 * independently owns its new allocation for prepublication abort.
 */
int rebuild_history_cow_write(spa_t *, const blkptr_t *, abd_t *,
    const zio_prop_t *, const zbookmark_phys_t *, uint64_t, dmu_tx_t *,
    blkptr_t *, rebuild_history_delta_t *);
int rebuild_history_cow_write_ex(spa_t *, const blkptr_t *, abd_t *,
    const zio_prop_t *, const zbookmark_phys_t *, uint64_t, dmu_tx_t *,
    const rebuild_history_write_options_t *, blkptr_t *,
    rebuild_history_delta_t *);
int rebuild_history_portable_bp_equal(const blkptr_t *, const blkptr_t *);
int rebuild_history_portable_dnode_equal(const void *, const void *, size_t);

/*
 * Advance an abort/retirement cursor in the same transaction as each free.
 * published=false frees new allocations using allocation-era birth; true
 * frees only obsolete metadata blocks, never recursively their children.
 * The publication decision MUST come from the atomically published phase.
 * done is true only when this ledger is drained. Ledger destruction is a
 * separate explicit operation so recovery never loses its cursor owner.
 */
int rebuild_history_ledger_drain(spa_t *, uint64_t, boolean_t, size_t,
    dmu_tx_t *, boolean_t *);
int rebuild_history_ledger_destroy(spa_t *, uint64_t, dmu_tx_t *);

#endif
