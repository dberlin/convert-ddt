/* SPDX-License-Identifier: CDDL-1.0 */
#ifndef REBUILD_BRIDGE_H
#define REBUILD_BRIDGE_H

#include <sys/ddt.h>
#include <sys/dmu_tx.h>
#include <sys/brt_impl.h>

typedef struct rebuild_bridge rebuild_bridge_t;

/* All callers must fence the pool against ordinary I/O and background frees. */
int rebuild_bridge_check(spa_t *, const ddt_key_t *,
    const ddt_univ_phys_t *, enum zio_checksum);

/* Read-only effective FDT view: active log > flushing log > stored entry.
 * Zero-ref/pending-free and cleared log records are emitted unchanged.
 * The fenced caller and callback must not mutate the pool or retain pointers.
 */
typedef int (*rebuild_bridge_flat_callback_t)(void *, enum zio_checksum,
    const ddt_key_t *, const ddt_univ_phys_t *);
int rebuild_bridge_foreach_flat(spa_t *, rebuild_bridge_flat_callback_t, void *);

/* stage=0 is read-only preflight. The indexed source is borrowed, immutable
 * until close, and must be registered again on every open (also recovery).
 * prepare() does bounded assigned sync tasks; publish() does only root swaps,
 * feature transitions and in-core replacement in the caller's transaction.
 * recover() discards unpublished roots or retires published predecessors.
 */
int rebuild_bridge_open(spa_t *, uint64_t stage, size_t batch,
    rebuild_bridge_t **);
/* Writable admission creates only stage-owned FINAL FDT class ZAPs. The
 * final source/BRT binding and prepare reuse these objects; no data BP is
 * published or treated as owned by these provisional metadata rows. */
int rebuild_bridge_admit_open(spa_t *, uint64_t, size_t,
    rebuild_bridge_t **);
int rebuild_bridge_admit(rebuild_bridge_t *, enum zio_checksum,
    const ddt_key_t *, const ddt_univ_phys_t *, boolean_t *);
typedef int (*rebuild_bridge_reader_t)(void *, uint64_t,
    enum zio_checksum *, ddt_key_t *, ddt_univ_phys_t *, int *);
int rebuild_bridge_set_source(rebuild_bridge_t *, rebuild_bridge_reader_t,
    void *, uint64_t count);
/* Already-FDT mutation: reader emits the complete effective replacement,
 * including untouched zero-ref/pending records. Ordinary/BRT adjustments are
 * separately typed and use observed before/after EXTRA reference counts.
 */
typedef int (*rebuild_bridge_brt_reader_t)(void *, uint64_t,
    blkptr_t *, uint64_t *, uint64_t *);
int rebuild_bridge_set_flat_source(rebuild_bridge_t *,
    rebuild_bridge_reader_t, void *, uint64_t,
    rebuild_bridge_brt_reader_t, void *, uint64_t);
int rebuild_bridge_validate(rebuild_bridge_t *);
int rebuild_bridge_prepare(rebuild_bridge_t *, boolean_t flat);
/* Invoke in the shared sync-task check, before either engine publishes.
 * The syncing invocation pins commit metadata through this TXG's publish.
 */
int rebuild_bridge_publish_check(rebuild_bridge_t *, boolean_t, dmu_tx_t *);
int rebuild_bridge_publish(rebuild_bridge_t *, boolean_t flat, dmu_tx_t *);
int rebuild_bridge_recover(rebuild_bridge_t *);
void rebuild_bridge_close(rebuild_bridge_t *);

/* Exact-source wrapper interface, not a second on-disk implementation. */
int rebuild_native_brt_load(spa_t *, uint64_t, uint64_t, brt_vdev_t **);
void rebuild_native_brt_close(brt_vdev_t *);
int rebuild_native_brt_count(spa_t *, brt_vdev_t *, const blkptr_t *, uint64_t *);
/* Live-memory overlay plus persistent BRT, without loading entries to a tree. */
int rebuild_native_brt_refcount(spa_t *, const blkptr_t *, uint64_t *);
int rebuild_native_brt_set_encoded(spa_t *, brt_vdev_t *, const blkptr_t *,
    uint64_t, uint64_t, boolean_t, dmu_tx_t *);
void rebuild_native_brt_adopt(spa_t *, brt_vdev_t **, uint64_t);
void rebuild_native_brt_flush(spa_t *, brt_vdev_t *, dmu_tx_t *);
int rebuild_native_ddt_match(spa_t *, enum zio_checksum, const ddt_key_t *,
    const ddt_univ_phys_t *);
/* Pure physical membership lookup; absent/pruned generations return count=0. */
int rebuild_native_ddt_refcount(spa_t *, const blkptr_t *, uint64_t *);
int rebuild_native_ddt_stage(spa_t *, enum zio_checksum, uint64_t,
    uint64_t, ddt_t **);
void rebuild_native_ddt_release(ddt_t *);
void rebuild_native_ddt_adopt(spa_t *, enum zio_checksum, ddt_t *);

#endif
