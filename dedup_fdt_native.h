/* SPDX-License-Identifier: CDDL-1.0 */
#ifndef DEDUP_FDT_NATIVE_H
#define DEDUP_FDT_NATIVE_H
#include <sys/spa.h>
#include <sys/dmu.h>
#include <sys/zio.h>
#include <sys/abd.h>
#include <pthread.h>

/* These are DATA ownership records, never history metadata ledger records. */
typedef enum dedup_fdt_ledger_kind {
    DEDUP_FDT_NEW_DATA = 1,
    DEDUP_FDT_RETIRE_DATA = 2
} dedup_fdt_ledger_kind_t;
typedef struct dedup_fdt_data_record {
    blkptr_t dfr_bp;
    zbookmark_phys_t dfr_bookmark;
    uint64_t dfr_domain;
    uint64_t dfr_source_ddt;
    uint64_t dfr_source_brt;
    uint64_t dfr_remaining;
    uint64_t dfr_audit_txg;
} dedup_fdt_data_record_t;
int dedup_fdt_data_create(spa_t *, dedup_fdt_ledger_kind_t, dmu_tx_t *, uint64_t *);
int dedup_fdt_data_retire(spa_t *, uint64_t,
    const dedup_fdt_data_record_t *, dmu_tx_t *);
int dedup_fdt_data_allocate(spa_t *, uint64_t, const blkptr_t *, abd_t *,
    const zbookmark_phys_t *, uint64_t, dmu_tx_t *, blkptr_t *);
int dedup_fdt_data_hold(spa_t *, uint64_t, dmu_buf_t **);
int dedup_fdt_data_validate(spa_t *, uint64_t, dedup_fdt_ledger_kind_t, boolean_t);
void dedup_fdt_data_publish(spa_t *, dmu_buf_t *, dmu_tx_t *);
void dedup_fdt_data_rele(dmu_buf_t *);
int dedup_fdt_data_drain(spa_t *, uint64_t, boolean_t, size_t,
    dmu_tx_t *, boolean_t *, uint64_t *);
int dedup_fdt_data_destroy(spa_t *, uint64_t, dmu_tx_t *);
/* Requests own no payload: callers reserve and reuse bounded ABD windows.
 * Submit in DVA order; native ZIO workers execute concurrently. */
typedef struct dedup_fdt_read_request {
    pthread_mutex_t lock;
    pthread_cond_t ready;
    boolean_t done, raw;
    int error;
    const char *phase;
    uint64_t pass, window, seq, window_limit;
    blkptr_t bp;
} dedup_fdt_read_request_t;
int dedup_fdt_read_start(spa_t *, const blkptr_t *,
    const zbookmark_phys_t *, abd_t *, boolean_t, const char *, uint64_t,
    uint64_t, uint64_t, uint64_t, dedup_fdt_read_request_t *);
int dedup_fdt_read_wait(dedup_fdt_read_request_t *);
/* Compute on an already native-verified raw representation; preserves the
 * complete authenticated BP/IV2/data-key domain and stored byte order. */
void dedup_fdt_stored_checksum(spa_t *, const blkptr_t *, abd_t *, blkptr_t *);
void dedup_fdt_fingerprint(spa_t *, abd_t *, uint64_t, zio_cksum_t *);
#endif
