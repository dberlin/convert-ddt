/* SPDX-License-Identifier: CDDL-1.0 */
#ifndef DEDUP_FDT_ADMISSION_H
#define DEDUP_FDT_ADMISSION_H
#include <sys/spa.h>
#include <sys/zio.h>

typedef struct dedup_fdt_admission dedup_fdt_admission_t;
/* Native metadata only: dataset physical roots, table/log dnode roots, owner
 * links and user-data future-free records. No user payload reads or writes. */
int dedup_fdt_admission_proof(spa_t *, size_t, zio_cksum_t *);
/* active=true requires an already durable matching attestation. Exported
 * pools may start a new attestation. Caller holds the common GUID fence lock
 * and keeps the secured directory descriptor open until close. */
int dedup_fdt_admission_open(spa_t *, int, const zio_cksum_t *,
    const zio_cksum_t *, boolean_t, dedup_fdt_admission_t **);
int dedup_fdt_admission_check(dedup_fdt_admission_t *, spa_t *,
    const zio_cksum_t *, const zio_cksum_t *);
int dedup_fdt_admission_remove(dedup_fdt_admission_t *);
/* Cleanup only after a MOS-authorized job/receipt has cleanly exported. */
int dedup_fdt_admission_cleanup(int, uint64_t, const zio_cksum_t *);
void dedup_fdt_admission_close(dedup_fdt_admission_t *);
#endif
