/* SPDX-License-Identifier: CDDL-1.0 */
#ifndef REBUILD_HISTORY_H
#define REBUILD_HISTORY_H
#include <sys/spa.h>
#include <sys/dmu.h>
#include <sys/ddt.h>
#include <sys/zio.h>
#include "dedup_fdt_resources.h"
typedef struct rebuild_history rebuild_history_t;

/*
 * Explicit opt-in for verified data remapping. The callback must preserve
 * logical contents, semantic type, level and logical birth. It supplies the
 * entire canonical BP, including the complete crypto tuple, not just DVAs.
 * owner zero and destroyed owners are never an implicit selection wildcard.
 * The history engine creates contextual historical aliases where required.
 */
typedef int rebuild_history_data_map_f(void *, uint64_t,
    const blkptr_t *, blkptr_t *);
/* Disk-backed contextual alias lookup/store; save=false returns ENOENT when
 * this source/context has no prepared alias. No ordinary-data heap index. */
typedef int rebuild_history_data_variant_f(void *, uint64_t,
    const blkptr_t *, blkptr_t *, boolean_t);
typedef struct rebuild_history_data_ops {
    rebuild_history_data_map_f *rhd_map;
    rebuild_history_data_variant_f *rhd_variant;
    void (*rhd_metadata)(void *, const blkptr_t *);
    void (*rhd_root)(void *, const blkptr_t *, const blkptr_t *);
    void *rhd_arg;
    dedup_fdt_resources_t *rhd_resources;
} rebuild_history_data_ops_t;

#define REBUILD_DATA_OWNER 1u
#define REBUILD_DATA_FREE 2u
#define REBUILD_DATA_AUXILIARY 4u
#define REBUILD_DATA_ZIL 8u
typedef int rebuild_history_data_visit_f(void *, uint64_t,
    const zbookmark_phys_t *, const blkptr_t *, unsigned);
int rebuild_history_set_data_ops(rebuild_history_t *,
    const rebuild_history_data_ops_t *);
/* Full logical inventory plus native allocation-lifetime ownership flags.
 * Prepared traversal reports the actual contextual result, not map guesses.
 * Unselected payloads are never read by this metadata-only traversal.
 */
int rebuild_history_foreach_data(rebuild_history_t *, boolean_t,
    rebuild_history_data_visit_f *, void *);
int rebuild_history_open(spa_t *, uint64_t, size_t, rebuild_history_t **);
/* Explicit data mode supplies the shared budget before root/owner inventory,
 * not after scalable metadata has already been allocated. */
int rebuild_history_open_resources(spa_t *, uint64_t, size_t,
    dedup_fdt_resources_t *, rebuild_history_t **);
int rebuild_history_add(rebuild_history_t *, enum zio_checksum,
    const ddt_key_t *, const ddt_univ_phys_t *, int);
int rebuild_history_check(rebuild_history_t *);
int rebuild_history_check_complete(rebuild_history_t *, boolean_t *);
boolean_t rebuild_history_needs_claim(const rebuild_history_t *);
int rebuild_history_prepare(rebuild_history_t *, boolean_t);
int rebuild_history_publish_check(rebuild_history_t *, boolean_t, dmu_tx_t *);
int rebuild_history_publish(rebuild_history_t *, boolean_t, dmu_tx_t *);
int rebuild_history_recover(rebuild_history_t *);
void rebuild_history_close(rebuild_history_t *);
#endif
