/* SPDX-License-Identifier: CDDL-1.0 */
#ifndef DEDUP_FDT_PLAN_H
#define DEDUP_FDT_PLAN_H
#include "rebuild_history.h"
#include "rebuild_bridge.h"
#include "dedup_fdt_resources.h"
#include <sys/dmu.h>

typedef struct dedup_fdt_plan dedup_fdt_plan_t;
typedef struct dedup_fdt_options {
    const char **datasets;
    size_t dataset_count;
    unsigned workers;
    size_t batch_size;
    dedup_fdt_resources_t *resources;
} dedup_fdt_options_t;
typedef struct dedup_fdt_counters {
    uint64_t metadata_visits, candidate_allocations, logical_hashed_bytes;
    uint64_t read_bytes, verified_bytes, duplicate_groups, aliases;
    uint64_t rewritten_roots, fdt_entries, retired_bytes;
    uint64_t changed_allocations, new_canonicals;
    uint64_t skipped_groups, skipped_blocks;
} dedup_fdt_counters_t;
int dedup_fdt_plan_create(spa_t *, int, const dedup_fdt_options_t *,
    dedup_fdt_plan_t **);
int dedup_fdt_plan_admit(dedup_fdt_plan_t *, spa_t *, uint64_t,
    rebuild_bridge_t **);
int dedup_fdt_plan_history(dedup_fdt_plan_t *, spa_t *, uint64_t,
    rebuild_history_t **);
int dedup_fdt_plan_allocate(dedup_fdt_plan_t *, uint64_t);
int dedup_fdt_plan_prepared(dedup_fdt_plan_t *, rebuild_history_t *, uint64_t);
int dedup_fdt_plan_bridge(dedup_fdt_plan_t *, rebuild_bridge_t *);
void dedup_fdt_plan_progress(dedup_fdt_plan_t *, const char *, boolean_t);
void dedup_fdt_plan_result(dedup_fdt_plan_t *, const char *);
boolean_t dedup_fdt_plan_has_changes(const dedup_fdt_plan_t *);
boolean_t dedup_fdt_plan_needs_claim(const dedup_fdt_plan_t *);
void dedup_fdt_plan_retired(dedup_fdt_plan_t *, uint64_t);
void dedup_fdt_plan_close(dedup_fdt_plan_t *);
#endif
