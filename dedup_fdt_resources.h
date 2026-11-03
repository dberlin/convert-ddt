/* SPDX-License-Identifier: CDDL-1.0 */
#ifndef DEDUP_FDT_RESOURCES_H
#define DEDUP_FDT_RESOURCES_H
#include <stddef.h>
#include <stdint.h>
typedef struct dedup_fdt_resources dedup_fdt_resources_t;
typedef struct dedup_fdt_file_state dedup_fdt_file_state_t;
/* Single-owner movable handle. fd is a lifecycle sentinel, not an I/O escape
 * hatch: logical offsets map to private backing records, not raw fd offsets. */
typedef struct dedup_fdt_file {
    int fd;
    uint64_t size;
    dedup_fdt_resources_t *resources;
    dedup_fdt_file_state_t *state;
} dedup_fdt_file_t;
typedef struct dedup_fdt_resource_stats {
    uint64_t memory_max, disk_max, work_limit, arc_limit, headroom;
    uint64_t workspace_bytes, workspace_peak, cache_bytes, cache_peak;
    /* Conservative committed spill bytes (64KiB data + 4KiB stamp/page),
     * independent of sparse logical size and filesystem compression. Native
     * filesystem metadata/record allocation overhead is not measured here. */
    uint64_t scratch_bytes, scratch_peak, cache_hits, cache_misses;
    uint64_t cache_evictions, disk_read_bytes, disk_write_bytes;
    uint64_t cache_buckets, victim_candidates;
} dedup_fdt_resource_stats_t;
/* Managed working set, not an address-space/RSS limit. Headroom reserves an
 * allowance for native/library/thread/allocator overhead; ARC is a sub-budget.
 * The CLI additionally enforces the pinned native ARC minimum. */
int dedup_fdt_resources_open(uint64_t, uint64_t, uint64_t,
    dedup_fdt_resources_t **);
void dedup_fdt_resources_close(dedup_fdt_resources_t *);
int dedup_fdt_resources_set_directory(dedup_fdt_resources_t *, int);
uint64_t dedup_fdt_resources_work_limit(const dedup_fdt_resources_t *);
uint64_t dedup_fdt_resources_arc_limit(const dedup_fdt_resources_t *);
void dedup_fdt_resources_stats(dedup_fdt_resources_t *, dedup_fdt_resource_stats_t *);
/* Leases are indispensable live workspace; reservation evicts cache first. */
int dedup_fdt_memory_reserve(dedup_fdt_resources_t *, uint64_t);
void dedup_fdt_memory_release(dedup_fdt_resources_t *, uint64_t);
int dedup_fdt_file_create(dedup_fdt_resources_t *, int, const char *,
    dedup_fdt_file_t *);
int dedup_fdt_file_resize(dedup_fdt_file_t *, uint64_t);
int dedup_fdt_file_pread(dedup_fdt_file_t *, void *, size_t, uint64_t);
int dedup_fdt_file_pwrite(dedup_fdt_file_t *, const void *, size_t, uint64_t);
/* Anonymous scratch is not recovery authority: sync retains dirty RAM. */
int dedup_fdt_file_sync(dedup_fdt_file_t *);
void dedup_fdt_file_close(dedup_fdt_file_t *);
#endif
