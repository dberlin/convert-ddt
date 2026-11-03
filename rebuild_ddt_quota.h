/* SPDX-License-Identifier: CDDL-1.0 */
#ifndef REBUILD_DDT_QUOTA_H
#define REBUILD_DDT_QUOTA_H
#include <stdbool.h>
#include <stdint.h>

/* Pinned ddt_over_quota policy, with actual staged allocation added by the
 * caller. Saturation must never wrap an over-quota size into an admission. */
static inline bool
rebuild_ddt_quota_exceeded(uint64_t quota, uint64_t dsize,
    uint64_t staged_dsize, uint64_t syncing_txg, uint64_t full_txg,
    uint64_t wait_txgs, uint64_t allocated, uint64_t capacity)
{
    if (quota == 0)
        return (false);
    if (quota != UINT64_MAX)
        return (dsize > quota || staged_dsize > quota - dsize);
    if (syncing_txg <= full_txg || syncing_txg - full_txg <= wait_txgs)
        return (true);
    if (capacity == 0)
        return (false);
    /* Equivalent to capacity * 85 / 100 without multiplication overflow. */
    uint64_t limit = (capacity / 100) * 85 + (capacity % 100) * 85 / 100;
    uint64_t free_limit = capacity > (UINT64_C(1) << 33) ?
        capacity - (UINT64_C(1) << 33) : 0;
    if (free_limit > limit)
        limit = free_limit;
    return (allocated >= limit);
}

#ifdef _SYS_SPA_H
/* All errors remain errors. Only *admit == B_FALSE denotes quota refusal.
 * Existing native keys remain admissible regardless of the quota. Staged
 * arguments are actual additional allocations, never serialized row sizes. */
int rebuild_native_ddt_admit(spa_t *, enum zio_checksum, const ddt_key_t *,
    uint64_t, uint64_t, boolean_t *, boolean_t *);
#endif
#endif
