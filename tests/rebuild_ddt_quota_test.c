/* SPDX-License-Identifier: CDDL-1.0 */
#include "rebuild_ddt_quota.h"
#include <assert.h>
#include <stdint.h>

int
main(void)
{
    /* Native literal policy is strictly greater, not greater-or-equal. */
    assert(!rebuild_ddt_quota_exceeded(0, UINT64_MAX, 0, 0, 0, 0, 0, 0));
    assert(!rebuild_ddt_quota_exceeded(4096, 4096, 0, 0, 0, 0, 0, 0));
    assert(rebuild_ddt_quota_exceeded(4096, 4096, 1, 0, 0, 0, 0, 0));
    assert(rebuild_ddt_quota_exceeded(4096, UINT64_MAX, 1, 0, 0, 0, 0, 0));
    /* Automatic policy includes the native recent-class-full TXG window. */
    assert(rebuild_ddt_quota_exceeded(UINT64_MAX, 0, 0, 10, 8, 2, 0, 0));
    assert(!rebuild_ddt_quota_exceeded(UINT64_MAX, 0, 0, 11, 8, 2, 0, 0));
    assert(!rebuild_ddt_quota_exceeded(UINT64_MAX, 0, 0, 11, 8, 2, 84, 100));
    assert(rebuild_ddt_quota_exceeded(UINT64_MAX, 0, 0, 11, 8, 2, 85, 100));
    uint64_t capacity = UINT64_C(100) << 30;
    assert(!rebuild_ddt_quota_exceeded(UINT64_MAX, 0, 0, 11, 8, 2,
        (UINT64_C(92) << 30) - 1, capacity));
    assert(rebuild_ddt_quota_exceeded(UINT64_MAX, 0, 0, 11, 8, 2,
        UINT64_C(92) << 30, capacity));
    return (0);
}
