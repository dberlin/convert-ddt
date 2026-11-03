/* SPDX-License-Identifier: CDDL-1.0 */
#ifndef REBUILD_PHASE_H
#define REBUILD_PHASE_H

/* A historical maintenance stage blocks admission. */
#define REBUILD_STAGE_KEY "org.rebuild-ddt:staging"

/* Publication changes this value in the same syncing transaction as roots. */
typedef enum rebuild_phase {
    REBUILD_INVENTORY = 1,
    REBUILD_BRIDGE_PREPARED,
    REBUILD_BRIDGE_PUBLISHED,
    REBUILD_LEGACY_RETIRED,
    REBUILD_FLAT_PREPARED,
    REBUILD_FLAT_PUBLISHED,
    REBUILD_RECLAIMING
} rebuild_phase_t;

/* Check between bounded tasks, never halfway through root publication. */
int rebuild_interrupted(void);

#endif
