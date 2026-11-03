/* SPDX-License-Identifier: CDDL-1.0 */
#ifndef REBUILD_SYNC_H
#define REBUILD_SYNC_H

#include <sys/spa.h>

/* Enable before writable import, disable only after all recovery owners retire. */
int rebuild_sync_fence(uint64_t);
void rebuild_sync_unfence(void);

#endif
