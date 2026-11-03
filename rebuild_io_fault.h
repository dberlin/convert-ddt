/* SPDX-License-Identifier: CDDL-1.0 */
#ifndef REBUILD_IO_FAULT_H
#define REBUILD_IO_FAULT_H
#include <sys/spa.h>

/* Test-only: snapshot native device identities during read-only preflight. */
int rebuild_io_fault_prepare(spa_t *, uint64_t attempt, int event_fd);
/* Activate only once an owned recovery stage has committed durably. */
void rebuild_io_fault_arm(void);
/* Call only after all native runtime threads have exited. */
void rebuild_io_fault_disarm(void);
#endif
