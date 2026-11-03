/* SPDX-License-Identifier: CDDL-1.0 */
#ifndef DEDUP_FDT_WORKERS_H
#define DEDUP_FDT_WORKERS_H
#include "dedup_fdt_resources.h"
typedef struct dedup_fdt_workers dedup_fdt_workers_t;
int dedup_fdt_workers_open(dedup_fdt_resources_t *, unsigned,
    dedup_fdt_workers_t **);
unsigned dedup_fdt_workers_count(const dedup_fdt_workers_t *);
void dedup_fdt_workers_run(dedup_fdt_workers_t *, unsigned,
    void (*)(void *, unsigned), void *);
void dedup_fdt_workers_close(dedup_fdt_workers_t *);
#endif
