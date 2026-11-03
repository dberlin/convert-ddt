/* SPDX-License-Identifier: CDDL-1.0 */
#ifndef DEDUP_FDT_SORT_H
#define DEDUP_FDT_SORT_H
#include "dedup_fdt_resources.h"
#include <stddef.h>

typedef struct dedup_fdt_sort dedup_fdt_sort_t;
int dedup_fdt_sort_open(dedup_fdt_resources_t *, int, size_t, size_t,
    int (*)(const void *, const void *), dedup_fdt_sort_t **);
int dedup_fdt_sort_add(dedup_fdt_sort_t *, const void *);
int dedup_fdt_sort_finish(dedup_fdt_sort_t *);
int dedup_fdt_sort_next(dedup_fdt_sort_t *, void *);
void dedup_fdt_sort_close(dedup_fdt_sort_t *);
#endif
