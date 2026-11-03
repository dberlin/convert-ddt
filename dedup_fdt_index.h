/* SPDX-License-Identifier: CDDL-1.0 */
#ifndef DEDUP_FDT_INDEX_H
#define DEDUP_FDT_INDEX_H
#include "dedup_fdt_resources.h"
#include <pthread.h>
#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>

typedef struct dedup_fdt_index {
    dedup_fdt_file_t file;
    uint64_t capacity, entries;
    size_t key_size, value_size, stride;
    pthread_mutex_t lock;
    int lock_initialized;
} dedup_fdt_index_t;
int dedup_fdt_index_create(dedup_fdt_resources_t *, int, const char *, uint64_t,
    size_t, size_t, dedup_fdt_index_t *);
/* Caller supplies its reusable value buffer. slot is stable and 1-based. */
int dedup_fdt_index_find(dedup_fdt_index_t *, const void *, void *, uint64_t *, int);
int dedup_fdt_index_read(dedup_fdt_index_t *, uint64_t, void *, void *);
int dedup_fdt_index_write(dedup_fdt_index_t *, uint64_t, const void *);
int dedup_fdt_index_sync(dedup_fdt_index_t *);
void dedup_fdt_index_close(dedup_fdt_index_t *);
#endif
