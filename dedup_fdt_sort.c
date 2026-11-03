/* SPDX-License-Identifier: CDDL-1.0 */
#include "dedup_fdt_sort.h"
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

struct dedup_fdt_sort {
    dedup_fdt_resources_t *resources;
    dedup_fdt_file_t file;
    int directory;
    size_t stride, capacity, used, reservation;
    uint64_t count, position;
    unsigned char *buffer;
    int (*compare)(const void *, const void *);
    int finished;
};

static int
flush_run(dedup_fdt_sort_t *sort)
{
    if (sort->used == 0)
        return (0);
    qsort(sort->buffer, sort->used, sort->stride, sort->compare);
    int error = dedup_fdt_file_resize(&sort->file,
        (sort->count + sort->used) * sort->stride);
    if (error == 0)
        error = dedup_fdt_file_pwrite(&sort->file, sort->buffer,
            sort->used * sort->stride, sort->count * sort->stride);
    if (error == 0) {
        sort->count += sort->used;
        sort->used = 0;
    }
    return (error);
}

int
dedup_fdt_sort_open(dedup_fdt_resources_t *resources, int directory,
    size_t stride, size_t bytes, int (*compare)(const void *, const void *),
    dedup_fdt_sort_t **out)
{
    if (resources == NULL || stride == 0 || compare == NULL || out == NULL ||
        stride > SIZE_MAX / 6)
        return (EINVAL);
    int error = dedup_fdt_memory_reserve(resources, sizeof (dedup_fdt_sort_t));
    if (error != 0)
        return (error);
    dedup_fdt_sort_t *sort = calloc(1, sizeof (*sort));
    if (sort == NULL) {
        dedup_fdt_memory_release(resources, sizeof (*sort));
        return (ENOMEM);
    }
    sort->file.fd = -1;
    sort->resources = resources;
    sort->directory = directory;
    sort->stride = stride;
    sort->compare = compare;
    size_t capacity = bytes / stride;
    if (capacity > SIZE_MAX / 2 / stride)
        capacity = SIZE_MAX / 2 / stride;
    if (capacity < 3)
        capacity = 3;
    /* libc qsort may allocate up to another run's worth of temporary state. */
    while ((error = dedup_fdt_memory_reserve(resources,
        2 * capacity * stride)) != 0 && capacity > 3)
        capacity = capacity / 2 < 3 ? 3 : capacity / 2;
    if (error == 0) {
        sort->reservation = 2 * capacity * stride;
        sort->capacity = capacity;
        sort->buffer = malloc(capacity * stride);
        if (sort->buffer == NULL)
            error = ENOMEM;
    }
    if (error == 0)
        error = dedup_fdt_file_create(resources, directory,
            "dedup-fdt.sort", &sort->file);
    if (error != 0) {
        dedup_fdt_sort_close(sort);
        return (error);
    }
    *out = sort;
    return (0);
}

int
dedup_fdt_sort_add(dedup_fdt_sort_t *sort, const void *record)
{
    if (sort == NULL || sort->finished)
        return (EINVAL);
    if (sort->count > UINT64_MAX / sort->stride - sort->used - 1)
        return (EOVERFLOW);
    memcpy(sort->buffer + sort->used++ * sort->stride, record, sort->stride);
    return (sort->used == sort->capacity ? flush_run(sort) : 0);
}

/* Run locations are arithmetic, not an unbounded per-run heap index. Two
 * coherent files and the original leased run buffer suffice for every pass. */
int
dedup_fdt_sort_finish(dedup_fdt_sort_t *sort)
{
    if (sort == NULL || sort->finished)
        return (EINVAL);
    int error = flush_run(sort);
    for (uint64_t run = sort->capacity; error == 0 && run < sort->count;) {
        dedup_fdt_file_t output = { .fd = -1 };
        error = dedup_fdt_file_create(sort->resources, sort->directory,
            "dedup-fdt.merge", &output);
        if (error == 0)
            error = dedup_fdt_file_resize(&output, sort->count * sort->stride);
        size_t chunk = sort->capacity / 3;
        unsigned char *left = sort->buffer;
        unsigned char *right = left + chunk * sort->stride;
        unsigned char *values = right + chunk * sort->stride;
        uint64_t written = 0;
        size_t output_count = 0;
        for (uint64_t base = 0; error == 0 && base < sort->count;) {
            uint64_t middle = sort->count - base < run ? sort->count : base + run;
            uint64_t end = sort->count - middle < run ? sort->count : middle + run;
            uint64_t a = base, b = middle;
            size_t left_count = 0, right_count = 0;
            size_t left_used = 0, right_used = 0;
            while (error == 0 && (a < middle || b < end)) {
                if (a < middle && left_used == left_count) {
                    left_count = middle - a < chunk ? middle - a : chunk;
                    left_used = 0;
                    error = dedup_fdt_file_pread(&sort->file, left,
                        left_count * sort->stride, a * sort->stride);
                }
                if (error == 0 && b < end && right_used == right_count) {
                    right_count = end - b < chunk ? end - b : chunk;
                    right_used = 0;
                    error = dedup_fdt_file_pread(&sort->file, right,
                        right_count * sort->stride, b * sort->stride);
                }
                if (error != 0)
                    break;
                const unsigned char *x = left + left_used * sort->stride;
                const unsigned char *y = right + right_used * sort->stride;
                const unsigned char *chosen;
                if (a < middle && (b == end || sort->compare(x, y) <= 0)) {
                    chosen = x;
                    a++;
                    left_used++;
                } else {
                    chosen = y;
                    b++;
                    right_used++;
                }
                memcpy(values + output_count++ * sort->stride, chosen,
                    sort->stride);
                if (output_count == chunk) {
                    error = dedup_fdt_file_pwrite(&output, values,
                        output_count * sort->stride, written * sort->stride);
                    written += output_count;
                    output_count = 0;
                }
            }
            base = end;
        }
        if (error == 0 && output_count != 0)
            error = dedup_fdt_file_pwrite(&output, values,
                output_count * sort->stride, written * sort->stride);
        if (error == 0) {
            dedup_fdt_file_close(&sort->file);
            sort->file = output;
        } else {
            dedup_fdt_file_close(&output);
        }
        if (run > sort->count / 2)
            run = sort->count;
        else
            run *= 2;
    }
    if (error == 0) {
        sort->finished = 1;
        /* Sorting workspace need not compete with native request buffers. */
        free(sort->buffer);
        sort->buffer = NULL;
        dedup_fdt_memory_release(sort->resources, sort->reservation);
        sort->reservation = 0;
    }
    return (error);
}

int
dedup_fdt_sort_next(dedup_fdt_sort_t *sort, void *record)
{
    if (sort == NULL || !sort->finished)
        return (EINVAL);
    if (sort->position == sort->count)
        return (ENOENT);
    int error = dedup_fdt_file_pread(&sort->file, record, sort->stride,
        sort->position * sort->stride);
    if (error == 0)
        sort->position++;
    return (error);
}

void
dedup_fdt_sort_close(dedup_fdt_sort_t *sort)
{
    if (sort == NULL)
        return;
    dedup_fdt_file_close(&sort->file);
    free(sort->buffer);
    dedup_fdt_memory_release(sort->resources, sort->reservation);
    dedup_fdt_memory_release(sort->resources, sizeof (*sort));
    free(sort);
}
