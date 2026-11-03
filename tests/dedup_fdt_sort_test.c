/* SPDX-License-Identifier: CDDL-1.0 */
#include "dedup_fdt_sort.h"
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>

static int
compare(const void *a, const void *b)
{
    uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
    return ((x > y) - (x < y));
}

int
main(void)
{
    char directory[] = "/tmp/dedup-fdt-sort.XXXXXX";
    assert(mkdtemp(directory) != NULL);
    int fd = open(directory, O_DIRECTORY | O_RDONLY);
    assert(fd >= 0);
    dedup_fdt_resources_t *resources;
    assert(dedup_fdt_resources_open(128ULL << 20, 32ULL << 20, 64ULL << 20,
        &resources) == 0);
    dedup_fdt_resource_stats_t baseline;
    dedup_fdt_resources_stats(resources, &baseline);
    dedup_fdt_sort_t *sort;
    /* Tiny runs force multiple merge passes through coherent quota files. */
    assert(dedup_fdt_sort_open(resources, fd, sizeof (uint64_t), 31 * 8,
        compare, &sort) == 0);
    for (uint64_t i = 8192; i != 0; i--) {
        uint64_t value = i - 1;
        assert(dedup_fdt_sort_add(sort, &value) == 0);
    }
    assert(dedup_fdt_sort_finish(sort) == 0);
    for (uint64_t i = 0; i < 8192; i++) {
        uint64_t value = UINT64_MAX;
        assert(dedup_fdt_sort_next(sort, &value) == 0);
        assert(value == i);
    }
    uint64_t end;
    assert(dedup_fdt_sort_next(sort, &end) == ENOENT);
    dedup_fdt_sort_close(sort);
    dedup_fdt_resource_stats_t stats;
    dedup_fdt_resources_stats(resources, &stats);
    assert(stats.workspace_bytes == baseline.workspace_bytes);
    assert(stats.cache_bytes == baseline.cache_bytes);
    assert(stats.scratch_bytes == 0);
    dedup_fdt_resources_close(resources);
    close(fd);
    assert(rmdir(directory) == 0);
    return (0);
}
