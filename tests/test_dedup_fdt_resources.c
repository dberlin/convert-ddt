/* SPDX-License-Identifier: CDDL-1.0 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#ifdef NDEBUG
#undef NDEBUG
#endif
#include "dedup_fdt_resources.h"
#include "dedup_fdt_index.h"
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
/* Fault injection writes a real valid stamp prefix, then fails the remaining
 * write. Production I/O must propagate the error and reclaim its lease once. */
static unsigned fail_stamp, fail_tail;
ssize_t __real_pwrite(int, const void *, size_t, off_t);
ssize_t __wrap_pwrite(int, const void *, size_t, off_t);
ssize_t
__wrap_pwrite(int fd, const void *data, size_t size, off_t offset)
{
    if (fail_tail == 1 && offset == 4096+113) {
        ssize_t n = __real_pwrite(fd, data, 16, offset);
        if (n == 16) fail_tail = 2;
        return (n);
    }
    if (fail_tail == 2 && offset == 4096+113+16) {
        fail_tail = 0;
        errno = EIO;
        return (-1);
    }
    if (fail_stamp == 1 && offset == 0 && size == 4096) {
        ssize_t n = __real_pwrite(fd, data, 16, offset);
        if (n == 16) fail_stamp = 2;
        return (n);
    }
    if (fail_stamp == 2 && offset == 16) {
        fail_stamp = 0;
        errno = EIO;
        return (-1);
    }
    return (__real_pwrite(fd, data, size, offset));
}
ssize_t __wrap_pwrite64(int, const void *, size_t, off64_t);
ssize_t
__wrap_pwrite64(int fd, const void *data, size_t size, off64_t offset)
{
    return (__wrap_pwrite(fd, data, size, (off_t)offset));
}

#define PAGE (64U << 10)
static void
pressure_and_reclaim(int dir)
{
    dedup_fdt_resources_t *r;
    assert(dedup_fdt_resources_open(4U<<20, 64U<<20, 0, &r) == 0);
    assert(dedup_fdt_resources_set_directory(r, dir) == 0);
    dedup_fdt_file_t a = { .fd = -1 }, b = { .fd = -1 };
    assert(dedup_fdt_file_create(r, -1, "pressure", &a) == 0);
    assert(dedup_fdt_file_resize(&a, 1ULL<<40) == 0);
    dedup_fdt_resource_stats_t s;
    dedup_fdt_resources_stats(r, &s);
    assert(s.scratch_bytes == 0);
    unsigned char *page = malloc(PAGE), *readback = malloc(PAGE);
    assert(page != NULL && readback != NULL);
    for (unsigned pass = 0; pass < 3; pass++) {
        for (unsigned i = 0; i < 128; i++) {
            memset(page, (unsigned char)(i+pass), PAGE);
            assert(dedup_fdt_file_pwrite(&a, page, PAGE, (uint64_t)i*PAGE) == 0);
        }
        for (unsigned i = 0; i < 128; i++) {
            assert(dedup_fdt_file_pread(&a, readback, PAGE, (uint64_t)i*PAGE) == 0);
            memset(page, (unsigned char)(i+pass), PAGE);
            assert(memcmp(page, readback, PAGE) == 0);
        }
    }
    dedup_fdt_resources_stats(r, &s);
    assert(s.cache_evictions > 0 && s.disk_write_bytes > 0 && s.disk_read_bytes > 0);
    assert(s.cache_bytes+s.workspace_bytes <= s.work_limit);
    assert(s.victim_candidates == s.cache_evictions);
    assert(s.scratch_bytes <= s.disk_max && s.scratch_bytes < a.size);
    uint64_t backing = s.scratch_bytes;
    assert(dedup_fdt_file_sync(&a) == 0);
    dedup_fdt_resources_stats(r, &s);
    assert(s.scratch_bytes == backing);
    assert(dedup_fdt_file_resize(&a, PAGE) == 0);
    dedup_fdt_resources_stats(r, &s);
    assert(s.scratch_bytes <= PAGE+4096);
    assert(dedup_fdt_file_resize(&a, PAGE*2) == 0);
    assert(dedup_fdt_file_pread(&a, readback, PAGE, PAGE) == 0);
    memset(page, 0, PAGE);
    assert(memcmp(page, readback, PAGE) == 0);
    /* Partial truncation must remain coherent across growth and later spill. */
    memset(page, 0x39, PAGE);
    assert(dedup_fdt_file_pwrite(&a, page, PAGE, 0) == 0);
    assert(dedup_fdt_file_resize(&a, 113) == 0);
    assert(dedup_fdt_file_resize(&a, PAGE) == 0);
    assert(dedup_fdt_file_pread(&a, readback, PAGE, 0) == 0);
    memset(page+113, 0, PAGE-113);
    assert(memcmp(page, readback, PAGE) == 0);
    /* Sorting moves handles; cached page ownership must survive by-value moves. */
    dedup_fdt_file_t moved = a;
    memset(&a, 0, sizeof (a));
    a.fd = -1;
    assert(dedup_fdt_file_pread(&moved, readback, PAGE, 0) == 0);
    assert(memcmp(page, readback, PAGE) == 0);
    a = moved;
    dedup_fdt_file_close(&a);
    dedup_fdt_resources_stats(r, &s);
    assert(s.scratch_bytes == 0 && s.cache_bytes == 0);
    assert(dedup_fdt_file_create(r, -1, "reuse", &b) == 0);
    assert(dedup_fdt_file_resize(&b, PAGE) == 0);
    assert(dedup_fdt_file_pwrite(&b, page, PAGE, 0) == 0);
    dedup_fdt_resources_stats(r, &s);
    assert(s.scratch_bytes == 0); /* Small working sets stay resident. */
    assert(dedup_fdt_file_sync(&b) == 0);
    dedup_fdt_resources_stats(r, &s);
    assert(s.scratch_bytes == 0);
    dedup_fdt_file_close(&b);
    dedup_fdt_resources_close(r);
    free(page);
    free(readback);
}
static void
aggregate_quota(int dir)
{
    dedup_fdt_resources_t *r;
    assert(dedup_fdt_resources_open(4U<<20, 2*(PAGE+4096), 0, &r) == 0);
    dedup_fdt_file_t a = { .fd = -1 }, b = { .fd = -1 };
    assert(dedup_fdt_file_create(r, dir, "quota-a", &a) == 0);
    assert(dedup_fdt_file_create(r, dir, "quota-b", &b) == 0);
    assert(dedup_fdt_file_resize(&a, PAGE*128) == 0);
    assert(dedup_fdt_file_resize(&b, PAGE*128) == 0);
    unsigned char page[PAGE];
    memset(page, 0x5a, sizeof (page));
    int error = 0;
    for (unsigned i = 0; i < 128 && error == 0; i++) {
        error = dedup_fdt_file_pwrite(i&1 ? &a : &b, page, PAGE, (uint64_t)i*PAGE);
    }
    assert(error == EDQUOT);
    dedup_fdt_resource_stats_t s;
    dedup_fdt_resources_stats(r, &s);
    assert(s.scratch_bytes <= s.disk_max);
    dedup_fdt_file_close(&a);
    dedup_fdt_resources_stats(r, &s);
    uint64_t before = s.scratch_bytes;
    unsigned char first[PAGE];
    assert(dedup_fdt_file_pread(&b, first, PAGE, 0) == 0);
    assert(memcmp(first, page, PAGE) == 0);
    dedup_fdt_resources_stats(r, &s);
    assert(s.scratch_bytes == before); /* Clean reload needs no new backing. */
    dedup_fdt_file_close(&b);
    dedup_fdt_resources_stats(r, &s);
    assert(s.scratch_bytes == 0);
    assert(dedup_fdt_file_create(r, dir, "quota-reuse", &a) == 0);
    assert(dedup_fdt_file_resize(&a, PAGE) == 0);
    assert(dedup_fdt_file_pwrite(&a, page, PAGE, 0) == 0);
    dedup_fdt_file_close(&a);
    dedup_fdt_resources_close(r);
}
static void
workspace_eviction(int dir)
{
    dedup_fdt_resources_t *r;
    dedup_fdt_file_t file = { .fd = -1 };
    assert(dedup_fdt_resources_open(4U<<20, 1U<<20, 0, &r) == 0);
    assert(dedup_fdt_file_create(r, dir, "workspace", &file) == 0);
    assert(dedup_fdt_file_resize(&file, PAGE) == 0);
    unsigned char data[PAGE], saved[PAGE];
    memset(data, 0x71, sizeof (data));
    assert(dedup_fdt_file_pwrite(&file, data, sizeof (data), 0) == 0);
    dedup_fdt_resource_stats_t s;
    dedup_fdt_resources_stats(r, &s);
    uint64_t lease = s.work_limit-s.workspace_bytes;
    assert(dedup_fdt_memory_reserve(r, lease) == 0);
    dedup_fdt_resources_stats(r, &s);
    assert(s.cache_bytes == 0 && s.scratch_bytes == PAGE+4096);
    assert(s.workspace_bytes == s.work_limit);
    assert(dedup_fdt_memory_reserve(r, 1) == ENOMEM);
    dedup_fdt_memory_release(r, lease);
    assert(dedup_fdt_file_pread(&file, saved, sizeof (saved), 0) == 0);
    assert(memcmp(data, saved, sizeof (data)) == 0);
    dedup_fdt_resources_stats(r, &s);
    uint64_t written = s.disk_write_bytes;
    assert(dedup_fdt_memory_reserve(r, lease) == 0);
    dedup_fdt_resources_stats(r, &s);
    assert(s.cache_bytes == 0 && s.disk_write_bytes == written);
    dedup_fdt_memory_release(r, lease);
    dedup_fdt_file_close(&file);
    dedup_fdt_resources_close(r);
}
static void
clean_victim_with_full_backing(int dir)
{
    dedup_fdt_resources_t *r;
    dedup_fdt_file_t file = { .fd = -1 };
    assert(dedup_fdt_resources_open(4U<<20, 1, 0, &r) == 0);
    assert(dedup_fdt_file_create(r, dir, "clean-victim", &file) == 0);
    assert(dedup_fdt_file_resize(&file, PAGE*4) == 0);
    unsigned char data[PAGE];
    memset(data, 0x4b, sizeof (data));
    assert(dedup_fdt_file_pwrite(&file, data, sizeof (data), 0) == 0);
    dedup_fdt_resource_stats_t s;
    dedup_fdt_resources_stats(r, &s);
    uint64_t lease = s.work_limit-s.workspace_bytes-2*s.cache_bytes;
    assert(dedup_fdt_memory_reserve(r, lease) == 0);
    assert(dedup_fdt_file_pread(&file, data, sizeof (data), PAGE) == 0);
    /* The oldest page is dirty and cannot spill. The clean second page must
     * nevertheless be evicted without scanning the whole resident cache. */
    assert(dedup_fdt_file_pwrite(&file, data, sizeof (data), PAGE*2) == 0);
    dedup_fdt_resources_stats(r, &s);
    assert(s.scratch_bytes == 0 && s.cache_evictions == 1);
    assert(s.victim_candidates == 1);
    assert(dedup_fdt_file_pwrite(&file, data, sizeof (data), PAGE*3) == EDQUOT);
    dedup_fdt_file_close(&file);
    dedup_fdt_memory_release(r, lease);
    dedup_fdt_resources_close(r);
}
static void
partial_truncate_reclaims_before_reload(int dir, int io_error)
{
    dedup_fdt_resources_t *r;
    dedup_fdt_file_t a = { .fd = -1 }, b = { .fd = -1 };
    assert(dedup_fdt_resources_open(4U<<20, 2*(PAGE+4096), 0, &r) == 0);
    assert(dedup_fdt_file_create(r, dir, "tail-other", &a) == 0);
    assert(dedup_fdt_file_create(r, dir, "tail-shrink", &b) == 0);
    assert(dedup_fdt_file_resize(&a, PAGE) == 0);
    assert(dedup_fdt_file_resize(&b, 2*PAGE) == 0);
    unsigned char data[PAGE], saved[PAGE];
    memset(data, 0x17, PAGE);
    assert(dedup_fdt_file_pwrite(&b, data, PAGE, 0) == 0);
    memset(data, 0x29, PAGE);
    assert(dedup_fdt_file_pwrite(&b, data, PAGE, PAGE) == 0);
    dedup_fdt_resource_stats_t s;
    dedup_fdt_resources_stats(r, &s);
    uint64_t lease = s.work_limit-s.workspace_bytes-s.cache_bytes/2;
    assert(dedup_fdt_memory_reserve(r, lease) == 0);
    memset(data, 0x55, PAGE);
    assert(dedup_fdt_file_pwrite(&a, data, PAGE, 0) == 0);
    dedup_fdt_resources_stats(r, &s);
    assert(s.scratch_bytes == s.disk_max);
    /* Tail zeroing needs no cache slot. A postcommit I/O error must retain
     * the smaller boundary and prevent stale bytes from reappearing. */
    if (io_error) {
        fail_tail = 1;
        assert(dedup_fdt_file_resize(&b, 113) == EIO);
        assert(fail_tail == 0 && b.size == 113);
    } else {
        assert(dedup_fdt_file_resize(&b, 113) == 0);
    }
    assert(dedup_fdt_file_resize(&b, PAGE) == 0);
    assert(dedup_fdt_file_pread(&b, saved, PAGE, 0) == 0);
    memset(data, 0x17, 113);
    memset(data+113, 0, PAGE-113);
    assert(memcmp(data, saved, PAGE) == 0);
    assert(dedup_fdt_file_pread(&a, saved, PAGE, 0) == 0);
    memset(data, 0x55, PAGE);
    assert(memcmp(data, saved, PAGE) == 0);
    dedup_fdt_file_close(&a);
    dedup_fdt_file_close(&b);
    dedup_fdt_memory_release(r, lease);
    dedup_fdt_resources_close(r);
}
static void
cache_scaling_and_io_failure(int dir)
{
    dedup_fdt_resources_t *r;
    dedup_fdt_resource_stats_t s;
    assert(dedup_fdt_resources_open(16ULL<<30, 1U<<20, 0, &r) == 0);
    dedup_fdt_resources_stats(r, &s);
    assert(s.cache_buckets >= s.work_limit/(PAGE+256));
    assert(s.workspace_bytes >= s.cache_buckets*sizeof (void *));
    dedup_fdt_resources_close(r);

    assert(dedup_fdt_resources_open(4U<<20, 1U<<20, 0, &r) == 0);
    dedup_fdt_file_t file = { .fd = -1 };
    unsigned char data[PAGE];
    memset(data, 0x67, sizeof (data));
    assert(dedup_fdt_file_create(r, dir, "io-failure", &file) == 0);
    assert(dedup_fdt_file_resize(&file, PAGE) == 0);
    assert(dedup_fdt_file_pwrite(&file, data, sizeof (data), 0) == 0);
    dedup_fdt_resources_stats(r, &s);
    uint64_t lease = s.work_limit-s.workspace_bytes;
    fail_stamp = 1;
    assert(dedup_fdt_memory_reserve(r, lease) == EIO);
    assert(fail_stamp == 0);
    assert(dedup_fdt_file_resize(&file, 0) == 0);
    dedup_fdt_resources_stats(r, &s);
    assert(s.scratch_bytes == 0 && s.cache_bytes == 0);
    assert(dedup_fdt_file_resize(&file, PAGE) == 0);
    assert(dedup_fdt_file_pwrite(&file, data, sizeof (data), 0) == 0);
    assert(dedup_fdt_memory_reserve(r, lease) == 0);
    /* Deliberately corrupt backing to exercise real short-read propagation. */
    assert(ftruncate(file.fd, 4096+PAGE/2) == 0);
    dedup_fdt_memory_release(r, lease);
    assert(dedup_fdt_file_pread(&file, data, sizeof (data), 0) == EIO);
    dedup_fdt_file_close(&file);
    dedup_fdt_resources_close(r);
}
struct writer { dedup_fdt_index_t *index; uint64_t slots[128]; unsigned id; };
static void *
write_rows(void *arg)
{
    struct writer *w = arg;
    for (unsigned pass = 0; pass < 20; pass++)
        for (unsigned i = 0; i < 128; i++) {
            uint64_t value = ((uint64_t)w->id<<32)|i;
            assert(dedup_fdt_index_write(w->index, w->slots[i], &value) == 0);
        }
    return (NULL);
}
static void
parallel_indices(int dir)
{
    dedup_fdt_resources_t *r;
    dedup_fdt_index_t index;
    assert(dedup_fdt_resources_open(4U<<20, 16U<<20, 0, &r) == 0);
    assert(dedup_fdt_index_create(r, dir, "parallel", 1024, 8, 8, &index) == 0);
    struct writer writers[4];
    pthread_t threads[4];
    for (unsigned t = 0; t < 4; t++) {
        writers[t].index = &index;
        writers[t].id = t;
        for (unsigned i = 0; i < 128; i++) {
            uint64_t key = t*128+i, value = 0;
            assert(dedup_fdt_index_find(&index, &key, &value, &writers[t].slots[i], 1) == 0);
        }
    }
    for (unsigned t = 0; t < 4; t++)
        assert(pthread_create(&threads[t], NULL, write_rows, &writers[t]) == 0);
    for (unsigned t = 0; t < 4; t++)
        assert(pthread_join(threads[t], NULL) == 0);
    for (unsigned t = 0; t < 4; t++)
        for (unsigned i = 0; i < 128; i++) {
            uint64_t value;
            assert(dedup_fdt_index_read(&index, writers[t].slots[i], NULL, &value) == 0);
            assert(value == (((uint64_t)t<<32)|i));
        }
    dedup_fdt_index_close(&index);
    dedup_fdt_resources_close(r);
}
int
main(void)
{
    char name[] = "/tmp/dedup-fdt-resources.XXXXXX";
    assert(mkdtemp(name) != NULL);
    int dir = open(name, O_DIRECTORY|O_RDONLY|O_CLOEXEC);
    assert(dir >= 0);
    pressure_and_reclaim(dir);
    aggregate_quota(dir);
    workspace_eviction(dir);
    cache_scaling_and_io_failure(dir);
    clean_victim_with_full_backing(dir);
    partial_truncate_reclaims_before_reload(dir, 0);
    partial_truncate_reclaims_before_reload(dir, 1);
    parallel_indices(dir);
    close(dir);
    assert(rmdir(name) == 0);
    puts("resource pressure, spill/reload, sparse accounting, reclamation and concurrent indices: ok");
    return (0);
}
