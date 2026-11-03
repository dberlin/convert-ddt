/* SPDX-License-Identifier: CDDL-1.0 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "dedup_fdt_resources.h"
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <unistd.h>

#define DF_PAGE (64U << 10)
#define DF_STAMP 4096U
#define DF_RECORD (DF_PAGE+DF_STAMP)
#define DF_MAGIC UINT64_C(0x4644545343524154)

typedef struct df_page df_page_t;
struct dedup_fdt_file_state {
    int fd;
    uint64_t backing;
    df_page_t *pages;
    unsigned tail_pending;
    struct dedup_fdt_file_state *next, *prev;
};
struct df_page {
    df_page_t *hash_next, **hash_prev, *older, *newer;
    df_page_t *file_next, **file_prev;
    df_page_t *queue_older, *queue_newer;
    dedup_fdt_file_state_t *file;
    uint64_t number;
    unsigned dirty, backed, queue; /* backed 1: reserved, 2: committed stamp */
    unsigned char data[DF_PAGE];
};
struct dedup_fdt_resources {
    pthread_mutex_t lock;
    int directory;
    dedup_fdt_resource_stats_t stats;
    df_page_t **buckets, *oldest, *newest;
    size_t bucket_count;
    df_page_t *queue_oldest[3], *queue_newest[3];
    dedup_fdt_file_state_t *files;
};

static int
df_io(int fd, void *buffer, size_t bytes, uint64_t offset, int mode)
{
    unsigned char *p = buffer;
    while (bytes != 0) {
        ssize_t n = mode > 0 ? pwrite(fd, p, bytes, (off_t)offset) :
            pread(fd, p, bytes, (off_t)offset);
        if (n < 0 && errno == EINTR)
            continue;
        if (n < 0)
            return (errno);
        if (n == 0) {
            if (mode >= 0 || p != (unsigned char *)buffer)
                return (EIO);
            memset(p, 0, bytes);
            return (0);
        }
        p += n;
        bytes -= (size_t)n;
        offset += (uint64_t)n;
    }
    return (0);
}
static size_t
df_bucket(dedup_fdt_resources_t *r, dedup_fdt_file_state_t *file, uint64_t number)
{
    uint64_t hash = number ^ ((uint64_t)(uintptr_t)file>>4);
    hash ^= hash>>30;
    hash *= UINT64_C(0xbf58476d1ce4e5b9);
    hash ^= hash>>27;
    hash *= UINT64_C(0x94d049bb133111eb);
    hash ^= hash>>31;
    return ((size_t)hash & (r->bucket_count-1));
}
static void
df_queue_remove(dedup_fdt_resources_t *r, df_page_t *p)
{
    unsigned q = p->queue;
    if (p->queue_older != NULL) p->queue_older->queue_newer = p->queue_newer;
    else r->queue_oldest[q] = p->queue_newer;
    if (p->queue_newer != NULL) p->queue_newer->queue_older = p->queue_older;
    else r->queue_newest[q] = p->queue_older;
}
static void
df_queue_add(dedup_fdt_resources_t *r, df_page_t *p)
{
    unsigned q = !p->dirty ? 0 : p->backed ? 1 : 2;
    p->queue = q;
    p->queue_older = r->queue_newest[q];
    p->queue_newer = NULL;
    if (p->queue_older != NULL) p->queue_older->queue_newer = p;
    else r->queue_oldest[q] = p;
    r->queue_newest[q] = p;
}
static void
df_dirty(dedup_fdt_resources_t *r, df_page_t *p)
{
    if (p->dirty) return;
    df_queue_remove(r, p);
    p->dirty = 1;
    df_queue_add(r, p);
}
static void
df_unlink_lru(dedup_fdt_resources_t *r, df_page_t *p)
{
    if (p->older != NULL) p->older->newer = p->newer;
    else r->oldest = p->newer;
    if (p->newer != NULL) p->newer->older = p->older;
    else r->newest = p->older;
    df_queue_remove(r, p);
}
static void
df_touch(dedup_fdt_resources_t *r, df_page_t *p)
{
    p->older = r->newest;
    p->newer = NULL;
    if (r->newest != NULL) r->newest->newer = p;
    else r->oldest = p;
    r->newest = p;
    df_queue_add(r, p);
}
static void
df_drop(dedup_fdt_resources_t *r, df_page_t *p)
{
    *p->hash_prev = p->hash_next;
    *p->file_prev = p->file_next;
    if (p->file_next != NULL) p->file_next->file_prev = p->file_prev;
    if (p->hash_next != NULL) p->hash_next->hash_prev = p->hash_prev;
    df_unlink_lru(r, p);
    r->stats.cache_bytes -= sizeof (*p);
    free(p);
}
static int
df_stamp(dedup_fdt_file_state_t *file, uint64_t number, unsigned *backed)
{
    uint64_t stamp[2];
    int error = df_io(file->fd, stamp, sizeof (stamp), number*DF_RECORD, -1);
    if (error != 0) return (error);
    if (stamp[0] == 0 && stamp[1] == 0) { *backed = 0; return (0); }
    if (stamp[0] != DF_MAGIC || stamp[1] != number) return (EIO);
    *backed = 2;
    return (0);
}
static int
df_spill(dedup_fdt_resources_t *r, df_page_t *p)
{
    if (!p->dirty) return (0);
    if (p->backed == 0) {
        if (DF_RECORD > r->stats.disk_max-r->stats.scratch_bytes)
            return (EDQUOT);
        r->stats.scratch_bytes += DF_RECORD;
        p->file->backing += DF_RECORD;
        df_queue_remove(r, p);
        p->backed = 1;
        df_queue_add(r, p);
        if (r->stats.scratch_bytes > r->stats.scratch_peak)
            r->stats.scratch_peak = r->stats.scratch_bytes;
    }
    int error = df_io(p->file->fd, p->data, DF_PAGE,
        p->number*DF_RECORD+DF_STAMP, 1);
    if (error != 0) return (error);
    if (p->backed != 2) {
        /* Independent commitment stamps, not SEEK_DATA, distinguish a written
         * page from an unwritten neighbor in a larger filesystem extent. The
         * conservative quota includes the stamp and uncompressed page bytes. */
        unsigned char stamp[DF_STAMP] = { 0 };
        uint64_t header[2] = { DF_MAGIC, p->number };
        memcpy(stamp, header, sizeof (header));
        error = df_io(p->file->fd, stamp, sizeof (stamp),
            p->number*DF_RECORD, 1);
        if (error != 0) return (error);
        p->backed = 2;
        r->stats.disk_write_bytes += DF_STAMP;
    }
    r->stats.disk_write_bytes += DF_PAGE;
    df_queue_remove(r, p);
    p->dirty = 0;
    df_queue_add(r, p);
    return (0);
}
static int
df_make_room(dedup_fdt_resources_t *r, uint64_t bytes)
{
    if (bytes > r->stats.work_limit-r->stats.workspace_bytes)
        return (ENOMEM);
    while (bytes > r->stats.work_limit-r->stats.workspace_bytes-r->stats.cache_bytes) {
        /* Independent clean/backed-dirty/new-dirty queues make victim
         * selection constant-time even at the full 16GiB working set. */
        df_page_t *victim = r->queue_oldest[0];
        if (victim == NULL) victim = r->queue_oldest[1];
        if (victim == NULL) victim = r->queue_oldest[2];
        if (victim == NULL) return (ENOMEM);
        r->stats.victim_candidates++;
        int error = df_spill(r, victim);
        if (error != 0) return (error);
        df_drop(r, victim);
        r->stats.cache_evictions++;
    }
    return (0);
}
static int
df_get_page(dedup_fdt_resources_t *r, dedup_fdt_file_state_t *f,
    uint64_t number, df_page_t **out)
{
    size_t bucket = df_bucket(r, f, number);
    for (df_page_t *p = r->buckets[bucket]; p != NULL; p = p->hash_next)
        if (p->file == f && p->number == number) {
            r->stats.cache_hits++;
            df_unlink_lru(r, p);
            df_touch(r, p);
            *out = p;
            return (0);
        }
    r->stats.cache_misses++;
    int error = df_make_room(r, sizeof (df_page_t));
    if (error != 0) return (error);
    df_page_t *p = calloc(1, sizeof (*p));
    if (p == NULL) return (ENOMEM);
    p->file = f;
    p->number = number;
    error = df_stamp(f, number, &p->backed);
    if (error == 0 && p->backed != 0) {
        error = df_io(f->fd, p->data, DF_PAGE, number*DF_RECORD+DF_STAMP, 0);
        if (error == 0) r->stats.disk_read_bytes += DF_PAGE;
    }
    if (error != 0) { free(p); return (error); }
    p->hash_next = r->buckets[bucket];
    p->hash_prev = &r->buckets[bucket];
    if (p->hash_next != NULL) p->hash_next->hash_prev = &p->hash_next;
    r->buckets[bucket] = p;
    p->file_next = f->pages;
    p->file_prev = &f->pages;
    if (p->file_next != NULL) p->file_next->file_prev = &p->file_next;
    f->pages = p;
    df_touch(r, p);
    r->stats.cache_bytes += sizeof (*p);
    if (r->stats.cache_bytes > r->stats.cache_peak)
        r->stats.cache_peak = r->stats.cache_bytes;
    *out = p;
    return (0);
}
int
dedup_fdt_resources_open(uint64_t memory, uint64_t disk, uint64_t arc,
    dedup_fdt_resources_t **out)
{
    *out = NULL;
    if (memory == 0 || disk == 0) return (EINVAL);
    uint64_t headroom = memory/8;
    if (headroom > (256ULL<<20)) headroom = 256ULL<<20;
    if (arc == 0) {
        arc = memory/4;
        if (arc > (1ULL<<30)) arc = 1ULL<<30;
    }
    if (arc >= memory || headroom >= memory-arc ||
        memory-arc-headroom < sizeof (dedup_fdt_resources_t)+sizeof (df_page_t))
        return (ENOMEM);
    dedup_fdt_resources_t *r = calloc(1, sizeof (*r));
    if (r == NULL) return (ENOMEM);
    int error = pthread_mutex_init(&r->lock, NULL);
    if (error != 0) { free(r); return (error); }
    r->directory = -1;
    r->stats.memory_max = memory;
    r->stats.disk_max = disk;
    r->stats.arc_limit = arc;
    r->stats.headroom = headroom;
    r->stats.work_limit = memory-arc-headroom;
    /* Keep hash load below one page/bucket at maximum cache residency.
     * The table itself is indispensable workspace and charged up front. */
    uint64_t max_pages = (r->stats.work_limit-sizeof (*r))/sizeof (df_page_t);
    size_t buckets = 1;
    while (buckets < max_pages) {
        if (buckets > SIZE_MAX/2/sizeof (df_page_t *)) {
            pthread_mutex_destroy(&r->lock);
            free(r);
            return (EOVERFLOW);
        }
        buckets *= 2;
    }
    uint64_t table_bytes = buckets*sizeof (df_page_t *);
    if (table_bytes > r->stats.work_limit-sizeof (*r)-sizeof (df_page_t)) {
        pthread_mutex_destroy(&r->lock);
        free(r);
        return (ENOMEM);
    }
    r->buckets = calloc(buckets, sizeof (*r->buckets));
    if (r->buckets == NULL) {
        pthread_mutex_destroy(&r->lock);
        free(r);
        return (ENOMEM);
    }
    r->bucket_count = buckets;
    r->stats.cache_buckets = buckets;
    r->stats.workspace_bytes = r->stats.workspace_peak = sizeof (*r)+table_bytes;
    *out = r;
    return (0);
}
int
dedup_fdt_resources_set_directory(dedup_fdt_resources_t *r, int fd)
{
    int copy = fcntl(fd, F_DUPFD_CLOEXEC, 0);
    if (copy < 0) return (errno);
    pthread_mutex_lock(&r->lock);
    if (r->directory >= 0) close(r->directory);
    r->directory = copy;
    pthread_mutex_unlock(&r->lock);
    return (0);
}
uint64_t dedup_fdt_resources_work_limit(const dedup_fdt_resources_t *r)
{ return (r->stats.work_limit); }
uint64_t dedup_fdt_resources_arc_limit(const dedup_fdt_resources_t *r)
{ return (r->stats.arc_limit); }
void
dedup_fdt_resources_stats(dedup_fdt_resources_t *r, dedup_fdt_resource_stats_t *s)
{
    pthread_mutex_lock(&r->lock);
    *s = r->stats;
    pthread_mutex_unlock(&r->lock);
}
int
dedup_fdt_memory_reserve(dedup_fdt_resources_t *r, uint64_t bytes)
{
    pthread_mutex_lock(&r->lock);
    int error = df_make_room(r, bytes);
    if (error == 0) {
        r->stats.workspace_bytes += bytes;
        if (r->stats.workspace_bytes > r->stats.workspace_peak)
            r->stats.workspace_peak = r->stats.workspace_bytes;
    }
    pthread_mutex_unlock(&r->lock);
    return (error);
}
void
dedup_fdt_memory_release(dedup_fdt_resources_t *r, uint64_t bytes)
{
    pthread_mutex_lock(&r->lock);
    uint64_t baseline = sizeof (*r)+r->bucket_count*sizeof (*r->buckets);
    if (bytes > r->stats.workspace_bytes-baseline) abort();
    r->stats.workspace_bytes -= bytes;
    pthread_mutex_unlock(&r->lock);
}
static int
df_scratch(int directory, const char *prefix)
{
    int fd = openat(directory, ".", O_RDWR|O_TMPFILE|O_CLOEXEC, 0600);
    if (fd >= 0) return (fd);
    if (errno != EOPNOTSUPP && errno != EINVAL && errno != EISDIR && errno != ENOSYS)
        return (-1);
    if (strlen(prefix) > 64) { errno = ENAMETOOLONG; return (-1); }
    for (unsigned attempt = 0; attempt < 8; attempt++) {
        uint64_t nonce;
        ssize_t n;
        do { n = getrandom(&nonce, sizeof (nonce), 0); } while (n < 0 && errno == EINTR);
        if (n != sizeof (nonce)) { if (n >= 0) errno = EIO; return (-1); }
        char name[128];
        snprintf(name, sizeof (name), "%s.%lu.%016llx", prefix,
            (unsigned long)getpid(), (unsigned long long)nonce);
        fd = openat(directory, name, O_RDWR|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC, 0600);
        if (fd < 0) { if (errno == EEXIST) continue; return (-1); }
        if (unlinkat(directory, name, 0) != 0) {
            int error = errno; close(fd); errno = error; return (-1);
        }
        return (fd);
    }
    errno = EEXIST;
    return (-1);
}
int
dedup_fdt_file_create(dedup_fdt_resources_t *r, int directory,
    const char *prefix, dedup_fdt_file_t *out)
{
    memset(out, 0, sizeof (*out));
    out->fd = -1;
    if (r == NULL) return (EINVAL);
    int error = dedup_fdt_memory_reserve(r, sizeof (dedup_fdt_file_state_t));
    if (error != 0) return (error);
    dedup_fdt_file_state_t *f = calloc(1, sizeof (*f));
    if (f == NULL) { dedup_fdt_memory_release(r, sizeof (*f)); return (ENOMEM); }
    pthread_mutex_lock(&r->lock);
    int fd = df_scratch(directory < 0 ? r->directory : directory, prefix);
    if (fd < 0) {
        error = errno;
        pthread_mutex_unlock(&r->lock);
        free(f);
        dedup_fdt_memory_release(r, sizeof (*f));
        return (error);
    }
    out->fd = fd;
    out->resources = r;
    out->state = f;
    f->fd = fd;
    f->next = r->files;
    if (r->files != NULL) r->files->prev = f;
    r->files = f;
    pthread_mutex_unlock(&r->lock);
    return (0);
}
static int
df_access(dedup_fdt_file_t *file, void *buffer, size_t bytes,
    uint64_t offset, int writing)
{
    if (file->state == NULL) return (EBADF);
    dedup_fdt_resources_t *r = file->resources;
    pthread_mutex_lock(&r->lock);
    int error = 0;
    if (offset > file->size || bytes > file->size-offset) error = EINVAL;
    unsigned char *p = buffer;
    while (error == 0 && bytes != 0) {
        df_page_t *page;
        error = df_get_page(r, file->state, offset/DF_PAGE, &page);
        if (error != 0) break;
        size_t within = offset%DF_PAGE, n = DF_PAGE-within;
        if (n > bytes) n = bytes;
        if (writing) { memcpy(page->data+within, p, n); df_dirty(r, page); }
        else memcpy(p, page->data+within, n);
        p += n;
        bytes -= n;
        offset += n;
    }
    pthread_mutex_unlock(&r->lock);
    return (error);
}
int dedup_fdt_file_pread(dedup_fdt_file_t *f, void *p, size_t n, uint64_t o)
{ return (df_access(f, p, n, o, 0)); }
int dedup_fdt_file_pwrite(dedup_fdt_file_t *f, const void *p, size_t n, uint64_t o)
{ return (df_access(f, (void *)p, n, o, 1)); }

/* SEEK_DATA only skips holes. The independent stamps are authoritative even
 * where native compression/recordsize makes adjacent unwritten pages data. */
static int
df_count_backing(dedup_fdt_file_t *file, uint64_t first, uint64_t *bytes)
{
    struct stat st;
    if (fstat(file->fd, &st) != 0) return (errno);
    uint64_t at = first*DF_RECORD, end = (uint64_t)st.st_size;
    *bytes = 0;
    while (at < end) {
        off_t data = lseek(file->fd, (off_t)at, SEEK_DATA);
        if (data < 0 && errno == ENXIO) break;
        if (data < 0 && errno != EINVAL && errno != EOPNOTSUPP) return (errno);
        if (data >= 0 && (uint64_t)data > at)
            at = ((uint64_t)data/DF_RECORD)*DF_RECORD;
        unsigned backed;
        int error = df_stamp(file->state, at/DF_RECORD, &backed);
        if (error != 0) return (error);
        df_page_t *resident = file->resources->buckets[df_bucket(
            file->resources, file->state, at/DF_RECORD)];
        while (resident != NULL && (resident->file != file->state ||
            resident->number != at/DF_RECORD)) resident = resident->hash_next;
        /* A short stamp write may have committed its valid 16-byte prefix
         * while this resident page still owns the reservation. Count it only
         * through the reserved-page path below, never twice. */
        if (backed && (resident == NULL || resident->backed != 1))
            *bytes += DF_RECORD;
        at += DF_RECORD;
    }
    return (0);
}
/* Called with the cache lock and the committed smaller logical size. A failed
 * backing write leaves the boundary pending; growth must retry it first. */
static int
df_clear_tail(dedup_fdt_file_t *file)
{
    dedup_fdt_resources_t *r = file->resources;
    if (!file->state->tail_pending)
        return (0);
    uint64_t number = file->size/DF_PAGE;
    size_t within = file->size%DF_PAGE;
    df_page_t *tail = r->buckets[df_bucket(r, file->state, number)];
    while (tail != NULL && (tail->file != file->state ||
        tail->number != number)) tail = tail->hash_next;
    if (tail != NULL) {
        memset(tail->data+within, 0, DF_PAGE-within);
        df_dirty(r, tail);
    } else {
        unsigned backed;
        int error = df_stamp(file->state, number, &backed);
        if (error != 0) return (error);
        if (backed != 0) {
            unsigned char zero[DF_PAGE] = {0};
            size_t bytes = DF_PAGE-within;
            error = df_io(file->fd, zero, bytes,
                number*DF_RECORD+DF_STAMP+within, 1);
            if (error != 0) return (error);
            r->stats.disk_write_bytes += bytes;
        }
    }
    file->state->tail_pending = 0;
    return (0);
}
int
dedup_fdt_file_resize(dedup_fdt_file_t *file, uint64_t size)
{
    if (file->state == NULL) return (EBADF);
    if (size > ((uint64_t)INT64_MAX/DF_RECORD)*DF_PAGE) return (EOVERFLOW);
    dedup_fdt_resources_t *r = file->resources;
    pthread_mutex_lock(&r->lock);
    int error = 0;
    if (size < file->size) {
        uint64_t pages = (size+DF_PAGE-1)/DF_PAGE, released = 0;
        error = df_count_backing(file, pages, &released);
        if (error == 0 && ftruncate(file->fd, (off_t)(pages*DF_RECORD)) != 0)
            error = errno;
        if (error == 0) {
            /* Commit the inaccessible suffix before any fallible zeroing.
             * No error may expose modified bytes at the old logical size. */
            file->size = size;
            file->state->tail_pending = size%DF_PAGE != 0;
            for (df_page_t *p = file->state->pages, *next; p != NULL; p = next) {
                next = p->file_next;
                if (p->number >= pages) {
                    if (p->backed == 1) released += DF_RECORD;
                    df_drop(r, p);
                }
            }
            r->stats.scratch_bytes -= released;
            file->state->backing -= released;
            error = df_clear_tail(file);
        }
    } else {
        error = df_clear_tail(file);
    }
    if (error == 0) file->size = size;
    pthread_mutex_unlock(&r->lock);
    return (error);
}
int dedup_fdt_file_sync(dedup_fdt_file_t *file)
{ return (file->state == NULL ? EBADF : 0); }
void
dedup_fdt_file_close(dedup_fdt_file_t *file)
{
    if (file->state == NULL) { file->fd = -1; return; }
    dedup_fdt_resources_t *r = file->resources;
    pthread_mutex_lock(&r->lock);
    dedup_fdt_file_state_t *f = file->state;
    while (f->pages != NULL)
        df_drop(r, f->pages);
    r->stats.scratch_bytes -= f->backing;
    r->stats.workspace_bytes -= sizeof (*f);
    if (f->prev != NULL) f->prev->next = f->next;
    else r->files = f->next;
    if (f->next != NULL) f->next->prev = f->prev;
    close(file->fd);
    free(f);
    memset(file, 0, sizeof (*file));
    file->fd = -1;
    pthread_mutex_unlock(&r->lock);
}
void
dedup_fdt_resources_close(dedup_fdt_resources_t *r)
{
    if (r == NULL) return;
    while (r->files != NULL) {
        dedup_fdt_file_t file = { .fd = r->files->fd, .resources = r,
            .state = r->files };
        dedup_fdt_file_close(&file);
    }
    if (r->directory >= 0) close(r->directory);
    pthread_mutex_destroy(&r->lock);
    free(r->buckets);
    free(r);
}
