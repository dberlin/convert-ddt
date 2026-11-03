/* SPDX-License-Identifier: CDDL-1.0 */
#include "dedup_fdt_index.h"
#include <errno.h>
#include <string.h>
#include <limits.h>

typedef struct df_slot_header { uint64_t used, hash; } df_slot_header_t;
static uint64_t
df_hash(const void *key, size_t size)
{
    const unsigned char *p = key;
    uint64_t h = 14695981039346656037ULL;
    for (size_t i = 0; i < size; i++) { h ^= p[i]; h *= 1099511628211ULL; }
    return (h);
}
int
dedup_fdt_index_create(dedup_fdt_resources_t *resources, int directory,
    const char *name, uint64_t expected, size_t key_size, size_t value_size,
    dedup_fdt_index_t *index)
{
    memset(index, 0, sizeof (*index));
    index->file.fd = -1;
    if (key_size == 0 || key_size > 64 || value_size == 0 ||
        expected > (UINT64_MAX-17)/2 || value_size > SIZE_MAX-key_size-16)
        return (EOVERFLOW);
    index->capacity = expected*2+17;
    index->key_size = key_size;
    index->value_size = value_size;
    index->stride = sizeof (df_slot_header_t)+key_size+value_size;
    if (index->capacity > INT64_MAX/index->stride) return (EOVERFLOW);
    int error = pthread_mutex_init(&index->lock, NULL);
    if (error != 0) return (error);
    index->lock_initialized = 1;
    error = dedup_fdt_file_create(resources, directory, name, &index->file);
    if (error == 0)
        error = dedup_fdt_file_resize(&index->file, index->capacity*index->stride);
    if (error != 0) dedup_fdt_index_close(index);
    return (error);
}
int
dedup_fdt_index_find(dedup_fdt_index_t *index, const void *key,
    void *value, uint64_t *slot, int create)
{
    uint64_t hash = df_hash(key, index->key_size);
    unsigned char saved[64];
    pthread_mutex_lock(&index->lock);
    int error = ENOSPC;
    for (uint64_t probe = 0, n = hash%index->capacity;
        probe < index->capacity; probe++, n = (n+1)%index->capacity) {
        uint64_t offset = n*index->stride;
        df_slot_header_t header;
        error = dedup_fdt_file_pread(&index->file, &header, sizeof (header), offset);
        if (error != 0) break;
        if (!header.used) {
            if (!create) { error = ENOENT; break; }
            if (index->entries >= index->capacity/2) { error = ENOSPC; break; }
            header.used = 1;
            header.hash = hash;
            error = dedup_fdt_file_pwrite(&index->file, key, index->key_size,
                offset+sizeof (header));
            if (error == 0)
                error = dedup_fdt_file_pwrite(&index->file, value, index->value_size,
                    offset+sizeof (header)+index->key_size);
            if (error == 0)
                error = dedup_fdt_file_pwrite(&index->file, &header, sizeof (header), offset);
            if (error == 0) { index->entries++; *slot = n+1; }
            break;
        }
        if (header.hash != hash) { error = ENOSPC; continue; }
        error = dedup_fdt_file_pread(&index->file, saved, index->key_size,
            offset+sizeof (header));
        if (error != 0) break;
        if (memcmp(saved, key, index->key_size) != 0) { error = ENOSPC; continue; }
        *slot = n+1;
        error = dedup_fdt_file_pread(&index->file, value, index->value_size,
            offset+sizeof (header)+index->key_size);
        break;
    }
    pthread_mutex_unlock(&index->lock);
    return (error);
}
int
dedup_fdt_index_read(dedup_fdt_index_t *index, uint64_t slot,
    void *key, void *value)
{
    if (slot == 0 || slot > index->capacity) return (EINVAL);
    pthread_mutex_lock(&index->lock);
    uint64_t offset = (slot-1)*index->stride;
    df_slot_header_t header;
    int error = dedup_fdt_file_pread(&index->file, &header, sizeof (header), offset);
    if (error == 0 && !header.used) error = ENOENT;
    if (error == 0 && key != NULL)
        error = dedup_fdt_file_pread(&index->file, key, index->key_size,
            offset+sizeof (header));
    if (error == 0)
        error = dedup_fdt_file_pread(&index->file, value, index->value_size,
            offset+sizeof (header)+index->key_size);
    pthread_mutex_unlock(&index->lock);
    return (error);
}
int
dedup_fdt_index_write(dedup_fdt_index_t *index, uint64_t slot,
    const void *value)
{
    if (slot == 0 || slot > index->capacity) return (EINVAL);
    pthread_mutex_lock(&index->lock);
    int error = dedup_fdt_file_pwrite(&index->file, value, index->value_size,
        (slot-1)*index->stride+sizeof (df_slot_header_t)+index->key_size);
    pthread_mutex_unlock(&index->lock);
    return (error);
}
int dedup_fdt_index_sync(dedup_fdt_index_t *index)
{ return (dedup_fdt_file_sync(&index->file)); }
void
dedup_fdt_index_close(dedup_fdt_index_t *index)
{
    dedup_fdt_file_close(&index->file);
    if (index->lock_initialized) pthread_mutex_destroy(&index->lock);
    index->lock_initialized = 0;
}
