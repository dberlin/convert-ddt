/* SPDX-License-Identifier: CDDL-1.0
 * Readonly OpenZFS 2.4.4 DDT census. No dataset blocks are rewritten or scrubbed.
 */
#include "validate_pool.h"
#include "ddt_physical.h"
#include <sys/arc_impl.h>
#include <sys/ddt.h>
#include <sys/ddt_impl.h>
#include <sys/dnode.h>
#include <sys/dmu_objset.h>
#include <sys/dbuf.h>
#include <sys/zap.h>
#include <sys/zap_impl.h>
#include <sys/zio_compress.h>
#include <sys/zio_checksum.h>
#include <sys/sha2.h>
#include <jansson.h>
#include <getopt.h>
#include <pthread.h>
#include <signal.h>
#include <time.h>

#define MAX_STORES (ZIO_CHECKSUM_FUNCTIONS * DDT_TYPES * DDT_CLASSES)
#define HASH_SPACE (1ULL << 48)
#define PRELOAD_WORKERS 48
#define PRELOAD_BATCH 8
#define PRELOAD_PLAN_MAX_BYTES (1ULL << 30)

enum { PHASE_OPEN, PHASE_INVENTORY, PHASE_SCAN, PHASE_PRELOAD,
    PHASE_PRELOAD_PLAN };

typedef unsigned __int128 wide_t;
typedef struct census {
    uint64_t keys, groups, ineligible, payload_bytes;
    uint64_t multi_group_keys, ditto_groups, malformed_groups;
    uint64_t occupied_slots[DDT_PHYS_MAX];
    wide_t references, logical_bytes, physical_bytes;
    unsigned char sum[2][SHA256_DIGEST_LENGTH];
    unsigned char xors[SHA256_DIGEST_LENGTH];
} census_t;

typedef struct store {
    ddt_t *ddt;
    dnode_t *dn;
    int checksum, type, class;
    uint64_t object, native_count;
    census_t census;
} store_t;

typedef struct scan {
    store_t stores[MAX_STORES];
    size_t nstores, next_task, total_tasks;
    unsigned int ranges;
    pthread_mutex_t mutex;
    uint64_t entries, bytes, completed_tasks, total_entries, active_workers;
    uint64_t preload_bytes, total_preload_bytes, preload_arc_budget;
    dp_store_t physical_stores[MAX_STORES];
    dp_plan_t physical_plan;
    uint64_t total_preload_plan_blocks;
    uint64_t preload_start_bytes, preload_plan_bytes;
    int error;
    unsigned int phase;
    boolean_t done;
    struct timespec started;
    struct timespec preload_started;
} scan_t;

static volatile sig_atomic_t interrupted;
static void on_signal(int sig) { (void)sig; interrupted = 1; }

static int
parse_uint(const char *s, uint64_t *n)
{
    if (s == NULL || s[0] < '0' || s[0] > '9') return (EINVAL);
    errno = 0;
    char *end;
    *n = strtoull(s, &end, 10);
    return (errno || *end || *n == 0 ? EINVAL : 0);
}

static void
add_digest(unsigned char *sum, const unsigned char *value)
{
    unsigned int carry = 0;
    for (int i = SHA256_DIGEST_LENGTH - 1; i >= 0; i--) {
        carry += sum[i] + value[i];
        sum[i] = carry;
        carry >>= 8;
    }
}

static void
merge(census_t *a, const census_t *b)
{
    a->keys += b->keys;
    a->groups += b->groups;
    a->ineligible += b->ineligible;
    a->payload_bytes += b->payload_bytes;
    a->multi_group_keys += b->multi_group_keys;
    a->ditto_groups += b->ditto_groups;
    a->malformed_groups += b->malformed_groups;
    for (int p = 0; p < DDT_PHYS_MAX; p++)
        a->occupied_slots[p] += b->occupied_slots[p];
    a->references += b->references;
    a->logical_bytes += b->logical_bytes;
    a->physical_bytes += b->physical_bytes;
    for (int d = 0; d < 2; d++) add_digest(a->sum[d], b->sum[d]);
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) a->xors[i] ^= b->xors[i];
}

/* Match pinned ddt_zap.c's version byte, compression, and byteorder semantics,
 * but use caller-owned stack buffers/ABDs and return corruption errors. */
static int
decode(unsigned char *src, size_t size, ddt_univ_phys_t *phys, size_t psize)
{
    if (size < 2 || size > psize + 1) return (EINVAL);
    int cpfunc = src[0] & 0x7f;
    if (cpfunc >= ZIO_COMPRESS_FUNCTIONS) return (EINVAL);
    memset(phys, 0, sizeof (*phys));
    if (zio_compress_table[cpfunc].ci_decompress == NULL) {
        if (cpfunc != ZIO_COMPRESS_OFF || size != psize + 1) return (EINVAL);
        memcpy(phys, src + 1, psize);
        return (0);
    }
    abd_t sabd, dabd;
    abd_get_from_buf_struct(&sabd, src + 1, size - 1);
    abd_get_from_buf_struct(&dabd, phys, psize);
    int error = zio_decompress_data(cpfunc, &sabd, &dabd, size - 1, psize, NULL);
    abd_free(&dabd);
    abd_free(&sabd);
    if (!error && (((src[0] & 0x80) != 0) != (ZFS_HOST_BYTEORDER != 0)))
        byteswap_uint64_array(phys, psize);
    return (error);
}

static void
encode_word(unsigned char **out, uint64_t word)
{
    for (int shift = 56; shift >= 0; shift -= 8) *(*out)++ = word >> shift;
}

static int
group_compare(const uint64_t *a, const uint64_t *b)
{
    for (int w = 0; w < 9; w++) {
        if (a[w] < b[w]) return (-1);
        if (a[w] > b[w]) return (1);
    }
    return (0);
}

/* Ordinary single copies=1/2/3 groups share one representation with FLAT.
 * Every nonzero legacy group is retained, including obsolete ditto and
 * zero-refcount allocated groups. Multiple groups retain their legacy slot
 * identities as well; such entries are never eligible for FLAT conversion. */
static int
fingerprint(store_t *store, const ddt_key_t *key, const ddt_univ_phys_t *phys,
    census_t *c)
{
    uint64_t groups[DDT_PHYS_MAX][9] = {{0}};
    unsigned int slots[DDT_PHYS_MAX];
    unsigned int ngroups = 0;
    boolean_t eligible = B_TRUE;
    const boolean_t flat = (store->ddt->ddt_flags & DDT_FLAG_FLAT) != 0;
    for (int p = 0; p < (flat ? 1 : DDT_PHYS_MAX); p++) {
        uint64_t words[9] = {0};
        words[0] = !flat && p == DDT_PHYS_DITTO;
        const dva_t *dva = flat ? phys->ddp_flat.ddp_dva : phys->ddp_trad[p].ddp_dva;
        for (int d = 0; d < SPA_DVAS_PER_BP; d++) {
            words[1 + d * 2] = dva[d].dva_word[0];
            words[2 + d * 2] = dva[d].dva_word[1];
        }
        words[7] = flat ? phys->ddp_flat.ddp_refcnt : phys->ddp_trad[p].ddp_refcnt;
        words[8] = flat ? phys->ddp_flat.ddp_phys_birth : phys->ddp_trad[p].ddp_phys_birth;
        boolean_t occupied = B_FALSE;
        for (int w = 1; w < 9; w++) occupied |= words[w] != 0;
        if (!occupied) continue;
        slots[ngroups] = p;
        memcpy(groups[ngroups++], words, sizeof (words));
        if (!flat) c->occupied_slots[p]++;
        c->ditto_groups += words[0];
        c->malformed_groups += !words[1] || !words[7] || !words[8];
        if (words[0] || !words[1] || !words[7] || !words[8]) eligible = B_FALSE;
        c->references += words[7];
        c->logical_bytes += (wide_t)DDK_GET_LSIZE(key) * words[7];
        c->physical_bytes += (wide_t)DDK_GET_PSIZE(key) * words[7];
    }
    if (ngroups == 0) return (EINVAL);
    c->multi_group_keys += ngroups > 1;
    if (ngroups > 1)
        for (unsigned int g = 0; g < ngroups; g++)
            groups[g][0] = 0x100 + slots[g];
    for (unsigned int a = 1; a < ngroups; a++) {
        uint64_t tmp[9];
        memcpy(tmp, groups[a], sizeof (tmp));
        unsigned int b = a;
        while (b > 0 && group_compare(groups[b - 1], tmp) > 0) {
            memcpy(groups[b], groups[b - 1], sizeof (tmp));
            b--;
        }
        memcpy(groups[b], tmp, sizeof (tmp));
    }
    unsigned char record[(7 + DDT_PHYS_MAX * 9) * sizeof (uint64_t)];
    unsigned char *out = record;
    encode_word(&out, store->checksum);
    for (int w = 0; w < 4; w++) encode_word(&out, key->ddk_cksum.zc_word[w]);
    encode_word(&out, key->ddk_prop);
    encode_word(&out, ngroups);
    for (unsigned int g = 0; g < ngroups; g++)
        for (int w = 0; w < 9; w++) encode_word(&out, groups[g][w]);
    for (unsigned char domain = 0; domain < 2; domain++) {
        SHA2_CTX ctx;
        unsigned char digest[SHA256_DIGEST_LENGTH];
        SHA2Init(SHA256, &ctx);
        SHA2Update(&ctx, "validate-ddt-v1", 15);
        SHA2Update(&ctx, &domain, 1);
        SHA2Update(&ctx, record, out - record);
        SHA2Final(digest, &ctx);
        add_digest(c->sum[domain], digest);
        if (domain == 0)
            for (int w = 0; w < SHA256_DIGEST_LENGTH; w++) c->xors[w] ^= digest[w];
    }
    c->keys++;
    c->groups += ngroups;
    c->ineligible += !eligible || ngroups != 1;
    return (0);
}

static void
publish_counts(scan_t *scan, uint64_t entries, uint64_t bytes)
{
    __atomic_fetch_add(&scan->entries, entries, __ATOMIC_RELAXED);
    __atomic_fetch_add(&scan->bytes, bytes, __ATOMIC_RELAXED);
}

static int
scan_range(scan_t *scan, store_t *store, unsigned int range,
    zap_attribute_t *za, census_t *c)
{
    const uint64_t width = HASH_SPACE / scan->ranges;
    const uint64_t low = (uint64_t)range * width, high = low + width;
    zap_cursor_t cursor;
    /* ddt_zap.c uses HASH64 UINT64_KEY ZAPs. Pinned zap_micro.c encodes a
     * cookie as [16-bit collision differentiator | 48-bit hash prefix].
     * Begin at cd=0, and stop on the retrieved HASH, not numeric cookie (cd
     * sorts above the hash in cookies). Half-open hash ranges keep every
     * collision group in exactly one task, even across leaf boundaries. */
    zap_cursor_init_serialized(&cursor, store->ddt->ddt_os, store->object, low);
    cursor.zc_prefetch = B_FALSE;
    uint64_t pending_entries = 0, pending_bytes = 0, last_hash = 0;
    uint32_t last_cd = 0;
    boolean_t have_last = B_FALSE;
    int error = 0;
    while (!interrupted && !__atomic_load_n(&scan->error, __ATOMIC_RELAXED)) {
        error = zap_cursor_retrieve(&cursor, za);
        if (error == ENOENT) { error = 0; break; }
        if (error) break;
        if (zap_hashbits(cursor.zc_zap) != 48 ||
            (zap_getflags(cursor.zc_zap) & (ZAP_FLAG_HASH64 | ZAP_FLAG_UINT64_KEY)) !=
            (ZAP_FLAG_HASH64 | ZAP_FLAG_UINT64_KEY)) { error = ENOTSUP; break; }
        uint64_t hash = cursor.zc_hash >> 16;
        if (hash >= high) break;
        if (hash < low || (have_last && (hash < last_hash ||
            (hash == last_hash && cursor.zc_cd <= last_cd)))) {
            error = EINVAL; break;
        }
        last_hash = hash; last_cd = cursor.zc_cd; have_last = B_TRUE;
        size_t psize = DDT_PHYS_SIZE(store->ddt);
        uint64_t size = za->za_num_integers;
        if (za->za_integer_length != 1 || size < 2 || size > psize + 1) {
            error = EINVAL; break;
        }
        ddt_key_t key;
        memcpy(&key, za->za_name, sizeof (key));
        unsigned char buffer[DDT_TRAD_PHYS_SIZE + 1];
        ddt_univ_phys_t phys;
        error = zap_lookup_uint64_by_dnode(store->dn, (uint64_t *)&key,
            sizeof (key) / sizeof (uint64_t), 1, size, buffer);
        if (!error) error = decode(buffer, size, &phys, psize);
        if (!error) error = fingerprint(store, &key, &phys, c);
        if (error) break;
        c->payload_bytes += size;
        pending_entries++;
        pending_bytes += size;
        if (pending_entries >= 1024) {
            publish_counts(scan, pending_entries, pending_bytes);
            pending_entries = pending_bytes = 0;
        }
        zap_cursor_advance(&cursor);
    }
    publish_counts(scan, pending_entries, pending_bytes);
    zap_cursor_fini(&cursor);
    if (interrupted) return (EINTR);
    return (error);
}

static void *
worker(void *arg)
{
    scan_t *scan = arg;
    __atomic_fetch_add(&scan->active_workers, 1, __ATOMIC_RELAXED);
    zap_attribute_t *za = zap_attribute_alloc();
    for (;;) {
        pthread_mutex_lock(&scan->mutex);
        size_t task = scan->next_task++;
        pthread_mutex_unlock(&scan->mutex);
        if (task >= scan->total_tasks || interrupted ||
            __atomic_load_n(&scan->error, __ATOMIC_RELAXED)) break;
        store_t *store = &scan->stores[task / scan->ranges];
        census_t c = {0};
        int error = scan_range(scan, store, task % scan->ranges, za, &c);
        pthread_mutex_lock(&scan->mutex);
        merge(&store->census, &c);
        if (error && !__atomic_load_n(&scan->error, __ATOMIC_RELAXED)) {
            fprintf(stderr, "validate-ddt: checksum=%d class=%d range=%zu: %s\n",
                store->checksum, store->class, task % scan->ranges, strerror(error));
            __atomic_store_n(&scan->error, error, __ATOMIC_RELAXED);
        }
        pthread_mutex_unlock(&scan->mutex);
        __atomic_fetch_add(&scan->completed_tasks, 1, __ATOMIC_RELAXED);
    }
    zap_attribute_free(za);
    __atomic_fetch_sub(&scan->active_workers, 1, __ATOMIC_RELAXED);
    return (NULL);
}

static void
preload_error(scan_t *scan, store_t *store, uint64_t blkid,
    const char *operation, int error)
{
    pthread_mutex_lock(&scan->mutex);
    if (!__atomic_load_n(&scan->error, __ATOMIC_RELAXED)) {
        fprintf(stderr, "validate-ddt: preload %s object=%llu block=%llu: %s\n",
            operation, (u_longlong_t)store->object, (u_longlong_t)blkid,
            strerror(error));
        __atomic_store_n(&scan->error, error, __ATOMIC_RELAXED);
    }
    pthread_mutex_unlock(&scan->mutex);
}

/* The census below remains independent of the converter's entry traversal.
 * Only physical I/O planning and native primary-replica warming are shared. */

/* Claim small consecutive physical batches, amortizing scheduler locking
 * while bounding the seek window and active native payload readers to 48. */
static void *
preload_worker(void *arg)
{
    scan_t *scan = arg;
    __atomic_fetch_add(&scan->active_workers, 1, __ATOMIC_RELAXED);
    for (;;) {
        pthread_mutex_lock(&scan->mutex);
        size_t first = scan->next_task;
        size_t count = MIN((size_t)PRELOAD_BATCH,
            scan->physical_plan.nblocks - first);
        scan->next_task += count;
        pthread_mutex_unlock(&scan->mutex);
        if (count == 0 || interrupted ||
            __atomic_load_n(&scan->error, __ATOMIC_RELAXED)) break;
        for (size_t b = first; b < first + count; b++) {
            if (interrupted || __atomic_load_n(&scan->error, __ATOMIC_RELAXED))
                break;
            const dp_block_t *block = &scan->physical_plan.blocks[b];
            store_t *store = &scan->stores[block->store - 1];
            int error = dp_primary_read(&scan->physical_plan, block);
            if (error) {
                preload_error(scan, store, block->blkid, "physical read", error);
                break;
            }
            __atomic_fetch_add(&scan->preload_bytes,
                scan->physical_stores[block->store - 1].blocksize,
                __ATOMIC_RELAXED);
            __atomic_fetch_add(&scan->completed_tasks, 1, __ATOMIC_RELAXED);
        }
    }
    __atomic_fetch_sub(&scan->active_workers, 1, __ATOMIC_RELAXED);
    return (NULL);
}

static double
elapsed(const struct timespec *start)
{
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return (now.tv_sec - start->tv_sec + (now.tv_nsec - start->tv_nsec) / 1e9);
}

static void
preload_progress(scan_t *scan)
{
    pthread_mutex_lock(&scan->mutex);
    boolean_t planning = __atomic_load_n(&scan->phase, __ATOMIC_ACQUIRE) ==
        PHASE_PRELOAD_PLAN;
    double seconds = elapsed(&scan->preload_started);
    uint64_t bytes = __atomic_load_n(&scan->preload_bytes, __ATOMIC_RELAXED);
    uint64_t planned = __atomic_load_n(&scan->physical_plan.planned_tasks,
        __ATOMIC_RELAXED);
    uint64_t work = planning ? planned : bytes - scan->preload_start_bytes;
    uint64_t remaining = planning ? scan->total_preload_plan_blocks - planned :
        scan->total_preload_bytes - bytes;
    double rate = seconds > 0 ? work / seconds : 0;
    char eta[64] = "null";
    if (remaining == 0)
        snprintf(eta, sizeof (eta), "0");
    else if (rate > 0)
        snprintf(eta, sizeof (eta), "%.1f", remaining / rate);
    fprintf(stderr, "{\"timestamp\":%llu,\"phase\":\"%s\","
        "\"entries\":%llu,\"total_entries\":%llu,\"bytes\":%llu,"
        "\"preload_bytes\":%llu,\"total_preload_bytes\":%llu,"
        "\"preload_arc_budget_bytes\":%llu,\"preload_limit_bytes\":%llu,"
        "\"preload_arc_floor_bytes\":%llu,"
        "\"preload_plan_blocks\":%llu,\"total_preload_plan_blocks\":%llu,"
        "\"preload_plan_bytes\":%llu,\"preload_plan_blocks_per_second\":%.3f,"
        "\"tasks\":%llu,\"total_tasks\":%zu,\"active_workers\":%llu,"
        "\"elapsed_seconds\":%.3f,\"entries_per_second\":0,\"bytes_per_second\":0,"
        "\"preload_bytes_per_second\":%.3f,\"eta_seconds\":%s}\n",
        (u_longlong_t)time(NULL), planning ? "ddt-preload-plan" : "ddt-preload",
        (u_longlong_t)__atomic_load_n(&scan->entries, __ATOMIC_RELAXED),
        (u_longlong_t)__atomic_load_n(&scan->total_entries, __ATOMIC_ACQUIRE),
        (u_longlong_t)__atomic_load_n(&scan->bytes, __ATOMIC_RELAXED),
        (u_longlong_t)bytes, (u_longlong_t)scan->total_preload_bytes,
        (u_longlong_t)scan->preload_arc_budget,
        (u_longlong_t)(scan->preload_arc_budget - scan->preload_arc_budget / 4 -
            (scan->preload_arc_budget % 4 != 0)),
        (u_longlong_t)arc_c_min,
        (u_longlong_t)planned, (u_longlong_t)scan->total_preload_plan_blocks,
        (u_longlong_t)scan->preload_plan_bytes, planning ? rate : 0,
        (u_longlong_t)__atomic_load_n(&scan->completed_tasks, __ATOMIC_RELAXED),
        __atomic_load_n(&scan->total_tasks, __ATOMIC_RELAXED),
        (u_longlong_t)__atomic_load_n(&scan->active_workers, __ATOMIC_RELAXED),
        elapsed(&scan->started), planning ? 0 : rate, eta);
    pthread_mutex_unlock(&scan->mutex);
}

static void *
progress(void *arg)
{
    scan_t *scan = arg;
    do {
        unsigned int phase = __atomic_load_n(&scan->phase, __ATOMIC_ACQUIRE);
        if (phase == PHASE_PRELOAD || phase == PHASE_PRELOAD_PLAN) {
            preload_progress(scan);
        } else {
            double seconds = elapsed(&scan->started);
            uint64_t entries = __atomic_load_n(&scan->entries, __ATOMIC_RELAXED);
            uint64_t bytes = __atomic_load_n(&scan->bytes, __ATOMIC_RELAXED);
            uint64_t total = __atomic_load_n(&scan->total_entries, __ATOMIC_ACQUIRE);
            double rate = seconds > 0 ? entries / seconds : 0;
            char eta[64] = "null";
            if (rate > 0 && total >= entries)
                snprintf(eta, sizeof (eta), "%.1f", (total - entries) / rate);
            static const char *phases[] = { "pool-open", "ddt-inventory", "ddt-scan" };
            fprintf(stderr, "{\"timestamp\":%llu,\"phase\":\"%s\",\"entries\":%llu,"
                "\"total_entries\":%llu,\"bytes\":%llu,\"tasks\":%llu,"
                "\"total_tasks\":%zu,\"active_workers\":%llu,\"elapsed_seconds\":%.3f,"
                "\"entries_per_second\":%.3f,\"bytes_per_second\":%.3f,\"eta_seconds\":%s}\n",
                (u_longlong_t)time(NULL), phases[phase], (u_longlong_t)entries,
                (u_longlong_t)total, (u_longlong_t)bytes,
                (u_longlong_t)__atomic_load_n(&scan->completed_tasks, __ATOMIC_RELAXED),
                __atomic_load_n(&scan->total_tasks, __ATOMIC_RELAXED),
                (u_longlong_t)__atomic_load_n(&scan->active_workers, __ATOMIC_RELAXED),
                seconds, rate, seconds > 0 ? bytes / seconds : 0, eta);
        }
        if (__atomic_load_n(&scan->done, __ATOMIC_ACQUIRE)) break;
        sleep(1);
    } while (1);
    return (NULL);
}

static int
preload_threads(scan_t *scan, pthread_t *threads, unsigned int workers,
    void *(*run)(void *))
{
    unsigned int started = 0;
    int error = 0;
    while (started < MIN(workers, PRELOAD_WORKERS) && !interrupted &&
        !__atomic_load_n(&scan->error, __ATOMIC_RELAXED)) {
        error = pthread_create(&threads[started], NULL, run, scan);
        if (error) {
            __atomic_store_n(&scan->error, error, __ATOMIC_RELAXED);
            break;
        }
        started++;
    }
    for (unsigned int i = 0; i < started; i++) pthread_join(threads[i], NULL);
    if (!error) error = __atomic_load_n(&scan->error, __ATOMIC_RELAXED);
    if (!error && interrupted) error = EINTR;
    return (error);
}

static int
preload(scan_t *scan, pthread_t *threads, unsigned int workers, uint64_t arc)
{
    uint64_t total = 0;
    size_t tasks = 0, capacity = 0;
    for (size_t s = 0; s < scan->nstores; s++) {
        store_t *store = &scan->stores[s];
        dp_store_t *physical = &scan->physical_stores[s];
        *physical = (dp_store_t) {
            .spa = store->ddt->ddt_spa,
            .os = store->ddt->ddt_spa->spa_meta_objset,
            .dn = store->dn, .object = store->object
        };
        int error = dp_store_geometry(physical);
        if (error) {
            preload_error(scan, store, 0, "dnode geometry", error);
            return (error);
        }
        if (physical->nblocks > SIZE_MAX - capacity ||
            physical->ntasks > SIZE_MAX - tasks ||
            UINT64_MAX - total < physical->logical_bytes)
            return (EOVERFLOW);
        capacity += (size_t)physical->nblocks;
        tasks += physical->ntasks;
        total += physical->logical_bytes;
    }
    if (capacity > SIZE_MAX / sizeof (dp_block_t)) return (EOVERFLOW);
    scan->preload_plan_bytes = capacity * sizeof (dp_block_t);
    scan->total_preload_plan_blocks = tasks;
    scan->total_preload_bytes = total;
    scan->preload_arc_budget = MIN(arc, arc_c_max);
    uint64_t limit = scan->preload_arc_budget - scan->preload_arc_budget / 4 -
        (scan->preload_arc_budget % 4 != 0);
    clock_gettime(CLOCK_MONOTONIC, &scan->preload_started);
    scan->next_task = 0;
    __atomic_store_n(&scan->completed_tasks, 0, __ATOMIC_RELAXED);
    __atomic_store_n(&scan->total_tasks, tasks, __ATOMIC_RELAXED);
    __atomic_store_n(&scan->phase, PHASE_PRELOAD_PLAN, __ATOMIC_RELEASE);
    /* Preserve the validator's conservative logical ARC guard, including
     * holes; the shared planner separately bounds its complete working set. */
    preload_progress(scan);
    if (total > limit) {
        fprintf(stderr, "validate-ddt: preload requires %llu logical bytes; "
            "75%% of native ARC budget %llu permits %llu bytes\n",
            (u_longlong_t)total, (u_longlong_t)scan->preload_arc_budget,
            (u_longlong_t)limit);
        return (E2BIG);
    }
    uint64_t plan_budget = MIN(PRELOAD_PLAN_MAX_BYTES, limit / 16);
    int error = dp_plan_build(&scan->physical_plan, scan->physical_stores,
        scan->nstores, MIN(workers, PRELOAD_WORKERS), plan_budget, &interrupted);
    pthread_mutex_lock(&scan->mutex);
    scan->preload_plan_bytes = scan->physical_plan.allocation_bytes;
    pthread_mutex_unlock(&scan->mutex);
    if (error) {
        fprintf(stderr, "validate-ddt: native physical plan: %s\n", strerror(error));
    } else {
        __atomic_fetch_add(&scan->preload_bytes, scan->physical_plan.hole_bytes,
            __ATOMIC_RELAXED);
        __atomic_store_n(&scan->completed_tasks,
            scan->physical_plan.planned_tasks, __ATOMIC_RELAXED);
    }
    preload_progress(scan);
    if (!error) {
        pthread_mutex_lock(&scan->mutex);
        scan->next_task = 0;
        scan->preload_start_bytes =
            __atomic_load_n(&scan->preload_bytes, __ATOMIC_RELAXED);
        clock_gettime(CLOCK_MONOTONIC, &scan->preload_started);
        __atomic_store_n(&scan->completed_tasks, 0, __ATOMIC_RELAXED);
        __atomic_store_n(&scan->total_tasks, scan->physical_plan.nblocks,
            __ATOMIC_RELAXED);
        __atomic_store_n(&scan->phase, PHASE_PRELOAD, __ATOMIC_RELEASE);
        pthread_mutex_unlock(&scan->mutex);
        preload_progress(scan);
        error = preload_threads(scan, threads, workers, preload_worker);
        if (!error && __atomic_load_n(&scan->preload_bytes, __ATOMIC_RELAXED) != total)
            error = EIO;
        preload_progress(scan);
    }
    dp_plan_fini(&scan->physical_plan);
    return (error);
}

static int
inventory(scan_t *scan, spa_t *spa)
{
    int error = zap_contains(spa->spa_meta_objset, DMU_POOL_DIRECTORY_OBJECT,
        "org.convert-ddt:staging");
    if (error != ENOENT) return (error == 0 ? EBUSY : error);
    error = zap_contains(spa->spa_meta_objset, DMU_POOL_DIRECTORY_OBJECT,
        "org.rebuild-ddt:staging");
    if (error != ENOENT) return (error == 0 ? EBUSY : error);
    for (int ck = 0; ck < ZIO_CHECKSUM_FUNCTIONS; ck++) {
        ddt_t *ddt = spa->spa_ddt[ck];
        if (ddt == NULL || ddt->ddt_version == DDT_VERSION_UNCONFIGURED) continue;
        if (ddt->ddt_version > DDT_VERSION_FDT ||
            (ddt->ddt_flags & ~DDT_FLAG_MASK) ||
            (ddt->ddt_version == DDT_VERSION_LEGACY && ddt->ddt_flags != 0) ||
            !avl_is_empty(&ddt->ddt_tree) || !avl_is_empty(&ddt->ddt_repair_tree))
            return (ENOTSUP);
        for (int log = 0; log < 2; log++) {
            if (ddt->ddt_log[log].ddl_length != 0 ||
                !avl_is_empty(&ddt->ddt_log[log].ddl_tree)) {
                fprintf(stderr, "validate-ddt: %s has an unflushed FDT log; "
                    "refusing incomplete base-ZAP census\n", zio_checksum_table[ck].ci_name);
                return (ENOTSUP);
            }
        }
        for (int type = 0; type < DDT_TYPES; type++) {
            for (int cl = 0; cl < DDT_CLASSES; cl++) {
                uint64_t object = ddt->ddt_object[type][cl];
                if (!object) continue;
                store_t *store = &scan->stores[scan->nstores++];
                store->ddt = ddt; store->dn = ddt->ddt_object_dnode[type][cl];
                store->checksum = ck; store->type = type; store->class = cl;
                store->object = object;
                if (store->dn == NULL) return (EINVAL);
                error = zap_count_by_dnode(store->dn, &store->native_count);
                if (error) return (error);
                uint64_t total = __atomic_load_n(&scan->total_entries, __ATOMIC_RELAXED);
                if (UINT64_MAX - total < store->native_count) return (EOVERFLOW);
                __atomic_store_n(&scan->total_entries, total + store->native_count, __ATOMIC_RELEASE);
            }
        }
    }
    return (0);
}

static json_t *
wide_json(wide_t value)
{
    char text[40], *end = text + sizeof (text);
    *--end = 0;
    do { *--end = '0' + value % 10; value /= 10; } while (value);
    return (json_string(end));
}

static json_t *
digest_json(const unsigned char *value)
{
    const char *hex = "0123456789abcdef";
    char text[SHA256_DIGEST_LENGTH * 2 + 1];
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        text[i * 2] = hex[value[i] >> 4]; text[i * 2 + 1] = hex[value[i] & 15];
    }
    text[sizeof (text) - 1] = 0;
    return (json_string(text));
}

static json_t *
census_json(const census_t *c)
{
    json_t *j = json_object();
    json_object_set_new(j, "keys", wide_json(c->keys));
    json_object_set_new(j, "physical_groups", wide_json(c->groups));
    json_object_set_new(j, "references", wide_json(c->references));
    json_object_set_new(j, "logical_reference_bytes", wide_json(c->logical_bytes));
    json_object_set_new(j, "physical_reference_bytes", wide_json(c->physical_bytes));
    json_object_set_new(j, "flat_ineligible_keys", wide_json(c->ineligible));
    json_object_set_new(j, "multi_group_keys", wide_json(c->multi_group_keys));
    json_object_set_new(j, "ditto_groups", wide_json(c->ditto_groups));
    json_object_set_new(j, "malformed_groups", wide_json(c->malformed_groups));
    json_object_set_new(j, "sha256_sum_domain0", digest_json(c->sum[0]));
    json_object_set_new(j, "sha256_sum_domain1", digest_json(c->sum[1]));
    json_object_set_new(j, "sha256_xor_domain0", digest_json(c->xors));
    return (j);
}

static json_t *
report(scan_t *scan, spa_t *spa, uint64_t guid, unsigned int workers)
{
    json_t *root = json_object(), *tables = json_array();
    json_object_set_new(root, "format", json_string("validate-ddt-v1"));
    json_object_set_new(root, "pool_guid", wide_json(guid));
    json_object_set_new(root, "complete", json_true());
    json_object_set_new(root, "workers", json_integer(workers));
    json_object_set_new(root, "hash_ranges_per_store", json_integer(scan->ranges));
    json_object_set_new(root, "fingerprint_encoding", json_string(
        "sha256-domain-separated-big-endian-key-and-sorted-physical-groups-v1"));
    census_t total = {0};
    for (int ck = 0; ck < ZIO_CHECKSUM_FUNCTIONS; ck++) {
        ddt_t *ddt = spa->spa_ddt[ck];
        if (ddt == NULL || ddt->ddt_version == DDT_VERSION_UNCONFIGURED) continue;
        json_t *table = json_object(), *stores = json_array();
        census_t subtotal = {0};
        json_object_set_new(table, "checksum", json_integer(ck));
        json_object_set_new(table, "checksum_name", json_string(zio_checksum_table[ck].ci_name));
        json_object_set_new(table, "version", json_integer(ddt->ddt_version));
        json_object_set_new(table, "flags", json_integer(ddt->ddt_flags));
        json_object_set_new(table, "layout", json_string(
            ddt->ddt_flags & DDT_FLAG_FLAT ? "flat" : "traditional"));
        for (size_t s = 0; s < scan->nstores; s++) {
            store_t *store = &scan->stores[s];
            if (store->checksum != ck) continue;
            json_t *j = json_object();
            json_object_set_new(j, "type", json_integer(store->type));
            json_object_set_new(j, "class", json_integer(store->class));
            json_object_set_new(j, "object", wide_json(store->object));
            json_object_set_new(j, "native_zap_count", wide_json(store->native_count));
            json_object_set_new(j, "identity", census_json(&store->census));
            json_t *slots = json_array();
            for (int p = 0; p < DDT_PHYS_MAX; p++)
                json_array_append_new(slots, wide_json(store->census.occupied_slots[p]));
            json_object_set_new(j, "legacy_occupied_slots", slots);
            json_array_append_new(stores, j);
            merge(&subtotal, &store->census);
        }
        json_object_set_new(table, "stores", stores);
        json_object_set_new(table, "identity", census_json(&subtotal));
        json_array_append_new(tables, table);
        merge(&total, &subtotal);
    }
    json_object_set_new(root, "tables", tables);
    json_object_set_new(root, "identity", census_json(&total));
    json_object_set_new(root, "total_keys", wide_json(total.keys));
    json_object_set_new(root, "total_references", wide_json(total.references));
    json_object_set_new(root, "full_flat_eligible", json_boolean(total.ineligible == 0));
    json_object_set_new(root, "elapsed_seconds", json_real(elapsed(&scan->started)));
    json_object_set_new(root, "payload_bytes", wide_json(scan->bytes));
    return (root);
}

static int
compare(json_t *actual, const char *path)
{
    struct stat st;
    if (stat(path, &st) != 0) return (errno);
    if (st.st_size <= 0 || st.st_size > (4 << 20)) return (EFBIG);
    json_error_t detail;
    json_t *expected = json_load_file(path, JSON_REJECT_DUPLICATES, &detail);
    if (!expected) { fprintf(stderr, "validate-ddt: expected JSON: %s\n", detail.text); return (EINVAL); }
    int error = EINVAL;
    json_t *format = json_object_get(expected, "format");
    if (!json_is_string(format) || strcmp(json_string_value(format), "validate-ddt-v1") ||
        !json_is_true(json_object_get(expected, "complete")) ||
        !json_equal(json_object_get(expected, "total_keys"), json_object_get(actual, "total_keys")) ||
        !json_equal(json_object_get(expected, "total_references"), json_object_get(actual, "total_references")) ||
        !json_equal(json_object_get(expected, "full_flat_eligible"), json_object_get(actual, "full_flat_eligible")) ||
        !json_equal(json_object_get(expected, "pool_guid"), json_object_get(actual, "pool_guid")) ||
        !json_equal(json_object_get(expected, "fingerprint_encoding"), json_object_get(actual, "fingerprint_encoding")) ||
        !json_equal(json_object_get(expected, "identity"), json_object_get(actual, "identity"))) goto out;
    json_t *a = json_object_get(actual, "tables"), *e = json_object_get(expected, "tables");
    if (!json_is_array(e) || json_array_size(a) != json_array_size(e)) goto out;
    for (size_t i = 0; i < json_array_size(a); i++) {
        json_t *at = json_array_get(a, i), *et = json_array_get(e, i);
        if (!json_equal(json_object_get(at, "checksum"), json_object_get(et, "checksum")) ||
            !json_equal(json_object_get(at, "checksum_name"), json_object_get(et, "checksum_name")) ||
            !json_equal(json_object_get(at, "identity"), json_object_get(et, "identity"))) goto out;
        json_t *evj = json_object_get(et, "version"), *efj = json_object_get(et, "flags");
        json_t *avj = json_object_get(at, "version"), *afj = json_object_get(at, "flags");
        if (!json_is_integer(evj) || !json_is_integer(efj)) goto out;
        json_int_t ev = json_integer_value(evj), ef = json_integer_value(efj);
        json_int_t av = json_integer_value(avj), af = json_integer_value(afj);
        const char *el = ef & DDT_FLAG_FLAT ? "flat" : "traditional";
        json_t *elj = json_object_get(et, "layout");
        if (!json_is_string(elj) || strcmp(json_string_value(elj), el)) goto out;
        if (!((ev == av && ef == af) ||
            (ev == DDT_VERSION_LEGACY && ef == 0 && av == DDT_VERSION_FDT &&
            af == (DDT_FLAG_FLAT | DDT_FLAG_LOG) &&
            json_is_true(json_object_get(expected, "full_flat_eligible"))))) goto out;
        if (ev < DDT_VERSION_LEGACY || ev > DDT_VERSION_FDT ||
            (ef & ~DDT_FLAG_MASK) || (ev == DDT_VERSION_LEGACY && ef != 0)) goto out;
        json_t *as = json_object_get(at, "stores"), *es = json_object_get(et, "stores");
        if (!json_is_array(es) || json_array_size(as) != json_array_size(es)) goto out;
        for (size_t s = 0; s < json_array_size(as); s++) {
            json_t *ax = json_array_get(as, s), *ex = json_array_get(es, s);
            const char *fields[] = { "type", "class", "native_zap_count", "identity" };
            for (size_t f = 0; f < sizeof (fields) / sizeof (fields[0]); f++)
                if (!json_equal(json_object_get(ax, fields[f]), json_object_get(ex, fields[f]))) goto out;
        }
    }
    error = 0;
out:
    json_decref(expected);
    if (error) fprintf(stderr, "validate-ddt: full DDT identity/count/layout comparison FAILED\n");
    return (error);
}

static int
atomic_report(json_t *root, const char *path)
{
    char temporary[PATH_MAX];
    if (snprintf(temporary, sizeof (temporary), "%s.tmp.XXXXXX", path) >=
        (int)sizeof (temporary)) return (ENAMETOOLONG);
    int fd = mkstemp(temporary);
    if (fd < 0) return (errno);
    int error = json_dumpfd(root, fd, JSON_INDENT(2) | JSON_SORT_KEYS) != 0 ? EIO : 0;
    if (!error && fsync(fd) != 0) error = errno;
    if (close(fd) != 0 && !error) error = errno;
    if (!error && rename(temporary, path) != 0) error = errno;
    if (error) unlink(temporary);
    return (error);
}

int
main(int argc, char **argv)
{
    uint64_t guid = 0, workers = 0, arc = 0;
    const char *directory = NULL, *output = NULL, *expect = NULL;
    boolean_t do_preload = B_FALSE;
    static const struct option options[] = {
        { "pool-guid", required_argument, NULL, 'p' },
        { "search-dir", required_argument, NULL, 'd' },
        { "workers", required_argument, NULL, 'w' },
        { "arc-max-bytes", required_argument, NULL, 'a' },
        { "output", required_argument, NULL, 'o' },
        { "expect", required_argument, NULL, 'e' },
        { "preload", no_argument, NULL, 'l' }, { NULL, 0, NULL, 0 }
    };
    int option;
    while ((option = getopt_long(argc, argv, "", options, NULL)) != -1) {
        switch (option) {
        case 'p': if (parse_uint(optarg, &guid)) return (2); break;
        case 'd': directory = optarg; break;
        case 'w': if (parse_uint(optarg, &workers)) return (2); break;
        case 'a': if (parse_uint(optarg, &arc)) return (2); break;
        case 'o': output = optarg; break;
        case 'e': expect = optarg; break;
        case 'l': do_preload = B_TRUE; break;
        default: return (2);
        }
    }
    if (!workers) { long cpus = sysconf(_SC_NPROCESSORS_ONLN); workers = cpus > 0 ? cpus : 1; }
    if (!arc) arc = 1ULL << 30;
    if (!guid || !directory || !output || workers > 1024 || optind != argc) {
        fprintf(stderr, "Usage: validate-ddt --pool-guid N --search-dir DIR "
            "[--workers N] [--arc-max-bytes N] [--preload] --output PATH [--expect PATH]\n");
        return (2);
    }
    signal(SIGINT, on_signal); signal(SIGTERM, on_signal);
    scan_t *scan = calloc(1, sizeof (*scan));
    pthread_t *threads = calloc(workers, sizeof (*threads));
    if (!scan || !threads) { free(scan); free(threads); return (1); }
    pthread_mutex_init(&scan->mutex, NULL);
    clock_gettime(CLOCK_MONOTONIC, &scan->started);
    vp_pool_t pool = { .lockfd = -1, .cachefd = -1 };
    unsigned int started = 0;
    pthread_t reporter;
    int error = pthread_create(&reporter, NULL, progress, scan);
    boolean_t reporter_started = error == 0;
    if (!error) error = vp_open(&pool, guid, directory, arc);
    __atomic_store_n(&scan->phase, PHASE_INVENTORY, __ATOMIC_RELEASE);
    if (!error) error = inventory(scan, pool.spa);
    if (!error && do_preload) error = preload(scan, threads, workers, arc);
    scan->ranges = 1;
    while (scan->ranges < workers * 16) scan->ranges *= 2;
    if (!error) {
        scan->next_task = 0;
        __atomic_store_n(&scan->completed_tasks, 0, __ATOMIC_RELAXED);
        __atomic_store_n(&scan->total_tasks, scan->nstores * scan->ranges, __ATOMIC_RELAXED);
        __atomic_store_n(&scan->phase, PHASE_SCAN, __ATOMIC_RELEASE);
    }
    while (!error && started < workers) {
        error = pthread_create(&threads[started], NULL, worker, scan);
        if (!error) started++;
    }
    if (error) __atomic_store_n(&scan->error, error, __ATOMIC_RELAXED);
    for (unsigned int i = 0; i < started; i++) pthread_join(threads[i], NULL);
    __atomic_store_n(&scan->done, B_TRUE, __ATOMIC_RELEASE);
    if (reporter_started) pthread_join(reporter, NULL);
    if (!error) error = __atomic_load_n(&scan->error, __ATOMIC_RELAXED);
    if (!error && interrupted) error = EINTR;
    for (size_t s = 0; !error && s < scan->nstores; s++) {
        uint64_t count;
        error = zap_count_by_dnode(scan->stores[s].dn, &count);
        if (!error && (count != scan->stores[s].native_count ||
            count != scan->stores[s].census.keys)) {
            fprintf(stderr, "validate-ddt: disjoint-range census disagrees with native ZAP count\n");
            error = EINVAL;
        }
    }
    json_t *root = NULL;
    if (!error) {
        root = report(scan, pool.spa, guid, workers);
        if (!root) error = ENOMEM;
    }
    if (!error && expect) error = compare(root, expect);
    if (!error) error = atomic_report(root, output);
    json_decref(root);
    vp_close(&pool);
    pthread_mutex_destroy(&scan->mutex);
    free(threads); free(scan);
    if (error) fprintf(stderr, "validate-ddt: %s\n", strerror(error));
    return (error ? 1 : 0);
}
