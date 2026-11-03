/* SPDX-License-Identifier: CDDL-1.0
 * Offline selected-content deduplication for the pinned OpenZFS 2.4.4 ABI.
 */
#include <sys/zfs_context.h>
#include <sys/arc_impl.h>
#include <sys/spa.h>
#include <sys/spa_impl.h>
#include <sys/dmu.h>
#include <sys/dmu_tx.h>
#include <sys/dsl_dataset.h>
#include <sys/dsl_pool.h>
#include <sys/dsl_scan.h>
#include <sys/dsl_synctask.h>
#include <sys/vdev_impl.h>
#include <sys/zap.h>
#include <sys/zfeature.h>
#include <sys/zfs_ioctl.h>
#include <sys/file.h>
#include <sys/mman.h>
#include <sys/eventfd.h>
#include <sys/stat.h>
#include <libzutil.h>
#include <getopt.h>
#include <signal.h>
#include <poll.h>
#include "dedup_fdt_plan.h"
#include "dedup_fdt_native.h"
#include "dedup_fdt_admission.h"
#include "rebuild_keys.h"
#include "rebuild_phase.h"
#include "rebuild_sync.h"
#include <sys/blake3.h>
#include <time.h>
#include <pthread.h>

extern uint64_t zfs_arc_min, zfs_arc_max;

#define DF_STAGE_KEY "org.convert-ddt:dedup-fdt"
#define DF_DONE_KEY "org.convert-ddt:dedup-fdt-completed"
#define DF_FORMAT 1
static const char tag[] = "dedup-fdt";
static volatile sig_atomic_t stop_requested;
static int stopfd = -1, phasefd = -1;
static const char *pause_phase, *error_phase;
static const char *const phases[] = { "inventory-durable", "data-prepared",
    "flat-prepared", "flat-published", "reclaim-complete", "import-admitted" };
#define DF_PHASES (sizeof (phases)/sizeof (*phases))

typedef struct df_job {
    spa_t *spa;
    rebuild_keys_t *keys;
    dedup_fdt_plan_t *plan;
    rebuild_history_t *history;
    rebuild_bridge_t *bridge;
    dedup_fdt_admission_t *admission;
    dedup_fdt_options_t options;
    uint64_t stage, receipt, phase, new_data, retired_data;
    zio_cksum_t scope;
    zio_cksum_t native_proof, receipt_proof;
    dmu_buf_t *new_hold, *retire_hold;
    boolean_t done;
    boolean_t receipt_matches;
    boolean_t receipt_published;
    uint64_t retired_bytes;
    int error;
} df_job_t;

/* Armed only for the preflight-proven empty-unclaimed-log import. Native
 * spa_ld_claim_log_blocks() runs before txg_sync_start(), using one assigned
 * first-import TXG. Its objset callbacks may run concurrently. */
static df_job_t *claim_job;
static pthread_mutex_t claim_lock = PTHREAD_MUTEX_INITIALIZER;
static int claim_error;

int
rebuild_interrupted(void)
{
    return (__atomic_load_n(&stop_requested, __ATOMIC_ACQUIRE) != 0);
}
static void
df_signal(int signal_number)
{
    (void)signal_number;
    int saved = errno;
    __atomic_store_n(&stop_requested, 1, __ATOMIC_RELEASE);
    if (stopfd >= 0) {
        uint64_t event = 1;
        (void)write(stopfd, &event, sizeof (event));
    }
    errno = saved;
}
static int
df_problem(int error, const char *message)
{
    fprintf(stderr, "%s: %s: %s\n", tag, message, strerror(error));
    return (error);
}
static int
df_number(const char *s, uint64_t *out)
{
    if (*s == 0)
        return (EINVAL);
    uint64_t value = 0;
    for (; *s; s++) {
        if (*s < '0' || *s > '9' || value > (UINT64_MAX-(*s-'0'))/10)
            return (EINVAL);
        value = value*10+(*s-'0');
    }
    *out = value;
    return (0);
}
static void
df_usage(FILE *file)
{
    fprintf(file, "Usage: dedup-fdt (--plan | --dedup --fenced) --pool-guid GUID "
        "--search-dir DIR --work-dir DIR --dataset POOL/PATH [--dataset ...]\n"
        "       [--key-file DATASET=PATH ...] [--workers 1..64] "
        "[--batch-size 1..65536]\n"
        "       --disk-max-bytes BYTES [--memory-max-bytes BYTES (default 16GiB)]\n"
        "       [--arc-max-bytes BYTES] (workers default: detected CPUs, capped 64)\n"
        "       dedup-fdt --list-test-phases\n");
}
static int
df_fault_setup(boolean_t fenced)
{
    const char *enable = getenv("DEDUP_FDT_TESTING");
    const char *channel = getenv("DEDUP_FDT_TEST_PHASE_FD");
    pause_phase = getenv("DEDUP_FDT_TEST_PAUSE_PHASE");
    error_phase = getenv("DEDUP_FDT_TEST_ERROR_PHASE");
    if (enable == NULL && channel == NULL && pause_phase == NULL && error_phase == NULL)
        return (0);
    uint64_t fd;
    if (!fenced || enable == NULL || strcmp(enable, "1") != 0 || channel == NULL ||
        df_number(channel, &fd) != 0 || fd > INT_MAX)
        return (EINVAL);
    struct stat info;
    int mode = fcntl((int)fd, F_GETFL);
    if (mode < 0 || (mode&O_ACCMODE) == O_RDONLY || fstat((int)fd, &info) != 0 ||
        (!S_ISFIFO(info.st_mode) && !S_ISSOCK(info.st_mode)))
        return (EINVAL);
    phasefd = (int)fd;
    for (unsigned which = 0; which < 2; which++) {
        const char *name = which == 0 ? pause_phase : error_phase;
        if (name == NULL)
            continue;
        boolean_t found = B_FALSE;
        for (size_t i = 0; i < DF_PHASES; i++)
            found |= strcmp(name, phases[i]) == 0;
        if (!found)
            return (EINVAL);
    }
    return (0);
}
static int
df_phase(unsigned number)
{
    const char *name = phases[number];
    boolean_t inject = error_phase != NULL && strcmp(error_phase, name) == 0;
    if (phasefd >= 0) {
        char event[256];
        int n = snprintf(event, sizeof (event),
            "{\"phase\":\"%s\",\"durable\":true,\"error\":%d%s}\n", name,
            inject ? EIO : 0, number == 5 ?
            ",\"admission_proof\":true,\"active_labels\":true,\"mos_stage\":false" : "");
        size_t sent = 0;
        while (sent < (size_t)n) {
            ssize_t done = write(phasefd, event+sent, (size_t)n-sent);
            if (done < 0 && errno == EINTR && !rebuild_interrupted())
                continue;
            if (done <= 0)
                return (done < 0 ? errno : EIO);
            sent += done;
        }
    }
    if (inject)
        return (EIO);
    if (pause_phase != NULL && strcmp(pause_phase, name) == 0) {
        struct pollfd notification = { .fd = stopfd, .events = POLLIN };
        while (!rebuild_interrupted())
            if (poll(&notification, 1, -1) < 0 && errno != EINTR)
                return (errno);
    }
    return (rebuild_interrupted() ? EINTR : 0);
}
static int
df_reject_kernel(uint64_t guid)
{
    int fd = open(ZFS_DEV, O_RDWR | O_CLOEXEC);
    if (fd < 0)
        return (errno);
    zfs_cmd_t *command = calloc(1, sizeof (*command));
    void *buffer = NULL;
    nvlist_t *configs = NULL;
    size_t size = 128*1024;
    int error = command == NULL ? ENOMEM : 0;
    while (error == 0) {
        free(buffer);
        buffer = malloc(size);
        if (buffer == NULL) { error = ENOMEM; break; }
        command->zc_nvlist_dst = (uintptr_t)buffer;
        command->zc_nvlist_dst_size = size;
        command->zc_cookie = 0;
        if (ioctl(fd, ZFS_IOC_POOL_CONFIGS, command) == 0) {
            error = nvlist_unpack(buffer, command->zc_nvlist_dst_size, &configs, 0);
            break;
        }
        error = errno;
        if (error != ENOMEM)
            break;
        if (command->zc_nvlist_dst_size <= size ||
            command->zc_nvlist_dst_size > 128*1024*1024) {
            error = EOVERFLOW;
            break;
        }
        size = command->zc_nvlist_dst_size;
        error = 0;
    }
    if (error == 0)
        for (nvpair_t *pair = nvlist_next_nvpair(configs, NULL); pair != NULL;
            pair = nvlist_next_nvpair(configs, pair)) {
            nvlist_t *pool;
            uint64_t found;
            if (nvpair_value_nvlist(pair, &pool) != 0 ||
                nvlist_lookup_uint64(pool, ZPOOL_CONFIG_POOL_GUID, &found) != 0) {
                error = EINVAL;
                break;
            }
            if (found == guid) { error = EBUSY; break; }
        }
    nvlist_free(configs);
    free(buffer);
    free(command);
    close(fd);
    return (error);
}
static int
df_labels(vdev_t *vdev, boolean_t recovery, boolean_t *active)
{
    for (uint64_t i = 0; i < vdev->vdev_children; i++) {
        int error = df_labels(vdev->vdev_child[i], recovery, active);
        if (error != 0)
            return (error);
    }
    if (!vdev->vdev_ops->vdev_op_leaf)
        return (0);
    nvlist_t *label = vdev_label_read_config(vdev, vdev->vdev_spa->spa_uberblock.ub_txg);
    uint64_t state, guid, leaf, txg;
    int error = label == NULL ||
        nvlist_lookup_uint64(label, ZPOOL_CONFIG_POOL_STATE, &state) != 0 ||
        (state != POOL_STATE_EXPORTED && (!recovery || state != POOL_STATE_ACTIVE)) ||
        nvlist_lookup_uint64(label, ZPOOL_CONFIG_POOL_GUID, &guid) != 0 ||
        guid != spa_guid(vdev->vdev_spa) ||
        nvlist_lookup_uint64(label, ZPOOL_CONFIG_GUID, &leaf) != 0 ||
        leaf != vdev->vdev_guid ||
        nvlist_lookup_uint64(label, ZPOOL_CONFIG_POOL_TXG, &txg) != 0 || txg == 0;
    nvlist_free(label);
    if (!error && state == POOL_STATE_ACTIVE)
        *active = B_TRUE;
    return (error ? EINVAL : 0);
}
static int
df_quiescent(spa_t *spa)
{
    dsl_scan_t *scan = spa_get_dsl(spa)->dp_scan;
    if (spa_has_checkpoint(spa) || spa->spa_checkpoint_txg != 0 ||
        spa_feature_is_active(spa, SPA_FEATURE_POOL_CHECKPOINT) ||
        scan->scn_phys.scn_state == DSS_SCANNING || dsl_errorscrub_active(scan) ||
        spa->spa_vdev_removal != NULL || spa->spa_raidz_expand != NULL ||
        spa->spa_condensing_indirect != NULL)
        return (EBUSY);
    if (spa->spa_root_vdev->vdev_state != VDEV_STATE_HEALTHY)
        return (ENXIO);
    for (uint64_t i = 0; i < spa->spa_root_vdev->vdev_children; i++)
        if (vdev_rebuild_active(spa->spa_root_vdev->vdev_child[i]))
            return (EBUSY);
    if (!spa_feature_is_enabled(spa, SPA_FEATURE_FAST_DEDUP) ||
        !spa_feature_is_enabled(spa, SPA_FEATURE_BLOCK_CLONING) ||
        !spa_feature_is_enabled(spa, SPA_FEATURE_BLAKE3))
        return (ENOTSUP);
    uint8_t salt[sizeof (spa->spa_cksum_salt.zcs_bytes)];
    int error = zap_lookup(spa_get_dsl(spa)->dp_meta_objset,
        DMU_POOL_DIRECTORY_OBJECT, DMU_POOL_CHECKSUM_SALT, 1, sizeof (salt), salt);
    if (error != 0)
        return (error == ENOENT ? ENOTSUP : error);
    if (memcmp(salt, spa->spa_cksum_salt.zcs_bytes, sizeof (salt)) != 0)
        return (ECKSUM);
    return (0);
}
static int
df_scope(df_job_t *job)
{
    BLAKE3_CTX context;
    Blake3_Init(&context);
    for (size_t i = 0; i < job->options.dataset_count; i++)
        Blake3_Update(&context, job->options.datasets[i],
            strlen(job->options.datasets[i])+1);
    Blake3_Final(&context, (uint8_t *)&job->scope);
    return (0);
}
static int
df_stage_read(df_job_t *job)
{
    objset_t *mos = spa_get_dsl(job->spa)->dp_meta_objset;
    const char *conflicts[] = { "org.convert-ddt:staging", REBUILD_STAGE_KEY };
    for (size_t i = 0; i < sizeof (conflicts)/sizeof (*conflicts); i++) {
        int error = zap_contains(mos, DMU_POOL_DIRECTORY_OBJECT, conflicts[i]);
        if (error != ENOENT)
            return (error != 0 ? error : EBUSY);
    }
    job->stage = job->receipt = job->phase = job->new_data = job->retired_data = 0;
    job->receipt_matches = job->receipt_published = B_FALSE;
    int error = zap_lookup(mos, DMU_POOL_DIRECTORY_OBJECT, DF_STAGE_KEY, 8, 1, &job->stage);
    if (error == ENOENT) {
        error = zap_lookup(mos, DMU_POOL_DIRECTORY_OBJECT, DF_DONE_KEY, 8, 1, &job->receipt);
        if (error == ENOENT)
            return (0);
    }
    if (error == 0 && job->stage == 0 && job->receipt == 0)
        return (EINVAL);
    if (error == 0 && job->stage != 0) {
        int other = zap_contains(mos, DMU_POOL_DIRECTORY_OBJECT, DF_DONE_KEY);
        if (other != ENOENT)
            return (other != 0 ? other : EINVAL);
    }
    if (error != 0)
        return (error);
    uint64_t object = job->stage != 0 ? job->stage : job->receipt;
    uint64_t format, guid;
    error = zap_lookup(mos, object, "format", 8, 1, &format);
    if (error == 0)
        error = zap_lookup(mos, object, "guid", 8, 1, &guid);
    if (error == 0)
        error = zap_lookup(mos, object, "phase", 8, 1, &job->phase);
    if (error != 0 || format != DF_FORMAT || guid != spa_guid(job->spa) ||
        job->phase < REBUILD_LEGACY_RETIRED || job->phase > REBUILD_RECLAIMING)
        return (error != 0 ? error : EINVAL);
    zio_cksum_t scope;
    error = zap_lookup(mos, object, "scope", 8, 4, &scope);
    if (error != 0)
        return (error);
    if (job->stage == 0) {
        uint64_t published;
        job->receipt_matches = memcmp(&scope, &job->scope, sizeof (scope)) == 0;
        error = zap_lookup(mos, object, "published", 8, 1, &published);
        if (error == 0)
            error = zap_lookup(mos, object, "native-proof", 8, 4, &job->receipt_proof);
        if (error == 0)
            error = zap_lookup(mos, object, "retired-bytes", 8, 1, &job->retired_bytes);
        if (error != 0 || published > 1 || job->phase != REBUILD_RECLAIMING)
            return (error != 0 ? error : EINVAL);
        job->receipt_published = published;
        return (0);
    }
    if (memcmp(&scope, &job->scope, sizeof (scope)) != 0)
        return (EBUSY);
    if (error == 0)
        error = zap_lookup(mos, object, "new-data", 8, 1, &job->new_data);
    if (error == 0)
        error = zap_lookup(mos, object, "retire-data", 8, 1, &job->retired_data);
    if (error == 0 && (job->new_data == 0 || job->retired_data == 0 ||
        job->new_data == job->retired_data || job->new_data == object ||
        job->retired_data == object))
        error = EINVAL;
    boolean_t published = job->phase >= REBUILD_FLAT_PUBLISHED;
    if (error == 0)
        error = dedup_fdt_data_validate(job->spa, job->new_data,
            DEDUP_FDT_NEW_DATA, published);
    if (error == 0)
        error = dedup_fdt_data_validate(job->spa, job->retired_data,
            DEDUP_FDT_RETIRE_DATA, published);
    return (error);
}
static void
df_stage_create(void *arg, dmu_tx_t *tx)
{
    df_job_t *job = arg;
    objset_t *mos = spa_get_dsl(job->spa)->dp_meta_objset;
    job->stage = zap_create(mos, DMU_OTN_ZAP_METADATA, DMU_OT_NONE, 0, tx);
    uint64_t format = DF_FORMAT, guid = spa_guid(job->spa);
    job->phase = REBUILD_LEGACY_RETIRED;
    VERIFY0(zap_add(mos, job->stage, "format", 8, 1, &format, tx));
    VERIFY0(zap_add(mos, job->stage, "guid", 8, 1, &guid, tx));
    VERIFY0(zap_add(mos, job->stage, "scope", 8, 4, &job->scope, tx));
    VERIFY0(zap_add(mos, job->stage, "phase", 8, 1, &job->phase, tx));
    for (size_t i = 0; i < job->options.dataset_count; i++) {
        char key[64];
        snprintf(key, sizeof (key), "dataset-%zu", i);
        VERIFY0(zap_add(mos, job->stage, key, 1,
            strlen(job->options.datasets[i])+1, job->options.datasets[i], tx));
    }
    VERIFY0(dedup_fdt_data_create(job->spa, DEDUP_FDT_NEW_DATA, tx, &job->new_data));
    VERIFY0(dedup_fdt_data_create(job->spa, DEDUP_FDT_RETIRE_DATA, tx, &job->retired_data));
    VERIFY0(zap_add(mos, job->stage, "new-data", 8, 1, &job->new_data, tx));
    VERIFY0(zap_add(mos, job->stage, "retire-data", 8, 1, &job->retired_data, tx));
    VERIFY0(zap_add(mos, DMU_POOL_DIRECTORY_OBJECT, DF_STAGE_KEY, 8, 1, &job->stage, tx));
    if (job->receipt != 0) {
        VERIFY0(zap_remove(mos, DMU_POOL_DIRECTORY_OBJECT, DF_DONE_KEY, tx));
        VERIFY0(dmu_object_free(mos, job->receipt, tx));
        job->receipt = 0;
    }
}

int __real_zil_claim(dsl_pool_t *, dsl_dataset_t *, void *);
int __wrap_zil_claim(dsl_pool_t *, dsl_dataset_t *, void *);

int
__wrap_zil_claim(dsl_pool_t *dp, dsl_dataset_t *dataset, void *arg)
{
    pthread_mutex_lock(&claim_lock);
    df_job_t *job = claim_job;
    if (job != NULL && claim_error == 0 && job->stage == 0) {
        spa_t *saved = job->spa;
        job->spa = dp->dp_spa;
        dmu_tx_t *tx = arg;
        zio_cksum_t proof;
        if (spa_guid(job->spa) == 0 || !dmu_tx_is_syncing(tx) ||
            dmu_tx_pool(tx) != dp ||
            dmu_tx_get_txg(tx) != spa_first_txg(job->spa)) {
            claim_error = EINVAL;
        } else {
            claim_error = df_stage_read(job);
            if (claim_error == 0 && job->stage != 0)
                claim_error = ESTALE;
            if (claim_error == 0)
                claim_error = dedup_fdt_admission_proof(job->spa,
                    job->options.batch_size, &proof);
            if (claim_error == 0)
                claim_error = dedup_fdt_admission_check(job->admission,
                    job->spa, &job->scope, &proof);
            if (claim_error == 0)
                df_stage_create(job, tx);
        }
        job->spa = saved;
    }
    int error = job != NULL ? claim_error : 0;
    pthread_mutex_unlock(&claim_lock);
    if (error != 0)
        return (error);
    /* Never suppress native claim, even for an unwritten terminal LWB. Its
     * physical allocation must be claimed before it can become reusable. */
    return (__real_zil_claim(dp, dataset, arg));
}
static void
df_prepared(void *arg, dmu_tx_t *tx)
{
    df_job_t *job = arg;
    job->phase = REBUILD_FLAT_PREPARED;
    VERIFY0(zap_update(spa_get_dsl(job->spa)->dp_meta_objset, job->stage,
        "phase", 8, 1, &job->phase, tx));
}
static int
df_publish_check(void *arg, dmu_tx_t *tx)
{
    df_job_t *job = arg;
    dedup_fdt_data_rele(job->new_hold);
    dedup_fdt_data_rele(job->retire_hold);
    job->new_hold = job->retire_hold = NULL;
    int error = rebuild_history_publish_check(job->history, B_TRUE, tx);
    if (error == 0)
        error = rebuild_bridge_publish_check(job->bridge, B_TRUE, tx);
    if (error == 0)
        error = dedup_fdt_data_hold(job->spa, job->new_data, &job->new_hold);
    if (error == 0)
        error = dedup_fdt_data_hold(job->spa, job->retired_data, &job->retire_hold);
    return (error);
}
static void
df_publish(void *arg, dmu_tx_t *tx)
{
    df_job_t *job = arg;
    VERIFY0(rebuild_history_publish(job->history, B_TRUE, tx));
    VERIFY0(rebuild_bridge_publish(job->bridge, B_TRUE, tx));
    dedup_fdt_data_publish(job->spa, job->new_hold, tx);
    dedup_fdt_data_publish(job->spa, job->retire_hold, tx);
    dedup_fdt_data_rele(job->new_hold);
    dedup_fdt_data_rele(job->retire_hold);
    job->new_hold = job->retire_hold = NULL;
    /* Owner scalars publish this same phase together with all root changes. */
    job->phase = REBUILD_FLAT_PUBLISHED;
}
static void
df_drain(void *arg, dmu_tx_t *tx)
{
    df_job_t *job = arg;
    boolean_t published = job->phase >= REBUILD_FLAT_PUBLISHED;
    boolean_t new_done = B_FALSE, retire_done = B_FALSE;
    uint64_t unused;
    job->error = dedup_fdt_data_drain(job->spa, job->new_data, published,
        job->options.batch_size, tx, &new_done, &unused);
    if (job->error == 0)
        job->error = dedup_fdt_data_drain(job->spa, job->retired_data, published,
            job->options.batch_size, tx, &retire_done, &job->retired_bytes);
    job->done = job->error == 0 && new_done && retire_done;
}
static void
df_finish(void *arg, dmu_tx_t *tx)
{
    df_job_t *job = arg;
    objset_t *mos = spa_get_dsl(job->spa)->dp_meta_objset;
    VERIFY0(dedup_fdt_data_destroy(job->spa, job->new_data, tx));
    VERIFY0(dedup_fdt_data_destroy(job->spa, job->retired_data, tx));
    VERIFY0(zap_remove(mos, job->stage, "new-data", tx));
    VERIFY0(zap_remove(mos, job->stage, "retire-data", tx));
    VERIFY0(zap_remove(mos, DMU_POOL_DIRECTORY_OBJECT, DF_STAGE_KEY, tx));
    uint64_t published = job->phase >= REBUILD_FLAT_PUBLISHED;
    job->phase = REBUILD_RECLAIMING;
    VERIFY0(zap_update(mos, job->stage, "phase", 8, 1, &job->phase, tx));
    VERIFY0(zap_add(mos, job->stage, "published", 8, 1, &published, tx));
    VERIFY0(zap_add(mos, job->stage, "native-proof", 8, 4, &job->native_proof, tx));
    VERIFY0(zap_add(mos, job->stage, "retired-bytes", 8, 1, &job->retired_bytes, tx));
    VERIFY0(zap_add(mos, DMU_POOL_DIRECTORY_OBJECT, DF_DONE_KEY, 8, 1, &job->stage, tx));
    job->receipt = job->stage;
    job->receipt_published = published;
    job->stage = job->new_data = job->retired_data = 0;
}
static void
df_close_engines(df_job_t *job)
{
    dedup_fdt_data_rele(job->new_hold);
    dedup_fdt_data_rele(job->retire_hold);
    job->new_hold = job->retire_hold = NULL;
    rebuild_history_close(job->history);
    rebuild_bridge_close(job->bridge);
    job->history = NULL;
    job->bridge = NULL;
}
static int
df_recover(df_job_t *job)
{
    int error = 0;
    if (job->history == NULL)
        error = rebuild_history_open_resources(job->spa, job->stage,
            job->options.batch_size, job->options.resources, &job->history);
    if (error == 0 && job->bridge == NULL)
        error = rebuild_bridge_open(job->spa, job->stage,
            job->options.batch_size, &job->bridge);
    if (error == 0)
        error = rebuild_history_recover(job->history);
    if (error == 0)
        error = rebuild_bridge_recover(job->bridge);
    while (error == 0 && !job->done) {
        if (rebuild_interrupted())
            return (EINTR);
        error = dsl_sync_task(spa_name(job->spa), NULL, df_drain, job, 32,
            ZFS_SPACE_CHECK_DESTROY);
        if (error == 0)
            error = job->error;
        if (error == 0) {
            if (job->plan != NULL)
                dedup_fdt_plan_retired(job->plan, job->retired_bytes);
            else {
                printf("{\"event\":\"progress\",\"phase\":\"retiring\","
                    "\"timestamp\":%lld,\"retired_bytes\":%llu,"
                    "\"rate_bytes_per_second\":null,\"eta_seconds\":null}\n",
                    (long long)time(NULL), (u_longlong_t)job->retired_bytes);
                fflush(stdout);
            }
        }
    }
    if (error == 0)
        error = dedup_fdt_admission_proof(job->spa, job->options.batch_size,
            &job->native_proof);
    if (error == 0)
        error = dsl_sync_task(spa_name(job->spa), NULL, df_finish, job, 16,
            ZFS_SPACE_CHECK_DESTROY);
    return (error);
}
static int
df_step(int error, const char *step)
{
    if (error != 0)
        fprintf(stderr, "dedup-fdt: native step '%s' failed: %d (%s)\n",
            step, error, strerror(error));
    return (error);
}

static int
df_run(df_job_t *job)
{
    rebuild_history_t *preflight = NULL;
    int error = df_step(dedup_fdt_plan_history(job->plan, job->spa, 0,
        &preflight), "history preflight");
    rebuild_history_close(preflight);
    if (error == 0)
        error = df_step(dsl_sync_task(spa_name(job->spa), NULL,
            df_stage_create, job, 64, ZFS_SPACE_CHECK_NORMAL), "stage creation");
    if (error == 0)
        error = df_phase(0);
    if (error == 0)
        error = df_step(dedup_fdt_plan_admit(job->plan, job->spa,
            job->stage, &job->bridge), "native DDT quota admission");
    if (error == 0 && !dedup_fdt_plan_has_changes(job->plan))
        return (df_step(df_recover(job), "quota-only stage cleanup"));
    if (error == 0)
        error = df_step(dedup_fdt_plan_history(job->plan, job->spa,
            job->stage, &job->history), "staged history open/check");
    if (error == 0)
        error = df_step(dedup_fdt_plan_allocate(job->plan, job->new_data),
            "canonical allocation/verification");
    if (error == 0)
        error = df_phase(1);
    if (error == 0) {
        dedup_fdt_plan_progress(job->plan, "preparing-history", B_TRUE);
        error = df_step(rebuild_history_prepare(job->history, B_TRUE),
            "history preparation");
    }
    if (error == 0)
        error = df_step(dedup_fdt_plan_prepared(job->plan, job->history,
            job->retired_data), "prepared ownership audit");
    if (error == 0 && job->bridge == NULL)
        error = df_step(rebuild_bridge_open(job->spa, job->stage,
            job->options.batch_size, &job->bridge), "FDT/BRT bridge open");
    if (error == 0)
        error = df_step(dedup_fdt_plan_bridge(job->plan, job->bridge),
            "FDT/BRT source binding");
    if (error == 0)
        error = df_step(rebuild_bridge_prepare(job->bridge, B_TRUE),
            "FDT/BRT preparation");
    if (error == 0)
        error = df_step(dsl_sync_task(spa_name(job->spa), NULL,
            df_prepared, job, 8, ZFS_SPACE_CHECK_NORMAL), "prepared marker");
    if (error == 0)
        error = df_phase(2);
    if (error == 0)
        error = df_step(dsl_sync_task(spa_name(job->spa),
            df_publish_check, df_publish, job, 256, ZFS_SPACE_CHECK_NORMAL),
            "atomic publication");
    if (error == 0)
        error = df_phase(3);
    if (error == 0)
        error = df_step(df_recover(job), "published retirement/recovery");
    if (error == 0)
        error = df_phase(4);
    return (error);
}
static int
df_name_compare(const void *left, const void *right)
{
    return (strcmp(*(const char *const *)left, *(const char *const *)right));
}
int
main(int argc, char **argv)
{
    long cpus = sysconf(_SC_NPROCESSORS_ONLN);
    df_job_t job = { .options = { .workers = cpus < 1 ? 1 : cpus > 64 ? 64 : cpus,
        .batch_size = 1024 } };
    boolean_t plan_only = B_FALSE, dedup = B_FALSE, fenced = B_FALSE, list = B_FALSE;
    boolean_t initialized = B_FALSE, writable = B_FALSE, active_labels = B_FALSE;
    uint64_t guid = 0, arc_max = 0, memory_max = 16ULL<<30, disk_max = 0, value;
    char *search = NULL, *work = NULL, *pool = NULL;
    int lockfd = -1, workfd = -1, cachefd = -1;
    nvlist_t *config = NULL, *props = NULL;
    int error = rebuild_keys_create(&job.keys);
    if (error != 0)
        return (1);
    static const struct option options[] = {
        {"plan", no_argument, NULL, 'p'}, {"dedup", no_argument, NULL, 'D'},
        {"fenced", no_argument, NULL, 'f'}, {"pool-guid", required_argument, NULL, 'g'},
        {"search-dir", required_argument, NULL, 's'}, {"work-dir", required_argument, NULL, 'w'},
        {"dataset", required_argument, NULL, 'd'}, {"key-file", required_argument, NULL, 'k'},
        {"workers", required_argument, NULL, 'j'}, {"batch-size", required_argument, NULL, 'b'},
        {"arc-max-bytes", required_argument, NULL, 'a'},
        {"memory-max-bytes", required_argument, NULL, 'm'},
        {"disk-max-bytes", required_argument, NULL, 'q'},
        {"list-test-phases", no_argument, NULL, 'l'}, {"help", no_argument, NULL, 'h'},
        {NULL, 0, NULL, 0}
    };
    int option;
    while ((option = getopt_long(argc, argv, "", options, NULL)) != -1) {
        switch (option) {
        case 'p': plan_only = B_TRUE; break;
        case 'D': dedup = B_TRUE; break;
        case 'f': fenced = B_TRUE; break;
        case 'g': error = df_number(optarg, &guid); break;
        case 's': search = optarg; break;
        case 'w': work = optarg; break;
        case 'd': {
            const char **names = realloc(job.options.datasets,
                (job.options.dataset_count+1)*sizeof (*names));
            if (names == NULL) { error = ENOMEM; break; }
            job.options.datasets = names;
            names[job.options.dataset_count++] = optarg;
            break;
        }
        case 'k': error = rebuild_keys_add(job.keys, optarg); break;
        case 'j':
            error = df_number(optarg, &value);
            if (error == 0 && (value == 0 || value > 64)) error = EINVAL;
            if (error == 0) job.options.workers = value;
            break;
        case 'b':
            error = df_number(optarg, &value);
            if (error == 0 && (value == 0 || value > 65536)) error = EINVAL;
            if (error == 0) job.options.batch_size = value;
            break;
        case 'a': error = df_number(optarg, &arc_max); if (arc_max == 0) error = EINVAL; break;
        case 'm': error = df_number(optarg, &memory_max);
            if (memory_max == 0) error = EINVAL;
            break;
        case 'q': error = df_number(optarg, &disk_max);
            if (disk_max == 0) error = EINVAL;
            break;
        case 'l': list = B_TRUE; break;
        case 'h': df_usage(stdout); goto out;
        default: error = EINVAL; break;
        }
        if (error != 0)
            goto invalid;
    }
    if (list && argc == 2) {
        printf("{\"phases\":[");
        for (size_t i = 0; i < DF_PHASES; i++)
            printf("%s\"%s\"", i ? "," : "", phases[i]);
        puts("]}");
        goto out;
    }
    if (list || optind != argc || plan_only == dedup || guid == 0 || search == NULL ||
        work == NULL || disk_max == 0 || job.options.dataset_count == 0 || (dedup && !fenced))
        goto invalid;
    /* Native 2.4.4 ignores ARC maxima below 64MiB. Budget the real minimum,
     * and explicitly lower its minimum before applying the requested cap. */
    if (arc_max == 0) {
        arc_max = memory_max/4;
        if (arc_max < (64ULL<<20)) arc_max = 64ULL<<20;
        if (arc_max > (1ULL<<30)) arc_max = 1ULL<<30;
    }
    if (arc_max < (64ULL<<20)) { error = EINVAL; goto out; }
    error = dedup_fdt_resources_open(memory_max, disk_max, arc_max,
        &job.options.resources);
    if (error != 0) goto out;
    arc_max = dedup_fdt_resources_arc_limit(job.options.resources);
    if (geteuid() != 0 || getenv("ZFS_HOSTID") != NULL) { error = EPERM; goto out; }
    qsort(job.options.datasets, job.options.dataset_count,
        sizeof (*job.options.datasets), df_name_compare);
    size_t unique = 0;
    for (size_t i = 0; i < job.options.dataset_count; i++)
        if (i == 0 || strcmp(job.options.datasets[i], job.options.datasets[i-1]) != 0)
            job.options.datasets[unique++] = job.options.datasets[i];
    job.options.dataset_count = unique;
    FILE *version_file = fopen("/sys/module/zfs/version", "r");
    char version[128];
    if (version_file == NULL) { error = ENODEV; goto out; }
    if (fgets(version, sizeof (version), version_file) == NULL)
        error = ENODEV;
    fclose(version_file);
    if (error == 0 && strcmp(version, "2.4.4-1\n") != 0 && strcmp(version, "2.4.4-1") != 0)
        error = ENOTSUP;
    if (error != 0)
        goto out;
    error = df_fault_setup(dedup && fenced);
    if (error != 0)
        goto out;
    char lockpath[128];
    snprintf(lockpath, sizeof (lockpath), "/run/lock/convert-ddt-%llu.lock", (u_longlong_t)guid);
    lockfd = open(lockpath, O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (lockfd < 0 || flock(lockfd, LOCK_EX | LOCK_NB) != 0) { error = errno; goto out; }
    struct stat lock_info;
    if (fstat(lockfd, &lock_info) != 0) { error = errno; goto out; }
    if (!S_ISREG(lock_info.st_mode) || lock_info.st_uid != 0 ||
        lock_info.st_nlink != 1 || (lock_info.st_mode&0077) != 0) {
        error = EPERM;
        goto out;
    }
    workfd = open(work, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (workfd < 0) { error = errno; goto out; }
    struct stat work_info;
    if (fstat(workfd, &work_info) != 0) { error = errno; goto out; }
    if (work_info.st_uid != geteuid() || (work_info.st_mode&0022) != 0) {
        error = EPERM;
        goto out;
    }
    error = dedup_fdt_resources_set_directory(job.options.resources, workfd);
    if (error != 0) goto out;
    error = df_reject_kernel(guid);
    if (error != 0)
        goto out;
    stopfd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
    if (stopfd < 0) { error = errno; goto out; }
    struct sigaction action = { .sa_handler = df_signal };
    sigemptyset(&action.sa_mask);
    sigaction(SIGINT, &action, NULL);
    sigaction(SIGTERM, &action, NULL);
    signal(SIGPIPE, SIG_IGN);
    setvbuf(stdout, NULL, _IOLBF, 0);
    if (handle_tunable_option("zfs_import_defer_txgs=4294967295", B_TRUE) != 0) {
        error = EINVAL;
        goto out;
    }
    /* libzpool does not register the kernel-only ARC setter tunables.
     * Configure the exported userspace variables before native ARC init. */
    zfs_arc_min = 32ULL << 20;
    zfs_arc_max = arc_max;
    cachefd = memfd_create("dedup-fdt-cache", MFD_CLOEXEC | MFD_ALLOW_SEALING);
    if (cachefd < 0 || fcntl(cachefd, F_ADD_SEALS,
        F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL) != 0) {
        error = errno;
        goto out;
    }
    char cachepath[64];
    snprintf(cachepath, sizeof (cachepath), "/proc/self/fd/%d", cachefd);
    spa_config_path = cachepath;
readonly_open:
    zfs_arc_min = 32ULL << 20;
    kernel_init(SPA_MODE_READ);
    zfs_arc_min = arc_c_max;
    arc_tuning_update(B_FALSE);
    initialized = B_TRUE;
    props = fnvlist_alloc();
    char target[32];
    snprintf(target, sizeof (target), "%llu", (u_longlong_t)guid);
    importargs_t args = { .path = &search, .paths = 1, .guid = guid, .scan = B_TRUE };
    libpc_handle_t handle = { .lpc_ops = &libzpool_config_ops, .lpc_printerr = B_TRUE };
    error = zpool_find_config(&handle, target, &config, &args);
    if (error != 0)
        goto out;
    uint64_t found, state;
    const char *name;
    if (nvlist_lookup_uint64(config, ZPOOL_CONFIG_POOL_GUID, &found) != 0 || found != guid ||
        nvlist_lookup_uint64(config, ZPOOL_CONFIG_POOL_STATE, &state) != 0 ||
        (state != POOL_STATE_EXPORTED && (!dedup || state != POOL_STATE_ACTIVE)) ||
        nvlist_lookup_string(config, ZPOOL_CONFIG_POOL_NAME, &name) != 0) {
        error = EINVAL;
        goto out;
    }
    pool = strdup(name);
    if (pool == NULL) { error = ENOMEM; goto out; }
    fnvlist_add_string(props, "cachefile", "none");
    fnvlist_add_uint64(props, "readonly", 1);
    error = df_reject_kernel(guid);
    if (error == 0)
        error = spa_import(pool, config, props, ZFS_IMPORT_NORMAL);
    if (error == 0)
        error = spa_open(pool, &job.spa, tag);
    if (error != 0)
        goto out;
    spa_config_enter(job.spa, SCL_STATE_ALL, tag, RW_WRITER);
    error = df_labels(job.spa->spa_root_vdev, dedup && fenced, &active_labels);
    spa_config_exit(job.spa, SCL_STATE_ALL, tag);
    if (error == 0) error = df_quiescent(job.spa);
    if (error == 0) error = df_scope(&job);
    if (error == 0) error = df_stage_read(&job);
    if (error == 0 && plan_only && job.stage != 0)
        error = df_problem(EBUSY, "owned recovery must complete before a new read-only plan");
    if (error == 0) error = rebuild_keys_load(job.keys, job.spa);
    if (error == 0 && active_labels && job.stage == 0) {
        error = dedup_fdt_admission_proof(job.spa, job.options.batch_size,
            &job.native_proof);
        if (error == 0 && !(job.receipt != 0 && job.receipt_matches &&
            memcmp(&job.native_proof, &job.receipt_proof,
            sizeof (job.native_proof)) == 0))
            error = dedup_fdt_admission_open(job.spa, workfd, &job.scope,
                &job.native_proof, B_TRUE, &job.admission);
    }
    if (error == 0 && job.stage == 0 &&
        (!active_labels || job.admission != NULL))
        error = dedup_fdt_plan_create(job.spa, workfd, &job.options, &job.plan);
    if (error != 0 || rebuild_interrupted()) { if (error == 0) error = EINTR; goto out; }
    if (plan_only) {
        dedup_fdt_plan_result(job.plan, "planned");
        goto out;
    }
    if (!active_labels && job.plan != NULL && !dedup_fdt_plan_has_changes(job.plan)) {
        dedup_fdt_plan_result(job.plan, "deduplicated");
        goto out;
    }
    if (job.plan != NULL && job.admission == NULL) {
        error = dedup_fdt_admission_proof(job.spa, job.options.batch_size,
            &job.native_proof);
        if (error == 0)
            error = dedup_fdt_admission_open(job.spa, workfd, &job.scope,
                &job.native_proof, B_FALSE, &job.admission);
        if (error != 0)
            goto out;
    }
    rebuild_keys_unload(job.keys);
    spa_close(job.spa, tag);
    job.spa = NULL;
    kernel_fini();
    initialized = B_FALSE;
    error = df_reject_kernel(guid);
    if (error == 0) error = rebuild_sync_fence(guid);
    if (error != 0)
        goto out;
    zfs_arc_min = 32ULL << 20;
    kernel_init(SPA_MODE_READ | SPA_MODE_WRITE);
    zfs_arc_min = arc_c_max;
    arc_tuning_update(B_FALSE);
    initialized = B_TRUE;
    VERIFY0(nvlist_remove_all(props, "readonly"));
    claim_error = 0;
    if (job.stage == 0 && dedup_fdt_plan_needs_claim(job.plan))
        claim_job = &job;
    error = spa_import(pool, config, props, ZFS_IMPORT_NORMAL);
    claim_job = NULL;
    if (error != 0)
        goto out;
    writable = B_TRUE;
    error = spa_open(pool, &job.spa, tag);
    if (error != 0)
        goto out;
    if (claim_error != 0) { error = claim_error; goto out; }
    if (spa_guid(job.spa) != guid) { error = EINVAL; goto out; }
    spa_async_suspend(job.spa);
    txg_wait_synced(spa_get_dsl(job.spa), 0);
    if (error == 0) error = df_quiescent(job.spa);
    if (error == 0) error = rebuild_keys_load(job.keys, job.spa);
    if (error == 0) error = df_stage_read(&job);
    if (error != 0)
        goto out;
    if (job.stage == 0) {
        error = dedup_fdt_admission_proof(job.spa, job.options.batch_size,
            &job.native_proof);
        if (error == 0 && job.admission != NULL) {
            error = dedup_fdt_admission_check(job.admission, job.spa,
                &job.scope, &job.native_proof);
        } else if (error == 0 && (job.receipt == 0 || !active_labels ||
            !job.receipt_matches || memcmp(&job.native_proof,
            &job.receipt_proof, sizeof (job.native_proof)) != 0)) {
            error = EBUSY;
        }
        if (error != 0)
            goto out;
        if (job.plan != NULL) {
            boolean_t now_active = B_FALSE;
            spa_config_enter(job.spa, SCL_STATE_ALL, tag, RW_WRITER);
            error = df_labels(job.spa->spa_root_vdev, B_TRUE, &now_active);
            spa_config_exit(job.spa, SCL_STATE_ALL, tag);
            int marker = zap_contains(spa_get_dsl(job.spa)->dp_meta_objset,
                DMU_POOL_DIRECTORY_OBJECT, DF_STAGE_KEY);
            if (error == 0 && (!now_active || marker != ENOENT))
                error = marker != 0 && marker != ENOENT ? marker : ESTALE;
            if (error == 0)
                error = df_phase(5);
            if (error != 0)
                goto out;
        }
    }
    if (job.stage != 0) {
        boolean_t published = job.phase >= REBUILD_FLAT_PUBLISHED;
        error = df_recover(&job);
        if (error != 0 || published) {
            if (error == 0)
                printf("{\"event\":\"complete\",\"status\":\"recovered\","
                    "\"retired_bytes\":%llu}\n", (u_longlong_t)job.retired_bytes);
            goto out;
        }
        /* Prepublication ownership was aborted using MOS only. Start a fresh
         * read-only discovery after clean export; never trust stale scratch. */
        df_close_engines(&job);
export_restart:
        dedup_fdt_admission_close(job.admission);
        job.admission = NULL;
        dedup_fdt_plan_close(job.plan);
        job.plan = NULL;
        rebuild_keys_unload(job.keys);
        spa_close(job.spa, tag);
        job.spa = NULL;
        error = spa_export(pool, NULL, B_FALSE, B_FALSE);
        if (error != 0)
            goto out;
        kernel_fini();
        initialized = writable = B_FALSE;
        rebuild_sync_unfence();
        nvlist_free(config); config = NULL;
        nvlist_free(props); props = NULL;
        free(pool); pool = NULL;
        active_labels = B_FALSE;
        job.done = B_FALSE;
        goto readonly_open;
    }
    if (active_labels && job.receipt != 0 && job.admission == NULL) {
        if (!job.receipt_published)
            goto export_restart;
        printf("{\"event\":\"complete\",\"status\":\"recovered\","
            "\"retired_bytes\":%llu}\n", (u_longlong_t)job.retired_bytes);
        goto out;
    }
    if (!dedup_fdt_plan_has_changes(job.plan)) {
        dedup_fdt_plan_result(job.plan, "deduplicated");
        goto out;
    }
    error = df_run(&job);
    if (error == 0)
        dedup_fdt_plan_result(job.plan, "deduplicated");
    goto out;
invalid:
    df_usage(stderr);
    error = EINVAL;
out:
    df_close_engines(&job);
    rebuild_keys_unload(job.keys);
    if (job.spa != NULL) {
        if (writable)
            txg_wait_synced(spa_get_dsl(job.spa), 0);
        spa_close(job.spa, tag);
    }
    if (writable && pool != NULL) {
        int export_error = spa_export(pool, NULL, B_FALSE, B_FALSE);
        if (export_error != 0)
            error = df_problem(export_error, "export failed; retain maintenance fence");
        else if (error == 0 && job.stage == 0)
            error = job.admission != NULL ?
                dedup_fdt_admission_remove(job.admission) :
                dedup_fdt_admission_cleanup(workfd, guid, &job.scope);
    }
    if (initialized)
        kernel_fini();
    rebuild_sync_unfence();
    dedup_fdt_plan_close(job.plan);
    dedup_fdt_admission_close(job.admission);
    rebuild_keys_destroy(job.keys);
    free(job.options.datasets);
    dedup_fdt_resources_close(job.options.resources);
    nvlist_free(config);
    nvlist_free(props);
    free(pool);
    if (cachefd >= 0) close(cachefd);
    if (workfd >= 0) close(workfd);
    if (lockfd >= 0) close(lockfd);
    if (stopfd >= 0) close(stopfd);
    if (error != 0)
        df_problem(error, "operation incomplete; retain fence and retry identical --dedup scope");
    return (rebuild_interrupted() || error == EINTR ? 130 : error != 0 ? 1 : 0);
}
