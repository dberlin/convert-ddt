/* SPDX-License-Identifier: CDDL-1.0
 * Prepare an independently importable pool on orchestrator-owned COW NBDs.
 */
#include <sys/zfs_context.h>
#include <sys/spa.h>
#include <sys/spa_impl.h>
#include <sys/dmu.h>
#include <sys/dsl_pool.h>
#include <sys/dsl_prop.h>
#include <sys/dsl_synctask.h>
#include <sys/dmu_tx.h>
#include <sys/txg.h>
#include <sys/vdev_impl.h>
#include <sys/zfs_file.h>
#include <sys/zfs_ioctl.h>
#include <libzutil.h>
#include <zfs_namecheck.h>
#include <dirent.h>
#include <getopt.h>
#include <limits.h>
#include <linux/fs.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/mman.h>
#include <time.h>

static const char *tag = "clone-pool";

typedef struct overlay {
    char path[PATH_MAX];
    char fdpath[64];
    int fd;
    dev_t rdev;
    uint64_t guid;
    unsigned int seen;
} overlay_t;

static overlay_t *overlays;
static size_t noverlays;
static int denied_open;
static int cachefd = -1;
static char cachepath[64];
static struct stat cache_identity;

int __real_zfs_file_open(const char *, int, int, cred_t *, zfs_file_t **);
int __wrap_zfs_file_open(const char *, int, int, cred_t *, zfs_file_t **);

/* Keep phase evidence on stderr; stdout is the clone_guid protocol. */
static void
phase(const char *name, const char *event, int error)
{
    fprintf(stderr, "{\"timestamp\":%llu,\"phase\":\"%s\","
        "\"event\":\"%s\",\"errno\":%d}\n",
        (u_longlong_t)time(NULL), name, event, error);
    fflush(stderr);
}

static int
problem(int error, const char *message)
{
    fprintf(stderr, "clone-pool: %s: %s\n", message, strerror(error));
    return (error);
}

static overlay_t *
allowed_path(const char *path)
{
    char resolved[PATH_MAX];
    struct stat st;
    if (path == NULL || realpath(path, resolved) == NULL ||
        stat(resolved, &st) != 0 || !S_ISBLK(st.st_mode))
        return (NULL);
    for (size_t i = 0; i < noverlays; i++) {
        if (strcmp(resolved, overlays[i].path) == 0 &&
            st.st_rdev == overlays[i].rdev)
            return (&overlays[i]);
    }
    return (NULL);
}

/* Pin allowlisted device descriptors to preserve identity across path changes. */
int
__wrap_zfs_file_open(const char *path, int flags, int mode, cred_t *cr,
    zfs_file_t **fp)
{
    overlay_t *overlay = allowed_path(path);
    const char *pinned = NULL;
    dev_t expected = 0;
    if (overlay != NULL) {
        pinned = overlay->fdpath;
        expected = overlay->rdev;
    } else if (path != NULL && strcmp(path, cachepath) == 0 && cachefd >= 0) {
        pinned = cachepath;
    }
    if (pinned == NULL || (flags & (O_CREAT | O_TRUNC | O_EXCL))) {
        __atomic_store_n(&denied_open, 1, __ATOMIC_RELAXED);
        fprintf(stderr, "clone-pool: denied libzpool open: %s\n",
            path != NULL ? path : "(null)");
        *fp = NULL;
        return (EACCES);
    }
    int error = __real_zfs_file_open(pinned, flags, mode, cr, fp);
    if (error == 0) {
        struct stat st;
        if (fstat((*fp)->f_fd, &st) != 0 ||
            (overlay != NULL && (!S_ISBLK(st.st_mode) || st.st_rdev != expected)) ||
            (overlay == NULL && (!S_ISREG(st.st_mode) || st.st_size != 0 ||
            st.st_dev != cache_identity.st_dev || st.st_ino != cache_identity.st_ino))) {
            zfs_file_close(*fp);
            *fp = NULL;
            __atomic_store_n(&denied_open, 1, __ATOMIC_RELAXED);
            error = EACCES;
        }
    }
    return (error);
}

static int
parse_uint(const char *text, uint64_t *value)
{
    if (text == NULL || text[0] < '0' || text[0] > '9')
        return (EINVAL);
    char *end;
    errno = 0;
    unsigned long long n = strtoull(text, &end, 10);
    if (errno != 0 || *end != '\0' || n == 0)
        return (EINVAL);
    *value = n;
    return (0);
}

static int
add_overlay(const char *directory, const char *name)
{
    char entry[PATH_MAX], resolved[PATH_MAX], sysfile[PATH_MAX];
    struct stat st;
    if (snprintf(entry, sizeof (entry), "%s/%s", directory, name) >=
        (int)sizeof (entry))
        return (ENAMETOOLONG);
    if (lstat(entry, &st) != 0)
        return (errno);
    if (!S_ISLNK(st.st_mode) || realpath(entry, resolved) == NULL)
        return (EINVAL);
    if (strncmp(resolved, "/dev/nbd", 8) != 0 || resolved[8] == '\0')
        return (EINVAL);
    for (const char *p = resolved + 8; *p != '\0'; p++)
        if (*p < '0' || *p > '9')
            return (EINVAL);
    if (stat(resolved, &st) != 0)
        return (errno);
    if (!S_ISBLK(st.st_mode))
        return (EINVAL);
    if (noverlays >= INT_MAX)
        return (E2BIG);
    snprintf(sysfile, sizeof (sysfile), "/sys/class/block/%s/dev", resolved + 5);
    FILE *devfile = fopen(sysfile, "r");
    unsigned int devmajor = 0, devminor = 0;
    if (devfile == NULL)
        return (ENODEV);
    int devfields = fscanf(devfile, "%u:%u", &devmajor, &devminor);
    fclose(devfile);
    if (devfields != 2 || st.st_rdev != makedev(devmajor, devminor))
        return (ENODEV);
    for (size_t i = 0; i < noverlays; i++)
        if (st.st_rdev == overlays[i].rdev)
            return (EEXIST);
    snprintf(sysfile, sizeof (sysfile), "/sys/class/block/%s/pid", resolved + 5);
    FILE *pidfile = fopen(sysfile, "r");
    long pid = 0;
    if (pidfile == NULL)
        return (ENODEV);
    int scanned = fscanf(pidfile, "%ld", &pid);
    fclose(pidfile);
    if (scanned != 1 || pid <= 0)
        return (ENODEV);
    int fd = open(resolved, O_RDWR | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0)
        return (errno);
    struct stat opened;
    uint64_t size = 0;
    if (fstat(fd, &opened) != 0 || !S_ISBLK(opened.st_mode) ||
        opened.st_rdev != st.st_rdev || ioctl(fd, BLKGETSIZE64, &size) != 0 ||
        size == 0) {
        close(fd);
        return (ENODEV);
    }
    overlay_t *grown = realloc(overlays, (noverlays + 1) * sizeof (*overlays));
    if (grown == NULL) {
        close(fd);
        return (ENOMEM);
    }
    overlays = grown;
    overlay_t *overlay = &overlays[noverlays++];
    memset(overlay, 0, sizeof (*overlay));
    strcpy(overlay->path, resolved);
    overlay->fd = fd;
    overlay->rdev = st.st_rdev;
    snprintf(overlay->fdpath, sizeof (overlay->fdpath), "/proc/self/fd/%d", fd);
    return (0);
}

static int
load_devices(const char *directory)
{
    struct stat st;
    if (lstat(directory, &st) != 0)
        return (errno);
    if (!S_ISDIR(st.st_mode))
        return (ENOTDIR);
    DIR *dir = opendir(directory);
    if (dir == NULL)
        return (errno);
    int error = 0;
    struct dirent *entry;
    for (;;) {
        errno = 0;
        entry = readdir(dir);
        if (entry == NULL) {
            error = errno;
            break;
        }
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            continue;
        error = add_overlay(directory, entry->d_name);
        if (error != 0)
            break;
    }
    closedir(dir);
    return (error != 0 ? error : noverlays == 0 ? ENOENT : 0);
}

static int
read_identities(uint64_t source)
{
    for (size_t i = 0; i < noverlays; i++) {
        nvlist_t *label = NULL;
        int labels = 0;
        int error = zpool_read_label(overlays[i].fd, &label, &labels);
        uint64_t guid = 0, poolguid = 0, state = 0;
        if (error != 0 || label == NULL || labels == 0 ||
            nvlist_lookup_uint64(label, ZPOOL_CONFIG_GUID, &guid) != 0 || !guid ||
            nvlist_lookup_uint64(label, ZPOOL_CONFIG_POOL_STATE, &state) != 0) {
            nvlist_free(label);
            return (EINVAL);
        }
        if (state != POOL_STATE_SPARE && state != POOL_STATE_L2CACHE &&
            (nvlist_lookup_uint64(label, ZPOOL_CONFIG_POOL_GUID, &poolguid) != 0 ||
            poolguid != source)) {
            nvlist_free(label);
            return (EINVAL);
        }
        nvlist_free(label);
        for (size_t j = 0; j < i; j++)
            if (overlays[j].guid == guid)
                return (EEXIST);
        overlays[i].guid = guid;
    }
    return (0);
}

/* Resolve device paths through the overlay's label GUID. */
static int
map_config(nvlist_t *node)
{
    static const char *arrays[] = {
        ZPOOL_CONFIG_CHILDREN, ZPOOL_CONFIG_SPARES, ZPOOL_CONFIG_L2CACHE
    };
    nvlist_t **children;
    uint_t count;
    boolean_t leaf = B_TRUE;
    for (size_t a = 0; a < sizeof (arrays) / sizeof (arrays[0]); a++) {
        int error = nvlist_lookup_nvlist_array(node, arrays[a], &children, &count);
        if (error == ENOENT)
            continue;
        if (error != 0)
            return (error);
        if (a == 0 && count != 0)
            leaf = B_FALSE;
        for (uint_t i = 0; i < count; i++) {
            error = map_config(children[i]);
            if (error != 0)
                return (error);
        }
    }
    if (!leaf)
        return (0);
    const char *type;
    uint64_t guid;
    if (nvlist_lookup_string(node, ZPOOL_CONFIG_TYPE, &type) != 0 ||
        (strcmp(type, VDEV_TYPE_DISK) != 0 && strcmp(type, VDEV_TYPE_FILE) != 0) ||
        nvlist_lookup_uint64(node, ZPOOL_CONFIG_GUID, &guid) != 0)
        return (EINVAL);
    for (size_t i = 0; i < noverlays; i++) {
        if (overlays[i].guid != guid)
            continue;
        if (++overlays[i].seen != 1)
            return (EINVAL);
        fnvlist_add_string(node, ZPOOL_CONFIG_PATH, overlays[i].path);
        (void) nvlist_remove_all(node, ZPOOL_CONFIG_DEVID);
        (void) nvlist_remove_all(node, ZPOOL_CONFIG_PHYS_PATH);
        (void) nvlist_remove_all(node, ZPOOL_CONFIG_VDEV_ENC_SYSFS_PATH);
        fnvlist_add_uint64(node, ZPOOL_CONFIG_WHOLE_DISK, 0);
        return (0);
    }
    return (EACCES);
}

static int
validate_vdev(vdev_t *vd)
{
    if (vd->vdev_children != 0) {
        for (uint64_t i = 0; i < vd->vdev_children; i++) {
            int error = validate_vdev(vd->vdev_child[i]);
            if (error != 0)
                return (error);
        }
        return (0);
    }
    overlay_t *overlay = allowed_path(vd->vdev_path);
    if (overlay == NULL || overlay->guid != vd->vdev_guid || ++overlay->seen != 1)
        return (EACCES);
    if (vd->vdev_state != VDEV_STATE_HEALTHY)
        return (ENXIO);
    return (0);
}

static int
validate_loaded(spa_t *spa, uint64_t source, boolean_t checkpoint)
{
    if (spa_guid(spa) != source || __atomic_load_n(&denied_open, __ATOMIC_RELAXED))
        return (EACCES);
    for (size_t i = 0; i < noverlays; i++)
        overlays[i].seen = 0;
    spa_config_enter(spa, SCL_ALL, tag, RW_READER);
    int error = validate_vdev(spa->spa_root_vdev);
    spa_aux_vdev_t *aux[] = { &spa->spa_spares, &spa->spa_l2cache };
    for (size_t a = 0; error == 0 && a < sizeof (aux) / sizeof (aux[0]); a++)
        for (int i = 0; error == 0 && i < aux[a]->sav_count; i++)
            error = validate_vdev(aux[a]->sav_vdevs[i]);
    spa_config_exit(spa, SCL_ALL, tag);
    for (size_t i = 0; error == 0 && i < noverlays; i++)
        if (overlays[i].seen != 1)
            error = EINVAL;
    /* A completed checkpoint rewind leaves an independent pool state. */
    if (error == 0 && spa_has_checkpoint(spa))
        error = checkpoint ? EIO : EBUSY;
    return (error);
}

static void
normalize_vdev(vdev_t *vd)
{
    for (uint64_t i = 0; i < vd->vdev_children; i++)
        normalize_vdev(vd->vdev_child[i]);
    if (vd->vdev_children != 0)
        return;
    /* File-backed fixtures become block vdevs for subsequent kernel imports.
     * The two libzpool operation tables use the same file-I/O callbacks.
     */
    vd->vdev_ops = &vdev_disk_ops;
    vd->vdev_wholedisk = 0;
    if (vd->vdev_devid != NULL)
        spa_strfree(vd->vdev_devid);
    vd->vdev_devid = NULL;
    if (vd->vdev_physpath != NULL)
        spa_strfree(vd->vdev_physpath);
    vd->vdev_physpath = NULL;
    if (vd->vdev_enc_sysfs_path != NULL)
        spa_strfree(vd->vdev_enc_sysfs_path);
    vd->vdev_enc_sysfs_path = NULL;
}

static void
normalize_config(void *arg, dmu_tx_t *tx)
{
    (void) arg;
    spa_t *spa = dmu_tx_pool(tx)->dp_spa;
    spa_config_enter(spa, SCL_STATE, tag, RW_WRITER);
    normalize_vdev(spa->spa_root_vdev);
    spa_aux_vdev_t *aux[] = { &spa->spa_spares, &spa->spa_l2cache };
    for (size_t a = 0; a < sizeof (aux) / sizeof (aux[0]); a++) {
        for (int i = 0; i < aux[a]->sav_count; i++)
            normalize_vdev(aux[a]->sav_vdevs[i]);
        if (aux[a]->sav_count != 0)
            aux[a]->sav_sync = aux[a]->sav_label_sync = B_TRUE;
    }
    vdev_config_dirty(spa->spa_root_vdev);
    spa_config_exit(spa, SCL_STATE, tag);
}

static int
collect_volume(const char *name, void *arg)
{
    objset_t *os;
    int error = dmu_objset_hold(name, tag, &os);
    if (error != 0)
        return (error);
    boolean_t volume = dmu_objset_type(os) == DMU_OST_ZVOL;
    dmu_objset_rele(os, tag);
    return (volume ? nvlist_add_boolean(arg, name) : 0);
}

static int
hide_volumes(const char *name)
{
    nvlist_t *volumes = fnvlist_alloc();
    int error = dmu_objset_find(name, collect_volume, volumes, DS_FIND_CHILDREN);
    /* Property sync tasks must run without dataset holds or traversal locks. */
    for (nvpair_t *pair = nvlist_next_nvpair(volumes, NULL);
        error == 0 && pair != NULL; pair = nvlist_next_nvpair(volumes, pair)) {
        error = dsl_prop_set_int(nvpair_name(pair), "volmode",
            ZPROP_SRC_LOCAL, ZFS_VOLMODE_NONE);
    }
    nvlist_free(volumes);
    return (error);
}

static void
usage(FILE *out)
{
    fputs("Usage: clone-pool --source-guid DECIMAL --devices DIRECTORY --name NEWNAME\n"
        "                  [--checkpoint] [--hide-volumes]\n"
        "Prepare a new-GUID clone on writable COW overlays and export it.\n"
        "DIRECTORY must contain only symlinks to connected whole /dev/nbdN overlays.\n"
        "The orchestrator must keep every backing image stable and read-only.\n"
        "--checkpoint rewinds only the overlay to an existing source checkpoint.\n"
        "--hide-volumes sets local volmode=none on every clone volume before export.\n", out);
}

int
main(int argc, char **argv)
{
    uint64_t source = 0, clone = 0;
    char *directory = NULL, *name = NULL;
    boolean_t checkpoint = B_FALSE;
    boolean_t hide_volumes_requested = B_FALSE;
    static const struct option options[] = {
        { "source-guid", required_argument, NULL, 'g' },
        { "devices", required_argument, NULL, 'd' },
        { "name", required_argument, NULL, 'n' },
        { "checkpoint", no_argument, NULL, 'c' },
        { "hide-volumes", no_argument, NULL, 'v' },
        { "help", no_argument, NULL, 'h' },
        { NULL, 0, NULL, 0 }
    };
    int opt;
    while ((opt = getopt_long(argc, argv, "", options, NULL)) != -1) {
        switch (opt) {
        case 'g': if (parse_uint(optarg, &source) != 0) { usage(stderr); return (2); } break;
        case 'd': directory = optarg; break;
        case 'n': name = optarg; break;
        case 'c': checkpoint = B_TRUE; break;
        case 'v': hide_volumes_requested = B_TRUE; break;
        case 'h': usage(stdout); return (0);
        default: usage(stderr); return (2);
        }
    }
    if (optind != argc || source == 0 || directory == NULL || name == NULL ||
        strlen(name) >= ZFS_MAX_DATASET_NAME_LEN || pool_namecheck(name, NULL, NULL)) {
        usage(stderr);
        return (2);
    }
    if (geteuid() != 0)
        return (problem(EPERM, "root required"));
    if (getenv("ZFS_HOSTID") != NULL)
        return (problem(EINVAL, "ZFS_HOSTID override is not permitted"));
    phase("devices", "begin", 0);
    int error = load_devices(directory);
    phase("devices", "end", error);
    if (error != 0) { problem(error, "invalid overlay directory"); goto out_devices; }
    /* An immutable empty cache gives this SPA namespace a private starting point. */
    cachefd = memfd_create("clone-pool-cache", MFD_CLOEXEC | MFD_ALLOW_SEALING);
    if (cachefd < 0 || fstat(cachefd, &cache_identity) != 0 ||
        fcntl(cachefd, F_ADD_SEALS,
        F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL) != 0) {
        error = problem(errno, "cannot create private configuration cache");
        goto out_devices;
    }
    snprintf(cachepath, sizeof (cachepath), "/proc/self/fd/%d", cachefd);
    if (handle_tunable_option("zfs_import_defer_txgs=4294967295", B_TRUE)) {
        error = problem(EINVAL, "cannot defer background scans and frees");
        goto out_devices;
    }
    spa_config_path = cachepath;
    phase("readonly-init", "begin", 0);
    kernel_init(SPA_MODE_READ);
    phase("readonly-init", "end", 0);
    nvlist_t *config = NULL, *props = fnvlist_alloc(), *root = NULL;
    spa_t *spa = NULL;
    boolean_t imported = B_FALSE, writable = B_FALSE;
    phase("labels", "begin", 0);
    error = read_identities(source);
    phase("labels", "end", error);
    if (error != 0) { problem(error, "overlay labels do not match source"); goto out; }
    char **paths = calloc(noverlays, sizeof (*paths));
    if (paths == NULL) { error = ENOMEM; goto out; }
    for (size_t i = 0; i < noverlays; i++)
        paths[i] = overlays[i].path;
    importargs_t args = { .path = paths, .paths = (int)noverlays, .guid = source,
        .can_be_active = B_TRUE, .scan = B_TRUE };
    libpc_handle_t handle = { .lpc_ops = &libzpool_config_ops, .lpc_printerr = B_TRUE };
    char target[32];
    snprintf(target, sizeof (target), "%llu", (u_longlong_t)source);
    /* can_be_active keeps discovery label-only, without a tryimport refresh. */
    phase("discovery", "begin", 0);
    error = zpool_find_config(&handle, target, &config, &args);
    phase("discovery", "end", error);
    free(paths);
    if (error != 0) { problem(error, "cannot discover source on overlays"); goto out; }
    uint64_t discovered;
    const char *actual;
    if (nvlist_lookup_uint64(config, ZPOOL_CONFIG_POOL_GUID, &discovered) != 0 ||
        discovered != source ||
        nvlist_lookup_string(config, ZPOOL_CONFIG_POOL_NAME, &actual) != 0 ||
        strcmp(actual, name) == 0 ||
        nvlist_lookup_nvlist(config, ZPOOL_CONFIG_VDEV_TREE, &root) != 0) {
        error = problem(EINVAL, "source identity or distinct clone name invalid");
        goto out;
    }
    phase("map-config", "begin", 0);
    error = map_config(root);
    phase("map-config", "end", error);
    if (error != 0) { problem(error, "unmapped or unsupported vdev topology"); goto out; }
    fnvlist_add_string(props, "cachefile", "none");
    fnvlist_add_uint64(props, "readonly", 1);
    uint64_t flags = checkpoint ? ZFS_IMPORT_CHECKPOINT : ZFS_IMPORT_NORMAL;
    phase("readonly-import", "begin", 0);
    error = spa_import(name, config, props, flags);
    phase("readonly-import", "end", error);
    if (error != 0) { problem(error, "read-only clone preflight import failed"); goto out; }
    imported = B_TRUE;
    phase("readonly-open", "begin", 0);
    error = spa_open(name, &spa, tag);
    phase("readonly-open", "end", error);
    if (error != 0) { problem(error, "cannot open read-only clone"); goto out; }
    phase("readonly-validation", "begin", 0);
    error = validate_loaded(spa, source, checkpoint);
    phase("readonly-validation", "end", error);
    if (error != 0) { problem(error, "read-only loaded topology is not isolated"); goto out; }
    phase("readonly-close", "begin", 0);
    spa_close(spa, tag);
    spa = NULL;
    phase("readonly-close", "end", 0);
    phase("readonly-shutdown", "begin", 0);
    kernel_fini();
    phase("readonly-shutdown", "end", 0);
    imported = B_FALSE;
    phase("writable-init", "begin", 0);
    kernel_init(SPA_MODE_READ | SPA_MODE_WRITE);
    phase("writable-init", "end", 0);
    (void) nvlist_remove_all(props, "readonly");
    phase("writable-import", "begin", 0);
    error = spa_import(name, config, props, flags);
    phase("writable-import", "end", error);
    if (error != 0) { problem(error, "writable overlay import failed"); goto out; }
    imported = writable = B_TRUE;
    phase("writable-open", "begin", 0);
    error = spa_open(name, &spa, tag);
    phase("writable-open", "end", error);
    if (error != 0) { problem(error, "cannot open writable clone"); goto out; }
    phase("async-suspend", "begin", 0);
    spa_async_suspend(spa);
    phase("async-suspend", "end", 0);
    phase("writable-validation", "begin", 0);
    error = validate_loaded(spa, source, checkpoint);
    phase("writable-validation", "end", error);
    if (error != 0) { problem(error, "writable loaded topology is not isolated"); goto out; }
    phase("sync", "begin", 0);
    txg_wait_synced(spa_get_dsl(spa), 0);
    phase("sync", "end", 0);
    phase("normalize", "begin", 0);
    error = dsl_sync_task(name, NULL, normalize_config, NULL, 5,
        ZFS_SPACE_CHECK_RESERVED);
    phase("normalize", "end", error);
    if (error != 0) { problem(error, "cannot persist overlay device identities"); goto out; }
    if (hide_volumes_requested) {
        phase("hide-volumes", "begin", 0);
        error = hide_volumes(name);
        phase("hide-volumes", "end", error);
        if (error != 0) { problem(error, "cannot hide clone volumes"); goto out; }
    }
    phase("reguid", "begin", 0);
    error = spa_change_guid(spa, NULL);
    phase("reguid", "end", error);
    if (error != 0) { problem(error, "cannot assign independent clone GUID"); goto out; }
    clone = spa_guid(spa);
    if (clone == 0 || clone == source) {
        error = problem(EIO, "clone GUID did not change");
        goto out;
    }
out:
    if (spa != NULL) {
        phase("close", "begin", 0);
        spa_close(spa, tag);
        phase("close", "end", 0);
    }
    if (imported && writable) {
        phase("export", "begin", 0);
        int export_error = spa_export(name, NULL, B_FALSE, B_FALSE);
        phase("export", "end", export_error);
        if (export_error != 0)
            error = problem(export_error, "clone export failed");
    }
    nvlist_free(config);
    nvlist_free(props);
    phase("shutdown", "begin", 0);
    kernel_fini();
    phase("shutdown", "end", 0);
    if (error == 0 && __atomic_load_n(&denied_open, __ATOMIC_RELAXED))
        error = problem(EACCES, "a libzpool open escaped the device allowlist");
    if (error == 0)
        printf("clone_guid=%llu\n", (u_longlong_t)clone);
out_devices:
    if (cachefd >= 0)
        close(cachefd);
    for (size_t i = 0; i < noverlays; i++)
        close(overlays[i].fd);
    free(overlays);
    return (error != 0 ? 1 : 0);
}
