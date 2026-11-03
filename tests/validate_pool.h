/* SPDX-License-Identifier: CDDL-1.0 */
#ifndef VALIDATE_POOL_H
#define VALIDATE_POOL_H

#include <sys/zfs_context.h>
#include <sys/spa.h>
#include <sys/spa_impl.h>
#include <sys/arc_impl.h>
#include <sys/vdev_impl.h>
#include <sys/zfs_file.h>
#include <sys/zfs_ioctl.h>
#include <libzutil.h>
#include <dirent.h>
#include <limits.h>
#include <sys/file.h>
#include <sys/mman.h>
#include <sys/stat.h>

/* One readonly userspace SPA per executable. Never consult the kernel SPA
 * namespace: an unrelated blocked kernel import/export must not stall us. The
 * caller must provide stable exported devices, exclusively fenced from writers.
 * Both validators share the converter's maintenance admission lock. */
typedef struct vp_device {
    int fd;
    struct stat identity;
    char path[PATH_MAX];
    char pinned[64];
} vp_device_t;

typedef struct vp_pool {
    spa_t *spa;
    int lockfd;
    int cachefd;
    boolean_t initialized;
    vp_device_t *devices;
    size_t ndevices;
    char cachepath[64];
    char *name;
} vp_pool_t;

static vp_pool_t *vp_current;
extern uint64_t zfs_arc_max;
extern uint64_t zfs_arc_min;
int __real_zfs_file_open(const char *, int, int, cred_t *, zfs_file_t **);
int __wrap_zfs_file_open(const char *, int, int, cred_t *, zfs_file_t **);

int
__wrap_zfs_file_open(const char *path, int flags, int mode, cred_t *cr,
    zfs_file_t **fp)
{
    vp_pool_t *p = vp_current;
    *fp = NULL;
    if (p == NULL || path == NULL ||
        (flags & (O_ACCMODE | O_CREAT | O_TRUNC | O_EXCL)) != O_RDONLY)
        return (EACCES);
    if (strcmp(path, p->cachepath) == 0)
        return (__real_zfs_file_open(path, flags, mode, cr, fp));
    char resolved[PATH_MAX];
    if (realpath(path, resolved) == NULL)
        return (errno);
    for (size_t i = 0; i < p->ndevices; i++) {
        vp_device_t *d = &p->devices[i];
        if (strcmp(resolved, d->path) != 0 && strcmp(path, d->pinned) != 0)
            continue;
        int error = __real_zfs_file_open(d->pinned, flags, mode, cr, fp);
        struct stat st;
        if (error == 0 && (fstat((*fp)->f_fd, &st) != 0 ||
            st.st_dev != d->identity.st_dev || st.st_ino != d->identity.st_ino ||
            st.st_rdev != d->identity.st_rdev ||
            (st.st_mode & S_IFMT) != (d->identity.st_mode & S_IFMT))) {
            zfs_file_close(*fp);
            *fp = NULL;
            error = EACCES;
        }
        return (error);
    }
    fprintf(stderr, "validator: denied non-allowlisted vdev open: %s\n", path);
    return (EACCES);
}

static int
vp_labels(vdev_t *vd, uint64_t guid)
{
    for (uint64_t i = 0; i < vd->vdev_children; i++) {
        int error = vp_labels(vd->vdev_child[i], guid);
        if (error != 0)
            return (error);
    }
    if (!vd->vdev_ops->vdev_op_leaf)
        return (0);
    nvlist_t *label = vdev_label_read_config(vd,
        vd->vdev_spa->spa_uberblock.ub_txg);
    uint64_t state, poolguid, leafguid, txg;
    int error = label == NULL ||
        nvlist_lookup_uint64(label, ZPOOL_CONFIG_POOL_STATE, &state) ||
        state != POOL_STATE_EXPORTED ||
        nvlist_lookup_uint64(label, ZPOOL_CONFIG_POOL_GUID, &poolguid) ||
        poolguid != guid ||
        nvlist_lookup_uint64(label, ZPOOL_CONFIG_GUID, &leafguid) ||
        leafguid != vd->vdev_guid ||
        nvlist_lookup_uint64(label, ZPOOL_CONFIG_POOL_TXG, &txg) || txg == 0;
    nvlist_free(label);
    return (error ? EBUSY : 0);
}

static void
vp_close(vp_pool_t *p)
{
    if (p->spa != NULL) {
        spa_close(p->spa, p);
        p->spa = NULL;
    }
    if (p->initialized) {
        /* kernel_fini unloads only this process's readonly SPA namespace. */
        kernel_fini();
        p->initialized = B_FALSE;
    }
    vp_current = NULL;
    for (size_t i = 0; i < p->ndevices; i++)
        close(p->devices[i].fd);
    free(p->devices);
    p->devices = NULL;
    p->ndevices = 0;
    free(p->name);
    p->name = NULL;
    if (p->cachefd >= 0) close(p->cachefd);
    if (p->lockfd >= 0) close(p->lockfd);
    p->cachefd = p->lockfd = -1;
}

static int
vp_open(vp_pool_t *p, uint64_t guid, const char *search_dir,
    uint64_t arc_max_bytes)
{
    memset(p, 0, sizeof (*p));
    p->cachefd = p->lockfd = -1;
    if (vp_current != NULL || guid == 0 || arc_max_bytes < (64ULL << 20))
        return (EINVAL);
    char lockpath[128];
    snprintf(lockpath, sizeof (lockpath), "/run/lock/convert-ddt-%llu.lock",
        (u_longlong_t)guid);
    p->lockfd = open(lockpath, O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
    int error = 0;
    if (p->lockfd < 0 || flock(p->lockfd, LOCK_SH | LOCK_NB) != 0) {
        error = errno;
        goto fail;
    }
    DIR *dir = opendir(search_dir);
    if (dir == NULL) { error = errno; goto fail; }
    struct dirent *de;
    while ((de = readdir(dir)) != NULL) {
        if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0)
            continue;
        char path[PATH_MAX];
        vp_device_t d = { .fd = -1 };
        if (snprintf(path, sizeof (path), "%s/%s", search_dir, de->d_name) >=
            (int)sizeof (path) || realpath(path, d.path) == NULL) {
            error = ENAMETOOLONG; break;
        }
        d.fd = open(d.path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
        if (d.fd < 0) { error = errno; break; }
        if (fstat(d.fd, &d.identity) != 0 ||
            (!S_ISREG(d.identity.st_mode) && !S_ISBLK(d.identity.st_mode))) {
            close(d.fd); error = EINVAL; break;
        }
        for (size_t i = 0; i < p->ndevices; i++) {
            struct stat *s = &p->devices[i].identity;
            if ((S_ISBLK(d.identity.st_mode) && s->st_rdev == d.identity.st_rdev) ||
                (s->st_dev == d.identity.st_dev && s->st_ino == d.identity.st_ino)) {
                error = EEXIST; break;
            }
        }
        if (error) { close(d.fd); break; }
        vp_device_t *grown = realloc(p->devices,
            (p->ndevices + 1) * sizeof (*grown));
        if (grown == NULL) { close(d.fd); error = ENOMEM; break; }
        p->devices = grown;
        snprintf(d.pinned, sizeof (d.pinned), "/proc/self/fd/%d", d.fd);
        p->devices[p->ndevices++] = d;
    }
    closedir(dir);
    if (error || p->ndevices == 0) { if (!error) error = ENOENT; goto fail; }
    p->cachefd = memfd_create("validate-pool-cache", MFD_CLOEXEC | MFD_ALLOW_SEALING);
    if (p->cachefd < 0 || fcntl(p->cachefd, F_ADD_SEALS,
        F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL) != 0) {
        error = errno; goto fail;
    }
    snprintf(p->cachepath, sizeof (p->cachepath), "/proc/self/fd/%d", p->cachefd);
    spa_config_path = p->cachepath;
    vp_current = p;
    zfs_arc_max = arc_max_bytes;
    zfs_arc_min = 32ULL << 20;
    kernel_init(SPA_MODE_READ);
    p->initialized = B_TRUE;
    /* libzpool simulates random memory pressure for upstream stress tests.
     * Keep this explicitly budgeted working cache from shrinking between
     * preloading metadata and consuming it. This sets a target, not an
     * allocation; the caller must leave real headroom outside its budget. */
    zfs_arc_min = arc_c_max;
    arc_tuning_update(B_FALSE);
    nvlist_t *config = NULL, *props = fnvlist_alloc();
    char target[32], *search = (char *)search_dir;
    snprintf(target, sizeof (target), "%llu", (u_longlong_t)guid);
    importargs_t args = { .path = &search, .paths = 1, .guid = guid,
        .scan = B_TRUE };
    libpc_handle_t handle = { .lpc_ops = &libzpool_config_ops,
        .lpc_printerr = B_TRUE };
    error = zpool_find_config(&handle, target, &config, &args);
    if (!error) {
        uint64_t found, state;
        const char *name;
        if (nvlist_lookup_uint64(config, ZPOOL_CONFIG_POOL_GUID, &found) ||
            found != guid ||
            nvlist_lookup_uint64(config, ZPOOL_CONFIG_POOL_STATE, &state) ||
            state != POOL_STATE_EXPORTED ||
            nvlist_lookup_string(config, ZPOOL_CONFIG_POOL_NAME, &name))
            error = EBUSY;
        else if ((p->name = strdup(name)) == NULL)
            error = ENOMEM;
    }
    if (!error) {
        fnvlist_add_string(props, "cachefile", "none");
        fnvlist_add_uint64(props, "readonly", 1);
        error = spa_import(p->name, config, props, ZFS_IMPORT_NORMAL);
    }
    if (!error) error = spa_open(p->name, &p->spa, p);
    if (!error && (spa_guid(p->spa) != guid || spa_writeable(p->spa)))
        error = EACCES;
    if (!error) {
        spa_config_enter(p->spa, SCL_STATE_ALL, p, RW_WRITER);
        error = vp_labels(p->spa->spa_root_vdev, guid);
        spa_config_exit(p->spa, SCL_STATE_ALL, p);
    }
    nvlist_free(config);
    nvlist_free(props);
    if (!error) return (0);
fail:
    fprintf(stderr, "validator: readonly fenced pool open failed: %s\n",
        strerror(error));
    vp_close(p);
    return (error);
}
#endif
