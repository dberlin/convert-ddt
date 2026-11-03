/* SPDX-License-Identifier: CDDL-1.0
 * Disposable-pool fault injection at real native vdev write attempts.
 */
#include <sys/zfs_context.h>
#include <sys/spa_impl.h>
#include <sys/vdev_impl.h>
#include <sys/zfs_file.h>
#include <sys/stat.h>
#include "rebuild_io_fault.h"

int __wrap_zfs_file_pwrite(zfs_file_t *, const void *, size_t,
    loff_t, uint8_t, ssize_t *);

typedef struct fault_device {
    dev_t device, rdev;
    ino_t inode;
    mode_t mode;
} fault_device_t;

static fault_device_t *devices;
static size_t ndevices;
static uint64_t fail_at, attempts, configured_attempt;
static int event_fd = -1;

static int
leaf_count(vdev_t *vd, size_t *count)
{
    if (vd->vdev_ops->vdev_op_leaf) {
        if (*count == SIZE_MAX / sizeof (fault_device_t))
            return (EOVERFLOW);
        (*count)++;
    }
    for (uint64_t i = 0; i < vd->vdev_children; i++) {
        int error = leaf_count(vd->vdev_child[i], count);
        if (error)
            return (error);
    }
    return (0);
}

static int
record_leaves(vdev_t *vd)
{
    if (vd->vdev_ops->vdev_op_leaf) {
        if (vd->vdev_path == NULL)
            return (EINVAL);
        int fd = open(vd->vdev_path, O_RDONLY | O_CLOEXEC | O_NONBLOCK);
        if (fd < 0)
            return (errno);
        struct stat st;
        int error = fstat(fd, &st) ? errno : 0;
        close(fd);
        if (error)
            return (error);
        if (!S_ISREG(st.st_mode) && !S_ISBLK(st.st_mode))
            return (ENOTSUP);
        devices[ndevices++] = (fault_device_t) {
            .device = st.st_dev, .rdev = st.st_rdev,
            .inode = st.st_ino, .mode = st.st_mode
        };
    }
    for (uint64_t i = 0; i < vd->vdev_children; i++) {
        int error = record_leaves(vd->vdev_child[i]);
        if (error)
            return (error);
    }
    return (0);
}

int
rebuild_io_fault_prepare(spa_t *spa, uint64_t attempt, int fd)
{
    if (attempt == 0 || fd < 0 || devices != NULL)
        return (EINVAL);
    size_t count = 0;
    int error = leaf_count(spa->spa_root_vdev, &count);
    if (error || count == 0)
        return (error ? error : EINVAL);
    devices = calloc(count, sizeof (*devices));
    if (devices == NULL)
        return (ENOMEM);
    error = record_leaves(spa->spa_root_vdev);
    if (error) {
        rebuild_io_fault_disarm();
        return (error);
    }
    event_fd = fd;
    attempts = 0;
    configured_attempt = attempt;
    return (0);
}

void
rebuild_io_fault_arm(void)
{
    __atomic_store_n(&fail_at, configured_attempt, __ATOMIC_RELEASE);
}

void
rebuild_io_fault_disarm(void)
{
    __atomic_store_n(&fail_at, 0, __ATOMIC_RELEASE);
    attempts = 0;
    configured_attempt = 0;
    event_fd = -1;
    free(devices);
    devices = NULL;
    ndevices = 0;
}

extern int __real_zfs_file_pwrite(zfs_file_t *, const void *, size_t,
    loff_t, uint8_t, ssize_t *);

int
__wrap_zfs_file_pwrite(zfs_file_t *fp, const void *buf, size_t length,
    loff_t offset, uint8_t ashift, ssize_t *residual)
{
    uint64_t target = __atomic_load_n(&fail_at, __ATOMIC_ACQUIRE);
    if (target != 0 && fp != NULL) {
        struct stat st;
        boolean_t owned = B_FALSE;
        if (fstat(fp->f_fd, &st) == 0) {
            for (size_t i = 0; i < ndevices; i++) {
                const fault_device_t *d = &devices[i];
                if ((S_ISBLK(st.st_mode) && S_ISBLK(d->mode) &&
                    st.st_rdev == d->rdev) ||
                    (S_ISREG(st.st_mode) && S_ISREG(d->mode) &&
                    st.st_dev == d->device && st.st_ino == d->inode)) {
                    owned = B_TRUE;
                    break;
                }
            }
        }
        if (owned) {
            uint64_t n = __atomic_add_fetch(&attempts, 1, __ATOMIC_RELAXED);
            if (n == target) {
                char event[384];
                int bytes = snprintf(event, sizeof (event),
                    "{\"kind\":\"native-write-fault\",\"attempt\":%llu,"
                    "\"offset\":%lld,\"length\":%llu,\"device\":%llu,"
                    "\"inode\":%llu,\"rdev\":%llu,\"owned\":true,\"error\":%d}\n",
                    (u_longlong_t)n, (long long)offset,
                    (u_longlong_t)length, (u_longlong_t)st.st_dev,
                    (u_longlong_t)st.st_ino, (u_longlong_t)st.st_rdev, EIO);
                if (bytes > 0 && (size_t)bytes < sizeof (event)) {
                    ssize_t sent;
                    do {
                        sent = write(event_fd, event, bytes);
                    } while (sent < 0 && errno == EINTR);
                }
                if (residual != NULL)
                    *residual = length;
                return (EIO);
            }
        }
    }
    return (__real_zfs_file_pwrite(fp, buf, length, offset, ashift, residual));
}
