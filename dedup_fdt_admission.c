/* SPDX-License-Identifier: CDDL-1.0 */
#include "dedup_fdt_admission.h"
#include "rebuild_owners.h"
#include "rebuild_phase.h"
#include <sys/blake3.h>
#include <sys/ddt_impl.h>
#include <sys/brt_impl.h>
#include <sys/dnode.h>
#include <sys/dsl_pool.h>
#include <sys/dsl_dataset.h>
#include <sys/dsl_dir.h>
#include <sys/dsl_crypt.h>
#include <sys/spa_impl.h>
#include <sys/zap.h>
#include <sys/vdev_impl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/random.h>
#include <linux/magic.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>

#define DFA_MAGIC 0x4446445441444d31ULL
#define DFA_VERSION 1
static const char proof_tag[] = "dedup-fdt-admission";
typedef struct dfa_record {
    uint64_t magic, version, guid, source_txg;
    zio_cksum_t scope, proof;
} dfa_record_t;
struct dedup_fdt_admission {
    int directory, fd;
    char name[96];
    dfa_record_t record;
};
typedef struct dfa_hash {
    spa_t *spa;
    BLAKE3_CTX context;
} dfa_hash_t;
static void
dfa_words(dfa_hash_t *hash, const uint64_t *words, size_t count)
{
    Blake3_Update(&hash->context, words, count*sizeof (*words));
}
static int
dfa_object(dfa_hash_t *hash, uint64_t object)
{
    uint64_t identity[] = { 1, object };
    dfa_words(hash, identity, 2);
    if (object == 0)
        return (0);
    dnode_t *node;
    int error = dnode_hold(spa_get_dsl(hash->spa)->dp_meta_objset,
        object, proof_tag, &node);
    if (error != 0)
        return (error);
    size_t slots = (size_t)node->dn_phys->dn_extra_slots+1;
    if (slots > DNODE_MAX_SLOTS)
        error = EINVAL;
    else
        Blake3_Update(&hash->context, node->dn_phys, slots*DNODE_MIN_SIZE);
    dnode_rele(node, proof_tag);
    return (error);
}
static int
dfa_noop(void *arg, uint64_t owner, const blkptr_t *old, blkptr_t *out)
{
    (void)arg, (void)owner;
    *out = *old;
    return (0);
}
static int
dfa_owner_identity(void *arg, uint64_t parent, uint64_t owner,
    rebuild_owners_role_t role, const char *name, uint64_t object)
{
    dfa_hash_t *hash = arg;
    size_t length = strlen(name);
    uint64_t identity[] = { 2, parent, owner, role, object, length };
    dfa_words(hash, identity, 6);
    Blake3_Update(&hash->context, name, length);
    /* Import sync can append METADATA frees to the deferred queue. Its
     * object identity and exact user-data records are stable under the fence;
     * hashing its changing metadata-only dnode would reject our own import. */
    return (role == REBUILD_OWNER_DEFERRED ? 0 : dfa_object(hash, object));
}
static int
dfa_owner_bp(void *arg, uint64_t owner, rebuild_owners_role_t role,
    const blkptr_t *bp, boolean_t freed)
{
    dfa_hash_t *hash = arg;
    if (BP_IS_METADATA(bp))
        return (0);
    uint64_t identity[] = { 3, owner, role, freed };
    dfa_words(hash, identity, 4);
    Blake3_Update(&hash->context, bp, sizeof (*bp));
    return (0);
}
static void
dfa_vdev(dfa_hash_t *hash, vdev_t *vdev)
{
    uint64_t identity[] = { 4, vdev->vdev_id, vdev->vdev_guid,
        vdev->vdev_asize, vdev->vdev_ashift, vdev->vdev_children };
    dfa_words(hash, identity, 6);
    for (uint64_t i = 0; i < vdev->vdev_children; i++)
        dfa_vdev(hash, vdev->vdev_child[i]);
}
int
dedup_fdt_admission_proof(spa_t *spa, size_t batch, zio_cksum_t *out)
{
    if (spa == NULL || out == NULL || batch == 0)
        return (EINVAL);
    dfa_hash_t hash = { .spa = spa };
    Blake3_Init(&hash.context);
    uint64_t pool[] = { DFA_MAGIC, DFA_VERSION, spa_guid(spa),
        spa->spa_uberblock.ub_guid_sum };
    dfa_words(&hash, pool, 4);
    Blake3_Update(&hash.context, &spa->spa_cksum_salt,
        sizeof (spa->spa_cksum_salt));
    dfa_vdev(&hash, spa->spa_root_vdev);
    dsl_pool_t *dp = spa_get_dsl(spa);
    uint64_t object = 0;
    int error;
    while ((error = dmu_object_next(dp->dp_meta_objset, &object, B_FALSE, 0)) == 0) {
        if (rebuild_interrupted())
            return (EINTR);
        dmu_object_info_t info;
        error = dmu_object_info(dp->dp_meta_objset, object, &info);
        if (error != 0)
            return (error);
        if (info.doi_bonus_type != DMU_OT_DSL_DATASET)
            continue;
        dsl_dataset_t *dataset;
        boolean_t enter = !dsl_pool_config_held(dp);
        if (enter)
            dsl_pool_config_enter(dp, proof_tag);
        error = dsl_dataset_hold_obj(dp, object, proof_tag, &dataset);
        if (error != 0) {
            if (enter)
                dsl_pool_config_exit(dp, proof_tag);
            return (error);
        }
        uint64_t identity[] = { 5, object, dataset->ds_dir->dd_object,
            dataset->ds_dir->dd_origin_txg, dataset->ds_dir->dd_crypto_obj };
        dfa_words(&hash, identity, 5);
        Blake3_Update(&hash.context, dsl_dataset_phys(dataset),
            sizeof (dsl_dataset_phys_t));
        if (dataset->ds_dir->dd_crypto_obj != 0) {
            uint64_t guid;
            error = zap_lookup(dp->dp_meta_objset,
                dataset->ds_dir->dd_crypto_obj, DSL_CRYPTO_KEY_GUID, 8, 1, &guid);
            if (error == 0)
                dfa_words(&hash, &guid, 1);
        }
        dsl_dataset_rele(dataset, proof_tag);
        if (enter)
            dsl_pool_config_exit(dp, proof_tag);
        if (error != 0)
            return (error);
    }
    if (error != ESRCH)
        return (error);
    error = dfa_object(&hash, spa->spa_ddt_stat_object);
    for (unsigned cs = 0; error == 0 && cs < ZIO_CHECKSUM_FUNCTIONS; cs++) {
        ddt_t *table = spa->spa_ddt[cs];
        if (table == NULL)
            continue;
        if (!avl_is_empty(&table->ddt_tree) ||
            !avl_is_empty(&table->ddt_repair_tree))
            return (EBUSY);
        uint64_t identity[] = { 6, cs, table->ddt_version, table->ddt_flags };
        dfa_words(&hash, identity, 4);
        error = dfa_object(&hash, table->ddt_dir_object);
        for (unsigned type = 0; error == 0 && type < DDT_TYPES; type++)
            for (unsigned cl = 0; error == 0 && cl < DDT_CLASSES; cl++)
                error = dfa_object(&hash, table->ddt_object[type][cl]);
        for (unsigned log = 0; error == 0 && log < 2; log++)
            error = dfa_object(&hash, table->ddt_log[log].ddl_object);
    }
    for (uint64_t id = 0; error == 0 && id < spa->spa_brt_nvdevs; id++) {
        brt_vdev_t *vdev = spa->spa_brt_vdevs[id];
        uint64_t identity[] = { 7, id, vdev == NULL ? 0 : vdev->bv_totalcount };
        dfa_words(&hash, identity, 3);
        if (vdev == NULL)
            continue;
        if (vdev->bv_meta_dirty || !avl_is_empty(&vdev->bv_tree))
            return (EBUSY);
        for (unsigned n = 0; n < TXG_SIZE; n++)
            if (!avl_is_empty(&vdev->bv_pending_tree[n]))
                return (EBUSY);
        error = dfa_object(&hash, vdev->bv_mos_brtvdev);
        if (error == 0)
            error = dfa_object(&hash, vdev->bv_mos_entries);
    }
    rebuild_owners_t *owners = NULL;
    if (error == 0)
        error = rebuild_owners_open(spa, 0, batch, dfa_noop, NULL, &owners);
    if (error == 0)
        error = rebuild_owners_foreach_identity(owners, dfa_owner_identity, &hash);
    if (error == 0)
        error = rebuild_owners_foreach_source(owners, dfa_owner_bp, &hash);
    rebuild_owners_close(owners);
    if (error == 0)
        Blake3_Final(&hash.context, (uint8_t *)out);
    return (error);
}
static int
dfa_io(int fd, dfa_record_t *record, boolean_t writing)
{
    size_t done = 0;
    while (done < sizeof (*record)) {
        ssize_t n = writing ? pwrite(fd, (char *)record+done,
            sizeof (*record)-done, done) : pread(fd, (char *)record+done,
            sizeof (*record)-done, done);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0)
            return (n < 0 ? errno : EIO);
        done += n;
    }
    return (0);
}
static int
dfa_file(dedup_fdt_admission_t *lease, boolean_t named)
{
    struct stat file, path;
    if (fstat(lease->fd, &file) != 0)
        return (errno);
    if (!S_ISREG(file.st_mode) || file.st_uid != 0 || file.st_nlink != 1 ||
        (file.st_mode&0077) != 0 || file.st_size != (off_t)sizeof (dfa_record_t))
        return (EPERM);
    if (named) {
        if (fstatat(lease->directory, lease->name, &path, AT_SYMLINK_NOFOLLOW) != 0)
            return (errno);
        if (file.st_dev != path.st_dev || file.st_ino != path.st_ino)
            return (ESTALE);
    }
    return (0);
}
static int
dfa_replace(dedup_fdt_admission_t *lease, const dfa_record_t *record)
{
    uint64_t nonce;
    ssize_t n;
    do { n = getrandom(&nonce, sizeof (nonce), 0); } while (n < 0 && errno == EINTR);
    if (n != (ssize_t)sizeof (nonce))
        return (n < 0 ? errno : EIO);
    char temporary[128];
    snprintf(temporary, sizeof (temporary), "%s.%016llx.new", lease->name,
        (u_longlong_t)nonce);
    int fd = openat(lease->directory, temporary,
        O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0)
        return (errno);
    int error = flock(fd, LOCK_EX | LOCK_NB) == 0 ? 0 : errno;
    dfa_record_t copy = *record;
    if (error == 0)
        error = dfa_io(fd, &copy, B_TRUE);
    if (error == 0 && fsync(fd) != 0)
        error = errno;
    if (error == 0 && renameat(lease->directory, temporary,
        lease->directory, lease->name) != 0)
        error = errno;
    if (error == 0 && fsync(lease->directory) != 0)
        error = errno;
    if (error != 0) {
        (void)unlinkat(lease->directory, temporary, 0);
        close(fd);
        return (error);
    }
    if (lease->fd >= 0)
        close(lease->fd);
    lease->fd = fd;
    lease->record = copy;
    return (0);
}
int
dedup_fdt_admission_check(dedup_fdt_admission_t *lease, spa_t *spa,
    const zio_cksum_t *scope, const zio_cksum_t *proof)
{
    if (lease == NULL || spa == NULL || scope == NULL || proof == NULL)
        return (EINVAL);
    int error = dfa_file(lease, B_TRUE);
    dfa_record_t record;
    if (error == 0)
        error = dfa_io(lease->fd, &record, B_FALSE);
    if (error != 0)
        return (error);
    if (record.magic != DFA_MAGIC || record.version != DFA_VERSION ||
        record.guid != spa_guid(spa) || record.source_txg == 0 ||
        record.source_txg > spa->spa_uberblock.ub_txg ||
        memcmp(&record.scope, scope, sizeof (*scope)) != 0 ||
        memcmp(&record.proof, proof, sizeof (*proof)) != 0)
        return (ESTALE);
    lease->record = record;
    return (0);
}
int
dedup_fdt_admission_open(spa_t *spa, int directory, const zio_cksum_t *scope,
    const zio_cksum_t *proof, boolean_t active, dedup_fdt_admission_t **out)
{
    struct statfs fs;
    if (fstatfs(directory, &fs) != 0)
        return (errno);
    if (fs.f_type == TMPFS_MAGIC || fs.f_type == RAMFS_MAGIC)
        return (ENOTSUP);
    dedup_fdt_admission_t *lease = calloc(1, sizeof (*lease));
    if (lease == NULL)
        return (ENOMEM);
    lease->directory = directory;
    snprintf(lease->name, sizeof (lease->name), ".dedup-fdt-admission-%llu",
        (u_longlong_t)spa_guid(spa));
    lease->fd = openat(directory, lease->name, O_RDWR | O_NOFOLLOW | O_CLOEXEC);
    int error = lease->fd < 0 ? errno : 0;
    if (error == 0 && flock(lease->fd, LOCK_EX | LOCK_NB) != 0)
        error = errno;
    if (error == 0)
        error = dfa_file(lease, B_TRUE);
    dfa_record_t previous = {0};
    if (error == 0)
        error = dfa_io(lease->fd, &previous, B_FALSE);
    if (error == 0 && (previous.magic != DFA_MAGIC || previous.version != DFA_VERSION ||
        previous.guid != spa_guid(spa)))
        error = EINVAL;
    if (active) {
        if (error == 0)
            error = dedup_fdt_admission_check(lease, spa, scope, proof);
    } else if (error == ENOENT || error == 0) {
        dfa_record_t record = { .magic = DFA_MAGIC, .version = DFA_VERSION,
            .guid = spa_guid(spa), .source_txg = spa->spa_uberblock.ub_txg,
            .scope = *scope, .proof = *proof };
        if (error != 0 || previous.source_txg == 0 ||
            previous.source_txg > record.source_txg ||
            memcmp(&previous.scope, scope, sizeof (*scope)) != 0 ||
            memcmp(&previous.proof, proof, sizeof (*proof)) != 0)
            error = dfa_replace(lease, &record);
        else
            lease->record = previous;
    }
    if (error == 0 && (fsync(lease->fd) != 0 || fsync(directory) != 0))
        error = errno;
    if (error != 0) {
        dedup_fdt_admission_close(lease);
        return (error);
    }
    *out = lease;
    return (0);
}
int
dedup_fdt_admission_remove(dedup_fdt_admission_t *lease)
{
    if (lease == NULL)
        return (0);
    int error = dfa_file(lease, B_TRUE);
    if (error == 0 && unlinkat(lease->directory, lease->name, 0) != 0)
        error = errno;
    if (error == 0 && fsync(lease->directory) != 0)
        error = errno;
    return (error);
}
int
dedup_fdt_admission_cleanup(int directory, uint64_t guid, const zio_cksum_t *scope)
{
    if (directory < 0 || guid == 0 || scope == NULL)
        return (EINVAL);
    dedup_fdt_admission_t lease = { .directory = directory, .fd = -1 };
    snprintf(lease.name, sizeof (lease.name), ".dedup-fdt-admission-%llu",
        (u_longlong_t)guid);
    lease.fd = openat(directory, lease.name, O_RDWR | O_NOFOLLOW | O_CLOEXEC);
    if (lease.fd < 0)
        return (errno == ENOENT ? 0 : errno);
    int error = flock(lease.fd, LOCK_EX | LOCK_NB) == 0 ? 0 : errno;
    if (error == 0)
        error = dfa_file(&lease, B_TRUE);
    dfa_record_t record;
    if (error == 0)
        error = dfa_io(lease.fd, &record, B_FALSE);
    if (error == 0 && (record.magic != DFA_MAGIC ||
        record.version != DFA_VERSION || record.guid != guid ||
        record.source_txg == 0 ||
        memcmp(&record.scope, scope, sizeof (*scope)) != 0))
        error = ESTALE;
    if (error == 0)
        error = dedup_fdt_admission_remove(&lease);
    close(lease.fd);
    return (error);
}
void
dedup_fdt_admission_close(dedup_fdt_admission_t *lease)
{
    if (lease == NULL)
        return;
    if (lease->fd >= 0)
        close(lease->fd);
    free(lease);
}
