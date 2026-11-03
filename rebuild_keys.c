/* SPDX-License-Identifier: CDDL-1.0
 * Native, version-pinned OpenZFS 2.4.4 userspace keystore preparation.
 */
#include <sys/zfs_context.h>
#include <sys/spa_impl.h>
#include <sys/dmu.h>
#include <sys/dsl_crypt.h>
#include <sys/dsl_dataset.h>
#include <sys/dsl_dir.h>
#include <sys/dsl_pool.h>
#include <sys/zap.h>
#include <sys/byteorder.h>
#include <sys/stat.h>
#include <zfs_namecheck.h>
#include <openssl/evp.h>
#include <limits.h>
#include "rebuild_keys.h"

/* libzfs_crypto.c's native creation limits, plus newline and overflow byte. */
#define KEY_FILE_LIMIT (512 + 2)

typedef struct rebuild_key_spec {
    struct rebuild_key_spec *next;
    char *dataset;
    char *path;
    uint64_t ddobj;
    uint64_t format;
    uint64_t salt;
    uint64_t iters;
    dsl_wrapping_key_t *wkey;
    /* Owned 32-byte wrapping material, usable only after full preflight. */
    uint8_t *verified_key;
} rebuild_key_spec_t;

typedef struct rebuild_key_mapping {
    struct rebuild_key_mapping *next;
    uint64_t dsobj;
    rebuild_key_spec_t *spec;
    dsl_key_mapping_t *mapping;
} rebuild_key_mapping_t;

struct rebuild_keys {
    rebuild_key_spec_t *specs;
    rebuild_key_mapping_t *mappings;
    spa_t *spa;
    boolean_t verified;
    uint64_t verified_pool_guid;
};

/*
 * Unlike native SPA keys, these short-lived handoff buffers survive unload()
 * across RO -> RW. They contain derived wrapping keys only, never passphrases
 * or file contents. A complete successful preflight guards their reuse; every
 * operational failure and destroy() explicitly wipes and releases all of them.
 */
static void
key_forget_verified(rebuild_keys_t *keys)
{
    for (rebuild_key_spec_t *spec = keys->specs; spec != NULL;
        spec = spec->next) {
        if (spec->verified_key != NULL) {
            explicit_bzero(spec->verified_key, WRAPPING_KEY_LEN);
            free(spec->verified_key);
            spec->verified_key = NULL;
        }
    }
    keys->verified = B_FALSE;
    keys->verified_pool_guid = 0;
}

static int
key_problem(int error, const char *root, boolean_t missing)
{
    if (missing)
        fprintf(stderr, "dedup-fdt: key required for encryption root '%s'\n",
            root);
    else
        fprintf(stderr, "dedup-fdt: key rejected for encryption root '%s': %s\n",
            root, strerror(error));
    return (error);
}

/* Never follow a final symlink or accept devices/publicly usable key files. */
static int
key_file_open(const char *path, int *fd_out)
{
    struct stat st;
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (fd < 0)
        return (errno);
    int error = 0;
    if (fstat(fd, &st) != 0)
        error = errno;
    else if (!S_ISREG(st.st_mode) || (st.st_mode & 077) != 0 ||
        (st.st_uid != geteuid() && st.st_uid != 0))
        error = EACCES;
    else if (st.st_size <= 0 || st.st_size >= KEY_FILE_LIMIT)
        error = EINVAL;
    if (error != 0) {
        close(fd);
        return (error);
    }
    *fd_out = fd;
    return (0);
}

int
rebuild_keys_create(rebuild_keys_t **out)
{
    if (out == NULL)
        return (EINVAL);
    *out = calloc(1, sizeof (**out));
    return (*out == NULL ? ENOMEM : 0);
}

int
rebuild_keys_add(rebuild_keys_t *keys, const char *arg)
{
    if (keys == NULL || arg == NULL)
        return (EINVAL);
    if (keys->spa != NULL || keys->verified)
        return (EBUSY);
    const char *eq = strchr(arg, '=');
    if (eq == NULL || eq == arg || eq[1] == '\0' ||
        (size_t)(eq - arg) >= ZFS_MAX_DATASET_NAME_LEN)
        return (EINVAL);
    char dataset[ZFS_MAX_DATASET_NAME_LEN];
    memcpy(dataset, arg, eq - arg);
    dataset[eq - arg] = '\0';
    if (dataset_namecheck(dataset, NULL, NULL) != 0 ||
        strpbrk(dataset, "@#$") != NULL)
        return (EINVAL);
    for (rebuild_key_spec_t *spec = keys->specs; spec != NULL;
        spec = spec->next) {
        if (strcmp(spec->dataset, dataset) == 0)
            return (EEXIST);
    }

    /* Check existence and permissions even before a SPA has been imported. */
    int fd;
    int error = key_file_open(eq + 1, &fd);
    if (error != 0)
        return (key_problem(error, dataset, B_FALSE));
    close(fd);

    rebuild_key_spec_t *spec = calloc(1, sizeof (*spec));
    if (spec == NULL)
        return (ENOMEM);
    spec->dataset = strdup(dataset);
    spec->path = strdup(eq + 1);
    if (spec->dataset == NULL || spec->path == NULL) {
        free(spec->dataset);
        free(spec->path);
        free(spec);
        return (ENOMEM);
    }
    spec->next = keys->specs;
    keys->specs = spec;
    return (0);
}

static rebuild_key_spec_t *
key_spec_by_ddobj(rebuild_keys_t *keys, uint64_t ddobj)
{
    for (rebuild_key_spec_t *spec = keys->specs; spec != NULL;
        spec = spec->next) {
        if (spec->ddobj == ddobj)
            return (spec);
    }
    return (NULL);
}

static int
key_root(dsl_dir_t *dd, uint64_t *root)
{
    if (dd->dd_crypto_obj == 0)
        return (EINVAL);
    return (zap_lookup(dd->dd_pool->dp_meta_objset, dd->dd_crypto_obj,
        DSL_CRYPTO_KEY_ROOT_DDOBJ, sizeof (*root), 1, root));
}

static int
key_metadata(dsl_dir_t *dd, rebuild_key_spec_t *spec, uint64_t *root_out)
{
    objset_t *mos = dd->dd_pool->dp_meta_objset;
    uint64_t root, crypt;
    int error = key_root(dd, &root);
    if (error != 0)
        return (error);
    *root_out = root;
    if (root != dd->dd_object)
        return (EINVAL);
    error = zap_lookup(mos, dd->dd_crypto_obj, DSL_CRYPTO_KEY_CRYPTO_SUITE,
        sizeof (crypt), 1, &crypt);
    if (error != 0)
        return (error);
    if (crypt <= ZIO_CRYPT_OFF || crypt >= ZIO_CRYPT_FUNCTIONS)
        return (ENOTSUP);
    error = zap_lookup(mos, dd->dd_crypto_obj,
        zfs_prop_to_name(ZFS_PROP_KEYFORMAT), sizeof (spec->format), 1,
        &spec->format);
    if (error == 0)
        error = zap_lookup(mos, dd->dd_crypto_obj,
            zfs_prop_to_name(ZFS_PROP_PBKDF2_SALT), sizeof (spec->salt), 1,
            &spec->salt);
    if (error == 0)
        error = zap_lookup(mos, dd->dd_crypto_obj,
            zfs_prop_to_name(ZFS_PROP_PBKDF2_ITERS), sizeof (spec->iters), 1,
            &spec->iters);
    if (error != 0)
        return (error);
    switch (spec->format) {
    case ZFS_KEYFORMAT_RAW:
    case ZFS_KEYFORMAT_HEX:
        if (spec->salt != 0 || spec->iters != 0)
            return (EINVAL);
        break;
    case ZFS_KEYFORMAT_PASSPHRASE:
        /* OpenSSL's native libzfs derivation takes a signed int count. */
        if (spec->salt == 0 || spec->iters == 0 || spec->iters > INT_MAX)
            return (EINVAL);
        break;
    default:
        return (EINVAL);
    }
    spec->ddobj = root;
    return (0);
}

static int
key_root_problem(rebuild_keys_t *keys, uint64_t root, int error,
    boolean_t missing)
{
    dsl_pool_t *dp = keys->spa->spa_dsl_pool;
    dsl_dir_t *dd = NULL;
    int hold_error = dsl_dir_hold_obj(dp, root, NULL, keys, &dd);
    if (hold_error != 0)
        return (hold_error);
    char name[ZFS_MAX_DATASET_NAME_LEN];
    dsl_dir_name(dd, name);
    dsl_dir_rele(dd, keys);
    return (key_problem(error, name, missing));
}

/* Called under the DSL config lock; no key bytes are read here. */
static int
key_validate_specs(rebuild_keys_t *keys)
{
    dsl_pool_t *dp = keys->spa->spa_dsl_pool;
    const char *pool = spa_name(keys->spa);
    size_t poollen = strlen(pool);
    for (rebuild_key_spec_t *spec = keys->specs; spec != NULL;
        spec = spec->next) {
        if (strncmp(spec->dataset, pool, poollen) != 0 ||
            (spec->dataset[poollen] != '\0' &&
            spec->dataset[poollen] != '/'))
            return (EXDEV);
        dsl_dir_t *dd = NULL;
        const char *tail = NULL;
        uint64_t root = 0;
        int error = dsl_dir_hold(dp, spec->dataset, keys, &dd, &tail);
        if (error == 0) {
            if (tail != NULL)
                error = ENOENT;
            else
                error = key_metadata(dd, spec, &root);
            if (root != 0 && root != dd->dd_object) {
                dsl_dir_rele(dd, keys);
                return (key_root_problem(keys, root, EINVAL, B_FALSE));
            }
            dsl_dir_rele(dd, keys);
        }
        if (error != 0)
            return (key_problem(error, spec->dataset, B_FALSE));
        /* Names are unique already; also reject native object aliases. */
        for (rebuild_key_spec_t *other = keys->specs; other != spec;
            other = other->next) {
            if (other->ddobj == spec->ddobj)
                return (EEXIST);
        }
    }
    return (0);
}

/*
 * Scan the MOS, not just snapnames/child ZAPs: temporary receive datasets and
 * otherwise unnamed dataset objects must not escape encryption preflight.
 * Inventory once and require every root before loading any keys. After key
 * loading, unwrap every inventoried DCK and retain its native ZIO mapping.
 */
static int
key_scan_datasets(rebuild_keys_t *keys)
{
    dsl_pool_t *dp = keys->spa->spa_dsl_pool;
    objset_t *mos = dp->dp_meta_objset;
    uint64_t object = 0;
    int error;
    while ((error = dmu_object_next(mos, &object, B_FALSE, 0)) == 0) {
        dmu_object_info_t info;
        error = dmu_object_info(mos, object, &info);
        if (error != 0)
            return (error);
        if (info.doi_bonus_type != DMU_OT_DSL_DATASET)
            continue;
        dsl_dataset_t *ds = NULL;
        error = dsl_dataset_hold_obj(dp, object, keys, &ds);
        if (error != 0)
            return (error);
        dsl_dir_t *dd = ds->ds_dir;
        if (dd->dd_crypto_obj == 0) {
            dsl_dataset_rele(ds, keys);
            continue;
        }
        uint64_t root;
        error = key_root(dd, &root);
        rebuild_key_spec_t *spec = error == 0 ?
            key_spec_by_ddobj(keys, root) : NULL;
        if (error == 0 && spec == NULL)
            error = key_root_problem(keys, root, ENOKEY, B_TRUE);
        if (error == 0) {
            rebuild_key_mapping_t *entry = calloc(1, sizeof (*entry));
            if (entry == NULL)
                error = ENOMEM;
            else {
                entry->dsobj = object;
                entry->spec = spec;
                entry->next = keys->mappings;
                keys->mappings = entry;
            }
        }
        dsl_dataset_rele(ds, keys);
        if (error != 0)
            return (error);
    }
    return (error == ESRCH ? 0 : error);
}

/* The fenced SPA cannot gain or lose dataset objects after inventory. */
static int
key_map_datasets(rebuild_keys_t *keys)
{
    dsl_pool_t *dp = keys->spa->spa_dsl_pool;
    for (rebuild_key_mapping_t *entry = keys->mappings; entry != NULL;
        entry = entry->next) {
        dsl_dataset_t *ds = NULL;
        int error = dsl_dataset_hold_obj(dp, entry->dsobj, keys, &ds);
        if (error == 0) {
            error = spa_keystore_create_mapping(keys->spa, ds, keys,
                &entry->mapping);
            dsl_dataset_rele(ds, keys);
        }
        if (error != 0)
            return (key_problem(error, entry->spec->dataset, B_FALSE));
    }
    return (0);
}

static int
key_hex_digit(uint8_t ch)
{
    if (ch >= '0' && ch <= '9')
        return (ch - '0');
    if (ch >= 'a' && ch <= 'f')
        return (ch - 'a' + 10);
    if (ch >= 'A' && ch <= 'F')
        return (ch - 'A' + 10);
    return (-1);
}

static int
key_derive(const rebuild_key_spec_t *spec, uint8_t *derived)
{
    uint8_t material[KEY_FILE_LIMIT] = { 0 };
    size_t length = 0;
    int fd;
    int error = key_file_open(spec->path, &fd);
    if (error != 0)
        return (error);
    while (length < sizeof (material)) {
        ssize_t count = read(fd, material + length,
            sizeof (material) - length);
        if (count < 0) {
            if (errno == EINTR)
                continue;
            error = errno;
            break;
        }
        if (count == 0)
            break;
        length += count;
    }
    close(fd);
    if (error != 0)
        goto out;
    if (length == sizeof (material)) {
        error = EINVAL;
        goto out;
    }
    if (spec->format != ZFS_KEYFORMAT_RAW && length != 0 &&
        material[length - 1] == '\n')
        length--;
    switch (spec->format) {
    case ZFS_KEYFORMAT_RAW:
        if (length != WRAPPING_KEY_LEN)
            error = EINVAL;
        else
            memcpy(derived, material, WRAPPING_KEY_LEN);
        break;
    case ZFS_KEYFORMAT_HEX:
        if (length != WRAPPING_KEY_LEN * 2) {
            error = EINVAL;
            break;
        }
        for (size_t i = 0; i < WRAPPING_KEY_LEN; i++) {
            int high = key_hex_digit(material[2 * i]);
            int low = key_hex_digit(material[2 * i + 1]);
            if (high < 0 || low < 0) {
                error = EINVAL;
                break;
            }
            derived[i] = (high << 4) | low;
        }
        break;
    case ZFS_KEYFORMAT_PASSPHRASE: {
        if (length < 8 || length > 512 ||
            memchr(material, '\0', length) != NULL ||
            memchr(material, '\n', length) != NULL) {
            error = EINVAL;
            break;
        }
        /* OpenZFS uses PBKDF2-HMAC-SHA1 and a little-endian uint64 salt. */
        uint64_t salt = LE_64(spec->salt);
        if (PKCS5_PBKDF2_HMAC_SHA1((const char *)material, (int)length,
            (const uint8_t *)&salt, sizeof (salt), (int)spec->iters,
            WRAPPING_KEY_LEN, derived) != 1)
            error = EIO;
        break;
    }
    default:
        error = EINVAL;
        break;
    }
out:
    explicit_bzero(material, sizeof (material));
    if (error != 0)
        explicit_bzero(derived, WRAPPING_KEY_LEN);
    return (error);
}

static int
key_load_one(rebuild_key_spec_t *spec, boolean_t use_verified)
{
    uint8_t derived[WRAPPING_KEY_LEN] = { 0 };
    nvlist_t *props = NULL, *args = NULL;
    dsl_crypto_params_t *params = NULL;
    const uint8_t *material = spec->verified_key;
    int error = 0;
    if (use_verified) {
        if (material == NULL) {
            error = ENOKEY;
            goto out;
        }
    } else {
        error = key_derive(spec, derived);
        if (error != 0)
            goto out;
        spec->verified_key = calloc(1, WRAPPING_KEY_LEN);
        if (spec->verified_key == NULL) {
            error = ENOMEM;
            goto out;
        }
        material = derived;
    }
    error = nvlist_alloc(&props, NV_UNIQUE_NAME, 0);
    if (error == 0)
        error = nvlist_alloc(&args, NV_UNIQUE_NAME, 0);
    if (error == 0)
        error = nvlist_add_uint64(props, zfs_prop_to_name(ZFS_PROP_KEYFORMAT),
            spec->format);
    if (error == 0)
        error = nvlist_add_uint8_array(args, "wkeydata", material,
            WRAPPING_KEY_LEN);
    if (error == 0)
        error = dsl_crypto_params_create_nvlist(DCP_CMD_NONE, props, args,
            &params);
    if (error == 0) {
        /* Native load authenticates the root's wrapped DCK before insertion. */
        error = spa_keystore_load_wkey(spec->dataset, params, B_FALSE);
        if (error == 0) {
            spec->wkey = params->cp_wkey;
            if (!use_verified)
                memcpy(spec->verified_key, derived, WRAPPING_KEY_LEN);
        }
    }
out:
    explicit_bzero(derived, sizeof (derived));
    if (args != NULL) {
        uint8_t *copy = NULL;
        uint_t length = 0;
        if (nvlist_lookup_uint8_array(args, "wkeydata", &copy, &length) == 0)
            explicit_bzero(copy, length);
        nvlist_free(args);
    }
    nvlist_free(props);
    if (params != NULL) {
        if (error != 0 && params->cp_wkey != NULL)
            explicit_bzero(params->cp_wkey->wk_key.ck_data, WRAPPING_KEY_LEN);
        /* On success the SPA owns the key; on failure free and zero it. */
        dsl_crypto_params_free(params, error != 0);
    }
    if (error != 0)
        key_problem(error, spec->dataset, B_FALSE);
    return (error);
}

int
rebuild_keys_load(rebuild_keys_t *keys, spa_t *spa)
{
    if (keys == NULL || spa == NULL || spa->spa_dsl_pool == NULL)
        return (EINVAL);
    if (keys->spa != NULL)
        return (EALREADY);
    if (keys->verified && keys->verified_pool_guid != spa_guid(spa)) {
        key_forget_verified(keys);
        return (EXDEV);
    }
    keys->spa = spa;
    dsl_pool_t *dp = spa->spa_dsl_pool;
    dsl_pool_config_enter(dp, keys);
    int error = key_validate_specs(keys);
    if (error == 0)
        error = key_scan_datasets(keys);
    dsl_pool_config_exit(dp, keys);

    /* Native load obtains its own pool/config holds; do not nest our lock. */
    for (rebuild_key_spec_t *spec = keys->specs;
        error == 0 && spec != NULL; spec = spec->next)
        error = key_load_one(spec, keys->verified);
    if (error == 0) {
        dsl_pool_config_enter(dp, keys);
        error = key_map_datasets(keys);
        dsl_pool_config_exit(dp, keys);
    }
    if (error != 0) {
        rebuild_keys_unload(keys);
        key_forget_verified(keys);
    } else {
        keys->verified = B_TRUE;
        keys->verified_pool_guid = spa_guid(spa);
    }
    return (error);
}

void
rebuild_keys_unload(rebuild_keys_t *keys)
{
    if (keys == NULL || keys->spa == NULL)
        return;
    while (keys->mappings != NULL) {
        rebuild_key_mapping_t *entry = keys->mappings;
        keys->mappings = entry->next;
        if (entry->mapping != NULL)
            key_mapping_rele(keys->spa, entry->mapping, keys);
        free(entry);
    }
    for (rebuild_key_spec_t *spec = keys->specs; spec != NULL;
        spec = spec->next) {
        if (spec->wkey != NULL) {
            /* No other key users may remain at this lifetime boundary. */
            if (zfs_refcount_count(&spec->wkey->wk_refcnt) == 0)
                explicit_bzero(spec->wkey->wk_key.ck_data, WRAPPING_KEY_LEN);
            int error = spa_keystore_unload_wkey_impl(keys->spa, spec->ddobj);
            if (error != 0)
                key_problem(error, spec->dataset, B_FALSE);
            spec->wkey = NULL;
        }
        spec->ddobj = 0;
        spec->format = 0;
        spec->salt = 0;
        spec->iters = 0;
    }
    keys->spa = NULL;
}

void
rebuild_keys_destroy(rebuild_keys_t *keys)
{
    if (keys == NULL)
        return;
    rebuild_keys_unload(keys);
    key_forget_verified(keys);
    while (keys->specs != NULL) {
        rebuild_key_spec_t *spec = keys->specs;
        keys->specs = spec->next;
        free(spec->dataset);
        free(spec->path);
        free(spec);
    }
    free(keys);
}
