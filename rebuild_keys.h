/* SPDX-License-Identifier: CDDL-1.0 */
#ifndef REBUILD_KEYS_H
#define REBUILD_KEYS_H

#include <sys/spa.h>

typedef struct rebuild_keys rebuild_keys_t;

int rebuild_keys_create(rebuild_keys_t **out);
/* Retains DATASET/PATH, not file contents. Add all specs before preflight. */
int rebuild_keys_add(rebuild_keys_t *, const char *dataset_eq_path);
/*
 * The SPA must be exclusively imported and fenced against background mutation.
 * Call with no DSL config lock held. This performs no persistent mutation and
 * works on both read-only and writable libzpool SPAs. All encrypted MOS dataset
 * objects (including snapshots and internal datasets) receive native mappings.
 * Missing/incorrect keys must be rejected by this call on the read-only import
 * before the caller performs its first writable import.
 * Successful preflight retains only a private derived 32-byte wrapping key per
 * root, guarded by full-preflight success and pool GUID. Subsequent load() calls
 * on this helper never reopen key files: native load reauthenticates the exact
 * proven material. Thus key-file replacement/removal between RO and RW imports
 * cannot introduce a new key-file failure after the first writable import.
 * Any operational load failure clears this handoff material.
 */
int rebuild_keys_load(rebuild_keys_t *, spa_t *);
/*
 * Finish IO and release all other decrypting dataset/objset holds first. Call
 * before spa_close/export/kernel_fini, while the loaded SPA remains alive.
 * Removes this helper's native mappings/wrapping keys, retaining configured
 * names/paths and verified derived wrapping material across SPA lifecycles.
 * Keep the same helper alive through the RO -> RW handoff. Its private derived
 * buffers remain secret until destroy(), or until an operational load failure.
 */
void rebuild_keys_unload(rebuild_keys_t *);
/* Also unloads and explicitly wipes handoff keys; accepts NULL. */
void rebuild_keys_destroy(rebuild_keys_t *);

#endif /* REBUILD_KEYS_H */
