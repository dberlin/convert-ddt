/* SPDX-License-Identifier: CDDL-1.0
 * Supplies the pinned traversal object, just like the native DDT/BRT bridges.
 * Existing public traversal entrypoints retain their exact upstream behavior.
 */
#include "module/zfs/dmu_traverse.c"
#include "dedup_fdt_traverse_native.h"

int
dedup_fdt_traverse_root(dsl_dataset_t *dataset, const blkptr_t *root,
    uint64_t minimum_txg, int flags, blkptr_cb_t callback, void *arg)
{
    if (dataset == NULL || root == NULL || callback == NULL)
        return (EINVAL);
    blkptr_t copy = *root;
    return (traverse_impl(dataset->ds_dir->dd_pool->dp_spa, dataset,
        dataset->ds_object, &copy, minimum_txg, NULL, flags, callback, arg));
}
