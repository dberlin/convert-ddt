/* SPDX-License-Identifier: CDDL-1.0 */
#ifndef DEDUP_FDT_TRAVERSE_NATIVE_H
#define DEDUP_FDT_TRAVERSE_NATIVE_H
#include <sys/dsl_dataset.h>
#include <sys/dmu_traverse.h>
/* Metadata-only native traversal of an unpublished root with its REAL dataset
 * bookmark/key context. Never temporarily mutates the live dataset root. */
int dedup_fdt_traverse_root(dsl_dataset_t *, const blkptr_t *, uint64_t,
    int, blkptr_cb_t, void *);
#endif
