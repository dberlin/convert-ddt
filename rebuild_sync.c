/* SPDX-License-Identifier: CDDL-1.0
 * The private maintenance importer must not consume future-free references
 * while their DDT/BRT ownership and historical metadata are being replaced.
 */
#include <sys/zfs_context.h>
#include <sys/spa_impl.h>
#include <sys/dmu_objset.h>
#include <sys/bpobj.h>
#include <sys/dsl_pool.h>
#include <sys/dsl_scan.h>
#include <sys/zthr.h>
#include <sys/ddt.h>
#include <sys/brt.h>
#include "rebuild_sync.h"

int __wrap_bpobj_iterate(bpobj_t *, bpobj_itor_t *, void *, dmu_tx_t *);
void __wrap_dsl_scan_sync(dsl_pool_t *, dmu_tx_t *);
void __wrap_ddt_sync(spa_t *, uint64_t);
void __wrap_brt_sync(spa_t *, uint64_t);
void __wrap_brt_pending_apply(spa_t *, uint64_t);
zthr_t *__wrap_zthr_create(const char *, zthr_checkfunc_t *,
    zthr_func_t *, void *, pri_t);

static uint64_t fenced_guid;
static zthr_checkfunc_t *delete_check, *condense_check;

static boolean_t
maintenance_pool(spa_t *spa)
{
    uint64_t guid = __atomic_load_n(&fenced_guid, __ATOMIC_ACQUIRE);
    return (guid != 0 && (spa_guid(spa) == 0 || spa_guid(spa) == guid));
}

int
rebuild_sync_fence(uint64_t guid)
{
    uint64_t expected = 0;
    if (guid == 0)
        return (EINVAL);
    if (!__atomic_compare_exchange_n(&fenced_guid, &expected, guid,
        B_FALSE, __ATOMIC_RELEASE, __ATOMIC_RELAXED))
        return (EBUSY);
    return (0);
}

void
rebuild_sync_unfence(void)
{
    __atomic_store_n(&fenced_guid, 0, __ATOMIC_RELEASE);
}

extern int __real_bpobj_iterate(bpobj_t *, bpobj_itor_t *, void *, dmu_tx_t *);

/* Link only dedup-fdt with --wrap=bpobj_iterate. Ordinary converter and
 * administrative binaries retain the unmodified native free pipeline.
 * Live syncing bplists still drain normally; new late-pass MOS frees remain
 * owned by the active deferred bpobj and must be merged, not overwritten, by
 * the auxiliary-owner publisher. The original queue is detached durably by
 * that publisher before it constructs its transformed replacement.
 */
int
__wrap_bpobj_iterate(bpobj_t *bpo, bpobj_itor_t *func, void *arg, dmu_tx_t *tx)
{
    uint64_t guid = __atomic_load_n(&fenced_guid, __ATOMIC_ACQUIRE);
    if (guid != 0 && bpo != NULL && bpo->bpo_os != NULL) {
        spa_t *spa = dmu_objset_spa(bpo->bpo_os);
        if (spa_guid(spa) == guid && bpo == &spa->spa_deferred_bpobj)
            return (0);
    }
    return (__real_bpobj_iterate(bpo, func, arg, tx));
}

extern void __real_dsl_scan_sync(dsl_pool_t *, dmu_tx_t *);

/* Suppress async-destroy, free-bpobj and scan work before import can start its
 * first writable TXG, rather than racing spa_async_suspend() after import. */
void
__wrap_dsl_scan_sync(dsl_pool_t *dp, dmu_tx_t *tx)
{
    if (!maintenance_pool(dp->dp_spa))
        __real_dsl_scan_sync(dp, tx);
}

extern void __real_ddt_sync(spa_t *, uint64_t);
extern void __real_brt_sync(spa_t *, uint64_t);
extern void __real_brt_pending_apply(spa_t *, uint64_t);

/* Import-defer scan tunables do not suppress ordinary sharing-table sync.
 * Its log flushing and zero-entry retirement would otherwise change the
 * authoritative inventory between shadow batches. Explicit private shadow
 * writes bypass these global hooks and publish their preloaded state. */
void
__wrap_ddt_sync(spa_t *spa, uint64_t txg)
{
    if (!maintenance_pool(spa))
        __real_ddt_sync(spa, txg);
}

void
__wrap_brt_sync(spa_t *spa, uint64_t txg)
{
    if (!maintenance_pool(spa))
        __real_brt_sync(spa, txg);
}

void
__wrap_brt_pending_apply(spa_t *spa, uint64_t txg)
{
    if (!maintenance_pool(spa))
        __real_brt_pending_apply(spa, txg);
}

static boolean_t
maintenance_delete_check(void *arg, zthr_t *thread)
{
    return (!maintenance_pool(arg) && delete_check(arg, thread));
}

static boolean_t
maintenance_condense_check(void *arg, zthr_t *thread)
{
    return (!maintenance_pool(arg) && condense_check(arg, thread));
}

extern zthr_t *__real_zthr_create(const char *, zthr_checkfunc_t *,
    zthr_func_t *, void *, pri_t);

/* These exact names and argument types are pinned by spa.c in 2.4.4. Keeping
 * the original worker and argument preserves ordinary zthr cancellation and
 * lifetime semantics; only admission is held while the GUID fence is active.
 */
zthr_t *
__wrap_zthr_create(const char *name, zthr_checkfunc_t *check,
    zthr_func_t *func, void *arg, pri_t priority)
{
    if (__atomic_load_n(&fenced_guid, __ATOMIC_ACQUIRE) != 0) {
        if (strcmp(name, "z_livelist_destroy") == 0) {
            delete_check = check;
            check = maintenance_delete_check;
        } else if (strcmp(name, "z_livelist_condense") == 0) {
            condense_check = check;
            check = maintenance_condense_check;
        }
    }
    return (__real_zthr_create(name, check, func, arg, priority));
}
