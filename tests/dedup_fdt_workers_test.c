/* SPDX-License-Identifier: CDDL-1.0 */
#include "dedup_fdt_workers.h"
#include <assert.h>
#include <pthread.h>
#include <stdint.h>

typedef struct test_state {
    pthread_barrier_t barrier;
    unsigned started, finished;
    uint64_t values[4];
} test_state_t;

static void
compute(void *arg, unsigned index)
{
    test_state_t *state = arg;
    __atomic_fetch_add(&state->started, 1, __ATOMIC_RELAXED);
    /* All four tasks must genuinely execute on separate workers. */
    int result = pthread_barrier_wait(&state->barrier);
    assert(result == 0 || result == PTHREAD_BARRIER_SERIAL_THREAD);
    uint64_t value = index + 1;
    for (unsigned i = 0; i < 10000; i++)
        value = value * 6364136223846793005ULL + 1;
    state->values[index] = value;
    __atomic_fetch_add(&state->finished, 1, __ATOMIC_RELAXED);
}

int
main(void)
{
    dedup_fdt_resources_t *resources;
    assert(dedup_fdt_resources_open(128ULL << 20, 32ULL << 20,
        64ULL << 20, &resources) == 0);
    dedup_fdt_resource_stats_t before, after;
    dedup_fdt_resources_stats(resources, &before);
    dedup_fdt_workers_t *workers;
    assert(dedup_fdt_workers_open(resources, 4, &workers) == 0);
    assert(dedup_fdt_workers_count(workers) == 4);
    test_state_t state = {0};
    assert(pthread_barrier_init(&state.barrier, NULL, 4) == 0);
    for (unsigned repeat = 0; repeat < 3; repeat++)
        dedup_fdt_workers_run(workers, 4, compute, &state);
    assert(state.started == 12 && state.finished == 12);
    for (unsigned i = 0; i < 4; i++)
        assert(state.values[i] != 0);
    pthread_barrier_destroy(&state.barrier);
    dedup_fdt_workers_close(workers);
    dedup_fdt_resources_stats(resources, &after);
    assert(after.workspace_bytes == before.workspace_bytes);
    dedup_fdt_resources_close(resources);
    return (0);
}
