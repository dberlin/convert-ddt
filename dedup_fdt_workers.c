/* SPDX-License-Identifier: CDDL-1.0 */
#include "dedup_fdt_workers.h"
#include <errno.h>
#include <pthread.h>
#include <stdlib.h>

#define DF_WORKER_STACK (256U << 10)
struct dedup_fdt_workers {
    dedup_fdt_resources_t *resources;
    uint64_t reservation, epoch;
    pthread_mutex_t lock;
    pthread_cond_t ready, done;
    pthread_t threads[64];
    unsigned count, finished, next, tasks;
    int stop;
    void (*function)(void *, unsigned);
    void *arg;
};

static void *
worker(void *arg)
{
    dedup_fdt_workers_t *workers = arg;
    uint64_t epoch = 0;
    pthread_mutex_lock(&workers->lock);
    for (;;) {
        while (!workers->stop && workers->epoch == epoch)
            pthread_cond_wait(&workers->ready, &workers->lock);
        if (workers->stop)
            break;
        epoch = workers->epoch;
        pthread_mutex_unlock(&workers->lock);
        for (;;) {
            unsigned index = __atomic_fetch_add(&workers->next, 1,
                __ATOMIC_RELAXED);
            if (index >= workers->tasks)
                break;
            workers->function(workers->arg, index);
        }
        pthread_mutex_lock(&workers->lock);
        if (++workers->finished == workers->count)
            pthread_cond_signal(&workers->done);
    }
    pthread_mutex_unlock(&workers->lock);
    return (NULL);
}

int
dedup_fdt_workers_open(dedup_fdt_resources_t *resources, unsigned count,
    dedup_fdt_workers_t **out)
{
    if (resources == NULL || count == 0 || count > 64 || out == NULL)
        return (EINVAL);
    int error;
    while ((error = dedup_fdt_memory_reserve(resources,
        sizeof (dedup_fdt_workers_t) + (uint64_t)count * DF_WORKER_STACK)) != 0 &&
        count > 1)
        count--;
    if (error != 0)
        return (error);
    uint64_t reservation = sizeof (dedup_fdt_workers_t) +
        (uint64_t)count * DF_WORKER_STACK;
    dedup_fdt_workers_t *workers = calloc(1, sizeof (*workers));
    if (workers == NULL) {
        dedup_fdt_memory_release(resources, reservation);
        return (ENOMEM);
    }
    workers->resources = resources;
    workers->reservation = reservation;
    pthread_mutex_init(&workers->lock, NULL);
    pthread_cond_init(&workers->ready, NULL);
    pthread_cond_init(&workers->done, NULL);
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    error = pthread_attr_setstacksize(&attr, DF_WORKER_STACK);
    while (error == 0 && workers->count < count) {
        error = pthread_create(&workers->threads[workers->count], &attr,
            worker, workers);
        if (error == 0)
            workers->count++;
    }
    pthread_attr_destroy(&attr);
    if (error != 0) {
        dedup_fdt_workers_close(workers);
        return (error);
    }
    *out = workers;
    return (0);
}

unsigned
dedup_fdt_workers_count(const dedup_fdt_workers_t *workers)
{
    return (workers->count);
}

void
dedup_fdt_workers_run(dedup_fdt_workers_t *workers, unsigned count,
    void (*function)(void *, unsigned), void *arg)
{
    if (count == 0)
        return;
    pthread_mutex_lock(&workers->lock);
    workers->tasks = count;
    workers->function = function;
    workers->arg = arg;
    workers->finished = 0;
    __atomic_store_n(&workers->next, 0, __ATOMIC_RELAXED);
    workers->epoch++;
    pthread_cond_broadcast(&workers->ready);
    while (workers->finished != workers->count)
        pthread_cond_wait(&workers->done, &workers->lock);
    pthread_mutex_unlock(&workers->lock);
}

void
dedup_fdt_workers_close(dedup_fdt_workers_t *workers)
{
    if (workers == NULL)
        return;
    pthread_mutex_lock(&workers->lock);
    workers->stop = 1;
    pthread_cond_broadcast(&workers->ready);
    pthread_mutex_unlock(&workers->lock);
    for (unsigned i = 0; i < workers->count; i++)
        pthread_join(workers->threads[i], NULL);
    pthread_cond_destroy(&workers->done);
    pthread_cond_destroy(&workers->ready);
    pthread_mutex_destroy(&workers->lock);
    dedup_fdt_memory_release(workers->resources, workers->reservation);
    free(workers);
}
