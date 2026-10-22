/*
 * Klee - Userspace bwrap translation layer
 * PID namespace simulation implementation
 */
#include "ns/pid_ns.h"
#include "util/hash_table.h"
#include "util/log.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

KleePidMap *klee_pid_map_create(void)
{
    KleePidMap *pm = calloc(1, sizeof(KleePidMap));
    if (!pm)
        return NULL;

    pm->real_to_virtual = klee_ht_create();
    pm->virtual_to_real = klee_ht_create();

    if (!pm->real_to_virtual || !pm->virtual_to_real) {
        klee_ht_destroy(pm->real_to_virtual);
        klee_ht_destroy(pm->virtual_to_real);
        free(pm);
        return NULL;
    }

    pm->next_vpid = 1;
    pm->init_real_pid = 0;
    return pm;
}

void klee_pid_map_destroy(KleePidMap *pm)
{
    if (!pm)
        return;
    klee_ht_destroy(pm->real_to_virtual);
    klee_ht_destroy(pm->virtual_to_real);
    free(pm);
}

pid_t klee_pid_map_add(KleePidMap *pm, pid_t real_pid)
{
    if (!pm)
        return 0;

    /* Check if already mapped */
    pid_t existing = klee_pid_map_r2v(pm, real_pid);
    if (existing > 0)
        return existing;

    /* Numbering: the first process is init and shows as 1; every other
     * process keeps its host number.  The kernel writes real ids where klee
     * cannot follow (CLONE_CHILD_SETTID, SIGCHLD, F_GETLK, PI and robust
     * futex owners that glibc compares with its cached tid), so sequential
     * virtual numbers would disagree with getpid()/gettid() and break
     * pthread_kill and friends.  What a PID namespace must still provide,
     * containment and a process that is 1, is done by lookup. */
    pid_t vpid = pm->init_real_pid == 0 ? 1 : real_pid;
    if (vpid != 1 && klee_ht_get(pm->virtual_to_real, (uint64_t)vpid)) {
        /* Should not happen: live host pids are unique.  Fall back to the
         * sequential counter rather than aliasing two processes. */
        vpid = pm->next_vpid;
        while (klee_ht_get(pm->virtual_to_real, (uint64_t)vpid) && vpid < 0x7FFFFFFF)
            vpid++;
    }
    if (vpid >= pm->next_vpid)
        pm->next_vpid = vpid + 1;

    /* Store as (uintptr_t) value in hash table since it stores void* */
    klee_ht_put(pm->real_to_virtual, (uint64_t)real_pid,
                (void *)(uintptr_t)vpid);
    klee_ht_put(pm->virtual_to_real, (uint64_t)vpid,
                (void *)(uintptr_t)real_pid);

    if (vpid == 1)
        pm->init_real_pid = real_pid;

    KLEE_DEBUG("pid_map: real=%d -> virtual=%d", real_pid, vpid);
    return vpid;
}

int klee_pid_map_add_explicit(KleePidMap *pm, pid_t real_pid, pid_t virtual_pid)
{
    if (!pm)
        return -1;

    klee_ht_put(pm->real_to_virtual, (uint64_t)real_pid,
                (void *)(uintptr_t)virtual_pid);
    klee_ht_put(pm->virtual_to_real, (uint64_t)virtual_pid,
                (void *)(uintptr_t)real_pid);

    if (virtual_pid == 1)
        pm->init_real_pid = real_pid;

    if (virtual_pid >= pm->next_vpid)
        pm->next_vpid = virtual_pid + 1;

    return 0;
}

void klee_pid_map_remove(KleePidMap *pm, pid_t real_pid)
{
    if (!pm)
        return;

    void *val = klee_ht_remove(pm->real_to_virtual, (uint64_t)real_pid);
    if (val) {
        pid_t vpid = (pid_t)(uintptr_t)val;
        klee_ht_remove(pm->virtual_to_real, (uint64_t)vpid);
        KLEE_DEBUG("pid_map: removed real=%d virtual=%d", real_pid, vpid);
    }
}

pid_t klee_pid_map_r2v(const KleePidMap *pm, pid_t real_pid)
{
    if (!pm)
        return 0;
    void *val = klee_ht_get(pm->real_to_virtual, (uint64_t)real_pid);
    return val ? (pid_t)(uintptr_t)val : 0;
}

pid_t klee_pid_map_v2r(const KleePidMap *pm, pid_t virtual_pid)
{
    if (!pm)
        return 0;
    void *val = klee_ht_get(pm->virtual_to_real, (uint64_t)virtual_pid);
    return val ? (pid_t)(uintptr_t)val : 0;
}

bool klee_pid_map_is_init(const KleePidMap *pm, pid_t real_pid)
{
    return pm && pm->init_real_pid == real_pid;
}

pid_t klee_pid_map_get_init(const KleePidMap *pm)
{
    return pm ? pm->init_real_pid : 0;
}

size_t klee_pid_map_count(const KleePidMap *pm)
{
    return pm ? klee_ht_size(pm->real_to_virtual) : 0;
}

int klee_proc_status_ids(pid_t pid, pid_t *tgid, pid_t *ppid)
{
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/status", pid);
    FILE *f = fopen(path, "re");
    if (!f)
        return -1;

    pid_t t = 0, p = -1;
    char line[256];
    while (fgets(line, sizeof(line), f)) {
        if (sscanf(line, "Tgid: %d", &t) == 1)
            continue;
        if (sscanf(line, "PPid: %d", &p) == 1)
            break;
    }
    fclose(f);

    if (t <= 0 || p < 0)
        return -1;
    if (tgid)
        *tgid = t;
    if (ppid)
        *ppid = p;
    return 0;
}
