/*
 * Klee - Userspace bwrap translation layer
 * Tracee ABI helpers implementation
 */
#include "syscall/abi.h"
#include "syscall/sysnum.h"
#include "syscall/sysnum32.h"
#include "syscall/dispatch.h"
#include "process/memory.h"
#include "process/regs.h"
#include "util/log.h"

#include <limits.h>
#include <string.h>
#include <sys/syscall.h>

/* ==================== Pointers ==================== */

int klee_abi_read_ptr(KleeInterceptor *ic, pid_t pid, KleeAbi abi,
                      uint64_t addr, uint64_t *out)
{
    if (abi == KLEE_ABI_I386) {
        uint32_t v;
        int rc = klee_read_mem(ic, pid, &v, (const void *)(uintptr_t)addr,
                               sizeof(v));
        if (rc < 0)
            return rc;
        *out = v;
        return 0;
    }
    return klee_read_mem(ic, pid, out, (const void *)(uintptr_t)addr,
                         sizeof(*out));
}

int klee_abi_write_ptr(KleeInterceptor *ic, pid_t pid, KleeAbi abi,
                       uint64_t addr, uint64_t value)
{
    if (abi == KLEE_ABI_I386) {
        uint32_t v = (uint32_t)value;
        return klee_write_mem(ic, pid, (void *)(uintptr_t)addr, &v, sizeof(v));
    }
    return klee_write_mem(ic, pid, (void *)(uintptr_t)addr, &value,
                          sizeof(value));
}

/* ==================== socketcall / ipc ==================== */

/* socketcall(call, args): which real syscall each call is, and how many
 * arguments sit in the array.  send/recv are sendto/recvfrom with a NULL
 * address, so their two missing arguments are zero. */
static const struct { int call; int nr64; int nargs; } socketcalls[] = {
    {  1, SYS_socket,      3 }, {  2, SYS_bind,        3 },
    {  3, SYS_connect,     3 }, {  4, SYS_listen,      2 },
    {  5, SYS_accept,      3 }, {  6, SYS_getsockname, 3 },
    {  7, SYS_getpeername, 3 }, {  8, SYS_socketpair,  4 },
    {  9, SYS_sendto,      4 }, { 10, SYS_recvfrom,    4 },
    { 11, SYS_sendto,      6 }, { 12, SYS_recvfrom,    6 },
    { 13, SYS_shutdown,    2 }, { 14, SYS_setsockopt,  5 },
    { 15, SYS_getsockopt,  5 }, { 16, SYS_sendmsg,     3 },
    { 17, SYS_recvmsg,     3 }, { 18, SYS_accept4,     4 },
    { 19, SYS_recvmmsg,    5 }, { 20, SYS_sendmmsg,    4 },
};

/* ipc(call, first, second, third, ptr, fifth): the calls whose arguments
 * line up with the real syscall once shifted left by one. */
static const struct { int call; int nr64; } ipccalls[] = {
    {  2, SYS_semget }, { 13, SYS_msgget }, { 23, SYS_shmget },
};

bool klee_abi_demux_enter(KleeProcess *proc, KleeInterceptor *ic,
                          KleeEvent *ev)
{
    if (ev->abi != KLEE_ABI_I386)
        return false;

    if (ev->raw_nr == KLEE_SYS32_socketcall) {
        int call = (int)ev->args[0];
        for (size_t i = 0; i < sizeof(socketcalls) / sizeof(socketcalls[0]); i++) {
            if (socketcalls[i].call != call)
                continue;
            if (!klee_dispatch_get(socketcalls[i].nr64))
                return false;   /* nothing klee does with this call */

            uint32_t arr[6] = { 0 };
            int nargs = socketcalls[i].nargs;
            if (klee_read_mem(ic, ev->pid, arr,
                              (const void *)(uintptr_t)ev->args[1],
                              (size_t)nargs * sizeof(uint32_t)) < 0)
                return false;

            proc->demux_mem = true;
            proc->demux_dirty = false;
            proc->demux_nargs = nargs;
            proc->demux_saved_ptr = ev->args[1];
            for (int a = 0; a < 6; a++)
                proc->demux_args[a] = ev->args[a] = arr[a];
            ev->syscall_nr = socketcalls[i].nr64;
            KLEE_TRACE("socketcall %d -> syscall %d", call, ev->syscall_nr);
            return true;
        }
        return false;
    }

    if (ev->raw_nr == KLEE_SYS32_ipc) {
        int call = (int)ev->args[0] & 0xffff;
        for (size_t i = 0; i < sizeof(ipccalls) / sizeof(ipccalls[0]); i++) {
            if (ipccalls[i].call != call)
                continue;
            proc->arg_shift = 1;
            for (int a = 0; a < 5; a++)
                ev->args[a] = ev->args[a + 1];
            ev->args[5] = 0;
            ev->syscall_nr = ipccalls[i].nr64;
            KLEE_TRACE("ipc %d -> syscall %d", call, ev->syscall_nr);
            return true;
        }
        return false;
    }

    return false;
}

void klee_abi_demux_commit(KleeProcess *proc, KleeInterceptor *ic,
                           KleeEvent *ev)
{
    if (!proc->demux_mem || !proc->demux_dirty)
        return;

    uint32_t arr[6];
    for (int a = 0; a < 6; a++)
        arr[a] = (uint32_t)proc->demux_args[a];

    klee_regs_fetch(ic, proc);
    uint64_t sp = klee_regs_get_sp(proc);
    /* Below every path scratch slot a handler may have used. */
    uint64_t scratch = (sp - 128 - (uint64_t)PATH_MAX *
                        (uint64_t)(proc->path_arg_count + 1) - 64) & ~7ULL;
    if (klee_write_mem(ic, ev->pid, (void *)(uintptr_t)scratch, arr,
                       (size_t)proc->demux_nargs * sizeof(uint32_t)) < 0) {
        KLEE_DEBUG("socketcall: cannot stage argument array for pid %d",
                   ev->pid);
        proc->demux_dirty = false;
        return;
    }
    klee_regs_set_arg_raw(proc, 1, scratch);
    klee_regs_push(ic, proc);
    proc->path_modified = true;   /* make sure the exit stop restores ecx */
}

void klee_abi_demux_exit_args(const KleeProcess *proc, KleeEvent *ev)
{
    if (proc->demux_mem) {
        for (int a = 0; a < 6; a++)
            ev->args[a] = proc->demux_args[a];
    } else if (proc->arg_shift) {
        for (int a = 0; a + proc->arg_shift < 6; a++)
            ev->args[a] = ev->args[a + proc->arg_shift];
    }
}

bool klee_abi_demux_restore(KleeProcess *proc)
{
    if (!proc->demux_mem || !proc->demux_dirty)
        return false;
    klee_regs_set_arg_raw(proc, 1, proc->demux_saved_ptr);
    proc->demux_dirty = false;
    return true;
}

/* ==================== Struct layouts ==================== */

void klee_abi_stat_layout(KleeAbi abi, size_t *mode_off, size_t *uid_off,
                          size_t *gid_off)
{
    if (abi == KLEE_ABI_I386) {
        /* struct stat64 (asm/stat.h, i386): st_dev(8) pad(4) __st_ino(4)
         * st_mode(4) st_nlink(4) st_uid(4) st_gid(4) ... */
        *mode_off = 16;
        *uid_off = 24;
        *gid_off = 28;
    } else {
        /* struct stat (x86_64): st_dev(8) st_ino(8) st_nlink(8) st_mode(4)
         * st_uid(4) st_gid(4) ... */
        *mode_off = 24;
        *uid_off = 28;
        *gid_off = 32;
    }
}

int klee_abi_read_msg_control(KleeInterceptor *ic, pid_t pid, KleeAbi abi,
                              uint64_t msg_addr, uint64_t *ctrl_addr,
                              size_t *ctrl_len)
{
    if (abi == KLEE_ABI_I386) {
        /* struct compat_msghdr: name(4) namelen(4) iov(4) iovlen(4)
         * control(4) controllen(4) flags(4) */
        uint32_t f[7];
        int rc = klee_read_mem(ic, pid, f, (const void *)(uintptr_t)msg_addr,
                               sizeof(f));
        if (rc < 0)
            return rc;
        *ctrl_addr = f[4];
        *ctrl_len = f[5];
        return 0;
    }
    /* struct msghdr: name(8) namelen(4)+pad(4) iov(8) iovlen(8) control(8)
     * controllen(8) flags(4) */
    uint64_t f[6];
    int rc = klee_read_mem(ic, pid, f, (const void *)(uintptr_t)msg_addr,
                           sizeof(f));
    if (rc < 0)
        return rc;
    *ctrl_addr = f[4];
    *ctrl_len = (size_t)f[5];
    return 0;
}

bool klee_abi_cmsg_next(KleeAbi abi, const uint8_t *buf, size_t len,
                        size_t *off, int *level, int *type,
                        size_t *data_off, size_t *data_len)
{
    size_t hdr = abi == KLEE_ABI_I386 ? 12 : 16;
    size_t align = abi == KLEE_ABI_I386 ? 4 : 8;

    if (*off + hdr > len)
        return false;

    uint64_t cmsg_len;
    if (abi == KLEE_ABI_I386) {
        uint32_t l;
        memcpy(&l, buf + *off, sizeof(l));
        cmsg_len = l;
    } else {
        memcpy(&cmsg_len, buf + *off, sizeof(cmsg_len));
    }
    if (cmsg_len < hdr || cmsg_len > len - *off)
        return false;

    memcpy(level, buf + *off + hdr - 8, sizeof(*level));
    memcpy(type, buf + *off + hdr - 4, sizeof(*type));
    *data_off = *off + hdr;
    *data_len = (size_t)cmsg_len - hdr;
    *off += ((size_t)cmsg_len + align - 1) & ~(align - 1);
    return true;
}

int klee_abi_read_fprog(KleeInterceptor *ic, pid_t pid, KleeAbi abi,
                        uint64_t addr, uint16_t *len, uint64_t *filter_addr)
{
    if (abi == KLEE_ABI_I386) {
        /* struct compat_sock_fprog: u16 len; pad(2); u32 filter */
        uint8_t raw[8];
        int rc = klee_read_mem(ic, pid, raw, (const void *)(uintptr_t)addr,
                               sizeof(raw));
        if (rc < 0)
            return rc;
        uint32_t f;
        memcpy(len, raw, sizeof(*len));
        memcpy(&f, raw + 4, sizeof(f));
        *filter_addr = f;
        return 0;
    }
    uint8_t raw[16];
    int rc = klee_read_mem(ic, pid, raw, (const void *)(uintptr_t)addr,
                           sizeof(raw));
    if (rc < 0)
        return rc;
    memcpy(len, raw, sizeof(*len));
    memcpy(filter_addr, raw + 8, sizeof(*filter_addr));
    return 0;
}

int klee_abi_write_fprog(KleeInterceptor *ic, pid_t pid, KleeAbi abi,
                         uint64_t addr, uint16_t len, uint64_t filter_addr)
{
    if (abi == KLEE_ABI_I386) {
        uint8_t raw[8] = { 0 };
        uint32_t f = (uint32_t)filter_addr;
        memcpy(raw, &len, sizeof(len));
        memcpy(raw + 4, &f, sizeof(f));
        return klee_write_mem(ic, pid, (void *)(uintptr_t)addr, raw,
                              sizeof(raw));
    }
    uint8_t raw[16] = { 0 };
    memcpy(raw, &len, sizeof(len));
    memcpy(raw + 8, &filter_addr, sizeof(filter_addr));
    return klee_write_mem(ic, pid, (void *)(uintptr_t)addr, raw, sizeof(raw));
}
