/*
 * Klee - Userspace bwrap translation layer
 * Raw BPF filter generation
 */
#include "filter.h"
#include "syscall/sysnum32.h"
#include "util/log.h"

#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <sys/syscall.h>
#include <linux/seccomp.h>
#include <linux/audit.h>

/* BPF helper macros - undef system ones and use compound literal form */
#undef BPF_STMT
#undef BPF_JUMP
#define BPF_STMT(code, k) \
    ((struct sock_filter){ (unsigned short)(code), 0, 0, (unsigned int)(k) })
#define BPF_JUMP(code, k, jt, jf) \
    ((struct sock_filter){ (unsigned short)(code), (unsigned char)(jt), (unsigned char)(jf), (unsigned int)(k) })

/* i386 numbers to trap for a list of x86_64 ones: every i386 spelling of
 * each syscall (stat, oldstat and stat64 for stat) plus the socketcall and
 * ipc multiplexers when any of the calls behind them is intercepted. */
static size_t expand_i386_list(const int *nrs64, size_t count, int *out,
                               size_t max)
{
    size_t n = 0;
    bool want_socketcall = false, want_ipc = false;
    for (size_t i = 0; i < count && n < max; i++) {
        n += klee_sysnum_x64_to_i386(nrs64[i], out + n, max - n);
        switch (nrs64[i]) {
        case SYS_bind: case SYS_connect: case SYS_sendmsg: case SYS_recvmsg:
        case SYS_recvfrom: case SYS_getsockopt: case SYS_sendto:
        case SYS_setsockopt: case SYS_socket:
            want_socketcall = true;
            break;
        case SYS_shmget: case SYS_msgget: case SYS_semget:
            want_ipc = true;
            break;
        default:
            break;
        }
    }
    if (want_socketcall && n < max)
        out[n++] = KLEE_SYS32_socketcall;
    if (want_ipc && n < max)
        out[n++] = KLEE_SYS32_ipc;
    return n;
}

/* One per-arch chain: load nr, compare against each number, ALLOW if none
 * matched, MATCH otherwise.  Jump offsets are 8-bit, which bounds a chain
 * at 254 entries. */
static size_t emit_chain(struct sock_filter *f, size_t n, const int *nrs,
                         size_t count, uint32_t match_action)
{
    f[n++] = BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr));
    for (size_t i = 0; i < count; i++) {
        size_t remaining = count - i - 1;
        f[n++] = BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (uint32_t)nrs[i],
                          (uint8_t)(remaining + 1), 0);
    }
    f[n++] = BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);
    f[n++] = BPF_STMT(BPF_RET | BPF_K, match_action);
    return n;
}

/*
 * Generate a BPF filter for seccomp.
 *
 *   [0]  Load architecture
 *   [1]  Jump to the x86_64 chain if AUDIT_ARCH_X86_64
 *   [2]  Jump to the i386 chain if AUDIT_ARCH_I386
 *   [3]  ALLOW (any other arch, x32 included)
 *   x86_64 chain, i386 chain (see emit_chain)
 */
static KleeBpfProg generate_filter(const int *syscall_nrs, size_t count,
                                    uint32_t match_action)
{
    KleeBpfProg prog = { NULL, 0 };

    int nrs32[KLEE_MAX_INTERCEPTED_SYSCALLS * 2];
    size_t count32 = expand_i386_list(syscall_nrs, count, nrs32,
                                      sizeof(nrs32) / sizeof(nrs32[0]));

    if (count > 254 || count32 > 254) {
        KLEE_WARN("seccomp filter: too many syscalls (%zu/%zu), truncating",
                  count, count32);
        if (count > 254) count = 254;
        if (count32 > 254) count32 = 254;
    }

    size_t max_len = 4 + (3 + count) + (3 + count32);
    struct sock_filter *f = calloc(max_len, sizeof(struct sock_filter));
    if (!f)
        return prog;

    size_t n = 0;
    size_t chain64_len = 3 + count;

    f[n++] = BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                       offsetof(struct seccomp_data, arch));
    f[n++] = BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 2, 0);
    f[n++] = BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_I386,
                      (uint8_t)(chain64_len + 1), 0);
    f[n++] = BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);

    n = emit_chain(f, n, syscall_nrs, count, match_action);
    n = emit_chain(f, n, nrs32, count32, match_action);

    prog.filter = f;
    prog.len = n;
    return prog;
}

KleeBpfProg klee_bpf_generate_notif_filter(const int *syscall_nrs, size_t count)
{
#ifdef SECCOMP_RET_USER_NOTIF
    return generate_filter(syscall_nrs, count, SECCOMP_RET_USER_NOTIF);
#else
    (void)syscall_nrs;
    (void)count;
    KLEE_ERROR("SECCOMP_RET_USER_NOTIF not available");
    return (KleeBpfProg){ NULL, 0 };
#endif
}

KleeBpfProg klee_bpf_generate_trace_filter(const int *syscall_nrs, size_t count)
{
    return generate_filter(syscall_nrs, count, SECCOMP_RET_TRACE);
}

void klee_bpf_free(KleeBpfProg *prog)
{
    if (prog) {
        free(prog->filter);
        prog->filter = NULL;
        prog->len = 0;
    }
}
