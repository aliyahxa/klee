/*
 * Klee - Userspace bwrap translation layer
 * Child seccomp filter interception implementation
 *
 * When a child installs a seccomp filter under the ptrace backend,
 * we prepend instructions that convert Klee's intercepted syscalls
 * to SECCOMP_RET_TRACE (which generates a ptrace stop), then fall
 * through to the child's original filter for everything else.
 */
#include "compat/seccomp_filter.h"
#include "syscall/abi.h"
#include "syscall/sysnum.h"
#include "syscall/sysnum32.h"
#include "util/log.h"

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>
#include <stddef.h>
#include <linux/seccomp.h>
#include <linux/audit.h>

/* BPF instruction macros */
#undef BPF_STMT
#undef BPF_JUMP
#define BPF_STMT(code, k) \
    ((struct sock_filter){ (unsigned short)(code), 0, 0, (unsigned int)(k) })
#define BPF_JUMP(code, k, jt, jf) \
    ((struct sock_filter){ (unsigned short)(code), (unsigned char)(jt), (unsigned char)(jf), (unsigned int)(k) })

/*
 * Build a rewritten BPF filter that prepends SECCOMP_RET_TRACE checks
 * for Klee's intercepted syscalls before the child's original filter.
 *
 * orig_insns: the child's original BPF instructions (already read into
 *             klee's memory from the tracee).
 * orig_len:   number of instructions in the child's original filter.
 *
 * Returns a malloc'd sock_fprog on success, NULL on failure.
 * Caller must free both result->filter and result.
 */
static struct sock_fprog *rewrite_child_filter(const struct sock_filter *orig_insns,
                                                unsigned short orig_len)
{
    /* Get the list of intercepted syscalls, for both ABIs */
    int syscalls[KLEE_INTERCEPTED_SYSCALL_COUNT];
    int count = klee_get_intercepted_syscalls(syscalls,
                                               KLEE_INTERCEPTED_SYSCALL_COUNT);
    if (count <= 0) {
        KLEE_WARN("seccomp rewrite: no intercepted syscalls");
        return NULL;
    }
    int syscalls32[KLEE_INTERCEPTED_SYSCALL_COUNT * 2];
    size_t count32 = 0;
    for (int i = 0; i < count; i++)
        count32 += klee_sysnum_x64_to_i386(syscalls[i], syscalls32 + count32,
                                           sizeof(syscalls32) / sizeof(int) - count32);
    if (count32 + 2 <= sizeof(syscalls32) / sizeof(int)) {
        syscalls32[count32++] = KLEE_SYS32_socketcall;
        syscalls32[count32++] = KLEE_SYS32_ipc;
    }
    if (count > 250 || count32 > 250) {
        KLEE_WARN("seccomp rewrite: too many intercepted syscalls");
        return NULL;
    }

    /*
     * Prefix layout (one block per ABI, each ending in its own RET_TRACE
     * so every jump stays within the 8-bit range):
     *   [0]        LD arch
     *   [1]        JEQ AUDIT_ARCH_I386 -> i386 block
     *   x86_64:    LD nr; JEQ syscall_i -> ret_trace ...; JA child; RET TRACE
     *   i386:      LD nr; JEQ syscall_i -> ret_trace ...; JA child; RET TRACE
     *   child's original filter
     */
    size_t block64 = 1 + (size_t)count + 2;
    size_t block32 = 1 + count32 + 2;
    size_t prefix_len = 2 + block64 + block32;
    size_t total_len = prefix_len + orig_len;

    if (total_len > 4096) { /* BPF_MAXINSNS */
        KLEE_WARN("seccomp rewrite: combined filter too large (%zu > %d)",
                   total_len, BPF_MAXINSNS);
        return NULL;
    }

    struct sock_filter *combined = calloc(total_len, sizeof(struct sock_filter));
    if (!combined)
        return NULL;

    size_t n = 0;
    combined[n++] = BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                              offsetof(struct seccomp_data, arch));
    combined[n++] = BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_I386,
                              (uint8_t)block64, 0);

    const int *lists[2] = { syscalls, syscalls32 };
    size_t counts[2] = { (size_t)count, count32 };
    for (int b = 0; b < 2; b++) {
        combined[n++] = BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                                  offsetof(struct seccomp_data, nr));
        for (size_t i = 0; i < counts[b]; i++) {
            size_t remaining = counts[b] - i - 1;
            combined[n++] = BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,
                                      (uint32_t)lists[b][i],
                                      (uint8_t)(remaining + 1), 0);
        }
        /* No match: jump over this block's RET_TRACE (and the other
         * block, if any) to the child's filter. */
        size_t to_child = prefix_len - (n + 1);
        if (to_child > 255) {
            KLEE_WARN("seccomp rewrite: prefix too long");
            free(combined);
            return NULL;
        }
        combined[n++] = BPF_JUMP(BPF_JMP | BPF_JA, (uint32_t)to_child, 0, 0);
        combined[n++] = BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRACE);
    }

    /* Append child's original filter unchanged */
    memcpy(&combined[n], orig_insns, orig_len * sizeof(struct sock_filter));
    n += orig_len;

    struct sock_fprog *result = calloc(1, sizeof(struct sock_fprog));
    if (!result) {
        free(combined);
        return NULL;
    }
    result->len = (unsigned short)n;
    result->filter = combined;

    KLEE_DEBUG("seccomp rewrite: prefix=%zu + orig=%d = %zu instructions",
               prefix_len, orig_len, n);
    return result;
}

int klee_compat_handle_seccomp_filter(KleeInterceptor *ic, pid_t pid,
                                       KleeAbi abi, uint16_t fprog_len,
                                       uint64_t fprog_filter,
                                       uint64_t fprog_remote,
                                       uint64_t tracee_rsp)
{
    if (!fprog_filter || fprog_len == 0) {
        KLEE_WARN("child seccomp filter: empty program");
        return 0;
    }
    struct sock_fprog fprog_storage = {
        .len = fprog_len,
        .filter = (struct sock_filter *)(uintptr_t)fprog_filter,
    };
    struct sock_fprog *fprog_local = &fprog_storage;

    KLEE_DEBUG("child seccomp filter: %d instructions from pid %d",
               fprog_local->len, pid);

    /*
     * For seccomp_unotify backend: child filters don't interfere with
     * the supervisor's notification mechanism, as USER_NOTIF takes priority
     * over other actions in the filter chain.
     */
    if (ic->backend == INTERCEPT_SECCOMP_UNOTIFY)
        return 0; /* Allow as-is */

    /*
     * For ptrace backend: child filters could potentially KILL syscalls
     * before ptrace sees them. Rewrite the child's BPF to exempt klee's
     * intercepted syscalls by prepending SECCOMP_RET_TRACE instructions.
     */
    if (ic->backend == INTERCEPT_PTRACE) {
        /* First, read the child's original BPF instructions from tracee memory.
         * fprog_local->filter is a TRACEE-SIDE pointer, not valid in our space. */
        size_t orig_filter_size = fprog_local->len * sizeof(struct sock_filter);
        struct sock_filter *orig_insns = malloc(orig_filter_size);
        if (!orig_insns)
            return 0;

        int rc = ic->read_mem(ic, pid, orig_insns,
                               fprog_local->filter, orig_filter_size);
        if (rc < 0) {
            KLEE_WARN("seccomp rewrite: failed to read %d BPF instructions from tracee",
                       fprog_local->len);
            free(orig_insns);
            return 0;
        }

        struct sock_fprog *rewritten = rewrite_child_filter(orig_insns,
                                                             fprog_local->len);
        free(orig_insns);

        if (!rewritten) {
            KLEE_WARN("child installing seccomp filter under ptrace - "
                       "rewrite failed, allowing original filter");
            return 0;
        }

        /* The rewritten filter is LARGER than the original (prefix added).
         * Write the new filter to a scratch area below the tracee's stack
         * and update the sock_fprog struct in the tracee to point there. */
        size_t filter_size = rewritten->len * sizeof(struct sock_filter);
        /* Place below tracee's stack (past 128-byte red zone on x86_64) */
        uint64_t scratch = (tracee_rsp - 128 - filter_size) & ~7ULL;

        rc = ic->write_mem(ic, pid, (void *)(uintptr_t)scratch,
                            rewritten->filter, filter_size);
        if (rc < 0) {
            KLEE_WARN("seccomp rewrite: failed to write filter to tracee: %d", rc);
            free(rewritten->filter);
            free(rewritten);
            return 0;
        }

        /* Update the tracee's sock_fprog: new length and new filter pointer.
         * fprog_remote is the tracee-side address of the sock_fprog struct. */
        rc = klee_abi_write_fprog(ic, pid, abi, fprog_remote, rewritten->len,
                                  scratch);
        if (rc < 0)
            KLEE_WARN("seccomp rewrite: failed to update fprog: %d", rc);

        KLEE_INFO("seccomp rewrite: successfully rewrote child filter for pid %d "
                   "(%d -> %d instructions)", pid, fprog_local->len, rewritten->len);
        free(rewritten->filter);
        free(rewritten);
        return 0;
    }

    return 0; /* Allow */
}
