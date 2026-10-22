/*
 * Klee - Userspace bwrap translation layer
 * Child seccomp filter interception
 */
#ifndef KLEE_SECCOMP_FILTER_H
#define KLEE_SECCOMP_FILTER_H

#include "intercept/intercept.h"
#include <linux/filter.h>
#include <stdint.h>

/* Handle a child process attempting to install a seccomp filter.
 * Analyzes the BPF program for conflicts with klee's interception.
 * fprog_remote is the tracee-side address of its sock_fprog (in the
 * tracee's ABI); fprog_len/fprog_filter are that struct's contents.
 * tracee_rsp is the tracee's current stack pointer (for scratch space).
 * Returns 0 to allow, negative to deny. */
int klee_compat_handle_seccomp_filter(KleeInterceptor *ic, pid_t pid,
                                       KleeAbi abi, uint16_t fprog_len,
                                       uint64_t fprog_filter,
                                       uint64_t fprog_remote,
                                       uint64_t tracee_rsp);

#endif /* KLEE_SECCOMP_FILTER_H */
