/*
 * Klee - Userspace bwrap translation layer
 * Read-only mount enforcement
 */
#ifndef KLEE_READONLY_H
#define KLEE_READONLY_H

#include "fs/mount_table.h"
#include <stdbool.h>

/* Check if a syscall on the given path should be blocked due to read-only mount.
 * Returns true if the operation should be denied with EROFS. */
bool klee_readonly_check_path(const KleeMountTable *mt, const char *guest_path,
                               int syscall_nr);

/* Check if an open() with the given flags should be blocked.  host_path is
 * the translated host path of the target (may be NULL); it is only stat()ed
 * so that existing special files, directories and read-only reopens of
 * existing files pass, the way they do on a real read-only mount. */
bool klee_readonly_check_open(const KleeMountTable *mt, const char *guest_path,
                               const char *host_path, int flags);

#endif /* KLEE_READONLY_H */
