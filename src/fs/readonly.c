/*
 * Klee - Userspace bwrap translation layer
 * Read-only mount enforcement implementation
 */
#include "fs/readonly.h"
#include "syscall/sysnum.h"
#include "util/log.h"

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <sys/syscall.h>

/* Syscalls that modify filesystem content */
static bool is_write_syscall(int syscall_nr)
{
    switch (syscall_nr) {
    case KLEE_SYS_unlink:
    case KLEE_SYS_unlinkat:
    case KLEE_SYS_rmdir:
    case KLEE_SYS_rename:
    case KLEE_SYS_renameat:
    case KLEE_SYS_renameat2:
    case KLEE_SYS_mkdir:
    case KLEE_SYS_mkdirat:
    case KLEE_SYS_symlink:
    case KLEE_SYS_symlinkat:
    case KLEE_SYS_link:
    case KLEE_SYS_linkat:
    case KLEE_SYS_chmod:
    case KLEE_SYS_fchmodat:
    case KLEE_SYS_chown:
    case KLEE_SYS_lchown:
    case KLEE_SYS_fchownat:
    case KLEE_SYS_truncate:
    case KLEE_SYS_creat:
    case KLEE_SYS_mknod:
    case KLEE_SYS_mknodat:
    case KLEE_SYS_utimensat:
    case KLEE_SYS_utimes:
    case KLEE_SYS_utime:
    case KLEE_SYS_futimesat:
    case KLEE_SYS_setxattr:
    case KLEE_SYS_lsetxattr:
    case KLEE_SYS_removexattr:
    case KLEE_SYS_lremovexattr:
    case KLEE_SYS_fchmodat2:
        return true;
    default:
        return false;
    }
}

bool klee_readonly_check_path(const KleeMountTable *mt, const char *guest_path,
                               int syscall_nr)
{
    if (!klee_mount_table_is_readonly(mt, guest_path))
        return false;

    if (is_write_syscall(syscall_nr)) {
        KLEE_DEBUG("readonly: blocking %d on %s", syscall_nr, guest_path);
        return true;
    }

    return false;
}

/*
 * Decide whether an open() on an emulated read-only mount must fail with
 * EROFS.  The host mount is writable, so anything let through here will
 * really write; mirror the kernel's own ordering of checks for a genuine
 * MS_RDONLY mount:
 *
 *  - O_PATH never needs write access.
 *  - O_TMPFILE always creates a file, so it is always refused.
 *  - Special files (char/block devices, fifos, sockets) are exempt from the
 *    read-only check in do_dentry_open(), and may_open() clears O_TRUNC for
 *    them: writing to /dev/null under --ro-bind / / is fine, as with bwrap.
 *  - Directories get EISDIR or EACCES from the kernel before any write check.
 *  - O_CREAT only needs write access when the file does not exist yet, and
 *    opening a missing file without O_CREAT is ENOENT, not EROFS.
 */
bool klee_readonly_check_open(const KleeMountTable *mt, const char *guest_path,
                               const char *host_path, int flags)
{
    if (flags & O_PATH)
        return false;

    if (!klee_mount_table_is_readonly(mt, guest_path))
        return false;

    int accmode = flags & O_ACCMODE;
    bool wants_write = accmode == O_WRONLY || accmode == O_RDWR;

    if ((flags & O_TMPFILE) == O_TMPFILE) {
        KLEE_DEBUG("readonly: blocking open(O_TMPFILE) in %s", guest_path);
        return true;
    }

    struct stat st;
    if (host_path && host_path[0] && stat(host_path, &st) == 0) {
        if (S_ISDIR(st.st_mode))
            return false;   /* kernel: EISDIR / EACCES, never a write */
        if (!S_ISREG(st.st_mode))
            return false;   /* special file: writes bypass MNT_READONLY */
        if (wants_write || (flags & O_TRUNC)) {
            KLEE_DEBUG("readonly: blocking open(write) on %s", guest_path);
            return true;
        }
        return false;       /* O_CREAT/O_APPEND on an existing file, read-only */
    }

    if (host_path && host_path[0] && (errno == ENOENT || errno == ENOTDIR)) {
        if (flags & O_CREAT) {
            KLEE_DEBUG("readonly: blocking open(create) on %s", guest_path);
            return true;
        }
        return false;       /* kernel: ENOENT */
    }

    /* No host path or stat failed for another reason: stay conservative. */
    if (wants_write || (flags & (O_CREAT | O_TRUNC))) {
        KLEE_DEBUG("readonly: blocking open(write/create/trunc) on %s",
                   guest_path);
        return true;
    }

    return false;
}
