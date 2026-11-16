#ifndef GINGERVM_GUEST_SIGPROCMASK_PTRACE_H
#define GINGERVM_GUEST_SIGPROCMASK_PTRACE_H

#include <errno.h>
#include <stdint.h>
#include <sys/ptrace.h>
#include <sys/types.h>

/* Linux UAPI values, available since Linux 3.11; some older libc headers omit them. */
#ifndef PTRACE_GETSIGMASK
#define PTRACE_GETSIGMASK 0x420a
#endif
#ifndef PTRACE_SETSIGMASK
#define PTRACE_SETSIGMASK 0x420b
#endif

#define GUEST_KERNEL_SIGSET_BYTES ((uintptr_t)sizeof(uint64_t))

static inline int guest_sigmask_ptrace_get(pid_t pid, uint64_t *mask) {
    if (!mask) {
        errno = EINVAL;
        return -1;
    }
    errno = 0;
    long rc = ptrace(PTRACE_GETSIGMASK, pid,
                     (void *)GUEST_KERNEL_SIGSET_BYTES, mask);
    if (rc != 0) {
        if (rc == -1 && errno == 0) errno = EIO;
        return -1;
    }
    return 0;
}

static inline int guest_sigmask_ptrace_set(pid_t pid, uint64_t mask) {
    errno = 0;
    long rc = ptrace(PTRACE_SETSIGMASK, pid,
                     (void *)GUEST_KERNEL_SIGSET_BYTES, &mask);
    if (rc != 0) {
        if (rc == -1 && errno == 0) errno = EIO;
        return -1;
    }
    return 0;
}

#endif
