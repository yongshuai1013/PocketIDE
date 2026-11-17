#ifndef GINGERVM_GUEST_KMSG_VIRTUAL_H
#define GINGERVM_GUEST_KMSG_VIRTUAL_H

#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <string.h>

#define GUEST_KMSG_PATH "/dev/__kmsg__"
#define GUEST_KMSG_MODE 0020600u
#define GUEST_KMSG_DEVICE 0x0000010bu /* API10 ARM32 makedev(1, 11) */
#define GUEST_KMSG_O_ACCMODE 00000003u
#define GUEST_KMSG_O_WRONLY 00000001u
#define GUEST_KMSG_O_LARGEFILE 000400000u
#define GUEST_KMSG_F_SETFD 2
#define GUEST_KMSG_FD_CLOEXEC 1

/* State for API10 init's optional kmsg logger. This represents only guest
 * namespace/FD state; it must never create, open, unlink, or write a host node. */
struct guest_kmsg_runtime {
    int node_present;
    int unlinked;
    int fd;
    int fd_open;
    int fd_cloexec;
    uint64_t mknod_attempts;
    uint64_t mknod_accepted;
    uint64_t mknod_rejected;
    uint64_t open_attempts;
    uint64_t open_succeeded;
    uint64_t open_failed;
    uint64_t fcntl_setfd_attempts;
    uint64_t fcntl_setfd_succeeded;
    uint64_t unlink_attempts;
    uint64_t unlink_succeeded;
    uint64_t write_calls;
    uint64_t write_bytes;
    uint64_t close_calls;
    uint64_t close_on_exec_calls;
};

static inline void guest_kmsg_runtime_init(struct guest_kmsg_runtime *runtime) {
    if (!runtime) return;
    memset(runtime, 0, sizeof(*runtime));
    runtime->fd = -1;
}

static inline int guest_kmsg_is_api10_init(int guest_pid,
                                            const char *executable,
                                            uint32_t euid) {
    return guest_pid == 1 && executable && strcmp(executable, "/init") == 0 &&
           euid == 0u;
}

static inline int guest_kmsg_mknod(struct guest_kmsg_runtime *runtime,
                                   int guest_pid, const char *executable,
                                   uint32_t euid, const char *path,
                                   uint32_t mode, uint32_t device) {
    if (!runtime) return -EINVAL;
    runtime->mknod_attempts++;
    if (!guest_kmsg_is_api10_init(guest_pid, executable, euid)) {
        runtime->mknod_rejected++;
        return -EPERM;
    }
    if (!path || strcmp(path, GUEST_KMSG_PATH) != 0) {
        runtime->mknod_rejected++;
        return -EOPNOTSUPP;
    }
    if (mode != GUEST_KMSG_MODE || device != GUEST_KMSG_DEVICE) {
        runtime->mknod_rejected++;
        return -EINVAL;
    }
    if (runtime->node_present) {
        runtime->mknod_rejected++;
        return -EEXIST;
    }
    runtime->node_present = 1;
    runtime->unlinked = 0;
    runtime->mknod_accepted++;
    return 0;
}

static inline int guest_kmsg_open_validate(struct guest_kmsg_runtime *runtime,
                                           int guest_pid,
                                           const char *executable,
                                           uint32_t euid, const char *path,
                                           uint32_t flags) {
    if (!runtime) return -EINVAL;
    runtime->open_attempts++;
    if (!guest_kmsg_is_api10_init(guest_pid, executable, euid)) {
        runtime->open_failed++;
        return -EPERM;
    }
    if (!path || strcmp(path, GUEST_KMSG_PATH) != 0) {
        runtime->open_failed++;
        return -EOPNOTSUPP;
    }
    if (!runtime->node_present || runtime->unlinked) {
        runtime->open_failed++;
        return -ENOENT;
    }
    if ((flags & GUEST_KMSG_O_ACCMODE) != GUEST_KMSG_O_WRONLY ||
        (flags & ~(GUEST_KMSG_O_ACCMODE | GUEST_KMSG_O_LARGEFILE)) != 0u) {
        runtime->open_failed++;
        return -EINVAL;
    }
    if (runtime->fd_open) {
        runtime->open_failed++;
        return -EBUSY;
    }
    return 0;
}

static inline int guest_kmsg_open_complete(struct guest_kmsg_runtime *runtime,
                                           int fd) {
    if (!runtime) return -EINVAL;
    if (fd < 0) {
        runtime->open_failed++;
        return fd;
    }
    if (!runtime->node_present || runtime->unlinked || runtime->fd_open) {
        runtime->open_failed++;
        return -ENOENT;
    }
    runtime->fd = fd;
    runtime->fd_open = 1;
    runtime->fd_cloexec = 0;
    runtime->open_succeeded++;
    return fd;
}

static inline int guest_kmsg_unlink(struct guest_kmsg_runtime *runtime,
                                    int guest_pid, const char *executable,
                                    uint32_t euid, const char *path) {
    if (!runtime) return -EINVAL;
    runtime->unlink_attempts++;
    if (!guest_kmsg_is_api10_init(guest_pid, executable, euid))
        return -EPERM;
    if (!path || strcmp(path, GUEST_KMSG_PATH) != 0)
        return -EOPNOTSUPP;
    if (!runtime->node_present || runtime->unlinked) return -ENOENT;
    runtime->node_present = 0;
    runtime->unlinked = 1;
    runtime->unlink_succeeded++;
    return 0;
}

static inline void guest_kmsg_note_fcntl(struct guest_kmsg_runtime *runtime,
                                         int fd, int command, int argument,
                                         int result) {
    if (!runtime || !runtime->fd_open || fd != runtime->fd ||
        command != GUEST_KMSG_F_SETFD) return;
    runtime->fcntl_setfd_attempts++;
    if (result == 0) {
        runtime->fd_cloexec = (argument & GUEST_KMSG_FD_CLOEXEC) != 0;
        runtime->fcntl_setfd_succeeded++;
    }
}

static inline void guest_kmsg_note_write(struct guest_kmsg_runtime *runtime,
                                         int fd, int result) {
    if (!runtime || !runtime->fd_open || fd != runtime->fd || result < 0)
        return;
    runtime->write_calls++;
    runtime->write_bytes += (uint64_t)(unsigned)result;
}

/* Call after virtual close/CLOEXEC processing, and only mark the open file
 * description closed once no guest descriptor table still references it. */
static inline void guest_kmsg_note_fd_closed(struct guest_kmsg_runtime *runtime,
                                             int fd, int result,
                                             int still_referenced,
                                             int due_to_exec) {
    if (!runtime || !runtime->fd_open || fd != runtime->fd || result != 0 ||
        still_referenced) return;
    runtime->fd_open = 0;
    runtime->fd = -1;
    runtime->fd_cloexec = 0;
    if (due_to_exec) runtime->close_on_exec_calls++;
    else runtime->close_calls++;
}

#endif
