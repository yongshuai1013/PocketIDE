#ifndef GINGERVM_GUEST_NULL_STDIO_H
#define GINGERVM_GUEST_NULL_STDIO_H

#include <errno.h>
#include <stdint.h>
#include <string.h>

/* Android 2.3.7/API10 init.c util.c creates this transient guest node with
 * mknod(path, S_IFCHR | 0600, (1 << 8) | 3).  These values are ARM32 guest
 * ABI values; they are not used to create a host filesystem device. */
#define GUEST_NULL_STDIO_PATH "/dev/__null__"
#define GUEST_NULL_STDIO_MODE 020600u
#define GUEST_NULL_STDIO_DEVICE 0x00000103u
#define GUEST_ARM32_O_ACCMODE 00000003u
#define GUEST_ARM32_O_RDWR 00000002u
#define GUEST_ARM32_O_LARGEFILE 0400000u
#define GUEST_NULL_STDIO_FD_MASK 0x07u

struct guest_null_stdio_runtime {
    int node_present;
    int unlinked;
    int source_fd;
    int source_fd_open;
    uint32_t mknod_attempts;
    uint32_t mknod_accepted;
    uint32_t mknod_rejected;
    uint32_t open_attempts;
    uint32_t open_succeeded;
    uint32_t open_failed;
    uint32_t unlink_attempts;
    uint32_t unlink_succeeded;
    uint32_t dup2_attempts;
    uint32_t dup2_succeeded;
    uint32_t source_fd_closes;
    uint32_t stdio_reads;
    uint32_t stdio_writes;
    uint32_t stdio_closes;
    uint32_t stdio_mask_last;
};

static inline void guest_null_stdio_runtime_init(
        struct guest_null_stdio_runtime *runtime) {
    if (!runtime) return;
    memset(runtime, 0, sizeof(*runtime));
    runtime->source_fd = -1;
}

static inline int guest_null_stdio_is_original_init(
        int guest_pid, const char *executable, uint32_t guest_euid) {
    return guest_pid == 1 && executable && strcmp(executable, "/init") == 0 &&
           guest_euid == 0u;
}

static inline int guest_null_stdio_mknod(
        struct guest_null_stdio_runtime *runtime, int guest_pid,
        const char *executable, uint32_t guest_euid, const char *path,
        uint32_t mode, uint32_t device) {
    if (!runtime) return -EINVAL;
    runtime->mknod_attempts++;
    if (!path || strcmp(path, GUEST_NULL_STDIO_PATH) != 0) {
        runtime->mknod_rejected++;
        return -EOPNOTSUPP;
    }
    if (!guest_null_stdio_is_original_init(guest_pid, executable, guest_euid)) {
        runtime->mknod_rejected++;
        return -EPERM;
    }
    if (mode != GUEST_NULL_STDIO_MODE || device != GUEST_NULL_STDIO_DEVICE) {
        runtime->mknod_rejected++;
        return -EINVAL;
    }
    if (runtime->node_present || runtime->source_fd_open) {
        runtime->mknod_rejected++;
        return -EEXIST;
    }
    runtime->node_present = 1;
    runtime->unlinked = 0;
    runtime->mknod_accepted++;
    return 0;
}

/* The API10 bionic ARM open wrapper may add its ABI O_LARGEFILE bit.  No
 * create/truncate/append or host open flags are accepted for this virtual node. */
static inline int guest_null_stdio_open_validate(
        struct guest_null_stdio_runtime *runtime, int guest_pid,
        const char *executable, uint32_t guest_euid, const char *path,
        uint32_t flags) {
    if (!runtime) return -EINVAL;
    runtime->open_attempts++;
    int result = 0;
    if (!path || strcmp(path, GUEST_NULL_STDIO_PATH) != 0)
        result = -EOPNOTSUPP;
    else if (!guest_null_stdio_is_original_init(guest_pid, executable, guest_euid))
        result = -EPERM;
    else if (!runtime->node_present || runtime->unlinked)
        result = -ENOENT;
    else if ((flags & GUEST_ARM32_O_ACCMODE) != GUEST_ARM32_O_RDWR ||
             (flags & ~(GUEST_ARM32_O_ACCMODE | GUEST_ARM32_O_LARGEFILE)) != 0u)
        result = -EINVAL;
    if (result != 0) runtime->open_failed++;
    return result;
}

static inline int guest_null_stdio_open_complete(
        struct guest_null_stdio_runtime *runtime, int virtual_fd) {
    if (!runtime) return -EINVAL;
    if (virtual_fd < 0) {
        runtime->open_failed++;
        return virtual_fd;
    }
    if (!runtime->node_present || runtime->unlinked) {
        runtime->open_failed++;
        return -ENOENT;
    }
    runtime->source_fd = virtual_fd;
    runtime->source_fd_open = 1;
    runtime->open_succeeded++;
    return virtual_fd;
}

/* The source unlinks even when open() failed.  An already opened virtual FD
 * remains valid because its semantics live in the FD table, not this name. */
static inline int guest_null_stdio_unlink(
        struct guest_null_stdio_runtime *runtime, int guest_pid,
        const char *executable, uint32_t guest_euid, const char *path) {
    if (!runtime) return -EINVAL;
    runtime->unlink_attempts++;
    if (!path || strcmp(path, GUEST_NULL_STDIO_PATH) != 0) return -EOPNOTSUPP;
    if (!guest_null_stdio_is_original_init(guest_pid, executable, guest_euid))
        return -EPERM;
    if (!runtime->node_present || runtime->unlinked) return -ENOENT;
    runtime->node_present = 0;
    runtime->unlinked = 1;
    runtime->unlink_succeeded++;
    return 0;
}

static inline void guest_null_stdio_source_fd_closed(
        struct guest_null_stdio_runtime *runtime, int fd) {
    if (!runtime || !runtime->source_fd_open || runtime->source_fd != fd) return;
    runtime->source_fd_open = 0;
    runtime->source_fd_closes++;
}

static inline int guest_null_stdio_fd_is_null(
        uint8_t stdio_mask, int fd, int validated_virtual_null_source) {
    if (validated_virtual_null_source) return 1;
    return fd >= 0 && fd <= 2 &&
           (stdio_mask & (uint8_t)(1u << (unsigned)fd)) != 0u;
}

/* Returns 1 when the supervisor must emulate dup2, 0 when another policy
 * handles the call.  The descriptor source is validated against the virtual
 * guest FD table before this helper is called. */
static inline int guest_null_stdio_dup2(
        struct guest_null_stdio_runtime *runtime, uint8_t *stdio_mask,
        int old_fd, int new_fd, int validated_virtual_null_source,
        int *result) {
    if (!runtime || !stdio_mask || !result) return 0;
    if (!guest_null_stdio_fd_is_null(*stdio_mask, old_fd,
                                     validated_virtual_null_source)) return 0;
    runtime->dup2_attempts++;
    if (old_fd == new_fd) {
        *result = new_fd;
        runtime->dup2_succeeded++;
        return 1;
    }
    if (new_fd < 0 || new_fd > 2) {
        *result = -EOPNOTSUPP;
        return 1;
    }
    *stdio_mask |= (uint8_t)(1u << (unsigned)new_fd);
    runtime->stdio_mask_last = *stdio_mask;
    runtime->dup2_succeeded++;
    *result = new_fd;
    return 1;
}

static inline int guest_null_stdio_close(
        struct guest_null_stdio_runtime *runtime, uint8_t *stdio_mask,
        int fd, int *result) {
    if (!runtime || !stdio_mask || !result || fd < 0 || fd > 2 ||
        (*stdio_mask & (uint8_t)(1u << (unsigned)fd)) == 0u) return 0;
    *stdio_mask &= (uint8_t)~(1u << (unsigned)fd);
    runtime->stdio_mask_last = *stdio_mask;
    runtime->stdio_closes++;
    *result = 0;
    return 1;
}

static inline int guest_null_stdio_io(
        struct guest_null_stdio_runtime *runtime, uint8_t stdio_mask,
        int fd, int is_write, uint32_t length, int32_t *result) {
    if (!runtime || !result || fd < 0 || fd > 2 ||
        (stdio_mask & (uint8_t)(1u << (unsigned)fd)) == 0u) return 0;
    if (length > (uint32_t)INT32_MAX) {
        *result = -EINVAL;
    } else if (is_write) {
        *result = (int32_t)length;
        runtime->stdio_writes++;
    } else {
        *result = 0;
        runtime->stdio_reads++;
    }
    runtime->stdio_mask_last = stdio_mask;
    return 1;
}

#endif
