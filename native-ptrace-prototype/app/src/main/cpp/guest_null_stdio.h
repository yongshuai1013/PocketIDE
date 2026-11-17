#ifndef GINGERVM_GUEST_NULL_STDIO_H
#define GINGERVM_GUEST_NULL_STDIO_H

#include <errno.h>
#include <stdint.h>
#include <string.h>

/* Android 2.3.7/API10 init.c util.c creates this transient guest node with
 * mknod(path, S_IFCHR | 0600, (1 << 8) | 3). These are ARM32 guest ABI
 * values; they are never used to create a host filesystem device. */
#define GUEST_NULL_STDIO_PATH "/dev/__null__"
#define GUEST_NULL_STDIO_MODE 020600u
#define GUEST_NULL_STDIO_DEVICE 0x00000103u
#define GUEST_ARM32_O_ACCMODE 00000003u
#define GUEST_ARM32_O_RDWR 00000002u
#define GUEST_ARM32_O_LARGEFILE 0400000u
#define GUEST_NULL_STDIO_FD_MASK 0x07u

enum guest_null_stdio_actor {
    GUEST_NULL_STDIO_ACTOR_DENIED = 0,
    GUEST_NULL_STDIO_ACTOR_INIT = 1,
    GUEST_NULL_STDIO_ACTOR_UEVENTD = 2
};

/* The supervisor derives these facts from the committed guest exec event (or
 * its separately verified initial /init launch), the guest PID/parent table,
 * virtual uid, ARM ELF validation, and an already admitted app-private guest
 * root (staged guest tree or packaged native payload). */
struct guest_null_stdio_identity {
    int32_t guest_pid;
    int32_t guest_parent_pid;
    uint32_t guest_euid;
    const char *executable;
    int exec_image_committed;
    int arm32_elf_valid;
    int backing_path_approved;
};

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

static inline enum guest_null_stdio_actor guest_null_stdio_actor_for_identity(
        const struct guest_null_stdio_identity *identity) {
    if (!identity || !identity->executable || identity->guest_euid != 0u ||
        !identity->exec_image_committed || !identity->arm32_elf_valid ||
        !identity->backing_path_approved)
        return GUEST_NULL_STDIO_ACTOR_DENIED;
    if (identity->guest_pid == 1 && identity->guest_parent_pid == 0 &&
        strcmp(identity->executable, "/init") == 0)
        return GUEST_NULL_STDIO_ACTOR_INIT;
    if (identity->guest_pid > 1 && identity->guest_parent_pid == 1 &&
        strcmp(identity->executable, "/sbin/ueventd") == 0)
        return GUEST_NULL_STDIO_ACTOR_UEVENTD;
    return GUEST_NULL_STDIO_ACTOR_DENIED;
}

static inline const char *guest_null_stdio_actor_name(
        enum guest_null_stdio_actor actor) {
    switch (actor) {
        case GUEST_NULL_STDIO_ACTOR_INIT: return "init";
        case GUEST_NULL_STDIO_ACTOR_UEVENTD: return "ueventd";
        default: return "denied";
    }
}

static inline int guest_null_stdio_mknod(
        struct guest_null_stdio_runtime *runtime,
        const struct guest_null_stdio_identity *identity,
        const char *path, uint32_t mode, uint32_t device) {
    if (!runtime) return -EINVAL;
    runtime->mknod_attempts++;
    if (!path || strcmp(path, GUEST_NULL_STDIO_PATH) != 0) {
        runtime->mknod_rejected++;
        return -EOPNOTSUPP;
    }
    enum guest_null_stdio_actor actor =
        guest_null_stdio_actor_for_identity(identity);
    if (actor == GUEST_NULL_STDIO_ACTOR_DENIED) {
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

/* The API10 bionic ARM open wrapper may add O_LARGEFILE. This minimal startup
 * backend supports one outstanding open description; other device semantics
 * remain fail-closed rather than sharing an incomplete FD model. */
static inline int guest_null_stdio_open_validate(
        struct guest_null_stdio_runtime *runtime,
        const struct guest_null_stdio_identity *identity,
        const char *path, uint32_t flags) {
    if (!runtime) return -EINVAL;
    runtime->open_attempts++;
    int result = 0;
    if (!path || strcmp(path, GUEST_NULL_STDIO_PATH) != 0)
        result = -EOPNOTSUPP;
    else if (guest_null_stdio_actor_for_identity(identity) ==
             GUEST_NULL_STDIO_ACTOR_DENIED)
        result = -EPERM;
    else if (!runtime->node_present || runtime->unlinked)
        result = -ENOENT;
    else if ((flags & GUEST_ARM32_O_ACCMODE) != GUEST_ARM32_O_RDWR ||
             (flags & ~(GUEST_ARM32_O_ACCMODE | GUEST_ARM32_O_LARGEFILE)) != 0u)
        result = -EINVAL;
    else if (runtime->source_fd_open)
        result = -EBUSY;
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
    if (runtime->source_fd_open) {
        runtime->open_failed++;
        return -EBUSY;
    }
    runtime->source_fd = virtual_fd;
    runtime->source_fd_open = 1;
    runtime->open_succeeded++;
    return virtual_fd;
}

/* API10 unlinks even after open failure. An opened virtual FD remains valid
 * because its semantics live in the guest descriptor table, not the node name. */
static inline int guest_null_stdio_unlink(
        struct guest_null_stdio_runtime *runtime,
        const struct guest_null_stdio_identity *identity,
        const char *path) {
    if (!runtime) return -EINVAL;
    runtime->unlink_attempts++;
    if (!path || strcmp(path, GUEST_NULL_STDIO_PATH) != 0) return -EOPNOTSUPP;
    if (guest_null_stdio_actor_for_identity(identity) ==
        GUEST_NULL_STDIO_ACTOR_DENIED)
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
 * handles it. The descriptor source must be validated against guest state. */
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

/* A successful ordinary guest dup2 replaces the target descriptor. Clear a
 * stale null-device alias only after success; null-backed sources retain it. */
static inline int guest_null_stdio_note_dup2_result(
        uint8_t *stdio_mask, int target_fd, int source_is_modeled_null,
        int32_t result) {
    if (!stdio_mask || result < 0 || target_fd < 0 || target_fd > 2 ||
        source_is_modeled_null)
        return 0;
    uint8_t bit = (uint8_t)(1u << (unsigned)target_fd);
    int changed = (*stdio_mask & bit) != 0u;
    *stdio_mask &= (uint8_t)~bit;
    return changed;
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
