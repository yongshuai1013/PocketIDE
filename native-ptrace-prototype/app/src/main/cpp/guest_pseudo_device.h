#ifndef GINGERVM_GUEST_PSEUDO_DEVICE_H
#define GINGERVM_GUEST_PSEUDO_DEVICE_H

#include "guest_socket_virtual.h"

#include <errno.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/stat.h>

#define GUEST_ARM32_STAT64_BYTES 96u
#define GUEST_MODE_IFCHR 0020000u

struct guest_pseudo_device_metadata {
    enum virtual_fd_kind kind;
    uint32_t mode;
    uint32_t major;
    uint32_t minor;
};

static inline int guest_pseudo_device_metadata_for_path(
        const char *path, struct guest_pseudo_device_metadata *metadata) {
    if (!path || !metadata) return -EINVAL;
    struct guest_pseudo_device_metadata value = {0};
    value.mode = GUEST_MODE_IFCHR | 0666u;
    value.major = 1u;
    if (strcmp(path, "/dev/null") == 0) {
        value.kind = VIRTUAL_FD_DEV_NULL; value.minor = 3u;
    } else if (strcmp(path, "/dev/__null__") == 0) {
        value.kind = VIRTUAL_FD_DEV_NULL; value.minor = 3u; value.mode = GUEST_MODE_IFCHR | 0600u;
    } else if (strcmp(path, "/dev/zero") == 0) {
        value.kind = VIRTUAL_FD_DEV_ZERO; value.minor = 5u;
    } else if (strcmp(path, "/dev/full") == 0) {
        value.kind = VIRTUAL_FD_DEV_FULL; value.minor = 7u;
    } else if (strcmp(path, "/dev/random") == 0) {
        value.kind = VIRTUAL_FD_DEV_RANDOM; value.minor = 8u;
    } else if (strcmp(path, "/dev/urandom") == 0) {
        value.kind = VIRTUAL_FD_DEV_RANDOM; value.minor = 9u;
    } else if (strcmp(path, "/dev/__kmsg__") == 0) {
        value.kind = VIRTUAL_FD_DEV_KMSG; value.minor = 11u; value.mode = GUEST_MODE_IFCHR | 0600u;
    } else {
        return 0;
    }
    *metadata = value;
    return 1;
}

static inline int guest_pseudo_device_kind_for_path(const char *path) {
    struct guest_pseudo_device_metadata metadata;
    int result = guest_pseudo_device_metadata_for_path(path, &metadata);
    return result > 0 ? (int)metadata.kind : result;
}

static inline int guest_pseudo_device_read(enum virtual_fd_kind kind,
                                           unsigned char *out,
                                           size_t length,
                                           size_t capacity) {
    if (length == 0) return 0;
    if (kind == VIRTUAL_FD_DEV_NULL) return 0;
    if (kind == VIRTUAL_FD_DEV_KMSG) return -EAGAIN;
    if (kind == VIRTUAL_FD_DEV_RANDOM) return -EOPNOTSUPP;
    if (kind != VIRTUAL_FD_DEV_ZERO && kind != VIRTUAL_FD_DEV_FULL)
        return -EOPNOTSUPP;
    if (!out || length > capacity) return -EFAULT;
    if (length > (size_t)INT32_MAX) return -EINVAL;
    memset(out, 0, length);
    return (int)length;
}

static inline int guest_pseudo_device_write(enum virtual_fd_kind kind,
                                            size_t length) {
    if (length > (size_t)INT32_MAX) return -EINVAL;
    if (kind == VIRTUAL_FD_DEV_FULL) return -ENOSPC;
    if (kind == VIRTUAL_FD_DEV_NULL || kind == VIRTUAL_FD_DEV_ZERO ||
        kind == VIRTUAL_FD_DEV_KMSG)
        return (int)length;
    return -EOPNOTSUPP;
}

static inline void guest_pseudo_store32(unsigned char *out, size_t offset,
                                        uint32_t value) {
    out[offset] = (unsigned char)(value & 0xffu);
    out[offset + 1u] = (unsigned char)((value >> 8) & 0xffu);
    out[offset + 2u] = (unsigned char)((value >> 16) & 0xffu);
    out[offset + 3u] = (unsigned char)((value >> 24) & 0xffu);
}

static inline void guest_pseudo_store64(unsigned char *out, size_t offset,
                                        uint64_t value) {
    guest_pseudo_store32(out, offset, (uint32_t)value);
    guest_pseudo_store32(out, offset + 4u, (uint32_t)(value >> 32));
}

static inline uint64_t guest_pseudo_makedev(uint32_t major, uint32_t minor) {
    return ((uint64_t)(major & 0xfffu) << 8) | (uint64_t)(minor & 0xffu) |
           ((uint64_t)(minor & ~0xffu) << 12);
}

/* ARM32 API10 kernel stat64 layout from bionic/libc/kernel/arch-arm/asm/stat.h. */
static inline int guest_pseudo_device_stat64(uint32_t mode, uint32_t major,
                                             uint32_t minor,
                                             unsigned char out[GUEST_ARM32_STAT64_BYTES]) {
    if (!out) return -EFAULT;
    memset(out, 0, GUEST_ARM32_STAT64_BYTES);
    guest_pseudo_store32(out, 16u, mode);
    guest_pseudo_store32(out, 20u, 1u); /* one guest node */
    guest_pseudo_store32(out, 24u, 0u); /* guest root uid */
    guest_pseudo_store32(out, 28u, 0u); /* guest root gid */
    guest_pseudo_store64(out, 32u, guest_pseudo_makedev(major, minor));
    return 0;
}

static inline int guest_pseudo_device_stat64_for_path(
        const char *path, unsigned char out[GUEST_ARM32_STAT64_BYTES]) {
    struct guest_pseudo_device_metadata metadata;
    int result = guest_pseudo_device_metadata_for_path(path, &metadata);
    if (result <= 0) return result;
    int rc = guest_pseudo_device_stat64(metadata.mode, metadata.major,
                                        metadata.minor, out);
    return rc == 0 ? 1 : rc;
}

#endif
