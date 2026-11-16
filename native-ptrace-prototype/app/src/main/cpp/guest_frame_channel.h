#ifndef GINGERVM_GUEST_FRAME_CHANNEL_H
#define GINGERVM_GUEST_FRAME_CHANNEL_H

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#ifndef O_DIRECTORY
#define O_DIRECTORY 00200000
#endif
#ifndef O_NOFOLLOW
#define O_NOFOLLOW 00400000
#endif
#ifndef O_CLOEXEC
#define O_CLOEXEC 02000000
#endif
#ifndef O_PATH
#define O_PATH 010000000
#endif
#ifndef AT_SYMLINK_NOFOLLOW
#define AT_SYMLINK_NOFOLLOW 0x100
#endif

#define GUEST_FRAME_CHANNEL_DIRECTORY "gingervm-display"
#define GUEST_FRAME_CHANNEL_FILE "latest.gvmf"
#define GUEST_FRAME_CHANNEL_TEMP_FILE "latest.gvmf.tmp"
#define GUEST_FRAME_CHANNEL_ENV "GINGERVM_GUEST_FRAME_DIR"
#define GUEST_FRAME_CHANNEL_MAX_PATH_COMPONENTS 32u
#define GUEST_FRAME_PROTOCOL_MAGIC "GVMF"
#define GUEST_FRAME_PROTOCOL_VERSION 1u
#define GUEST_FRAME_PROTOCOL_HEADER_BYTES 64u
#define GUEST_FRAME_SOURCE_GUEST_FRAMEBUFFER 1u
#define GUEST_FRAME_SOURCE_TEST_ONLY 2u
#define GUEST_FRAME_MAX_WIDTH 4096u
#define GUEST_FRAME_MAX_HEIGHT 4096u
#define GUEST_FRAME_MAX_PIXELS 2097152u
#define GUEST_FRAME_MAX_STRIDE 65536u
#define GUEST_FRAME_MAX_PAYLOAD_BYTES 8388608u

enum guest_frame_channel_validation_reason {
    GUEST_FRAME_CHANNEL_VALID = 0,
    GUEST_FRAME_CHANNEL_INVALID_ARGUMENT,
    GUEST_FRAME_CHANNEL_PATH_TOO_LONG,
    GUEST_FRAME_CHANNEL_NOT_EXACT_SIBLING,
    GUEST_FRAME_CHANNEL_OPEN_FAILED,
    GUEST_FRAME_CHANNEL_FSTAT_FAILED,
    GUEST_FRAME_CHANNEL_NOT_DIRECTORY,
    GUEST_FRAME_CHANNEL_WRONG_OWNER,
    GUEST_FRAME_CHANNEL_NOT_PRIVATE,
    GUEST_FRAME_CHANNEL_PARENT_UNSAFE_WRITABLE,
    GUEST_FRAME_CHANNEL_GUEST_ROOT_NOT_PRIVATE,
    GUEST_FRAME_CHANNEL_PATH_COMPONENT_SYMLINK,
    GUEST_FRAME_CHANNEL_PATH_COMPONENT_LIMIT
};

struct guest_frame_channel_component_audit {
    char name[NAME_MAX + 1u];
    uid_t owner;
    gid_t group;
    mode_t mode;
    uint64_t device;
    uint64_t inode;
    int has_stat;
    int opened;
    int symlink;
    int error_number;
};

struct guest_frame_channel_path_audit {
    char path[PATH_MAX];
    unsigned int component_count;
    int error_number;
    struct guest_frame_channel_component_audit components[GUEST_FRAME_CHANNEL_MAX_PATH_COMPONENTS];
};

enum guest_frame_channel_validation_scope {
    GUEST_FRAME_CHANNEL_SCOPE_NONE = 0,
    GUEST_FRAME_CHANNEL_SCOPE_ROOT_PARENT,
    GUEST_FRAME_CHANNEL_SCOPE_CHANNEL_PARENT,
    GUEST_FRAME_CHANNEL_SCOPE_PARENT_IDENTITY,
    GUEST_FRAME_CHANNEL_SCOPE_PARENT_OWNER,
    GUEST_FRAME_CHANNEL_SCOPE_PARENT_MODE,
    GUEST_FRAME_CHANNEL_SCOPE_GUEST_ROOT_LEAF,
    GUEST_FRAME_CHANNEL_SCOPE_CHANNEL_LEAF
};

struct guest_frame_channel_validation_detail {
    enum guest_frame_channel_validation_reason reason;
    enum guest_frame_channel_validation_scope scope;
    int error_number;
    uid_t expected_owner;
    uid_t actual_owner;
    mode_t actual_mode;
    int has_stat;
    char expected_path[PATH_MAX];
    char guest_root_path[PATH_MAX];
    char channel_path[PATH_MAX];
    struct guest_frame_channel_path_audit root_parent_audit;
    struct guest_frame_channel_path_audit channel_parent_audit;
    uid_t root_owner;
    gid_t root_group;
    mode_t root_mode;
    uint64_t root_device;
    uint64_t root_inode;
    int root_has_stat;
    int root_is_symlink;
    uid_t channel_owner;
    gid_t channel_group;
    mode_t channel_mode;
    uint64_t channel_device;
    uint64_t channel_inode;
    int channel_has_stat;
    int channel_is_symlink;
};

static inline const char *guest_frame_channel_validation_reason_name(
        enum guest_frame_channel_validation_reason reason) {
    switch (reason) {
        case GUEST_FRAME_CHANNEL_VALID: return "valid";
        case GUEST_FRAME_CHANNEL_INVALID_ARGUMENT: return "invalid-argument";
        case GUEST_FRAME_CHANNEL_PATH_TOO_LONG: return "path-too-long";
        case GUEST_FRAME_CHANNEL_NOT_EXACT_SIBLING: return "not-exact-guest-root-sibling";
        case GUEST_FRAME_CHANNEL_OPEN_FAILED: return "open-no-follow-failed";
        case GUEST_FRAME_CHANNEL_FSTAT_FAILED: return "fstat-failed";
        case GUEST_FRAME_CHANNEL_NOT_DIRECTORY: return "not-directory";
        case GUEST_FRAME_CHANNEL_WRONG_OWNER: return "wrong-owner";
        case GUEST_FRAME_CHANNEL_NOT_PRIVATE: return "leaf-group-or-other-permission-present";
        case GUEST_FRAME_CHANNEL_PARENT_UNSAFE_WRITABLE: return "app-parent-writable-by-untrusted-group-or-world";
        case GUEST_FRAME_CHANNEL_GUEST_ROOT_NOT_PRIVATE: return "guest-root-leaf-not-private";
        case GUEST_FRAME_CHANNEL_PATH_COMPONENT_SYMLINK: return "symlink-path-component-rejected";
        case GUEST_FRAME_CHANNEL_PATH_COMPONENT_LIMIT: return "path-component-audit-limit-exceeded";
        default: return "unknown-validation-reason";
    }
}

typedef struct guest_frame_bitfield {
    uint8_t offset;
    uint8_t length;
    uint8_t msb_right;
} guest_frame_bitfield;

typedef struct guest_frame_packet {
    uint32_t source;
    uint32_t width;
    uint32_t height;
    uint32_t stride;
    uint8_t bits_per_pixel;
    guest_frame_bitfield red;
    guest_frame_bitfield green;
    guest_frame_bitfield blue;
    guest_frame_bitfield transparency;
    uint64_t sequence;
    const unsigned char *pixels;
} guest_frame_packet;

static inline void guest_frame_put_u16le(unsigned char *out, uint16_t value) {
    out[0] = (unsigned char)(value & 0xffu);
    out[1] = (unsigned char)((value >> 8) & 0xffu);
}

static inline void guest_frame_put_u32le(unsigned char *out, uint32_t value) {
    out[0] = (unsigned char)(value & 0xffu);
    out[1] = (unsigned char)((value >> 8) & 0xffu);
    out[2] = (unsigned char)((value >> 16) & 0xffu);
    out[3] = (unsigned char)((value >> 24) & 0xffu);
}

static inline void guest_frame_put_u64le(unsigned char *out, uint64_t value) {
    for (unsigned i = 0; i < 8; ++i) out[i] = (unsigned char)((value >> (i * 8)) & 0xffu);
}

static inline uint32_t guest_frame_crc32(const unsigned char *data, size_t size) {
    uint32_t crc = 0xffffffffu;
    for (size_t i = 0; i < size; ++i) {
        crc ^= data[i];
        for (unsigned bit = 0; bit < 8; ++bit)
            crc = (crc >> 1) ^ (0xedb88320u & (uint32_t)-(int32_t)(crc & 1u));
    }
    return ~crc;
}

static inline uint64_t guest_frame_field_mask(guest_frame_bitfield field) {
    if (field.length == 0) return 0;
    return ((1ull << field.length) - 1ull) << field.offset;
}

static inline int guest_frame_channel_profile_valid(const guest_frame_packet *frame,
                                                     uint32_t *payload_bytes) {
    if (!frame || !frame->pixels || !payload_bytes ||
        frame->source != GUEST_FRAME_SOURCE_GUEST_FRAMEBUFFER ||
        frame->width == 0 || frame->height == 0 ||
        frame->width > GUEST_FRAME_MAX_WIDTH || frame->height > GUEST_FRAME_MAX_HEIGHT ||
        frame->sequence == 0 ||
        (frame->bits_per_pixel != 16 && frame->bits_per_pixel != 32)) return -EINVAL;

    uint64_t pixel_count = (uint64_t)frame->width * frame->height;
    uint32_t bytes_per_pixel = frame->bits_per_pixel / 8u;
    uint64_t min_stride = (uint64_t)frame->width * bytes_per_pixel;
    uint64_t payload = (uint64_t)frame->stride * frame->height;
    if (pixel_count > GUEST_FRAME_MAX_PIXELS || frame->stride < min_stride ||
        frame->stride > GUEST_FRAME_MAX_STRIDE ||
        payload == 0 || payload > GUEST_FRAME_MAX_PAYLOAD_BYTES || payload > UINT32_MAX)
        return -EOVERFLOW;

    const guest_frame_bitfield channels[] = {
        frame->red, frame->green, frame->blue, frame->transparency
    };
    uint64_t used = 0;
    for (size_t i = 0; i < sizeof(channels) / sizeof(channels[0]); ++i) {
        guest_frame_bitfield f = channels[i];
        if (f.msb_right > 1 || (f.length == 0 && i != 3) || f.length > 8 ||
            (f.length != 0 && (f.length < 5 || (unsigned)f.offset + f.length > frame->bits_per_pixel)))
            return -EINVAL;
        uint64_t mask = guest_frame_field_mask(f);
        if ((used & mask) != 0) return -EINVAL;
        used |= mask;
    }
    if (frame->transparency.length == 0 && frame->transparency.offset != 0) return -EINVAL;
    *payload_bytes = (uint32_t)payload;
    return 0;
}

static inline int guest_frame_channel_open_private_directory(const char *directory) {
    if (!directory || directory[0] != '/') return -EINVAL;
    int fd = open(directory, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return -errno;
    struct stat st;
    if (fstat(fd, &st) != 0) {
        int saved = errno;
        close(fd);
        return -saved;
    }
    if (!S_ISDIR(st.st_mode) || st.st_uid != getuid() || (st.st_mode & 0077) != 0) {
        close(fd);
        return -EACCES;
    }
    return fd;
}

static inline int guest_frame_channel_split_absolute_path(const char *path,
        char *parent, size_t parent_capacity, char *leaf, size_t leaf_capacity) {
    if (!path || path[0] != '/' || !parent || !leaf) return -EINVAL;
    size_t length = strlen(path);
    if (length < 2u || length >= PATH_MAX || path[length - 1u] == '/') return -EINVAL;
    const char *slash = strrchr(path, '/');
    if (!slash || slash[1] == '\0') return -EINVAL;
    size_t parent_length = slash == path ? 1u : (size_t)(slash - path);
    size_t leaf_length = length - (size_t)(slash + 1u - path);
    if (parent_length >= parent_capacity || leaf_length == 0u || leaf_length >= leaf_capacity)
        return -ENAMETOOLONG;
    memcpy(parent, path, parent_length);
    parent[parent_length] = '\0';
    memcpy(leaf, slash + 1, leaf_length + 1u);
    const char *component = path + 1;
    while (*component) {
        const char *end = strchr(component, '/');
        size_t component_length = end ? (size_t)(end - component) : strlen(component);
        if (component_length == 0u ||
            (component_length == 1u && component[0] == '.') ||
            (component_length == 2u && component[0] == '.' && component[1] == '.'))
            return -EACCES;
        if (!end) break;
        component = end + 1;
    }
    return 0;
}

static inline void guest_frame_channel_audit_stat(
        struct guest_frame_channel_component_audit *component,
        const struct stat *st) {
    if (!component || !st) return;
    component->owner = st->st_uid;
    component->group = st->st_gid;
    component->mode = st->st_mode;
    component->device = (uint64_t)st->st_dev;
    component->inode = (uint64_t)st->st_ino;
    component->has_stat = 1;
}

static inline int guest_frame_channel_parent_mode_safe(mode_t mode,
        gid_t parent_group, gid_t app_group) {
    return (mode & S_IWOTH) == 0 &&
        ((mode & S_IWGRP) == 0 || parent_group == app_group);
}

/* Walk only a canonical absolute path, holding each opened directory FD.  Every
 * component is checked with fstatat(AT_SYMLINK_NOFOLLOW), opened with O_NOFOLLOW,
 * and compared by device/inode before the previous FD is released.  O_PATH lets
 * us inspect/traverse platform ancestors such as /data/user without requiring
 * their ownership or broad 0700 permissions; the app-private leaves are checked
 * separately below. */
static inline int guest_frame_channel_open_directory_path_nofollow(
        const char *path, struct guest_frame_channel_path_audit *audit) {
    if (!path || path[0] != '/' || !audit) return -EINVAL;
    memset(audit, 0, sizeof(*audit));
    size_t path_length = strlen(path);
    if (path_length == 0 || path_length >= sizeof(audit->path)) return -ENAMETOOLONG;
    memcpy(audit->path, path, path_length + 1u);
    int fd = open("/", O_PATH | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) { audit->error_number = errno; return -errno; }
    struct stat root_stat;
    if (fstat(fd, &root_stat) != 0) {
        int saved = errno;
        close(fd);
        audit->error_number = saved;
        return -saved;
    }
    struct guest_frame_channel_component_audit *root = &audit->components[0];
    memcpy(root->name, "/", 2u);
    guest_frame_channel_audit_stat(root, &root_stat);
    root->opened = 1;
    audit->component_count = 1u;
    const char *cursor = path + 1;
    while (*cursor) {
        const char *end = strchr(cursor, '/');
        size_t length = end ? (size_t)(end - cursor) : strlen(cursor);
        if (length == 0u || length > NAME_MAX ||
            (length == 1u && cursor[0] == '.') ||
            (length == 2u && cursor[0] == '.' && cursor[1] == '.')) {
            close(fd);
            audit->error_number = length > NAME_MAX ? ENAMETOOLONG : EACCES;
            return -audit->error_number;
        }
        if (audit->component_count >= GUEST_FRAME_CHANNEL_MAX_PATH_COMPONENTS) {
            close(fd);
            audit->error_number = E2BIG;
            return -E2BIG;
        }
        struct guest_frame_channel_component_audit *component =
            &audit->components[audit->component_count++];
        memcpy(component->name, cursor, length);
        component->name[length] = '\0';
        struct stat before_open;
        if (fstatat(fd, component->name, &before_open, AT_SYMLINK_NOFOLLOW) != 0) {
            int saved = errno;
            component->error_number = saved;
            audit->error_number = saved;
            close(fd);
            return -saved;
        }
        guest_frame_channel_audit_stat(component, &before_open);
        if (S_ISLNK(before_open.st_mode)) {
            component->symlink = 1;
            component->error_number = ELOOP;
            audit->error_number = ELOOP;
            close(fd);
            return -ELOOP;
        }
        int next_fd = openat(fd, component->name,
            O_PATH | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        if (next_fd < 0) {
            int saved = errno;
            component->error_number = saved;
            audit->error_number = saved;
            close(fd);
            return -saved;
        }
        struct stat opened_stat;
        if (fstat(next_fd, &opened_stat) != 0) {
            int saved = errno;
            component->error_number = saved;
            audit->error_number = saved;
            close(next_fd);
            close(fd);
            return -saved;
        }
        if (opened_stat.st_dev != before_open.st_dev ||
            opened_stat.st_ino != before_open.st_ino) {
            component->error_number = EAGAIN;
            audit->error_number = EAGAIN;
            close(next_fd);
            close(fd);
            return -EAGAIN;
        }
        guest_frame_channel_audit_stat(component, &opened_stat);
        component->opened = 1;
        if (!S_ISDIR(opened_stat.st_mode)) {
            component->error_number = ENOTDIR;
            audit->error_number = ENOTDIR;
            close(next_fd);
            close(fd);
            return -ENOTDIR;
        }
        close(fd);
        fd = next_fd;
        if (!end) break;
        cursor = end + 1;
    }
    return fd;
}

static inline int guest_frame_channel_open_app_private_sibling_ex(
        const char *directory, const char *guest_root, uid_t expected_owner,
        struct guest_frame_channel_validation_detail *detail) {
    struct guest_frame_channel_validation_detail value;
    memset(&value, 0, sizeof(value));
    value.reason = GUEST_FRAME_CHANNEL_INVALID_ARGUMENT;
    value.error_number = EINVAL;
    value.expected_owner = expected_owner;
    if (!directory || !guest_root || !directory[0] || !guest_root[0]) {
        if (detail) *detail = value;
        return -EINVAL;
    }
    char root_parent[PATH_MAX], channel_parent[PATH_MAX];
    char root_leaf[NAME_MAX + 1u], channel_leaf[NAME_MAX + 1u];
    int split_rc = guest_frame_channel_split_absolute_path(guest_root,
        root_parent, sizeof(root_parent), root_leaf, sizeof(root_leaf));
    if (split_rc == 0)
        split_rc = guest_frame_channel_split_absolute_path(directory,
            channel_parent, sizeof(channel_parent), channel_leaf, sizeof(channel_leaf));
    if (split_rc != 0) {
        value.reason = split_rc == -ENAMETOOLONG ? GUEST_FRAME_CHANNEL_PATH_TOO_LONG :
                       GUEST_FRAME_CHANNEL_INVALID_ARGUMENT;
        value.error_number = -split_rc;
        if (detail) *detail = value;
        return split_rc;
    }
    memcpy(value.guest_root_path, guest_root, strlen(guest_root) + 1u);
    memcpy(value.channel_path, directory, strlen(directory) + 1u);
    size_t root_len = strlen(root_parent);
    if (root_len >= sizeof(value.expected_path)) {
        value.reason = GUEST_FRAME_CHANNEL_PATH_TOO_LONG;
        value.error_number = ENAMETOOLONG;
        if (detail) *detail = value;
        return -ENAMETOOLONG;
    }
    int n = snprintf(value.expected_path, sizeof(value.expected_path), "%s%s%s", root_parent,
                     strcmp(root_parent, "/") == 0 ? "" : "/",
                     GUEST_FRAME_CHANNEL_DIRECTORY);
    if (n <= 0 || (size_t)n >= sizeof(value.expected_path)) {
        value.reason = GUEST_FRAME_CHANNEL_PATH_TOO_LONG;
        value.error_number = ENAMETOOLONG;
        if (detail) *detail = value;
        return -ENAMETOOLONG;
    }
    if (strcmp(channel_leaf, GUEST_FRAME_CHANNEL_DIRECTORY) != 0) {
        value.reason = GUEST_FRAME_CHANNEL_NOT_EXACT_SIBLING;
        value.error_number = EACCES;
        if (detail) *detail = value;
        return -EACCES;
    }

    int root_parent_fd = guest_frame_channel_open_directory_path_nofollow(
        root_parent, &value.root_parent_audit);
    if (root_parent_fd < 0) {
        int saved = -root_parent_fd;
        value.scope = GUEST_FRAME_CHANNEL_SCOPE_ROOT_PARENT;
        value.reason = value.root_parent_audit.components[
            value.root_parent_audit.component_count ? value.root_parent_audit.component_count - 1u : 0u].symlink
                ? GUEST_FRAME_CHANNEL_PATH_COMPONENT_SYMLINK
                : (saved == E2BIG ? GUEST_FRAME_CHANNEL_PATH_COMPONENT_LIMIT
                                  : GUEST_FRAME_CHANNEL_OPEN_FAILED);
        value.error_number = saved;
        if (detail) *detail = value;
        return root_parent_fd;
    }
    int channel_parent_fd = guest_frame_channel_open_directory_path_nofollow(
        channel_parent, &value.channel_parent_audit);
    if (channel_parent_fd < 0) {
        int saved = -channel_parent_fd;
        close(root_parent_fd);
        value.scope = GUEST_FRAME_CHANNEL_SCOPE_CHANNEL_PARENT;
        value.reason = value.channel_parent_audit.components[
            value.channel_parent_audit.component_count ? value.channel_parent_audit.component_count - 1u : 0u].symlink
                ? GUEST_FRAME_CHANNEL_PATH_COMPONENT_SYMLINK
                : (saved == E2BIG ? GUEST_FRAME_CHANNEL_PATH_COMPONENT_LIMIT
                                  : GUEST_FRAME_CHANNEL_OPEN_FAILED);
        value.error_number = saved;
        if (detail) *detail = value;
        return channel_parent_fd;
    }
    struct stat root_parent_stat, channel_parent_stat;
    if (fstat(root_parent_fd, &root_parent_stat) != 0 ||
        fstat(channel_parent_fd, &channel_parent_stat) != 0) {
        int saved = errno;
        close(channel_parent_fd);
        close(root_parent_fd);
        value.reason = GUEST_FRAME_CHANNEL_FSTAT_FAILED;
        value.error_number = saved;
        if (detail) *detail = value;
        return -saved;
    }
    if (!S_ISDIR(root_parent_stat.st_mode) || !S_ISDIR(channel_parent_stat.st_mode) ||
        root_parent_stat.st_dev != channel_parent_stat.st_dev ||
        root_parent_stat.st_ino != channel_parent_stat.st_ino) {
        close(channel_parent_fd);
        close(root_parent_fd);
        value.reason = GUEST_FRAME_CHANNEL_NOT_EXACT_SIBLING;
        value.scope = GUEST_FRAME_CHANNEL_SCOPE_PARENT_IDENTITY;
        value.error_number = EACCES;
        if (detail) *detail = value;
        return -EACCES;
    }
    if (root_parent_stat.st_uid != expected_owner || channel_parent_stat.st_uid != expected_owner) {
        close(channel_parent_fd);
        close(root_parent_fd);
        value.reason = GUEST_FRAME_CHANNEL_WRONG_OWNER;
        value.scope = GUEST_FRAME_CHANNEL_SCOPE_PARENT_OWNER;
        value.error_number = EACCES;
        if (detail) *detail = value;
        return -EACCES;
    }
    /* Parent ancestors may legitimately be searchable/readable by platform
     * users.  Only reject writes available to world or to a non-app group;
     * channel and guest-root leaves below remain strictly owner-private. */
    if (!guest_frame_channel_parent_mode_safe(root_parent_stat.st_mode,
            root_parent_stat.st_gid, getgid())) {
        close(channel_parent_fd);
        close(root_parent_fd);
        value.reason = GUEST_FRAME_CHANNEL_PARENT_UNSAFE_WRITABLE;
        value.scope = GUEST_FRAME_CHANNEL_SCOPE_PARENT_MODE;
        value.error_number = EACCES;
        if (detail) *detail = value;
        return -EACCES;
    }

    struct stat root_link_stat;
    if (fstatat(root_parent_fd, root_leaf, &root_link_stat,
                AT_SYMLINK_NOFOLLOW) != 0) {
        int saved = errno;
        close(channel_parent_fd);
        close(root_parent_fd);
        value.scope = GUEST_FRAME_CHANNEL_SCOPE_GUEST_ROOT_LEAF;
        value.reason = GUEST_FRAME_CHANNEL_OPEN_FAILED;
        value.error_number = saved;
        if (detail) *detail = value;
        return -saved;
    }
    value.root_owner = root_link_stat.st_uid;
    value.root_group = root_link_stat.st_gid;
    value.root_mode = root_link_stat.st_mode;
    value.root_device = (uint64_t)root_link_stat.st_dev;
    value.root_inode = (uint64_t)root_link_stat.st_ino;
    value.root_has_stat = 1;
    if (S_ISLNK(root_link_stat.st_mode)) {
        value.root_is_symlink = 1;
        close(channel_parent_fd);
        close(root_parent_fd);
        value.scope = GUEST_FRAME_CHANNEL_SCOPE_GUEST_ROOT_LEAF;
        value.reason = GUEST_FRAME_CHANNEL_PATH_COMPONENT_SYMLINK;
        value.error_number = ELOOP;
        if (detail) *detail = value;
        return -ELOOP;
    }
    int root_fd = openat(root_parent_fd, root_leaf,
                         O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (root_fd < 0) {
        int saved = errno;
        close(channel_parent_fd);
        close(root_parent_fd);
        value.reason = GUEST_FRAME_CHANNEL_OPEN_FAILED;
        value.error_number = saved;
        if (detail) *detail = value;
        return -saved;
    }
    struct stat root_stat;
    if (fstat(root_fd, &root_stat) != 0) {
        int saved = errno;
        close(root_fd);
        close(channel_parent_fd);
        close(root_parent_fd);
        value.reason = GUEST_FRAME_CHANNEL_FSTAT_FAILED;
        value.error_number = saved;
        if (detail) *detail = value;
        return -saved;
    }
    if (root_stat.st_dev != root_link_stat.st_dev ||
        root_stat.st_ino != root_link_stat.st_ino) {
        close(root_fd);
        close(channel_parent_fd);
        close(root_parent_fd);
        value.scope = GUEST_FRAME_CHANNEL_SCOPE_GUEST_ROOT_LEAF;
        value.reason = GUEST_FRAME_CHANNEL_FSTAT_FAILED;
        value.error_number = EAGAIN;
        if (detail) *detail = value;
        return -EAGAIN;
    }
    value.root_owner = root_stat.st_uid;
    value.root_group = root_stat.st_gid;
    value.root_mode = root_stat.st_mode;
    value.root_device = (uint64_t)root_stat.st_dev;
    value.root_inode = (uint64_t)root_stat.st_ino;
    value.root_has_stat = 1;
    if (!S_ISDIR(root_stat.st_mode) || root_stat.st_uid != expected_owner) {
        close(root_fd);
        close(channel_parent_fd);
        close(root_parent_fd);
        value.scope = GUEST_FRAME_CHANNEL_SCOPE_GUEST_ROOT_LEAF;
        value.reason = S_ISDIR(root_stat.st_mode) ? GUEST_FRAME_CHANNEL_WRONG_OWNER :
                       GUEST_FRAME_CHANNEL_NOT_DIRECTORY;
        value.error_number = S_ISDIR(root_stat.st_mode) ? EACCES : ENOTDIR;
        if (detail) *detail = value;
        return -value.error_number;
    }
    if ((root_stat.st_mode & 0077) != 0) {
        close(root_fd);
        close(channel_parent_fd);
        close(root_parent_fd);
        value.scope = GUEST_FRAME_CHANNEL_SCOPE_GUEST_ROOT_LEAF;
        value.reason = GUEST_FRAME_CHANNEL_GUEST_ROOT_NOT_PRIVATE;
        value.error_number = EACCES;
        if (detail) *detail = value;
        return -EACCES;
    }
    close(root_fd);

    struct stat channel_link_stat;
    if (fstatat(channel_parent_fd, channel_leaf, &channel_link_stat,
                AT_SYMLINK_NOFOLLOW) != 0) {
        int saved = errno;
        close(channel_parent_fd);
        close(root_parent_fd);
        value.scope = GUEST_FRAME_CHANNEL_SCOPE_CHANNEL_LEAF;
        value.reason = GUEST_FRAME_CHANNEL_OPEN_FAILED;
        value.error_number = saved;
        if (detail) *detail = value;
        return -saved;
    }
    value.channel_owner = channel_link_stat.st_uid;
    value.channel_group = channel_link_stat.st_gid;
    value.channel_mode = channel_link_stat.st_mode;
    value.channel_device = (uint64_t)channel_link_stat.st_dev;
    value.channel_inode = (uint64_t)channel_link_stat.st_ino;
    value.channel_has_stat = 1;
    if (S_ISLNK(channel_link_stat.st_mode)) {
        value.channel_is_symlink = 1;
        close(channel_parent_fd);
        close(root_parent_fd);
        value.scope = GUEST_FRAME_CHANNEL_SCOPE_CHANNEL_LEAF;
        value.reason = GUEST_FRAME_CHANNEL_PATH_COMPONENT_SYMLINK;
        value.error_number = ELOOP;
        if (detail) *detail = value;
        return -ELOOP;
    }
    int fd = openat(channel_parent_fd, channel_leaf,
                    O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    close(channel_parent_fd);
    close(root_parent_fd);
    if (fd < 0) {
        value.reason = GUEST_FRAME_CHANNEL_OPEN_FAILED;
        value.error_number = errno;
        if (detail) *detail = value;
        return -errno;
    }
    struct stat st;
    if (fstat(fd, &st) != 0) {
        int saved = errno;
        close(fd);
        value.reason = GUEST_FRAME_CHANNEL_FSTAT_FAILED;
        value.error_number = saved;
        if (detail) *detail = value;
        return -saved;
    }
    if (st.st_dev != channel_link_stat.st_dev ||
        st.st_ino != channel_link_stat.st_ino) {
        close(fd);
        value.scope = GUEST_FRAME_CHANNEL_SCOPE_CHANNEL_LEAF;
        value.reason = GUEST_FRAME_CHANNEL_FSTAT_FAILED;
        value.error_number = EAGAIN;
        if (detail) *detail = value;
        return -EAGAIN;
    }
    value.actual_owner = st.st_uid;
    value.actual_mode = st.st_mode;
    value.has_stat = 1;
    value.channel_owner = st.st_uid;
    value.channel_group = st.st_gid;
    value.channel_mode = st.st_mode;
    value.channel_device = (uint64_t)st.st_dev;
    value.channel_inode = (uint64_t)st.st_ino;
    value.channel_has_stat = 1;
    if (!S_ISDIR(st.st_mode)) {
        close(fd);
        value.scope = GUEST_FRAME_CHANNEL_SCOPE_CHANNEL_LEAF;
        value.reason = GUEST_FRAME_CHANNEL_NOT_DIRECTORY;
        value.error_number = ENOTDIR;
        if (detail) *detail = value;
        return -ENOTDIR;
    }
    if (st.st_uid != expected_owner) {
        close(fd);
        value.scope = GUEST_FRAME_CHANNEL_SCOPE_CHANNEL_LEAF;
        value.reason = GUEST_FRAME_CHANNEL_WRONG_OWNER;
        value.error_number = EACCES;
        if (detail) *detail = value;
        return -EACCES;
    }
    if ((st.st_mode & 0077) != 0) {
        close(fd);
        value.scope = GUEST_FRAME_CHANNEL_SCOPE_CHANNEL_LEAF;
        value.reason = GUEST_FRAME_CHANNEL_NOT_PRIVATE;
        value.error_number = EACCES;
        if (detail) *detail = value;
        return -EACCES;
    }
    value.reason = GUEST_FRAME_CHANNEL_VALID;
    value.scope = GUEST_FRAME_CHANNEL_SCOPE_NONE;
    value.error_number = 0;
    if (detail) *detail = value;
    return fd;
}

static inline int guest_frame_channel_validate_app_private_directory_ex(
        const char *directory, const char *guest_root, uid_t expected_owner,
        struct guest_frame_channel_validation_detail *detail) {
    int fd = guest_frame_channel_open_app_private_sibling_ex(
        directory, guest_root, expected_owner, detail);
    if (fd < 0) return fd;
    close(fd);
    return 1;
}

static inline int guest_frame_channel_validate_app_private_directory(
        const char *directory, const char *guest_root) {
    return guest_frame_channel_validate_app_private_directory_ex(
        directory, guest_root, getuid(), NULL);
}

static inline int guest_frame_write_all(int fd, const unsigned char *data, size_t size) {
    size_t written = 0;
    while (written < size) {
        ssize_t rc = write(fd, data + written, size - written);
        if (rc < 0) {
            if (errno == EINTR) continue;
            return -errno;
        }
        if (rc == 0) return -EIO;
        written += (size_t)rc;
    }
    return 0;
}

static inline int guest_frame_channel_publish_file_at(int dirfd,
                                                       const guest_frame_packet *frame) {
    uint32_t payload_bytes = 0;
    int rc = guest_frame_channel_profile_valid(frame, &payload_bytes);
    if (rc != 0) return rc;
    struct stat directory_stat;
    if (fstat(dirfd, &directory_stat) != 0) return -errno;
    if (!S_ISDIR(directory_stat.st_mode) || directory_stat.st_uid != getuid() ||
        (directory_stat.st_mode & 0077) != 0) return -EACCES;

    unsigned char header[GUEST_FRAME_PROTOCOL_HEADER_BYTES];
    memset(header, 0, sizeof(header));
    memcpy(header, GUEST_FRAME_PROTOCOL_MAGIC, 4);
    guest_frame_put_u16le(header + 4, GUEST_FRAME_PROTOCOL_VERSION);
    guest_frame_put_u16le(header + 6, GUEST_FRAME_PROTOCOL_HEADER_BYTES);
    guest_frame_put_u32le(header + 8, frame->source);
    guest_frame_put_u32le(header + 12, frame->width);
    guest_frame_put_u32le(header + 16, frame->height);
    guest_frame_put_u32le(header + 20, frame->stride);
    header[24] = frame->bits_per_pixel;
    header[25] = 1; /* Pixel words are little-endian, as reported by the guest fb ABI. */
    header[28] = frame->red.offset;
    header[29] = frame->red.length;
    header[30] = frame->red.msb_right;
    header[32] = frame->green.offset;
    header[33] = frame->green.length;
    header[34] = frame->green.msb_right;
    header[36] = frame->blue.offset;
    header[37] = frame->blue.length;
    header[38] = frame->blue.msb_right;
    header[40] = frame->transparency.offset;
    header[41] = frame->transparency.length;
    header[42] = frame->transparency.msb_right;
    guest_frame_put_u32le(header + 44, payload_bytes);
    guest_frame_put_u64le(header + 48, frame->sequence);
    guest_frame_put_u32le(header + 56, guest_frame_crc32(frame->pixels, payload_bytes));

    (void)unlinkat(dirfd, GUEST_FRAME_CHANNEL_TEMP_FILE, 0);
    int fd = openat(dirfd, GUEST_FRAME_CHANNEL_TEMP_FILE,
                    O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0) return -errno;
    struct stat st;
    if (fstat(fd, &st) != 0) {
        int saved = errno;
        close(fd);
        (void)unlinkat(dirfd, GUEST_FRAME_CHANNEL_TEMP_FILE, 0);
        return -saved;
    }
    if (!S_ISREG(st.st_mode) || st.st_uid != getuid()) {
        int saved = EACCES;
        close(fd);
        (void)unlinkat(dirfd, GUEST_FRAME_CHANNEL_TEMP_FILE, 0);
        return -saved;
    }
    rc = guest_frame_write_all(fd, header, sizeof(header));
    if (rc == 0) rc = guest_frame_write_all(fd, frame->pixels, payload_bytes);
    if (rc == 0 && fsync(fd) != 0) rc = -errno;
    if (close(fd) != 0 && rc == 0) rc = -errno;
    if (rc == 0 && renameat(dirfd, GUEST_FRAME_CHANNEL_TEMP_FILE,
                            dirfd, GUEST_FRAME_CHANNEL_FILE) != 0) rc = -errno;
    if (rc == 0 && fsync(dirfd) != 0) rc = -errno;
    if (rc != 0) (void)unlinkat(dirfd, GUEST_FRAME_CHANNEL_TEMP_FILE, 0);
    return rc;
}

static inline int guest_frame_channel_publish_file(const char *directory,
                                                    const guest_frame_packet *frame) {
    int dirfd = guest_frame_channel_open_private_directory(directory);
    if (dirfd < 0) return dirfd;
    int rc = guest_frame_channel_publish_file_at(dirfd, frame);
    if (close(dirfd) != 0 && rc == 0) rc = -errno;
    return rc;
}

#endif
