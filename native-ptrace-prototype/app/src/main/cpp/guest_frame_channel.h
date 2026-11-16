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

#define GUEST_FRAME_CHANNEL_DIRECTORY "gingervm-display"
#define GUEST_FRAME_CHANNEL_FILE "latest.gvmf"
#define GUEST_FRAME_CHANNEL_TEMP_FILE "latest.gvmf.tmp"
#define GUEST_FRAME_CHANNEL_ENV "GINGERVM_GUEST_FRAME_DIR"
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
    GUEST_FRAME_CHANNEL_NOT_PRIVATE
};

struct guest_frame_channel_validation_detail {
    enum guest_frame_channel_validation_reason reason;
    int error_number;
    uid_t expected_owner;
    uid_t actual_owner;
    mode_t actual_mode;
    int has_stat;
    char expected_path[PATH_MAX];
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
        case GUEST_FRAME_CHANNEL_NOT_PRIVATE: return "group-or-other-permission-present";
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

static inline int guest_frame_channel_validate_app_private_directory_ex(
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
    char parent[PATH_MAX];
    size_t root_len = strlen(guest_root);
    if (root_len == 0 || root_len >= sizeof(parent)) {
        value.reason = GUEST_FRAME_CHANNEL_PATH_TOO_LONG;
        value.error_number = ENAMETOOLONG;
        if (detail) *detail = value;
        return -ENAMETOOLONG;
    }
    memcpy(parent, guest_root, root_len + 1);
    char *slash = strrchr(parent, '/');
    if (!slash) {
        if (detail) *detail = value;
        return -EINVAL;
    }
    if (slash == parent) slash[1] = '\0';
    else *slash = '\0';
    int n = snprintf(value.expected_path, sizeof(value.expected_path), "%s%s%s", parent,
                     strcmp(parent, "/") == 0 ? "" : "/",
                     GUEST_FRAME_CHANNEL_DIRECTORY);
    if (n <= 0 || (size_t)n >= sizeof(value.expected_path)) {
        value.reason = GUEST_FRAME_CHANNEL_PATH_TOO_LONG;
        value.error_number = ENAMETOOLONG;
        if (detail) *detail = value;
        return -ENAMETOOLONG;
    }
    if (strcmp(directory, value.expected_path) != 0) {
        value.reason = GUEST_FRAME_CHANNEL_NOT_EXACT_SIBLING;
        value.error_number = EACCES;
        if (detail) *detail = value;
        return -EACCES;
    }
    int fd = open(directory, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
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
    value.actual_owner = st.st_uid;
    value.actual_mode = st.st_mode;
    value.has_stat = 1;
    if (!S_ISDIR(st.st_mode)) {
        close(fd);
        value.reason = GUEST_FRAME_CHANNEL_NOT_DIRECTORY;
        value.error_number = ENOTDIR;
        if (detail) *detail = value;
        return -ENOTDIR;
    }
    if (st.st_uid != expected_owner) {
        close(fd);
        value.reason = GUEST_FRAME_CHANNEL_WRONG_OWNER;
        value.error_number = EACCES;
        if (detail) *detail = value;
        return -EACCES;
    }
    if ((st.st_mode & 0077) != 0) {
        close(fd);
        value.reason = GUEST_FRAME_CHANNEL_NOT_PRIVATE;
        value.error_number = EACCES;
        if (detail) *detail = value;
        return -EACCES;
    }
    close(fd);
    value.reason = GUEST_FRAME_CHANNEL_VALID;
    value.error_number = 0;
    if (detail) *detail = value;
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

static inline int guest_frame_channel_publish_file(const char *directory,
                                                    const guest_frame_packet *frame) {
    uint32_t payload_bytes = 0;
    int rc = guest_frame_channel_profile_valid(frame, &payload_bytes);
    if (rc != 0) return rc;
    int dirfd = guest_frame_channel_open_private_directory(directory);
    if (dirfd < 0) return dirfd;

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
    if (fd < 0) {
        int saved = errno;
        close(dirfd);
        return -saved;
    }
    struct stat st;
    if (fstat(fd, &st) != 0) {
        int saved = errno;
        close(fd);
        (void)unlinkat(dirfd, GUEST_FRAME_CHANNEL_TEMP_FILE, 0);
        close(dirfd);
        return -saved;
    }
    if (!S_ISREG(st.st_mode) || st.st_uid != getuid()) {
        int saved = EACCES;
        close(fd);
        (void)unlinkat(dirfd, GUEST_FRAME_CHANNEL_TEMP_FILE, 0);
        close(dirfd);
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
    close(dirfd);
    return rc;
}

#endif
