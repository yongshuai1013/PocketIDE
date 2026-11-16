#ifndef GINGERVM_GUEST_FRAMEBUFFER_VIRTUAL_H
#define GINGERVM_GUEST_FRAMEBUFFER_VIRTUAL_H

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "guest_frame_channel.h"
#include "guest_hardware_profile.h"
#include "guest_identity_compat.h"

#define GUEST_FB0_PATH "/dev/graphics/fb0"
#define GUEST_FB0_SYSFS_DEVICE_PATH "/devices/virtual/graphics/fb0"
#define GUEST_FB0_SYSFS_ATTRIBUTE_PATH "/sys" GUEST_FB0_SYSFS_DEVICE_PATH "/uevent"
#define GUEST_FB0_BACKING_FILE "fb0.backing"
#define GUEST_FB0_MAJOR 29u
#define GUEST_FB0_MINOR 0u
#define GUEST_FB0_OWNER_UID 0u
#define GUEST_FB0_OWNER_GID GUEST_ID_AID_GRAPHICS
#define GUEST_FB0_MODE 0020660u
#define GUEST_FB0_BPP 16u
#define GUEST_FB0_BYTES_PER_PIXEL 2u
#define GUEST_FB0_DOUBLE_BUFFER_COUNT 2u
#define GUEST_FB0_TYPE_PACKED_PIXELS 0u
#define GUEST_FB0_VISUAL_TRUECOLOR 2u
#define GUEST_FB0_ACTIVATE_NOW 0u
#define GUEST_FB0_IOCTL_GET_VSCREENINFO 0x4600u
#define GUEST_FB0_IOCTL_PUT_VSCREENINFO 0x4601u
#define GUEST_FB0_IOCTL_GET_FSCREENINFO 0x4602u
#define GUEST_FB0_IOCTL_PAN_DISPLAY 0x4606u
#define GUEST_FB0_MAX_CAPTURE_BYTES GUEST_FRAME_MAX_PAYLOAD_BYTES

struct guest_arm32_fb_bitfield {
    uint32_t offset;
    uint32_t length;
    uint32_t msb_right;
};

/* Linux 2.6.29 fb_var_screeninfo for ARM32; all fields are fixed-width u32. */
struct guest_arm32_fb_var_screeninfo {
    uint32_t xres, yres, xres_virtual, yres_virtual;
    uint32_t xoffset, yoffset, bits_per_pixel, grayscale;
    struct guest_arm32_fb_bitfield red, green, blue, transp;
    uint32_t nonstd, activate, height, width, accel_flags, pixclock;
    uint32_t left_margin, right_margin, upper_margin, lower_margin;
    uint32_t hsync_len, vsync_len, sync, vmode, rotate, colorspace;
    uint32_t reserved[4];
};

/* Linux 2.6.29 fb_fix_screeninfo for ARM32 (including explicit ABI padding). */
struct guest_arm32_fb_fix_screeninfo {
    char id[16];
    uint32_t smem_start, smem_len, type, type_aux, visual;
    uint16_t xpanstep, ypanstep, ywrapstep, reserved0;
    uint32_t line_length, mmio_start, mmio_len, accel;
    uint16_t capabilities, reserved[2];
};

_Static_assert(sizeof(struct guest_arm32_fb_bitfield) == 12u,
               "API10 ARM32 fb_bitfield layout");
_Static_assert(sizeof(struct guest_arm32_fb_var_screeninfo) == 160u,
               "API10 ARM32 fb_var_screeninfo layout");
_Static_assert(sizeof(struct guest_arm32_fb_fix_screeninfo) == 68u,
               "API10 ARM32 fb_fix_screeninfo layout");

struct guest_framebuffer_model {
    uint32_t xres;
    uint32_t yres;
    uint32_t yres_virtual;
    uint32_t yoffset;
    uint64_t sequence;
    unsigned long opens;
    unsigned long ioctls;
    unsigned long mappings;
    unsigned long page_flips;
    unsigned long software_base_update_acks;
    unsigned long published;
    unsigned long rejected;
};

static inline uint32_t guest_fb0_line_length(void) {
    return GUEST_PROFILE_DISPLAY_WIDTH * GUEST_FB0_BYTES_PER_PIXEL;
}

static inline uint32_t guest_fb0_smem_len(void) {
    return guest_fb0_line_length() * GUEST_PROFILE_DISPLAY_HEIGHT *
           GUEST_FB0_DOUBLE_BUFFER_COUNT;
}

static inline uint32_t guest_fb0_makedev(uint32_t major, uint32_t minor) {
    return ((major & 0xfffu) << 8) | (minor & 0xffu) |
           ((minor & ~0xffu) << 12);
}

static inline int guest_fb0_mknod_args_valid(uint32_t guest_euid,
                                             uint32_t guest_fsgid,
                                             int graphics_uevent_received,
                                             uint32_t mode,
                                             uint32_t device) {
    return guest_euid == GUEST_FB0_OWNER_UID &&
        guest_fsgid == GUEST_FB0_OWNER_GID && graphics_uevent_received &&
        (mode & (S_IFMT | 07777u)) == (GUEST_FB0_MODE & (S_IFMT | 07777u)) &&
        device == guest_fb0_makedev(GUEST_FB0_MAJOR, GUEST_FB0_MINOR);
}

static inline int guest_fb0_open_ready(int backend_ready,
                                       int graphics_uevent_received,
                                       int node_created) {
    if (!backend_ready) return -ENODEV;
    if (!graphics_uevent_received || !node_created) return -ENOENT;
    return 0;
}

static inline int guest_fb0_open_authorized(int backend_ready,
                                            int graphics_uevent_received,
                                            int node_created,
                                            const struct guest_identity_state *identity,
                                            int flags) {
    int ready = guest_fb0_open_ready(backend_ready,
                                     graphics_uevent_received,
                                     node_created);
    return ready != 0 ? ready : guest_identity_fb0_access(identity, flags);
}

static inline int guest_fb0_fd_matches_proc(pid_t pid, int fd,
                                             const struct stat *backing) {
    if (pid <= 0 || fd < 0 || !backing || !S_ISREG(backing->st_mode) ||
        backing->st_uid != getuid() || backing->st_nlink != 1 ||
        backing->st_size != (off_t)guest_fb0_smem_len()) return 0;
    char path[64];
    int n = snprintf(path, sizeof(path), "/proc/%ld/fd/%d", (long)pid, fd);
    if (n <= 0 || (size_t)n >= sizeof(path)) return 0;
    struct stat opened;
    if (stat(path, &opened) != 0) return 0;
    return S_ISREG(opened.st_mode) && opened.st_dev == backing->st_dev &&
           opened.st_ino == backing->st_ino && opened.st_uid == backing->st_uid &&
           opened.st_nlink == 1 && opened.st_size == backing->st_size;
}

static inline void guest_framebuffer_model_init(struct guest_framebuffer_model *model) {
    if (!model) return;
    memset(model, 0, sizeof(*model));
    model->xres = GUEST_PROFILE_DISPLAY_WIDTH;
    model->yres = GUEST_PROFILE_DISPLAY_HEIGHT;
    model->yres_virtual = GUEST_PROFILE_DISPLAY_HEIGHT * GUEST_FB0_DOUBLE_BUFFER_COUNT;
}

static inline void guest_fb0_make_fix(const struct guest_framebuffer_model *model,
                                     struct guest_arm32_fb_fix_screeninfo *fix) {
    if (!model || !fix) return;
    memset(fix, 0, sizeof(*fix));
    /* goldfishfb.c leaves fix.id zeroed (the strncpy is commented out). */
    fix->smem_start = 0; /* no guest physical/DMA address exists in the software backend */
    fix->smem_len = guest_fb0_smem_len();
    fix->type = GUEST_FB0_TYPE_PACKED_PIXELS;
    fix->visual = GUEST_FB0_VISUAL_TRUECOLOR;
    fix->ypanstep = 1;
    fix->line_length = guest_fb0_line_length();
}

static inline void guest_fb0_make_var(const struct guest_framebuffer_model *model,
                                     struct guest_arm32_fb_var_screeninfo *var) {
    if (!model || !var) return;
    memset(var, 0, sizeof(*var));
    var->xres = model->xres;
    var->yres = model->yres;
    var->xres_virtual = model->xres;
    var->yres_virtual = model->yres_virtual;
    var->yoffset = model->yoffset;
    var->bits_per_pixel = GUEST_FB0_BPP;
    var->activate = GUEST_FB0_ACTIVATE_NOW;
    /* Physical-width registers are not supplied by the selected API10 skin. */
    var->height = 0;
    var->width = 0;
    var->pixclock = 0u; /* Goldfish driver leaves timing fields zeroed. */
    var->red.offset = 11u; var->red.length = 5u;
    var->green.offset = 5u; var->green.length = 6u;
    var->blue.offset = 0u; var->blue.length = 5u;
}

static inline int guest_fb0_bitfield_is(const struct guest_arm32_fb_bitfield *field,
                                        uint32_t offset, uint32_t length) {
    return field && field->offset == offset && field->length == length &&
           field->msb_right == 0u;
}

/* Implements Goldfish driver's unrotated check_var constraints for API10 HAL. */
static inline int guest_fb0_validate_put(const struct guest_framebuffer_model *model,
                                        const struct guest_arm32_fb_var_screeninfo *var) {
    if (!model || !var) return -EINVAL;
    if (var->xres != model->xres || var->yres != model->yres ||
        var->xres_virtual != model->xres || var->yres_virtual < model->yres ||
        var->yres_virtual > model->yres * GUEST_FB0_DOUBLE_BUFFER_COUNT ||
        var->xoffset != 0u || var->yoffset != 0u ||
        var->bits_per_pixel != GUEST_FB0_BPP || var->grayscale != 0u ||
        var->rotate != 0u || var->activate != GUEST_FB0_ACTIVATE_NOW ||
        !guest_fb0_bitfield_is(&var->red, 11u, 5u) ||
        !guest_fb0_bitfield_is(&var->green, 5u, 6u) ||
        !guest_fb0_bitfield_is(&var->blue, 0u, 5u) ||
        !guest_fb0_bitfield_is(&var->transp, 0u, 0u)) return -EINVAL;
    return 0;
}

static inline int guest_fb0_commit_put(struct guest_framebuffer_model *model,
                                       const struct guest_arm32_fb_var_screeninfo *var) {
    int rc = guest_fb0_validate_put(model, var);
    if (rc != 0) return rc;
    model->yres_virtual = var->yres_virtual;
    model->yoffset = 0;
    return 0;
}

static inline int guest_fb0_validate_pan(const struct guest_framebuffer_model *model,
                                         const struct guest_arm32_fb_var_screeninfo *var) {
    if (!model || !var) return -EINVAL;
    if (var->xres != model->xres || var->yres != model->yres ||
        var->xres_virtual != model->xres || var->yres_virtual != model->yres_virtual ||
        var->xoffset != 0u || var->bits_per_pixel != GUEST_FB0_BPP ||
        var->grayscale != 0u || var->rotate != 0u ||
        var->yoffset > model->yres_virtual - model->yres ||
        var->activate != GUEST_FB0_ACTIVATE_NOW) return -EINVAL;
    return 0;
}

static inline int guest_fb0_commit_pan(struct guest_framebuffer_model *model,
                                       const struct guest_arm32_fb_var_screeninfo *var) {
    int rc = guest_fb0_validate_pan(model, var);
    if (rc != 0) return rc;
    model->yoffset = var->yoffset;
    model->page_flips++;
    model->software_base_update_acks++;
    return 0;
}

static inline int guest_fb0_validate_mmap(uint32_t length, uint32_t protection,
                                          uint32_t flags, uint32_t offset_pages) {
    if (length != guest_fb0_smem_len() || offset_pages != 0u || flags != MAP_SHARED)
        return -EINVAL;
    if ((protection & (PROT_READ | PROT_WRITE)) != (PROT_READ | PROT_WRITE) ||
        (protection & PROT_EXEC) != 0u) return -EACCES;
    return 0;
}

static inline int guest_fb0_prepare_app_private_backing(const char *directory,
                                                       const char *guest_root,
                                                       char *path, size_t path_capacity,
                                                       int *backing_fd) {
    if (!directory || !guest_root || !path || path_capacity == 0 || !backing_fd)
        return -EINVAL;
    *backing_fd = -1;
    int validated = guest_frame_channel_validate_app_private_directory(directory, guest_root);
    if (validated != 1) return validated < 0 ? validated : -EACCES;
    int dirfd = guest_frame_channel_open_private_directory(directory);
    if (dirfd < 0) return dirfd;
    int fd = openat(dirfd, GUEST_FB0_BACKING_FILE,
                    O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
    int saved = errno;
    if (fd < 0) { close(dirfd); return -saved; }
    struct stat st;
    int rc = 0;
    if (fstat(fd, &st) != 0) rc = -errno;
    else if (!S_ISREG(st.st_mode) || st.st_uid != getuid() || st.st_nlink != 1)
        rc = -EACCES;
    else if (fchmod(fd, 0600) != 0) rc = -errno;
    else if (ftruncate(fd, 0) != 0 || ftruncate(fd, (off_t)guest_fb0_smem_len()) != 0)
        rc = -errno;
    int n = snprintf(path, path_capacity, "%s/%s", directory, GUEST_FB0_BACKING_FILE);
    if (n <= 0 || (size_t)n >= path_capacity) rc = -ENAMETOOLONG;
    if (close(dirfd) != 0 && rc == 0) rc = -errno;
    if (rc != 0) { close(fd); return rc; }
    *backing_fd = fd;
    return 0;
}

static inline int guest_fb0_capture_publish(int backing_fd,
                                            const char *frame_directory,
                                            struct guest_framebuffer_model *model,
                                            uint32_t yoffset) {
    if (backing_fd < 0 || !frame_directory || !model ||
        yoffset > model->yres_virtual - model->yres) return -EINVAL;
    uint64_t byte_offset = (uint64_t)yoffset * guest_fb0_line_length();
    uint64_t frame_length = (uint64_t)guest_fb0_line_length() * model->yres;
    if (byte_offset + frame_length > guest_fb0_smem_len() ||
        frame_length > GUEST_FB0_MAX_CAPTURE_BYTES || frame_length > SIZE_MAX)
        return -EOVERFLOW;
    unsigned char *pixels = (unsigned char *)malloc((size_t)frame_length);
    if (!pixels) return -ENOMEM;
    size_t received = 0;
    while (received < (size_t)frame_length) {
        ssize_t amount = pread(backing_fd, pixels + received,
                               (size_t)frame_length - received,
                               (off_t)(byte_offset + received));
        if (amount < 0) {
            if (errno == EINTR) continue;
            int saved = errno; free(pixels); return -saved;
        }
        if (amount == 0) { free(pixels); return -EIO; }
        received += (size_t)amount;
    }
    guest_frame_packet packet = {
        .source = GUEST_FRAME_SOURCE_GUEST_FRAMEBUFFER,
        .width = model->xres,
        .height = model->yres,
        .stride = guest_fb0_line_length(),
        .bits_per_pixel = GUEST_FB0_BPP,
        .red = {.offset = 11, .length = 5, .msb_right = 0},
        .green = {.offset = 5, .length = 6, .msb_right = 0},
        .blue = {.offset = 0, .length = 5, .msb_right = 0},
        .transparency = {.offset = 0, .length = 0, .msb_right = 0},
        .sequence = model->sequence + 1u,
        .pixels = pixels,
    };
    int rc = guest_frame_channel_publish_file(frame_directory, &packet);
    free(pixels);
    if (rc == 0) {
        model->sequence++;
        model->published++;
    }
    return rc;
}

#endif
