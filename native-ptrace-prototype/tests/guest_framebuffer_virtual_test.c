#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include "../app/src/main/cpp/guest_framebuffer_virtual.h"
#include "../app/src/main/cpp/guest_pseudo_device.h"

static void join(char *out, size_t capacity, const char *parent, const char *leaf) {
    int n = snprintf(out, capacity, "%s/%s", parent, leaf);
    assert(n > 0 && (size_t)n < capacity);
}

static void read_exact(int fd, unsigned char *bytes, size_t length) {
    size_t done = 0;
    while (done < length) {
        ssize_t n = read(fd, bytes + done, length - done);
        assert(n > 0);
        done += (size_t)n;
    }
}

int main(int argc, char **argv) {
    assert(argc == 2 || argc == 3);
    int keep_packet = argc == 3 && strcmp(argv[2], "--keep-packet") == 0;
    assert(argc == 2 || keep_packet);
    const char *root = argv[1];
    assert(root[0] == '/');
    assert(mkdir(root, 0700) == 0);
    char guest_root[PATH_MAX], frame_dir[PATH_MAX], backing_path[PATH_MAX];
    char packet_path[PATH_MAX], linked_dir[PATH_MAX], target_file[PATH_MAX];
    join(guest_root, sizeof(guest_root), root, "guest-root");
    join(frame_dir, sizeof(frame_dir), root, GUEST_FRAME_CHANNEL_DIRECTORY);
    join(linked_dir, sizeof(linked_dir), root, "linked-display");
    join(target_file, sizeof(target_file), root, "outside-target");
    assert(mkdir(guest_root, 0700) == 0);
    assert(mkdir(frame_dir, 0700) == 0);
    assert(guest_frame_channel_validate_app_private_directory(frame_dir, guest_root) == 1);
    assert(symlink(frame_dir, linked_dir) == 0);
    assert(guest_frame_channel_validate_app_private_directory(linked_dir, guest_root) == -EACCES);

    struct guest_framebuffer_model model;
    guest_framebuffer_model_init(&model);
    assert(model.xres == 480 && model.yres == 800 && model.yres_virtual == 1600);
    assert(guest_fb0_line_length() == 960);
    assert(guest_fb0_smem_len() == 1536000);
    assert(guest_fb0_open_ready(0, 1, 1) == -ENODEV);
    assert(guest_fb0_open_ready(1, 0, 0) == -ENOENT);
    assert(guest_fb0_open_ready(1, 1, 0) == -ENOENT);
    assert(guest_fb0_open_ready(1, 1, 1) == 0);
    assert(!guest_fb0_mknod_args_valid(1000, GUEST_FB0_OWNER_GID, 1,
                                       GUEST_FB0_MODE, guest_fb0_makedev(29, 0)));
    assert(!guest_fb0_mknod_args_valid(0, 1000, 1, GUEST_FB0_MODE,
                                       guest_fb0_makedev(29, 0)));
    assert(!guest_fb0_mknod_args_valid(0, GUEST_FB0_OWNER_GID, 0,
                                       GUEST_FB0_MODE, guest_fb0_makedev(29, 0)));
    assert(!guest_fb0_mknod_args_valid(0, GUEST_FB0_OWNER_GID, 1,
                                       GUEST_FB0_MODE, guest_fb0_makedev(29, 1)));
    assert(!guest_fb0_mknod_args_valid(0, GUEST_FB0_OWNER_GID, 1,
                                       GUEST_FB0_MODE ^ 0001u, guest_fb0_makedev(29, 0)));
    assert(guest_fb0_mknod_args_valid(0, GUEST_FB0_OWNER_GID, 1,
                                      GUEST_FB0_MODE, guest_fb0_makedev(29, 0)));
    struct guest_identity_state service_identity;
    guest_identity_init(&service_identity);
    assert(guest_identity_setgid(&service_identity, 1000) == 0);
    assert(guest_identity_setuid(&service_identity, 1000) == 0);
    assert(guest_fb0_open_authorized(1, 1, 1, &service_identity, O_RDWR) == -EACCES);
    guest_identity_init(&service_identity);
    const uint32_t surfaceflinger_groups[] = {GUEST_ID_AID_GRAPHICS};
    assert(guest_identity_setgroups(&service_identity, 0, surfaceflinger_groups, 1) == 0);
    assert(guest_identity_setgid(&service_identity, 1000) == 0);
    assert(guest_identity_setuid(&service_identity, 1000) == 0);
    assert(guest_fb0_open_authorized(1, 1, 1, &service_identity, O_RDWR) == 0);
    assert(sizeof(struct guest_arm32_fb_bitfield) == 12);
    assert(sizeof(struct guest_arm32_fb_var_screeninfo) == 160);
    assert(sizeof(struct guest_arm32_fb_fix_screeninfo) == 68);

    struct guest_arm32_fb_var_screeninfo var;
    guest_fb0_make_var(&model, &var);
    assert(var.xres == 480 && var.yres == 800 && var.xres_virtual == 480);
    assert(var.yres_virtual == 1600 && var.bits_per_pixel == 16);
    assert(var.red.offset == 11 && var.red.length == 5);
    assert(var.green.offset == 5 && var.green.length == 6);
    assert(var.blue.offset == 0 && var.blue.length == 5);
    assert(guest_fb0_validate_put(&model, &var) == 0);
    assert(guest_fb0_commit_put(&model, &var) == 0);
    var.xres = 320;
    assert(guest_fb0_validate_put(&model, &var) == -EINVAL);
    guest_fb0_make_var(&model, &var);
    var.bits_per_pixel = 32;
    assert(guest_fb0_validate_put(&model, &var) == -EINVAL);
    guest_fb0_make_var(&model, &var);

    struct guest_arm32_fb_fix_screeninfo fix;
    guest_fb0_make_fix(&model, &fix);
    assert(fix.smem_start == 0 && fix.smem_len == 1536000);
    assert(fix.type == GUEST_FB0_TYPE_PACKED_PIXELS);
    assert(fix.visual == GUEST_FB0_VISUAL_TRUECOLOR && fix.ypanstep == 1);
    assert(fix.line_length == 960);
    assert(guest_fb0_validate_mmap(1536000, PROT_READ | PROT_WRITE,
                                   MAP_SHARED, 0) == 0);
    assert(guest_fb0_validate_mmap(1536000, PROT_READ | PROT_WRITE,
                                   MAP_PRIVATE, 0) == -EINVAL);
    assert(guest_fb0_validate_mmap(1536000, PROT_READ | PROT_WRITE | PROT_EXEC,
                                   MAP_SHARED, 0) == -EACCES);
    assert(guest_fb0_validate_mmap(768000, PROT_READ | PROT_WRITE,
                                   MAP_SHARED, 0) == -EINVAL);
    assert(guest_fb0_validate_mmap(1536000, PROT_READ | PROT_WRITE,
                                   MAP_SHARED, 1) == -EINVAL);

    int backing_fd = -1;
    assert(guest_fb0_prepare_app_private_backing(frame_dir, guest_root,
        backing_path, sizeof(backing_path), &backing_fd) == 0);
    assert(backing_fd >= 0);
    struct stat backing_stat;
    assert(fstat(backing_fd, &backing_stat) == 0);
    assert(S_ISREG(backing_stat.st_mode) && backing_stat.st_uid == getuid());
    assert((backing_stat.st_mode & 0777) == 0600 && backing_stat.st_nlink == 1);
    assert(backing_stat.st_size == (off_t)guest_fb0_smem_len());
    assert(guest_fb0_fd_matches_proc(getpid(), backing_fd, &backing_stat));

    /* A symlink at the private backing leaf must never be followed. */
    assert(close(backing_fd) == 0);
    backing_fd = -1;
    assert(unlink(backing_path) == 0);
    int outside = open(target_file, O_CREAT | O_RDWR | O_CLOEXEC, 0600);
    assert(outside >= 0 && close(outside) == 0);
    assert(symlink(target_file, backing_path) == 0);
    int rejected_fd = -1;
    assert(guest_fb0_prepare_app_private_backing(frame_dir, guest_root,
        backing_path, sizeof(backing_path), &rejected_fd) == -ELOOP);
    assert(rejected_fd == -1);
    assert(unlink(backing_path) == 0);
    assert(guest_fb0_prepare_app_private_backing(frame_dir, guest_root,
        backing_path, sizeof(backing_path), &backing_fd) == 0);

    size_t buffer_bytes = guest_fb0_smem_len();
    unsigned char *mapping = mmap(NULL, buffer_bytes, PROT_READ | PROT_WRITE,
                                  MAP_SHARED, backing_fd, 0);
    assert(mapping != MAP_FAILED);
    const size_t second_buffer = GUEST_PROFILE_DISPLAY_HEIGHT * guest_fb0_line_length();
    const unsigned char four_rgb565_pixels[] = {
        0x00, 0xf8, /* red */ 0xe0, 0x07, /* green */
        0x1f, 0x00, /* blue */ 0xff, 0xff /* white */
    };
    memcpy(mapping + second_buffer, four_rgb565_pixels, sizeof(four_rgb565_pixels));
    assert(msync(mapping, buffer_bytes, MS_SYNC) == 0);

    guest_fb0_make_var(&model, &var);
    var.yoffset = GUEST_PROFILE_DISPLAY_HEIGHT;
    assert(guest_fb0_validate_pan(&model, &var) == 0);
    assert(guest_fb0_commit_pan(&model, &var) == 0);
    assert(model.yoffset == 800 && model.page_flips == 1 &&
           model.software_base_update_acks == 1);
    assert(guest_fb0_capture_publish(backing_fd, frame_dir, &model,
                                     model.yoffset) == 0);
    assert(model.sequence == 1 && model.published == 1);

    join(packet_path, sizeof(packet_path), frame_dir, GUEST_FRAME_CHANNEL_FILE);
    int packet_fd = open(packet_path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    assert(packet_fd >= 0);
    struct stat packet_stat;
    assert(fstat(packet_fd, &packet_stat) == 0 && S_ISREG(packet_stat.st_mode));
    assert(packet_stat.st_size == GUEST_FRAME_PROTOCOL_HEADER_BYTES + 768000);
    unsigned char header[GUEST_FRAME_PROTOCOL_HEADER_BYTES];
    read_exact(packet_fd, header, sizeof(header));
    assert(memcmp(header, "GVMF", 4) == 0);
    assert(header[8] == GUEST_FRAME_SOURCE_GUEST_FRAMEBUFFER);
    assert(header[12] == 0xe0 && header[13] == 0x01); /* width=480 */
    assert(header[16] == 0x20 && header[17] == 0x03); /* height=800 */
    assert(header[20] == 0xc0 && header[21] == 0x03); /* stride=960 */
    unsigned char pixels[sizeof(four_rgb565_pixels)];
    read_exact(packet_fd, pixels, sizeof(pixels));
    assert(memcmp(pixels, four_rgb565_pixels, sizeof(pixels)) == 0);
    assert(close(packet_fd) == 0);

    assert(guest_fb0_commit_pan(&model, &var) == 0);
    assert(model.yoffset == 800 && model.page_flips == 2 &&
           model.software_base_update_acks == 2);
    var.yoffset = 801;
    assert(guest_fb0_validate_pan(&model, &var) == -EINVAL);

    struct guest_pseudo_device_metadata metadata;
    assert(guest_pseudo_device_metadata_for_path(GUEST_FB0_PATH, &metadata) == 1);
    assert(metadata.kind == VIRTUAL_FD_DEV_FRAMEBUFFER);
    assert(metadata.mode == GUEST_FB0_MODE && metadata.uid == 0 && metadata.gid == 1003);
    assert(metadata.major == 29 && metadata.minor == 0);

    assert(munmap(mapping, buffer_bytes) == 0);
    assert(close(backing_fd) == 0);
    if (!keep_packet) {
        assert(unlink(packet_path) == 0);
        assert(unlink(backing_path) == 0);
        assert(unlink(target_file) == 0);
        assert(unlink(linked_dir) == 0);
        assert(rmdir(frame_dir) == 0);
        assert(rmdir(guest_root) == 0);
        assert(rmdir(root) == 0);
    } else {
        assert(unlink(backing_path) == 0);
        assert(unlink(target_file) == 0);
        assert(unlink(linked_dir) == 0);
        assert(rmdir(guest_root) == 0);
    }
    puts("guest framebuffer regression: PASS (ARM32 ABI, Goldfish WVGA800 RGB565 double-buffer model, no-follow app-private backing, MAP_SHARED bytes -> page-flip -> GVMF/1 packet)");
    return 0;
}
