#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "../app/src/main/cpp/guest_frame_channel.h"

static int read_exact(int fd, unsigned char *buffer, size_t size) {
    size_t read_bytes = 0;
    while (read_bytes < size) {
        ssize_t n = read(fd, buffer + read_bytes, size - read_bytes);
        if (n <= 0) return -1;
        read_bytes += (size_t)n;
    }
    return 0;
}

static void join_path(char *out, size_t capacity, const char *directory, const char *leaf) {
    size_t directory_length = strlen(directory);
    size_t leaf_length = strlen(leaf);
    assert(directory_length + leaf_length + 2 <= capacity);
    memcpy(out, directory, directory_length);
    out[directory_length] = '/';
    memcpy(out + directory_length + 1, leaf, leaf_length + 1);
}

int main(int argc, char **argv) {
    assert(argc == 2);
    const char *root = argv[1];
    assert(root[0] == '/' && strlen(root) < PATH_MAX - 64);
    assert(mkdir(root, 0700) == 0);
    char guest_root[PATH_MAX], frame_dir[PATH_MAX], wrong_dir[PATH_MAX];
    char link_dir[PATH_MAX], target_dir[PATH_MAX], frame_file[PATH_MAX];
    char linked_parent[PATH_MAX], linked_guest_root[PATH_MAX], linked_expected[PATH_MAX];
    char alias_area[PATH_MAX], alias_shared[PATH_MAX], alias_link[PATH_MAX];
    char alias_guest_root[PATH_MAX], alias_frame_dir[PATH_MAX], alias_frame_alias[PATH_MAX];
    char outside_parent[PATH_MAX], outside_frame_dir[PATH_MAX], outside_alias[PATH_MAX];
    char symlink_guest_root[PATH_MAX], symlink_root_parent[PATH_MAX];
    join_path(guest_root, sizeof(guest_root), root, "guest-root");
    join_path(frame_dir, sizeof(frame_dir), root, GUEST_FRAME_CHANNEL_DIRECTORY);
    join_path(wrong_dir, sizeof(wrong_dir), root, "wrong");
    join_path(link_dir, sizeof(link_dir), root, "linked-display");
    join_path(target_dir, sizeof(target_dir), root, "target");
    assert(mkdir(guest_root, 0700) == 0);
    assert(mkdir(frame_dir, 0700) == 0);
    assert(mkdir(wrong_dir, 0700) == 0);
    assert(mkdir(target_dir, 0700) == 0);
    assert(guest_frame_channel_validate_app_private_directory(frame_dir, guest_root) == 1);
    struct guest_frame_channel_validation_detail detail;
    assert(guest_frame_channel_validate_app_private_directory_ex(
        frame_dir, guest_root, getuid(), &detail) == 1);
    assert(detail.reason == GUEST_FRAME_CHANNEL_VALID && detail.has_stat);
    assert(detail.actual_owner == getuid() && (detail.actual_mode & 0077) == 0);
    assert(strcmp(detail.expected_path, frame_dir) == 0);
    assert(guest_frame_channel_validate_app_private_directory_ex(
        wrong_dir, guest_root, getuid(), &detail) == -EACCES);
    assert(detail.reason == GUEST_FRAME_CHANNEL_NOT_EXACT_SIBLING);
    assert(strcmp(detail.expected_path, frame_dir) == 0);

    /* Android may spell the same app-private files directory through /data/data
       and /data/user/0. Accept only when opened parent directory identities match. */
    join_path(alias_area, sizeof(alias_area), root, "alias-area");
    join_path(alias_shared, sizeof(alias_shared), alias_area, "shared");
    join_path(alias_link, sizeof(alias_link), root, "alias-parent");
    join_path(alias_guest_root, sizeof(alias_guest_root), alias_shared, "guest-root");
    join_path(alias_frame_dir, sizeof(alias_frame_dir), alias_shared,
              GUEST_FRAME_CHANNEL_DIRECTORY);
    assert(mkdir(alias_area, 0700) == 0);
    assert(mkdir(alias_shared, 0700) == 0);
    assert(mkdir(alias_guest_root, 0700) == 0);
    assert(mkdir(alias_frame_dir, 0700) == 0);
    assert(symlink(alias_area, alias_link) == 0);
    char alias_shared_path[PATH_MAX];
    join_path(alias_shared_path, sizeof(alias_shared_path), alias_link, "shared");
    join_path(alias_frame_alias, sizeof(alias_frame_alias), alias_shared_path,
              GUEST_FRAME_CHANNEL_DIRECTORY);
    assert(strcmp(alias_frame_alias, alias_frame_dir) != 0);
    assert(guest_frame_channel_validate_app_private_directory_ex(
        alias_frame_alias, alias_guest_root, getuid(), &detail) == 1);
    assert(detail.reason == GUEST_FRAME_CHANNEL_VALID && detail.has_stat);
    assert(strcmp(detail.expected_path, alias_frame_dir) == 0);
    int alias_frame_fd = guest_frame_channel_open_app_private_sibling_ex(
        alias_frame_alias, alias_guest_root, getuid(), &detail);
    assert(alias_frame_fd >= 0);
    struct stat alias_frame_stat;
    assert(fstat(alias_frame_fd, &alias_frame_stat) == 0 && S_ISDIR(alias_frame_stat.st_mode));
    assert(alias_frame_stat.st_uid == getuid() && (alias_frame_stat.st_mode & 0077) == 0);
    assert(close(alias_frame_fd) == 0);

    join_path(outside_parent, sizeof(outside_parent), root, "outside-private");
    join_path(outside_frame_dir, sizeof(outside_frame_dir), outside_parent,
              GUEST_FRAME_CHANNEL_DIRECTORY);
    join_path(outside_alias, sizeof(outside_alias), root, "outside-alias");
    assert(mkdir(outside_parent, 0700) == 0);
    assert(mkdir(outside_frame_dir, 0700) == 0);
    assert(guest_frame_channel_validate_app_private_directory_ex(
        outside_frame_dir, alias_guest_root, getuid(), &detail) == -EACCES);
    assert(detail.reason == GUEST_FRAME_CHANNEL_NOT_EXACT_SIBLING);
    assert(symlink(outside_parent, outside_alias) == 0);
    char outside_symlink_frame[PATH_MAX];
    join_path(outside_symlink_frame, sizeof(outside_symlink_frame), outside_alias,
              GUEST_FRAME_CHANNEL_DIRECTORY);
    assert(guest_frame_channel_validate_app_private_directory_ex(
        outside_symlink_frame, alias_guest_root, getuid(), &detail) < 0);
    assert(detail.reason == GUEST_FRAME_CHANNEL_OPEN_FAILED);

    char traversal_frame[PATH_MAX];
    int traversal_length = snprintf(traversal_frame, sizeof(traversal_frame),
        "%s/../%s", alias_shared, GUEST_FRAME_CHANNEL_DIRECTORY);
    assert(traversal_length > 0 && (size_t)traversal_length < sizeof(traversal_frame));
    assert(guest_frame_channel_validate_app_private_directory_ex(
        traversal_frame, alias_guest_root, getuid(), &detail) == -EACCES);

    join_path(symlink_root_parent, sizeof(symlink_root_parent), root, "symlink-root-parent");
    join_path(symlink_guest_root, sizeof(symlink_guest_root), symlink_root_parent, "guest-root");
    char symlink_root_frame[PATH_MAX];
    join_path(symlink_root_frame, sizeof(symlink_root_frame), symlink_root_parent,
              GUEST_FRAME_CHANNEL_DIRECTORY);
    assert(mkdir(symlink_root_parent, 0700) == 0);
    assert(mkdir(symlink_root_frame, 0700) == 0);
    assert(symlink(target_dir, symlink_guest_root) == 0);
    assert(guest_frame_channel_validate_app_private_directory_ex(
        symlink_root_frame, symlink_guest_root, getuid(), &detail) < 0);
    assert(detail.reason == GUEST_FRAME_CHANNEL_OPEN_FAILED);

    uid_t wrong_owner = getuid() == 0 ? 1u : 0u;
    assert(guest_frame_channel_validate_app_private_directory_ex(
        frame_dir, guest_root, wrong_owner, &detail) == -EACCES);
    assert(detail.reason == GUEST_FRAME_CHANNEL_WRONG_OWNER);
    assert(!detail.has_stat && detail.expected_owner == wrong_owner);
    assert(chmod(frame_dir, 0755) == 0);
    assert(guest_frame_channel_validate_app_private_directory_ex(
        frame_dir, guest_root, getuid(), &detail) == -EACCES);
    assert(detail.reason == GUEST_FRAME_CHANNEL_NOT_PRIVATE);
    assert((detail.actual_mode & 0077) == 0055);
    assert(chmod(frame_dir, 0700) == 0);
    assert(symlink(target_dir, link_dir) == 0);
    assert(guest_frame_channel_open_private_directory(link_dir) < 0);
    join_path(linked_parent, sizeof(linked_parent), root, "linked-root");
    join_path(linked_guest_root, sizeof(linked_guest_root), linked_parent, "guest-root");
    join_path(linked_expected, sizeof(linked_expected), linked_parent,
              GUEST_FRAME_CHANNEL_DIRECTORY);
    assert(mkdir(linked_parent, 0700) == 0);
    assert(mkdir(linked_guest_root, 0700) == 0);
    assert(symlink(target_dir, linked_expected) == 0);
    assert(guest_frame_channel_validate_app_private_directory_ex(
        linked_expected, linked_guest_root, getuid(), &detail) < 0);
    assert(detail.reason == GUEST_FRAME_CHANNEL_OPEN_FAILED);
    assert(detail.error_number != 0);

    static const unsigned char rgb565[] = {
        0x00, 0xf8, /* red */ 0xe0, 0x07, /* green */
        0x1f, 0x00, /* blue */ 0xff, 0xff /* white */
    };
    guest_frame_packet frame;
    memset(&frame, 0, sizeof(frame));
    frame.source = GUEST_FRAME_SOURCE_GUEST_FRAMEBUFFER;
    frame.width = 2;
    frame.height = 2;
    frame.stride = 4;
    frame.bits_per_pixel = 16;
    frame.red = (guest_frame_bitfield){11, 5, 0};
    frame.green = (guest_frame_bitfield){5, 6, 0};
    frame.blue = (guest_frame_bitfield){0, 5, 0};
    frame.sequence = 7;
    frame.pixels = rgb565;
    assert(guest_frame_channel_publish_file(frame_dir, &frame) == 0);
    int stable_frame_fd = guest_frame_channel_open_app_private_sibling_ex(
        frame_dir, guest_root, getuid(), &detail);
    assert(stable_frame_fd >= 0);
    assert(guest_frame_channel_publish_file_at(stable_frame_fd, &frame) == 0);
    assert(close(stable_frame_fd) == 0);

    join_path(frame_file, sizeof(frame_file), frame_dir, GUEST_FRAME_CHANNEL_FILE);
    int fd = open(frame_file, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    assert(fd >= 0);
    struct stat st;
    assert(fstat(fd, &st) == 0 && S_ISREG(st.st_mode) && st.st_uid == getuid());
    assert((st.st_mode & 0777) == 0600);
    assert(st.st_size == GUEST_FRAME_PROTOCOL_HEADER_BYTES + sizeof(rgb565));
    unsigned char bytes[GUEST_FRAME_PROTOCOL_HEADER_BYTES + sizeof(rgb565)];
    assert(read_exact(fd, bytes, sizeof(bytes)) == 0);
    close(fd);
    assert(memcmp(bytes, "GVMF", 4) == 0);
    assert(bytes[4] == 1 && bytes[6] == GUEST_FRAME_PROTOCOL_HEADER_BYTES);
    assert(bytes[8] == GUEST_FRAME_SOURCE_GUEST_FRAMEBUFFER);
    uint32_t encoded_crc = (uint32_t)bytes[56] | ((uint32_t)bytes[57] << 8) |
                          ((uint32_t)bytes[58] << 16) | ((uint32_t)bytes[59] << 24);
    assert(guest_frame_crc32(bytes + GUEST_FRAME_PROTOCOL_HEADER_BYTES, sizeof(rgb565)) == encoded_crc);
    assert(access(frame_file, F_OK) == 0);
    char temp_file[PATH_MAX];
    join_path(temp_file, sizeof(temp_file), frame_dir, GUEST_FRAME_CHANNEL_TEMP_FILE);
    assert(access(temp_file, F_OK) != 0 && errno == ENOENT);

    guest_frame_packet bad = frame;
    bad.source = GUEST_FRAME_SOURCE_TEST_ONLY;
    assert(guest_frame_channel_publish_file(frame_dir, &bad) == -EINVAL);
    bad = frame;
    bad.stride = 3;
    uint32_t payload = 0;
    assert(guest_frame_channel_profile_valid(&bad, &payload) != 0);
    bad = frame;
    bad.green.offset = 10;
    assert(guest_frame_channel_profile_valid(&bad, &payload) == -EINVAL);
    bad = frame;
    bad.width = GUEST_FRAME_MAX_PIXELS + 1u;
    assert(guest_frame_channel_profile_valid(&bad, &payload) != 0);

    char symlink_target_file[PATH_MAX];
    join_path(symlink_target_file, sizeof(symlink_target_file), target_dir, GUEST_FRAME_CHANNEL_FILE);
    assert(access(symlink_target_file, F_OK) != 0 && errno == ENOENT);

    puts("guest_frame_channel_test: PASS");
    return 0;
}
