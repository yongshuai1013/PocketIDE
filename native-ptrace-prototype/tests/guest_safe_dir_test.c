#define _GNU_SOURCE
#include "../app/src/main/cpp/guest_safe_dir.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void join(char *out, size_t capacity, const char *a, const char *b) {
    int n = snprintf(out, capacity, "%s/%s", a, b);
    assert(n > 0 && (size_t)n < capacity);
}

static void write_text(const char *path, const char *text) {
    int fd = open(path, O_CREAT | O_TRUNC | O_WRONLY, 0600);
    assert(fd >= 0);
    size_t length = strlen(text);
    assert(write(fd, text, length) == (ssize_t)length);
    assert(close(fd) == 0);
}

static void assert_text(const char *path, const char *expected) {
    char actual[128];
    int fd = open(path, O_RDONLY | O_NOFOLLOW);
    assert(fd >= 0);
    ssize_t count = read(fd, actual, sizeof(actual) - 1u);
    assert(count >= 0);
    actual[count] = '\0';
    assert(close(fd) == 0);
    assert(strcmp(actual, expected) == 0);
}

int main(void) {
    char base[] = "/tmp/gingervm-safe-dir-XXXXXX";
    char *workspace = mkdtemp(base);
    assert(workspace != NULL);

    char root[PATH_MAX], outside[PATH_MAX], link_path[PATH_MAX], target[PATH_MAX];
    join(root, sizeof(root), workspace, "guest-root");
    join(outside, sizeof(outside), workspace, "outside");
    assert(mkdir(root, 0700) == 0);
    assert(mkdir(outside, 0700) == 0);

    join(link_path, sizeof(link_path), root, ".vfs");
    assert(symlink(outside, link_path) == 0);
    join(target, sizeof(target), link_path, "mount-0");
    int fd = guest_safe_dir_open_beneath_root(root, target, 1, 0700);
    assert(fd == -ELOOP);
    join(target, sizeof(target), outside, "mount-0");
    assert(access(target, F_OK) != 0);
    assert(unlink(link_path) == 0);

    join(link_path, sizeof(link_path), root, ".vfs");
    assert(mkdir(link_path, 0700) == 0);
    char real_directory[PATH_MAX];
    join(real_directory, sizeof(real_directory), root, "real-target");
    assert(mkdir(real_directory, 0700) == 0);
    char second_link[PATH_MAX];
    join(second_link, sizeof(second_link), link_path, "mount-1");
    assert(symlink(real_directory, second_link) == 0);
    join(target, sizeof(target), second_link, "child");
    fd = guest_safe_dir_open_beneath_root(root, target, 1, 0700);
    assert(fd == -ELOOP);
    join(target, sizeof(target), real_directory, "child");
    assert(access(target, F_OK) != 0);

    join(target, sizeof(target), root, "../outside/escape");
    assert(guest_safe_dir_open_beneath_root(root, target, 1, 0700) == -EACCES);
    char devdir[PATH_MAX];
    join(devdir, sizeof(devdir), root, ".vfs/mount-0/dev");
    fd = guest_safe_dir_open_beneath_root(root, devdir, 1, 0700);
    assert(fd >= 0);
    close(fd);
    assert(access(devdir, F_OK) == 0);

    assert(guest_safe_file_replace_beneath_root(root, devdir, "profile",
                                                "goldfish\n", 9u, 0600) == 0);
    char file_path[PATH_MAX];
    join(file_path, sizeof(file_path), devdir, "profile");
    assert_text(file_path, "goldfish\n");
    char sentinel[PATH_MAX];
    join(sentinel, sizeof(sentinel), outside, "sentinel");
    write_text(sentinel, "untouched\n");
    char escape_file[PATH_MAX];
    join(escape_file, sizeof(escape_file), devdir, "escape");
    assert(symlink(sentinel, escape_file) == 0);
    assert(guest_safe_file_replace_beneath_root(root, devdir, "escape",
                                                "corrupt\n", 8u, 0600) == -ELOOP);
    assert_text(sentinel, "untouched\n");

    char sysdir[PATH_MAX], classdir[PATH_MAX], classnet[PATH_MAX];
    char devices[PATH_MAX], virtual_dir[PATH_MAX], netdir[PATH_MAX], eth0[PATH_MAX];
    join(sysdir, sizeof(sysdir), root, ".vfs/mount-0/sys");
    join(classdir, sizeof(classdir), sysdir, "class");
    join(classnet, sizeof(classnet), classdir, "net");
    join(devices, sizeof(devices), sysdir, "devices");
    join(virtual_dir, sizeof(virtual_dir), devices, "virtual");
    join(netdir, sizeof(netdir), virtual_dir, "net");
    join(eth0, sizeof(eth0), netdir, "eth0");
    fd = guest_safe_dir_open_beneath_root(root, classnet, 1, 0700);
    assert(fd >= 0); close(fd);
    fd = guest_safe_dir_open_beneath_root(root, eth0, 1, 0700);
    assert(fd >= 0); close(fd);
    assert(guest_safe_symlink_beneath_root(root, classnet, "eth0",
                                           "../../devices/virtual/net/eth0") == 0);
    char class_eth0[PATH_MAX], resolved[PATH_MAX];
    join(class_eth0, sizeof(class_eth0), classnet, "eth0");
    assert(realpath(class_eth0, resolved) != NULL);
    assert(strcmp(resolved, eth0) == 0);

    assert(guest_safe_symlink_beneath_root(root, classnet, "escape-link",
                                           outside) == -EACCES);
    char rejected_link[PATH_MAX];
    join(rejected_link, sizeof(rejected_link), classnet, "escape-link");
    assert(access(rejected_link, F_OK) != 0);

    assert(unlink(class_eth0) == 0);
    assert(unlink(file_path) == 0);
    assert(unlink(escape_file) == 0);
    assert(unlink(sentinel) == 0);
    assert(rmdir(classnet) == 0);
    assert(rmdir(classdir) == 0);
    assert(rmdir(eth0) == 0);
    assert(rmdir(netdir) == 0);
    assert(rmdir(virtual_dir) == 0);
    assert(rmdir(devices) == 0);
    assert(rmdir(sysdir) == 0);
    assert(rmdir(devdir) == 0);
    join(target, sizeof(target), root, ".vfs/mount-0");
    assert(rmdir(target) == 0);
    assert(unlink(second_link) == 0);
    assert(rmdir(link_path) == 0);
    assert(rmdir(real_directory) == 0);
    assert(rmdir(root) == 0);
    assert(rmdir(outside) == 0);
    assert(rmdir(workspace) == 0);
    puts("guest safe app-private filesystem regression: PASS (no-follow dirs/files, contained sysfs class symlink, outside symlink/traversal rejected, no outside writes)");
    return 0;
}
