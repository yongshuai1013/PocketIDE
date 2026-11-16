#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "../app/src/main/cpp/guest_path_fd.h"
#include "../app/src/main/cpp/init_broker.h"

static void make_dir(const char *path) {
    assert(mkdir(path, 0700) == 0 || errno == EEXIST);
}

int main(void) {
    struct guest_path_fd_table table;
    guest_path_fd_table_init(&table);
    assert(guest_path_fd_track(&table, 2, 10, "/sys/devices/virtual/gingervm") == 0);
    char resolved[PATH_MAX];
    assert(guest_path_resolve_at(&table, 2, 10, "/", "uevent", resolved, sizeof(resolved)) == 0);
    assert(strcmp(resolved, "/sys/devices/virtual/gingervm/uevent") == 0);
    assert(guest_path_resolve_at(&table, 2, GUEST_AT_FDCWD, "/sys",
                                 "devices/virtual/gingervm/uevent", resolved,
                                 sizeof(resolved)) == 0);
    assert(strcmp(resolved, "/sys/devices/virtual/gingervm/uevent") == 0);
    assert(guest_path_resolve_at(&table, 2, 99, "/", "uevent", resolved,
                                 sizeof(resolved)) == -EBADF);
    assert(guest_path_resolve_at(&table, 2, 10, "/", "../outside", resolved,
                                 sizeof(resolved)) == -EACCES);
    assert(guest_path_resolve_at(&table, 2, GUEST_AT_FDCWD, "/sys",
                                 "devices/../../outside", resolved,
                                 sizeof(resolved)) == -EACCES);
    assert(guest_path_resolve_at(&table, 2, GUEST_AT_FDCWD, "/",
                                 "/sys/./devices//virtual/gingervm", resolved,
                                 sizeof(resolved)) == 0);
    assert(strcmp(resolved, "/sys/devices/virtual/gingervm") == 0);
    assert(guest_path_resolve_at(&table, 3, 10, "/", "uevent", resolved,
                                 sizeof(resolved)) == -EBADF);
    assert(guest_path_fd_clone_owner(&table, 2, 3) == 0);
    assert(guest_path_resolve_at(&table, 3, 10, "/", "uevent", resolved,
                                 sizeof(resolved)) == 0);
    assert(strcmp(resolved, "/sys/devices/virtual/gingervm/uevent") == 0);
    guest_path_fd_remove(&table, 3, 10);
    assert(guest_path_resolve_at(&table, 3, 10, "/", "uevent", resolved,
                                 sizeof(resolved)) == -EBADF);
    assert(guest_path_resolve_at(&table, 2, 10, "/", "uevent", resolved,
                                 sizeof(resolved)) == 0);

    char base[] = "/tmp/gingervm-path-fd-XXXXXX";
    char *tmp = mkdtemp(base);
    assert(tmp != NULL);
    char root[PATH_MAX], outside[PATH_MAX], sys[PATH_MAX], devices[PATH_MAX];
    char virtual_dir[PATH_MAX], guest_dir[PATH_MAX], escape_link[PATH_MAX], outside_file[PATH_MAX];
    assert(snprintf(root, sizeof(root), "%s/guest", tmp) > 0);
    assert(snprintf(outside, sizeof(outside), "%s/outside", tmp) > 0);
    assert(snprintf(sys, sizeof(sys), "%s/sys", root) > 0);
    assert(snprintf(devices, sizeof(devices), "%s/devices", sys) > 0);
    assert(snprintf(virtual_dir, sizeof(virtual_dir), "%s/virtual", devices) > 0);
    assert(snprintf(guest_dir, sizeof(guest_dir), "%s/gingervm", virtual_dir) > 0);
    assert(snprintf(escape_link, sizeof(escape_link), "%s/escape", guest_dir) > 0);
    assert(snprintf(outside_file, sizeof(outside_file), "%s/secret", outside) > 0);
    make_dir(root); make_dir(outside); make_dir(sys); make_dir(devices);
    make_dir(virtual_dir); make_dir(guest_dir);
    FILE *file = fopen(outside_file, "w");
    assert(file != NULL); fputs("outside", file); fclose(file);
    assert(symlink(outside, escape_link) == 0);
    assert(guest_path_fd_track(&table, 2, 11,
        "/sys/devices/virtual/gingervm") == 0);
    assert(guest_path_resolve_at(&table, 2, 11, "/", "escape/secret",
                                 resolved, sizeof(resolved)) == 0);
    assert(strcmp(resolved, "/sys/devices/virtual/gingervm/escape/secret") == 0);
    char host[PATH_MAX];
    assert(guest_path_to_host(root, resolved, host, sizeof(host)) == -EACCES);

    unlink(escape_link); unlink(outside_file);
    rmdir(guest_dir); rmdir(virtual_dir); rmdir(devices); rmdir(sys);
    rmdir(outside); rmdir(root); rmdir(tmp);
    puts("guest dirfd path regression: PASS (relative resolution, guest-owner isolation, fork inheritance, .. and symlink escapes denied)");
    return 0;
}
