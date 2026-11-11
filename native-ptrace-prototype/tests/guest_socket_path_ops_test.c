#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "../app/src/main/cpp/guest_socket_path_ops.h"

static void mkdir_ok(const char *path) {
    assert(mkdir(path, 0700) == 0 || errno == EEXIST);
}

int main(void) {
    char tmp_template[] = "/tmp/gingervm-property-socket-path-XXXXXX";
    char *tmp = mkdtemp(tmp_template);
    assert(tmp != NULL);
    char root[512], dev[512], socket_dir[512], outside[512], link_dir[512];
    char marker[768], escaped[768], traversal[768], lookalike[768], outside_marker[768];
    assert(snprintf(root, sizeof(root), "%s/guest", tmp) > 0);
    assert(snprintf(dev, sizeof(dev), "%s/dev", root) > 0);
    assert(snprintf(socket_dir, sizeof(socket_dir), "%s/socket", dev) > 0);
    assert(snprintf(outside, sizeof(outside), "%s/outside", tmp) > 0);
    assert(snprintf(link_dir, sizeof(link_dir), "%s/dev/socket-escape", root) > 0);
    assert(snprintf(marker, sizeof(marker), "%s/property_service", socket_dir) > 0);
    assert(snprintf(escaped, sizeof(escaped), "%s/property_service", link_dir) > 0);
    assert(snprintf(traversal, sizeof(traversal), "%s/../outside/traversal", root) > 0);
    assert(snprintf(lookalike, sizeof(lookalike), "%s-evil/dev/socket/property_service", root) > 0);
    assert(snprintf(outside_marker, sizeof(outside_marker), "%s/property_service", outside) > 0);
    mkdir_ok(root);
    mkdir_ok(dev);
    mkdir_ok(socket_dir);
    mkdir_ok(outside);
    assert(symlink(outside, link_dir) == 0);

    assert(guest_socket_marker_create_app_private(marker, root) == 0);
    struct stat st;
    assert(lstat(marker, &st) == 0 && S_ISREG(st.st_mode));
    assert(guest_socket_marker_create_app_private(marker, root) == -EEXIST);
    assert(guest_socket_marker_create_app_private(escaped, root) == -EACCES);
    assert(guest_socket_marker_create_app_private(traversal, root) == -EACCES);
    assert(guest_socket_marker_create_app_private(lookalike, root) == -EACCES);
    assert(access(outside_marker, F_OK) != 0 && errno == ENOENT);

    assert(unlink(marker) == 0);
    assert(unlink(link_dir) == 0);
    assert(rmdir(socket_dir) == 0);
    assert(rmdir(dev) == 0);
    assert(rmdir(outside) == 0);
    assert(rmdir(root) == 0);
    assert(rmdir(tmp) == 0);
    puts("guest property socket path containment regression: PASS (app-private regular marker only; symlink, traversal and prefix escapes rejected)");
    return 0;
}
