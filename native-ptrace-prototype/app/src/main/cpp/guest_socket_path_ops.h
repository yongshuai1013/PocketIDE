#ifndef GINGERVM_GUEST_SOCKET_PATH_OPS_H
#define GINGERVM_GUEST_SOCKET_PATH_OPS_H

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

static inline int guest_socket_path_within_root(const char *path, const char *root) {
    size_t n = strlen(root);
    return strncmp(path, root, n) == 0 && (path[n] == '\0' || path[n] == '/');
}

static inline int guest_socket_marker_has_dot_component(const char *path) {
    const char *p = path;
    while (*p) {
        while (*p == '/') ++p;
        const char *start = p;
        while (*p && *p != '/') ++p;
        size_t n = (size_t)(p - start);
        if ((n == 1 && start[0] == '.') ||
            (n == 2 && start[0] == '.' && start[1] == '.')) return 1;
    }
    return 0;
}

/* Create a regular app-private path marker only. This does not create a host socket. */
static inline int guest_socket_marker_create_app_private(const char *path,
                                                          const char *guest_root) {
    if (!path || path[0] != '/' || guest_socket_marker_has_dot_component(path) ||
        !guest_root || guest_root[0] != '/') return -EACCES;

    char canonical_root[PATH_MAX];
    if (!realpath(guest_root, canonical_root)) return -errno;
    if (!guest_socket_path_within_root(path, canonical_root)) return -EACCES;

    char parent[PATH_MAX];
    size_t path_length = strlen(path);
    if (path_length >= sizeof(parent)) return -ENAMETOOLONG;
    memcpy(parent, path, path_length + 1);
    char *slash = strrchr(parent, '/');
    if (!slash || slash[1] == '\0') return -EINVAL;
    const char *leaf = slash + 1;
    if (strcmp(leaf, ".") == 0 || strcmp(leaf, "..") == 0) return -EACCES;
    if (slash == parent) parent[1] = '\0';
    else *slash = '\0';

    char resolved_parent[PATH_MAX];
    if (!realpath(parent, resolved_parent)) return -errno;
    if (!guest_socket_path_within_root(resolved_parent, canonical_root)) return -EACCES;

    int dirfd = open(resolved_parent, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (dirfd < 0) return -errno;
    char fd_path[64], opened_parent[PATH_MAX];
    int n = snprintf(fd_path, sizeof(fd_path), "/proc/self/fd/%d", dirfd);
    if (n <= 0 || (size_t)n >= sizeof(fd_path)) {
        (void)close(dirfd);
        return -ENAMETOOLONG;
    }
    if (!realpath(fd_path, opened_parent) ||
        !guest_socket_path_within_root(opened_parent, canonical_root)) {
        int saved = errno;
        (void)close(dirfd);
        return saved ? -saved : -EACCES;
    }

    int marker = openat(dirfd, leaf,
                        O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
                        0600);
    if (marker < 0) {
        int rc = -errno;
        (void)close(dirfd);
        return rc;
    }
    struct stat st;
    int result = 0;
    if (fstat(marker, &st) != 0) result = -errno;
    else if (!S_ISREG(st.st_mode)) result = -EACCES;
    (void)close(marker);
    if (result != 0) (void)unlinkat(dirfd, leaf, 0);
    (void)close(dirfd);
    return result;
}

#endif
