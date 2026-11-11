#ifndef GINGERVM_GUEST_SYMLINK_OPS_H
#define GINGERVM_GUEST_SYMLINK_OPS_H

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

static inline int guest_symlink_path_within_root(const char *path, const char *root) {
    size_t n = strlen(root);
    return strncmp(path, root, n) == 0 && (path[n] == '\0' || path[n] == '/');
}

static inline int guest_symlink_has_dot_component(const char *path) {
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

static inline int guest_symlink_path_allowed(const char *path, const char *guest_root,
                                              const char *native_root) {
    return guest_symlink_path_within_root(path, guest_root) ||
           (native_root && native_root[0] && guest_symlink_path_within_root(path, native_root));
}

/* Resolve a possibly dangling target through its deepest existing ancestor.
 * Existing symlinks are followed and must end within one of the app-private roots. */
static inline int guest_symlink_resolve_target(const char *path, const char *guest_root,
                                                const char *native_root, char *resolved,
                                                size_t capacity) {
    if (!path || path[0] != '/' || guest_symlink_has_dot_component(path) ||
        !guest_root || guest_root[0] != '/' || capacity == 0) return -EACCES;

    char canonical_guest_root[PATH_MAX];
    if (!realpath(guest_root, canonical_guest_root)) return -errno;
    char canonical_native_root[PATH_MAX] = "";
    if (native_root && native_root[0] && !realpath(native_root, canonical_native_root))
        return -errno;

    char candidate[PATH_MAX];
    if (strlen(path) >= sizeof(candidate)) return -ENAMETOOLONG;
    strcpy(candidate, path);
    char suffix[PATH_MAX] = "";
    for (;;) {
        char existing[PATH_MAX];
        if (realpath(candidate, existing)) {
            if (!guest_symlink_path_allowed(existing, canonical_guest_root, canonical_native_root))
                return -EACCES;
            int n = suffix[0] == '\0'
                ? snprintf(resolved, capacity, "%s", existing)
                : snprintf(resolved, capacity, "%s/%s", existing, suffix);
            if (n <= 0 || (size_t)n >= capacity) return -ENAMETOOLONG;
            if (!guest_symlink_path_allowed(resolved, canonical_guest_root, canonical_native_root))
                return -EACCES;
            return 0;
        }
        if (errno != ENOENT && errno != ENOTDIR) return -errno;
        char *slash = strrchr(candidate, '/');
        if (!slash) return -EACCES;
        const char *tail = slash + 1;
        if (*tail == '\0') return -EACCES;
        char combined[PATH_MAX];
        int n = suffix[0] == '\0'
            ? snprintf(combined, sizeof(combined), "%s", tail)
            : snprintf(combined, sizeof(combined), "%s/%s", tail, suffix);
        if (n <= 0 || (size_t)n >= sizeof(combined)) return -ENAMETOOLONG;
        strcpy(suffix, combined);
        if (slash == candidate) candidate[1] = '\0';
        else *slash = '\0';
    }
}

/* Create a host symlink only inside the app-private guest tree. The target may
 * resolve under the guest root or the APK-extracted guest payload root; the link
 * itself must be placed under the guest root. The opened parent fd pins the
 * checked directory, and its /proc/self/fd path is rechecked before symlinkat. */
static inline int guest_symlink_create_app_private(const char *target_path,
                                                    const char *link_path,
                                                    const char *guest_root,
                                                    const char *native_root) {
    if (!target_path || !link_path || link_path[0] != '/' ||
        guest_symlink_has_dot_component(link_path) ||
        !guest_root || guest_root[0] != '/') return -EACCES;

    char canonical_guest_root[PATH_MAX];
    if (!realpath(guest_root, canonical_guest_root)) return -errno;
    char resolved_target[PATH_MAX];
    int rc = guest_symlink_resolve_target(target_path, canonical_guest_root, native_root,
                                          resolved_target, sizeof(resolved_target));
    if (rc != 0) return rc;

    char parent[PATH_MAX];
    if (strlen(link_path) >= sizeof(parent)) return -ENAMETOOLONG;
    strcpy(parent, link_path);
    char *slash = strrchr(parent, '/');
    if (!slash || slash[1] == '\0' || strcmp(slash + 1, ".") == 0 ||
        strcmp(slash + 1, "..") == 0) return -EINVAL;
    const char *leaf = slash + 1;
    if (slash == parent) parent[1] = '\0';
    else *slash = '\0';

    char resolved_parent[PATH_MAX];
    if (!realpath(parent, resolved_parent)) return -errno;
    if (!guest_symlink_path_within_root(resolved_parent, canonical_guest_root)) return -EACCES;

    int dirfd = open(resolved_parent, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (dirfd < 0) return -errno;
    char fd_path[64], opened_parent[PATH_MAX];
    int n = snprintf(fd_path, sizeof(fd_path), "/proc/self/fd/%d", dirfd);
    if (n <= 0 || (size_t)n >= sizeof(fd_path)) {
        (void)close(dirfd);
        return -ENAMETOOLONG;
    }
    if (!realpath(fd_path, opened_parent) ||
        !guest_symlink_path_within_root(opened_parent, canonical_guest_root)) {
        int saved = errno;
        (void)close(dirfd);
        return saved ? -saved : -EACCES;
    }

    int result = symlinkat(resolved_target, dirfd, leaf) == 0 ? 0 : -errno;
    (void)close(dirfd);
    return result;
}

#endif
