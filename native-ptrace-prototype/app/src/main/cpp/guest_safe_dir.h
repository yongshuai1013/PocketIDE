#ifndef GINGERVM_GUEST_SAFE_DIR_H
#define GINGERVM_GUEST_SAFE_DIR_H

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* Open a guest-root directory, optionally creating missing components, without
 * following any symlink below root. Returns an owned descriptor or -errno. */
static inline int guest_safe_dir_open_beneath_root(const char *root,
                                                    const char *path,
                                                    int create,
                                                    mode_t mode) {
    char canonical_root[PATH_MAX];
    char relative[PATH_MAX];
    if (!root || !path || root[0] != '/' || path[0] != '/' ||
        !realpath(root, canonical_root)) return -EACCES;

    size_t root_length = strlen(root);
    while (root_length > 1 && root[root_length - 1] == '/') root_length--;
    if (root_length == 1 && root[0] == '/') {
        if (path[0] != '/') return -EACCES;
        if (strlen(path + 1) >= sizeof(relative)) return -ENAMETOOLONG;
        memcpy(relative, path + 1, strlen(path + 1) + 1);
    } else {
        if (strncmp(path, root, root_length) != 0 ||
            (path[root_length] != '\0' && path[root_length] != '/')) return -EACCES;
        const char *suffix = path + root_length;
        while (*suffix == '/') suffix++;
        if (strlen(suffix) >= sizeof(relative)) return -ENAMETOOLONG;
        memcpy(relative, suffix, strlen(suffix) + 1);
    }

    int current = open(canonical_root,
                       O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (current < 0) return -errno;

    char *cursor = relative;
    while (*cursor) {
        while (*cursor == '/') cursor++;
        if (!*cursor) break;
        char *component = cursor;
        while (*cursor && *cursor != '/') cursor++;
        size_t component_length = (size_t)(cursor - component);
        if (component_length == 0 || component_length > NAME_MAX ||
            (component_length == 1 && component[0] == '.') ||
            (component_length == 2 && component[0] == '.' && component[1] == '.')) {
            close(current);
            return -EACCES;
        }
        char name[NAME_MAX + 1];
        memcpy(name, component, component_length);
        name[component_length] = '\0';

        struct stat st;
        if (fstatat(current, name, &st, AT_SYMLINK_NOFOLLOW) != 0) {
            if (errno != ENOENT || !create) {
                int saved = errno;
                close(current);
                return -saved;
            }
            if (mkdirat(current, name, mode) != 0 && errno != EEXIST) {
                int saved = errno;
                close(current);
                return -saved;
            }
            if (fstatat(current, name, &st, AT_SYMLINK_NOFOLLOW) != 0) {
                int saved = errno;
                close(current);
                return -saved;
            }
        }
        if (S_ISLNK(st.st_mode)) {
            close(current);
            return -ELOOP;
        }
        if (!S_ISDIR(st.st_mode)) {
            close(current);
            return -ENOTDIR;
        }
        int next = openat(current, name,
                          O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        if (next < 0) {
            int saved = errno;
            close(current);
            return -saved;
        }
        close(current);
        current = next;
    }
    return current;
}

static inline int guest_safe_file_open_beneath_root(const char *root,
                                                     const char *directory,
                                                     const char *name,
                                                     int truncate_file,
                                                     mode_t mode) {
    if (!name || name[0] == '\0' || strchr(name, '/') ||
        strcmp(name, ".") == 0 || strcmp(name, "..") == 0 ||
        strlen(name) > NAME_MAX) return -EINVAL;
    int dirfd = guest_safe_dir_open_beneath_root(root, directory, 1, 0700);
    if (dirfd < 0) return dirfd;
    struct stat st;
    if (fstatat(dirfd, name, &st, AT_SYMLINK_NOFOLLOW) == 0) {
        if (S_ISLNK(st.st_mode)) {
            close(dirfd);
            return -ELOOP;
        }
        if (!S_ISREG(st.st_mode)) {
            close(dirfd);
            return -EACCES;
        }
    } else if (errno != ENOENT) {
        int saved = errno;
        close(dirfd);
        return -saved;
    }
    int flags = O_CREAT | O_WRONLY | O_CLOEXEC | O_NOFOLLOW;
    if (truncate_file) flags |= O_TRUNC;
    int fd = openat(dirfd, name, flags, mode);
    int saved = errno;
    close(dirfd);
    if (fd < 0) return -saved;
    if (fstat(fd, &st) != 0) {
        saved = errno;
        close(fd);
        return -saved;
    }
    if (!S_ISREG(st.st_mode)) {
        close(fd);
        return -EACCES;
    }
    return fd;
}

static inline int guest_safe_file_replace_beneath_root(const char *root,
                                                        const char *directory,
                                                        const char *name,
                                                        const void *bytes,
                                                        size_t length,
                                                        mode_t mode) {
    if (!bytes && length != 0u) return -EINVAL;
    int fd = guest_safe_file_open_beneath_root(root, directory, name, 1, mode);
    if (fd < 0) return fd;
    const unsigned char *cursor = (const unsigned char *)bytes;
    size_t written = 0;
    while (written < length) {
        ssize_t count = write(fd, cursor + written, length - written);
        if (count < 0) {
            if (errno == EINTR) continue;
            int saved = errno;
            close(fd);
            return -saved;
        }
        if (count == 0) {
            close(fd);
            return -EIO;
        }
        written += (size_t)count;
    }
    if (close(fd) != 0) return -errno;
    return 0;
}

static inline int guest_safe_symlink_beneath_root(const char *root,
                                                   const char *directory,
                                                   const char *name,
                                                   const char *target) {
    if (!root || !directory || !name || !target || name[0] == '\0' ||
        strchr(name, '/') || strcmp(name, ".") == 0 || strcmp(name, "..") == 0 ||
        target[0] == '\0' || strlen(name) > NAME_MAX || strlen(target) >= PATH_MAX)
        return -EINVAL;
    char canonical_root[PATH_MAX];
    if (!realpath(root, canonical_root)) return -EACCES;
    int dirfd = guest_safe_dir_open_beneath_root(root, directory, 1, 0700);
    if (dirfd < 0) return dirfd;
    struct stat st;
    int exists = fstatat(dirfd, name, &st, AT_SYMLINK_NOFOLLOW) == 0;
    if (!exists && errno != ENOENT) {
        int saved = errno;
        close(dirfd);
        return -saved;
    }
    if (exists && !S_ISLNK(st.st_mode)) {
        close(dirfd);
        return -EEXIST;
    }
    int created = 0;
    if (!exists && symlinkat(target, dirfd, name) != 0) {
        int saved = errno;
        close(dirfd);
        return -saved;
    }
    if (!exists) created = 1;
    char actual[PATH_MAX];
    ssize_t length = readlinkat(dirfd, name, actual, sizeof(actual) - 1u);
    if (length < 0) {
        int saved = errno;
        if (created) (void)unlinkat(dirfd, name, 0);
        close(dirfd);
        return -saved;
    }
    actual[length] = '\0';
    if (strcmp(actual, target) != 0) {
        if (created) (void)unlinkat(dirfd, name, 0);
        close(dirfd);
        return -EACCES;
    }
    char link_path[PATH_MAX], resolved[PATH_MAX];
    int n = snprintf(link_path, sizeof(link_path), "%s/%s", directory, name);
    if (n <= 0 || (size_t)n >= sizeof(link_path) || !realpath(link_path, resolved)) {
        int saved = errno ? errno : EACCES;
        if (created) (void)unlinkat(dirfd, name, 0);
        close(dirfd);
        return -saved;
    }
    size_t root_length = strlen(canonical_root);
    if (strncmp(resolved, canonical_root, root_length) != 0 ||
        (resolved[root_length] != '\0' && resolved[root_length] != '/')) {
        if (created) (void)unlinkat(dirfd, name, 0);
        close(dirfd);
        return -EACCES;
    }
    close(dirfd);
    return 0;
}

#endif
