#ifndef GINGERVM_GUEST_FILE_OPS_H
#define GINGERVM_GUEST_FILE_OPS_H

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

static inline int guest_file_path_within_root(const char *path, const char *root) {
    size_t n = strlen(root);
    return strncmp(path, root, n) == 0 &&
           (path[n] == '\0' || path[n] == '/');
}

static inline int guest_proc_fd_path(pid_t pid, int fd, char *path, size_t capacity) {
    int n = snprintf(path, capacity, "/proc/%ld/fd/%d", (long)pid, fd);
    return n > 0 && (size_t)n < capacity ? 0 : -ENAMETOOLONG;
}

static inline int guest_proc_fd_is_writable(pid_t pid, int fd) {
    char path[96];
    int n = snprintf(path, sizeof(path), "/proc/%ld/fdinfo/%d", (long)pid, fd);
    if (n <= 0 || (size_t)n >= sizeof(path)) return -ENAMETOOLONG;
    int info_fd = open(path, O_RDONLY | O_CLOEXEC);
    if (info_fd < 0) return -errno;
    char info[4096];
    ssize_t got;
    do { got = read(info_fd, info, sizeof(info) - 1); } while (got < 0 && errno == EINTR);
    int saved = errno;
    (void)close(info_fd);
    if (got < 0) return -saved;
    info[got] = '\0';
    char *flags_line = strstr(info, "flags:");
    if (!flags_line) return -EIO;
    flags_line += strlen("flags:");
    while (*flags_line == ' ' || *flags_line == '\t') ++flags_line;
    errno = 0;
    char *end = NULL;
    unsigned long flags = strtoul(flags_line, &end, 8);
    if (errno != 0 || end == flags_line) return -EIO;
    if ((flags & O_ACCMODE) == O_RDONLY) return -EBADF;
    return 0;
}

/*
 * Model ARM EABI ftruncate(2) on a guest-opened app-private regular file.
 * This only opens /proc/<tracee>/fd/N after checking its target is confined to
 * guest_root; it never forwards ARM syscall 93 to the Android host kernel.
 */
static inline int32_t guest_ftruncate_app_private(pid_t tracee_pid, int guest_fd,
                                                   int32_t length, const char *guest_root,
                                                   char *guest_relative_path,
                                                   size_t path_capacity) {
    if (guest_relative_path && path_capacity) guest_relative_path[0] = '\0';
    if (tracee_pid <= 0 || guest_fd < 0) return -EBADF;
    if (length < 0) return -EINVAL;
    if (!guest_root || guest_root[0] != '/') return -EINVAL;

    char proc_path[128];
    int rc = guest_proc_fd_path(tracee_pid, guest_fd, proc_path, sizeof(proc_path));
    if (rc != 0) return rc;

    char original_target[PATH_MAX];
    ssize_t target_len = readlink(proc_path, original_target, sizeof(original_target) - 1);
    if (target_len < 0) return errno == ENOENT ? -EBADF : -errno;
    original_target[target_len] = '\0';
    if (!guest_file_path_within_root(original_target, guest_root)) return -EPERM;

    struct stat target_stat;
    if (stat(proc_path, &target_stat) != 0) return errno == ENOENT ? -EBADF : -errno;
    if (!S_ISREG(target_stat.st_mode)) return -EINVAL;

    rc = guest_proc_fd_is_writable(tracee_pid, guest_fd);
    if (rc != 0) return rc;

    int writable_fd = open(proc_path, O_WRONLY | O_CLOEXEC);
    if (writable_fd < 0) return errno == ENOENT ? -EBADF : -errno;

    struct stat opened_stat;
    char opened_link[64];
    char opened_target[PATH_MAX];
    int n = snprintf(opened_link, sizeof(opened_link), "/proc/self/fd/%d", writable_fd);
    if (n <= 0 || (size_t)n >= sizeof(opened_link)) {
        (void)close(writable_fd);
        return -ENAMETOOLONG;
    }
    target_len = readlink(opened_link, opened_target, sizeof(opened_target) - 1);
    if (target_len < 0) {
        int saved = errno;
        (void)close(writable_fd);
        return -saved;
    }
    opened_target[target_len] = '\0';
    if (!guest_file_path_within_root(opened_target, guest_root)) {
        (void)close(writable_fd);
        return -EPERM;
    }
    if (fstat(writable_fd, &opened_stat) != 0) {
        int saved = errno;
        (void)close(writable_fd);
        return -saved;
    }
    if (!S_ISREG(opened_stat.st_mode)) {
        (void)close(writable_fd);
        return -EINVAL;
    }

    if (guest_relative_path && path_capacity) {
        size_t root_len = strlen(guest_root);
        const char *relative = opened_target + root_len;
        if (*relative == '\0') relative = "/";
        int written = snprintf(guest_relative_path, path_capacity, "%s", relative);
        if (written < 0 || (size_t)written >= path_capacity) {
            (void)close(writable_fd);
            guest_relative_path[0] = '\0';
            return -ENAMETOOLONG;
        }
    }

    int32_t result = 0;
    if (ftruncate(writable_fd, (off_t)length) != 0) result = -errno;
    (void)close(writable_fd);
    return result;
}

#endif
