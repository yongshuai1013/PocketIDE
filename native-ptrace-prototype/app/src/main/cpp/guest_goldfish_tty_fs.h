#ifndef GINGERVM_GUEST_GOLDFISH_TTY_FS_H
#define GINGERVM_GUEST_GOLDFISH_TTY_FS_H

#include "guest_goldfish_tty_virtual.h"
#include "guest_safe_dir.h"

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

/* Create an empty regular app-private placeholder, never a host device node. */
static inline int guest_goldfish_tty_create_app_private_placeholder(
        const char *guest_root, const char *guest_path, const char *backing_path,
        struct guest_goldfish_tty_runtime *runtime, int verified_ueventd,
        uint32_t mode, uint32_t device, uint32_t *minor_out) {
    if (!runtime || !guest_root || !guest_path || !backing_path) return -EINVAL;
    runtime->mknod_attempts++;
    uint32_t minor = 0;
    int rc = guest_goldfish_tty_mknod_validate(runtime, verified_ueventd,
        guest_path, mode, device, &minor);
    if (rc != 0) return rc;

    char expected_leaf[16];
    int n = snprintf(expected_leaf, sizeof(expected_leaf), "ttyS%u", minor);
    if (n <= 0 || (size_t)n >= sizeof(expected_leaf)) return -ENAMETOOLONG;
    const char *slash = strrchr(backing_path, '/');
    if (!slash || slash == backing_path || strcmp(slash + 1, expected_leaf) != 0)
        return -EACCES;
    size_t directory_length = (size_t)(slash - backing_path);
    if (directory_length >= PATH_MAX) return -ENAMETOOLONG;
    char directory[PATH_MAX];
    memcpy(directory, backing_path, directory_length);
    directory[directory_length] = '\0';

    int dirfd = guest_safe_dir_open_beneath_root(guest_root, directory, 0, 0);
    if (dirfd < 0) return dirfd;
    struct stat existing;
    if (fstatat(dirfd, expected_leaf, &existing, AT_SYMLINK_NOFOLLOW) == 0) {
        int result = S_ISLNK(existing.st_mode) ? -ELOOP : -EEXIST;
        close(dirfd);
        return result;
    }
    if (errno != ENOENT) {
        int saved = errno;
        close(dirfd);
        return -saved;
    }

    int fd = openat(dirfd, expected_leaf,
                    O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0) {
        int saved = errno;
        close(dirfd);
        return -saved;
    }
    struct stat st;
    if (fstat(fd, &st) != 0) {
        int saved = errno;
        close(fd);
        (void)unlinkat(dirfd, expected_leaf, 0);
        close(dirfd);
        return -saved;
    }
    if (!S_ISREG(st.st_mode) || st.st_uid != getuid() || st.st_nlink != 1 ||
        st.st_size != 0 || (st.st_mode & 0777u) != 0600u) {
        close(fd);
        (void)unlinkat(dirfd, expected_leaf, 0);
        close(dirfd);
        return -EACCES;
    }
    if (close(fd) != 0) {
        int saved = errno;
        (void)unlinkat(dirfd, expected_leaf, 0);
        close(dirfd);
        return -saved;
    }
    if (close(dirfd) != 0) {
        int saved = errno;
        /* The guest-private node remains, but a close failure is reported. */
        return -saved;
    }
    guest_goldfish_tty_note_node_created(runtime, minor);
    if (minor_out) *minor_out = minor;
    return 0;
}

#endif
