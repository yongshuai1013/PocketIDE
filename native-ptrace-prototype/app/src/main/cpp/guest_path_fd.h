#ifndef GINGERVM_GUEST_PATH_FD_H
#define GINGERVM_GUEST_PATH_FD_H

#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>

#define GUEST_PATH_FD_MAX 128u
#define GUEST_PATH_FD_PATH_CAPACITY 1024u
#define GUEST_AT_FDCWD (-100)

struct guest_path_fd_entry {
    int used;
    pid_t owner_pid;
    int fd;
    char path[GUEST_PATH_FD_PATH_CAPACITY];
};

struct guest_path_fd_table {
    struct guest_path_fd_entry entries[GUEST_PATH_FD_MAX];
};

static inline int guest_path_normalize(const char *input, char *output,
                                       size_t capacity) {
    if (!input || !output || capacity == 0 || input[0] != '/') return -EINVAL;
    size_t written = 0;
    const char *cursor = input;
    output[written++] = '/';
    while (*cursor == '/') ++cursor;
    while (*cursor) {
        const char *start = cursor;
        while (*cursor && *cursor != '/') ++cursor;
        size_t length = (size_t)(cursor - start);
        while (*cursor == '/') ++cursor;
        if (length == 0 || (length == 1 && start[0] == '.')) continue;
        if (length == 2 && start[0] == '.' && start[1] == '.') return -EACCES;
        if (written > 1) {
            if (written + 1 >= capacity) return -ENAMETOOLONG;
            output[written++] = '/';
        }
        if (length >= capacity - written) return -ENAMETOOLONG;
        memcpy(output + written, start, length);
        written += length;
    }
    if (written >= capacity) return -ENAMETOOLONG;
    output[written] = '\0';
    return 0;
}

static inline void guest_path_fd_table_init(struct guest_path_fd_table *table) {
    if (table) memset(table, 0, sizeof(*table));
}

static inline int guest_path_fd_track(struct guest_path_fd_table *table,
                                      pid_t owner_pid, int fd,
                                      const char *guest_path) {
    if (!table || owner_pid <= 0 || fd < 0 || !guest_path) return -EINVAL;
    char normalized[GUEST_PATH_FD_PATH_CAPACITY];
    int rc = guest_path_normalize(guest_path, normalized, sizeof(normalized));
    if (rc != 0) return rc;
    struct guest_path_fd_entry *free_entry = NULL;
    for (size_t i = 0; i < GUEST_PATH_FD_MAX; ++i) {
        struct guest_path_fd_entry *entry = &table->entries[i];
        if (entry->used && entry->owner_pid == owner_pid && entry->fd == fd) {
            free_entry = entry;
            break;
        }
        if (!entry->used && !free_entry) free_entry = entry;
    }
    if (!free_entry) return -ENOSPC;
    free_entry->used = 1;
    free_entry->owner_pid = owner_pid;
    free_entry->fd = fd;
    memcpy(free_entry->path, normalized, strlen(normalized) + 1u);
    return 0;
}

static inline int guest_path_fd_lookup(const struct guest_path_fd_table *table,
                                       pid_t owner_pid, int fd,
                                       char *guest_path, size_t capacity) {
    if (!table || !guest_path || capacity == 0) return -EINVAL;
    for (size_t i = 0; i < GUEST_PATH_FD_MAX; ++i) {
        const struct guest_path_fd_entry *entry = &table->entries[i];
        if (!entry->used || entry->owner_pid != owner_pid || entry->fd != fd) continue;
        size_t length = strlen(entry->path);
        if (length >= capacity) return -ENAMETOOLONG;
        memcpy(guest_path, entry->path, length + 1u);
        return 0;
    }
    return -EBADF;
}

static inline void guest_path_fd_remove(struct guest_path_fd_table *table,
                                        pid_t owner_pid, int fd) {
    if (!table) return;
    for (size_t i = 0; i < GUEST_PATH_FD_MAX; ++i) {
        struct guest_path_fd_entry *entry = &table->entries[i];
        if (entry->used && entry->owner_pid == owner_pid && entry->fd == fd)
            memset(entry, 0, sizeof(*entry));
    }
}

static inline void guest_path_fd_remove_owner(struct guest_path_fd_table *table,
                                              pid_t owner_pid) {
    if (!table) return;
    for (size_t i = 0; i < GUEST_PATH_FD_MAX; ++i) {
        struct guest_path_fd_entry *entry = &table->entries[i];
        if (entry->used && entry->owner_pid == owner_pid)
            memset(entry, 0, sizeof(*entry));
    }
}

static inline int guest_path_fd_clone_owner(struct guest_path_fd_table *table,
                                            pid_t source_pid, pid_t target_pid) {
    if (!table || source_pid <= 0 || target_pid <= 0 || source_pid == target_pid)
        return -EINVAL;
    struct guest_path_fd_entry saved[GUEST_PATH_FD_MAX];
    size_t count = 0;
    for (size_t i = 0; i < GUEST_PATH_FD_MAX; ++i)
        if (table->entries[i].used && table->entries[i].owner_pid == source_pid)
            saved[count++] = table->entries[i];
    for (size_t i = 0; i < count; ++i) {
        int rc = guest_path_fd_track(table, target_pid, saved[i].fd, saved[i].path);
        if (rc != 0) {
            guest_path_fd_remove_owner(table, target_pid);
            return rc;
        }
    }
    return 0;
}

static inline int guest_path_resolve_at(const struct guest_path_fd_table *table,
                                        pid_t owner_pid, int dirfd,
                                        const char *guest_cwd,
                                        const char *input_path,
                                        char *resolved, size_t capacity) {
    if (!input_path || !resolved || capacity == 0 || input_path[0] == '\0')
        return -ENOENT;
    if (input_path[0] == '/') return guest_path_normalize(input_path, resolved, capacity);
    char base[GUEST_PATH_FD_PATH_CAPACITY];
    int rc;
    if (dirfd == GUEST_AT_FDCWD) {
        if (!guest_cwd || guest_cwd[0] != '/') return -EACCES;
        rc = guest_path_normalize(guest_cwd, base, sizeof(base));
    } else {
        rc = guest_path_fd_lookup(table, owner_pid, dirfd, base, sizeof(base));
    }
    if (rc != 0) return rc;
    char joined[GUEST_PATH_FD_PATH_CAPACITY * 2u];
    int n = snprintf(joined, sizeof(joined), "%s%s%s", base,
                     strcmp(base, "/") == 0 ? "" : "/", input_path);
    if (n <= 0 || (size_t)n >= sizeof(joined)) return -ENAMETOOLONG;
    return guest_path_normalize(joined, resolved, capacity);
}

#endif
