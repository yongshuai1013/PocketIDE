#ifndef GINGERVM_GUEST_SIGSYS_CONTEXT_H
#define GINGERVM_GUEST_SIGSYS_CONTEXT_H

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>

#define GUEST_DIAG_PROC_MAP_PATH_CAPACITY 512u

struct guest_diag_proc_map {
    uint64_t start;
    uint64_t end;
    uint64_t file_offset;
    char permissions[5];
    char path[GUEST_DIAG_PROC_MAP_PATH_CAPACITY];
    int path_truncated;
};

static inline int guest_diag_parse_proc_maps_line(const char *line,
                                                   struct guest_diag_proc_map *mapping) {
    if (!line || !mapping) return -EINVAL;

    unsigned long long start = 0;
    unsigned long long end = 0;
    unsigned long long file_offset = 0;
    unsigned long long inode = 0;
    char permissions[5] = {0};
    char device[64] = {0};
    int path_offset = -1;
    int fields = sscanf(line, "%llx-%llx %4s %llx %63s %llu %n",
                        &start, &end, permissions, &file_offset,
                        device, &inode, &path_offset);
    if (fields != 6 || path_offset < 0 || start >= end ||
        strlen(permissions) >= sizeof(mapping->permissions)) {
        return -EINVAL;
    }

    const char *path = line + path_offset;
    while (*path == ' ' || *path == '\t') ++path;
    size_t path_length = 0;
    while (path[path_length] && path[path_length] != '\n' && path[path_length] != '\r') {
        ++path_length;
    }

    memset(mapping, 0, sizeof(*mapping));
    mapping->start = (uint64_t)start;
    mapping->end = (uint64_t)end;
    mapping->file_offset = (uint64_t)file_offset;
    memcpy(mapping->permissions, permissions, strlen(permissions));

    if (path_length == 0) {
        static const char anonymous[] = "[anonymous]";
        memcpy(mapping->path, anonymous, sizeof(anonymous));
    } else {
        size_t copy_length = path_length;
        if (copy_length >= sizeof(mapping->path)) {
            copy_length = sizeof(mapping->path) - 1;
            mapping->path_truncated = 1;
        }
        memcpy(mapping->path, path, copy_length);
        mapping->path[copy_length] = '\0';
    }
    return 0;
}

static inline int guest_diag_proc_map_contains(const struct guest_diag_proc_map *mapping,
                                                uint64_t address) {
    return mapping && address >= mapping->start && address < mapping->end;
}

static inline uint64_t guest_diag_proc_map_file_offset(
        const struct guest_diag_proc_map *mapping, uint64_t address) {
    if (!guest_diag_proc_map_contains(mapping, address)) return UINT64_MAX;
    uint64_t delta = address - mapping->start;
    if (UINT64_MAX - mapping->file_offset < delta) return UINT64_MAX;
    return mapping->file_offset + delta;
}

/* Best-effort read-only lookup. A failure is diagnostic only and must never
 * affect ptrace signal forwarding or guest execution. */
static inline int guest_diag_find_proc_map(pid_t pid, uint64_t address,
                                            struct guest_diag_proc_map *mapping) {
    if (pid <= 0 || !mapping) return -EINVAL;

    char proc_path[64];
    int path_length = snprintf(proc_path, sizeof(proc_path), "/proc/%ld/maps", (long)pid);
    if (path_length < 0 || (size_t)path_length >= sizeof(proc_path)) return -ENAMETOOLONG;

    FILE *file = fopen(proc_path, "r");
    if (!file) return errno ? -errno : -EIO;

    char line[4096];
    int result = -ENOENT;
    while (fgets(line, sizeof(line), file)) {
        struct guest_diag_proc_map candidate;
        if (guest_diag_parse_proc_maps_line(line, &candidate) == 0 &&
            guest_diag_proc_map_contains(&candidate, address)) {
            *mapping = candidate;
            result = 0;
            break;
        }
    }
    if (ferror(file) && result != 0) result = errno ? -errno : -EIO;
    fclose(file);
    return result;
}

static inline int guest_diag_read_proc_seccomp_mode(pid_t pid) {
    if (pid <= 0) return -EINVAL;

    char proc_path[64];
    int path_length = snprintf(proc_path, sizeof(proc_path), "/proc/%ld/status", (long)pid);
    if (path_length < 0 || (size_t)path_length >= sizeof(proc_path)) return -ENAMETOOLONG;

    FILE *file = fopen(proc_path, "r");
    if (!file) return errno ? -errno : -EIO;

    char line[256];
    int result = -ENOENT;
    while (fgets(line, sizeof(line), file)) {
        if (strncmp(line, "Seccomp:", 8) != 0) continue;
        int mode = -1;
        if (sscanf(line + 8, "%d", &mode) == 1 && mode >= 0 && mode <= 2) result = mode;
        else result = -EINVAL;
        break;
    }
    if (ferror(file) && result == -ENOENT) result = errno ? -errno : -EIO;
    fclose(file);
    return result;
}

#endif
