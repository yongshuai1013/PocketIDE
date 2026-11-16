#ifndef GINGERVM_GUEST_ENTRY_PROBE_H
#define GINGERVM_GUEST_ENTRY_PROBE_H

#include <stddef.h>
#include <string.h>

static inline int guest_entry_mapping_matches(const char *mapped_path,
                                              const char *target_path,
                                              const char *permissions) {
    if (!mapped_path || !target_path || !permissions || permissions[2] != 'x') return 0;
    size_t length = strlen(target_path);
    if (strncmp(mapped_path, target_path, length) == 0 && mapped_path[length] == '\0')
        return 1;
    static const char deleted[] = " (deleted)";
    return strncmp(mapped_path, target_path, length) == 0 &&
           strncmp(mapped_path + length, deleted, sizeof(deleted) - 1u) == 0 &&
           mapped_path[length + sizeof(deleted) - 1u] == '\0';
}

#endif
