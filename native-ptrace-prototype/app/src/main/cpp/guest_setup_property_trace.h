#ifndef GINGERVM_GUEST_SETUP_PROPERTY_TRACE_H
#define GINGERVM_GUEST_SETUP_PROPERTY_TRACE_H

#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define GUEST_SETUP_PROPERTY_KEY_CAPACITY 128u

enum guest_setup_property_tool {
    GUEST_SETUP_PROPERTY_TOOL_NONE = 0,
    GUEST_SETUP_PROPERTY_TOOL_GETPROP,
    GUEST_SETUP_PROPERTY_TOOL_SETPROP,
};

enum guest_setup_property_key_status {
    GUEST_SETUP_PROPERTY_KEY_READ = 0,
    GUEST_SETUP_PROPERTY_KEY_MISSING,
    GUEST_SETUP_PROPERTY_KEY_UNREADABLE,
    GUEST_SETUP_PROPERTY_KEY_TRUNCATED,
};

typedef int (*guest_setup_property_read_memory_fn)(void *context,
        uint32_t address, void *output, size_t length);

static inline enum guest_setup_property_tool guest_setup_property_tool_for_path(
        const char *path) {
    if (!path) return GUEST_SETUP_PROPERTY_TOOL_NONE;
    if (strcmp(path, "/system/bin/getprop") == 0)
        return GUEST_SETUP_PROPERTY_TOOL_GETPROP;
    if (strcmp(path, "/system/bin/setprop") == 0)
        return GUEST_SETUP_PROPERTY_TOOL_SETPROP;
    return GUEST_SETUP_PROPERTY_TOOL_NONE;
}

static inline const char *guest_setup_property_tool_name(
        enum guest_setup_property_tool tool) {
    switch (tool) {
        case GUEST_SETUP_PROPERTY_TOOL_GETPROP: return "getprop";
        case GUEST_SETUP_PROPERTY_TOOL_SETPROP: return "setprop";
        case GUEST_SETUP_PROPERTY_TOOL_NONE:
        default: return "none";
    }
}

static inline const char *guest_setup_property_key_status_name(
        enum guest_setup_property_key_status status) {
    switch (status) {
        case GUEST_SETUP_PROPERTY_KEY_READ: return "read";
        case GUEST_SETUP_PROPERTY_KEY_MISSING: return "missing";
        case GUEST_SETUP_PROPERTY_KEY_UNREADABLE: return "unreadable";
        case GUEST_SETUP_PROPERTY_KEY_TRUNCATED: return "truncated";
        default: return "invalid";
    }
}

/* Read only argv[1] (the getprop/setprop property key). This helper never
 * dereferences argv[0] or argv[2], so the setprop property value is not read. */
static inline enum guest_setup_property_key_status
 guest_setup_property_capture_key(uint32_t argv_address,
        guest_setup_property_read_memory_fn read_memory, void *context,
        char *key, size_t key_capacity) {
    if (!key || key_capacity == 0) return GUEST_SETUP_PROPERTY_KEY_UNREADABLE;
    key[0] = '\0';
    if (!argv_address || !read_memory || key_capacity < 2u ||
        argv_address > UINT32_MAX - 2u * (uint32_t)sizeof(uint32_t))
        return GUEST_SETUP_PROPERTY_KEY_UNREADABLE;

    uint32_t key_address = 0;
    if (read_memory(context, argv_address + (uint32_t)sizeof(uint32_t),
                    &key_address, sizeof(key_address)) != 0)
        return GUEST_SETUP_PROPERTY_KEY_UNREADABLE;
    if (!key_address) return GUEST_SETUP_PROPERTY_KEY_MISSING;

    size_t length = 0;
    while (length + 1u < key_capacity) {
        uint32_t address = key_address + (uint32_t)length;
        if (address < key_address ||
            read_memory(context, address, &key[length], sizeof(key[length])) != 0) {
            key[length] = '\0';
            return GUEST_SETUP_PROPERTY_KEY_UNREADABLE;
        }
        if (key[length] == '\0') return GUEST_SETUP_PROPERTY_KEY_READ;
        length++;
    }

    key[key_capacity - 1u] = '\0';
    return GUEST_SETUP_PROPERTY_KEY_TRUNCATED;
}

#endif
