#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "../app/src/main/cpp/guest_setup_property_trace.h"

struct mock_memory {
    uint32_t base;
    unsigned char bytes[512];
    uint32_t read_addresses[256];
    size_t read_count;
};

static int mock_read(void *context, uint32_t address, void *output, size_t length) {
    struct mock_memory *memory = context;
    if (!memory || !output || address < memory->base ||
        (uint64_t)address + length > (uint64_t)memory->base + sizeof(memory->bytes))
        return -1;
    if (memory->read_count < sizeof(memory->read_addresses) /
                             sizeof(memory->read_addresses[0]))
        memory->read_addresses[memory->read_count++] = address;
    memcpy(output, memory->bytes + (address - memory->base), length);
    return 0;
}

static void put_u32(struct mock_memory *memory, uint32_t address, uint32_t value) {
    assert(address >= memory->base);
    assert((uint64_t)address + sizeof(value) <=
           (uint64_t)memory->base + sizeof(memory->bytes));
    memcpy(memory->bytes + (address - memory->base), &value, sizeof(value));
}

static void put_string(struct mock_memory *memory, uint32_t address,
                       const char *value) {
    size_t length = strlen(value) + 1u;
    assert(address >= memory->base);
    assert((uint64_t)address + length <=
           (uint64_t)memory->base + sizeof(memory->bytes));
    memcpy(memory->bytes + (address - memory->base), value, length);
}

static void test_exact_tool_paths(void) {
    assert(guest_setup_property_tool_for_path("/system/bin/getprop") ==
           GUEST_SETUP_PROPERTY_TOOL_GETPROP);
    assert(guest_setup_property_tool_for_path("/system/bin/setprop") ==
           GUEST_SETUP_PROPERTY_TOOL_SETPROP);
    assert(guest_setup_property_tool_for_path("/system/bin/setprop-extra") ==
           GUEST_SETUP_PROPERTY_TOOL_NONE);
    assert(guest_setup_property_tool_for_path(NULL) ==
           GUEST_SETUP_PROPERTY_TOOL_NONE);
    assert(strcmp(guest_setup_property_tool_name(
               GUEST_SETUP_PROPERTY_TOOL_SETPROP), "setprop") == 0);
}

static void test_only_argv_one_property_key_is_read(void) {
    struct mock_memory memory = {.base = 0x1000u};
    char key[GUEST_SETUP_PROPERTY_KEY_CAPACITY];
    put_u32(&memory, 0x1000u, 0x1080u); /* argv[0], intentionally not read */
    put_u32(&memory, 0x1004u, 0x1100u); /* argv[1]: property key */
    put_u32(&memory, 0x1008u, 0x1180u); /* argv[2]: property value */
    put_string(&memory, 0x1080u, "setprop");
    put_string(&memory, 0x1100u, "ro.kernel.qemu");
    put_string(&memory, 0x1180u, "sensitive-value-must-not-be-read");

    assert(guest_setup_property_capture_key(0x1000u, mock_read, &memory,
               key, sizeof(key)) == GUEST_SETUP_PROPERTY_KEY_READ);
    assert(strcmp(key, "ro.kernel.qemu") == 0);
    assert(memory.read_count > 0u);
    for (size_t i = 0; i < memory.read_count; ++i) {
        assert(memory.read_addresses[i] != 0x1000u); /* argv[0] slot */
        assert(memory.read_addresses[i] != 0x1008u); /* argv[2] slot */
        assert(memory.read_addresses[i] < 0x1180u ||
               memory.read_addresses[i] >= 0x1180u + 32u);
    }
}

static void test_missing_unreadable_and_truncated_keys(void) {
    struct mock_memory memory = {.base = 0x2000u};
    char key[8];
    put_u32(&memory, 0x2000u, 0x2080u);
    put_u32(&memory, 0x2004u, 0u);
    assert(guest_setup_property_capture_key(0x2000u, mock_read, &memory,
               key, sizeof(key)) == GUEST_SETUP_PROPERTY_KEY_MISSING);
    assert(key[0] == '\0');
    assert(guest_setup_property_capture_key(0x2000u, NULL, &memory,
               key, sizeof(key)) == GUEST_SETUP_PROPERTY_KEY_UNREADABLE);
    assert(guest_setup_property_capture_key(0xfffffffcu, mock_read, &memory,
               key, sizeof(key)) == GUEST_SETUP_PROPERTY_KEY_UNREADABLE);

    put_u32(&memory, 0x2004u, 0x2100u);
    put_string(&memory, 0x2100u, "ro.long.property.name");
    assert(guest_setup_property_capture_key(0x2000u, mock_read, &memory,
               key, sizeof(key)) == GUEST_SETUP_PROPERTY_KEY_TRUNCATED);
    assert(strcmp(key, "ro.long") == 0);
}

int main(void) {
    test_exact_tool_paths();
    test_only_argv_one_property_key_is_read();
    test_missing_unreadable_and_truncated_keys();
    puts("setup-shell property trace regression: PASS (exact tools, argv[1] key only, no argv[2] value reads)");
    return 0;
}
