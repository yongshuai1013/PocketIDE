#include "../app/src/main/cpp/guest_pseudo_device.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

static uint32_t load32le(const unsigned char *bytes, size_t offset) {
    return (uint32_t)bytes[offset] | ((uint32_t)bytes[offset + 1] << 8) |
           ((uint32_t)bytes[offset + 2] << 16) | ((uint32_t)bytes[offset + 3] << 24);
}

static uint64_t load64le(const unsigned char *bytes, size_t offset) {
    return (uint64_t)load32le(bytes, offset) |
           ((uint64_t)load32le(bytes, offset + 4) << 32);
}

struct fake_entropy_state { size_t maximum_seen; int result; };
static int fake_entropy_fill(void *context, unsigned char *out, size_t length) {
    struct fake_entropy_state *state = (struct fake_entropy_state *)context;
    state->maximum_seen = length;
    if (state->result < 0) return state->result;
    size_t amount = (size_t)state->result;
    if (amount > length) amount = length;
    for (size_t i = 0; i < amount; ++i) out[i] = (unsigned char)(i ^ 0x5au);
    return (int)amount;
}

int main(void) {
    assert(guest_pseudo_device_kind_for_path("/dev/__null__") == VIRTUAL_FD_DEV_NULL);
    assert(guest_pseudo_device_kind_for_path("/dev/__kmsg__") == VIRTUAL_FD_DEV_KMSG);
    assert(guest_pseudo_device_kind_for_path("/dev/null") == VIRTUAL_FD_DEV_NULL);
    assert(guest_pseudo_device_kind_for_path("/dev/zero") == VIRTUAL_FD_DEV_ZERO);
    assert(guest_pseudo_device_kind_for_path("/dev/full") == VIRTUAL_FD_DEV_FULL);
    assert(guest_pseudo_device_kind_for_path("/dev/random") == VIRTUAL_FD_DEV_RANDOM);
    assert(guest_pseudo_device_kind_for_path("/dev/urandom") == VIRTUAL_FD_DEV_RANDOM);
    assert(guest_pseudo_device_kind_for_path("/dev/binder") == 0);

    struct guest_pseudo_device_metadata metadata;
    assert(guest_pseudo_device_metadata_for_path("/dev/null", &metadata) == 1);
    assert(metadata.kind == VIRTUAL_FD_DEV_NULL && metadata.mode == (GUEST_MODE_IFCHR | 0666u));
    assert(metadata.major == 1 && metadata.minor == 3);
    assert(guest_pseudo_device_metadata_for_path("/dev/__null__", &metadata) == 1);
    assert(metadata.mode == (GUEST_MODE_IFCHR | 0600u) && metadata.minor == 3);
    assert(guest_pseudo_device_metadata_for_path("/dev/zero", &metadata) == 1);
    assert(metadata.mode == (GUEST_MODE_IFCHR | 0666u) && metadata.minor == 5);
    assert(guest_pseudo_device_metadata_for_path("/dev/full", &metadata) == 1);
    assert(metadata.mode == (GUEST_MODE_IFCHR | 0666u) && metadata.minor == 7);
    assert(guest_pseudo_device_metadata_for_path("/dev/random", &metadata) == 1);
    assert(metadata.major == 1 && metadata.minor == 8);
    assert(guest_pseudo_device_metadata_for_path("/dev/urandom", &metadata) == 1);
    assert(metadata.major == 1 && metadata.minor == 9);
    assert(guest_pseudo_device_metadata_for_path("/dev/__kmsg__", &metadata) == 1);
    assert(metadata.mode == (GUEST_MODE_IFCHR | 0600u) && metadata.major == 1 && metadata.minor == 11);

    unsigned char bytes[8];
    memset(bytes, 0xa5, sizeof(bytes));
    assert(guest_pseudo_device_read(VIRTUAL_FD_DEV_NULL, bytes, sizeof(bytes), sizeof(bytes)) == 0);
    assert(guest_pseudo_device_read(VIRTUAL_FD_DEV_ZERO, bytes, sizeof(bytes), sizeof(bytes)) == (int)sizeof(bytes));
    for (size_t i = 0; i < sizeof(bytes); ++i) assert(bytes[i] == 0);
    memset(bytes, 0xa5, sizeof(bytes));
    assert(guest_pseudo_device_read(VIRTUAL_FD_DEV_FULL, bytes, sizeof(bytes), sizeof(bytes)) == (int)sizeof(bytes));
    for (size_t i = 0; i < sizeof(bytes); ++i) assert(bytes[i] == 0);
    assert(guest_pseudo_device_read(VIRTUAL_FD_DEV_ZERO, NULL, 1, 0) == -EFAULT);
    assert(guest_pseudo_device_read(VIRTUAL_FD_DEV_KMSG, bytes, sizeof(bytes), sizeof(bytes)) == -EAGAIN);
    assert(guest_pseudo_device_read(VIRTUAL_FD_DEV_RANDOM, bytes, sizeof(bytes), sizeof(bytes)) == -EOPNOTSUPP);
    struct fake_entropy_state entropy = {.maximum_seen = 0u, .result = 12};
    unsigned char random_bytes[GUEST_URANDOM_MAX_READ_BYTES];
    assert(guest_pseudo_device_read_urandom(9u, random_bytes, 64u,
        sizeof(random_bytes), fake_entropy_fill, &entropy) == 12);
    assert(entropy.maximum_seen == 64u && random_bytes[0] == 0x5au &&
           random_bytes[11] == (unsigned char)(11u ^ 0x5au));
    assert(guest_pseudo_device_read_urandom(8u, random_bytes, 64u,
        sizeof(random_bytes), fake_entropy_fill, &entropy) == -EOPNOTSUPP);
    assert(guest_pseudo_device_read_urandom(10u, random_bytes, 64u,
        sizeof(random_bytes), fake_entropy_fill, &entropy) == -ENODEV);
    entropy.result = -EAGAIN;
    assert(guest_pseudo_device_read_urandom(9u, random_bytes, 64u,
        sizeof(random_bytes), fake_entropy_fill, &entropy) == -EAGAIN);
    entropy.result = (int)sizeof(random_bytes);
    assert(guest_pseudo_device_read_urandom(9u, random_bytes, 4096u,
        sizeof(random_bytes), fake_entropy_fill, &entropy) == (int)sizeof(random_bytes));
    assert(entropy.maximum_seen == GUEST_URANDOM_MAX_READ_BYTES);
    assert(guest_pseudo_device_write(VIRTUAL_FD_DEV_NULL, 17) == 17);
    assert(guest_pseudo_device_write(VIRTUAL_FD_DEV_ZERO, 17) == 17);
    assert(guest_pseudo_device_write(VIRTUAL_FD_DEV_KMSG, 17) == 17);
    assert(guest_pseudo_device_write(VIRTUAL_FD_DEV_FULL, 17) == -ENOSPC);
    assert(guest_pseudo_device_write(VIRTUAL_FD_DEV_RANDOM, 17) == -EOPNOTSUPP);

    unsigned char stat64[GUEST_ARM32_STAT64_BYTES];
    memset(stat64, 0xa5, sizeof(stat64));
    assert(guest_pseudo_device_stat64_for_path("/dev/null", stat64) == 1);
    assert(load32le(stat64, 16) == (GUEST_MODE_IFCHR | 0666u));
    assert((load32le(stat64, 16) & 0170000u) == 0020000u);
    assert(load32le(stat64, 20) == 1 && load32le(stat64, 24) == 0 && load32le(stat64, 28) == 0);
    assert(load64le(stat64, 32) == guest_pseudo_makedev(1, 3));
    assert(guest_pseudo_device_stat64_for_path("/dev/random", stat64) == 1);
    assert(load64le(stat64, 32) == guest_pseudo_makedev(1, 8));
    assert(guest_pseudo_device_stat64_for_path("/dev/binder", stat64) == 0);
    puts("guest pseudo-device ABI regression: PASS (API10 null/zero/full/random/urandom/kmsg nodes and ARM32 stat64 metadata; no host entropy/device use)");
    return 0;
}
