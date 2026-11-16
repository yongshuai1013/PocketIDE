#include "../app/src/main/cpp/guest_device_boundary.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

int main(void) {
    assert(strcmp(guest_device_unimplemented_reason("/dev/ptmx"),
                  "pty-kernel-backend-not-implemented") == 0);
    assert(strcmp(guest_device_unimplemented_reason("/dev/tty0"),
                  "pty-kernel-backend-not-implemented") == 0);
    assert(strcmp(guest_device_unimplemented_reason("/dev/ttyHS0"),
                  "pty-kernel-backend-not-implemented") == 0);
    assert(strcmp(guest_device_unimplemented_reason("/dev/pts/1"),
                  "pty-kernel-backend-not-implemented") == 0);
    assert(strcmp(guest_device_unimplemented_reason("/dev/log/main"),
                  "android-log-device-backend-not-implemented") == 0);
    assert(strcmp(guest_device_unimplemented_reason("/dev/binder"),
                  "binder-kernel-backend-not-implemented") == 0);
    assert(strcmp(guest_device_unimplemented_reason("/dev/ashmem"),
                  "ashmem-kernel-backend-not-implemented") == 0);
    assert(strcmp(guest_device_unimplemented_reason("/dev/goldfish_pipe"),
                  "goldfish-emulator-pipe-backend-not-implemented") == 0);
    assert(strcmp(guest_device_unimplemented_reason("/dev/qemu_pipe"),
                  "goldfish-emulator-pipe-backend-not-implemented") == 0);
    const char *api10_hardware_nodes[] = {
        "/dev/msm_hw3dc", "/dev/kgsl", "/dev/diag", "/dev/android_adb",
        "/dev/uinput", "/dev/alarm", "/dev/graphics/fb0",
        "/dev/input/event0", "/dev/pmem_adsp0", "/dev/oncrpc/00000000",
        "/dev/snd/dsp", "/dev/akm8976_daemon", "/dev/msm_pcm_out0",
        "/dev/qmi0", "/dev/usb_accessory", "/dev/ts0710mux0", "/dev/tun"
    };
    for (size_t i = 0; i < sizeof(api10_hardware_nodes) / sizeof(api10_hardware_nodes[0]); ++i)
        assert(strcmp(guest_device_unimplemented_reason(api10_hardware_nodes[i]),
                      "api10-ueventd-declared-hardware-backend-not-implemented") == 0);
    assert(guest_device_unimplemented_reason("/dev/null") == NULL);
    assert(guest_device_unimplemented_reason("/dev/urandom") == NULL);
    assert(guest_device_unimplemented_reason("/dev/random") == NULL);
    assert(guest_device_unimplemented_reason("/dev/zero") == NULL);
    assert(guest_device_unimplemented_reason("/dev/full") == NULL);
    assert(guest_device_unimplemented_reason("/dev/.coldboot_done") == NULL);
    assert(guest_device_unimplemented_reason("/dev/__properties__") == NULL);
    assert(guest_device_unimplemented_reason("/dev/socket/property_service") == NULL);
    assert(strcmp(guest_device_unimplemented_reason("/dev/console"),
                  "unknown-guest-dev-node-fails-closed") == 0);
    assert(strcmp(guest_device_unimplemented_reason("/dev/logical-not-a-device"),
                  "unknown-guest-dev-node-fails-closed") == 0);
    assert(strcmp(guest_device_unimplemented_reason("/dev/socketX"),
                  "unknown-guest-dev-node-fails-closed") == 0);
    puts("guest device boundary regression: PASS (API10 ueventd hardware nodes and unknown paths fail closed; guest-private nodes allowlisted; no host /dev substitution)");
    return 0;
}
