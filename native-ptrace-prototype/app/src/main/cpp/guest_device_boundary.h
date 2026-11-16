#ifndef GINGERVM_GUEST_DEVICE_BOUNDARY_H
#define GINGERVM_GUEST_DEVICE_BOUNDARY_H

#include <stddef.h>
#include <string.h>

static inline int guest_device_path_prefix(const char *path, const char *prefix) {
    size_t length = strlen(prefix);
    return strncmp(path, prefix, length) == 0 &&
           (path[length] == '\0' || path[length] == '/');
}

static inline int guest_device_name_prefix(const char *path, const char *prefix) {
    size_t length = strlen(prefix);
    return strncmp(path, prefix, length) == 0;
}

static inline int guest_device_guest_file_path_is_allowed(const char *path) {
    if (!path) return 0;
    if (strcmp(path, "/dev") == 0 || strcmp(path, "/dev/__properties__") == 0 ||
        strcmp(path, "/dev/.coldboot_done") == 0 ||
        strcmp(path, "/dev/graphics/fb0") == 0 ||
        strcmp(path, "/dev/__null__") == 0 || strcmp(path, "/dev/__kmsg__") == 0 ||
        strcmp(path, "/dev/null") == 0 || strcmp(path, "/dev/zero") == 0 ||
        strcmp(path, "/dev/full") == 0 || strcmp(path, "/dev/random") == 0 ||
        strcmp(path, "/dev/urandom") == 0 ||
        strcmp(path, "/dev/socket") == 0 || guest_device_path_prefix(path, "/dev/socket"))
        return 1;
    return 0;
}

/* These are app-private API10 guest nodes only. Unknown /dev paths are denied
 * before VFS open; no host /dev, Binder, ashmem, PTY, GPU, radio, audio, input,
 * or emulator pipe endpoint is ever substituted. */
static inline const char *guest_device_unimplemented_reason(const char *path) {
    if (!path || !guest_device_path_prefix(path, "/dev") ||
        guest_device_guest_file_path_is_allowed(path)) return NULL;
    if (strcmp(path, "/dev/graphics/fb0") == 0) return NULL;

    if (strcmp(path, "/dev/ptmx") == 0 || strcmp(path, "/dev/tty") == 0 ||
        strcmp(path, "/dev/tty0") == 0 || guest_device_path_prefix(path, "/dev/pts") ||
        strcmp(path, "/dev/ttyMSM0") == 0 || strcmp(path, "/dev/ttyHS0") == 0)
        return "pty-kernel-backend-not-implemented";
    if (guest_device_path_prefix(path, "/dev/log"))
        return "android-log-device-backend-not-implemented";
    if (strcmp(path, "/dev/binder") == 0)
        return "binder-kernel-backend-not-implemented";
    if (strcmp(path, "/dev/ashmem") == 0)
        return "ashmem-kernel-backend-not-implemented";
    if (strcmp(path, "/dev/goldfish_pipe") == 0 ||
        strcmp(path, "/dev/qemu_pipe") == 0)
        return "goldfish-emulator-pipe-backend-not-implemented";

    if (guest_device_path_prefix(path, "/dev/graphics") ||
        guest_device_path_prefix(path, "/dev/input") ||
        guest_device_path_prefix(path, "/dev/snd") ||
        guest_device_path_prefix(path, "/dev/bus/usb") ||
        guest_device_path_prefix(path, "/dev/oncrpc") ||
        guest_device_path_prefix(path, "/dev/adsp") ||
        guest_device_path_prefix(path, "/dev/msm_camera"))
        return "api10-ueventd-declared-hardware-backend-not-implemented";

    static const char *const api10_device_prefixes[] = {
        "/dev/msm_hw3dc", "/dev/kgsl", "/dev/diag", "/dev/diag_arm9",
        "/dev/android_adb", "/dev/android_adb_enable", "/dev/uinput",
        "/dev/alarm", "/dev/msm_hw3dm", "/dev/eac", "/dev/cam",
        "/dev/pmem", "/dev/pmem_adsp", "/dev/pmem_camera", "/dev/mt9t013",
        "/dev/akm8976_daemon", "/dev/akm8976_aot", "/dev/akm8973_daemon",
        "/dev/akm8973_aot", "/dev/bma150", "/dev/cm3602", "/dev/akm8976_pffd",
        "/dev/lightsensor", "/dev/msm_pcm_out", "/dev/msm_pcm_in",
        "/dev/msm_pcm_ctl", "/dev/msm_snd", "/dev/msm_mp3",
        "/dev/audience_a1026", "/dev/tpa2018d1", "/dev/msm_audpre",
        "/dev/msm_audio_ctl", "/dev/htc-acoustic", "/dev/vdec", "/dev/q6venc",
        "/dev/smd0", "/dev/qmi", "/dev/usb_accessory", "/dev/ts0710mux",
        "/dev/ppp", "/dev/tun"
    };
    for (size_t i = 0; i < sizeof(api10_device_prefixes) / sizeof(api10_device_prefixes[0]); ++i)
        if (guest_device_name_prefix(path, api10_device_prefixes[i]))
            return "api10-ueventd-declared-hardware-backend-not-implemented";

    return "unknown-guest-dev-node-fails-closed";
}

#endif
