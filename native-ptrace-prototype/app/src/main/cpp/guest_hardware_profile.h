#ifndef GINGERVM_GUEST_HARDWARE_PROFILE_H
#define GINGERVM_GUEST_HARDWARE_PROFILE_H

/*
 * Guest profile: original Google Android 2.3.7 / API 10 SDK emulator image.
 * Identity fields are sourced from the staged build.prop/default.prop and
 * init.goldfish.sh. The original image does not contain a runtime Goldfish
 * kernel, so vCPU count and RAM below are explicit GingerVM synthetic defaults,
 * never observations copied from the host phone.
 */
#define GUEST_PROFILE_HARDWARE "goldfish"
#define GUEST_PROFILE_CPU_COUNT 1u
#define GUEST_PROFILE_SYNTHETIC_RAM_TOTAL_KB 262144u
#define GUEST_PROFILE_SYNTHETIC_RAM_FREE_KB 131072u

/* Explicit official API10 WVGA800 AVD-skin selection, not image-fixed mode. */
#define GUEST_PROFILE_DISPLAY_SKIN "WVGA800"
#define GUEST_PROFILE_DISPLAY_WIDTH 480u
#define GUEST_PROFILE_DISPLAY_HEIGHT 800u
#define GUEST_PROFILE_DISPLAY_DENSITY_DPI 240u

#define GUEST_PROFILE_PROC_CMDLINE \
    "qemu=1 android.qemud=ttyS1 androidboot.hardware=" GUEST_PROFILE_HARDWARE "\n"
#define GUEST_PROFILE_PROC_CPUINFO \
    "processor : 0\n" \
    "Processor : ARMv7 Processor rev 0 (v7l)\n" \
    "Hardware : " GUEST_PROFILE_HARDWARE "\n"
#define GUEST_PROFILE_PROC_MEMINFO \
    "MemTotal:       262144 kB\n" \
    "MemFree:        131072 kB\n"
#define GUEST_PROFILE_PROC_STAT \
    "cpu  0 0 0 0\n" \
    "cpu0 0 0 0 0\n"

/* Values used by the original API10 Goldfish init.goldfish.sh, guest-only. */
#define GUEST_PROFILE_NET_IFACE "eth0"
#define GUEST_PROFILE_NET_ADDRESS "10.0.2.15"
#define GUEST_PROFILE_NET_NETMASK "255.255.255.0"
#define GUEST_PROFILE_NET_GATEWAY "10.0.2.2"
#define GUEST_PROFILE_NET_DNS1 "10.0.2.3"

#endif
