#ifndef GINGERVM_GUEST_UEVENT_VIRTUAL_H
#define GINGERVM_GUEST_UEVENT_VIRTUAL_H

#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "guest_hardware_profile.h"
#include "guest_framebuffer_virtual.h"
#include "guest_goldfish_tty_virtual.h"

#define GUEST_UEVENT_AF_NETLINK 16u
#define GUEST_UEVENT_SOCK_DGRAM 2u
#define GUEST_UEVENT_NETLINK_KOBJECT_UEVENT 15u
#define GUEST_UEVENT_SOL_SOCKET 1u
#define GUEST_UEVENT_SO_PASSCRED 16u
#define GUEST_UEVENT_SO_RCVBUFFORCE 33u
#define GUEST_UEVENT_RCVBUFFORCE_BYTES 65536
#define GUEST_UEVENT_QUEUE_CAPACITY 8u
#define GUEST_UEVENT_MESSAGE_CAPACITY 1024u
#define GUEST_UEVENT_SYSFS_DEVICE_PATH "/devices/virtual/net/" GUEST_PROFILE_NET_IFACE
#define GUEST_UEVENT_SYSFS_ATTRIBUTE_PATH "/sys" GUEST_UEVENT_SYSFS_DEVICE_PATH "/uevent"
#define GUEST_COLD_BOOT_MARKER_PATH "/dev/.coldboot_done"

struct guest_uevent_sockaddr_nl {
    uint16_t family;
    uint16_t pad;
    uint32_t pid;
    uint32_t groups;
};

/* ARM32 userspace ABI layouts consumed by API10 ueventd's recvmsg(). */
struct guest_arm32_iovec {
    uint32_t base;
    uint32_t length;
};

struct guest_arm32_msghdr {
    uint32_t name;
    uint32_t name_length;
    uint32_t iov;
    uint32_t iov_length;
    uint32_t control;
    uint32_t control_length;
    int32_t flags;
};

struct guest_arm32_cmsghdr {
    uint32_t length;
    int32_t level;
    int32_t type;
};

struct guest_arm32_ucred {
    int32_t pid;
    int32_t uid;
    int32_t gid;
};

struct guest_uevent_event {
    size_t length;
    unsigned char data[GUEST_UEVENT_MESSAGE_CAPACITY];
};

struct guest_uevent_queue {
    struct guest_uevent_event events[GUEST_UEVENT_QUEUE_CAPACITY];
    size_t head;
    size_t count;
    unsigned long enqueued;
    unsigned long delivered;
    unsigned long rejected;
};

struct guest_coldboot_observation {
    int marker_opened_by_ueventd;
    uint32_t marker_open_flags;
    uint32_t marker_open_mode;
    int32_t marker_open_fd;
    int32_t marker_open_result;
    int marker_close_observed;
    int32_t marker_close_result;
    int pid1_stat_succeeded_after_marker;
    int marker_stat_pair_observed;
    unsigned long pid1_stat_checks;
};

static inline int guest_uevent_socket_args_valid(uint32_t domain,
                                                  uint32_t type,
                                                  uint32_t protocol) {
    return domain == GUEST_UEVENT_AF_NETLINK &&
           type == GUEST_UEVENT_SOCK_DGRAM &&
           protocol == GUEST_UEVENT_NETLINK_KOBJECT_UEVENT;
}

static inline int guest_uevent_bind_args_valid(
        const struct guest_uevent_sockaddr_nl *addr, size_t addr_len,
        uint32_t guest_pid) {
    return addr != NULL && addr_len >= sizeof(*addr) &&
           addr->family == GUEST_UEVENT_AF_NETLINK && addr->pad == 0 &&
           addr->pid == guest_pid && addr->groups == UINT32_MAX;
}

static inline int guest_uevent_setsockopt_args_valid(uint32_t level,
                                                      uint32_t option,
                                                      int32_t value,
                                                      uint32_t value_len) {
    if (level != GUEST_UEVENT_SOL_SOCKET || value_len < sizeof(value))
        return 0;
    if (option == GUEST_UEVENT_SO_RCVBUFFORCE)
        return value == GUEST_UEVENT_RCVBUFFORCE_BYTES;
    if (option == GUEST_UEVENT_SO_PASSCRED)
        return value == 1;
    return 0;
}

static inline void guest_uevent_queue_init(struct guest_uevent_queue *queue) {
    if (queue) memset(queue, 0, sizeof(*queue));
}

static inline int guest_uevent_queue_readable(const struct guest_uevent_queue *queue) {
    return queue && queue->count != 0;
}

static inline const struct guest_uevent_event *guest_uevent_queue_front(
        const struct guest_uevent_queue *queue) {
    if (!queue || queue->count == 0) return NULL;
    return &queue->events[queue->head];
}

static inline int guest_uevent_queue_consume(struct guest_uevent_queue *queue) {
    if (!queue || queue->count == 0) return -EAGAIN;
    queue->head = (queue->head + 1u) % GUEST_UEVENT_QUEUE_CAPACITY;
    queue->count--;
    queue->delivered++;
    return 0;
}

/* API10 ueventd consumes source-backed Goldfish net and graphics events. */
static inline int guest_uevent_enqueue_coldboot_add(
        struct guest_uevent_queue *queue, int authorized_ueventd,
        const char *guest_attribute_path, const void *bytes, size_t length) {
    static const char request[] = "add\n";
    static const char net_header[] = "add@" GUEST_UEVENT_SYSFS_DEVICE_PATH;
    static const char graphics_header[] = "add@" GUEST_FB0_SYSFS_DEVICE_PATH;
    static const char action[] = "ACTION=add";
    static const char net_devpath[] = "DEVPATH=" GUEST_UEVENT_SYSFS_DEVICE_PATH;
    static const char graphics_devpath[] = "DEVPATH=" GUEST_FB0_SYSFS_DEVICE_PATH;
    static const char net_subsystem[] = "SUBSYSTEM=net";
    static const char graphics_subsystem[] = "SUBSYSTEM=graphics";
    static const char interface_name[] = "INTERFACE=" GUEST_PROFILE_NET_IFACE;
    static const char graphics_major[] = "MAJOR=29";
    static const char graphics_minor[] = "MINOR=0";
    static const char tty_subsystem[] = "SUBSYSTEM=tty";
    const char *header = NULL, *devpath = NULL, *subsystem = NULL;
    const char *extra_one = NULL, *extra_two = NULL;
    char tty_header[96], tty_devpath[96], tty_major[24], tty_minor_text[24], tty_devname[32];
    uint32_t tty_minor = 0;
    if (!queue || !guest_attribute_path || (!bytes && length != 0)) return -EINVAL;
    if (!authorized_ueventd) { queue->rejected++; return -EPERM; }
    if (strcmp(guest_attribute_path, GUEST_UEVENT_SYSFS_ATTRIBUTE_PATH) == 0) {
        header = net_header; devpath = net_devpath; subsystem = net_subsystem;
        extra_one = interface_name;
    } else if (strcmp(guest_attribute_path, GUEST_FB0_SYSFS_ATTRIBUTE_PATH) == 0) {
        header = graphics_header; devpath = graphics_devpath;
        subsystem = graphics_subsystem; extra_one = graphics_major;
        extra_two = graphics_minor;
    } else if (guest_goldfish_tty_parse_sysfs_uevent_path(
                   guest_attribute_path, &tty_minor)) {
        int n = snprintf(tty_header, sizeof(tty_header), "add@%s%u",
            GUEST_GOLDFISH_TTY_SYSFS_DEVICE_PREFIX, tty_minor);
        if (n <= 0 || (size_t)n >= sizeof(tty_header)) return -ENAMETOOLONG;
        n = snprintf(tty_devpath, sizeof(tty_devpath), "DEVPATH=%s%u",
            GUEST_GOLDFISH_TTY_SYSFS_DEVICE_PREFIX, tty_minor);
        if (n <= 0 || (size_t)n >= sizeof(tty_devpath)) return -ENAMETOOLONG;
        n = snprintf(tty_major, sizeof(tty_major), "MAJOR=%u",
            GUEST_GOLDFISH_TTY_SYNTHETIC_MAJOR);
        if (n <= 0 || (size_t)n >= sizeof(tty_major)) return -ENAMETOOLONG;
        n = snprintf(tty_minor_text, sizeof(tty_minor_text), "MINOR=%u", tty_minor);
        if (n <= 0 || (size_t)n >= sizeof(tty_minor_text)) return -ENAMETOOLONG;
        n = snprintf(tty_devname, sizeof(tty_devname), "DEVNAME=ttyS%u", tty_minor);
        if (n <= 0 || (size_t)n >= sizeof(tty_devname)) return -ENAMETOOLONG;
        header = tty_header; devpath = tty_devpath; subsystem = tty_subsystem;
        extra_one = tty_major; extra_two = tty_minor_text;
    } else {
        queue->rejected++;
        return -ENOENT;
    }
    if (length != sizeof(request) - 1u || memcmp(bytes, request, length) != 0) {
        queue->rejected++;
        return -EINVAL;
    }
    if (queue->count >= GUEST_UEVENT_QUEUE_CAPACITY) {
        queue->rejected++;
        return -ENOBUFS;
    }
    size_t slot = (queue->head + queue->count) % GUEST_UEVENT_QUEUE_CAPACITY;
    struct guest_uevent_event *event = &queue->events[slot];
    size_t offset = 0;
#define GUEST_UEVENT_APPEND_FIELD(field) do { \
        size_t field_bytes = strlen(field) + 1u; \
        if (field_bytes > sizeof(event->data) - offset) { \
            queue->rejected++; return -EMSGSIZE; \
        } \
        memcpy(event->data + offset, (field), field_bytes); \
        offset += field_bytes; \
    } while (0)
    GUEST_UEVENT_APPEND_FIELD(header);
    GUEST_UEVENT_APPEND_FIELD(action);
    GUEST_UEVENT_APPEND_FIELD(devpath);
    GUEST_UEVENT_APPEND_FIELD(subsystem);
    if (extra_one) GUEST_UEVENT_APPEND_FIELD(extra_one);
    if (extra_two) GUEST_UEVENT_APPEND_FIELD(extra_two);
    if (tty_minor < GUEST_GOLDFISH_TTY_LINE_COUNT &&
        subsystem == tty_subsystem) GUEST_UEVENT_APPEND_FIELD(tty_devname);
#undef GUEST_UEVENT_APPEND_FIELD
    event->length = offset;
    queue->count++;
    queue->enqueued++;
    return (int)length;
}

static inline int guest_coldboot_marker_open_args_valid(uint32_t flags,
                                                         uint32_t mode) {
    uint32_t source_flags = O_WRONLY | O_CREAT;
    int flags_match = flags == source_flags;
#ifdef O_LARGEFILE
    flags_match = flags_match || flags == (source_flags | O_LARGEFILE);
#endif
    return flags_match && (mode & 07777u) == 0;
}

/* API10 devices.c creates the marker with open(O_WRONLY|O_CREAT, 0000). */
static inline int guest_coldboot_note_marker_open(
        struct guest_coldboot_observation *observation, int is_ueventd,
        const char *guest_path, uint32_t flags, uint32_t mode,
        int32_t result) {
    if (!observation || !is_ueventd || !guest_path ||
        strcmp(guest_path, GUEST_COLD_BOOT_MARKER_PATH) != 0 || result < 0 ||
        !guest_coldboot_marker_open_args_valid(flags, mode) ||
        observation->marker_opened_by_ueventd)
        return 0;
    observation->marker_opened_by_ueventd = 1;
    observation->marker_open_flags = flags;
    observation->marker_open_mode = mode;
    observation->marker_open_fd = result;
    observation->marker_open_result = result;
    return 0;
}

static inline int guest_coldboot_note_marker_close(
        struct guest_coldboot_observation *observation, int is_ueventd,
        int32_t fd, int32_t result) {
    if (!observation || !is_ueventd ||
        !observation->marker_opened_by_ueventd ||
        fd != observation->marker_open_fd || observation->marker_close_observed)
        return 0;
    observation->marker_close_observed = 1;
    observation->marker_close_result = result;
    return 1;
}

static inline int guest_coldboot_note_pid1_stat(
        struct guest_coldboot_observation *observation, uint32_t guest_pid,
        const char *guest_path, int32_t result) {
    if (!observation || guest_pid != 1 || !guest_path ||
        strcmp(guest_path, GUEST_COLD_BOOT_MARKER_PATH) != 0)
        return 0;
    observation->pid1_stat_checks++;
    if (result == 0 && observation->marker_opened_by_ueventd)
        observation->pid1_stat_succeeded_after_marker = 1;
    if (observation->pid1_stat_succeeded_after_marker &&
        !observation->marker_stat_pair_observed) {
        observation->marker_stat_pair_observed = 1;
        return 1;
    }
    return 0;
}

#endif
