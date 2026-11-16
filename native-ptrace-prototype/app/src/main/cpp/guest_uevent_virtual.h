#ifndef GINGERVM_GUEST_UEVENT_VIRTUAL_H
#define GINGERVM_GUEST_UEVENT_VIRTUAL_H

#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "guest_hardware_profile.h"

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

/*
 * API10 init.goldfish.sh configures eth0. Model only that source-backed virtual
 * network interface; do not invent block devices or host-derived hardware.
 * API10 parse_event() accepts the no-DEVNAME net event, and handle_device_event()
 * consequently creates no /dev node and performs no host-device operation.
 */
static inline int guest_uevent_enqueue_coldboot_add(
        struct guest_uevent_queue *queue, int authorized_ueventd,
        const char *guest_attribute_path, const void *bytes, size_t length) {
    static const char request[] = "add\n";
    static const char header[] = "add@" GUEST_UEVENT_SYSFS_DEVICE_PATH;
    static const char action[] = "ACTION=add";
    static const char devpath[] = "DEVPATH=" GUEST_UEVENT_SYSFS_DEVICE_PATH;
    static const char subsystem[] = "SUBSYSTEM=net";
    static const char interface_name[] = "INTERFACE=" GUEST_PROFILE_NET_IFACE;
    if (!queue || !guest_attribute_path || (!bytes && length != 0)) return -EINVAL;
    if (!authorized_ueventd) { queue->rejected++; return -EPERM; }
    if (strcmp(guest_attribute_path, GUEST_UEVENT_SYSFS_ATTRIBUTE_PATH) != 0) {
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
        size_t field_bytes = sizeof(field); \
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
    GUEST_UEVENT_APPEND_FIELD(interface_name);
#undef GUEST_UEVENT_APPEND_FIELD
    event->length = offset;
    queue->count++;
    queue->enqueued++;
    return (int)length;
}

/* Returns 1 exactly once both API10 observations have occurred, in either order. */
static inline int guest_coldboot_note_marker_open(
        struct guest_coldboot_observation *observation, int is_ueventd,
        const char *guest_path, int32_t result) {
    if (!observation || !is_ueventd || !guest_path ||
        strcmp(guest_path, GUEST_COLD_BOOT_MARKER_PATH) != 0 || result < 0)
        return 0;
    observation->marker_opened_by_ueventd = 1;
    return 0;
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
