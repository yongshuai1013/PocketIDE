#ifndef GINGERVM_GUEST_GOLDFISH_TTY_VIRTUAL_H
#define GINGERVM_GUEST_GOLDFISH_TTY_VIRTUAL_H

#include "guest_socket_virtual.h"

#include <errno.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/*
 * API10 Goldfish source registers eight dynamically allocated ttyS lines.
 * GingerVM's 240:0-7 assignment is a synthetic guest-profile number only; no
 * matching kernel was booted and this is not the Goldfish runtime major.
 */
#define GUEST_GOLDFISH_TTY_LINE_COUNT 8u
#define GUEST_GOLDFISH_TTY_SYNTHETIC_MAJOR 240u
#define GUEST_GOLDFISH_TTY_MINOR_BASE 0u
#define GUEST_GOLDFISH_TTY_QEMUD_MINOR 1u
#define GUEST_GOLDFISH_TTY_MODE 0020600u
#define GUEST_GOLDFISH_TTY_DEVICE_PREFIX "/dev/ttyS"
#define GUEST_GOLDFISH_TTY_SYSFS_DEVICE_PREFIX "/devices/virtual/tty/ttyS"
#define GUEST_GOLDFISH_TTY_SYSFS_ATTRIBUTE_PREFIX "/sys/devices/virtual/tty/ttyS"
#define GUEST_GOLDFISH_TTY_SYSFS_CLASS_PATH "/sys/class/tty"
#define GUEST_GOLDFISH_TTY_SYSFS_CLASS_DEVICE_PREFIX "/sys/class/tty/ttyS"
#define GUEST_GOLDFISH_TTY_QEMUD_SOCKET_PATH "/dev/socket/qemud"
#define GUEST_GOLDFISH_TTY_QEMUD_BACKLOG_MAX 128
#define GUEST_GOLDFISH_TTY_TCGETS 0x5401u
#define GUEST_GOLDFISH_TTY_TCSETS 0x5402u
#define GUEST_GOLDFISH_TTY_O_LARGEFILE 0400000u
#define GUEST_GOLDFISH_TTY_TERMios_BYTES 36u
#define GUEST_GOLDFISH_TTY_EPOLL_MAX_INSTANCES 8u
#define GUEST_GOLDFISH_TTY_EPOLL_MAX_WATCHES 8u
#define GUEST_GOLDFISH_TTY_EPOLL_CTL_ADD 1
#define GUEST_GOLDFISH_TTY_EPOLL_CTL_DEL 2
#define GUEST_GOLDFISH_TTY_EPOLL_CTL_MOD 3
#define GUEST_GOLDFISH_TTY_EPOLLIN 0x00000001u
#define GUEST_GOLDFISH_TTY_EPOLLHUP 0x00000010u
#define GUEST_GOLDFISH_TTY_EPOLLET 0x80000000u
#define GUEST_GOLDFISH_TTY_RX_CAPACITY 4096u
#define GUEST_GOLDFISH_TTY_READ_PARK INT32_MIN
#define GUEST_GOLDFISH_TTY_EPOLL_WAIT_PARK INT32_MIN

/* Paired API10 ARM bionic asm/termbits.h: four u32 flags, line byte, cc[19]. */
struct guest_arm32_termios {
    uint32_t c_iflag;
    uint32_t c_oflag;
    uint32_t c_cflag;
    uint32_t c_lflag;
    uint8_t c_line;
    uint8_t c_cc[19];
};

/* API10 Bionic epoll.h: events at byte 0, the 64-bit data union at byte 8. */
struct guest_arm32_epoll_event {
    uint32_t events;
    uint32_t abi_padding;
    uint64_t data;
};

_Static_assert(sizeof(struct guest_arm32_termios) == GUEST_GOLDFISH_TTY_TERMios_BYTES,
               "API10 ARM32 termios layout");
_Static_assert(sizeof(struct guest_arm32_epoll_event) == 16u,
               "API10 ARM32 epoll_event size");
_Static_assert(offsetof(struct guest_arm32_epoll_event, data) == 8u,
               "API10 ARM32 epoll_event data offset");

enum guest_goldfish_tty_epoll_status {
    GUEST_GOLDFISH_TTY_EPOLL_READY = 0,
    GUEST_GOLDFISH_TTY_EPOLL_PARK = 1,
};

struct guest_goldfish_tty_runtime {
    uint8_t uevent_mask;
    uint8_t node_mask;
    uint8_t peer_attached;
    int tty_fd;
    uint8_t rx[GUEST_GOLDFISH_TTY_RX_CAPACITY];
    size_t rx_length;
    struct guest_arm32_termios termios[GUEST_GOLDFISH_TTY_LINE_COUNT];
    unsigned long events_received;
    unsigned long mknod_attempts;
    unsigned long nodes_created;
    unsigned long nodes_reused;
    unsigned long open_attempts;
    unsigned long ioctl_gets;
    unsigned long ioctl_sets;
    unsigned long empty_reads;
    unsigned long writes_without_peer;
    unsigned long peer_write_calls;
    unsigned long peer_write_bytes;
    unsigned long peer_read_bytes;
    unsigned long rx_overflows;
    unsigned long epoll_creates;
    unsigned long epoll_controls;
    unsigned long epoll_empty_waits;
    unsigned long unsupported;
};

struct guest_goldfish_tty_epoll_watch {
    int registered;
    int fd;
    uint32_t events;
    uint64_t data;
    uint8_t last_ready;
};

struct guest_goldfish_tty_epoll_instance {
    int allocated;
    int fd;
    uint32_t owner_table_id;
    struct guest_goldfish_tty_epoll_watch watches[GUEST_GOLDFISH_TTY_EPOLL_MAX_WATCHES];
};

struct guest_goldfish_tty_epoll_table {
    struct guest_goldfish_tty_epoll_instance instances[GUEST_GOLDFISH_TTY_EPOLL_MAX_INSTANCES];
};

static inline void guest_goldfish_tty_runtime_init(struct guest_goldfish_tty_runtime *runtime) {
    if (!runtime) return;
    memset(runtime, 0, sizeof(*runtime));
    runtime->tty_fd = -1;
    static const uint8_t default_cc[19] = {
        0x03, 0x1c, 0x7f, 0x15, 0x04, 0x00, 0x01, 0x00, 0x11, 0x13,
        0x1a, 0x00, 0x12, 0x0f, 0x17, 0x16, 0x00, 0x00, 0x00,
    };
    for (size_t i = 0; i < GUEST_GOLDFISH_TTY_LINE_COUNT; ++i) {
        struct guest_arm32_termios *t = &runtime->termios[i];
        t->c_iflag = 0000400u | 0002000u; /* ICRNL | IXON */
        t->c_oflag = 0000001u | 0000004u; /* OPOST | ONLCR */
        t->c_cflag = 0000017u | 0000060u | 0000200u | 0002000u; /* B38400 | CS8 | CREAD | HUPCL */
        t->c_lflag = 0000001u | 0000002u | 0000010u | 0000020u | 0000040u |
                     0001000u | 0004000u | 0100000u; /* API10 tty_std_termios */
        t->c_line = 0;
        memcpy(t->c_cc, default_cc, sizeof(default_cc));
    }
}

static inline void guest_goldfish_tty_epoll_table_init(
        struct guest_goldfish_tty_epoll_table *table) {
    if (table) memset(table, 0, sizeof(*table));
}

static inline int guest_goldfish_tty_parse_device_path(const char *path,
                                                       uint32_t *minor) {
    static const char prefix[] = GUEST_GOLDFISH_TTY_DEVICE_PREFIX;
    if (!path || !minor || strncmp(path, prefix, sizeof(prefix) - 1u) != 0)
        return 0;
    const char *suffix = path + sizeof(prefix) - 1u;
    if (suffix[0] < '0' || suffix[0] > '7' || suffix[1] != '\0') return 0;
    *minor = (uint32_t)(suffix[0] - '0');
    return 1;
}

static inline int guest_goldfish_tty_parse_sysfs_uevent_path(const char *path,
                                                             uint32_t *minor) {
    static const char prefix[] = GUEST_GOLDFISH_TTY_SYSFS_ATTRIBUTE_PREFIX;
    if (!path || !minor || strncmp(path, prefix, sizeof(prefix) - 1u) != 0)
        return 0;
    const char *suffix = path + sizeof(prefix) - 1u;
    if (suffix[0] < '0' || suffix[0] > '7' || strcmp(suffix + 1, "/uevent") != 0)
        return 0;
    *minor = (uint32_t)(suffix[0] - '0');
    return 1;
}

static inline uint32_t guest_goldfish_tty_makedev(uint32_t major, uint32_t minor) {
    return ((major & 0xfffu) << 8) | (minor & 0xffu) |
           ((minor & ~0xffu) << 12);
}

static inline int guest_goldfish_tty_append_field(char *out, size_t capacity,
                                                  size_t *used, const char *field) {
    size_t length = strlen(field) + 1u;
    if (!out || !used || !field || *used > capacity || length > capacity - *used)
        return -ENOSPC;
    memcpy(out + *used, field, length);
    *used += length;
    return 0;
}

static inline int guest_goldfish_tty_build_add_event(uint32_t minor, char *out,
                                                     size_t capacity,
                                                     size_t *event_length) {
    if (!out || !event_length || minor >= GUEST_GOLDFISH_TTY_LINE_COUNT)
        return -EINVAL;
    char header[96], devpath[96], major[24], minor_text[24], devname[32];
    int n = snprintf(header, sizeof(header), "add@%s%u",
                     GUEST_GOLDFISH_TTY_SYSFS_DEVICE_PREFIX, minor);
    if (n <= 0 || (size_t)n >= sizeof(header)) return -ENAMETOOLONG;
    n = snprintf(devpath, sizeof(devpath), "DEVPATH=%s%u",
                 GUEST_GOLDFISH_TTY_SYSFS_DEVICE_PREFIX, minor);
    if (n <= 0 || (size_t)n >= sizeof(devpath)) return -ENAMETOOLONG;
    n = snprintf(major, sizeof(major), "MAJOR=%u", GUEST_GOLDFISH_TTY_SYNTHETIC_MAJOR);
    if (n <= 0 || (size_t)n >= sizeof(major)) return -ENAMETOOLONG;
    n = snprintf(minor_text, sizeof(minor_text), "MINOR=%u", minor);
    if (n <= 0 || (size_t)n >= sizeof(minor_text)) return -ENAMETOOLONG;
    n = snprintf(devname, sizeof(devname), "DEVNAME=ttyS%u", minor);
    if (n <= 0 || (size_t)n >= sizeof(devname)) return -ENAMETOOLONG;
    size_t used = 0;
    const char *fields[] = {header, "ACTION=add", devpath, "SUBSYSTEM=tty",
                            major, minor_text, devname};
    for (size_t i = 0; i < sizeof(fields) / sizeof(fields[0]); ++i) {
        int rc = guest_goldfish_tty_append_field(out, capacity, &used, fields[i]);
        if (rc != 0) return rc;
    }
    *event_length = used;
    return 0;
}

static inline int guest_goldfish_tty_event_matches(const void *data, size_t length,
                                                   uint32_t *minor_out) {
    if (!data || !length || !minor_out || length > 512u) return 0;
    const unsigned char *bytes = (const unsigned char *)data;
    size_t offset = 0;
    uint32_t minor = UINT32_MAX;
    unsigned seen = 0;
    while (offset < length) {
        size_t end = offset;
        while (end < length && bytes[end] != 0) end++;
        if (end == length) return 0;
        size_t token_length = end - offset;
        char token[128];
        if (token_length >= sizeof(token)) return 0;
        memcpy(token, bytes + offset, token_length);
        token[token_length] = '\0';
        if (strncmp(token, "add@" GUEST_GOLDFISH_TTY_SYSFS_DEVICE_PREFIX, 4u +
                    sizeof(GUEST_GOLDFISH_TTY_SYSFS_DEVICE_PREFIX) - 1u) == 0) {
            const char *digit = token + 4u + sizeof(GUEST_GOLDFISH_TTY_SYSFS_DEVICE_PREFIX) - 1u;
            if (digit[0] >= '0' && digit[0] <= '7' && digit[1] == '\0') {
                minor = (uint32_t)(digit[0] - '0');
                seen |= 1u;
            }
        } else if (strcmp(token, "ACTION=add") == 0) {
            seen |= 2u;
        } else if (strcmp(token, "SUBSYSTEM=tty") == 0) {
            seen |= 4u;
        } else if (strcmp(token, "DEVPATH=/devices/virtual/tty/ttyS0") == 0 ||
                   strcmp(token, "DEVPATH=/devices/virtual/tty/ttyS1") == 0 ||
                   strcmp(token, "DEVPATH=/devices/virtual/tty/ttyS2") == 0 ||
                   strcmp(token, "DEVPATH=/devices/virtual/tty/ttyS3") == 0 ||
                   strcmp(token, "DEVPATH=/devices/virtual/tty/ttyS4") == 0 ||
                   strcmp(token, "DEVPATH=/devices/virtual/tty/ttyS5") == 0 ||
                   strcmp(token, "DEVPATH=/devices/virtual/tty/ttyS6") == 0 ||
                   strcmp(token, "DEVPATH=/devices/virtual/tty/ttyS7") == 0) {
            const char *digit = token + strlen("DEVPATH=/devices/virtual/tty/ttyS");
            if (minor != UINT32_MAX && digit[0] == (char)('0' + minor) && digit[1] == '\0')
                seen |= 8u;
        } else if (strcmp(token, "MAJOR=240") == 0) {
            seen |= 16u;
        } else if (strncmp(token, "MINOR=", 6u) == 0 && token[6] >= '0' &&
                   token[6] <= '7' && token[7] == '\0') {
            if (minor != UINT32_MAX && (uint32_t)(token[6] - '0') == minor) seen |= 32u;
        } else if (strncmp(token, "DEVNAME=ttyS", 12u) == 0 &&
                   token[12] >= '0' && token[12] <= '7' && token[13] == '\0') {
            if (minor != UINT32_MAX && (uint32_t)(token[12] - '0') == minor) seen |= 64u;
        }
        offset = end + 1u;
    }
    if (seen != 127u || minor >= GUEST_GOLDFISH_TTY_LINE_COUNT) return 0;
    *minor_out = minor;
    return 1;
}

static inline int guest_goldfish_tty_note_event(struct guest_goldfish_tty_runtime *runtime,
                                                const void *data, size_t length,
                                                uint32_t *minor_out) {
    uint32_t minor = 0;
    if (!runtime || !guest_goldfish_tty_event_matches(data, length, &minor)) return 0;
    runtime->uevent_mask |= (uint8_t)(1u << minor);
    runtime->events_received++;
    if (minor_out) *minor_out = minor;
    return 1;
}

static inline int guest_goldfish_tty_mknod_validate(
        const struct guest_goldfish_tty_runtime *runtime, int verified_ueventd,
        const char *path, uint32_t mode, uint32_t device, uint32_t *minor_out) {
    uint32_t minor = 0;
    if (!runtime || !guest_goldfish_tty_parse_device_path(path, &minor))
        return -EOPNOTSUPP;
    if (!verified_ueventd) return -EPERM;
    if ((runtime->uevent_mask & (uint8_t)(1u << minor)) == 0) return -ENOENT;
    if ((mode & 0177777u) != (GUEST_GOLDFISH_TTY_MODE & 0177777u)) return -EINVAL;
    if (device != guest_goldfish_tty_makedev(GUEST_GOLDFISH_TTY_SYNTHETIC_MAJOR, minor))
        return -EINVAL;
    if (minor_out) *minor_out = minor;
    return 0;
}

static inline void guest_goldfish_tty_note_node_created(
        struct guest_goldfish_tty_runtime *runtime, uint32_t minor) {
    if (!runtime || minor >= GUEST_GOLDFISH_TTY_LINE_COUNT) return;
    runtime->node_mask |= (uint8_t)(1u << minor);
    runtime->nodes_created++;
}

static inline void guest_goldfish_tty_note_node_reused(
        struct guest_goldfish_tty_runtime *runtime, uint32_t minor) {
    if (!runtime || minor >= GUEST_GOLDFISH_TTY_LINE_COUNT) return;
    runtime->node_mask |= (uint8_t)(1u << minor);
    runtime->nodes_reused++;
}

static inline int guest_goldfish_tty_open_validate(
        const struct guest_goldfish_tty_runtime *runtime, int verified_qemud,
        const char *path, uint32_t flags, uint32_t *minor_out) {
    uint32_t minor = 0;
    if (!runtime || !guest_goldfish_tty_parse_device_path(path, &minor))
        return -EOPNOTSUPP;
    if (!verified_qemud) return -EPERM;
    if (minor != GUEST_GOLDFISH_TTY_QEMUD_MINOR) return -EOPNOTSUPP;
    if ((runtime->node_mask & (uint8_t)(1u << minor)) == 0) return -ENOENT;
    if (flags != (2u | GUEST_GOLDFISH_TTY_O_LARGEFILE)) return -EACCES;
    /* Owner trace ARM syscall 5 observed 0x20002 (O_RDWR|O_LARGEFILE). */
    if (runtime->tty_fd >= 0) return -EBUSY;
    if (minor_out) *minor_out = minor;
    return 0;
}

static inline int guest_goldfish_tty_note_open(struct guest_goldfish_tty_runtime *runtime,
                                              uint32_t minor, int fd) {
    if (!runtime || minor != GUEST_GOLDFISH_TTY_QEMUD_MINOR || fd < 0 ||
        runtime->tty_fd >= 0) return -EINVAL;
    runtime->tty_fd = fd;
    return 0;
}

static inline int guest_goldfish_tty_note_peer_attached(
        struct guest_goldfish_tty_runtime *runtime, int fd) {
    if (!runtime || runtime->tty_fd != fd) return -EBADF;
    runtime->peer_attached = 1u;
    return 0;
}

static inline int guest_goldfish_tty_write_result(
        struct guest_goldfish_tty_runtime *runtime, int fd, size_t length);

static inline int guest_goldfish_tty_rx_enqueue(
        struct guest_goldfish_tty_runtime *runtime,
        const void *bytes, size_t length) {
    if (!runtime || (!bytes && length)) return -EINVAL;
    if (runtime->tty_fd < 0 || !runtime->peer_attached) return -ENOTCONN;
    if (length > GUEST_GOLDFISH_TTY_RX_CAPACITY - runtime->rx_length) {
        runtime->rx_overflows++;
        return -ENOBUFS;
    }
    if (length) memcpy(runtime->rx + runtime->rx_length, bytes, length);
    runtime->rx_length += length;
    return 0;
}

static inline size_t guest_goldfish_tty_rx_available(
        const struct guest_goldfish_tty_runtime *runtime) {
    if (!runtime || runtime->rx_length > GUEST_GOLDFISH_TTY_RX_CAPACITY) return 0u;
    return GUEST_GOLDFISH_TTY_RX_CAPACITY - runtime->rx_length;
}

static inline int guest_goldfish_tty_rx_peek(
        struct guest_goldfish_tty_runtime *runtime, int fd,
        void *out, size_t length) {
    if (!runtime || fd != runtime->tty_fd) return -EBADF;
    if (length == 0u) return 0;
    if (!out) return -EFAULT;
    if (runtime->rx_length == 0u) return -EAGAIN;
    size_t copied = length < runtime->rx_length ? length : runtime->rx_length;
    memcpy(out, runtime->rx, copied);
    return (int)copied;
}

static inline int guest_goldfish_tty_rx_consume(
        struct guest_goldfish_tty_runtime *runtime, int fd, size_t length) {
    if (!runtime || fd != runtime->tty_fd) return -EBADF;
    if (length > runtime->rx_length) return -EINVAL;
    runtime->rx_length -= length;
    if (length) memmove(runtime->rx, runtime->rx + length, runtime->rx_length);
    runtime->peer_read_bytes += length;
    return 0;
}

static inline int guest_goldfish_tty_read_bytes(
        struct guest_goldfish_tty_runtime *runtime, int fd,
        void *out, size_t length, int nonblocking) {
    if (!runtime || fd != runtime->tty_fd) return -EBADF;
    int rc = guest_goldfish_tty_rx_peek(runtime, fd, out, length);
    if (rc == -EAGAIN) {
        runtime->empty_reads++;
        return nonblocking ? -EAGAIN : GUEST_GOLDFISH_TTY_READ_PARK;
    }
    if (rc <= 0) return rc;
    int consume = guest_goldfish_tty_rx_consume(runtime, fd, (size_t)rc);
    return consume == 0 ? rc : consume;
}

static inline int guest_goldfish_tty_peer_write_result(
        struct guest_goldfish_tty_runtime *runtime, int fd, size_t length) {
    if (!runtime || fd != runtime->tty_fd) return -EBADF;
    if (length == 0u) return 0;
    if (!runtime->peer_attached) return guest_goldfish_tty_write_result(runtime, fd, length);
    if (length > (size_t)INT32_MAX) return -EINVAL;
    runtime->peer_write_calls++;
    runtime->peer_write_bytes += length;
    return (int)length;
}

static inline int guest_goldfish_tty_note_close(struct guest_goldfish_tty_runtime *runtime,
                                               int fd) {
    if (!runtime || runtime->tty_fd != fd) return -EBADF;
    runtime->tty_fd = -1;
    runtime->peer_attached = 0u;
    runtime->rx_length = 0u;
    return 0;
}

static inline int guest_goldfish_tty_ioctl(struct guest_goldfish_tty_runtime *runtime,
                                           int verified_qemud, int fd,
                                           uint32_t request, void *bytes,
                                           size_t capacity) {
    if (!runtime || fd != runtime->tty_fd) return -EBADF;
    if (!verified_qemud) return -EPERM;
    if (!bytes) return -EFAULT;
    if (capacity < sizeof(struct guest_arm32_termios)) return -EFAULT;
    struct guest_arm32_termios *termios = &runtime->termios[GUEST_GOLDFISH_TTY_QEMUD_MINOR];
    if (request == GUEST_GOLDFISH_TTY_TCGETS) {
        memcpy(bytes, termios, sizeof(*termios));
        runtime->ioctl_gets++;
        return 0;
    }
    if (request == GUEST_GOLDFISH_TTY_TCSETS) {
        memcpy(termios, bytes, sizeof(*termios));
        runtime->ioctl_sets++;
        return 0;
    }
    return -ENOTTY;
}

static inline int guest_goldfish_tty_read_result(
        struct guest_goldfish_tty_runtime *runtime, int fd, int nonblocking) {
    if (!runtime || fd != runtime->tty_fd) return -EBADF;
    runtime->empty_reads++;
    return nonblocking ? -EAGAIN : GUEST_GOLDFISH_TTY_READ_PARK;
}

static inline int guest_goldfish_tty_write_result(
        struct guest_goldfish_tty_runtime *runtime, int fd, size_t length) {
    if (!runtime || fd != runtime->tty_fd) return -EBADF;
    if (length == 0u) return 0;
    runtime->writes_without_peer++;
    return -EOPNOTSUPP; /* fail closed unless the verified profile peer is attached */
}

static inline int guest_goldfish_tty_poll_events(
        const struct guest_goldfish_tty_runtime *runtime, int fd,
        int16_t events) {
    if (!runtime || fd != runtime->tty_fd) return GUEST_VSOCKET_POLLNVAL;
    return runtime->rx_length > 0u && (events & GUEST_VSOCKET_POLLIN)
        ? GUEST_VSOCKET_POLLIN : 0;
}

static inline struct guest_goldfish_tty_epoll_instance *guest_goldfish_tty_epoll_find(
        struct guest_goldfish_tty_epoll_table *table, int fd) {
    if (!table) return NULL;
    for (size_t i = 0; i < GUEST_GOLDFISH_TTY_EPOLL_MAX_INSTANCES; ++i)
        if (table->instances[i].allocated && table->instances[i].fd == fd)
            return &table->instances[i];
    return NULL;
}

static inline int guest_goldfish_tty_epoll_create(
        struct guest_goldfish_tty_epoll_table *table,
        struct guest_vsocket_table *fds, int size, uint32_t owner_table_id) {
    if (!table || !fds || size <= 0 || owner_table_id == 0u) return -EINVAL;
    struct guest_goldfish_tty_epoll_instance *slot = NULL;
    for (size_t i = 0; i < GUEST_GOLDFISH_TTY_EPOLL_MAX_INSTANCES; ++i)
        if (!table->instances[i].allocated) { slot = &table->instances[i]; break; }
    if (!slot) return -ENOSPC;
    int fd = guest_vsocket_alloc_fd(fds, VIRTUAL_FD_EPOLL);
    if (fd < 0) return fd;
    memset(slot, 0, sizeof(*slot));
    slot->allocated = 1;
    slot->fd = fd;
    slot->owner_table_id = owner_table_id;
    return fd;
}

static inline int guest_goldfish_tty_epoll_ctl(
        struct guest_goldfish_tty_epoll_table *table,
        struct guest_vsocket_table *fds, int verified_qemud,
        uint32_t owner_table_id, int epfd, int operation, int fd,
        uint32_t events, uint64_t data, int tty_fd, int qemud_listener_fd) {
    if (!verified_qemud) return -EPERM;
    struct guest_goldfish_tty_epoll_instance *instance =
        guest_goldfish_tty_epoll_find(table, epfd);
    if (!instance || instance->owner_table_id != owner_table_id) return -EBADF;
    struct guest_vsocket_fd *epoll_fd = guest_vsocket_fd_get(fds, epfd);
    struct guest_vsocket_fd *watched_fd = guest_vsocket_fd_get(fds, fd);
    if (!epoll_fd || epoll_fd->kind != VIRTUAL_FD_EPOLL || !watched_fd) return -EBADF;
    int qemud_stream = watched_fd->kind == VIRTUAL_FD_QEMUD_ACCEPTED &&
        watched_fd->channel >= 0;
    if (!((fd == tty_fd && watched_fd->kind == VIRTUAL_FD_DEV_TTY) ||
          (fd == qemud_listener_fd && watched_fd->kind == VIRTUAL_FD_QEMUD_LISTENER) ||
          qemud_stream))
        return -EPERM;
    /* API10's Goldfish 2.6.29 epoll permits an empty interest mask; qemud
     * installs watches first and enables EPOLLIN later with EPOLL_CTL_MOD. */
    if (operation != GUEST_GOLDFISH_TTY_EPOLL_CTL_DEL &&
        (events & ~(GUEST_GOLDFISH_TTY_EPOLLIN |
                    GUEST_GOLDFISH_TTY_EPOLLET)) != 0u) return -EINVAL;
    struct guest_goldfish_tty_epoll_watch *found = NULL;
    struct guest_goldfish_tty_epoll_watch *free_slot = NULL;
    for (size_t i = 0; i < GUEST_GOLDFISH_TTY_EPOLL_MAX_WATCHES; ++i) {
        struct guest_goldfish_tty_epoll_watch *watch = &instance->watches[i];
        if (watch->registered && watch->fd == fd) found = watch;
        if (!watch->registered && !free_slot) free_slot = watch;
    }
    if (operation == GUEST_GOLDFISH_TTY_EPOLL_CTL_ADD) {
        if (found) return -EEXIST;
        if (!free_slot) return -ENOSPC;
        free_slot->registered = 1;
        free_slot->fd = fd;
        free_slot->events = events;
        free_slot->data = data;
        free_slot->last_ready = 0u;
        return 0;
    }
    if (operation == GUEST_GOLDFISH_TTY_EPOLL_CTL_MOD) {
        if (!found) return -ENOENT;
        found->events = events;
        found->data = data;
        found->last_ready = 0u;
        return 0;
    }
    if (operation == GUEST_GOLDFISH_TTY_EPOLL_CTL_DEL) {
        if (!found) return -ENOENT;
        memset(found, 0, sizeof(*found));
        return 0;
    }
    return -EINVAL;
}

static inline int guest_goldfish_tty_epoll_wait_result(
        struct guest_goldfish_tty_epoll_table *table, uint32_t owner_table_id,
        int epfd, int maxevents, int timeout_ms) {
    struct guest_goldfish_tty_epoll_instance *instance =
        guest_goldfish_tty_epoll_find(table, epfd);
    if (!instance || instance->owner_table_id != owner_table_id) return -EBADF;
    if (maxevents <= 0) return -EINVAL;
    if (timeout_ms < -1) return -EINVAL;
    if (timeout_ms == 0) return 0;
    if (timeout_ms == -1) return GUEST_GOLDFISH_TTY_EPOLL_WAIT_PARK;
    return -EOPNOTSUPP; /* timed waits need a guest timer source; none is modeled */
}

static inline int guest_goldfish_tty_epoll_collect(
        struct guest_goldfish_tty_epoll_table *table,
        struct guest_vsocket_table *fds,
        struct guest_goldfish_tty_runtime *tty,
        uint32_t owner_table_id, int epfd, int maxevents,
        struct guest_arm32_epoll_event *out) {
    struct guest_goldfish_tty_epoll_instance *instance =
        guest_goldfish_tty_epoll_find(table, epfd);
    if (!instance || instance->owner_table_id != owner_table_id) return -EBADF;
    if (maxevents <= 0 || !out) return -EINVAL;
    int count = 0;
    for (size_t i = 0; i < GUEST_GOLDFISH_TTY_EPOLL_MAX_WATCHES &&
                       count < maxevents; ++i) {
        struct guest_goldfish_tty_epoll_watch *watch = &instance->watches[i];
        if (!watch->registered) continue;
        uint32_t ready = 0u;
        if (watch->fd == tty->tty_fd && tty->rx_length > 0u) {
            ready = GUEST_GOLDFISH_TTY_EPOLLIN;
        } else {
            int16_t poll_events = guest_vsocket_poll_events(fds, watch->fd,
                                                            GUEST_VSOCKET_POLLIN);
            if (poll_events & GUEST_VSOCKET_POLLIN)
                ready |= GUEST_GOLDFISH_TTY_EPOLLIN;
            if (poll_events & GUEST_VSOCKET_POLLHUP)
                ready |= GUEST_GOLDFISH_TTY_EPOLLHUP;
        }
        int is_ready = ready != 0u &&
            ((watch->events & GUEST_GOLDFISH_TTY_EPOLLIN) != 0u ||
             (ready & GUEST_GOLDFISH_TTY_EPOLLHUP) != 0u);
        int edge = (watch->events & GUEST_GOLDFISH_TTY_EPOLLET) != 0u;
        int report = is_ready && (!edge || !watch->last_ready);
        watch->last_ready = (uint8_t)is_ready;
        if (!report) continue;
        out[count].events = ready;
        out[count].abi_padding = 0u;
        out[count].data = watch->data;
        count++;
    }
    return count;
}

static inline size_t guest_goldfish_tty_epoll_watch_count(
        const struct guest_goldfish_tty_epoll_table *table, int epfd) {
    if (!table) return 0;
    for (size_t i = 0; i < GUEST_GOLDFISH_TTY_EPOLL_MAX_INSTANCES; ++i) {
        const struct guest_goldfish_tty_epoll_instance *instance = &table->instances[i];
        if (!instance->allocated || instance->fd != epfd) continue;
        size_t count = 0;
        for (size_t j = 0; j < GUEST_GOLDFISH_TTY_EPOLL_MAX_WATCHES; ++j)
            if (instance->watches[j].registered) count++;
        return count;
    }
    return 0;
}

static inline int guest_goldfish_tty_epoll_close(
        struct guest_goldfish_tty_epoll_table *table, int fd) {
    struct guest_goldfish_tty_epoll_instance *instance =
        guest_goldfish_tty_epoll_find(table, fd);
    if (!instance) return -ENOENT;
    memset(instance, 0, sizeof(*instance));
    return 0;
}

static inline void guest_goldfish_tty_epoll_remove_watched_fd(
        struct guest_goldfish_tty_epoll_table *table, int fd) {
    if (!table) return;
    for (size_t i = 0; i < GUEST_GOLDFISH_TTY_EPOLL_MAX_INSTANCES; ++i) {
        struct guest_goldfish_tty_epoll_instance *instance = &table->instances[i];
        if (!instance->allocated) continue;
        for (size_t j = 0; j < GUEST_GOLDFISH_TTY_EPOLL_MAX_WATCHES; ++j)
            if (instance->watches[j].registered && instance->watches[j].fd == fd)
                memset(&instance->watches[j], 0, sizeof(instance->watches[j]));
    }
}

#endif
