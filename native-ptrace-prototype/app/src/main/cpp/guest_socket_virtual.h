#ifndef GINGERVM_GUEST_SOCKET_VIRTUAL_H
#define GINGERVM_GUEST_SOCKET_VIRTUAL_H

#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define GUEST_VSOCKET_FD_BASE 5000
#define GUEST_VSOCKET_MAX_FDS 32
#define GUEST_VSOCKET_MAX_CHANNELS 16
#define GUEST_VSOCKET_BUFFER_SIZE 4096
#define GUEST_VSOCKET_PROPERTY_PATH "/dev/socket/property_service"
#define GUEST_VSOCKET_AF_UNIX 1u
#define GUEST_VSOCKET_SOCK_STREAM 1u
#define GUEST_VSOCKET_SOL_SOCKET 1u
#define GUEST_VSOCKET_SO_PEERCRED 17u
#define GUEST_VSOCKET_F_GETFD 1
#define GUEST_VSOCKET_F_SETFD 2
#define GUEST_VSOCKET_F_GETFL 3
#define GUEST_VSOCKET_F_SETFL 4
#define GUEST_VSOCKET_FD_CLOEXEC 1
#define GUEST_VSOCKET_O_NONBLOCK 00004000
#define GUEST_VSOCKET_O_RDWR 2
#define GUEST_VSOCKET_POLLIN 0x0001
#define GUEST_VSOCKET_POLLHUP 0x0010
#define GUEST_VSOCKET_POLLNVAL 0x0020

/* These are guest descriptor kinds, not host kernel socket objects. */
enum virtual_fd_kind {
    VIRTUAL_FD_GENERIC = 0,
    VIRTUAL_FD_PROPERTY = 1,
    VIRTUAL_FD_UEVENT = 2,
    VIRTUAL_FD_PROPERTY_ACCEPTED = 3,
    VIRTUAL_FD_SIGNAL = 4,
};

enum guest_vsocket_channel_kind {
    GUEST_VSOCKET_CHANNEL_PROPERTY = 1,
    GUEST_VSOCKET_CHANNEL_SIGNAL = 2,
};

struct guest_vsocket_fd {
    int allocated;
    int fd;
    enum virtual_fd_kind kind;
    int channel;
    int side;
    int bound;
    int listening;
    int nonblocking;
};

struct guest_vsocket_channel {
    int allocated;
    enum guest_vsocket_channel_kind kind;
    int fd[2];
    int listener_fd;
    int pending;
    int closed[2];
    int32_t peer_pid;
    int32_t peer_uid;
    int32_t peer_gid;
    unsigned char data[2][GUEST_VSOCKET_BUFFER_SIZE];
    size_t data_len[2];
};

struct guest_vsocket_table {
    struct guest_vsocket_fd fds[GUEST_VSOCKET_MAX_FDS];
    struct guest_vsocket_channel channels[GUEST_VSOCKET_MAX_CHANNELS];
    int property_listener_fd;
    unsigned long created;
    unsigned long bound;
    unsigned long listening;
    unsigned long connected;
    unsigned long accepted;
    unsigned long sent_bytes;
    unsigned long received_bytes;
    unsigned long poll_readable;
    unsigned long signal_pairs;
};

struct guest_vsocket_peercred {
    int32_t pid;
    int32_t uid;
    int32_t gid;
};

static inline int guest_vsocket_socketcall_arg_count(int operation) {
    switch (operation) {
        case 1: case 2: case 3: case 5: return 3; /* socket, bind, connect, accept */
        case 4: return 2; /* listen */
        case 8: return 4; /* socketpair */
        case 9: case 10: return 4; /* send, recv */
        case 14: case 15: return 5; /* setsockopt, getsockopt */
        default: return -EOPNOTSUPP;
    }
}

static inline void guest_vsocket_table_init(struct guest_vsocket_table *table) {
    memset(table, 0, sizeof(*table));
    table->property_listener_fd = -1;
    for (size_t i = 0; i < GUEST_VSOCKET_MAX_FDS; ++i) {
        table->fds[i].fd = GUEST_VSOCKET_FD_BASE + (int)i;
        table->fds[i].channel = -1;
    }
    for (size_t i = 0; i < GUEST_VSOCKET_MAX_CHANNELS; ++i) {
        table->channels[i].fd[0] = -1;
        table->channels[i].fd[1] = -1;
        table->channels[i].listener_fd = -1;
    }
}

static inline int guest_vsocket_fd_slot(int fd) {
    int slot = fd - GUEST_VSOCKET_FD_BASE;
    return slot >= 0 && slot < GUEST_VSOCKET_MAX_FDS ? slot : -1;
}

static inline int guest_vsocket_fd_number_reserved(int fd) {
    return guest_vsocket_fd_slot(fd) >= 0;
}

static inline struct guest_vsocket_fd *guest_vsocket_fd_get(
        struct guest_vsocket_table *table, int fd) {
    int slot = guest_vsocket_fd_slot(fd);
    if (slot < 0 || !table->fds[slot].allocated) return NULL;
    return &table->fds[slot];
}

static inline struct guest_vsocket_channel *guest_vsocket_channel_get(
        struct guest_vsocket_table *table, int index) {
    return index >= 0 && index < GUEST_VSOCKET_MAX_CHANNELS &&
           table->channels[index].allocated ? &table->channels[index] : NULL;
}

static inline int guest_vsocket_alloc_fd(struct guest_vsocket_table *table,
                                         enum virtual_fd_kind kind) {
    for (size_t i = 0; i < GUEST_VSOCKET_MAX_FDS; ++i) {
        struct guest_vsocket_fd *entry = &table->fds[i];
        if (entry->allocated) continue;
        memset(entry, 0, sizeof(*entry));
        entry->allocated = 1;
        entry->fd = GUEST_VSOCKET_FD_BASE + (int)i;
        entry->kind = kind;
        entry->channel = -1;
        return entry->fd;
    }
    return -EMFILE;
}

static inline int guest_vsocket_create(struct guest_vsocket_table *table,
                                       uint32_t domain, uint32_t type,
                                       uint32_t protocol) {
    if (domain != GUEST_VSOCKET_AF_UNIX) return -EAFNOSUPPORT;
    if (type != GUEST_VSOCKET_SOCK_STREAM) return -ESOCKTNOSUPPORT;
    if (protocol != 0) return -EPROTONOSUPPORT;
    int fd = guest_vsocket_alloc_fd(table, VIRTUAL_FD_PROPERTY);
    if (fd >= 0) table->created++;
    return fd;
}

static inline int guest_vsocket_channel_alloc(struct guest_vsocket_table *table,
                                               enum guest_vsocket_channel_kind kind) {
    for (size_t i = 0; i < GUEST_VSOCKET_MAX_CHANNELS; ++i) {
        struct guest_vsocket_channel *channel = &table->channels[i];
        if (channel->allocated) continue;
        memset(channel, 0, sizeof(*channel));
        channel->allocated = 1;
        channel->kind = kind;
        channel->fd[0] = -1;
        channel->fd[1] = -1;
        channel->listener_fd = -1;
        return (int)i;
    }
    return -ENOBUFS;
}

static inline void guest_vsocket_channel_maybe_free(
        struct guest_vsocket_table *table, int index) {
    struct guest_vsocket_channel *channel = guest_vsocket_channel_get(table, index);
    if (!channel || channel->fd[0] >= 0 || channel->fd[1] >= 0 || channel->pending)
        return;
    memset(channel, 0, sizeof(*channel));
    channel->fd[0] = -1;
    channel->fd[1] = -1;
    channel->listener_fd = -1;
}

static inline int guest_vsocket_create_pair(struct guest_vsocket_table *table,
                                             uint32_t domain, uint32_t type,
                                             uint32_t protocol, int32_t out[2]) {
    if (!out) return -EFAULT;
    if (domain != GUEST_VSOCKET_AF_UNIX) return -EAFNOSUPPORT;
    if (type != GUEST_VSOCKET_SOCK_STREAM) return -ESOCKTNOSUPPORT;
    if (protocol != 0) return -EPROTONOSUPPORT;
    int channel_index = guest_vsocket_channel_alloc(table, GUEST_VSOCKET_CHANNEL_SIGNAL);
    if (channel_index < 0) return channel_index;
    int first = guest_vsocket_alloc_fd(table, VIRTUAL_FD_SIGNAL);
    if (first < 0) {
        guest_vsocket_channel_maybe_free(table, channel_index);
        return first;
    }
    int second = guest_vsocket_alloc_fd(table, VIRTUAL_FD_SIGNAL);
    if (second < 0) {
        int slot = guest_vsocket_fd_slot(first);
        if (slot >= 0) {
            memset(&table->fds[slot], 0, sizeof(table->fds[slot]));
            table->fds[slot].fd = first;
            table->fds[slot].channel = -1;
        }
        guest_vsocket_channel_maybe_free(table, channel_index);
        return second;
    }
    struct guest_vsocket_channel *channel = &table->channels[channel_index];
    channel->fd[0] = first;
    channel->fd[1] = second;
    struct guest_vsocket_fd *a = guest_vsocket_fd_get(table, first);
    struct guest_vsocket_fd *b = guest_vsocket_fd_get(table, second);
    a->channel = b->channel = channel_index;
    a->side = 0;
    b->side = 1;
    out[0] = first;
    out[1] = second;
    table->signal_pairs++;
    return 0;
}

/* Parse sockaddr_un without trusting a guest pointer or accepting abstract names. */
static inline int guest_vsocket_parse_path(const void *address, size_t address_len,
                                           uint32_t *family, char *path,
                                           size_t path_capacity) {
    const size_t family_size = sizeof(uint16_t);
    const size_t path_capacity_guest = 108;
    if (!address || !family || !path || path_capacity == 0 ||
        address_len < family_size + 2 || address_len > family_size + path_capacity_guest)
        return -EINVAL;
    const unsigned char *bytes = (const unsigned char *)address;
    uint16_t guest_family;
    memcpy(&guest_family, bytes, sizeof(guest_family));
    *family = guest_family;
    size_t available = address_len - family_size;
    if (available > path_capacity_guest) available = path_capacity_guest;
    const char *guest_path = (const char *)(bytes + family_size);
    const char *nul = memchr(guest_path, '\0', available);
    if (!nul) return -ENAMETOOLONG;
    size_t length = (size_t)(nul - guest_path);
    if (length == 0 || length >= path_capacity) return -ENAMETOOLONG;
    memcpy(path, guest_path, length);
    path[length] = '\0';
    return 0;
}

static inline int guest_vsocket_path_is_property_service(const char *path) {
    return path && strcmp(path, GUEST_VSOCKET_PROPERTY_PATH) == 0;
}

static inline int guest_vsocket_bind_validate(struct guest_vsocket_table *table,
                                              int fd, uint32_t family,
                                              const char *path) {
    struct guest_vsocket_fd *entry = guest_vsocket_fd_get(table, fd);
    if (!entry) return -EBADF;
    if (entry->kind != VIRTUAL_FD_PROPERTY || entry->bound || entry->channel >= 0)
        return -EINVAL;
    if (family != GUEST_VSOCKET_AF_UNIX) return -EAFNOSUPPORT;
    if (!guest_vsocket_path_is_property_service(path)) return -EACCES;
    if (table->property_listener_fd >= 0) return -EADDRINUSE;
    return 0;
}

static inline int guest_vsocket_bind_commit(struct guest_vsocket_table *table, int fd) {
    struct guest_vsocket_fd *entry = guest_vsocket_fd_get(table, fd);
    if (!entry || entry->kind != VIRTUAL_FD_PROPERTY || entry->bound ||
        table->property_listener_fd >= 0) return -EINVAL;
    entry->bound = 1;
    entry->kind = VIRTUAL_FD_PROPERTY;
    table->property_listener_fd = fd;
    table->bound++;
    return 0;
}

static inline int guest_vsocket_listen(struct guest_vsocket_table *table,
                                       int fd, int backlog) {
    struct guest_vsocket_fd *entry = guest_vsocket_fd_get(table, fd);
    if (!entry) return -EBADF;
    if (entry->kind != VIRTUAL_FD_PROPERTY || !entry->bound ||
        table->property_listener_fd != fd) return -EINVAL;
    if (backlog != 8) return -EINVAL;
    if (!entry->listening) table->listening++;
    entry->listening = 1;
    return 0;
}

static inline int guest_vsocket_connect(struct guest_vsocket_table *table,
                                        int fd, uint32_t family, const char *path,
                                        int32_t guest_pid, int32_t guest_uid,
                                        int32_t guest_gid) {
    struct guest_vsocket_fd *client = guest_vsocket_fd_get(table, fd);
    if (!client) return -EBADF;
    if (client->kind != VIRTUAL_FD_PROPERTY || client->bound || client->channel >= 0)
        return -EINVAL;
    if (family != GUEST_VSOCKET_AF_UNIX) return -EAFNOSUPPORT;
    if (!guest_vsocket_path_is_property_service(path)) return -EACCES;
    struct guest_vsocket_fd *listener = guest_vsocket_fd_get(table, table->property_listener_fd);
    if (!listener || !listener->listening) return -ECONNREFUSED;
    int channel_index = guest_vsocket_channel_alloc(table, GUEST_VSOCKET_CHANNEL_PROPERTY);
    if (channel_index < 0) return channel_index;
    struct guest_vsocket_channel *channel = &table->channels[channel_index];
    channel->fd[0] = fd;
    channel->listener_fd = table->property_listener_fd;
    channel->pending = 1;
    channel->peer_pid = guest_pid;
    channel->peer_uid = guest_uid;
    channel->peer_gid = guest_gid;
    client->channel = channel_index;
    client->side = 0;
    table->connected++;
    return 0;
}

static inline int guest_vsocket_accept(struct guest_vsocket_table *table, int fd) {
    struct guest_vsocket_fd *listener = guest_vsocket_fd_get(table, fd);
    if (!listener) return -EBADF;
    if (listener->kind != VIRTUAL_FD_PROPERTY || !listener->listening ||
        table->property_listener_fd != fd) return -EINVAL;
    for (size_t i = 0; i < GUEST_VSOCKET_MAX_CHANNELS; ++i) {
        struct guest_vsocket_channel *channel = &table->channels[i];
        if (!channel->allocated || channel->kind != GUEST_VSOCKET_CHANNEL_PROPERTY ||
            channel->listener_fd != fd || !channel->pending) continue;
        int accepted_fd = guest_vsocket_alloc_fd(table, VIRTUAL_FD_PROPERTY_ACCEPTED);
        if (accepted_fd < 0) return accepted_fd;
        channel->fd[1] = accepted_fd;
        channel->pending = 0;
        struct guest_vsocket_fd *accepted = guest_vsocket_fd_get(table, accepted_fd);
        accepted->channel = (int)i;
        accepted->side = 1;
        table->accepted++;
        return accepted_fd;
    }
    return -EAGAIN;
}

static inline int guest_vsocket_peercred(struct guest_vsocket_table *table,
                                         int fd, struct guest_vsocket_peercred *out) {
    struct guest_vsocket_fd *entry = guest_vsocket_fd_get(table, fd);
    if (!entry) return -EBADF;
    if (entry->kind != VIRTUAL_FD_PROPERTY_ACCEPTED || entry->side != 1 || !out)
        return -ENOTCONN;
    struct guest_vsocket_channel *channel = guest_vsocket_channel_get(table, entry->channel);
    if (!channel || channel->kind != GUEST_VSOCKET_CHANNEL_PROPERTY) return -ENOTCONN;
    out->pid = channel->peer_pid;
    out->uid = channel->peer_uid;
    out->gid = channel->peer_gid;
    return 0;
}

static inline int guest_vsocket_send(struct guest_vsocket_table *table, int fd,
                                     const void *data, size_t length, int flags) {
    struct guest_vsocket_fd *entry = guest_vsocket_fd_get(table, fd);
    if (!entry) return -EBADF;
    if (flags != 0) return -EOPNOTSUPP;
    if (!data && length) return -EFAULT;
    if (entry->kind != VIRTUAL_FD_PROPERTY &&
        entry->kind != VIRTUAL_FD_PROPERTY_ACCEPTED && entry->kind != VIRTUAL_FD_SIGNAL)
        return -ENOTCONN;
    if (length == 0) return 0;
    struct guest_vsocket_channel *channel = guest_vsocket_channel_get(table, entry->channel);
    if (!channel) return -ENOTCONN;
    int side = entry->side;
    int peer = 1 - side;
    if (channel->closed[side]) return -EBADF;
    if (channel->closed[peer]) return -EPIPE;
    size_t available = GUEST_VSOCKET_BUFFER_SIZE - channel->data_len[peer];
    if (available == 0) return entry->nonblocking ? -EAGAIN : -EAGAIN;
    size_t copied = length < available ? length : available;
    if (copied) memcpy(channel->data[peer] + channel->data_len[peer], data, copied);
    channel->data_len[peer] += copied;
    table->sent_bytes += copied;
    return (int)copied;
}

static inline int guest_vsocket_peek(struct guest_vsocket_table *table, int fd,
                                     void *out, size_t length, int flags) {
    struct guest_vsocket_fd *entry = guest_vsocket_fd_get(table, fd);
    if (!entry) return -EBADF;
    if (flags != 0) return -EOPNOTSUPP;
    if (!out && length) return -EFAULT;
    if (entry->kind != VIRTUAL_FD_PROPERTY &&
        entry->kind != VIRTUAL_FD_PROPERTY_ACCEPTED && entry->kind != VIRTUAL_FD_SIGNAL)
        return -ENOTCONN;
    if (length == 0) return 0;
    struct guest_vsocket_channel *channel = guest_vsocket_channel_get(table, entry->channel);
    if (!channel) return -ENOTCONN;
    int side = entry->side;
    if (channel->closed[side]) return -EBADF;
    size_t available = channel->data_len[side];
    if (available == 0) return channel->closed[1 - side] ? 0 : -EAGAIN;
    size_t copied = length < available ? length : available;
    if (copied) memcpy(out, channel->data[side], copied);
    return (int)copied;
}

static inline int guest_vsocket_consume(struct guest_vsocket_table *table, int fd,
                                        size_t length) {
    struct guest_vsocket_fd *entry = guest_vsocket_fd_get(table, fd);
    if (!entry) return -EBADF;
    struct guest_vsocket_channel *channel = guest_vsocket_channel_get(table, entry->channel);
    if (!channel) return -ENOTCONN;
    int side = entry->side;
    if (length > channel->data_len[side]) return -EINVAL;
    if (length < channel->data_len[side])
        memmove(channel->data[side], channel->data[side] + length,
                channel->data_len[side] - length);
    channel->data_len[side] -= length;
    table->received_bytes += length;
    return 0;
}

static inline int guest_vsocket_recv(struct guest_vsocket_table *table, int fd,
                                     void *out, size_t length, int flags) {
    int result = guest_vsocket_peek(table, fd, out, length, flags);
    if (result <= 0) return result;
    return guest_vsocket_consume(table, fd, (size_t)result) == 0 ? result : -EIO;
}

static inline int guest_vsocket_poll_events(struct guest_vsocket_table *table,
                                            int fd, int16_t events) {
    struct guest_vsocket_fd *entry = guest_vsocket_fd_get(table, fd);
    if (!entry) return 0;
    if (entry->kind == VIRTUAL_FD_PROPERTY && entry->listening) {
        for (size_t i = 0; i < GUEST_VSOCKET_MAX_CHANNELS; ++i) {
            struct guest_vsocket_channel *channel = &table->channels[i];
            if (channel->allocated && channel->kind == GUEST_VSOCKET_CHANNEL_PROPERTY &&
                channel->listener_fd == fd && channel->pending)
                return (events & GUEST_VSOCKET_POLLIN) ? GUEST_VSOCKET_POLLIN : 0;
        }
        return 0;
    }
    struct guest_vsocket_channel *channel = guest_vsocket_channel_get(table, entry->channel);
    if (!channel) return 0;
    int side = entry->side;
    int revents = 0;
    if (channel->data_len[side] > 0 && (events & GUEST_VSOCKET_POLLIN))
        revents |= GUEST_VSOCKET_POLLIN;
    if (channel->closed[1 - side]) revents |= GUEST_VSOCKET_POLLHUP;
    return revents;
}

static inline int guest_vsocket_fcntl(struct guest_vsocket_table *table, int fd,
                                      int command, int argument, int *status_flags,
                                      int *descriptor_flags) {
    struct guest_vsocket_fd *entry = guest_vsocket_fd_get(table, fd);
    if (!entry) return -EBADF;
    if (!status_flags || !descriptor_flags) return -EINVAL;
    if (command == GUEST_VSOCKET_F_GETFD) return *descriptor_flags;
    if (command == GUEST_VSOCKET_F_SETFD) {
        if ((argument & ~GUEST_VSOCKET_FD_CLOEXEC) != 0) return -EINVAL;
        *descriptor_flags = argument;
        return 0;
    }
    if (command == GUEST_VSOCKET_F_GETFL)
        return GUEST_VSOCKET_O_RDWR | (entry->nonblocking ? GUEST_VSOCKET_O_NONBLOCK : 0);
    if (command == GUEST_VSOCKET_F_SETFL) {
        if ((argument & ~(GUEST_VSOCKET_O_RDWR | GUEST_VSOCKET_O_NONBLOCK)) != 0)
            return -EINVAL;
        entry->nonblocking = (argument & GUEST_VSOCKET_O_NONBLOCK) != 0;
        *status_flags = argument;
        return 0;
    }
    return -EINVAL;
}

static inline int guest_vsocket_close_fd(struct guest_vsocket_table *table, int fd) {
    struct guest_vsocket_fd *entry = guest_vsocket_fd_get(table, fd);
    if (!entry) return -EBADF;
    int channel_index = entry->channel;
    int side = entry->side;
    if (channel_index >= 0) {
        struct guest_vsocket_channel *channel = guest_vsocket_channel_get(table, channel_index);
        if (channel) {
            channel->closed[side] = 1;
            channel->fd[side] = -1;
        }
    }
    if (table->property_listener_fd == fd) {
        table->property_listener_fd = -1;
        for (size_t i = 0; i < GUEST_VSOCKET_MAX_CHANNELS; ++i) {
            struct guest_vsocket_channel *channel = &table->channels[i];
            if (!channel->allocated || channel->listener_fd != fd) continue;
            channel->pending = 0;
            channel->listener_fd = -1;
            channel->closed[1] = 1;
        }
    }
    memset(entry, 0, sizeof(*entry));
    entry->fd = fd;
    entry->channel = -1;
    guest_vsocket_channel_maybe_free(table, channel_index);
    return 0;
}

#endif
