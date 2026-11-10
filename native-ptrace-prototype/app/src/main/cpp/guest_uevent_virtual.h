#ifndef GINGERVM_GUEST_UEVENT_VIRTUAL_H
#define GINGERVM_GUEST_UEVENT_VIRTUAL_H

#include <stddef.h>
#include <stdint.h>

#define GUEST_UEVENT_AF_NETLINK 16u
#define GUEST_UEVENT_SOCK_DGRAM 2u
#define GUEST_UEVENT_NETLINK_KOBJECT_UEVENT 15u
#define GUEST_UEVENT_SOL_SOCKET 1u
#define GUEST_UEVENT_SO_PASSCRED 16u
#define GUEST_UEVENT_SO_RCVBUFFORCE 33u
#define GUEST_UEVENT_RCVBUFFORCE_BYTES 65536

struct guest_uevent_sockaddr_nl {
    uint16_t family;
    uint16_t pad;
    uint32_t pid;
    uint32_t groups;
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

#endif
