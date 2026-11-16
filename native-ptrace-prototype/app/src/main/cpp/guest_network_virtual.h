#ifndef GINGERVM_GUEST_NETWORK_VIRTUAL_H
#define GINGERVM_GUEST_NETWORK_VIRTUAL_H

#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "guest_hardware_profile.h"

#define GUEST_NET_AF_INET 2u
#define GUEST_NET_SOCK_DGRAM 2u
#define GUEST_NET_IFNAMSIZ 16u

#define GUEST_NET_SIOCADDRT 0x890bu
#define GUEST_NET_SIOCGIFADDR 0x8915u
#define GUEST_NET_SIOCSIFADDR 0x8916u
#define GUEST_NET_SIOCGIFFLAGS 0x8913u
#define GUEST_NET_SIOCSIFFLAGS 0x8914u
#define GUEST_NET_SIOCGIFNETMASK 0x891bu
#define GUEST_NET_SIOCSIFNETMASK 0x891cu

#define GUEST_NET_IFF_UP 0x0001u
#define GUEST_NET_IFF_BROADCAST 0x0002u
#define GUEST_NET_IFF_LOOPBACK 0x0008u
#define GUEST_NET_IFF_RUNNING 0x0040u
#define GUEST_NET_IFF_MULTICAST 0x1000u
#define GUEST_NET_RTF_UP 0x0001u
#define GUEST_NET_RTF_GATEWAY 0x0002u

/* Fixed-width Linux ARM EABI layouts; do not substitute the host's ifreq. */
struct guest_arm32_sockaddr {
    uint16_t family;
    uint8_t data[14];
};

struct guest_arm32_ifreq {
    char name[GUEST_NET_IFNAMSIZ];
    union {
        uint8_t bytes[16];
        uint16_t flags;
        int32_t integer;
        struct guest_arm32_sockaddr address;
    } value;
};

struct guest_arm32_rtentry {
    uint32_t pad1;
    struct guest_arm32_sockaddr destination;
    struct guest_arm32_sockaddr gateway;
    struct guest_arm32_sockaddr netmask;
    uint16_t flags;
    int16_t pad2;
    uint32_t pad3;
    uint32_t pad4;
    int16_t metric;
    uint16_t metric_alignment;
    uint32_t device_pointer;
    uint32_t mtu;
    uint32_t window;
    uint16_t irtt;
    uint16_t tail_alignment;
};

#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
_Static_assert(sizeof(struct guest_arm32_sockaddr) == 16u, "ARM32 sockaddr ABI");
_Static_assert(sizeof(struct guest_arm32_ifreq) == 32u, "ARM32 ifreq ABI");
_Static_assert(sizeof(struct guest_arm32_rtentry) == 84u, "ARM32 rtentry ABI");
_Static_assert(offsetof(struct guest_arm32_rtentry, device_pointer) == 68u,
               "ARM32 rtentry device pointer offset");
#endif

struct guest_network_state {
    int eth0_present;
    int lo_present;
    uint16_t lo_flags;
    int address_set;
    int netmask_set;
    uint16_t flags;
    uint8_t address[4];
    uint8_t netmask[4];
    int default_route_set;
    uint8_t gateway[4];
};

static inline int guest_net_socket_args_valid(uint32_t domain, uint32_t type,
                                               uint32_t protocol) {
    return domain == GUEST_NET_AF_INET && type == GUEST_NET_SOCK_DGRAM &&
           protocol == 0u;
}

static inline void guest_net_state_init(struct guest_network_state *state) {
    if (!state) return;
    memset(state, 0, sizeof(*state));
    state->eth0_present = 1;
    state->lo_present = 1;
    state->lo_flags = GUEST_NET_IFF_LOOPBACK;
    state->flags = GUEST_NET_IFF_BROADCAST | GUEST_NET_IFF_MULTICAST;
}

static inline int guest_net_parse_ipv4(const char *text, uint8_t out[4]) {
    if (!text || !out) return -EINVAL;
    unsigned octets[4] = {0, 0, 0, 0};
    const char *cursor = text;
    for (size_t i = 0; i < 4u; ++i) {
        if (*cursor < '0' || *cursor > '9') return -EINVAL;
        unsigned value = 0;
        size_t digits = 0;
        while (*cursor >= '0' && *cursor <= '9') {
            value = value * 10u + (unsigned)(*cursor - '0');
            if (value > 255u || ++digits > 3u) return -EINVAL;
            ++cursor;
        }
        octets[i] = value;
        if (i < 3u) {
            if (*cursor != '.') return -EINVAL;
            ++cursor;
        } else if (*cursor != '\0') {
            return -EINVAL;
        }
    }
    for (size_t i = 0; i < 4u; ++i) out[i] = (uint8_t)octets[i];
    return 0;
}

static inline int guest_net_sockaddr_is_ipv4(const struct guest_arm32_sockaddr *addr,
                                              uint8_t out[4]) {
    if (!addr || addr->family != GUEST_NET_AF_INET || addr->data[0] != 0u ||
        addr->data[1] != 0u) return 0;
    if (out) memcpy(out, addr->data + 2u, 4u);
    return 1;
}

static inline void guest_net_sockaddr_set_ipv4(struct guest_arm32_sockaddr *addr,
                                                const uint8_t value[4]) {
    memset(addr, 0, sizeof(*addr));
    addr->family = GUEST_NET_AF_INET;
    memcpy(addr->data + 2u, value, 4u);
}

static inline int guest_net_ifreq_has_eth0(const struct guest_arm32_ifreq *request) {
    return request && memchr(request->name, '\0', sizeof(request->name)) != NULL &&
           strcmp(request->name, GUEST_PROFILE_NET_IFACE) == 0;
}

static inline int guest_net_ifreq_has_name(const struct guest_arm32_ifreq *request,
                                           const char *name) {
    return request && name && memchr(request->name, '\0', sizeof(request->name)) != NULL &&
           strcmp(request->name, name) == 0;
}

static inline int guest_net_apply_ifreq(struct guest_network_state *state,
                                         uint32_t request,
                                         struct guest_arm32_ifreq *ifr) {
    if (!state || !ifr) return -EFAULT;
    int is_lo = guest_net_ifreq_has_name(ifr, "lo");
    int is_eth0 = guest_net_ifreq_has_eth0(ifr);
    if (is_lo && state->lo_present) {
        switch (request) {
            case GUEST_NET_SIOCGIFFLAGS:
                ifr->value.flags = state->lo_flags |
                    ((state->lo_flags & GUEST_NET_IFF_UP) ? GUEST_NET_IFF_RUNNING : 0u);
                return 0;
            case GUEST_NET_SIOCSIFFLAGS: {
                const uint16_t allowed = GUEST_NET_IFF_UP | GUEST_NET_IFF_BROADCAST |
                                         GUEST_NET_IFF_RUNNING | GUEST_NET_IFF_LOOPBACK;
                if ((ifr->value.flags & (uint16_t)~allowed) != 0u ||
                    (ifr->value.flags & GUEST_NET_IFF_LOOPBACK) == 0u) return -EINVAL;
                state->lo_flags = ifr->value.flags;
                return 0;
            }
            default:
                return -EOPNOTSUPP;
        }
    }
    if (!is_eth0 || !state->eth0_present) return -ENODEV;
    uint8_t address[4];
    switch (request) {
        case GUEST_NET_SIOCGIFFLAGS:
            ifr->value.flags = state->flags |
                ((state->flags & GUEST_NET_IFF_UP) ? GUEST_NET_IFF_RUNNING : 0u);
            return 0;
        case GUEST_NET_SIOCSIFFLAGS: {
            const uint16_t allowed = GUEST_NET_IFF_UP | GUEST_NET_IFF_BROADCAST |
                                     GUEST_NET_IFF_RUNNING | GUEST_NET_IFF_MULTICAST;
            if ((ifr->value.flags & (uint16_t)~allowed) != 0u) return -EINVAL;
            state->flags = ifr->value.flags;
            return 0;
        }
        case GUEST_NET_SIOCSIFADDR: {
            uint8_t expected[4];
            if (!guest_net_sockaddr_is_ipv4(&ifr->value.address, address)) return -EINVAL;
            if (guest_net_parse_ipv4(GUEST_PROFILE_NET_ADDRESS, expected) != 0 ||
                memcmp(address, expected, sizeof(expected)) != 0) return -EACCES;
            memcpy(state->address, address, sizeof(state->address));
            state->address_set = 1;
            return 0;
        }
        case GUEST_NET_SIOCGIFADDR:
            if (!state->address_set) return -EADDRNOTAVAIL;
            guest_net_sockaddr_set_ipv4(&ifr->value.address, state->address);
            return 0;
        case GUEST_NET_SIOCSIFNETMASK: {
            uint8_t expected[4];
            if (!guest_net_sockaddr_is_ipv4(&ifr->value.address, address)) return -EINVAL;
            if (guest_net_parse_ipv4(GUEST_PROFILE_NET_NETMASK, expected) != 0 ||
                memcmp(address, expected, sizeof(expected)) != 0) return -EACCES;
            memcpy(state->netmask, address, sizeof(state->netmask));
            state->netmask_set = 1;
            return 0;
        }
        case GUEST_NET_SIOCGIFNETMASK:
            if (!state->netmask_set) return -EADDRNOTAVAIL;
            guest_net_sockaddr_set_ipv4(&ifr->value.address, state->netmask);
            return 0;
        default:
            return -ENOTTY;
    }
}

static inline int guest_net_add_route(struct guest_network_state *state,
                                      const struct guest_arm32_rtentry *route,
                                      const char *device) {
    uint8_t expected_gateway[4];
    uint8_t destination[4], gateway[4], netmask[4];
    if (!state || !route || !device) return -EFAULT;
    if (guest_net_parse_ipv4(GUEST_PROFILE_NET_GATEWAY, expected_gateway) != 0)
        return -EINVAL;
    if (!state->eth0_present || strcmp(device, GUEST_PROFILE_NET_IFACE) != 0)
        return -ENODEV;
    if (!state->address_set || !state->netmask_set || !(state->flags & GUEST_NET_IFF_UP))
        return -ENETDOWN;
    if (route->flags != (GUEST_NET_RTF_UP | GUEST_NET_RTF_GATEWAY) ||
        route->pad1 != 0u || route->pad2 != 0 || route->pad3 != 0u ||
        route->pad4 != 0u || route->metric != 0 || route->mtu != 0u ||
        route->window != 0u || route->irtt != 0u || route->device_pointer == 0u ||
        !guest_net_sockaddr_is_ipv4(&route->destination, destination) ||
        !guest_net_sockaddr_is_ipv4(&route->gateway, gateway) ||
        !guest_net_sockaddr_is_ipv4(&route->netmask, netmask)) return -EINVAL;
    for (size_t i = 0; i < 4u; ++i)
        if (destination[i] != 0u || netmask[i] != 0u) return -EINVAL;
    if (memcmp(gateway, expected_gateway, sizeof(gateway)) != 0) return -EACCES;
    if (state->default_route_set) return -EEXIST;
    memcpy(state->gateway, gateway, sizeof(state->gateway));
    state->default_route_set = 1;
    return 0;
}

#endif
