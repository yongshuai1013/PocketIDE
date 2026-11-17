#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

#include "../app/src/main/cpp/guest_hardware_profile.h"
#include "../app/src/main/cpp/guest_network_virtual.h"

static void set_ifreq_name(struct guest_arm32_ifreq *ifr, const char *name) {
    memset(ifr, 0, sizeof(*ifr));
    assert(strlen(name) < sizeof(ifr->name));
    memcpy(ifr->name, name, strlen(name) + 1u);
}

static void test_profile_socket_and_abi(void) {
    assert(guest_net_socket_args_valid(GUEST_NET_AF_INET, GUEST_NET_SOCK_DGRAM, 0));
    assert(!guest_net_socket_args_valid(1, GUEST_NET_SOCK_DGRAM, 0));
    assert(!guest_net_socket_args_valid(GUEST_NET_AF_INET, 1, 0));
    assert(!guest_net_socket_args_valid(GUEST_NET_AF_INET, GUEST_NET_SOCK_DGRAM, 1));
    assert(sizeof(struct guest_arm32_ifreq) == 32u);
    assert(sizeof(struct guest_arm32_rtentry) == 84u);
    assert(offsetof(struct guest_arm32_rtentry, device_pointer) == 68u);
    assert(strstr(GUEST_PROFILE_PROC_CMDLINE, "androidboot.hardware=goldfish") != NULL);
    assert(strstr(GUEST_PROFILE_PROC_CMDLINE, "qemu=1") != NULL);
    assert(strstr(GUEST_PROFILE_PROC_CMDLINE, "android.qemud=ttyS1") != NULL);
    assert(strstr(GUEST_PROFILE_PROC_CPUINFO, "Hardware : goldfish") != NULL);
    assert(strstr(GUEST_PROFILE_PROC_MEMINFO, "MemTotal:       262144 kB") != NULL);
    assert(GUEST_PROFILE_CPU_COUNT == 1u);
}

static void test_ifconfig_guest_state(void) {
    struct guest_network_state state;
    struct guest_arm32_ifreq ifr;
    uint8_t address[4], expected[4];
    guest_net_state_init(&state);
    set_ifreq_name(&ifr, GUEST_PROFILE_NET_IFACE);
    assert(guest_net_apply_ifreq(&state, GUEST_NET_SIOCGIFADDR, &ifr) == -EADDRNOTAVAIL);

    assert(guest_net_parse_ipv4(GUEST_PROFILE_NET_ADDRESS, expected) == 0);
    guest_net_sockaddr_set_ipv4(&ifr.value.address, expected);
    assert(guest_net_apply_ifreq(&state, GUEST_NET_SIOCSIFADDR, &ifr) == 0);
    set_ifreq_name(&ifr, GUEST_PROFILE_NET_IFACE);
    assert(guest_net_apply_ifreq(&state, GUEST_NET_SIOCGIFADDR, &ifr) == 0);
    assert(guest_net_sockaddr_is_ipv4(&ifr.value.address, address));
    assert(memcmp(address, expected, sizeof(address)) == 0);

    assert(guest_net_parse_ipv4(GUEST_PROFILE_NET_NETMASK, expected) == 0);
    set_ifreq_name(&ifr, GUEST_PROFILE_NET_IFACE);
    guest_net_sockaddr_set_ipv4(&ifr.value.address, expected);
    assert(guest_net_apply_ifreq(&state, GUEST_NET_SIOCSIFNETMASK, &ifr) == 0);
    set_ifreq_name(&ifr, GUEST_PROFILE_NET_IFACE);
    assert(guest_net_apply_ifreq(&state, GUEST_NET_SIOCGIFNETMASK, &ifr) == 0);
    assert(guest_net_sockaddr_is_ipv4(&ifr.value.address, address));
    assert(memcmp(address, expected, sizeof(address)) == 0);

    set_ifreq_name(&ifr, GUEST_PROFILE_NET_IFACE);
    assert(guest_net_apply_ifreq(&state, GUEST_NET_SIOCGIFFLAGS, &ifr) == 0);
    ifr.value.flags |= GUEST_NET_IFF_UP;
    assert(guest_net_apply_ifreq(&state, GUEST_NET_SIOCSIFFLAGS, &ifr) == 0);
    set_ifreq_name(&ifr, GUEST_PROFILE_NET_IFACE);
    assert(guest_net_apply_ifreq(&state, GUEST_NET_SIOCGIFFLAGS, &ifr) == 0);
    assert((ifr.value.flags & (GUEST_NET_IFF_UP | GUEST_NET_IFF_RUNNING)) ==
           (GUEST_NET_IFF_UP | GUEST_NET_IFF_RUNNING));

    set_ifreq_name(&ifr, "wlan0");
    assert(guest_net_apply_ifreq(&state, GUEST_NET_SIOCGIFFLAGS, &ifr) == -ENODEV);
    set_ifreq_name(&ifr, GUEST_PROFILE_NET_IFACE);
    assert(guest_net_apply_ifreq(&state, 0xdead, &ifr) == -ENOTTY);

    assert(guest_net_parse_ipv4("10.0.2.16", address) == 0);
    set_ifreq_name(&ifr, GUEST_PROFILE_NET_IFACE);
    guest_net_sockaddr_set_ipv4(&ifr.value.address, address);
    assert(guest_net_apply_ifreq(&state, GUEST_NET_SIOCSIFADDR, &ifr) == -EACCES);
    assert(guest_net_parse_ipv4("10.0.2.999", address) == -EINVAL);
}

static struct guest_arm32_rtentry make_default_route(const char *gateway) {
    struct guest_arm32_rtentry route;
    uint8_t bytes[4];
    memset(&route, 0, sizeof(route));
    route.destination.family = GUEST_NET_AF_INET;
    route.netmask.family = GUEST_NET_AF_INET;
    route.flags = GUEST_NET_RTF_UP | GUEST_NET_RTF_GATEWAY;
    route.device_pointer = 1u; /* supervisor validates the guest string separately */
    route.gateway.family = GUEST_NET_AF_INET;
    assert(guest_net_parse_ipv4(gateway, bytes) == 0);
    memcpy(route.gateway.data + 2u, bytes, sizeof(bytes));
    return route;
}

static void strip_line_ending(char *line) {
    size_t length = strlen(line);
    if (length && line[length - 1u] == '\n') line[--length] = '\0';
    if (length && line[length - 1u] == '\r') line[--length] = '\0';
}

static int read_next_command(FILE *script, char *line, size_t capacity) {
    while (fgets(line, (int)capacity, script) != NULL) {
        strip_line_ending(line);
        char *command = line;
        while (*command == ' ' || *command == '\t') ++command;
        if (*command == '\0' || *command == '#') continue;
        if (command != line) memmove(line, command, strlen(command) + 1u);
        return 1;
    }
    return 0;
}

/* Pinned API10 toolbox/ifconfig.c and route.c map these two script commands to
 * guest AF_INET/SOCK_DGRAM control calls. This couples the exact staged script
 * to the software-only state model; it does not execute host sockets or route packets. */
static void test_staged_init_goldfish_network_sequence(const char *script_path) {
    FILE *script = fopen(script_path, "r");
    assert(script != NULL);
    char shebang[256], ifconfig_command[256], route_command[256];
    assert(fgets(shebang, sizeof(shebang), script) != NULL);
    strip_line_ending(shebang);
    assert(read_next_command(script, ifconfig_command, sizeof(ifconfig_command)));
    assert(read_next_command(script, route_command, sizeof(route_command)));
    assert(fclose(script) == 0);

    char expected_ifconfig[256], expected_route[256];
    assert(snprintf(expected_ifconfig, sizeof(expected_ifconfig),
                    "ifconfig %s %s netmask %s up", GUEST_PROFILE_NET_IFACE,
                    GUEST_PROFILE_NET_ADDRESS, GUEST_PROFILE_NET_NETMASK) > 0);
    assert(snprintf(expected_route, sizeof(expected_route),
                    "route add default gw %s dev %s", GUEST_PROFILE_NET_GATEWAY,
                    GUEST_PROFILE_NET_IFACE) > 0);
    assert(strcmp(shebang, "#!/system/bin/sh") == 0);
    assert(strcmp(ifconfig_command, expected_ifconfig) == 0);
    assert(strcmp(route_command, expected_route) == 0);

    struct guest_network_state state;
    struct guest_arm32_ifreq ifr;
    uint8_t address[4];
    guest_net_state_init(&state);
    assert(guest_net_socket_args_valid(GUEST_NET_AF_INET, GUEST_NET_SOCK_DGRAM, 0u));

    struct guest_arm32_rtentry route = make_default_route(GUEST_PROFILE_NET_GATEWAY);
    assert(guest_net_add_route(&state, &route, GUEST_PROFILE_NET_IFACE) == -ENETDOWN);
    set_ifreq_name(&ifr, GUEST_PROFILE_NET_IFACE);
    assert(guest_net_parse_ipv4(GUEST_PROFILE_NET_ADDRESS, address) == 0);
    guest_net_sockaddr_set_ipv4(&ifr.value.address, address);
    assert(guest_net_apply_ifreq(&state, GUEST_NET_SIOCSIFADDR, &ifr) == 0);
    set_ifreq_name(&ifr, GUEST_PROFILE_NET_IFACE);
    assert(guest_net_parse_ipv4(GUEST_PROFILE_NET_NETMASK, address) == 0);
    guest_net_sockaddr_set_ipv4(&ifr.value.address, address);
    assert(guest_net_apply_ifreq(&state, GUEST_NET_SIOCSIFNETMASK, &ifr) == 0);
    set_ifreq_name(&ifr, GUEST_PROFILE_NET_IFACE);
    assert(guest_net_apply_ifreq(&state, GUEST_NET_SIOCGIFFLAGS, &ifr) == 0);
    ifr.value.flags |= GUEST_NET_IFF_UP;
    assert(guest_net_apply_ifreq(&state, GUEST_NET_SIOCSIFFLAGS, &ifr) == 0);

    assert(guest_net_add_route(&state, &route, GUEST_PROFILE_NET_IFACE) == 0);
    assert(state.address_set && state.netmask_set && state.default_route_set);
    assert((state.flags & GUEST_NET_IFF_UP) != 0u);
    assert(guest_net_parse_ipv4(GUEST_PROFILE_NET_ADDRESS, address) == 0);
    assert(memcmp(state.address, address, sizeof(address)) == 0);
    assert(guest_net_parse_ipv4(GUEST_PROFILE_NET_NETMASK, address) == 0);
    assert(memcmp(state.netmask, address, sizeof(address)) == 0);
    assert(guest_net_parse_ipv4(GUEST_PROFILE_NET_GATEWAY, address) == 0);
    assert(memcmp(state.gateway, address, sizeof(address)) == 0);
}

static void test_route_is_exact_and_guest_only(void) {
    struct guest_network_state state;
    struct guest_arm32_ifreq ifr;
    uint8_t address[4];
    guest_net_state_init(&state);
    struct guest_arm32_rtentry route = make_default_route(GUEST_PROFILE_NET_GATEWAY);
    assert(guest_net_add_route(&state, &route, GUEST_PROFILE_NET_IFACE) == -ENETDOWN);

    set_ifreq_name(&ifr, GUEST_PROFILE_NET_IFACE);
    assert(guest_net_parse_ipv4(GUEST_PROFILE_NET_ADDRESS, address) == 0);
    guest_net_sockaddr_set_ipv4(&ifr.value.address, address);
    assert(guest_net_apply_ifreq(&state, GUEST_NET_SIOCSIFADDR, &ifr) == 0);
    set_ifreq_name(&ifr, GUEST_PROFILE_NET_IFACE);
    assert(guest_net_parse_ipv4(GUEST_PROFILE_NET_NETMASK, address) == 0);
    guest_net_sockaddr_set_ipv4(&ifr.value.address, address);
    assert(guest_net_apply_ifreq(&state, GUEST_NET_SIOCSIFNETMASK, &ifr) == 0);
    set_ifreq_name(&ifr, GUEST_PROFILE_NET_IFACE);
    assert(guest_net_apply_ifreq(&state, GUEST_NET_SIOCGIFFLAGS, &ifr) == 0);
    ifr.value.flags |= GUEST_NET_IFF_UP;
    assert(guest_net_apply_ifreq(&state, GUEST_NET_SIOCSIFFLAGS, &ifr) == 0);

    assert(guest_net_add_route(&state, &route, GUEST_PROFILE_NET_IFACE) == 0);
    assert(state.default_route_set);
    assert(guest_net_add_route(&state, &route, GUEST_PROFILE_NET_IFACE) == -EEXIST);
    assert(guest_net_add_route(&state, &route, "wlan0") == -ENODEV);

    route = make_default_route("10.0.2.1");
    assert(guest_net_add_route(&state, &route, GUEST_PROFILE_NET_IFACE) == -EACCES);
    route = make_default_route(GUEST_PROFILE_NET_GATEWAY);
    route.flags |= 0x0004u;
    assert(guest_net_add_route(&state, &route, GUEST_PROFILE_NET_IFACE) == -EINVAL);
}

static void test_api10_ifup_lo_flags_are_guest_only(void) {
    struct guest_network_state state;
    struct guest_arm32_ifreq ifr;
    guest_net_state_init(&state);
    set_ifreq_name(&ifr, "lo");
    assert(guest_net_apply_ifreq(&state, GUEST_NET_SIOCGIFFLAGS, &ifr) == 0);
    assert((ifr.value.flags & GUEST_NET_IFF_LOOPBACK) != 0u);
    assert((ifr.value.flags & GUEST_NET_IFF_UP) == 0u);
    assert((ifr.value.flags & (GUEST_NET_IFF_BROADCAST | GUEST_NET_IFF_MULTICAST |
                               GUEST_NET_IFF_RUNNING)) == 0u);
    ifr.value.flags |= GUEST_NET_IFF_UP;
    assert(guest_net_apply_ifreq(&state, GUEST_NET_SIOCSIFFLAGS, &ifr) == 0);
    set_ifreq_name(&ifr, "lo");
    assert(guest_net_apply_ifreq(&state, GUEST_NET_SIOCGIFFLAGS, &ifr) == 0);
    assert((ifr.value.flags & (GUEST_NET_IFF_UP | GUEST_NET_IFF_RUNNING |
                               GUEST_NET_IFF_LOOPBACK)) ==
           (GUEST_NET_IFF_UP | GUEST_NET_IFF_RUNNING | GUEST_NET_IFF_LOOPBACK));
    set_ifreq_name(&ifr, "lo");
    assert(guest_net_apply_ifreq(&state, GUEST_NET_SIOCSIFADDR, &ifr) == -EOPNOTSUPP);
    ifr.value.flags &= (uint16_t)~GUEST_NET_IFF_LOOPBACK;
    assert(guest_net_apply_ifreq(&state, GUEST_NET_SIOCSIFFLAGS, &ifr) == -EINVAL);
}

int main(int argc, char **argv) {
    assert(argc == 2);
    test_profile_socket_and_abi();
    test_ifconfig_guest_state();
    test_route_is_exact_and_guest_only();
    test_api10_ifup_lo_flags_are_guest_only();
    test_staged_init_goldfish_network_sequence(argv[1]);
    puts("API10 init.goldfish.sh network regression: PASS (staged script -> guest ifconfig address/netmask/up ioctls -> guest default route; no host socket or packet path)");
    return 0;
}
