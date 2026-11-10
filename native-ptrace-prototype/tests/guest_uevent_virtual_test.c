#include <assert.h>
#include <stdint.h>
#include <stdio.h>

#include "../app/src/main/cpp/guest_uevent_virtual.h"

int main(void) {
    assert(guest_uevent_socket_args_valid(16, 2, 15));
    assert(!guest_uevent_socket_args_valid(1, 2, 15));
    assert(!guest_uevent_socket_args_valid(16, 1, 15));
    assert(!guest_uevent_socket_args_valid(16, 2, 0));

    struct guest_uevent_sockaddr_nl addr = {
        .family = 16,
        .pad = 0,
        .pid = 2,
        .groups = UINT32_MAX,
    };
    assert(guest_uevent_bind_args_valid(&addr, sizeof(addr), 2));
    assert(!guest_uevent_bind_args_valid(&addr, sizeof(addr) - 1, 2));
    assert(!guest_uevent_bind_args_valid(&addr, sizeof(addr), 3));
    addr.pad = 1;
    assert(!guest_uevent_bind_args_valid(&addr, sizeof(addr), 2));
    addr.pad = 0;
    addr.groups = 0;
    assert(!guest_uevent_bind_args_valid(&addr, sizeof(addr), 2));
    addr.groups = UINT32_MAX;
    addr.family = 1;
    assert(!guest_uevent_bind_args_valid(&addr, sizeof(addr), 2));

    assert(guest_uevent_setsockopt_args_valid(1, 33, 65536, 4));
    assert(guest_uevent_setsockopt_args_valid(1, 16, 1, 4));
    assert(!guest_uevent_setsockopt_args_valid(1, 33, 65535, 4));
    assert(!guest_uevent_setsockopt_args_valid(1, 16, 0, 4));
    assert(!guest_uevent_setsockopt_args_valid(0, 16, 1, 4));
    assert(!guest_uevent_setsockopt_args_valid(1, 999, 1, 4));
    assert(!guest_uevent_setsockopt_args_valid(1, 16, 1, 3));

    puts("API10 guest-only uevent socket contract: PASS (no host netlink required)");
    return 0;
}
