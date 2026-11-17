#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../app/src/main/cpp/guest_socket_virtual.h"

static size_t make_sockaddr(unsigned char out[110], const char *path) {
    memset(out, 0, 110);
    uint16_t family = GUEST_VSOCKET_AF_UNIX;
    memcpy(out, &family, sizeof(family));
    size_t n = strlen(path) + 1;
    assert(n <= 108);
    memcpy(out + sizeof(family), path, n);
    return sizeof(family) + n;
}

static void test_qemud_control_socket_service_child_handoff(void) {
    assert(guest_vsocket_actor_is_verified_api10_init_pid1(1, 0, 0, 0, 1));
    assert(!guest_vsocket_actor_is_verified_api10_init_pid1(1, 1, 0, 0, 1));
    assert(!guest_vsocket_actor_is_verified_api10_init_pid1(1, 0, 1000, 0, 1));
    assert(!guest_vsocket_actor_is_verified_api10_init_pid1(1, 0, 0, 1, 1));
    assert(!guest_vsocket_actor_is_verified_api10_init_pid1(1, 0, 0, 0, 0));
    assert(guest_vsocket_actor_is_verified_api10_init_service_child(
        14, 1, 0, 0, 1));
    assert(!guest_vsocket_actor_is_verified_api10_init_service_child(
        1, 1, 0, 0, 1));
    assert(!guest_vsocket_actor_is_verified_api10_init_service_child(
        14, 2, 0, 0, 1));
    assert(!guest_vsocket_actor_is_verified_api10_init_service_child(
        14, 1, 1000, 0, 1));
    assert(!guest_vsocket_actor_is_verified_api10_init_service_child(
        14, 1, 0, 1, 1));
    assert(!guest_vsocket_actor_is_verified_api10_init_service_child(
        14, 1, 0, 0, 0));
    assert(guest_vsocket_bind_actor_allowed(1, 0,
        GUEST_VSOCKET_PROPERTY_PATH));
    assert(!guest_vsocket_bind_actor_allowed(0, 1,
        GUEST_VSOCKET_PROPERTY_PATH));
    assert(guest_vsocket_bind_actor_allowed(0, 1,
        GUEST_VSOCKET_QEMUD_PATH));
    assert(!guest_vsocket_bind_actor_allowed(1, 0,
        GUEST_VSOCKET_QEMUD_PATH));
    assert(!guest_vsocket_bind_actor_allowed(0, 0,
        GUEST_VSOCKET_QEMUD_PATH));
    assert(!guest_vsocket_bind_actor_allowed(0, 1,
        "/dev/socket/qemud/../property_service"));

    struct guest_vsocket_table table;
    guest_vsocket_table_init(&table);
    int listener = guest_vsocket_create(&table, GUEST_VSOCKET_AF_UNIX,
                                        GUEST_VSOCKET_SOCK_STREAM, 0);
    assert(listener == GUEST_VSOCKET_FD_BASE);
    assert(guest_vsocket_bind_validate(&table, listener,
        GUEST_VSOCKET_AF_UNIX, GUEST_VSOCKET_QEMUD_PATH) == 0);
    assert(guest_vsocket_bind_commit_path(&table, listener,
        GUEST_VSOCKET_QEMUD_PATH) == 0);

    int status_flags = 0, descriptor_flags = 0;
    assert(guest_vsocket_fcntl(&table, listener, GUEST_VSOCKET_F_SETFD, 0,
        &status_flags, &descriptor_flags) == 0);
    assert(guest_vsocket_fcntl(&table, listener, GUEST_VSOCKET_F_GETFD, 0,
        &status_flags, &descriptor_flags) == 0);
    char environment[64];
    snprintf(environment, sizeof(environment), "ANDROID_SOCKET_qemud=%d", listener);
    char *value = strchr(environment, '=');
    assert(value && strtol(value + 1, NULL, 10) == listener);

    assert(guest_vsocket_listen(&table, listener, 4) == 0);
    assert(guest_vsocket_poll_events(&table, listener,
        GUEST_VSOCKET_POLLIN) == 0);
    assert(guest_vsocket_accept(&table, listener) == -EAGAIN);
    int client = guest_vsocket_create(&table, GUEST_VSOCKET_AF_UNIX,
                                      GUEST_VSOCKET_SOCK_STREAM, 0);
    assert(client >= 0);
    assert(guest_vsocket_connect(&table, client, GUEST_VSOCKET_AF_UNIX,
        GUEST_VSOCKET_QEMUD_PATH, 22, 0, 0) == -EOPNOTSUPP);
    assert(table.connected == 0 && table.accepted == 0 &&
           table.sent_bytes == 0 && table.received_bytes == 0);
    assert(guest_vsocket_close_fd(&table, client) == 0);
    assert(guest_vsocket_close_fd(&table, listener) == 0);
}

int main(void) {
    struct guest_vsocket_table table;
    guest_vsocket_table_init(&table);
    assert(guest_vsocket_socketcall_arg_count(1) == 3);
    assert(guest_vsocket_socketcall_arg_count(2) == 3);
    assert(guest_vsocket_socketcall_arg_count(3) == 3);
    assert(guest_vsocket_socketcall_arg_count(4) == 2);
    assert(guest_vsocket_socketcall_arg_count(5) == 3);
    assert(guest_vsocket_socketcall_arg_count(8) == 4);
    assert(guest_vsocket_socketcall_arg_count(9) == 4);
    assert(guest_vsocket_socketcall_arg_count(10) == 4);
    assert(guest_vsocket_socketcall_arg_count(14) == 5);
    assert(guest_vsocket_socketcall_arg_count(15) == 5);
    assert(guest_vsocket_socketcall_arg_count(11) == -EOPNOTSUPP);
    assert(guest_vsocket_socketcall_arg_count(12) == -EOPNOTSUPP);
    assert(guest_vsocket_socketcall_arg_count(13) == -EOPNOTSUPP);
    assert(guest_vsocket_socketcall_arg_count(16) == -EOPNOTSUPP);
    assert(guest_vsocket_fd_number_reserved(GUEST_VSOCKET_FD_BASE));
    assert(!guest_vsocket_fd_number_reserved(GUEST_VSOCKET_FD_BASE + GUEST_VSOCKET_MAX_FDS));
    assert(guest_vsocket_create(&table, 2, GUEST_VSOCKET_SOCK_STREAM, 0) == -EAFNOSUPPORT);
    assert(guest_vsocket_create(&table, GUEST_VSOCKET_AF_UNIX, 2, 0) == -ESOCKTNOSUPPORT);
    assert(guest_vsocket_create(&table, GUEST_VSOCKET_AF_UNIX,
                                GUEST_VSOCKET_SOCK_STREAM, 1) == -EPROTONOSUPPORT);

    unsigned char addr[110];
    uint32_t family = 0;
    char path[108];
    size_t addr_len = make_sockaddr(addr, GUEST_VSOCKET_PROPERTY_PATH);
    assert(guest_vsocket_parse_path(addr, addr_len, &family, path, sizeof(path)) == 0);
    assert(family == GUEST_VSOCKET_AF_UNIX);
    assert(strcmp(path, GUEST_VSOCKET_PROPERTY_PATH) == 0);
    unsigned char malformed[sizeof(uint16_t) + 108];
    memset(malformed, 'x', sizeof(malformed));
    family = 0;
    assert(guest_vsocket_parse_path(malformed, sizeof(malformed), &family, path, sizeof(path)) == -ENAMETOOLONG);
    assert(guest_vsocket_parse_path(addr, 1, &family, path, sizeof(path)) == -EINVAL);

    int listener = guest_vsocket_create(&table, GUEST_VSOCKET_AF_UNIX,
                                        GUEST_VSOCKET_SOCK_STREAM, 0);
    assert(listener == GUEST_VSOCKET_FD_BASE);
    family = GUEST_VSOCKET_AF_UNIX;
    assert(guest_vsocket_bind_validate(&table, listener, family,
                                       GUEST_VSOCKET_PROPERTY_PATH) == 0);
    assert(guest_vsocket_bind_validate(&table, listener, 2,
                                       GUEST_VSOCKET_PROPERTY_PATH) == -EAFNOSUPPORT);
    assert(guest_vsocket_bind_validate(&table, listener, GUEST_VSOCKET_AF_UNIX,
                                       "/dev/socket/property_service.evil") == -EACCES);
    assert(guest_vsocket_bind_commit(&table, listener) == 0);
    assert(guest_vsocket_listen(&table, listener, 7) == -EINVAL);
    assert(guest_vsocket_listen(&table, listener, 8) == 0);
    assert(guest_vsocket_accept(&table, listener) == -EAGAIN);

    int client = guest_vsocket_create(&table, GUEST_VSOCKET_AF_UNIX,
                                      GUEST_VSOCKET_SOCK_STREAM, 0);
    assert(client >= 0);
    assert(guest_vsocket_connect(&table, client, GUEST_VSOCKET_AF_UNIX,
                                 "/dev/socket/not-property-service", 22, 1000, 1001) == -EACCES);
    assert(guest_vsocket_connect(&table, client, GUEST_VSOCKET_AF_UNIX,
                                 GUEST_VSOCKET_PROPERTY_PATH, 22, 1000, 1001) == 0);
    assert(guest_vsocket_poll_events(&table, listener, GUEST_VSOCKET_POLLIN) == GUEST_VSOCKET_POLLIN);
    int accepted = guest_vsocket_accept(&table, listener);
    assert(accepted >= 0 && accepted != listener && accepted != client);
    assert(guest_vsocket_poll_events(&table, listener, GUEST_VSOCKET_POLLIN) == 0);
    struct guest_vsocket_peercred cred;
    assert(guest_vsocket_peercred(&table, accepted, &cred) == 0);
    assert(cred.pid == 22 && cred.uid == 1000 && cred.gid == 1001);
    assert(guest_vsocket_peercred(&table, client, &cred) == -ENOTCONN);

    const unsigned char prop_msg[] = {1, 0, 0, 0, 'r', 'o', '.', 'x', 0, '1', 0};
    assert(guest_vsocket_send(&table, client, prop_msg, sizeof(prop_msg), 0) == (int)sizeof(prop_msg));
    assert(guest_vsocket_poll_events(&table, accepted, GUEST_VSOCKET_POLLIN) == GUEST_VSOCKET_POLLIN);
    unsigned char received[64] = {0};
    assert(guest_vsocket_recv(&table, accepted, received, sizeof(received), 0) == (int)sizeof(prop_msg));
    assert(memcmp(received, prop_msg, sizeof(prop_msg)) == 0);
    assert(guest_vsocket_recv(&table, accepted, received, sizeof(received), 0) == -EAGAIN);
    assert(guest_vsocket_close_fd(&table, client) == 0);
    assert(guest_vsocket_recv(&table, accepted, received, sizeof(received), 0) == 0);
    assert(guest_vsocket_close_fd(&table, accepted) == 0);

    int pair[2];
    assert(guest_vsocket_create_pair(&table, GUEST_VSOCKET_AF_UNIX,
                                     GUEST_VSOCKET_SOCK_STREAM, 0, pair) == 0);
    int status_flags = 0, descriptor_flags = 0;
    assert(guest_vsocket_fcntl(&table, pair[0], GUEST_VSOCKET_F_SETFD,
                               GUEST_VSOCKET_FD_CLOEXEC | GUEST_VSOCKET_O_NONBLOCK,
                               &status_flags,
                               &descriptor_flags) == 0);
    assert(guest_vsocket_fcntl(&table, pair[0], GUEST_VSOCKET_F_GETFD, 0,
                               &status_flags, &descriptor_flags) == GUEST_VSOCKET_FD_CLOEXEC);
    assert(guest_vsocket_fcntl(&table, pair[0], GUEST_VSOCKET_F_SETFD,
                               GUEST_VSOCKET_O_NONBLOCK, &status_flags,
                               &descriptor_flags) == 0);
    assert(guest_vsocket_fcntl(&table, pair[0], GUEST_VSOCKET_F_GETFD, 0,
                               &status_flags, &descriptor_flags) == 0);
    assert(guest_vsocket_fcntl(&table, pair[0], GUEST_VSOCKET_F_SETFD,
                               GUEST_VSOCKET_FD_CLOEXEC, &status_flags,
                               &descriptor_flags) == 0);
    assert(guest_vsocket_fcntl(&table, pair[0], GUEST_VSOCKET_F_GETFD, 0,
                               &status_flags, &descriptor_flags) == GUEST_VSOCKET_FD_CLOEXEC);
    assert(guest_vsocket_fcntl(&table, pair[0], GUEST_VSOCKET_F_SETFL,
                               GUEST_VSOCKET_O_NONBLOCK, &status_flags,
                               &descriptor_flags) == 0);
    assert(guest_vsocket_fcntl(&table, pair[0], GUEST_VSOCKET_F_GETFL, 0,
                               &status_flags, &descriptor_flags) ==
           (GUEST_VSOCKET_O_RDWR | GUEST_VSOCKET_O_NONBLOCK));
    const char signal_byte = 17;
    char signal_read = 0;
    assert(guest_vsocket_recv(&table, pair[1], &signal_read, 1, 0) == -EAGAIN);
    assert(guest_vsocket_send(&table, pair[0], &signal_byte, 1, 0) == 1);
    assert(guest_vsocket_poll_events(&table, pair[1], GUEST_VSOCKET_POLLIN) == GUEST_VSOCKET_POLLIN);
    assert(guest_vsocket_recv(&table, pair[1], &signal_read, 1, 0) == 1);
    assert(signal_read == signal_byte);
    assert(guest_vsocket_close_fd(&table, pair[0]) == 0);
    assert(guest_vsocket_poll_events(&table, pair[1], GUEST_VSOCKET_POLLIN) == GUEST_VSOCKET_POLLHUP);
    assert(guest_vsocket_close_fd(&table, pair[1]) == 0);
    assert(guest_vsocket_close_fd(&table, listener) == 0);
    assert(guest_vsocket_create(&table, GUEST_VSOCKET_AF_UNIX,
                                GUEST_VSOCKET_SOCK_STREAM, 0) == listener);
    test_qemud_control_socket_service_child_handoff();
    puts("qemud control socket regression: PASS (verified init child only; ANDROID_SOCKET_qemud fd survives F_SETFD(0); listen; empty accept EAGAIN; no synthetic peer/data)");

    puts("guest AF_UNIX software socket regression: PASS (property listener/connect/send/accept/SO_PEERCRED/recv/close/poll; SIGCHLD socketpair; unsupported domains, paths, types, protocols and options fail closed)");
    return 0;
}
