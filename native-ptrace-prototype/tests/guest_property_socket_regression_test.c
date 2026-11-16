#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "../app/src/main/cpp/guest_property_protocol.h"
#include "../app/src/main/cpp/guest_socket_virtual.h"

static void setup_property_pair(struct guest_vsocket_table *table,
                                int *listener, int *client, int *accepted) {
    guest_vsocket_table_init(table);
    *listener = guest_vsocket_create(table, GUEST_VSOCKET_AF_UNIX,
                                     GUEST_VSOCKET_SOCK_STREAM, 0);
    assert(*listener >= 0);
    assert(guest_vsocket_bind_validate(table, *listener,
           GUEST_VSOCKET_AF_UNIX, GUEST_VSOCKET_PROPERTY_PATH) == 0);
    assert(guest_vsocket_bind_commit(table, *listener) == 0);
    assert(guest_vsocket_listen(table, *listener, 8) == 0);

    *client = guest_vsocket_create(table, GUEST_VSOCKET_AF_UNIX,
                                   GUEST_VSOCKET_SOCK_STREAM, 0);
    assert(*client >= 0);
    assert(guest_vsocket_connect(table, *client, GUEST_VSOCKET_AF_UNIX,
           GUEST_VSOCKET_PROPERTY_PATH, 20, 0, 0) == 0);
    assert(guest_vsocket_poll_events(table, *listener,
           GUEST_VSOCKET_POLLIN) == GUEST_VSOCKET_POLLIN);

    /* API10 client can send immediately after connect, before init accepts. */
    *accepted = -1;
}

static void test_exact_api10_setprop_path(void) {
    struct guest_vsocket_table table;
    int listener, client, accepted;
    setup_property_pair(&table, &listener, &client, &accepted);

    struct guest_api10_prop_msg request;
    memset(&request, 0, sizeof(request));
    request.cmd = GUEST_API10_PROP_MSG_SETPROP;
    memcpy(request.name, "sys.gingervm.test", sizeof("sys.gingervm.test"));
    memcpy(request.value, "stream-ok", sizeof("stream-ok"));
    assert(sizeof(request) == 128u);

    /* API10 Bionic send() uses sendto(fd, buf, len, 0, NULL, 0). */
    assert(guest_vsocket_sendto(&table, client, &request, sizeof(request),
           0, 0, 0) == 128);
    assert(table.sent_bytes == 128u);

    /* init accepts the queued client and recv() uses recvfrom(..., NULL, NULL). */
    accepted = guest_vsocket_accept(&table, listener);
    assert(accepted >= 0);
    struct guest_vsocket_peercred peer;
    assert(guest_vsocket_peercred(&table, accepted, &peer) == 0);
    assert(peer.pid == 20 && peer.uid == 0 && peer.gid == 0);

    struct guest_api10_prop_msg received;
    memset(&received, 0, sizeof(received));
    assert(guest_vsocket_recvfrom(&table, accepted, &received,
           sizeof(received), 0, 0, 0) == 128);
    assert(memcmp(&received, &request, sizeof(request)) == 0);
    assert(received.cmd == 1u);
    assert(strcmp(received.name, "sys.gingervm.test") == 0);
    assert(strcmp(received.value, "stream-ok") == 0);
    assert(guest_vsocket_recvfrom(&table, accepted, &received,
           sizeof(received), 0, 0, 0) == -EAGAIN);
    assert(table.received_bytes == 128u);

    /* API10 property_service closes the accepted fd after the fixed record;
     * property_set has no response read and succeeds on the full send alone. */
    assert(guest_vsocket_close_fd(&table, accepted) == 0);
    assert(guest_vsocket_close_fd(&table, client) == 0);
    assert(guest_vsocket_close_fd(&table, listener) == 0);
}

static void test_argument_and_descriptor_errors(void) {
    struct guest_vsocket_table table;
    int listener, client, accepted;
    setup_property_pair(&table, &listener, &client, &accepted);
    char byte = 'x';

    assert(guest_vsocket_sendto(&table, client, &byte, 1, 0, 1, 1) == -EOPNOTSUPP);
    assert(guest_vsocket_sendto(&table, client, &byte, 1, 0, 0, 1) == -EOPNOTSUPP);
    assert(guest_vsocket_sendto(&table, client, &byte, 1, 1, 0, 0) == -EOPNOTSUPP);
    assert(guest_vsocket_sendto(&table, client, NULL, 1, 0, 0, 0) == -EFAULT);
    assert(guest_vsocket_sendto(&table, client, &byte,
           (size_t)INT32_MAX + 1u, 0, 0, 0) == -EINVAL);
    assert(guest_vsocket_sendto(&table, 4000, &byte, 1, 0, 0, 0) == -ENOTSOCK);
    assert(guest_vsocket_sendto(&table, 5003, &byte, 1, 0, 0, 0) == -EBADF);
    assert(guest_vsocket_sendto(&table, listener, &byte, 1, 0, 0, 0) == -ENOTCONN);

    accepted = guest_vsocket_accept(&table, listener);
    assert(accepted >= 0);
    char output[4];
    assert(guest_vsocket_recvfrom(&table, accepted, output, sizeof(output),
           0, 1, 1) == -EOPNOTSUPP);
    assert(guest_vsocket_recvfrom(&table, accepted, output, sizeof(output),
           0, 0, 1) == -EOPNOTSUPP);
    assert(guest_vsocket_recvfrom(&table, accepted, output, sizeof(output),
           1, 0, 0) == -EOPNOTSUPP);
    assert(guest_vsocket_recvfrom(&table, accepted, NULL, 1, 0, 0, 0) == -EFAULT);
    assert(guest_vsocket_recvfrom(&table, accepted, output,
           (size_t)INT32_MAX + 1u, 0, 0, 0) == -EINVAL);
    assert(guest_vsocket_recvfrom(&table, accepted, output, sizeof(output),
           0, 0, 0) == -EAGAIN);

    int pair[2];
    assert(guest_vsocket_create_pair(&table, GUEST_VSOCKET_AF_UNIX,
           GUEST_VSOCKET_SOCK_STREAM, 0, pair) == 0);
    assert(guest_vsocket_sendto(&table, pair[0], &byte, 1, 0, 0, 0) == -ENOTSOCK);
    assert(guest_vsocket_recvfrom(&table, pair[1], output, sizeof(output),
           0, 0, 0) == -ENOTSOCK);

    assert(guest_vsocket_close_fd(&table, pair[0]) == 0);
    assert(guest_vsocket_close_fd(&table, pair[1]) == 0);
    assert(guest_vsocket_close_fd(&table, accepted) == 0);
    assert(guest_vsocket_close_fd(&table, client) == 0);
    assert(guest_vsocket_close_fd(&table, listener) == 0);
}

static void test_queue_backpressure_and_peer_close(void) {
    struct guest_vsocket_table table;
    int listener, client, accepted;
    setup_property_pair(&table, &listener, &client, &accepted);
    accepted = guest_vsocket_accept(&table, listener);
    assert(accepted >= 0);

    unsigned char source[GUEST_VSOCKET_BUFFER_SIZE];
    unsigned char output[GUEST_VSOCKET_BUFFER_SIZE];
    for (size_t i = 0; i < sizeof(source); ++i)
        source[i] = (unsigned char)(i * 37u + 11u);

    /* A full bounded guest queue applies backpressure without dropping data. */
    assert(guest_vsocket_sendto(&table, client, source, sizeof(source),
           0, 0, 0) == (int)sizeof(source));
    assert(guest_vsocket_sendto(&table, client, source, 1, 0, 0, 0) == -EAGAIN);
    assert(table.channels[guest_vsocket_fd_get(&table, accepted)->channel].data_len[1]
           == sizeof(source));

    assert(guest_vsocket_recvfrom(&table, accepted, output, 2048, 0, 0, 0) == 2048);
    assert(memcmp(output, source, 2048) == 0);
    assert(guest_vsocket_sendto(&table, client, source, sizeof(source),
           0, 0, 0) == 2048);
    assert(guest_vsocket_recvfrom(&table, accepted, output, sizeof(output),
           0, 0, 0) == (int)sizeof(output));
    assert(memcmp(output, source + 2048, 2048) == 0);
    assert(memcmp(output + 2048, source, 2048) == 0);

    assert(guest_vsocket_close_fd(&table, client) == 0);
    assert(guest_vsocket_sendto(&table, accepted, source, 1, 0, 0, 0) == -EPIPE);
    assert(guest_vsocket_recvfrom(&table, accepted, output, sizeof(output),
           0, 0, 0) == 0);

    assert(guest_vsocket_close_fd(&table, accepted) == 0);
    assert(guest_vsocket_close_fd(&table, listener) == 0);
}

int main(void) {
    test_exact_api10_setprop_path();
    test_argument_and_descriptor_errors();
    test_queue_backpressure_and_peer_close();
    puts("guest property socket stream regressions passed");
    return 0;
}
