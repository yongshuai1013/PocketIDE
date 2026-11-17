#include "../app/src/main/cpp/guest_hardware_profile.h"
#include "../app/src/main/cpp/guest_property_protocol.h"
#include "../app/src/main/cpp/guest_qemud_peer_virtual.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

static size_t make_serial_frame(uint8_t *out, uint8_t channel,
                                const uint8_t *payload, size_t length) {
    static const char hex[] = "0123456789abcdef";
    assert(out && (payload || length == 0u));
    assert(length <= GUEST_QEMUD_PEER_MAX_FRAME_PAYLOAD);
    out[0] = (uint8_t)hex[(channel >> 4) & 0xfu];
    out[1] = (uint8_t)hex[channel & 0xfu];
    out[2] = (uint8_t)hex[(length >> 12) & 0xfu];
    out[3] = (uint8_t)hex[(length >> 8) & 0xfu];
    out[4] = (uint8_t)hex[(length >> 4) & 0xfu];
    out[5] = (uint8_t)hex[length & 0xfu];
    if (length) memcpy(out + 6u, payload, length);
    return 6u + length;
}

static void open_profile_tty(struct guest_goldfish_tty_runtime *tty) {
    guest_goldfish_tty_runtime_init(tty);
    assert(guest_goldfish_tty_note_open(tty,
        GUEST_GOLDFISH_TTY_QEMUD_MINOR, 6001) == 0);
    assert(guest_goldfish_tty_note_peer_attached(tty, 6001) == 0);
}

static void test_qemu_props_lineage_is_exact_and_fail_closed(void) {
    struct guest_qemud_client_identity identity = {
        .client_elf_verified = 1,
        .client_guest_euid = 0,
        .client_is_thread = 0,
        .script_shell_elf_verified = 1,
        .script_shell_guest_euid = 0,
        .script_shell_is_thread = 0,
        .exact_init_goldfish_script = 1,
        .shell_direct_init_child = 1,
        .original_init_verified = 1,
    };
    assert(guest_qemud_client_actor_authorized(&identity));
    identity.client_elf_verified = 0;
    assert(!guest_qemud_client_actor_authorized(&identity));
    identity.client_elf_verified = 1;
    identity.client_guest_euid = 1000;
    assert(!guest_qemud_client_actor_authorized(&identity));
    identity.client_guest_euid = 0;
    identity.client_is_thread = 1;
    assert(!guest_qemud_client_actor_authorized(&identity));
    identity.client_is_thread = 0;
    identity.script_shell_elf_verified = 0;
    assert(!guest_qemud_client_actor_authorized(&identity));
    identity.script_shell_elf_verified = 1;
    identity.exact_init_goldfish_script = 0;
    assert(!guest_qemud_client_actor_authorized(&identity));
    identity.exact_init_goldfish_script = 1;
    identity.shell_direct_init_child = 0;
    assert(!guest_qemud_client_actor_authorized(&identity));
    identity.shell_direct_init_child = 1;
    identity.original_init_verified = 0;
    assert(!guest_qemud_client_actor_authorized(&identity));
}

static void test_control_and_boot_properties_framing(void) {
    struct guest_goldfish_tty_runtime tty;
    struct guest_qemud_peer_runtime peer;
    open_profile_tty(&tty);
    guest_qemud_peer_runtime_init(&peer, GUEST_PROFILE_DISPLAY_DENSITY_DPI);
    assert(peer.profile_density_present && peer.profile_density == 240u);

    const uint8_t connect[] = "connect:boot-properties:01";
    uint8_t frame[256], received[256], expected[64];
    size_t frame_length = make_serial_frame(frame, 0u, connect, sizeof(connect) - 1u);
    assert(guest_qemud_peer_feed_serial(&peer, &tty, frame, 2u) == 0);
    assert(peer.serial_frames_received == 0u && tty.rx_length == 0u);
    assert(guest_qemud_peer_feed_serial(&peer, &tty, frame + 2u,
                                        frame_length - 2u) == 0);
    assert(peer.serial_frames_received == 1u);
    assert(peer.control_connects == 1u && peer.boot_properties_connected);
    size_t expected_length = make_serial_frame(expected, 0u,
        (const uint8_t *)"ok:connect:01", strlen("ok:connect:01"));
    int amount = guest_goldfish_tty_read_bytes(&tty, 6001, received,
                                                sizeof(received), 0);
    assert(amount == (int)expected_length);
    assert(memcmp(received, expected, expected_length) == 0);
    assert(guest_goldfish_tty_poll_events(&tty, 6001,
        GUEST_VSOCKET_POLLIN) == 0);

    const uint8_t list_payload[] = "0004list";
    frame_length = make_serial_frame(frame, 1u, list_payload,
                                      sizeof(list_payload) - 1u);
    assert(guest_qemud_peer_feed_serial(&peer, &tty, frame, frame_length) == 0);
    assert(peer.service_list_requests == 1u);
    assert(peer.property_records_sent == 1u && peer.terminators_sent == 1u);

    amount = guest_goldfish_tty_read_bytes(&tty, 6001, received,
                                            sizeof(received), 0);
    assert(amount > 0);
    size_t at = 0u;
    uint32_t channel = 0u, outer_length = 0u, record_length = 0u;
    assert(guest_qemud_peer_parse_hex(received + at, 2u, &channel) == 0);
    assert(channel == 1u);
    assert(guest_qemud_peer_parse_hex(received + at + 2u, 4u,
                                      &outer_length) == 0);
    at += 6u;
    assert(outer_length <= (uint32_t)amount - 6u);
    assert(guest_qemud_peer_parse_hex(received + at, 4u,
                                      &record_length) == 0);
    at += 4u;
    assert(record_length == strlen(GUEST_QEMUD_PEER_BOOT_PROPERTY));
    assert(at + record_length <= (size_t)amount);
    assert(memcmp(received + at, GUEST_QEMUD_PEER_BOOT_PROPERTY,
                  record_length) == 0);
    at += record_length;
    assert(at + 10u <= (size_t)amount);
    assert(guest_qemud_peer_parse_hex(received + at, 2u, &channel) == 0);
    assert(channel == 1u);
    assert(guest_qemud_peer_parse_hex(received + at + 2u, 4u,
                                      &outer_length) == 0);
    assert(outer_length == 5u);
    assert(memcmp(received + at + 6u, "0001\0", 5u) == 0);
    at += 11u;
    assert(at == (size_t)amount);
    assert(peer.profile_density == 240u);
    assert(tty.peer_write_bytes == 0u);
    unsigned long frames_before_close = peer.serial_frames_received;
    peer.input[0] = '0';
    peer.input[1] = '0';
    peer.input_length = 2u;
    guest_qemud_peer_reset_connection(&peer);
    assert(!peer.boot_properties_connected && peer.channel_id == 0u);
    assert(peer.input_length == 0u && peer.serial_frames_received == frames_before_close);
}

static void test_unknown_service_is_rejected_and_no_extra_property_is_sent(void) {
    struct guest_goldfish_tty_runtime tty;
    struct guest_qemud_peer_runtime peer;
    open_profile_tty(&tty);
    guest_qemud_peer_runtime_init(&peer, GUEST_PROFILE_DISPLAY_DENSITY_DPI);
    const uint8_t connect[] = "connect:not-a-service:02";
    uint8_t frame[128], received[128], expected[128];
    size_t frame_length = make_serial_frame(frame, 0u, connect,
                                            sizeof(connect) - 1u);
    assert(guest_qemud_peer_feed_serial(&peer, &tty, frame, frame_length) == 0);
    size_t expected_length = make_serial_frame(expected, 0u,
        (const uint8_t *)"ko:connect:02:unknown service",
        strlen("ko:connect:02:unknown service"));
    assert(guest_goldfish_tty_read_bytes(&tty, 6001, received,
        sizeof(received), 0) == (int)expected_length);
    assert(memcmp(received, expected, expected_length) == 0);
    assert(!peer.boot_properties_connected);
    assert(peer.service_list_requests == 0u && peer.property_records_sent == 0u);
    assert(guest_qemud_peer_feed_serial(&peer, &tty, frame, 5u) == 0);
    assert(peer.malformed_frames == 0u); /* still a partial frame, not malformed */
}

static void test_response_backpressure_is_atomic(void) {
    struct guest_goldfish_tty_runtime tty;
    struct guest_qemud_peer_runtime peer;
    open_profile_tty(&tty);
    guest_qemud_peer_runtime_init(&peer, GUEST_PROFILE_DISPLAY_DENSITY_DPI);
    uint8_t frame[128];
    size_t length = make_serial_frame(frame, 0u,
        (const uint8_t *)"connect:boot-properties:01",
        strlen("connect:boot-properties:01"));
    tty.rx_length = GUEST_GOLDFISH_TTY_RX_CAPACITY - 18u;
    assert(guest_qemud_peer_feed_serial(&peer, &tty, frame, length) == -ENOBUFS);
    assert(!peer.boot_properties_connected && peer.channel_id == 0u);
    assert(peer.control_connects == 0u && tty.rx_length ==
           GUEST_GOLDFISH_TTY_RX_CAPACITY - 18u);

    guest_qemud_peer_reset_connection(&peer);
    peer.boot_properties_connected = 1u;
    peer.channel_id = 1u;
    const uint8_t list[] = "0004list";
    length = make_serial_frame(frame, 1u, list, sizeof(list) - 1u);
    size_t property_wire = 10u + strlen(GUEST_QEMUD_PEER_BOOT_PROPERTY);
    size_t terminator_wire = 11u;
    tty.rx_length = GUEST_GOLDFISH_TTY_RX_CAPACITY -
        (property_wire + terminator_wire) + 1u;
    assert(guest_qemud_peer_feed_serial(&peer, &tty, frame, length) == -ENOBUFS);
    assert(peer.service_list_requests == 0u && peer.property_records_sent == 0u &&
           peer.terminators_sent == 0u);
    assert(tty.rx_length == GUEST_GOLDFISH_TTY_RX_CAPACITY -
           (property_wire + terminator_wire) + 1u);
}

static void setup_qemud_listener(struct guest_vsocket_table *fds,
                                 int *listener_fd) {
    guest_vsocket_table_init(fds);
    int fd = guest_vsocket_alloc_fd(fds, VIRTUAL_FD_PROPERTY);
    assert(fd >= 0);
    assert(guest_vsocket_bind_validate(fds, fd, GUEST_VSOCKET_AF_UNIX,
                                      GUEST_VSOCKET_QEMUD_PATH) == 0);
    assert(guest_vsocket_bind_commit_path(fds, fd,
        GUEST_VSOCKET_QEMUD_PATH) == 0);
    assert(guest_vsocket_listen(fds, fd, 8) == 0);
    *listener_fd = fd;
}

static void test_qemud_connect_accept_stream_and_epoll_edges(void) {
    struct guest_vsocket_table fds;
    struct guest_goldfish_tty_runtime tty;
    struct guest_goldfish_tty_epoll_table epolls;
    int listener = -1;
    setup_qemud_listener(&fds, &listener);
    guest_goldfish_tty_runtime_init(&tty);
    int tty_fd = guest_vsocket_alloc_fd(&fds, VIRTUAL_FD_DEV_TTY);
    assert(tty_fd >= 0);
    assert(guest_goldfish_tty_note_open(&tty,
        GUEST_GOLDFISH_TTY_QEMUD_MINOR, tty_fd) == 0);
    assert(guest_goldfish_tty_note_peer_attached(&tty, tty_fd) == 0);
    guest_goldfish_tty_epoll_table_init(&epolls);
    int epfd = guest_goldfish_tty_epoll_create(&epolls, &fds, 4, 9u);
    assert(epfd >= 0);
    struct guest_arm32_epoll_event event = {
        .events = GUEST_GOLDFISH_TTY_EPOLLIN | GUEST_GOLDFISH_TTY_EPOLLET,
        .abi_padding = 0,
        .data = UINT64_C(0x1122334455667788),
    };
    assert(guest_goldfish_tty_epoll_ctl(&epolls, &fds, 1, 9u, epfd,
        GUEST_GOLDFISH_TTY_EPOLL_CTL_ADD, listener, event.events,
        event.data, tty.tty_fd, listener) == 0);
    event.data = UINT64_C(0xaabbccdd01020304);
    assert(guest_goldfish_tty_epoll_ctl(&epolls, &fds, 1, 9u, epfd,
        GUEST_GOLDFISH_TTY_EPOLL_CTL_ADD, tty_fd, event.events,
        event.data, tty.tty_fd, listener) == 0);
    struct guest_arm32_epoll_event out[8];
    assert(guest_goldfish_tty_epoll_collect(&epolls, &fds, &tty, 9u,
        epfd, 8, out) == 0);

    int client = guest_vsocket_alloc_fd(&fds, VIRTUAL_FD_PROPERTY);
    assert(client >= 0);
    assert(guest_vsocket_qemud_connect(&fds, client, GUEST_VSOCKET_AF_UNIX,
        GUEST_VSOCKET_QEMUD_PATH, 41, 0, 0) == 0);
    assert(guest_goldfish_tty_epoll_collect(&epolls, &fds, &tty, 9u,
        epfd, 8, out) == 1);
    assert(out[0].data == UINT64_C(0x1122334455667788));
    assert(out[0].events & GUEST_GOLDFISH_TTY_EPOLLIN);
    int accepted = guest_vsocket_accept(&fds, listener);
    assert(accepted >= 0);
    event.data = UINT64_C(0x9988776655443322);
    assert(guest_goldfish_tty_epoll_ctl(&epolls, &fds, 1, 9u, epfd,
        GUEST_GOLDFISH_TTY_EPOLL_CTL_ADD, accepted, event.events,
        event.data, tty.tty_fd, listener) == 0);
    assert(guest_goldfish_tty_epoll_collect(&epolls, &fds, &tty, 9u,
        epfd, 8, out) == 0); /* listener edge clears after accept */

    const char service[] = "boot-properties";
    assert(guest_vsocket_send(&fds, client, service, sizeof(service) - 1u, 0) ==
           (int)(sizeof(service) - 1u));
    assert(guest_goldfish_tty_epoll_collect(&epolls, &fds, &tty, 9u,
        epfd, 8, out) == 1);
    assert(out[0].data == UINT64_C(0x9988776655443322));
    char received[64];
    int amount = guest_vsocket_peek(&fds, accepted, received,
                                     sizeof(received), 0);
    assert(amount == (int)(sizeof(service) - 1u));
    assert(memcmp(received, service, sizeof(service) - 1u) == 0);
    assert(guest_vsocket_consume(&fds, accepted, (size_t)amount) == 0);
    assert(guest_goldfish_tty_epoll_collect(&epolls, &fds, &tty, 9u,
        epfd, 8, out) == 0); /* drained edge is not repeated */
    assert(guest_vsocket_send(&fds, client, "x", 1u, 0) == 1);
    assert(guest_goldfish_tty_epoll_collect(&epolls, &fds, &tty, 9u,
        epfd, 8, out) == 1);
    assert(out[0].data == UINT64_C(0x9988776655443322));

    assert(guest_goldfish_tty_rx_enqueue(&tty, "rx", 2u) == 0);
    int saw_tty = 0;
    int count = guest_goldfish_tty_epoll_collect(&epolls, &fds, &tty, 9u,
        epfd, 8, out);
    for (int i = 0; i < count; ++i)
        if (out[i].data == UINT64_C(0xaabbccdd01020304)) saw_tty = 1;
    assert(saw_tty);
    char tty_bytes[8];
    assert(guest_goldfish_tty_read_bytes(&tty, tty_fd, tty_bytes,
        sizeof(tty_bytes), 0) == 2);
    assert(memcmp(tty_bytes, "rx", 2u) == 0);
    assert(guest_goldfish_tty_poll_events(&tty, tty_fd,
        GUEST_VSOCKET_POLLIN) == 0);
    assert(guest_vsocket_close_fd(&fds, listener) == 0);
    assert(guest_vsocket_send(&fds, client, "z", 1u, 0) == 1);
    assert(guest_vsocket_peek(&fds, accepted, received, sizeof(received), 0) == 2);
    assert(memcmp(received, "xz", 2u) == 0);
    assert(guest_vsocket_consume(&fds, accepted, 2u) == 0);
    assert(guest_goldfish_tty_epoll_close(&epolls, epfd) == 0);
}

static void test_pending_qemud_client_gets_eof_on_listener_close(void) {
    struct guest_vsocket_table fds;
    int listener = -1;
    setup_qemud_listener(&fds, &listener);
    int client = guest_vsocket_alloc_fd(&fds, VIRTUAL_FD_PROPERTY);
    assert(client >= 0);
    assert(guest_vsocket_qemud_connect(&fds, client, GUEST_VSOCKET_AF_UNIX,
        GUEST_VSOCKET_QEMUD_PATH, 45, 0, 0) == 0);
    assert(guest_vsocket_close_fd(&fds, listener) == 0);
    char byte = 0;
    assert(guest_vsocket_peek(&fds, client, &byte, 1u, 0) == 0);
    assert(guest_vsocket_poll_events(&fds, client, GUEST_VSOCKET_POLLIN) &
           GUEST_VSOCKET_POLLHUP);
    assert(guest_vsocket_close_fd(&fds, client) == 0);
}

static void test_unaccepted_qemud_client_close_releases_channel(void) {
    struct guest_vsocket_table fds;
    int listener = -1;
    setup_qemud_listener(&fds, &listener);
    int client = guest_vsocket_alloc_fd(&fds, VIRTUAL_FD_PROPERTY);
    assert(client >= 0);
    assert(guest_vsocket_qemud_connect(&fds, client, GUEST_VSOCKET_AF_UNIX,
        GUEST_VSOCKET_QEMUD_PATH, 46, 0, 0) == 0);
    struct guest_vsocket_fd *client_entry = guest_vsocket_fd_get(&fds, client);
    assert(client_entry && client_entry->channel >= 0);
    int channel_index = client_entry->channel;
    assert(fds.channels[channel_index].allocated &&
           fds.channels[channel_index].pending);
    assert(guest_vsocket_close_fd(&fds, client) == 0);
    assert(!fds.channels[channel_index].allocated);
    assert(guest_vsocket_poll_events(&fds, listener,
        GUEST_VSOCKET_POLLIN) == 0);
    assert(guest_vsocket_accept(&fds, listener) == -EAGAIN);
    assert(guest_vsocket_close_fd(&fds, listener) == 0);
}

static void test_boot_properties_to_api10_property_set_wire_request(void) {
    struct guest_vsocket_table fds;
    struct guest_goldfish_tty_runtime tty;
    struct guest_qemud_peer_runtime peer;
    setup_qemud_listener(&fds, &(int){-1});
    int qemud_listener = fds.qemud_listener_fd;
    int tty_fd = guest_vsocket_alloc_fd(&fds, VIRTUAL_FD_DEV_TTY);
    assert(tty_fd >= 0);
    guest_goldfish_tty_runtime_init(&tty);
    assert(guest_goldfish_tty_note_open(&tty,
        GUEST_GOLDFISH_TTY_QEMUD_MINOR, tty_fd) == 0);
    assert(guest_goldfish_tty_note_peer_attached(&tty, tty_fd) == 0);
    guest_qemud_peer_runtime_init(&peer, GUEST_PROFILE_DISPLAY_DENSITY_DPI);

    int qemu_props = guest_vsocket_alloc_fd(&fds, VIRTUAL_FD_PROPERTY);
    assert(qemu_props >= 0);
    assert(guest_vsocket_qemud_connect(&fds, qemu_props,
        GUEST_VSOCKET_AF_UNIX, GUEST_VSOCKET_QEMUD_PATH, 44, 0, 0) == 0);
    int qemud_client = guest_vsocket_accept(&fds, qemud_listener);
    assert(qemud_client >= 0);
    assert(guest_vsocket_send(&fds, qemu_props, "boot-properties", 15u, 0) == 15);
    char stream[256];
    int amount = guest_vsocket_peek(&fds, qemud_client, stream,
                                     sizeof(stream), 0);
    assert(amount == 15 && memcmp(stream, "boot-properties", 15u) == 0);
    assert(guest_vsocket_consume(&fds, qemud_client, (size_t)amount) == 0);

    uint8_t serial[256], tty_bytes[512];
    size_t serial_length = make_serial_frame(serial, 0u,
        (const uint8_t *)"connect:boot-properties:01",
        strlen("connect:boot-properties:01"));
    assert(guest_qemud_peer_feed_serial(&peer, &tty, serial,
                                        serial_length) == 0);
    amount = guest_goldfish_tty_read_bytes(&tty, tty_fd, tty_bytes,
                                            sizeof(tty_bytes), 0);
    assert(amount > 0);
    uint32_t outer_length = 0u;
    assert(guest_qemud_peer_parse_hex(tty_bytes + 2u, 4u,
                                      &outer_length) == 0);
    assert((size_t)amount == 6u + outer_length);
    assert(memcmp(tty_bytes + 6u, "ok:connect:01", outer_length) == 0);
    assert(guest_vsocket_send(&fds, qemud_client, "OK", 2u, 0) == 2);
    assert(guest_vsocket_peek(&fds, qemu_props, stream,
        sizeof(stream), 0) == 2);
    assert(memcmp(stream, "OK", 2u) == 0);
    assert(guest_vsocket_consume(&fds, qemu_props, 2u) == 0);

    const uint8_t list_request[] = "0004list";
    assert(guest_vsocket_send(&fds, qemu_props, list_request,
        sizeof(list_request) - 1u, 0) == (int)(sizeof(list_request) - 1u));
    amount = guest_vsocket_peek(&fds, qemud_client, stream,
        sizeof(stream), 0);
    assert(amount == (int)(sizeof(list_request) - 1u));
    serial_length = make_serial_frame(serial, 1u, (const uint8_t *)stream,
                                      (size_t)amount);
    assert(guest_vsocket_consume(&fds, qemud_client, (size_t)amount) == 0);
    assert(guest_qemud_peer_feed_serial(&peer, &tty, serial,
                                        serial_length) == 0);

    amount = guest_goldfish_tty_read_bytes(&tty, tty_fd, tty_bytes,
                                            sizeof(tty_bytes), 0);
    assert(amount > 0);
    size_t offset = 0u;
    while (offset < (size_t)amount) {
        uint32_t channel = 0u, payload_length = 0u;
        assert((size_t)amount - offset >= 6u);
        assert(guest_qemud_peer_parse_hex(tty_bytes + offset, 2u,
                                          &channel) == 0);
        assert(guest_qemud_peer_parse_hex(tty_bytes + offset + 2u, 4u,
                                          &payload_length) == 0);
        assert(channel == 1u && offset + 6u + payload_length <= (size_t)amount);
        assert(guest_vsocket_send(&fds, qemud_client, tty_bytes + offset + 6u,
                                  payload_length, 0) == (int)payload_length);
        offset += 6u + payload_length;
    }
    amount = guest_vsocket_peek(&fds, qemu_props, stream, sizeof(stream), 0);
    assert(amount == (int)(4u + strlen(GUEST_QEMUD_PEER_BOOT_PROPERTY) + 5u));
    uint32_t record_length = 0u;
    assert(guest_qemud_peer_parse_hex((const uint8_t *)stream, 4u,
                                      &record_length) == 0);
    assert(record_length == strlen(GUEST_QEMUD_PEER_BOOT_PROPERTY));
    assert(memcmp(stream + 4u, GUEST_QEMUD_PEER_BOOT_PROPERTY,
                  record_length) == 0);
    size_t terminator_offset = 4u + record_length;
    assert(memcmp(stream + terminator_offset, "0001\0", 5u) == 0);
    assert(guest_vsocket_consume(&fds, qemu_props, (size_t)amount) == 0);

    /* This fixture follows API10 qemu-props' property_set call with the exact
     * API10 libcutils fixed-size request on property_service. It validates the
     * broker wire path, not execution of the ARM32 qemu-props binary. */
    char property_name[GUEST_API10_PROP_NAME_MAX];
    char property_value[GUEST_API10_PROP_VALUE_MAX];
    const char *equals = strchr(stream + 4u, '=');
    assert(equals != NULL);
    size_t name_length = (size_t)(equals - (stream + 4u));
    size_t value_length = record_length - name_length - 1u;
    assert(name_length < sizeof(property_name) &&
           value_length < sizeof(property_value));
    memcpy(property_name, stream + 4u, name_length);
    property_name[name_length] = '\0';
    memcpy(property_value, equals + 1, value_length);
    property_value[value_length] = '\0';
    assert(strcmp(property_name, "qemu.sf.lcd_density") == 0);
    assert(strcmp(property_value, "240") == 0);

    int property_listener = guest_vsocket_create(&fds,
        GUEST_VSOCKET_AF_UNIX, GUEST_VSOCKET_SOCK_STREAM, 0);
    assert(property_listener >= 0);
    assert(guest_vsocket_bind_validate(&fds, property_listener,
        GUEST_VSOCKET_AF_UNIX, GUEST_VSOCKET_PROPERTY_PATH) == 0);
    assert(guest_vsocket_bind_commit(&fds, property_listener) == 0);
    assert(guest_vsocket_listen(&fds, property_listener, 8) == 0);
    int property_client = guest_vsocket_create(&fds,
        GUEST_VSOCKET_AF_UNIX, GUEST_VSOCKET_SOCK_STREAM, 0);
    assert(property_client >= 0);
    assert(guest_vsocket_connect(&fds, property_client,
        GUEST_VSOCKET_AF_UNIX, GUEST_VSOCKET_PROPERTY_PATH, 44, 0, 0) == 0);
    int property_service = guest_vsocket_accept(&fds, property_listener);
    assert(property_service >= 0);
    struct guest_api10_prop_msg received;
    memset(&received, 0, sizeof(received));
    assert(guest_vsocket_recvfrom(&fds, property_service, &received,
        sizeof(received), 0, 0, 0) == -EAGAIN);
    struct guest_api10_prop_msg request;
    memset(&request, 0, sizeof(request));
    request.cmd = GUEST_API10_PROP_MSG_SETPROP;
    memcpy(request.name, property_name, name_length + 1u);
    memcpy(request.value, property_value, value_length + 1u);
    assert(guest_vsocket_sendto(&fds, property_client, &request,
        sizeof(request), 0, 0, 0) == (int)sizeof(request));
    assert(guest_vsocket_recvfrom(&fds, property_service, &received,
        sizeof(received), 0, 0, 0) == (int)sizeof(received));
    assert(received.cmd == GUEST_API10_PROP_MSG_SETPROP);
    assert(strcmp(received.name, "qemu.sf.lcd_density") == 0);
    assert(strcmp(received.value, "240") == 0);
    assert(peer.control_connects == 1u && peer.service_list_requests == 1u);
    assert(peer.property_records_sent == 1u && peer.terminators_sent == 1u);
}

int main(void) {
    test_qemu_props_lineage_is_exact_and_fail_closed();
    test_control_and_boot_properties_framing();
    test_unknown_service_is_rejected_and_no_extra_property_is_sent();
    test_response_backpressure_is_atomic();
    test_qemud_connect_accept_stream_and_epoll_edges();
    test_pending_qemud_client_gets_eof_on_listener_close();
    test_unaccepted_qemud_client_close_releases_channel();
    test_boot_properties_to_api10_property_set_wire_request();
    puts("guest QEMUD peer/boot-properties regression: PASS (source-backed protocol state machine; property_set wire request shape validated, not a device boot claim)");
    return 0;
}
