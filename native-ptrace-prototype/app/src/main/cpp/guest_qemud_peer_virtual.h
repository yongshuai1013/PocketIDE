#ifndef GINGERVM_GUEST_QEMUD_PEER_VIRTUAL_H
#define GINGERVM_GUEST_QEMUD_PEER_VIRTUAL_H

#include "guest_goldfish_tty_virtual.h"

#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

/*
 * Source-backed, explicitly synthetic Android API10 emulator-side peer subset.
 * It speaks only the documented QEMUD multiplex wire format and the paired
 * boot-properties service's "list" request. It is not QEMU and supplies no
 * AVD/user/shared-network values. The sole property comes from GingerVM's
 * named WVGA800/240-dpi profile, not from the host device.
 */
#define GUEST_QEMUD_PEER_CHANNEL_CONTROL 0u
#define GUEST_QEMUD_PEER_CHANNEL_MAX 255u
#define GUEST_QEMUD_PEER_PROPERTY_KEY "qemu.sf.lcd_density"
#define GUEST_QEMUD_PEER_PROPERTY_VALUE "240"
#define GUEST_QEMUD_PEER_BOOT_PROPERTIES_SERVICE "boot-properties"
#define GUEST_QEMUD_PEER_LIST_COMMAND "list"
#define GUEST_QEMUD_PEER_BOOT_PROPERTY \
    GUEST_QEMUD_PEER_PROPERTY_KEY "=" GUEST_QEMUD_PEER_PROPERTY_VALUE
#define GUEST_QEMUD_PEER_CONNECT_PREFIX "connect:"
#define GUEST_QEMUD_PEER_DISCONNECT_PREFIX "disconnect:"
#define GUEST_QEMUD_PEER_OK_PREFIX "ok:connect:"
#define GUEST_QEMUD_PEER_KO_PREFIX "ko:connect:"
#define GUEST_QEMUD_PEER_CONTROL_HEADER_BYTES 6u
#define GUEST_QEMUD_PEER_SERVICE_HEADER_BYTES 4u
#define GUEST_QEMUD_PEER_MAX_PENDING_INPUT 4096u
#define GUEST_QEMUD_PEER_MAX_FRAME_PAYLOAD 4096u

struct guest_qemud_client_identity {
    int client_elf_verified;
    int client_guest_euid;
    int client_is_thread;
    int script_shell_elf_verified;
    int script_shell_guest_euid;
    int script_shell_is_thread;
    int exact_init_goldfish_script;
    int shell_direct_init_child;
    int original_init_verified;
};

static inline int guest_qemud_client_actor_authorized(
        const struct guest_qemud_client_identity *identity) {
    return identity && identity->client_elf_verified &&
        identity->client_guest_euid == 0 && !identity->client_is_thread &&
        identity->script_shell_elf_verified &&
        identity->script_shell_guest_euid == 0 &&
        !identity->script_shell_is_thread &&
        identity->exact_init_goldfish_script &&
        identity->shell_direct_init_child && identity->original_init_verified;
}

struct guest_qemud_peer_runtime {
    uint8_t input[GUEST_QEMUD_PEER_MAX_PENDING_INPUT];
    size_t input_length;
    uint8_t channel_id;
    uint8_t boot_properties_connected;
    uint8_t profile_density_present;
    uint16_t profile_density;
    unsigned long serial_frames_received;
    unsigned long control_connects;
    unsigned long control_disconnects;
    unsigned long service_list_requests;
    unsigned long property_records_sent;
    unsigned long terminators_sent;
    unsigned long ignored_frames;
    unsigned long malformed_frames;
};

static inline int guest_qemud_peer_hex_value(uint8_t byte) {
    if (byte >= '0' && byte <= '9') return (int)(byte - '0');
    if (byte >= 'a' && byte <= 'f') return (int)(byte - 'a') + 10;
    if (byte >= 'A' && byte <= 'F') return (int)(byte - 'A') + 10;
    return -1;
}

static inline int guest_qemud_peer_parse_hex(const uint8_t *bytes, size_t count,
                                             uint32_t *value) {
    if (!bytes || !value || count == 0u || count > 8u) return -EINVAL;
    uint32_t result = 0;
    for (size_t i = 0; i < count; ++i) {
        int nibble = guest_qemud_peer_hex_value(bytes[i]);
        if (nibble < 0) return -EINVAL;
        result = (result << 4) | (uint32_t)nibble;
    }
    *value = result;
    return 0;
}

static inline int guest_qemud_peer_append_serial_frame(
        struct guest_goldfish_tty_runtime *tty, uint32_t channel,
        const uint8_t *payload, size_t payload_length) {
    if (!tty || (!payload && payload_length) || channel > GUEST_QEMUD_PEER_CHANNEL_MAX ||
        payload_length == 0u || payload_length > GUEST_QEMUD_PEER_MAX_FRAME_PAYLOAD)
        return -EINVAL;
    size_t wire_length = GUEST_QEMUD_PEER_CONTROL_HEADER_BYTES + payload_length;
    if (guest_goldfish_tty_rx_available(tty) < wire_length) return -ENOBUFS;
    uint8_t frame[GUEST_QEMUD_PEER_CONTROL_HEADER_BYTES +
                  GUEST_QEMUD_PEER_MAX_FRAME_PAYLOAD];
    static const char hex[] = "0123456789abcdef";
    frame[0] = (uint8_t)hex[(channel >> 4) & 0xfu];
    frame[1] = (uint8_t)hex[channel & 0xfu];
    frame[2] = (uint8_t)hex[(payload_length >> 12) & 0xfu];
    frame[3] = (uint8_t)hex[(payload_length >> 8) & 0xfu];
    frame[4] = (uint8_t)hex[(payload_length >> 4) & 0xfu];
    frame[5] = (uint8_t)hex[payload_length & 0xfu];
    memcpy(frame + GUEST_QEMUD_PEER_CONTROL_HEADER_BYTES, payload, payload_length);
    return guest_goldfish_tty_rx_enqueue(tty, frame,
        GUEST_QEMUD_PEER_CONTROL_HEADER_BYTES + payload_length);
}

static inline int guest_qemud_peer_append_control(
        struct guest_goldfish_tty_runtime *tty, const char *text) {
    size_t length = strlen(text);
    return guest_qemud_peer_append_serial_frame(tty,
        GUEST_QEMUD_PEER_CHANNEL_CONTROL, (const uint8_t *)text, length);
}

static inline void guest_qemud_peer_runtime_init(
        struct guest_qemud_peer_runtime *peer, uint16_t profile_density) {
    if (!peer) return;
    memset(peer, 0, sizeof(*peer));
    /* Only the already named synthetic WVGA800 profile is accepted here. */
    if (profile_density == 240u) {
        peer->profile_density_present = 1u;
        peer->profile_density = 240u;
    }
}

static inline void guest_qemud_peer_reset_connection(
        struct guest_qemud_peer_runtime *peer) {
    if (!peer) return;
    memset(peer->input, 0, sizeof(peer->input));
    peer->input_length = 0u;
    peer->channel_id = 0u;
    peer->boot_properties_connected = 0u;
}

static inline int guest_qemud_peer_send_service_record(
        struct guest_qemud_peer_runtime *peer,
        struct guest_goldfish_tty_runtime *tty, uint8_t channel,
        const uint8_t *record, size_t record_length) {
    if (!peer || !tty || (!record && record_length) ||
        record_length > GUEST_QEMUD_PEER_MAX_FRAME_PAYLOAD -
                        GUEST_QEMUD_PEER_SERVICE_HEADER_BYTES) return -EINVAL;
    uint8_t framed[GUEST_QEMUD_PEER_MAX_FRAME_PAYLOAD];
    static const char hex[] = "0123456789abcdef";
    framed[0] = (uint8_t)hex[(record_length >> 12) & 0xfu];
    framed[1] = (uint8_t)hex[(record_length >> 8) & 0xfu];
    framed[2] = (uint8_t)hex[(record_length >> 4) & 0xfu];
    framed[3] = (uint8_t)hex[record_length & 0xfu];
    if (record_length) memcpy(framed + GUEST_QEMUD_PEER_SERVICE_HEADER_BYTES,
                              record, record_length);
    int rc = guest_qemud_peer_append_serial_frame(tty, channel, framed,
        GUEST_QEMUD_PEER_SERVICE_HEADER_BYTES + record_length);
    if (rc == 0) {
        if (record_length == 1u && record[0] == 0u) peer->terminators_sent++;
        else if (record_length > 0u) peer->property_records_sent++;
    }
    return rc;
}

static inline int guest_qemud_peer_send_list(
        struct guest_qemud_peer_runtime *peer,
        struct guest_goldfish_tty_runtime *tty, uint8_t channel) {
    int rc = 0;
    if (peer->profile_density_present) {
        static const uint8_t property[] = GUEST_QEMUD_PEER_BOOT_PROPERTY;
        size_t property_wire_length = GUEST_QEMUD_PEER_CONTROL_HEADER_BYTES +
            GUEST_QEMUD_PEER_SERVICE_HEADER_BYTES + sizeof(property) - 1u;
        size_t terminator_wire_length = GUEST_QEMUD_PEER_CONTROL_HEADER_BYTES +
            GUEST_QEMUD_PEER_SERVICE_HEADER_BYTES + 1u;
        if (guest_goldfish_tty_rx_available(tty) <
            property_wire_length + terminator_wire_length) return -ENOBUFS;
        rc = guest_qemud_peer_send_service_record(peer, tty, channel, property,
                                                   sizeof(property) - 1u);
        if (rc != 0) return rc;
    } else if (guest_goldfish_tty_rx_available(tty) <
               GUEST_QEMUD_PEER_CONTROL_HEADER_BYTES +
               GUEST_QEMUD_PEER_SERVICE_HEADER_BYTES + 1u) {
        return -ENOBUFS;
    }
    static const uint8_t terminator[] = {0u};
    return guest_qemud_peer_send_service_record(peer, tty, channel,
                                                 terminator, sizeof(terminator));
}

static inline int guest_qemud_peer_parse_connect(
        struct guest_qemud_peer_runtime *peer,
        struct guest_goldfish_tty_runtime *tty,
        const uint8_t *payload, size_t length) {
    static const char prefix[] = GUEST_QEMUD_PEER_CONNECT_PREFIX;
    if (length <= sizeof(prefix) - 1u ||
        memcmp(payload, prefix, sizeof(prefix) - 1u) != 0) return -EINVAL;
    const uint8_t *name = payload + sizeof(prefix) - 1u;
    size_t name_and_id_length = length - (sizeof(prefix) - 1u);
    if (name_and_id_length < 4u) return -EINVAL;
    const uint8_t *colon = NULL;
    for (size_t i = 0; i < name_and_id_length; ++i)
        if (name[i] == ':') colon = name + i;
    if (!colon || (size_t)(colon - name) == 0u ||
        (size_t)(payload + length - colon) != 3u) return -EINVAL;
    uint32_t channel = 0;
    if (guest_qemud_peer_parse_hex(colon + 1u, 2u, &channel) != 0 ||
        channel == GUEST_QEMUD_PEER_CHANNEL_CONTROL ||
        channel > GUEST_QEMUD_PEER_CHANNEL_MAX) return -EINVAL;
    size_t service_length = (size_t)(colon - name);
    static const char service[] = GUEST_QEMUD_PEER_BOOT_PROPERTIES_SERVICE;
    char response[128];
    if (service_length != sizeof(service) - 1u ||
        memcmp(name, service, sizeof(service) - 1u) != 0) {
        int n = snprintf(response, sizeof(response), GUEST_QEMUD_PEER_KO_PREFIX
                         "%02x:unknown service", channel);
        if (n <= 0 || (size_t)n >= sizeof(response)) return -EOVERFLOW;
        int rc = guest_qemud_peer_append_control(tty, response);
        if (rc == 0) peer->control_connects++;
        return rc;
    }
    if (peer->boot_properties_connected) {
        int n = snprintf(response, sizeof(response), GUEST_QEMUD_PEER_KO_PREFIX
                         "%02x:service busy", channel);
        if (n <= 0 || (size_t)n >= sizeof(response)) return -EOVERFLOW;
        int rc = guest_qemud_peer_append_control(tty, response);
        if (rc == 0) peer->control_connects++;
        return rc;
    }
    int n = snprintf(response, sizeof(response), GUEST_QEMUD_PEER_OK_PREFIX "%02x", channel);
    if (n <= 0 || (size_t)n >= sizeof(response)) return -EOVERFLOW;
    int rc = guest_qemud_peer_append_control(tty, response);
    if (rc == 0) {
        peer->channel_id = (uint8_t)channel;
        peer->boot_properties_connected = 1u;
        peer->control_connects++;
    }
    return rc;
}

static inline int guest_qemud_peer_handle_control(
        struct guest_qemud_peer_runtime *peer,
        struct guest_goldfish_tty_runtime *tty,
        const uint8_t *payload, size_t length) {
    static const char connect_prefix[] = GUEST_QEMUD_PEER_CONNECT_PREFIX;
    static const char disconnect_prefix[] = GUEST_QEMUD_PEER_DISCONNECT_PREFIX;
    if (length >= sizeof(connect_prefix) - 1u &&
        memcmp(payload, connect_prefix, sizeof(connect_prefix) - 1u) == 0)
        return guest_qemud_peer_parse_connect(peer, tty, payload, length);
    if (length == sizeof(disconnect_prefix) - 1u + 2u &&
        memcmp(payload, disconnect_prefix, sizeof(disconnect_prefix) - 1u) == 0) {
        uint32_t channel = 0;
        if (guest_qemud_peer_parse_hex(payload + sizeof(disconnect_prefix) - 1u,
                                       2u, &channel) != 0 || channel == 0u)
            return -EINVAL;
        if (peer->boot_properties_connected && channel == peer->channel_id) {
            peer->boot_properties_connected = 0u;
            peer->channel_id = 0u;
        }
        peer->control_disconnects++;
        return 0;
    }
    peer->ignored_frames++;
    return 0;
}

static inline int guest_qemud_peer_handle_data(
        struct guest_qemud_peer_runtime *peer,
        struct guest_goldfish_tty_runtime *tty, uint8_t channel,
        const uint8_t *payload, size_t length) {
    if (!peer->boot_properties_connected || channel != peer->channel_id) {
        peer->ignored_frames++;
        return 0;
    }
    size_t offset = 0;
    while (offset + GUEST_QEMUD_PEER_SERVICE_HEADER_BYTES <= length) {
        uint32_t record_length = 0;
        if (guest_qemud_peer_parse_hex(payload + offset,
                GUEST_QEMUD_PEER_SERVICE_HEADER_BYTES, &record_length) != 0) {
            peer->malformed_frames++;
            return 0;
        }
        offset += GUEST_QEMUD_PEER_SERVICE_HEADER_BYTES;
        if (record_length > length - offset) {
            peer->malformed_frames++;
            return 0;
        }
        const uint8_t *command = payload + offset;
        if (record_length == sizeof(GUEST_QEMUD_PEER_LIST_COMMAND) - 1u &&
            memcmp(command, GUEST_QEMUD_PEER_LIST_COMMAND, record_length) == 0) {
            int rc = guest_qemud_peer_send_list(peer, tty, channel);
            if (rc != 0) return rc;
            peer->service_list_requests++;
        } else {
            peer->ignored_frames++;
        }
        offset += record_length;
    }
    if (offset != length) peer->malformed_frames++;
    return 0;
}

static inline int guest_qemud_peer_handle_serial_frame(
        struct guest_qemud_peer_runtime *peer,
        struct guest_goldfish_tty_runtime *tty,
        const uint8_t *frame, size_t frame_length) {
    if (!peer || !tty || !frame || frame_length < GUEST_QEMUD_PEER_CONTROL_HEADER_BYTES)
        return -EINVAL;
    uint32_t channel = 0, payload_length = 0;
    if (guest_qemud_peer_parse_hex(frame, 2u, &channel) != 0 ||
        guest_qemud_peer_parse_hex(frame + 2u, 4u, &payload_length) != 0 ||
        payload_length != frame_length - GUEST_QEMUD_PEER_CONTROL_HEADER_BYTES) {
        peer->malformed_frames++;
        return 0;
    }
    peer->serial_frames_received++;
    const uint8_t *payload = frame + GUEST_QEMUD_PEER_CONTROL_HEADER_BYTES;
    if (channel == GUEST_QEMUD_PEER_CHANNEL_CONTROL)
        return guest_qemud_peer_handle_control(peer, tty, payload, payload_length);
    return guest_qemud_peer_handle_data(peer, tty, (uint8_t)channel,
                                        payload, payload_length);
}

/* Accept arbitrary write chunking from the guest TTY while bounding buffered
 * parser state. This is a peer model only; the guest write result remains a
 * separate syscall decision in the supervisor. */
static inline int guest_qemud_peer_feed_serial(
        struct guest_qemud_peer_runtime *peer,
        struct guest_goldfish_tty_runtime *tty,
        const uint8_t *bytes, size_t length) {
    if (!peer || !tty || (!bytes && length)) return -EINVAL;
    if (length > sizeof(peer->input) - peer->input_length) return -ENOBUFS;
    if (length) memcpy(peer->input + peer->input_length, bytes, length);
    peer->input_length += length;
    while (peer->input_length >= GUEST_QEMUD_PEER_CONTROL_HEADER_BYTES) {
        uint32_t channel = 0, payload_length = 0;
        if (guest_qemud_peer_parse_hex(peer->input, 2u, &channel) != 0 ||
            channel > GUEST_QEMUD_PEER_CHANNEL_MAX ||
            guest_qemud_peer_parse_hex(peer->input + 2u, 4u, &payload_length) != 0 ||
            payload_length > GUEST_QEMUD_PEER_MAX_FRAME_PAYLOAD) {
            peer->malformed_frames++;
            /* Resynchronize only on ASCII hex header bytes; discard one byte. */
            memmove(peer->input, peer->input + 1u, --peer->input_length);
            continue;
        }
        size_t total = GUEST_QEMUD_PEER_CONTROL_HEADER_BYTES + payload_length;
        if (peer->input_length < total) break;
        int rc = guest_qemud_peer_handle_serial_frame(peer, tty, peer->input, total);
        if (rc != 0) return rc;
        peer->input_length -= total;
        if (peer->input_length) memmove(peer->input, peer->input + total,
                                        peer->input_length);
    }
    return 0;
}

#endif
