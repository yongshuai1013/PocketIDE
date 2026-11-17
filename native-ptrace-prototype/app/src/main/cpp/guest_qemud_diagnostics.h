#ifndef GINGERVM_GUEST_QEMUD_DIAGNOSTICS_H
#define GINGERVM_GUEST_QEMUD_DIAGNOSTICS_H

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#define GUEST_QEMUD_DIAG_MAX_RECORDS 96u
#define GUEST_QEMUD_DIAG_RUN_MAX_LINES 256u
#define GUEST_QEMUD_DIAG_FD_SLOTS 12u
#define GUEST_QEMUD_DIAG_PATH_CAP 128u
#define GUEST_QEMUD_DIAG_CMDLINE_CAP 512u
#define GUEST_QEMUD_DIAG_PORT_CAP 32u
#define GUEST_QEMUD_DIAG_STDERR_MAX_CHUNKS 4u
#define GUEST_QEMUD_DIAG_STDERR_MAX_BYTES 96u
#define GUEST_QEMUD_DIAG_STDERR_ESCAPED_CAP (GUEST_QEMUD_DIAG_STDERR_MAX_BYTES * 4u + 1u)

struct guest_qemud_diag_fd {
    int used;
    int fd;
    char path[GUEST_QEMUD_DIAG_PATH_CAP];
};

struct guest_qemud_diag_record {
    uint32_t sequence;
    int syscall_number;
    uint32_t pc;
    uint32_t lr;
    uint32_t args[6];
    int32_t result;
    char path[GUEST_QEMUD_DIAG_PATH_CAP];
    char fd_path[GUEST_QEMUD_DIAG_PATH_CAP];
};

struct guest_qemud_diag_state {
    uint32_t syscall_count;
    uint32_t records_emitted;
    uint32_t records_suppressed;
    int pending;
    int pending_selected;
    uint32_t pending_sequence;
    int pending_syscall_number;
    uint32_t pending_pc;
    uint32_t pending_lr;
    uint32_t pending_args[6];
    char pending_path[GUEST_QEMUD_DIAG_PATH_CAP];
    char pending_fd_path[GUEST_QEMUD_DIAG_PATH_CAP];
    struct guest_qemud_diag_fd fds[GUEST_QEMUD_DIAG_FD_SLOTS];
    int cmdline_fd;
    uint32_t cmdline_open_count;
    uint32_t cmdline_read_calls;
    uint32_t cmdline_read_bytes;
    char cmdline_data[GUEST_QEMUD_DIAG_CMDLINE_CAP];
    size_t cmdline_data_length;
    int cmdline_qemu_enabled;
    int cmdline_qemud_parameter_present;
    int cmdline_observation_logged;
    char cmdline_qemud_port[GUEST_QEMUD_DIAG_PORT_CAP];
    uint32_t tty_open_attempts;
    int tty_open_result;
    char tty_open_path[GUEST_QEMUD_DIAG_PATH_CAP];
    int exit_request_seen;
    int exit_request_syscall;
    uint32_t exit_request_status;
    uint32_t exit_request_pc;
    uint32_t exit_request_lr;
    int stderr_capture_armed;
    uint32_t stderr_preview_chunks;
};

struct guest_qemud_diag_run_budget {
    uint32_t emitted;
    uint32_t suppressed;
};

static inline int guest_qemud_diag_run_budget_take(
        struct guest_qemud_diag_run_budget *budget) {
    if (!budget) return 0;
    if (budget->emitted >= GUEST_QEMUD_DIAG_RUN_MAX_LINES) {
        if (budget->suppressed < UINT32_MAX) budget->suppressed++;
        return 0;
    }
    budget->emitted++;
    return 1;
}

static inline void guest_qemud_diag_state_init(struct guest_qemud_diag_state *state) {
    if (!state) return;
    memset(state, 0, sizeof(*state));
    state->cmdline_fd = -1;
    state->tty_open_result = 0;
}

static inline int guest_qemud_diag_syscall_selected(int number) {
    switch (number) {
        case 1:   /* exit */
        case 3:   /* read */
        case 4:   /* write */
        case 5:   /* open */
        case 6:   /* close */
        case 11:  /* execve */
        case 14:  /* mknod */
        case 33:  /* access */
        case 41:  /* dup */
        case 54:  /* ioctl */
        case 55:  /* fcntl */
        case 63:  /* dup2 */
        case 221: /* fcntl64 */
        case 85:  /* readlink */
        case 114: /* wait4 */
        case 142: /* select */
        case 168: /* poll */
        case 195: /* stat64 */
        case 197: /* fstat64 */
        case 248: /* exit_group */
        case 250: /* epoll_create */
        case 251: /* epoll_ctl */
        case 252: /* epoll_wait */
        case 281: /* socket */
        case 282: /* bind */
        case 283: /* connect */
        case 284: /* listen */
        case 285: /* accept */
        case 288: /* socketpair */
        case 290: /* sendto */
        case 292: /* recvfrom */
        case 297: /* recvmsg */
        case 322: /* openat */
        case 327: /* fstatat64 */
            return 1;
        default:
            return 0;
    }
}

static inline void guest_qemud_diag_copy(char *output, size_t capacity,
                                         const char *input) {
    if (!output || capacity == 0) return;
    if (!input) input = "";
    size_t length = strlen(input);
    if (length >= capacity) length = capacity - 1u;
    memcpy(output, input, length);
    output[length] = '\0';
}

static inline void guest_qemud_diag_begin(struct guest_qemud_diag_state *state,
        int syscall_number, const uint32_t args[6], uint32_t pc, uint32_t lr,
        const char *path, const char *fd_path) {
    if (!state) return;
    if (state->syscall_count < UINT32_MAX) state->syscall_count++;
    state->pending = 1;
    state->pending_selected = guest_qemud_diag_syscall_selected(syscall_number);
    state->pending_sequence = state->syscall_count;
    state->pending_syscall_number = syscall_number;
    state->pending_pc = pc;
    state->pending_lr = lr;
    if (args) memcpy(state->pending_args, args, sizeof(state->pending_args));
    else memset(state->pending_args, 0, sizeof(state->pending_args));
    guest_qemud_diag_copy(state->pending_path, sizeof(state->pending_path), path);
    guest_qemud_diag_copy(state->pending_fd_path, sizeof(state->pending_fd_path), fd_path);
    if (syscall_number == 1 || syscall_number == 248) {
        state->exit_request_seen = 1;
        state->exit_request_syscall = syscall_number;
        state->exit_request_status = state->pending_args[0];
        state->exit_request_pc = pc;
        state->exit_request_lr = lr;
    }
}

/* Returns 1 for a record, 0 for a successful unselected call, and -1 once the
 * fixed per-process output budget has been exhausted. Negative results are
 * retained even for otherwise unselected syscalls, so unexpected failures do
 * not disappear behind the filtered success stream. */
static inline int guest_qemud_diag_finish(struct guest_qemud_diag_state *state,
        int32_t result, struct guest_qemud_diag_record *record) {
    if (!state || !state->pending) return 0;
    if (state->pending_syscall_number == 250 && result < 0)
        state->stderr_capture_armed = 1;
    int retain = state->pending_selected || result < 0;
    if (!retain) {
        state->pending = 0;
        return 0;
    }
    if (state->records_emitted >= GUEST_QEMUD_DIAG_MAX_RECORDS) {
        state->records_suppressed++;
        state->pending = 0;
        return -1;
    }
    if (record) {
        memset(record, 0, sizeof(*record));
        record->sequence = state->pending_sequence;
        record->syscall_number = state->pending_syscall_number;
        record->pc = state->pending_pc;
        record->lr = state->pending_lr;
        memcpy(record->args, state->pending_args, sizeof(record->args));
        record->result = result;
        guest_qemud_diag_copy(record->path, sizeof(record->path), state->pending_path);
        guest_qemud_diag_copy(record->fd_path, sizeof(record->fd_path),
                              state->pending_fd_path);
    }
    state->records_emitted++;
    state->pending = 0;
    return 1;
}

static inline int guest_qemud_diag_claim_stderr_preview(
        struct guest_qemud_diag_state *state, int fd, int32_t result,
        uint32_t requested, size_t *capture_length) {
    /* The fixed cap counts attempts, including a failed ptrace read, so a
     * damaged guest pointer cannot cause unbounded repeated diagnostics. */
    if (capture_length) *capture_length = 0;
    if (!state || !capture_length || !state->stderr_capture_armed ||
        fd != 2 || result <= 0 || requested == 0 ||
        state->stderr_preview_chunks >= GUEST_QEMUD_DIAG_STDERR_MAX_CHUNKS)
        return 0;
    size_t amount = (size_t)result;
    if (amount > requested) amount = requested;
    if (amount > GUEST_QEMUD_DIAG_STDERR_MAX_BYTES)
        amount = GUEST_QEMUD_DIAG_STDERR_MAX_BYTES;
    if (amount == 0) return 0;
    state->stderr_preview_chunks++;
    *capture_length = amount;
    return 1;
}

static inline int guest_qemud_diag_guest_range_valid(uint32_t address,
        size_t length) {
    const uint64_t address_space_end = (uint64_t)UINT32_MAX + 1u;
    return (uint64_t)length <= address_space_end - (uint64_t)address;
}

/* Escapes an explicit byte span, including embedded NULs, before it is placed
 * inside a line-oriented log. The output never contains raw control/high bytes. */
static inline int guest_qemud_diag_escape_bytes(const unsigned char *input,
        size_t input_length, char *output, size_t capacity) {
    static const char hex[] = "0123456789abcdef";
    size_t used = 0;
    int truncated = 0;
    if (!output || capacity == 0) return 1;
    output[0] = '\0';
    if (!input && input_length) return 1;
    for (size_t i = 0; i < input_length; ++i) {
        unsigned char c = input[i];
        char piece[4];
        size_t length;
        if (c >= 0x20 && c <= 0x7e && c != '\\' && c != '"') {
            piece[0] = (char)c;
            length = 1;
        } else if (c == '\\' || c == '"') {
            piece[0] = '\\';
            piece[1] = (char)c;
            length = 2;
        } else {
            piece[0] = '\\';
            piece[1] = 'x';
            piece[2] = hex[c >> 4];
            piece[3] = hex[c & 0x0f];
            length = 4;
        }
        if (length > capacity - 1u - used) {
            truncated = 1;
            break;
        }
        memcpy(output + used, piece, length);
        used += length;
    }
    if (truncated) {
        if (capacity >= 4u) {
            if (used > capacity - 4u) used = capacity - 4u;
            memcpy(output + used, "...", 3u);
            used += 3u;
        } else {
            used = 0;
        }
    }
    output[used] = '\0';
    return truncated;
}

static inline void guest_qemud_diag_track_fd(struct guest_qemud_diag_state *state,
        int fd, const char *path) {
    if (!state || fd < 0 || !path || !path[0]) return;
    size_t slot = GUEST_QEMUD_DIAG_FD_SLOTS;
    for (size_t i = 0; i < GUEST_QEMUD_DIAG_FD_SLOTS; ++i) {
        if (state->fds[i].used && state->fds[i].fd == fd) { slot = i; break; }
        if (!state->fds[i].used && slot == GUEST_QEMUD_DIAG_FD_SLOTS) slot = i;
    }
    if (slot == GUEST_QEMUD_DIAG_FD_SLOTS) return;
    state->fds[slot].used = 1;
    state->fds[slot].fd = fd;
    guest_qemud_diag_copy(state->fds[slot].path, sizeof(state->fds[slot].path), path);
}

static inline const char *guest_qemud_diag_fd_path(
        const struct guest_qemud_diag_state *state, int fd) {
    if (!state || fd < 0) return NULL;
    for (size_t i = 0; i < GUEST_QEMUD_DIAG_FD_SLOTS; ++i)
        if (state->fds[i].used && state->fds[i].fd == fd) return state->fds[i].path;
    return NULL;
}

static inline void guest_qemud_diag_untrack_fd(struct guest_qemud_diag_state *state,
        int fd) {
    if (!state || fd < 0) return;
    for (size_t i = 0; i < GUEST_QEMUD_DIAG_FD_SLOTS; ++i) {
        if (state->fds[i].used && state->fds[i].fd == fd) {
            memset(&state->fds[i], 0, sizeof(state->fds[i]));
            if (state->cmdline_fd == fd) state->cmdline_fd = -1;
            return;
        }
    }
}

static inline void guest_qemud_diag_dup_fd(struct guest_qemud_diag_state *state,
        int old_fd, int new_fd) {
    if (!state || old_fd < 0 || new_fd < 0 || old_fd == new_fd) return;
    const char *path = guest_qemud_diag_fd_path(state, old_fd);
    if (path) guest_qemud_diag_track_fd(state, new_fd, path);
    else guest_qemud_diag_untrack_fd(state, new_fd);
}

static inline int guest_qemud_diag_claim_cmdline_observation(
        struct guest_qemud_diag_state *state) {
    if (!state || state->cmdline_observation_logged) return 0;
    state->cmdline_observation_logged = 1;
    return 1;
}

static inline const char *guest_qemud_diag_safe_port_label(
        const struct guest_qemud_diag_state *state) {
    if (!state || !state->cmdline_qemud_parameter_present) return "<missing>";
    if (strcmp(state->cmdline_qemud_port, "ttyS1") == 0) return "ttyS1";
    return "<noncanonical-redacted>";
}

static inline int guest_qemud_diag_token_value(const char *cmdline,
        const char *key, char *value, size_t value_capacity) {
    if (!value || value_capacity == 0) return 0;
    value[0] = '\0';
    if (!cmdline || !key || !key[0]) return 0;
    size_t key_length = strlen(key);
    const char *cursor = cmdline;
    while (*cursor) {
        while (*cursor == ' ' || *cursor == '\t' || *cursor == '\n' || *cursor == '\r') ++cursor;
        if (!*cursor) break;
        const char *end = cursor;
        while (*end && *end != ' ' && *end != '\t' && *end != '\n' && *end != '\r') ++end;
        const char *equal = memchr(cursor, '=', (size_t)(end - cursor));
        if (equal && (size_t)(equal - cursor) == key_length &&
            memcmp(cursor, key, key_length) == 0) {
            size_t length = (size_t)(end - equal - 1);
            if (length >= value_capacity) length = value_capacity - 1u;
            memcpy(value, equal + 1, length);
            value[length] = '\0';
            return 1;
        }
        cursor = end;
    }
    return 0;
}

static inline int guest_qemud_diag_is_tty_s_path(const char *path) {
    static const char prefix[] = "/dev/ttyS";
    if (!path || strncmp(path, prefix, sizeof(prefix) - 1u) != 0) return 0;
    const char *suffix = path + sizeof(prefix) - 1u;
    if (*suffix < '0' || *suffix > '9') return 0;
    do { ++suffix; } while (*suffix >= '0' && *suffix <= '9');
    return *suffix == '\0';
}

static inline int guest_qemud_diag_is_selected_tty_path(
        const struct guest_qemud_diag_state *state, const char *path) {
    return state && state->cmdline_qemud_parameter_present &&
        strcmp(state->cmdline_qemud_port, "ttyS1") == 0 && path &&
        strcmp(path, "/dev/ttyS1") == 0;
}

static inline void guest_qemud_diag_note_open(struct guest_qemud_diag_state *state,
        const char *path, int result) {
    if (!state || !path || !path[0]) return;
    if (strcmp(path, "/proc/cmdline") == 0) {
        state->cmdline_open_count++;
        if (result >= 0) {
            state->cmdline_fd = result;
            guest_qemud_diag_track_fd(state, result, path);
        }
    }
    if (guest_qemud_diag_is_tty_s_path(path)) {
        state->tty_open_attempts++;
        state->tty_open_result = result;
        guest_qemud_diag_copy(state->tty_open_path, sizeof(state->tty_open_path), path);
        if (result < 0 && guest_qemud_diag_is_selected_tty_path(state, path))
            state->stderr_capture_armed = 1;
        if (result >= 0) guest_qemud_diag_track_fd(state, result, path);
    } else if (result >= 0 && strncmp(path, "/dev/log/", 9u) == 0) {
        guest_qemud_diag_track_fd(state, result, path);
    }
}

static inline void guest_qemud_diag_note_cmdline_read(
        struct guest_qemud_diag_state *state, const void *bytes, size_t length) {
    if (!state || (!bytes && length)) return;
    state->cmdline_read_calls++;
    if (length > UINT32_MAX - state->cmdline_read_bytes)
        state->cmdline_read_bytes = UINT32_MAX;
    else state->cmdline_read_bytes += (uint32_t)length;
    if (length > GUEST_QEMUD_DIAG_CMDLINE_CAP - 1u - state->cmdline_data_length)
        length = GUEST_QEMUD_DIAG_CMDLINE_CAP - 1u - state->cmdline_data_length;
    if (length) {
        memcpy(state->cmdline_data + state->cmdline_data_length, bytes, length);
        state->cmdline_data_length += length;
    }
    state->cmdline_data[state->cmdline_data_length] = '\0';
    char value[GUEST_QEMUD_DIAG_PORT_CAP];
    state->cmdline_qemu_enabled = guest_qemud_diag_token_value(
        state->cmdline_data, "qemu", value, sizeof(value)) && strcmp(value, "1") == 0;
    state->cmdline_qemud_parameter_present = guest_qemud_diag_token_value(
        state->cmdline_data, "android.qemud", state->cmdline_qemud_port,
        sizeof(state->cmdline_qemud_port));
}

#endif
