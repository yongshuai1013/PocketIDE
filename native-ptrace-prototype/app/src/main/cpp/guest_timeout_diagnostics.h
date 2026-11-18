#ifndef GINGERVM_GUEST_TIMEOUT_DIAGNOSTICS_H
#define GINGERVM_GUEST_TIMEOUT_DIAGNOSTICS_H

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include "guest_diagnostics.h"
#include "guest_sigsys_context.h"
#include "guest_setup_property_trace.h"

#define GUEST_TIMEOUT_TRACE_PATH_CAPACITY 256u
#define GUEST_TIMEOUT_TRACE_ROLE_COUNT 3u

enum guest_timeout_trace_role {
    GUEST_TIMEOUT_TRACE_SETUP_SHELL = 0,
    GUEST_TIMEOUT_TRACE_SETPROP = 1,
    GUEST_TIMEOUT_TRACE_APP_PROCESS = 2,
};

enum guest_timeout_trace_result_state {
    GUEST_TIMEOUT_TRACE_RESULT_NONE = 0,
    GUEST_TIMEOUT_TRACE_RESULT_PENDING,
    GUEST_TIMEOUT_TRACE_RESULT_PARKED,
    GUEST_TIMEOUT_TRACE_RESULT_COMPLETE,
    GUEST_TIMEOUT_TRACE_RESULT_EXEC_COMMITTED,
};

enum guest_timeout_trace_terminal_state {
    GUEST_TIMEOUT_TRACE_TERMINAL_LIVE = 0,
    GUEST_TIMEOUT_TRACE_TERMINAL_EXITED,
    GUEST_TIMEOUT_TRACE_TERMINAL_SIGNALED,
};

enum guest_timeout_trace_pc_source {
    GUEST_TIMEOUT_TRACE_PC_NONE = 0,
    GUEST_TIMEOUT_TRACE_PC_SYSCALL_ENTRY,
    GUEST_TIMEOUT_TRACE_PC_EXEC_STOP,
};

struct guest_timeout_trace_snapshot {
    int valid;
    enum guest_timeout_trace_role role;
    pid_t host_pid;
    pid_t guest_pid;
    pid_t guest_parent_pid;
    char executable[GUEST_TIMEOUT_TRACE_PATH_CAPACITY];
    char script[GUEST_TIMEOUT_TRACE_PATH_CAPACITY];
    char property_key[GUEST_SETUP_PROPERTY_KEY_CAPACITY];
    int has_property_key;
    int syscall_valid;
    int syscall_number;
    uint32_t pc;
    int pc_valid;
    enum guest_timeout_trace_pc_source pc_source;
    enum guest_timeout_trace_result_state result_state;
    int32_t syscall_result;
    int result_valid;
    int last_signal;
    enum guest_timeout_trace_terminal_state terminal_state;
    int exit_code;
    int exit_signal;
    int mapping_result;
    int mapping_valid;
    struct guest_diag_proc_map mapping;
};

struct guest_timeout_diagnostics {
    struct guest_timeout_trace_snapshot roles[GUEST_TIMEOUT_TRACE_ROLE_COUNT];
};

static inline const char *guest_timeout_trace_role_name(
        enum guest_timeout_trace_role role) {
    switch (role) {
        case GUEST_TIMEOUT_TRACE_SETUP_SHELL: return "setup-shell";
        case GUEST_TIMEOUT_TRACE_SETPROP: return "setprop";
        case GUEST_TIMEOUT_TRACE_APP_PROCESS: return "app_process";
        default: return "unknown";
    }
}

static inline void guest_timeout_diagnostics_init(
        struct guest_timeout_diagnostics *diagnostics) {
    if (diagnostics) memset(diagnostics, 0, sizeof(*diagnostics));
}

static inline struct guest_timeout_trace_snapshot *
guest_timeout_trace_touch(struct guest_timeout_diagnostics *diagnostics,
        enum guest_timeout_trace_role role, pid_t host_pid, pid_t guest_pid,
        pid_t guest_parent_pid, const char *executable, const char *script,
        const char *property_key) {
    if (!diagnostics || role < GUEST_TIMEOUT_TRACE_SETUP_SHELL ||
        role >= GUEST_TIMEOUT_TRACE_ROLE_COUNT || host_pid <= 0)
        return NULL;
    struct guest_timeout_trace_snapshot *snapshot = &diagnostics->roles[role];
    if (!snapshot->valid || snapshot->host_pid != host_pid) {
        memset(snapshot, 0, sizeof(*snapshot));
        snapshot->valid = 1;
        snapshot->role = role;
        snapshot->host_pid = host_pid;
        snapshot->guest_pid = guest_pid;
        snapshot->guest_parent_pid = guest_parent_pid;
        snapshot->syscall_number = -1;
        snapshot->mapping_result = -1;
    }
    snapshot->guest_pid = guest_pid;
    snapshot->guest_parent_pid = guest_parent_pid;
    if (executable)
        snprintf(snapshot->executable, sizeof(snapshot->executable), "%s", executable);
    if (script)
        snprintf(snapshot->script, sizeof(snapshot->script), "%s", script);
    if (property_key && property_key[0]) {
        snprintf(snapshot->property_key, sizeof(snapshot->property_key), "%s",
                 property_key);
        snapshot->has_property_key = 1;
    }
    return snapshot;
}

static inline void guest_timeout_diagnostics_note_exec(
        struct guest_timeout_diagnostics *diagnostics,
        enum guest_timeout_trace_role role, pid_t host_pid, pid_t guest_pid,
        pid_t guest_parent_pid, const char *executable, const char *script,
        const char *property_key) {
    struct guest_timeout_trace_snapshot *snapshot = guest_timeout_trace_touch(
        diagnostics, role, host_pid, guest_pid, guest_parent_pid, executable,
        script, property_key);
    if (!snapshot) return;
    snapshot->syscall_valid = 1;
    snapshot->syscall_number = 11; /* execve committed; it does not return. */
    snapshot->pc = 0;
    snapshot->pc_valid = 0;
    snapshot->pc_source = GUEST_TIMEOUT_TRACE_PC_NONE;
    snapshot->result_state = GUEST_TIMEOUT_TRACE_RESULT_EXEC_COMMITTED;
    snapshot->result_valid = 0;
    snapshot->mapping_valid = 0;
    snapshot->mapping_result = -1;
}

static inline void guest_timeout_diagnostics_note_syscall(
        struct guest_timeout_diagnostics *diagnostics,
        enum guest_timeout_trace_role role, pid_t host_pid, pid_t guest_pid,
        pid_t guest_parent_pid, const char *executable, const char *script,
        const char *property_key, int syscall_number, uint32_t pc) {
    struct guest_timeout_trace_snapshot *snapshot = guest_timeout_trace_touch(
        diagnostics, role, host_pid, guest_pid, guest_parent_pid, executable,
        script, property_key);
    if (!snapshot) return;
    snapshot->syscall_valid = 1;
    snapshot->syscall_number = syscall_number;
    snapshot->pc = pc;
    snapshot->pc_valid = 1;
    snapshot->pc_source = GUEST_TIMEOUT_TRACE_PC_SYSCALL_ENTRY;
    snapshot->result_state = GUEST_TIMEOUT_TRACE_RESULT_PENDING;
    snapshot->result_valid = 0;
    snapshot->terminal_state = GUEST_TIMEOUT_TRACE_TERMINAL_LIVE;
    if (snapshot->mapping_valid &&
        guest_diag_proc_map_contains(&snapshot->mapping, pc))
        return;
    snapshot->mapping_result = guest_diag_find_proc_map(host_pid, pc,
                                                         &snapshot->mapping);
    snapshot->mapping_valid = snapshot->mapping_result == 0;
}

static inline void guest_timeout_diagnostics_note_exec_stop_pc(
        struct guest_timeout_diagnostics *diagnostics,
        enum guest_timeout_trace_role role, pid_t host_pid, uint32_t pc) {
    if (!diagnostics || role < GUEST_TIMEOUT_TRACE_SETUP_SHELL ||
        role >= GUEST_TIMEOUT_TRACE_ROLE_COUNT) return;
    struct guest_timeout_trace_snapshot *snapshot = &diagnostics->roles[role];
    if (!snapshot->valid || snapshot->host_pid != host_pid) return;
    snapshot->pc = pc;
    snapshot->pc_valid = 1;
    snapshot->pc_source = GUEST_TIMEOUT_TRACE_PC_EXEC_STOP;
    if (snapshot->mapping_valid &&
        guest_diag_proc_map_contains(&snapshot->mapping, pc))
        return;
    snapshot->mapping_result = guest_diag_find_proc_map(host_pid, pc,
                                                         &snapshot->mapping);
    snapshot->mapping_valid = snapshot->mapping_result == 0;
}

static inline void guest_timeout_diagnostics_note_result(
        struct guest_timeout_diagnostics *diagnostics,
        enum guest_timeout_trace_role role, pid_t host_pid, int32_t result) {
    if (!diagnostics || role < GUEST_TIMEOUT_TRACE_SETUP_SHELL ||
        role >= GUEST_TIMEOUT_TRACE_ROLE_COUNT) return;
    struct guest_timeout_trace_snapshot *snapshot = &diagnostics->roles[role];
    if (!snapshot->valid || snapshot->host_pid != host_pid) return;
    snapshot->syscall_result = result;
    snapshot->result_valid = 1;
    snapshot->result_state = GUEST_TIMEOUT_TRACE_RESULT_COMPLETE;
}

static inline void guest_timeout_diagnostics_note_parked(
        struct guest_timeout_diagnostics *diagnostics,
        enum guest_timeout_trace_role role, pid_t host_pid) {
    if (!diagnostics || role < GUEST_TIMEOUT_TRACE_SETUP_SHELL ||
        role >= GUEST_TIMEOUT_TRACE_ROLE_COUNT) return;
    struct guest_timeout_trace_snapshot *snapshot = &diagnostics->roles[role];
    if (!snapshot->valid || snapshot->host_pid != host_pid) return;
    snapshot->result_valid = 0;
    snapshot->result_state = GUEST_TIMEOUT_TRACE_RESULT_PARKED;
}

static inline void guest_timeout_diagnostics_note_signal(
        struct guest_timeout_diagnostics *diagnostics,
        enum guest_timeout_trace_role role, pid_t host_pid, int signal_number) {
    if (!diagnostics || role < GUEST_TIMEOUT_TRACE_SETUP_SHELL ||
        role >= GUEST_TIMEOUT_TRACE_ROLE_COUNT) return;
    struct guest_timeout_trace_snapshot *snapshot = &diagnostics->roles[role];
    if (!snapshot->valid || snapshot->host_pid != host_pid) return;
    snapshot->last_signal = signal_number;
}

static inline void guest_timeout_diagnostics_note_exit(
        struct guest_timeout_diagnostics *diagnostics,
        enum guest_timeout_trace_role role, pid_t host_pid, int exit_code) {
    if (!diagnostics || role < GUEST_TIMEOUT_TRACE_SETUP_SHELL ||
        role >= GUEST_TIMEOUT_TRACE_ROLE_COUNT) return;
    struct guest_timeout_trace_snapshot *snapshot = &diagnostics->roles[role];
    if (!snapshot->valid || snapshot->host_pid != host_pid) return;
    snapshot->terminal_state = GUEST_TIMEOUT_TRACE_TERMINAL_EXITED;
    snapshot->exit_code = exit_code;
    snapshot->exit_signal = 0;
}

static inline void guest_timeout_diagnostics_note_signal_exit(
        struct guest_timeout_diagnostics *diagnostics,
        enum guest_timeout_trace_role role, pid_t host_pid, int signal_number) {
    if (!diagnostics || role < GUEST_TIMEOUT_TRACE_SETUP_SHELL ||
        role >= GUEST_TIMEOUT_TRACE_ROLE_COUNT) return;
    struct guest_timeout_trace_snapshot *snapshot = &diagnostics->roles[role];
    if (!snapshot->valid || snapshot->host_pid != host_pid) return;
    snapshot->terminal_state = GUEST_TIMEOUT_TRACE_TERMINAL_SIGNALED;
    snapshot->exit_signal = signal_number;
}

static inline const char *guest_timeout_trace_result_state_name(
        enum guest_timeout_trace_result_state state) {
    switch (state) {
        case GUEST_TIMEOUT_TRACE_RESULT_PENDING: return "awaiting-return";
        case GUEST_TIMEOUT_TRACE_RESULT_PARKED: return "parked-no-return";
        case GUEST_TIMEOUT_TRACE_RESULT_COMPLETE: return "complete";
        case GUEST_TIMEOUT_TRACE_RESULT_EXEC_COMMITTED: return "exec-committed";
        case GUEST_TIMEOUT_TRACE_RESULT_NONE:
        default: return "unavailable";
    }
}

static inline const char *guest_timeout_trace_pc_source_name(
        enum guest_timeout_trace_pc_source source) {
    switch (source) {
        case GUEST_TIMEOUT_TRACE_PC_SYSCALL_ENTRY: return "syscall-entry";
        case GUEST_TIMEOUT_TRACE_PC_EXEC_STOP: return "exec-stop";
        case GUEST_TIMEOUT_TRACE_PC_NONE:
        default: return "unavailable";
    }
}

static inline void guest_timeout_diagnostics_log(
        const struct guest_timeout_diagnostics *diagnostics,
        const char *timeout_reason, long elapsed_ms, unsigned long stops) {
    if (!diagnostics) return;
    printf("GUEST TIMEOUT TRACE SNAPSHOTS: reason=%s elapsed-ms=%ld syscall-stops=%lu; read-only supervisor snapshots, no guest state changed\n",
           timeout_reason ? timeout_reason : "unspecified", elapsed_ms, stops);
    for (size_t i = 0; i < GUEST_TIMEOUT_TRACE_ROLE_COUNT; ++i) {
        const struct guest_timeout_trace_snapshot *snapshot = &diagnostics->roles[i];
        if (!snapshot->valid) {
            printf("GUEST TIMEOUT TRACEE: role=%s observed=0\n",
                   guest_timeout_trace_role_name((enum guest_timeout_trace_role)i));
            continue;
        }
        char executable[GUEST_TIMEOUT_TRACE_PATH_CAPACITY * 4u];
        char script[GUEST_TIMEOUT_TRACE_PATH_CAPACITY * 4u];
        char mapping_path[GUEST_DIAG_PROC_MAP_PATH_CAPACITY * 4u];
        char property_key[GUEST_SETUP_PROPERTY_KEY_CAPACITY * 4u];
        int executable_truncated = guest_diag_escape(snapshot->executable,
            executable, sizeof(executable));
        int script_truncated = guest_diag_escape(snapshot->script,
            script, sizeof(script));
        int mapping_truncated = guest_diag_escape(snapshot->mapping.path,
            mapping_path, sizeof(mapping_path));
        int key_truncated = guest_diag_escape(snapshot->property_key,
            property_key, sizeof(property_key));
        int error_number = snapshot->result_valid && snapshot->syscall_result < 0 &&
            snapshot->syscall_result >= -4095 ? -snapshot->syscall_result : 0;
        const char *terminal = snapshot->terminal_state == GUEST_TIMEOUT_TRACE_TERMINAL_EXITED
            ? "exited" : snapshot->terminal_state == GUEST_TIMEOUT_TRACE_TERMINAL_SIGNALED
                ? "signaled" : "live-at-timeout";
        printf("GUEST TIMEOUT TRACEE: role=%s observed=1 host-pid=%d guest-pid=%d parent-guest-pid=%d terminal=%s executable=\"%s\" script=\"%s\" last-observed-pc-source=%s last-observed-pc=%s0x%08x mapping-status=%d map=0x%llx-0x%llx perms=%s file-offset=0x%llx mapped-file=\"%s\" syscall=%d(%s) result-state=%s result=%s%d errno=%d(%s) last-signal=%d exit-code=%d exit-signal=%d property-key=\"%s\" truncated=%d,%d,%d,%d\n",
               guest_timeout_trace_role_name(snapshot->role), snapshot->host_pid,
               snapshot->guest_pid, snapshot->guest_parent_pid, terminal,
               executable, script,
               guest_timeout_trace_pc_source_name(snapshot->pc_source),
               snapshot->pc_valid ? "" : "unavailable/",
               snapshot->pc, snapshot->mapping_valid ? 0 : snapshot->mapping_result,
               (unsigned long long)snapshot->mapping.start,
               (unsigned long long)snapshot->mapping.end,
               snapshot->mapping_valid ? snapshot->mapping.permissions : "----",
               (unsigned long long)(snapshot->mapping_valid && snapshot->pc_valid
                   ? guest_diag_proc_map_file_offset(&snapshot->mapping, snapshot->pc)
                   : UINT64_MAX),
               snapshot->mapping_valid ? mapping_path : "<unresolved>",
               snapshot->syscall_valid ? snapshot->syscall_number : -1,
               snapshot->syscall_valid
                   ? guest_diag_syscall_name(snapshot->syscall_number) : "none",
               guest_timeout_trace_result_state_name(snapshot->result_state),
               snapshot->result_valid ? "" : "unavailable/",
               snapshot->result_valid ? snapshot->syscall_result : 0,
               error_number, error_number ? guest_diag_errno_name(error_number) : "none",
               snapshot->last_signal,
               snapshot->terminal_state == GUEST_TIMEOUT_TRACE_TERMINAL_EXITED
                   ? snapshot->exit_code : -1,
               snapshot->terminal_state == GUEST_TIMEOUT_TRACE_TERMINAL_SIGNALED
                   ? snapshot->exit_signal : 0,
               snapshot->has_property_key ? property_key : "<none>",
               executable_truncated, script_truncated,
               mapping_truncated || snapshot->mapping.path_truncated, key_truncated);
    }
}

#endif
