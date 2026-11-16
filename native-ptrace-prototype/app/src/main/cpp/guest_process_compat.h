#ifndef GINGERVM_GUEST_PROCESS_COMPAT_H
#define GINGERVM_GUEST_PROCESS_COMPAT_H

#include <errno.h>
#include <stdint.h>

#define GUEST_RLIMIT_NICE 13u
#define GUEST_RLIMIT_COUNT 16u
#define GUEST_RLIM_INFINITY UINT32_MAX
#define GUEST_IOPRIO_WHO_PROCESS 1u
#define GUEST_IOPRIO_WHO_PGRP 2u
#define GUEST_IOPRIO_WHO_USER 3u
#define GUEST_IOPRIO_CLASS_SHIFT 13u
#define GUEST_IOPRIO_CLASS_NONE 0u
#define GUEST_IOPRIO_CLASS_RT 1u
#define GUEST_IOPRIO_CLASS_BE 2u
#define GUEST_IOPRIO_CLASS_IDLE 3u
#define GUEST_IOPRIO_DATA_MASK 0x1fffu
#define GUEST_IOPRIO_CLASS_DATA(class_value, data_value) \
    (((uint32_t)(class_value) << GUEST_IOPRIO_CLASS_SHIFT) | (uint32_t)(data_value))

struct guest_arm32_timezone {
    int32_t minutes_west;
    int32_t dst_time;
};

struct guest_arm32_rlimit {
    uint32_t current;
    uint32_t maximum;
};

struct guest_process_compat_state {
    /* Linux 2.6.29 ARM INIT_RLIMITS sets RLIMIT_NICE to {0,0}. */
    struct guest_arm32_rlimit nice_limit;
    uint32_t ioprio;
};

static inline void guest_process_compat_init(struct guest_process_compat_state *state) {
    if (!state) return;
    state->nice_limit.current = 0u;
    state->nice_limit.maximum = 0u;
    state->ioprio = GUEST_IOPRIO_CLASS_DATA(GUEST_IOPRIO_CLASS_NONE, 0u);
}

static inline int guest_process_setrlimit(struct guest_process_compat_state *state,
                                          uint32_t resource,
                                          struct guest_arm32_rlimit requested,
                                          uint32_t guest_euid) {
    if (!state) return -EINVAL;
    if (resource >= GUEST_RLIMIT_COUNT) return -EINVAL;
    if (resource != GUEST_RLIMIT_NICE) return -EOPNOTSUPP;
    if (requested.current > requested.maximum) return -EINVAL;
    if (requested.maximum > state->nice_limit.maximum && guest_euid != 0u)
        return -EPERM;
    state->nice_limit = requested;
    return 0;
}

static inline int guest_process_ioprio_value_valid(uint32_t value) {
    uint32_t class_value = value >> GUEST_IOPRIO_CLASS_SHIFT;
    uint32_t data = value & GUEST_IOPRIO_DATA_MASK;
    if (class_value > GUEST_IOPRIO_CLASS_IDLE) return 0;
    if (class_value == GUEST_IOPRIO_CLASS_NONE) return data == 0u;
    if (class_value == GUEST_IOPRIO_CLASS_RT || class_value == GUEST_IOPRIO_CLASS_BE)
        return data <= 7u;
    return class_value == GUEST_IOPRIO_CLASS_IDLE && data == 0u;
}

/* Process-only subset used by API10 init: no host PID, scheduler, or ioprio call. */
static inline int guest_process_ioprio_set(struct guest_process_compat_state *target_state,
                                           uint32_t caller_euid,
                                           uint32_t target_ruid,
                                           uint32_t target_euid,
                                           uint32_t which,
                                           int32_t who,
                                           int target_exists,
                                           uint32_t priority) {
    if (!target_state || who < 0) return -EINVAL;
    if (!guest_process_ioprio_value_valid(priority)) return -EINVAL;
    if (which != GUEST_IOPRIO_WHO_PROCESS) {
        if (which == GUEST_IOPRIO_WHO_PGRP || which == GUEST_IOPRIO_WHO_USER)
            return -EOPNOTSUPP;
        return -EINVAL;
    }
    if (!target_exists) return -ESRCH;
    if (caller_euid != 0u && caller_euid != target_ruid && caller_euid != target_euid)
        return -EPERM;
    if ((priority >> GUEST_IOPRIO_CLASS_SHIFT) == GUEST_IOPRIO_CLASS_RT &&
        caller_euid != 0u) return -EPERM;
    target_state->ioprio = priority;
    return 0;
}

static inline int guest_process_group_get(int32_t requested_pid,
                                          uint32_t caller_guest_pid,
                                          uint32_t caller_guest_pgid,
                                          uint32_t target_guest_pgid,
                                          int target_exists) {
    if (requested_pid < 0) return -EINVAL;
    if (requested_pid == 0 || (uint32_t)requested_pid == caller_guest_pid)
        return (int)caller_guest_pgid;
    if (!target_exists) return -ESRCH;
    return (int)target_guest_pgid;
}

/* Conservative setpgid model: self or a direct child only, and only a new
 * group whose ID is that target's guest PID. No host PGID is consulted. */
static inline int guest_process_group_set(uint32_t caller_guest_pid,
                                          uint32_t target_guest_pid,
                                          uint32_t target_parent_guest_pid,
                                          int target_alive,
                                          int32_t requested_pid,
                                          int32_t requested_pgid,
                                          uint32_t current_guest_pgid,
                                          uint32_t *new_guest_pgid) {
    if (!new_guest_pgid || caller_guest_pid == 0) return -EINVAL;
    if (requested_pid < 0 || requested_pgid < 0) return -EINVAL;
    uint32_t selected_pid = requested_pid == 0 ? caller_guest_pid : (uint32_t)requested_pid;
    if (!target_alive || selected_pid != target_guest_pid) return -ESRCH;
    if (target_guest_pid != caller_guest_pid && target_parent_guest_pid != caller_guest_pid)
        return -EPERM;
    uint32_t selected_pgid = requested_pgid == 0 ? target_guest_pid : (uint32_t)requested_pgid;
    if (selected_pgid != target_guest_pid && selected_pgid != current_guest_pgid)
        return -EPERM;
    *new_guest_pgid = selected_pgid;
    return 0;
}

/* API10 init's observed settimeofday(NULL, &timezone) request is guest state
 * only. Wall-clock changes are deliberately not represented by this helper. */
static inline int guest_timezone_set_request(int has_timeval, int has_timezone,
                                             struct guest_arm32_timezone value,
                                             struct guest_arm32_timezone *state) {
    if (!state || !has_timezone || has_timeval) return -EPERM;
    if (value.minutes_west < -1440 || value.minutes_west > 1440 ||
        value.dst_time < 0 || value.dst_time > 2)
        return -EINVAL;
    *state = value;
    return 0;
}

#endif
