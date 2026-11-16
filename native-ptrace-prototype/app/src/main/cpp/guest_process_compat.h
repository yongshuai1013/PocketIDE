#ifndef GINGERVM_GUEST_PROCESS_COMPAT_H
#define GINGERVM_GUEST_PROCESS_COMPAT_H

#include <errno.h>
#include <stdint.h>

struct guest_arm32_timezone {
    int32_t minutes_west;
    int32_t dst_time;
};

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
