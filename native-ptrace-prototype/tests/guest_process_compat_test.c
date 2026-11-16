#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>

#include "../app/src/main/cpp/guest_process_compat.h"

int main(void) {
    uint32_t pgid = 0;
    assert(guest_process_group_set(1, 1, 0, 1, 0, 0, 1, &pgid) == 0);
    assert(pgid == 1);
    assert(guest_process_group_set(1, 2, 1, 1, 2, 2, 1, &pgid) == 0);
    assert(pgid == 2);
    assert(guest_process_group_set(1, 3, 2, 1, 3, 0, 2, &pgid) == -EPERM);
    assert(guest_process_group_set(1, 2, 1, 1, -1, 0, 1, &pgid) == -EINVAL);
    assert(guest_process_group_set(1, 2, 1, 1, 2, -1, 1, &pgid) == -EINVAL);
    assert(guest_process_group_set(1, 2, 1, 0, 2, 2, 1, &pgid) == -ESRCH);
    assert(guest_process_group_set(1, 2, 9, 1, 2, 2, 1, &pgid) == -EPERM);
    assert(guest_process_group_set(1, 1, 0, 1, 1, 5, 1, &pgid) == -EPERM);

    struct guest_process_compat_state process;
    guest_process_compat_init(&process);
    assert(process.nice_limit.current == 0u && process.nice_limit.maximum == 0u);
    struct guest_arm32_rlimit nice = {.current = 40u, .maximum = 40u};
    assert(guest_process_setrlimit(&process, GUEST_RLIMIT_NICE, nice, 0u) == 0);
    assert(process.nice_limit.current == 40u && process.nice_limit.maximum == 40u);
    nice.current = 41u;
    assert(guest_process_setrlimit(&process, GUEST_RLIMIT_NICE, nice, 0u) == -EINVAL);
    nice.current = 30u; nice.maximum = 41u;
    assert(guest_process_setrlimit(&process, GUEST_RLIMIT_NICE, nice, 1000u) == -EPERM);
    nice.current = 40u; nice.maximum = 40u;
    assert(guest_process_setrlimit(&process, 2u, nice, 0u) == -EOPNOTSUPP);
    assert(guest_process_setrlimit(&process, GUEST_RLIMIT_COUNT, nice, 0u) == -EINVAL);

    struct guest_process_compat_state target;
    guest_process_compat_init(&target);
    uint32_t rt4 = GUEST_IOPRIO_CLASS_DATA(GUEST_IOPRIO_CLASS_RT, 4u);
    uint32_t be2 = GUEST_IOPRIO_CLASS_DATA(GUEST_IOPRIO_CLASS_BE, 2u);
    uint32_t idle = GUEST_IOPRIO_CLASS_DATA(GUEST_IOPRIO_CLASS_IDLE, 0u);
    assert(rt4 == 0x2004u && be2 == 0x4002u);
    assert(guest_process_ioprio_set(&target, 0u, 0u, 0u,
        GUEST_IOPRIO_WHO_PROCESS, 0, 1, idle) == 0);
    assert(guest_process_ioprio_set(&target, 0u, 0u, 0u,
        GUEST_IOPRIO_WHO_PROCESS, 0, 1,
        GUEST_IOPRIO_CLASS_DATA(GUEST_IOPRIO_CLASS_IDLE, 1u)) == -EINVAL);
    assert(guest_process_ioprio_set(&target, 0u, 1000u, 1000u,
        GUEST_IOPRIO_WHO_PROCESS, 0, 1, rt4) == 0);
    assert(target.ioprio == rt4);
    assert(guest_process_ioprio_set(&target, 0u, 1000u, 1000u,
        GUEST_IOPRIO_WHO_PROCESS, 9, 1, be2) == 0);
    assert(target.ioprio == be2);
    assert(guest_process_ioprio_set(&target, 1000u, 2000u, 2000u,
        GUEST_IOPRIO_WHO_PROCESS, 9, 1, be2) == -EPERM);
    assert(guest_process_ioprio_set(&target, 1000u, 1000u, 1000u,
        GUEST_IOPRIO_WHO_PROCESS, 0, 1, rt4) == -EPERM);
    assert(guest_process_ioprio_set(&target, 0u, 0u, 0u,
        GUEST_IOPRIO_WHO_PROCESS, 3, 0, be2) == -ESRCH);
    assert(guest_process_ioprio_set(&target, 0u, 0u, 0u,
        GUEST_IOPRIO_WHO_PGRP, 3, 1, be2) == -EOPNOTSUPP);
    assert(guest_process_ioprio_set(&target, 0u, 0u, 0u,
        99u, 3, 1, be2) == -EINVAL);
    assert(guest_process_ioprio_set(&target, 0u, 0u, 0u,
        GUEST_IOPRIO_WHO_PROCESS, -1, 1, be2) == -EINVAL);
    assert(guest_process_ioprio_set(&target, 0u, 0u, 0u,
        GUEST_IOPRIO_WHO_PROCESS, 3, 1,
        GUEST_IOPRIO_CLASS_DATA(GUEST_IOPRIO_CLASS_BE, 8u)) == -EINVAL);

    assert(guest_process_group_get(0, 13u, 13u, 0u, 0) == 13);
    assert(guest_process_group_get(13, 13u, 13u, 0u, 0) == 13);
    assert(guest_process_group_get(2, 13u, 13u, 2u, 1) == 2);
    assert(guest_process_group_get(2, 13u, 13u, 0u, 0) == -ESRCH);
    assert(guest_process_group_get(-1, 13u, 13u, 0u, 0) == -EINVAL);

    struct guest_arm32_timezone timezone = {.minutes_west = 0, .dst_time = 0};
    struct guest_arm32_timezone timezone_state = {.minutes_west = 60, .dst_time = 1};
    assert(guest_timezone_set_request(0, 1, timezone, &timezone_state) == 0);
    assert(timezone_state.minutes_west == 0 && timezone_state.dst_time == 0);
    struct guest_arm32_timezone value = {.minutes_west = -480, .dst_time = 0};
    assert(guest_timezone_set_request(0, 1, value, &timezone_state) == 0);
    assert(timezone_state.minutes_west == -480);
    assert(guest_timezone_set_request(1, 1, value, &timezone_state) == -EPERM);
    assert(guest_timezone_set_request(0, 0, value, &timezone_state) == -EPERM);
    value.minutes_west = 1441;
    assert(guest_timezone_set_request(0, 1, value, &timezone_state) == -EINVAL);
    value.minutes_west = 0; value.dst_time = 3;
    assert(guest_timezone_set_request(0, 1, value, &timezone_state) == -EINVAL);

    puts("guest process compatibility regression: PASS (guest setpgid/getpgid, source-backed RLIMIT_NICE/ioprio, timezone-only settimeofday)");
    return 0;
}
