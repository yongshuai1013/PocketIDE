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
    assert(pgid == 2); /* init may establish a process group for its child */
    assert(guest_process_group_set(1, 3, 2, 1, 3, 0, 2, &pgid) == -EPERM);
    assert(guest_process_group_set(1, 2, 1, 1, -1, 0, 1, &pgid) == -EINVAL);
    assert(guest_process_group_set(1, 2, 1, 1, 2, -1, 1, &pgid) == -EINVAL);
    assert(guest_process_group_set(1, 2, 1, 0, 2, 2, 1, &pgid) == -ESRCH);
    assert(guest_process_group_set(1, 2, 9, 1, 2, 2, 1, &pgid) == -EPERM);
    assert(guest_process_group_set(1, 1, 0, 1, 1, 5, 1, &pgid) == -EPERM);

    struct guest_arm32_timezone timezone = {.minutes_west = 0, .dst_time = 0};
    struct guest_arm32_timezone state = {.minutes_west = 60, .dst_time = 1};
    assert(guest_timezone_set_request(0, 1, timezone, &state) == 0);
    assert(state.minutes_west == 0 && state.dst_time == 0);
    struct guest_arm32_timezone value = {.minutes_west = -480, .dst_time = 0};
    assert(guest_timezone_set_request(0, 1, value, &state) == 0);
    assert(state.minutes_west == -480);
    assert(guest_timezone_set_request(1, 1, value, &state) == -EPERM);
    assert(guest_timezone_set_request(0, 0, value, &state) == -EPERM);
    value.minutes_west = 1441;
    assert(guest_timezone_set_request(0, 1, value, &state) == -EINVAL);
    value.minutes_west = 0; value.dst_time = 3;
    assert(guest_timezone_set_request(0, 1, value, &state) == -EINVAL);

    puts("guest process compatibility regression: PASS (setpgid modifies guest IDs only; timezone-only settimeofday is virtual)");
    return 0;
}
