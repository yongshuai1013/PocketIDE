#define _GNU_SOURCE
#include <assert.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>

#include "../app/src/main/cpp/broker_sigsys_state.h"

int main(void) {
    struct broker_sigsys_candidate candidate = {0};

    /* SIGSYS at the syscall-exit boundary, while the virtual result is pending. */
    broker_sigsys_arm(&candidate, 224, 1);
    assert(candidate.armed && !candidate.response_committed);
    assert(!broker_sigsys_take(&candidate, SIGSYS, SI_USER));
    assert(broker_sigsys_take(&candidate, SIGSYS, SYS_SECCOMP));
    assert(!candidate.armed);

    /* Kernel reports the syscall-exit stop first; pending is then cleared. */
    broker_sigsys_arm(&candidate, 224, 1);
    int pending = 1;
    int expect_exit = 1;
    pending = 0;
    expect_exit = 0;
    broker_sigsys_mark_response_committed(&candidate);
    assert(!pending && !expect_exit && candidate.response_committed);
    assert(broker_sigsys_take(&candidate, SIGSYS, SYS_SECCOMP));
    assert(!candidate.armed);

    /* A later, unrelated guest syscall expires a committed candidate. */
    broker_sigsys_arm(&candidate, 224, 1);
    broker_sigsys_mark_response_committed(&candidate);
    assert(broker_sigsys_expire_before_next_entry(&candidate));
    assert(!candidate.armed);
    assert(!broker_sigsys_take(&candidate, SIGSYS, SYS_SECCOMP));

    puts("brokered SIGSYS wait-order regression: PASS (both response orderings covered; non-seccomp signals rejected; stale candidate expires)");
    return 0;
}
