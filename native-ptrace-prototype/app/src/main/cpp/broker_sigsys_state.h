#ifndef GINGERVM_BROKER_SIGSYS_STATE_H
#define GINGERVM_BROKER_SIGSYS_STATE_H

#include <signal.h>
#include <stdint.h>

#ifndef SYS_SECCOMP
#define SYS_SECCOMP 1
#endif

struct broker_sigsys_candidate {
    int armed;
    int response_committed;
    int syscall_number;
    int32_t virtual_result;
};

static inline void broker_sigsys_clear(struct broker_sigsys_candidate *candidate) {
    candidate->armed = 0;
    candidate->response_committed = 0;
}

static inline void broker_sigsys_arm(struct broker_sigsys_candidate *candidate,
                                     int syscall_number, int32_t virtual_result) {
    candidate->armed = 1;
    candidate->response_committed = 0;
    candidate->syscall_number = syscall_number;
    candidate->virtual_result = virtual_result;
}

static inline void broker_sigsys_mark_response_committed(
        struct broker_sigsys_candidate *candidate) {
    if (candidate->armed) candidate->response_committed = 1;
}

/*
 * The seccomp SIGSYS can be reported either before or after the ptrace syscall
 * exit stop has caused the supervisor to commit and clear its pending result.
 * Keep the correlation latch until that SIGSYS, or until the tracee reaches a
 * subsequent syscall entry, which proves it progressed beyond that operation.
 */
static inline int broker_sigsys_take(struct broker_sigsys_candidate *candidate,
                                     int signal_number, int signal_code) {
    if (!candidate->armed || signal_number != SIGSYS || signal_code != SYS_SECCOMP)
        return 0;
    candidate->armed = 0;
    return 1;
}

static inline int broker_sigsys_expire_before_next_entry(
        struct broker_sigsys_candidate *candidate) {
    if (!candidate->armed) return 0;
    broker_sigsys_clear(candidate);
    return 1;
}

#endif
