#ifndef GINGERVM_PTRACE_TRACEE_CLEANUP_H
#define GINGERVM_PTRACE_TRACEE_CLEANUP_H

#include <errno.h>
#include <signal.h>
#include <stddef.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef __WALL
#define __WALL 0x40000000
#endif

struct ptrace_cleanup_result {
    size_t requested;
    size_t reaped;
    size_t already_gone;
    size_t unresolved;
};

/*
 * Terminate every known tracee first, then wait each one to a terminal state.
 * A stopped tracee is resumed with SIGKILL and waited again. This is shared
 * with a host-kernel regression so the user-cancel path tests the exact
 * production kill/reap primitive rather than a lookalike implementation.
 */
static inline struct ptrace_cleanup_result
ptrace_terminate_and_reap(const pid_t *pids, size_t count) {
    struct ptrace_cleanup_result result = { .requested = count };

    for (size_t i = 0; i < count; ++i) {
        if (pids[i] <= 0) {
            result.unresolved++;
            continue;
        }
        (void)ptrace(PTRACE_KILL, pids[i], NULL, NULL);
        (void)kill(pids[i], SIGKILL);
    }

    for (size_t i = 0; i < count; ++i) {
        pid_t pid = pids[i];
        if (pid <= 0) continue;
        int status = 0;
        int terminal = 0;
        for (unsigned attempt = 0; attempt < 8; ++attempt) {
            pid_t waited;
            do {
                waited = waitpid(pid, &status, __WALL);
            } while (waited < 0 && errno == EINTR);

            if (waited == pid) {
                if (WIFEXITED(status) || WIFSIGNALED(status)) {
                    result.reaped++;
                    terminal = 1;
                    break;
                }
                if (WIFSTOPPED(status)) {
                    (void)ptrace(PTRACE_CONT, pid, NULL,
                                 (void *)(long)SIGKILL);
                    (void)kill(pid, SIGKILL);
                    continue;
                }
                continue;
            }

            if (waited < 0 && (errno == ECHILD || errno == ESRCH)) {
                result.already_gone++;
                terminal = 1;
            }
            break;
        }
        if (!terminal) result.unresolved++;
    }
    return result;
}

#endif
