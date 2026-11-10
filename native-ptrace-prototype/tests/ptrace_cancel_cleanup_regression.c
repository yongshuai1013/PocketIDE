#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include "../app/src/main/cpp/ptrace_tracee_cleanup.h"

#ifndef __WALL
#define __WALL 0x40000000
#endif

static volatile sig_atomic_t cancel_requested;

static void on_sigterm(int signo) {
    (void)signo;
    cancel_requested = 1;
}

static int fail(const char *message, const pid_t *pids, size_t count) {
    fprintf(stderr, "ptrace cancel cleanup regression: FAIL: %s (errno=%d: %s)\n",
            message, errno, strerror(errno));
    for (size_t i = 0; i < count; ++i) {
        if (pids[i] > 0) {
            (void)ptrace(PTRACE_KILL, pids[i], NULL, NULL);
            (void)kill(pids[i], SIGKILL);
            int status;
            (void)waitpid(pids[i], &status, __WALL);
        }
    }
    return 1;
}

int main(void) {
    enum { TRACEES = 3 };
    pid_t pids[TRACEES] = { -1, -1, -1 };
    struct sigaction action;
    memset(&action, 0, sizeof(action));
    action.sa_handler = on_sigterm;
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGTERM, &action, NULL) != 0)
        return fail("install SIGTERM request handler", pids, TRACEES);

    for (size_t i = 0; i < TRACEES; ++i) {
        pid_t child = fork();
        if (child < 0) return fail("fork traced child", pids, TRACEES);
        if (child == 0) {
            if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) != 0) _exit(90);
            raise(SIGSTOP);
            for (;;) pause();
        }
        pids[i] = child;
        int status = 0;
        pid_t waited;
        do { waited = waitpid(child, &status, __WALL); }
        while (waited < 0 && errno == EINTR);
        if (waited != child || !WIFSTOPPED(status))
            return fail("wait for initial ptrace stop", pids, TRACEES);
    }

    if (kill(getpid(), SIGTERM) != 0 || !cancel_requested)
        return fail("SIGTERM must set the cancellation request", pids, TRACEES);

    struct ptrace_cleanup_result cleanup = ptrace_terminate_and_reap(pids, TRACEES);
    if (cleanup.requested != TRACEES || cleanup.reaped != TRACEES || cleanup.unresolved != 0)
        return fail("all stopped tracees must reach a reaped terminal state", pids, TRACEES);

    for (size_t i = 0; i < TRACEES; ++i) {
        errno = 0;
        if (kill(pids[i], 0) == 0 || errno != ESRCH)
            return fail("tracee PID must no longer exist after cleanup", pids, TRACEES);
        int status = 0;
        errno = 0;
        if (waitpid(pids[i], &status, __WALL | WNOHANG) != -1 || errno != ECHILD)
            return fail("tracee must not remain waitable/zombie", pids, TRACEES);
    }

    printf("ptrace cancel cleanup regression: PASS (SIGTERM requested cancellation; tracked=%zu reaped=%zu unresolved=%zu; no tracee PID or zombie remains)\n",
           cleanup.requested, cleanup.reaped, cleanup.unresolved);
    return 0;
}
