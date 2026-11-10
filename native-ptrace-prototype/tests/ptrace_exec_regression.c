#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef __x86_64__
#error "This portable host regression test currently targets x86_64 Linux"
#endif

#define SYSCALL_STOP (SIGTRAP | 0x80)

static int fail(pid_t child, const char *message) {
    fprintf(stderr, "ptrace exec-start regression: FAIL: %s (errno=%d)\n",
            message, errno);
    if (child > 0) {
        (void)ptrace(PTRACE_KILL, child, NULL, NULL);
        (void)kill(child, SIGKILL);
        int status;
        (void)waitpid(child, &status, __WALL);
    }
    return 1;
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: %s <static-tracee>\n", argv[0]);
        return 2;
    }

    pid_t child = fork();
    if (child < 0) return fail(-1, "fork failed");
    if (child == 0) {
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) != 0) _exit(120);
        char *const child_argv[] = {argv[1], NULL};
        char *const child_envp[] = {"PATH=/usr/bin:/bin", NULL};
        execve(argv[1], child_argv, child_envp);
        _exit(121);
    }

    int status = 0;
    if (waitpid(child, &status, __WALL) != child || !WIFSTOPPED(status) ||
        WSTOPSIG(status) != SIGTRAP) {
        return fail(child, "successful exec did not produce the initial SIGTRAP stop");
    }

    const long options = PTRACE_O_TRACESYSGOOD | PTRACE_O_EXITKILL;
    if (ptrace(PTRACE_SETOPTIONS, child, NULL, (void *)(unsigned long)options) != 0) {
        return fail(child, "PTRACE_SETOPTIONS failed at the post-exec stop");
    }
    if (ptrace(PTRACE_SYSCALL, child, NULL, NULL) != 0) {
        return fail(child, "could not start tracing after exec");
    }

    int saw_getpid_entry = 0;
    int saw_getpid_exit = 0;
    for (int stops = 0; stops < 16; ++stops) {
        if (waitpid(child, &status, __WALL) != child) {
            return fail(child, "waitpid failed while tracing the new image");
        }
        if (WIFEXITED(status)) {
            if (WEXITSTATUS(status) == 0 && saw_getpid_entry && saw_getpid_exit) {
                puts("ptrace exec-start regression: PASS (first traced syscall is new-image getpid)");
                return 0;
            }
            return fail(-1, "tracee exited before the expected getpid entry/exit stops");
        }
        if (WIFSIGNALED(status)) {
            return fail(-1, "tracee was signaled");
        }
        if (!WIFSTOPPED(status)) continue;

        if (WSTOPSIG(status) == SYSCALL_STOP) {
            struct user_regs_struct regs;
            if (ptrace(PTRACE_GETREGS, child, NULL, &regs) != 0) {
                return fail(child, "PTRACE_GETREGS failed");
            }
            if (!saw_getpid_entry) {
                if ((long)regs.orig_rax != SYS_getpid) {
                    fprintf(stderr, "first traced syscall was %lld, expected %d\n",
                            (long long)regs.orig_rax, SYS_getpid);
                    return fail(child, "a pre-exec syscall leaked into the new-image trace");
                }
                saw_getpid_entry = 1;
            } else if (!saw_getpid_exit) {
                if ((long)regs.orig_rax != SYS_getpid) {
                    return fail(child, "the expected getpid exit stop was not observed");
                }
                saw_getpid_exit = 1;
            }
        }

        if (ptrace(PTRACE_SYSCALL, child, NULL, NULL) != 0) {
            return fail(child, "could not resume tracee");
        }
    }

    return fail(child, "trace stop limit exceeded");
}
