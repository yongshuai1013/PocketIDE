#define _GNU_SOURCE
#include <errno.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

#include "../app/src/main/cpp/broker_sigsys_state.h"

#ifndef __WALL
#define __WALL 0x40000000
#endif
#ifndef PTRACE_O_TRACESYSGOOD
#define PTRACE_O_TRACESYSGOOD 0x00000001
#endif
#define SYSCALL_STOP (SIGTRAP | 0x80)

static int child_setup(void) {
    struct sock_filter filter[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, UINT32_MAX, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRAP),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog program = {
        .len = (unsigned short)(sizeof(filter) / sizeof(filter[0])),
        .filter = filter,
    };
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) return -1;
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &program) != 0) return -1;
    return 0;
}

static int fail_child(pid_t child, const char *what) {
    perror(what);
    (void)kill(child, SIGKILL);
    (void)waitpid(child, NULL, __WALL);
    return 1;
}

int main(void) {
    pid_t child = fork();
    if (child < 0) { perror("fork"); return 1; }
    if (child == 0) {
        if (child_setup() != 0) _exit(80);
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) != 0) _exit(81);
        if (raise(SIGSTOP) != 0) _exit(82);
        (void)syscall(SYS_getpid);
        _exit(0);
    }

    int status = 0;
    if (waitpid(child, &status, __WALL) != child || !WIFSTOPPED(status) || WSTOPSIG(status) != SIGSTOP)
        return fail_child(child, "wait initial trace stop");
    if (ptrace(PTRACE_SETOPTIONS, child, NULL, (void *)(uintptr_t)PTRACE_O_TRACESYSGOOD) != 0)
        return fail_child(child, "PTRACE_SETOPTIONS");
    if (ptrace(PTRACE_SYSCALL, child, NULL, NULL) != 0)
        return fail_child(child, "resume to syscall entry");

    int changed_syscall = 0;
    int response_committed = 0;
    int got_sigsys = 0;
    struct broker_sigsys_candidate candidate = {0};
    broker_sigsys_arm(&candidate, 224, 1);

    for (int iteration = 0; iteration < 8 && !got_sigsys; ++iteration) {
        if (waitpid(child, &status, __WALL) != child || !WIFSTOPPED(status))
            return fail_child(child, "wait traced syscall status");
        int stop_signal = WSTOPSIG(status);
        if (stop_signal == SYSCALL_STOP) {
            if (!changed_syscall) {
                struct user_regs_struct regs;
                if (ptrace(PTRACE_GETREGS, child, NULL, &regs) != 0)
                    return fail_child(child, "PTRACE_GETREGS entry");
                if ((long)regs.orig_rax != SYS_getpid) {
                    fprintf(stderr, "unexpected syscall at first entry: %lld\n", (long long)regs.orig_rax);
                    (void)kill(child, SIGKILL); (void)waitpid(child, NULL, __WALL); return 1;
                }
                regs.orig_rax = (unsigned long)-1;
                if (ptrace(PTRACE_SETREGS, child, NULL, &regs) != 0)
                    return fail_child(child, "PTRACE_SETREGS cancel syscall");
                changed_syscall = 1;
            } else if (!response_committed) {
                /* Exercise the same state update that clears pending/expect_exit. */
                broker_sigsys_mark_response_committed(&candidate);
                response_committed = 1;
            }
            if (ptrace(PTRACE_SYSCALL, child, NULL, NULL) != 0)
                return fail_child(child, "resume traced syscall stop");
            continue;
        }
        if (stop_signal == SIGSYS) {
            siginfo_t info;
            if (ptrace(PTRACE_GETSIGINFO, child, NULL, &info) != 0)
                return fail_child(child, "PTRACE_GETSIGINFO SIGSYS");
            if ((unsigned)status >> 16 != 0 || info.si_code != SYS_SECCOMP) {
                fprintf(stderr, "unexpected SIGSYS wait/siginfo: status=0x%x si_code=%d\n", status, info.si_code);
                (void)kill(child, SIGKILL); (void)waitpid(child, NULL, __WALL); return 1;
            }
            if (!response_committed) {
                broker_sigsys_mark_response_committed(&candidate);
                response_committed = 1;
            }
            if (!broker_sigsys_take(&candidate, stop_signal, info.si_code)) {
                fprintf(stderr, "seccomp SIGSYS did not match armed broker candidate\n");
                (void)kill(child, SIGKILL); (void)waitpid(child, NULL, __WALL); return 1;
            }
            got_sigsys = 1;
            printf("HOST PTRACE SIGSYS: wait-status=0x%x stop=%d si-code=%d committed-before-signal=%d\n",
                   status, stop_signal, info.si_code, response_committed);
            break;
        }
        fprintf(stderr, "unexpected ptrace stop: status=0x%x stop=%d\n", status, stop_signal);
        (void)kill(child, SIGKILL); (void)waitpid(child, NULL, __WALL); return 1;
    }
    if (!got_sigsys) {
        fprintf(stderr, "no seccomp SIGSYS observed after canceling syscall number\n");
        (void)kill(child, SIGKILL); (void)waitpid(child, NULL, __WALL); return 1;
    }

    if (ptrace(PTRACE_CONT, child, NULL, NULL) != 0)
        return fail_child(child, "suppress SIGSYS and continue");
    if (waitpid(child, &status, __WALL) != child || !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        fprintf(stderr, "tracee failed after suppressed SIGSYS: status=0x%x\n", status);
        (void)kill(child, SIGKILL); (void)waitpid(child, NULL, __WALL); return 1;
    }
    puts("ptrace seccomp SIGSYS regression: PASS (raw delivery stop and SYS_SECCOMP siginfo observed; candidate accepted after pending response commit)");
    return 0;
}
