#define _GNU_SOURCE
#include <errno.h>
#include <linux/audit.h>
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

static int child_setup(uint32_t trapped_syscall) {
    struct sock_filter filter[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, trapped_syscall, 0, 1),
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

static int test_nonplaceholder_sigsys_is_forwarded(int arm_unrelated_candidate) {
    pid_t child = fork();
    if (child < 0) { perror("fork real SIGSYS child"); return 1; }
    if (child == 0) {
        pid_t child_pid = getpid();
        pid_t child_tid = (pid_t)syscall(SYS_gettid);
        if (child_setup((uint32_t)SYS_getpid) != 0) _exit(90);
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) != 0) _exit(91);
        if (syscall(SYS_tgkill, child_pid, child_tid, SIGSTOP) != 0) _exit(92);
        (void)syscall(SYS_getpid);
        _exit(93);
    }

    int status = 0;
    if (waitpid(child, &status, __WALL) != child || !WIFSTOPPED(status) ||
        WSTOPSIG(status) != SIGSTOP) return fail_child(child, "wait real SIGSYS initial stop");
    if (ptrace(PTRACE_SETOPTIONS, child, NULL, (void *)(uintptr_t)PTRACE_O_TRACESYSGOOD) != 0)
        return fail_child(child, "set real SIGSYS ptrace options");
    if (ptrace(PTRACE_SYSCALL, child, NULL, NULL) != 0)
        return fail_child(child, "resume real SIGSYS child to syscall entry");
    if (waitpid(child, &status, __WALL) != child || !WIFSTOPPED(status) ||
        WSTOPSIG(status) != SYSCALL_STOP) return fail_child(child, "wait real SIGSYS syscall entry");

    struct user_regs_struct regs;
    if (ptrace(PTRACE_GETREGS, child, NULL, &regs) != 0)
        return fail_child(child, "read real SIGSYS syscall entry");
    if ((long)regs.orig_rax != SYS_getpid) {
        fprintf(stderr, "real SIGSYS test saw unexpected syscall entry: %lld\n",
                (long long)regs.orig_rax);
        (void)kill(child, SIGKILL); (void)waitpid(child, NULL, __WALL); return 1;
    }

    struct broker_sigsys_candidate candidate = {0};
    if (arm_unrelated_candidate) {
        broker_sigsys_arm(&candidate, 202, 0);
        broker_sigsys_mark_response_committed(&candidate);
    }
    if (ptrace(PTRACE_SYSCALL, child, NULL, NULL) != 0)
        return fail_child(child, "continue real SIGSYS syscall entry");
    int got_sigsys = 0;
    for (int iteration = 0; iteration < 8 && !got_sigsys; ++iteration) {
        if (waitpid(child, &status, __WALL) != child || !WIFSTOPPED(status))
            return fail_child(child, "wait real seccomp SIGSYS");
        int stop_signal = WSTOPSIG(status);
        if (stop_signal == SYSCALL_STOP) {
            if (ptrace(PTRACE_SYSCALL, child, NULL, NULL) != 0)
                return fail_child(child, "resume real SIGSYS syscall stop");
            continue;
        }
        if (stop_signal == SIGSYS) {
            got_sigsys = 1;
            break;
        }
        fprintf(stderr, "unexpected stop before real SIGSYS: status=0x%x stop=%d\n",
                status, stop_signal);
        (void)kill(child, SIGKILL); (void)waitpid(child, NULL, __WALL); return 1;
    }
    if (!got_sigsys) return fail_child(child, "no real seccomp SIGSYS delivery stop");

    siginfo_t info;
    if (ptrace(PTRACE_GETSIGINFO, child, NULL, &info) != 0)
        return fail_child(child, "get real seccomp SIGSYS info");
    if ((unsigned)status >> 16 != 0 || info.si_code != SYS_SECCOMP ||
        info.si_syscall != SYS_getpid || info.si_arch != AUDIT_ARCH_X86_64 ||
        !info.si_call_addr) {
        fprintf(stderr, "real SIGSYS metadata mismatch: status=0x%x code=%d syscall=%d arch=0x%x\n",
                status, info.si_code, info.si_syscall, (unsigned)info.si_arch);
        (void)kill(child, SIGKILL); (void)waitpid(child, NULL, __WALL); return 1;
    }
    if (broker_sigsys_take(&candidate, SIGSYS, info.si_code, info.si_syscall)) {
        fprintf(stderr, "non-placeholder seccomp SIGSYS was incorrectly consumed\n");
        (void)kill(child, SIGKILL); (void)waitpid(child, NULL, __WALL); return 1;
    }
    broker_sigsys_clear(&candidate);
    if (ptrace(PTRACE_CONT, child, NULL, (void *)(uintptr_t)SIGSYS) != 0)
        return fail_child(child, "forward real SIGSYS to tracee");
    if (waitpid(child, &status, __WALL) != child || !WIFSIGNALED(status) ||
        WTERMSIG(status) != SIGSYS) {
        fprintf(stderr, "forwarded real SIGSYS did not terminate tracee: status=0x%x\n", status);
        return 1;
    }
    printf("HOST REAL SIGSYS FORWARDED: syscall=%d candidate-armed=%d response-committed=%d\n",
           info.si_syscall, arm_unrelated_candidate, arm_unrelated_candidate);
    return 0;
}

int main(void) {
    pid_t child = fork();
    if (child < 0) { perror("fork"); return 1; }
    if (child == 0) {
        if (child_setup(UINT32_MAX) != 0) _exit(80);
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
            if (info.si_syscall != -1 || info.si_arch != AUDIT_ARCH_X86_64 || !info.si_call_addr) {
                fprintf(stderr, "unexpected seccomp SIGSYS metadata: syscall=%d arch=0x%x call_addr=%p\n",
                        info.si_syscall, (unsigned)info.si_arch, info.si_call_addr);
                (void)kill(child, SIGKILL); (void)waitpid(child, NULL, __WALL); return 1;
            }
            if (!response_committed) {
                broker_sigsys_mark_response_committed(&candidate);
                response_committed = 1;
            }
            if (!broker_sigsys_take(&candidate, stop_signal, info.si_code, info.si_syscall)) {
                fprintf(stderr, "seccomp SIGSYS did not match armed broker candidate\n");
                (void)kill(child, SIGKILL); (void)waitpid(child, NULL, __WALL); return 1;
            }
            got_sigsys = 1;
            printf("HOST PTRACE SIGSYS: wait-status=0x%x stop=%d si-code=%d si-syscall=%d si-arch=0x%x si-call-addr=%p committed-before-signal=%d\n",
                   status, stop_signal, info.si_code, info.si_syscall,
                   (unsigned)info.si_arch, info.si_call_addr, response_committed);
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
    if (test_nonplaceholder_sigsys_is_forwarded(0) != 0) return 1;
    if (test_nonplaceholder_sigsys_is_forwarded(1) != 0) return 1;
    puts("ptrace non-placeholder SIGSYS regression: PASS (forwarded with no candidate and with an unrelated committed candidate)");
    return 0;
}
