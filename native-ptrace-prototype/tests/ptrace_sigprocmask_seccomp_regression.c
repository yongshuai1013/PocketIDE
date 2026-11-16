#define _GNU_SOURCE
#include <errno.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

#include "../app/src/main/cpp/guest_sigprocmask_compat.h"
#include "../app/src/main/cpp/guest_sigprocmask_ptrace.h"

#ifndef __WALL
#define __WALL 0x40000000
#endif
#define SYSCALL_STOP (SIGTRAP | 0x80)

struct child_report {
    int64_t syscall_result;
    uint32_t old_set;
    int pending_before_unblock;
    int handler_calls;
};

struct tracee_memory_context { pid_t pid; };
static volatile sig_atomic_t usr1_handler_calls;

static void usr1_handler(int signal_number) {
    if (signal_number == SIGUSR1) usr1_handler_calls++;
}

static int child_install_filter(void) {
    struct sock_filter filter[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (uint32_t)SYS_rt_sigprocmask, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRAP),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog program = {
        .len = (unsigned short)(sizeof(filter) / sizeof(filter[0])),
        .filter = filter,
    };
    return prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0 &&
           prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &program) == 0 ? 0 : -1;
}

static int tracee_read_u32(void *opaque, uintptr_t address, uint32_t *value) {
    struct tracee_memory_context *context = opaque;
    if (!context || !value) { errno = EINVAL; return -1; }
    uintptr_t aligned = address & ~((uintptr_t)sizeof(long) - 1u);
    size_t offset = (size_t)(address - aligned);
    errno = 0;
    long word = ptrace(PTRACE_PEEKDATA, context->pid, (void *)aligned, NULL);
    if (word == -1 && errno != 0) return -1;
    unsigned char bytes[sizeof(long)];
    memcpy(bytes, &word, sizeof(word));
    if (offset + sizeof(*value) > sizeof(bytes)) { errno = EFAULT; return -1; }
    memcpy(value, bytes + offset, sizeof(*value));
    return 0;
}

static int tracee_write_u32(void *opaque, uintptr_t address, uint32_t value) {
    struct tracee_memory_context *context = opaque;
    if (!context) { errno = EINVAL; return -1; }
    uintptr_t aligned = address & ~((uintptr_t)sizeof(long) - 1u);
    size_t offset = (size_t)(address - aligned);
    errno = 0;
    long word = ptrace(PTRACE_PEEKDATA, context->pid, (void *)aligned, NULL);
    if (word == -1 && errno != 0) return -1;
    unsigned char bytes[sizeof(long)];
    memcpy(bytes, &word, sizeof(word));
    if (offset + sizeof(value) > sizeof(bytes)) { errno = EFAULT; return -1; }
    memcpy(bytes + offset, &value, sizeof(value));
    memcpy(&word, bytes, sizeof(word));
    return ptrace(PTRACE_POKEDATA, context->pid, (void *)aligned,
                  (void *)(uintptr_t)(unsigned long)word) == 0 ? 0 : -1;
}

static int tracee_get_mask(void *opaque, uint64_t *mask) {
    struct tracee_memory_context *context = opaque;
    if (!context) { errno = EINVAL; return -1; }
    return guest_sigmask_ptrace_get(context->pid, mask);
}

static int tracee_set_mask(void *opaque, uint64_t mask) {
    struct tracee_memory_context *context = opaque;
    if (!context) { errno = EINVAL; return -1; }
    return guest_sigmask_ptrace_set(context->pid, mask);
}

static int wait_stopped(pid_t child, int *status, const char *phase) {
    if (waitpid(child, status, __WALL) != child || !WIFSTOPPED(*status)) {
        fprintf(stderr, "%s: child did not stop; status=0x%x errno=%d\n", phase, *status, errno);
        return -1;
    }
    return 0;
}

static int kill_and_reap(pid_t child, const char *phase) {
    fprintf(stderr, "%s failed; terminating test child\n", phase);
    (void)ptrace(PTRACE_KILL, child, NULL, NULL);
    (void)kill(child, SIGKILL);
    (void)waitpid(child, NULL, __WALL);
    return 1;
}

static int read_full(int fd, void *buffer, size_t length) {
    unsigned char *bytes = buffer;
    size_t done = 0;
    while (done < length) {
        ssize_t got = read(fd, bytes + done, length - done);
        if (got < 0 && errno == EINTR) continue;
        if (got <= 0) return -1;
        done += (size_t)got;
    }
    return 0;
}

static int write_full(int fd, const void *buffer, size_t length) {
    const unsigned char *bytes = buffer;
    size_t done = 0;
    while (done < length) {
        ssize_t put = write(fd, bytes + done, length - done);
        if (put < 0 && errno == EINTR) continue;
        if (put <= 0) return -1;
        done += (size_t)put;
    }
    return 0;
}

int main(void) {
#if !defined(__x86_64__) || !defined(SYS_rt_sigprocmask)
    puts("ptrace sigprocmask seccomp regression: SKIP (requires Linux x86_64)");
    return 0;
#else
    int report_pipe[2];
    if (pipe(report_pipe) != 0) { perror("pipe"); return 1; }
    pid_t child = fork();
    if (child < 0) { perror("fork"); return 1; }
    if (child == 0) {
        close(report_pipe[0]);
        struct sigaction action;
        memset(&action, 0, sizeof(action));
        action.sa_handler = usr1_handler;
        sigemptyset(&action.sa_mask);
        if (sigaction(SIGUSR1, &action, NULL) != 0) _exit(80);
        if (child_install_filter() != 0) _exit(81);
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) != 0) _exit(82);
        if (syscall(SYS_tgkill, getpid(), syscall(SYS_gettid), SIGSTOP) != 0) _exit(83);

        uint32_t requested_set = UINT32_C(1) << (SIGUSR1 - 1);
        uint32_t old_set = UINT32_C(0xdeadbeef);
        long result = syscall(SYS_rt_sigprocmask, GUEST_ARM_SIGPROCMASK_SIG_BLOCK,
                              &requested_set, &old_set, sizeof(uint64_t));
        struct child_report first = {
            .syscall_result = result,
            .old_set = old_set,
            .pending_before_unblock = -1,
            .handler_calls = (int)usr1_handler_calls,
        };
        if (write_full(report_pipe[1], &first, sizeof(first)) != 0) _exit(84);
        if (raise(SIGSTOP) != 0) _exit(85);

        sigset_t pending;
        if (sigpending(&pending) != 0) _exit(86);
        struct child_report blocked = {
            .syscall_result = 0,
            .old_set = old_set,
            .pending_before_unblock = sigismember(&pending, SIGUSR1),
            .handler_calls = (int)usr1_handler_calls,
        };
        if (write_full(report_pipe[1], &blocked, sizeof(blocked)) != 0) _exit(87);
        if (raise(SIGSTOP) != 0) _exit(88);

        struct child_report delivered = {
            .syscall_result = 0,
            .old_set = old_set,
            .pending_before_unblock = blocked.pending_before_unblock,
            .handler_calls = (int)usr1_handler_calls,
        };
        if (write_full(report_pipe[1], &delivered, sizeof(delivered)) != 0) _exit(89);
        _exit(usr1_handler_calls == 1 ? 0 : 90);
    }

    close(report_pipe[1]);
    int status = 0;
    if (wait_stopped(child, &status, "initial trace stop") != 0 || WSTOPSIG(status) != SIGSTOP)
        return kill_and_reap(child, "initial trace stop");
    if (ptrace(PTRACE_SETOPTIONS, child, NULL, (void *)(uintptr_t)PTRACE_O_TRACESYSGOOD) != 0)
        return kill_and_reap(child, "set ptrace options");

    const uint64_t initial_mask = (UINT64_C(1) << (SIGUSR2 - 1)) |
                                  (UINT64_C(1) << 39); /* SIGUSR2 plus signal 40. */
    if (guest_sigmask_ptrace_set(child, initial_mask) != 0)
        return kill_and_reap(child, "seed tracee mask");
    uint64_t verify_mask = 0;
    if (guest_sigmask_ptrace_get(child, &verify_mask) != 0 || verify_mask != initial_mask)
        return kill_and_reap(child, "verify seeded tracee mask");
    if (ptrace(PTRACE_SYSCALL, child, NULL, NULL) != 0)
        return kill_and_reap(child, "resume tracee to blocked rt_sigprocmask entry");

    struct user_regs_struct regs;
    int found_target_entry = 0;
    for (int i = 0; i < 64; ++i) {
        if (wait_stopped(child, &status, "search rt_sigprocmask entry") != 0)
            return kill_and_reap(child, "search rt_sigprocmask entry");
        if (WSTOPSIG(status) == SIGSYS) {
            siginfo_t info;
            if (ptrace(PTRACE_GETSIGINFO, child, NULL, &info) == 0)
                fprintf(stderr, "unmodified rt_sigprocmask reached seccomp before interception: si-syscall=%d\n", info.si_syscall);
            return kill_and_reap(child, "seccomp trapped before ptrace rewrite");
        }
        if (WSTOPSIG(status) != SYSCALL_STOP) {
            if (ptrace(PTRACE_SYSCALL, child, NULL, NULL) != 0)
                return kill_and_reap(child, "resume non-syscall stop");
            continue;
        }
        if (ptrace(PTRACE_GETREGS, child, NULL, &regs) != 0)
            return kill_and_reap(child, "read syscall registers");
        if ((long)regs.orig_rax == SYS_rt_sigprocmask) {
            found_target_entry = 1;
            break;
        }
        if (ptrace(PTRACE_SYSCALL, child, NULL, NULL) != 0)
            return kill_and_reap(child, "advance to rt_sigprocmask entry");
    }
    if (!found_target_entry || (int)regs.rdi != GUEST_ARM_SIGPROCMASK_SIG_BLOCK)
        return kill_and_reap(child, "locate expected rt_sigprocmask call");

    uintptr_t set_address = (uintptr_t)regs.rsi;
    uintptr_t old_set_address = (uintptr_t)regs.rdx;
    struct tracee_memory_context memory = { .pid = child };
    const struct guest_sigprocmask_ops ops = {
        .context = &memory,
        .read_u32 = tracee_read_u32,
        .write_u32 = tracee_write_u32,
        .get_mask = tracee_get_mask,
        .set_mask = tracee_set_mask,
    };
    struct guest_sigprocmask_report report;
    if (guest_sigprocmask_compat_apply(&ops, GUEST_ARM_SIGPROCMASK_SIG_BLOCK,
            set_address, old_set_address, &report) != 0 || report.result != 0 ||
        report.old_set != (UINT32_C(1) << (SIGUSR2 - 1)))
        return kill_and_reap(child, "apply legacy SIG_BLOCK to real tracee");

    regs.orig_rax = (unsigned long)-1; /* Do not execute the seccomp-blocked RT syscall. */
    if (ptrace(PTRACE_SETREGS, child, NULL, &regs) != 0 ||
        ptrace(PTRACE_SYSCALL, child, NULL, NULL) != 0)
        return kill_and_reap(child, "rewrite blocked syscall to no-op");
    if (wait_stopped(child, &status, "wait rewritten syscall exit") != 0 ||
        WSTOPSIG(status) != SYSCALL_STOP)
        return kill_and_reap(child, "rewritten syscall did not exit without SIGSYS");
    if (ptrace(PTRACE_GETREGS, child, NULL, &regs) != 0)
        return kill_and_reap(child, "read rewritten syscall result");
    regs.rax = (unsigned long)report.result;
    if (ptrace(PTRACE_SETREGS, child, NULL, &regs) != 0)
        return kill_and_reap(child, "inject legacy syscall result");
    uint64_t expected_mask = initial_mask | (UINT64_C(1) << (SIGUSR1 - 1));
    if (guest_sigmask_ptrace_get(child, &verify_mask) != 0 || verify_mask != expected_mask)
        return kill_and_reap(child, "verify real SIG_BLOCK and preserved upper word");
    if (ptrace(PTRACE_CONT, child, NULL, NULL) != 0)
        return kill_and_reap(child, "resume after SIG_BLOCK");

    struct child_report child_first;
    if (read_full(report_pipe[0], &child_first, sizeof(child_first)) != 0 ||
        child_first.syscall_result != 0 ||
        child_first.old_set != (UINT32_C(1) << (SIGUSR2 - 1)))
        return kill_and_reap(child, "verify injected result and oldset");
    if (wait_stopped(child, &status, "wait blocked-mask checkpoint") != 0 || WSTOPSIG(status) != SIGSTOP)
        return kill_and_reap(child, "blocked-mask checkpoint");

    if (kill(child, SIGUSR1) != 0 || ptrace(PTRACE_CONT, child, NULL, NULL) != 0)
        return kill_and_reap(child, "queue SIGUSR1 while blocked");
    struct child_report blocked_report;
    if (read_full(report_pipe[0], &blocked_report, sizeof(blocked_report)) != 0 ||
        blocked_report.pending_before_unblock != 1 || blocked_report.handler_calls != 0)
        return kill_and_reap(child, "verify blocked signal remained pending");
    if (wait_stopped(child, &status, "wait before SIG_UNBLOCK") != 0 || WSTOPSIG(status) != SIGSTOP)
        return kill_and_reap(child, "SIG_UNBLOCK checkpoint");

    if (guest_sigprocmask_compat_apply(&ops, GUEST_ARM_SIGPROCMASK_SIG_UNBLOCK,
            set_address, old_set_address, &report) != 0 || report.result != 0 ||
        report.old_set != ((UINT32_C(1) << (SIGUSR2 - 1)) | (UINT32_C(1) << (SIGUSR1 - 1))))
        return kill_and_reap(child, "apply legacy SIG_UNBLOCK to real tracee");
    expected_mask = initial_mask;
    if (guest_sigmask_ptrace_get(child, &verify_mask) != 0 || verify_mask != expected_mask)
        return kill_and_reap(child, "verify real SIG_UNBLOCK");
    if (ptrace(PTRACE_CONT, child, NULL, NULL) != 0)
        return kill_and_reap(child, "resume after SIG_UNBLOCK");

    if (wait_stopped(child, &status, "wait pending SIGUSR1 delivery") != 0 || WSTOPSIG(status) != SIGUSR1)
        return kill_and_reap(child, "pending signal was not delivered after unblocking");
    if (ptrace(PTRACE_CONT, child, NULL, (void *)(uintptr_t)SIGUSR1) != 0)
        return kill_and_reap(child, "deliver pending SIGUSR1 to handler");
    if (waitpid(child, &status, __WALL) != child || !WIFEXITED(status) || WEXITSTATUS(status) != 0)
        return kill_and_reap(child, "wait child signal handler completion");
    struct child_report delivered_report;
    if (read_full(report_pipe[0], &delivered_report, sizeof(delivered_report)) != 0 ||
        delivered_report.handler_calls != 1)
        return kill_and_reap(child, "verify pending SIGUSR1 handler ran exactly once");

    close(report_pipe[0]);
    printf("ptrace sigprocmask/seccomp regression: PASS (blocked syscall was rewritten before SYS_SECCOMP; oldset=%#x; upper mask preserved; pending SIGUSR1 delivered after SIG_UNBLOCK)\n",
           child_first.old_set);
    return 0;
#endif
}
