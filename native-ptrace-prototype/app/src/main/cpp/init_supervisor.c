#define _GNU_SOURCE
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "init_broker.h"
#include "guest_exec_elf.h"
#include "broker_sigsys_state.h"
#include "ptrace_tracee_cleanup.h"
#include "guest_uevent_virtual.h"
#include "guest_file_ops.h"
#include "guest_symlink_ops.h"
#include "guest_socket_virtual.h"
#include "guest_socket_path_ops.h"
#include "guest_diagnostics.h"
#include "guest_sigsys_context.h"
#include "guest_script_launch.h"
#include "guest_sigprocmask_compat.h"
#include "guest_sigprocmask_ptrace.h"
#include "guest_sigaction_compat.h"
#include "guest_process_compat.h"
#include "guest_safe_dir.h"
#include "guest_hardware_profile.h"
#include "guest_network_virtual.h"
#include "guest_pseudo_device.h"
#include "guest_path_fd.h"
#include "guest_entry_probe.h"

#ifndef __WALL
#define __WALL 0x40000000
#endif
#ifndef PTRACE_O_EXITKILL
#define PTRACE_O_EXITKILL 0x00100000
#endif
#ifndef PTRACE_O_TRACESYSGOOD
#define PTRACE_O_TRACESYSGOOD 0x00000001
#endif
#ifndef PTRACE_O_TRACEFORK
#define PTRACE_O_TRACEFORK 0x00000002
#endif
#ifndef PTRACE_O_TRACEVFORK
#define PTRACE_O_TRACEVFORK 0x00000004
#endif
#ifndef PTRACE_O_TRACECLONE
#define PTRACE_O_TRACECLONE 0x00000008
#endif
#ifndef PTRACE_O_TRACEEXEC
#define PTRACE_O_TRACEEXEC 0x00000010
#endif
#ifndef PTRACE_EVENT_FORK
#define PTRACE_EVENT_FORK 1
#endif
#ifndef PTRACE_EVENT_VFORK
#define PTRACE_EVENT_VFORK 2
#endif
#ifndef PTRACE_EVENT_CLONE
#define PTRACE_EVENT_CLONE 3
#endif
#ifndef PTRACE_EVENT_EXEC
#define PTRACE_EVENT_EXEC 4
#endif
#ifndef NT_ARM_SYSTEM_CALL
#define NT_ARM_SYSTEM_CALL 0x404
#endif
#ifndef NT_PRSTATUS
#define NT_PRSTATUS 1
#endif

#define ARM_NR_EXIT 1
#define ARM_NR_FORK 2
#define ARM_NR_CLOSE 6
#define ARM_NR_READ 3
#define ARM_NR_WRITE 4
#define ARM_NR_OPEN 5
#define ARM_NR_CREAT 8
#define ARM_NR_UNLINK 10
#define ARM_NR_EXECVE 11
#define ARM_NR_CHDIR 12
#define ARM_NR_MKNOD 14
#define ARM_NR_CHMOD 15
#define ARM_NR_LCHOWN 16
#define ARM_NR_CHOWN 182
#define ARM_NR_LSEEK 19
#define ARM_NR_GETPID 20
#define ARM_NR_MOUNT 21
#define ARM_NR_SETUID 23
#define ARM_NR_GETUID 24
#define ARM_NR_PTRACE 26
#define ARM_NR_ACCESS 33
#define ARM_NR_SYMLINK 83
#define ARM_NR_READLINK 85
#define ARM_NR_KILL 37
#define ARM_NR_RENAME 38
#define ARM_NR_MKDIR 39
#define ARM_NR_RMDIR 40
#define ARM_NR_DUP2 63
#define ARM_NR_FCNTL 55
#define ARM_NR_FCNTL64 221
#define ARM_NR_GETPPID 64
#define ARM_NR_SIGACTION 67
#define ARM_NR_SETGID 46
#define ARM_NR_GETGID 47
#define ARM_NR_GETEUID 49
#define ARM_NR_GETEGID 50
#define ARM_NR_UMOUNT2 52
#define ARM_NR_IOCTL 54
#define ARM_NR_UMASK 60
#define ARM_NR_FCHMOD 94
#define ARM_NR_FCHOWN 95
#define ARM_NR_SOCKETCALL 102
#define ARM_NR_POLL 168
#define ARM_NR_SOCKET 281
#define ARM_NR_BIND 282
#define ARM_NR_CONNECT 283
#define ARM_NR_LISTEN 284
#define ARM_NR_ACCEPT 285
#define ARM_NR_SOCKETPAIR 288
#define ARM_NR_SEND 289
#define ARM_NR_RECVMSG 297
#define ARM_NR_SENDTO 290
#define ARM_NR_RECV 291
#define ARM_NR_RECVFROM 292
#define ARM_NR_SETSOCKOPT 294
#define ARM_NR_GETSOCKOPT 295
#define ARM_NR_SETPGID 57
#define ARM_NR_SETTIMEOFDAY 79
#define GUEST_MSG_CTRUNC 0x0008
#define GUEST_MSG_TRUNC 0x0020
#define GUEST_MSG_DONTWAIT 0x0040
#define GUEST_SCM_CREDENTIALS 2
#define ARM_NR_WAIT4 114
#define ARM_NR_CLONE 120
#define ARM_NR_MPROTECT 125
#define ARM_NR_SIGRETURN 119
#define ARM_NR_MUNMAP 91
#define ARM_NR_MREMAP 163
#define ARM_NR_NANOSLEEP 162
#define ARM_NR_SETRESUID 164
#define ARM_NR_GETRESUID 165
#define ARM_NR_SETRESGID 170
#define ARM_NR_GETRESGID 171
#define ARM_NR_PRCTL 172
#define ARM_NR_RT_SIGRETURN 173
#define ARM_NR_RT_SIGACTION 174
#define ARM_NR_SIGPROCMASK 126
#define ARM_NR_RT_SIGPROCMASK 175
#define ARM_NR_SIGALTSTACK 186
#define ARM_NR_VFORK 190
#define ARM_NR_MMAP2 192
#define ARM_NR_FTRUNCATE 93
#define ARM_NR_FTRUNCATE64 194
#define ARM_NR_STAT64 195
#define ARM_NR_LSTAT64 196
#define ARM_NR_FSTAT64 197
#define ARM_NR_LCHOWN32 198
#define ARM_NR_GETUID32 199
#define ARM_NR_GETGID32 200
#define ARM_NR_GETEUID32 201
#define ARM_NR_GETEGID32 202
#define ARM_NR_SETREUID32 203
#define ARM_NR_SETREGID32 204
#define ARM_NR_GETGROUPS32 205
#define ARM_NR_SETGROUPS32 206
#define ARM_NR_FCHOWN32 207
#define ARM_NR_SETRESUID32 208
#define ARM_NR_GETRESUID32 209
#define ARM_NR_SETRESGID32 210
#define ARM_NR_GETRESGID32 211
#define ARM_NR_CHOWN32 212
#define ARM_NR_SETUID32 213
#define ARM_NR_SETGID32 214
#define ARM_NR_FCHDIR 133
#define ARM_NR_SETFSUID32 215
#define ARM_NR_SETFSGID32 216
#define ARM_NR_GETDENTS64 217
#define ARM_NR_PIVOT_ROOT 218
#define ARM_NR_MADVISE 220
#define ARM_NR_GETTID 224
#define ARM_NR_FUTEX 240
#define ARM_NR_EXIT_GROUP 248
#define ARM_NR_CLOCK_GETTIME 263
#define ARM_NR_CLOCK_GETRES 264
#define ARM_NR_CLOCK_NANOSLEEP 265
#define ARM_NR_UMOUNT 52
#define ARM_NR_OPENAT 322
#define ARM_NR_MKDIRAT 323
#define ARM_NR_MKNODAT 324
#define ARM_NR_FCHOWNAT 325
#define ARM_NR_FSTATAT64 327
#define ARM_NR_UNLINKAT 328
#define ARM_NR_RENAMEAT 329
#define ARM_NR_SYMLINKAT 331
#define ARM_NR_READLINKAT 332
#define ARM_NR_FCHMODAT 333
#define ARM_NR_FACCESSAT 334

#define GUEST_MS_RDONLY 1u
#define GUEST_MS_NOSUID 2u
#define GUEST_MS_NODEV 4u
#define GUEST_MS_REMOUNT 32u
#define TRACE_TIMEOUT_MS 15000
#define TRACE_STOP_LIMIT 20000
#define MAX_GUEST_MOUNTS 32
#define SCRATCH_BELOW_SP 8192u
#define ARM_SYSCALL_STOP (SIGTRAP | 0x80)
#define MAX_TRACE_LINES 160
#define MAX_BROKER_DENIAL_DIAGNOSTICS 24u
#define MAX_EXEC_FAILURE_DIAGNOSTICS 16u
#define GUEST_DIAGNOSTIC_TEXT_CAPACITY 512u
#define MAX_SIGSYS_CONTEXT_DIAGNOSTICS 16u
#define MAX_SIGPROCMASK_DIAGNOSTICS 16u
#define VIRTUAL_FD_BASE GUEST_VSOCKET_FD_BASE
#define MAX_VIRTUAL_FDS GUEST_VSOCKET_MAX_FDS
#define MAX_TRACEES 32
#define GUEST_LINKER_FD 198

struct compat_pt_regs { uint32_t uregs[18]; };
struct guest_mount { char target[PATH_MAX]; char backing[PATH_MAX]; };
struct tracee_state {
    pid_t pid;
    pid_t guest_pid;
    pid_t guest_tid;
    pid_t guest_parent_pid;
    uint32_t guest_pgid;
    uint32_t virtual_fd_table_id;
    unsigned long clone_flags;
    uint64_t virtual_fd_mask;
    uint8_t virtual_fd_flags[MAX_VIRTUAL_FDS];
    uint32_t guest_ruid;
    uint32_t guest_euid;
    uint32_t guest_rgid;
    uint32_t guest_egid;
    int alive;
    int is_thread;
    int guest_reaped;
    int expect_exit;
    int pending;
    int needs_options;
    int last_syscall;
    int exec_was_dynamic;
    int exec_was_script;
    int32_t pending_return;
    struct broker_sigsys_candidate broker_sigsys;
    unsigned int poll_diagnostic_count;
    uint32_t last_syscall_args[6];
    char guest_cwd[GUEST_PATH_FD_PATH_CAPACITY];
    char last_guest_path[PATH_MAX];
    char exec_target[PATH_MAX];
    char pending_exec_target[PATH_MAX];
    char exec_script_path[PATH_MAX];
    char pending_exec_script[PATH_MAX];
    int sigaction_compat_pending;
    uint32_t sigaction_compat_old_address;
    uint32_t sigaction_compat_rt_old_address;
    int target_elf_text_seen;
    uint32_t target_elf_text_pc;
    uint64_t target_elf_text_file_offset;
};
enum pending_kind { PENDING_NONE, PENDING_RESULT };

static pid_t traced_pid = -1;
static char guest_root[PATH_MAX];
static char native_guest_root[PATH_MAX];
static const char *guest_program = "/init";
static long trace_timeout_ms = TRACE_TIMEOUT_MS;
static struct guest_mount mounts[MAX_GUEST_MOUNTS];
static size_t mount_count;
static unsigned long syscall_stops;
static unsigned long denied_count;
static unsigned long broker_denial_diagnostics_emitted;
static unsigned long broker_denial_diagnostics_suppressed;
static unsigned long exec_failure_diagnostics_emitted;
static unsigned long exec_failure_diagnostics_suppressed;
static unsigned long sigsys_context_diagnostics_emitted;
static unsigned long sigsys_context_diagnostics_suppressed;
static unsigned long guest_sigprocmask_compat_calls;
static unsigned long guest_sigprocmask_diagnostics_emitted;
static unsigned long guest_sigprocmask_diagnostics_suppressed;
static unsigned long guest_sigprocmask_ptrace_failures;
static unsigned long path_rewrites;
static unsigned long guest_target_path_opens;
static unsigned long virtual_mount_count;
static unsigned long virtual_device_count;
static unsigned long virtual_identity_count;
static unsigned long virtual_file_ops;
static unsigned long virtual_symlink_ops;
static unsigned long virtual_socket_calls;
static unsigned long virtual_poll_waits;
static unsigned long virtual_network_socket_count;
static unsigned long virtual_network_ioctl_count;
static unsigned long virtual_network_ioctl_rejected_count;
static unsigned long virtual_pseudo_device_open_count;
static unsigned long virtual_pseudo_device_io_count;
static unsigned long unsupported_guest_device_open_count;
static unsigned long blocked_process_count;
static unsigned long process_events;
static unsigned long successful_guest_execs;
static unsigned long dynamic_exec_allowed_count;
static unsigned long dynamic_exec_started_count;
static unsigned long guest_script_routes_approved;
static unsigned long guest_script_exec_started_count;
static unsigned long brokered_sigsys_suppressed;
static struct guest_vsocket_table guest_sockets;
static unsigned long virtual_property_bind_count;
static unsigned long virtual_property_socket_count;
static unsigned long virtual_property_connect_count;
static unsigned long virtual_property_accept_count;
static unsigned long virtual_socketpair_count;
static unsigned long virtual_socket_rejected_count;
static int virtual_uevent_fd = -1;
static int virtual_uevent_bound;
static unsigned long virtual_uevent_socket_count;
static unsigned long virtual_uevent_bind_count;
static unsigned long virtual_uevent_setsockopt_count;
static unsigned long virtual_uevent_write_count;
static unsigned long virtual_uevent_recvmsg_count;
static int virtual_uevent_passcred;
static int virtual_uevent_rcvbuf_configured;
static struct guest_uevent_queue guest_uevent_queue;
static struct guest_coldboot_observation coldboot_observation;
static struct guest_network_state guest_network_state;
static struct guest_path_fd_table guest_path_fds;
static struct guest_arm32_timezone guest_timezone;
static unsigned long guest_sigaction_compat_calls;
static unsigned long guest_sigaction_compat_failures;
static unsigned long guest_setpgid_calls;
static unsigned long guest_timezone_calls;
static unsigned long guest_target_elf_text_entry_count;
static unsigned long guest_shell_elf_text_entry_count;
static unsigned long guest_app_process_elf_text_entry_count;
static int saw_exec;
static int trace_timed_out;
static volatile sig_atomic_t user_cancel_requested;
static int trace_cancelled;
static int trace_cleanup_confirmed;
static size_t trace_cleanup_unresolved;
static int guest_root_readonly;
static int guest_system_readonly;
static struct tracee_state tracees[MAX_TRACEES];
static size_t tracee_count;
static size_t active_tracee_count;
static pid_t next_guest_pid = 2;
static pid_t next_guest_tid = 2;
static uint32_t next_virtual_fd_table_id = 2;
static struct tracee_state *active_tracee;
static int dynamic_exec_blocked;
static int process_limit_hit;
static char dynamic_exec_guest_path[PATH_MAX];
static char dynamic_exec_interpreter[PATH_MAX];
static void cancel_signal_handler(int signo) {
    if (signo == SIGTERM || signo == SIGINT) user_cancel_requested = 1;
}
static int install_cancel_signal_handlers(void) {
    struct sigaction action;
    memset(&action, 0, sizeof(action));
    action.sa_handler = cancel_signal_handler;
    sigemptyset(&action.sa_mask);
    action.sa_flags = 0;
    return sigaction(SIGTERM, &action, NULL) == 0 &&
           sigaction(SIGINT, &action, NULL) == 0 ? 0 : -1;
}
static int get_regs(pid_t pid, struct compat_pt_regs *regs) {
    struct iovec iov = { .iov_base = regs, .iov_len = sizeof(*regs) };
    return ptrace(PTRACE_GETREGSET, pid, (void *)(uintptr_t)NT_PRSTATUS, &iov) == 0 &&
           iov.iov_len == sizeof(*regs) ? 0 : -1;
}

static int set_regs(pid_t pid, const struct compat_pt_regs *regs) {
    struct iovec iov = { .iov_base = (void *)regs, .iov_len = sizeof(*regs) };
    return ptrace(PTRACE_SETREGSET, pid, (void *)(uintptr_t)NT_PRSTATUS, &iov) == 0 &&
           iov.iov_len == sizeof(*regs) ? 0 : -1;
}

static int set_kernel_syscall(pid_t pid, int32_t number) {
    struct iovec iov = { .iov_base = &number, .iov_len = sizeof(number) };
    return ptrace(PTRACE_SETREGSET, pid, (void *)(uintptr_t)NT_ARM_SYSTEM_CALL, &iov) == 0 ? 0 : -1;
}

static int read_remote(pid_t pid, uint32_t address, void *out, size_t length) {
    unsigned char *dst = out;
    size_t copied = 0;
    while (copied < length) {
        uint32_t at = address + (uint32_t)copied;
        uint32_t aligned = at & ~((uint32_t)sizeof(long) - 1u);
        size_t offset = (size_t)(at - aligned);
        errno = 0;
        long word = ptrace(PTRACE_PEEKDATA, pid, (void *)(uintptr_t)aligned, NULL);
        if (word == -1 && errno != 0) return -1;
        unsigned char bytes[sizeof(long)];
        memcpy(bytes, &word, sizeof(word));
        size_t take = sizeof(long) - offset;
        if (take > length - copied) take = length - copied;
        memcpy(dst + copied, bytes + offset, take);
        copied += take;
    }
    return 0;
}

static int write_remote(pid_t pid, uint32_t address, const void *data, size_t length) {
    const unsigned char *src = data;
    size_t copied = 0;
    while (copied < length) {
        uint32_t at = address + (uint32_t)copied;
        uint32_t aligned = at & ~((uint32_t)sizeof(long) - 1u);
        size_t offset = (size_t)(at - aligned);
        errno = 0;
        long word = ptrace(PTRACE_PEEKDATA, pid, (void *)(uintptr_t)aligned, NULL);
        if (word == -1 && errno != 0) return -1;
        unsigned char bytes[sizeof(long)];
        memcpy(bytes, &word, sizeof(word));
        size_t take = sizeof(long) - offset;
        if (take > length - copied) take = length - copied;
        memcpy(bytes + offset, src + copied, take);
        memcpy(&word, bytes, sizeof(word));
        if (ptrace(PTRACE_POKEDATA, pid, (void *)(uintptr_t)aligned,
                   (void *)(uintptr_t)(unsigned long)word) != 0) return -1;
        copied += take;
    }
    return 0;
}

struct guest_sigmask_trace_context { pid_t pid; };

static int guest_sigmask_read_u32(void *opaque, uintptr_t address, uint32_t *value) {
    struct guest_sigmask_trace_context *context = opaque;
    if (!context || !value || address > UINT32_MAX ||
        (uint64_t)address + sizeof(*value) - 1u > UINT32_MAX) {
        errno = EFAULT;
        return -1;
    }
    return read_remote(context->pid, (uint32_t)address, value, sizeof(*value));
}

static int guest_sigmask_write_u32(void *opaque, uintptr_t address, uint32_t value) {
    struct guest_sigmask_trace_context *context = opaque;
    if (!context || address > UINT32_MAX ||
        (uint64_t)address + sizeof(value) - 1u > UINT32_MAX) {
        errno = EFAULT;
        return -1;
    }
    return write_remote(context->pid, (uint32_t)address, &value, sizeof(value));
}

static int guest_sigmask_get(void *opaque, uint64_t *mask) {
    struct guest_sigmask_trace_context *context = opaque;
    if (!context) { errno = EINVAL; return -1; }
    return guest_sigmask_ptrace_get(context->pid, mask);
}

static int guest_sigmask_set(void *opaque, uint64_t mask) {
    struct guest_sigmask_trace_context *context = opaque;
    if (!context) { errno = EINVAL; return -1; }
    return guest_sigmask_ptrace_set(context->pid, mask);
}

static int mediate_guest_sigprocmask(pid_t pid, struct tracee_state *state,
                                     const struct compat_pt_regs *regs,
                                     int32_t *guest_result) {
    struct guest_sigmask_trace_context context = { .pid = pid };
    const struct guest_sigprocmask_ops ops = {
        .context = &context,
        .read_u32 = guest_sigmask_read_u32,
        .write_u32 = guest_sigmask_write_u32,
        .get_mask = guest_sigmask_get,
        .set_mask = guest_sigmask_set,
    };
    struct guest_sigprocmask_report report;
    guest_sigprocmask_compat_calls++;
    if (guest_sigprocmask_compat_apply(&ops, (int32_t)regs->uregs[0],
            (uintptr_t)regs->uregs[1], (uintptr_t)regs->uregs[2], &report) != 0) {
        guest_sigprocmask_ptrace_failures++;
        const char *request = report.internal_request == GUEST_SIGPROCMASK_PTRACE_GET
            ? "PTRACE_GETSIGMASK" : report.internal_request == GUEST_SIGPROCMASK_PTRACE_SET
                ? "PTRACE_SETSIGMASK" : "broker-configuration";
        int saved_errno = report.internal_errno ? report.internal_errno : errno;
        fprintf(stderr,
                "GUEST SIGPROCMASK PTRACE FAILURE: host-pid=%d guest-pid=%d syscall=126 how=%d set=0x%08x oldset=0x%08x request=%s errno=%d(%s); refusing fake success\n",
                pid, state ? state->guest_pid : 0, (int32_t)regs->uregs[0],
                regs->uregs[1], regs->uregs[2], request, saved_errno,
                guest_diag_errno_name(saved_errno));
        errno = saved_errno ? saved_errno : EIO;
        return -1;
    }
    *guest_result = report.result;
    if (guest_sigprocmask_diagnostics_emitted >= MAX_SIGPROCMASK_DIAGNOSTICS) {
        guest_sigprocmask_diagnostics_suppressed++;
        return 0;
    }
    guest_sigprocmask_diagnostics_emitted++;
    int guest_errno = report.result < 0 ? -report.result : 0;
    printf("GUEST SIGPROCMASK COMPAT: host-pid=%d guest-pid=%d syscall=126 how=%d set=0x%08x oldset=0x%08x requested=0x%08x result=%d errno=%d(%s) mask-read=%d mask-before=0x%016llx mask-after=0x%016llx real-mask-update=%d oldset-write=%d mechanism=PTRACE_GETSIGMASK%s\n",
           pid, state ? state->guest_pid : 0, report.how,
           regs->uregs[1], regs->uregs[2], report.requested_set,
           report.result, guest_errno, guest_diag_errno_name(guest_errno),
           report.mask_read, (unsigned long long)report.mask_before,
           (unsigned long long)report.mask_after, report.mask_written,
           report.old_set_written, report.mask_written ? "/SETSIGMASK" : "");
    return 0;
}

static int mediate_guest_sigaction(pid_t pid, struct tracee_state *state,
                                   struct compat_pt_regs *regs,
                                   int32_t *guest_error, int *forward) {
    if (!state || !regs || !guest_error || !forward) return -1;
    *forward = 0;
    uint32_t action_address = regs->uregs[1];
    uint32_t old_action_address = regs->uregs[2];
    uint32_t sp = regs->uregs[13];
    if (sp <= SCRATCH_BELOW_SP + 96u) { *guest_error = -EFAULT; return 0; }
    uint32_t scratch = (sp - SCRATCH_BELOW_SP) & ~7u;
    if (scratch > UINT32_MAX - 96u) { *guest_error = -EFAULT; return 0; }

    struct guest_arm32_legacy_sigaction legacy_action;
    struct guest_arm32_rt_sigaction rt_action, rt_old_action;
    memset(&legacy_action, 0, sizeof(legacy_action));
    memset(&rt_action, 0, sizeof(rt_action));
    memset(&rt_old_action, 0, sizeof(rt_old_action));
    if (action_address) {
        if (read_remote(pid, action_address, &legacy_action, sizeof(legacy_action)) != 0) {
            *guest_error = -EFAULT;
            return 0;
        }
        if (guest_sigaction_legacy_to_rt(&legacy_action, &rt_action) != 0) {
            *guest_error = -EINVAL;
            return 0;
        }
        if (write_remote(pid, scratch, &rt_action, sizeof(rt_action)) != 0) {
            *guest_error = -EFAULT;
            return 0;
        }
    }
    uint32_t rt_old_address = scratch + 64u;
    if (old_action_address && write_remote(pid, rt_old_address, &rt_old_action,
                                           sizeof(rt_old_action)) != 0) {
        *guest_error = -EFAULT;
        return 0;
    }

    regs->uregs[1] = action_address ? scratch : 0;
    regs->uregs[2] = old_action_address ? rt_old_address : 0;
    regs->uregs[3] = GUEST_ARM32_RT_SIGSET_SIZE;
    regs->uregs[7] = ARM_NR_RT_SIGACTION;
    if (set_regs(pid, regs) != 0 || set_kernel_syscall(pid, ARM_NR_RT_SIGACTION) != 0)
        return -1;
    state->sigaction_compat_pending = 1;
    state->sigaction_compat_old_address = old_action_address;
    state->sigaction_compat_rt_old_address = rt_old_address;
    guest_sigaction_compat_calls++;
    *forward = 1;
    printf("GUEST SIGACTION COMPAT ENTER: host-pid=%d guest-pid=%d legacy-syscall=67 rt-syscall=174 signo=%d act=0x%08x oldact=0x%08x sigsetsize=%u mask-lowword-preserved=1 highword=0 app-seccomp-check=rt_sigaction\n",
           pid, state->guest_pid, (int32_t)state->last_syscall_args[0],
           action_address, old_action_address, GUEST_ARM32_RT_SIGSET_SIZE);
    return 0;
}

static int complete_guest_sigaction(pid_t pid, struct tracee_state *state,
                                    struct compat_pt_regs *regs,
                                    int32_t *syscall_result) {
    if (!state || !state->sigaction_compat_pending) return 0;
    int converted_old = 0;
    if (*syscall_result >= 0 && state->sigaction_compat_old_address) {
        struct guest_arm32_rt_sigaction rt_old_action;
        struct guest_arm32_legacy_sigaction legacy_old_action;
        if (read_remote(pid, state->sigaction_compat_rt_old_address,
                        &rt_old_action, sizeof(rt_old_action)) != 0 ||
            guest_sigaction_rt_to_legacy(&rt_old_action, &legacy_old_action) != 0 ||
            write_remote(pid, state->sigaction_compat_old_address,
                         &legacy_old_action, sizeof(legacy_old_action)) != 0) {
            guest_sigaction_compat_failures++;
            *syscall_result = -EFAULT;
            regs->uregs[0] = (uint32_t)-EFAULT;
            if (set_regs(pid, regs) != 0) return -1;
        } else {
            converted_old = 1;
        }
    }
    int result = *syscall_result;
    state->sigaction_compat_pending = 0;
    state->sigaction_compat_old_address = 0;
    state->sigaction_compat_rt_old_address = 0;
    printf("GUEST SIGACTION COMPAT EXIT: host-pid=%d guest-pid=%d syscall=67 via=174 result=%d errno=%d oldact-converted=%d genuine-SIGSYS-forwarding=unchanged\n",
           pid, state->guest_pid, result, result < 0 ? -result : 0, converted_old);
    return 0;
}

static int read_remote_string(pid_t pid, uint32_t address, char *out, size_t capacity) {
    if (capacity == 0) return -1;
    for (size_t i = 0; i < capacity; ++i) {
        if (read_remote(pid, address + (uint32_t)i, &out[i], 1) != 0) return -1;
        if (out[i] == '\0') return 0;
    }
    out[capacity - 1] = '\0';
    return -1;
}

static void log_broker_denial_detail(pid_t host_pid, const struct tracee_state *state,
                                    int nr, int32_t result, const char *guest_path,
                                    const char *reason, int exec_failure) {
    unsigned long *emitted = exec_failure ? &exec_failure_diagnostics_emitted
                                          : &broker_denial_diagnostics_emitted;
    unsigned long *suppressed = exec_failure ? &exec_failure_diagnostics_suppressed
                                             : &broker_denial_diagnostics_suppressed;
    unsigned long limit = exec_failure ? MAX_EXEC_FAILURE_DIAGNOSTICS
                                       : MAX_BROKER_DENIAL_DIAGNOSTICS;
    if (*emitted >= limit) {
        (*suppressed)++;
        return;
    }
    (*emitted)++;

    const char *exe = state && state->exec_target[0] ? state->exec_target : "<unknown>";
    const char *path = guest_path && guest_path[0] ? guest_path
        : state && state->last_guest_path[0] ? state->last_guest_path : "<not-decoded>";
    char safe_exe[GUEST_DIAGNOSTIC_TEXT_CAPACITY];
    char safe_path[GUEST_DIAGNOSTIC_TEXT_CAPACITY];
    int exe_truncated = guest_diag_escape(exe, safe_exe, sizeof(safe_exe));
    int path_truncated = guest_diag_escape(path, safe_path, sizeof(safe_path));
    uint32_t args[6] = {0, 0, 0, 0, 0, 0};
    if (state) memcpy(args, state->last_syscall_args, sizeof(args));
    int error_number = result < 0 ? -result : 0;

    fprintf(stderr,
            "%s: host-pid=%d guest-pid=%d guest-executable=\"%s\" syscall=%d(%s) "
            "args=0x%08x,0x%08x,0x%08x,0x%08x,0x%08x,0x%08x path=\"%s\" "
            "result=%d errno=%d(%s) reason=%s truncated=%d,%d\n",
            exec_failure ? "GUEST EXEC FAILURE DETAIL" : "BROKER DENIED DETAIL",
            host_pid, state ? state->guest_pid : 0, safe_exe, nr,
            guest_diag_syscall_name(nr), args[0], args[1], args[2], args[3], args[4], args[5],
            safe_path, result, error_number, guest_diag_errno_name(error_number),
            reason ? reason : "unspecified", exe_truncated, path_truncated);
}

static void log_unbrokered_seccomp_sigsys_context(
        pid_t host_pid, const struct tracee_state *state, int siginfo_code,
        int sigsys_syscall, unsigned int sigsys_arch, void *sigsys_call_addr,
        const struct compat_pt_regs *regs, int regs_rc) {
    if (sigsys_context_diagnostics_emitted >= MAX_SIGSYS_CONTEXT_DIAGNOSTICS) {
        sigsys_context_diagnostics_suppressed++;
        return;
    }
    sigsys_context_diagnostics_emitted++;

    const char *exe = state && state->exec_target[0] ? state->exec_target : "<unknown>";
    const char *script = state && state->exec_script_path[0]
        ? state->exec_script_path : "<none>";
    char safe_exe[GUEST_DIAGNOSTIC_TEXT_CAPACITY];
    char safe_script[GUEST_DIAGNOSTIC_TEXT_CAPACITY];
    char safe_module[GUEST_DIAGNOSTIC_TEXT_CAPACITY];
    int exe_truncated = guest_diag_escape(exe, safe_exe, sizeof(safe_exe));
    int script_truncated = guest_diag_escape(script, safe_script, sizeof(safe_script));

    uint32_t live[6] = {0, 0, 0, 0, 0, 0};
    uint32_t live_r7 = UINT32_MAX;
    uint32_t live_pc = (uint32_t)(uintptr_t)sigsys_call_addr;
    if (regs_rc == 0 && regs) {
        for (size_t i = 0; i < 6; ++i) live[i] = regs->uregs[i];
        live_r7 = regs->uregs[7];
        live_pc = regs->uregs[15];
    }

    struct guest_diag_proc_map mapping;
    memset(&mapping, 0, sizeof(mapping));
    int map_rc = guest_diag_find_proc_map(host_pid, live_pc, &mapping);
    const char *module = map_rc == 0 ? mapping.path : "<unresolved>";
    int module_truncated = guest_diag_escape(module, safe_module, sizeof(safe_module));
    uint64_t module_offset = map_rc == 0
        ? guest_diag_proc_map_file_offset(&mapping, live_pc) : UINT64_MAX;
    int seccomp_mode = guest_diag_read_proc_seccomp_mode(host_pid);
    int candidate_syscall = state ? state->broker_sigsys.syscall_number : -1;
    int candidate_committed = state ? state->broker_sigsys.response_committed : 0;
    int candidate_armed = state ? state->broker_sigsys.armed : 0;
    int last_syscall = state ? state->last_syscall : -1;
    uint32_t last_args[6] = {0, 0, 0, 0, 0, 0};
    if (state) memcpy(last_args, state->last_syscall_args, sizeof(last_args));

    printf("GUEST SIGSYS CONTEXT: origin=SYS_SECCOMP host-pid=%d guest-pid=%d guest-executable=\"%s\" guest-script=\"%s\" "
           "si-code=%d si-syscall=%d(%s) si-arch=0x%08x si-call-addr=0x%08x "
           "candidate=%d response-committed=%d candidate-syscall=%d(%s) "
           "last-syscall=%d(%s) last-args=%u,%u,%u,%u,%u,%u "
           "live-r0=%u live-r1=%u live-r2=%u live-r3=%u live-r4=%u live-r5=%u live-r7=%u live-pc=0x%08x regs-rc=%d "
           "tracee-seccomp-mode=%d pc-map-rc=%d map=0x%llx-0x%llx perms=%s module-offset=0x%llx mapped-module=\"%s\" truncated=%d,%d,%d\n",
           host_pid, state ? state->guest_pid : 0, safe_exe, safe_script,
           siginfo_code, sigsys_syscall, guest_diag_syscall_name(sigsys_syscall),
           sigsys_arch, (uint32_t)(uintptr_t)sigsys_call_addr,
           candidate_armed, candidate_committed, candidate_syscall,
           guest_diag_syscall_name(candidate_syscall), last_syscall,
           guest_diag_syscall_name(last_syscall), last_args[0], last_args[1],
           last_args[2], last_args[3], last_args[4], last_args[5],
           live[0], live[1], live[2], live[3], live[4], live[5], live_r7,
           live_pc, regs_rc, seccomp_mode, map_rc,
           (unsigned long long)mapping.start, (unsigned long long)mapping.end,
           map_rc == 0 ? mapping.permissions : "----",
           (unsigned long long)module_offset, safe_module,
           exe_truncated, script_truncated, module_truncated || mapping.path_truncated);
}

static int guest_exec_failure(const char **failure_reason, const char *reason, int result) {
    if (failure_reason) *failure_reason = reason;
    return result;
}

static int mkdir_p(const char *path) {
    char copy[PATH_MAX];
    if (strlen(path) >= sizeof(copy)) return -ENAMETOOLONG;
    strcpy(copy, path);
    for (char *p = copy + 1; *p; ++p) {
        if (*p != '/') continue;
        *p = '\0';
        if (mkdir(copy, 0700) != 0 && errno != EEXIST) return -errno;
        *p = '/';
    }
    if (mkdir(copy, 0700) != 0 && errno != EEXIST) return -errno;
    return 0;
}

static int path_is_within(const char *path, const char *root) {
    size_t n = strlen(root);
    return strncmp(path, root, n) == 0 && (path[n] == '\0' || path[n] == '/');
}

static int guest_path_uses_native_payload(const char *guest) {
    static const char *const roots[] = {"/system/lib", "/system/bin", "/system/xbin", NULL};
    for (size_t i = 0; roots[i]; ++i) {
        size_t n = strlen(roots[i]);
        if (strncmp(guest, roots[i], n) == 0 && (guest[n] == '\0' || guest[n] == '/')) return 1;
    }
    return 0;
}

static int map_guest_physical_path(const char *guest, const char *mapped_guest,
                                   char *host, size_t capacity) {
    int rc = guest_path_to_host(guest_root, mapped_guest, host, capacity);
    if (rc != -EACCES || !guest_path_uses_native_payload(guest)) return rc;
    char candidate[PATH_MAX], resolved[PATH_MAX];
    int n = snprintf(candidate, sizeof(candidate), "%s%s", guest_root, mapped_guest);
    if (n <= 0 || (size_t)n >= sizeof(candidate) || !realpath(candidate, resolved) ||
        !path_is_within(resolved, native_guest_root)) return -EACCES;
    n = snprintf(host, capacity, "%s", resolved);
    return n > 0 && (size_t)n < capacity ? 0 : -ENAMETOOLONG;
}

static int map_guest_path(const char *guest, char *host, size_t capacity) {
    if (!guest || guest[0] != '/' || guest_path_has_parent(guest)) return -EACCES;
    const struct guest_mount *best = NULL;
    size_t best_len = 0;
    for (size_t i = 0; i < mount_count; ++i) {
        size_t n = strlen(mounts[i].target);
        if (n > best_len && strncmp(guest, mounts[i].target, n) == 0 &&
            (guest[n] == '\0' || guest[n] == '/')) {
            best = &mounts[i];
            best_len = n;
        }
    }
    char mapped[PATH_MAX];
    int n;
    if (best) {
        const char *suffix = guest + best_len;
        if (*suffix == '\0') suffix = "/";
        n = snprintf(mapped, sizeof(mapped), "%s%s", best->backing, suffix);
        if (n <= 0 || (size_t)n >= sizeof(mapped)) return -ENAMETOOLONG;
        /* Mount backing is an ordinary directory under guest_root; validate it too. */
        return map_guest_physical_path(guest, mapped + strlen(guest_root), host, capacity);
    }
    return map_guest_physical_path(guest, guest, host, capacity);
}

static int guest_path_lexical_host(const char *guest, char *host, size_t capacity) {
    if (!guest || guest[0] != '/' || guest_path_has_parent(guest) || !host || capacity == 0)
        return -EACCES;
    const struct guest_mount *best = NULL;
    size_t best_length = 0;
    for (size_t i = 0; i < mount_count; ++i) {
        size_t length = strlen(mounts[i].target);
        if (length > best_length && strncmp(guest, mounts[i].target, length) == 0 &&
            (guest[length] == '\0' || guest[length] == '/')) {
            best = &mounts[i];
            best_length = length;
        }
    }
    const char *base = best ? best->backing : guest_root;
    const char *suffix = best ? guest + best_length : guest;
    if (*suffix == '\0') suffix = "/";
    int n = snprintf(host, capacity, "%s%s", base, suffix);
    if (n <= 0 || (size_t)n >= capacity) return -ENAMETOOLONG;
    return path_is_within(host, guest_root) ? 0 : -EACCES;
}

static int guest_pseudo_device_backing_present(const char *guest) {
    char host[PATH_MAX], parent[PATH_MAX];
    int rc = guest_path_lexical_host(guest, host, sizeof(host));
    if (rc != 0) return rc;
    if (strlen(host) >= sizeof(parent)) return -ENAMETOOLONG;
    strcpy(parent, host);
    char *slash = strrchr(parent, '/');
    if (!slash || slash == parent || !slash[1]) return -EACCES;
    char leaf[NAME_MAX + 1];
    size_t leaf_length = strlen(slash + 1);
    if (leaf_length == 0 || leaf_length > NAME_MAX) return -ENAMETOOLONG;
    memcpy(leaf, slash + 1, leaf_length + 1u);
    *slash = '\0';
    int fd = guest_safe_file_open_beneath_root(guest_root, parent, leaf, 0, 0600);
    if (fd < 0) return fd;
    return close(fd) == 0 ? 0 : -errno;
}

static void observe_guest_target_elf_text(pid_t host_pid,
                                          struct tracee_state *state,
                                          const struct compat_pt_regs *regs) {
    if (!state || !regs || state->target_elf_text_seen || !state->exec_target[0]) return;
    uint32_t pc = regs->uregs[15] & ~1u;
    struct guest_diag_proc_map mapping;
    memset(&mapping, 0, sizeof(mapping));
    if (guest_diag_find_proc_map(host_pid, pc, &mapping) != 0) return;
    char expected[PATH_MAX], canonical_expected[PATH_MAX];
    if (map_guest_path(state->exec_target, expected, sizeof(expected)) != 0) return;
    int match = guest_entry_mapping_matches(mapping.path, expected, mapping.permissions);
    if (!match && realpath(expected, canonical_expected))
        match = guest_entry_mapping_matches(mapping.path, canonical_expected, mapping.permissions);
    if (!match) return;
    state->target_elf_text_seen = 1;
    state->target_elf_text_pc = pc;
    state->target_elf_text_file_offset = guest_diag_proc_map_file_offset(&mapping, pc);
    guest_target_elf_text_entry_count++;
    if (strcmp(state->exec_target, GUEST_API10_SHELL_PATH) == 0)
        guest_shell_elf_text_entry_count++;
    if (strcmp(state->exec_target, "/system/bin/app_process") == 0)
        guest_app_process_elf_text_entry_count++;
    char safe_target[GUEST_DIAGNOSTIC_TEXT_CAPACITY];
    char safe_module[GUEST_DIAGNOSTIC_TEXT_CAPACITY];
    int target_truncated = guest_diag_escape(state->exec_target, safe_target, sizeof(safe_target));
    int module_truncated = guest_diag_escape(mapping.path, safe_module, sizeof(safe_module));
    printf("GUEST TARGET ELF TEXT ENTRY: host-pid=%d guest-pid=%d target=\"%s\" pc=0x%08x map=0x%llx-0x%llx perms=%s file-offset=0x%llx module=\"%s\"; target ELF code reached after linker; C main() symbol is not inferred truncated=%d,%d\n",
           host_pid, state->guest_pid, safe_target, pc,
           (unsigned long long)mapping.start, (unsigned long long)mapping.end,
           mapping.permissions, (unsigned long long)state->target_elf_text_file_offset,
           safe_module, target_truncated, module_truncated || mapping.path_truncated);
}

static int map_guest_symlink_target(const char *target, char *host, size_t capacity) {
    if (target && strcmp(target, "/system") == 0) {
        return map_guest_physical_path(target, "/.images/system", host, capacity);
    }
    if (target && strncmp(target, "/system/", 8) == 0) {
        char backing_path[PATH_MAX];
        int n = snprintf(backing_path, sizeof(backing_path), "/.images/system%s", target + 7);
        if (n <= 0 || (size_t)n >= sizeof(backing_path)) return -ENAMETOOLONG;
        return map_guest_physical_path(target, backing_path, host, capacity);
    }
    return map_guest_path(target, host, capacity);
}

static int syscall_path_uses_dirfd(int nr) {
    switch (nr) {
        case ARM_NR_OPENAT: case ARM_NR_MKDIRAT: case ARM_NR_MKNODAT:
        case ARM_NR_FCHOWNAT: case ARM_NR_FSTATAT64: case ARM_NR_UNLINKAT:
        case ARM_NR_READLINKAT: case ARM_NR_FCHMODAT: case ARM_NR_FACCESSAT:
            return 1;
        default:
            return 0;
    }
}

static int decode_guest_path_arg(pid_t pid, struct compat_pt_regs *regs, int nr,
                                 unsigned arg, char *guest_out, size_t guest_capacity) {
    char raw[PATH_MAX];
    if (arg >= 6 || read_remote_string(pid, regs->uregs[arg], raw, sizeof(raw)) != 0)
        return -EFAULT;
    struct tracee_state *state = active_tracee && active_tracee->pid == pid
        ? active_tracee : NULL;
    if (!state)
        return guest_path_normalize(raw, guest_out, guest_capacity);
    int dirfd = GUEST_AT_FDCWD;
    if (syscall_path_uses_dirfd(nr)) {
        if (arg == 0) return -EINVAL;
        dirfd = (int32_t)regs->uregs[arg - 1u];
    }
    return guest_path_resolve_at(&guest_path_fds, (pid_t)state->virtual_fd_table_id,
                                 dirfd, state->guest_cwd, raw,
                                 guest_out, guest_capacity);
}

static int rewrite_path_arg(pid_t pid, struct compat_pt_regs *regs, unsigned arg,
                            char *guest_out, size_t guest_capacity) {
    int nr = active_tracee && active_tracee->pid == pid ? active_tracee->last_syscall : -1;
    int rc = decode_guest_path_arg(pid, regs, nr, arg, guest_out, guest_capacity);
    if (rc != 0) return rc;
    char host[PATH_MAX];
    rc = map_guest_path(guest_out, host, sizeof(host));
    if (rc != 0) return rc;
    size_t bytes = strlen(host) + 1;
    if (bytes >= 2048) return -ENAMETOOLONG;
    uint32_t scratch = (regs->uregs[13] - SCRATCH_BELOW_SP) & ~((uint32_t)sizeof(long) - 1u);
    if (write_remote(pid, scratch, host, bytes) != 0) return -EFAULT;
    regs->uregs[arg] = scratch;
    path_rewrites++;
    if (active_tracee && (active_tracee->last_syscall == 5 || active_tracee->last_syscall == 322) &&
        strcmp(guest_out, guest_program) == 0)
        guest_target_path_opens++;
    return 0;
}

static int fake_syscall(pid_t pid, struct compat_pt_regs *regs) {
    regs->uregs[7] = UINT32_MAX;
    if (set_regs(pid, regs) != 0 || set_kernel_syscall(pid, -1) != 0) return -1;
    return 0;
}

static int resume_trace(pid_t pid, int signal_number) {
    return ptrace(PTRACE_SYSCALL, pid, NULL,
                  (void *)(uintptr_t)(unsigned int)signal_number) == 0 ? 0 : -1;
}

static int make_guest_device(const char *guest) {
    char host[PATH_MAX];
    int rc = map_guest_path(guest, host, sizeof(host));
    if (rc != 0) return rc;
    if (!path_is_within(host, guest_root)) return -EACCES;
    char parent[PATH_MAX];
    if (strlen(host) >= sizeof(parent)) return -ENAMETOOLONG;
    strcpy(parent, host);
    char *slash = strrchr(parent, '/');
    if (!slash || slash == parent) return -EACCES;
    char *leaf = slash + 1;
    if (!*leaf) return -EACCES;
    *slash = '\0';
    int fd = guest_safe_file_open_beneath_root(guest_root, parent, leaf, 0, 0600);
    if (fd < 0) return fd;
    return close(fd) == 0 ? 0 : -errno;
}

static int seed_regular_file(const char *dir, const char *name, const char *contents) {
    if (!contents) return -EINVAL;
    return guest_safe_file_replace_beneath_root(guest_root, dir, name,
                                                 contents, strlen(contents), 0600);
}

static int seed_virtual_sysfs_tree(const char *backing) {
    static const char *const suffixes[] = {
        "class", "class/net", "block", "devices", "devices/virtual",
        "devices/virtual/net", "devices/virtual/net/eth0", NULL,
    };
    if (!backing) return -EACCES;
    int backing_fd = guest_safe_dir_open_beneath_root(guest_root, backing, 1, 0700);
    if (backing_fd < 0) return backing_fd;
    close(backing_fd);
    for (size_t i = 0; suffixes[i]; ++i) {
        char path[PATH_MAX];
        int n = snprintf(path, sizeof(path), "%s/%s", backing, suffixes[i]);
        if (n <= 0 || (size_t)n >= sizeof(path)) return -ENAMETOOLONG;
        int directory_fd = guest_safe_dir_open_beneath_root(guest_root, path, 1, 0700);
        if (directory_fd < 0) return directory_fd;
        close(directory_fd);
    }
    char class_net[PATH_MAX], device[PATH_MAX];
    int n = snprintf(class_net, sizeof(class_net), "%s/class/net", backing);
    if (n <= 0 || (size_t)n >= sizeof(class_net)) return -ENAMETOOLONG;
    int rc = guest_safe_symlink_beneath_root(guest_root, class_net, "eth0",
                                              "../../devices/virtual/net/eth0");
    if (rc != 0) return rc;
    n = snprintf(device, sizeof(device), "%s/devices/virtual/net/eth0", backing);
    if (n <= 0 || (size_t)n >= sizeof(device)) return -ENAMETOOLONG;
    return seed_regular_file(device, "operstate", "down\n");
}

static int seed_virtual_proc_tree(const char *backing) {
    char netdir[PATH_MAX];
    int n = snprintf(netdir, sizeof(netdir), "%s/net", backing);
    if (n <= 0 || (size_t)n >= sizeof(netdir)) return -ENAMETOOLONG;
    int net_fd = guest_safe_dir_open_beneath_root(guest_root, netdir, 1, 0700);
    if (net_fd < 0) return net_fd;
    close(net_fd);
    int rc = seed_regular_file(backing, "cmdline", GUEST_PROFILE_PROC_CMDLINE);
    if (rc != 0) return rc;
    rc = seed_regular_file(backing, "cpuinfo", GUEST_PROFILE_PROC_CPUINFO);
    if (rc != 0) return rc;
    rc = seed_regular_file(backing, "meminfo", GUEST_PROFILE_PROC_MEMINFO);
    if (rc != 0) return rc;
    rc = seed_regular_file(backing, "stat", GUEST_PROFILE_PROC_STAT);
    if (rc != 0) return rc;
    rc = seed_regular_file(netdir, "route",
        "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n");
    if (rc != 0) return rc;
    return seed_regular_file(netdir, "dev",
        "Inter-|   Receive                                                |  Transmit\n"
        " face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n"
        "    lo: 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n"
        "  eth0: 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n");
}

static int replace_guest_virtual_file(const char *guest_path, const char *contents) {
    char host_path[PATH_MAX];
    int rc = map_guest_path(guest_path, host_path, sizeof(host_path));
    if (rc != 0) return rc;
    if (!path_is_within(host_path, guest_root)) return -EACCES;
    char directory[PATH_MAX];
    if (strlen(host_path) >= sizeof(directory)) return -ENAMETOOLONG;
    strcpy(directory, host_path);
    char *slash = strrchr(directory, '/');
    if (!slash || slash == directory || !slash[1]) return -EACCES;
    char leaf[NAME_MAX + 1];
    size_t leaf_length = strlen(slash + 1);
    if (leaf_length > NAME_MAX) return -ENAMETOOLONG;
    memcpy(leaf, slash + 1, leaf_length + 1u);
    *slash = '\0';
    return guest_safe_file_replace_beneath_root(guest_root, directory, leaf,
                                                 contents, strlen(contents), 0600);
}

static int guest_network_sync_proc_route(void) {
    char text[512];
    int n;
    if (!guest_network_state.default_route_set) {
        n = snprintf(text, sizeof(text),
            "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n");
    } else {
        const uint8_t *g = guest_network_state.gateway;
        n = snprintf(text, sizeof(text),
            "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n"
            "%s\t00000000\t%02X%02X%02X%02X\t0003\t0\t0\t0\t00000000\t0\t0\t0\n",
            GUEST_PROFILE_NET_IFACE, g[3], g[2], g[1], g[0]);
    }
    if (n <= 0 || (size_t)n >= sizeof(text)) return -ENAMETOOLONG;
    return replace_guest_virtual_file("/proc/net/route", text);
}

static int guest_network_sync_operstate(void) {
    const char *state = (guest_network_state.flags & GUEST_NET_IFF_UP) ? "up\n" : "down\n";
    return replace_guest_virtual_file(
        "/sys/devices/virtual/net/eth0/operstate", state);
}

static int add_standalone_mount(const char *target, const char *backing) {
    struct stat st;
    if (stat(backing, &st) != 0 || !S_ISDIR(st.st_mode)) return -ENOENT;
    for (size_t i = 0; i < mount_count; ++i) {
        if (strcmp(mounts[i].target, target) == 0) {
            strcpy(mounts[i].backing, backing);
            virtual_mount_count++;
            return 0;
        }
    }
    if (mount_count >= MAX_GUEST_MOUNTS) return -ENOSPC;
    strcpy(mounts[mount_count].target, target);
    strcpy(mounts[mount_count].backing, backing);
    mount_count++;
    virtual_mount_count++;
    return 0;
}

static int prepare_standalone_guest(void) {
    char backing[6][PATH_MAX];
    static const char *const names[] = {"system", "dev", "proc", "sys", "data", "cache"};
    for (size_t i = 0; i < 6; ++i) {
        int n;
        if (i == 0) n = snprintf(backing[i], sizeof(backing[i]), "%s/.images/system", guest_root);
        else if (i == 4 || i == 5) n = snprintf(backing[i], sizeof(backing[i]), "%s/%s", guest_root, names[i]);
        else n = snprintf(backing[i], sizeof(backing[i]), "%s/.vfs/standalone-%s", guest_root, names[i]);
        if (n <= 0 || (size_t)n >= sizeof(backing[i])) return -ENAMETOOLONG;
        if (i != 0) {
            int directory_fd = guest_safe_dir_open_beneath_root(guest_root, backing[i], 1, 0700);
            if (directory_fd < 0) return directory_fd;
            close(directory_fd);
        }
        if (i == 3) {
            int rc = seed_virtual_sysfs_tree(backing[i]);
            if (rc != 0) return rc;
        } else if (i == 2) {
            int rc = seed_virtual_proc_tree(backing[i]);
            if (rc != 0) return rc;
        }
        char target[32];
        n = snprintf(target, sizeof(target), "/%s", names[i]);
        if (n <= 0 || (size_t)n >= sizeof(target)) return -ENAMETOOLONG;
        int rc = add_standalone_mount(target, backing[i]);
        if (rc != 0) return rc;
    }
    static const char *const devices[] = {"null", "zero", "random", "urandom", "kmsg",
        "__properties__", "binder", "ashmem", NULL};
    for (size_t i = 0; devices[i]; ++i) {
        int rc = seed_regular_file(backing[1], devices[i], "");
        if (rc != 0) return rc;
    }
    char logdir[PATH_MAX], sockets[PATH_MAX];
    int n = snprintf(logdir, sizeof(logdir), "%s/log", backing[1]);
    if (n <= 0 || (size_t)n >= sizeof(logdir)) return -ENAMETOOLONG;
    int log_fd = guest_safe_dir_open_beneath_root(guest_root, logdir, 1, 0700);
    if (log_fd < 0) return log_fd;
    close(log_fd);
    if (seed_regular_file(logdir, "main", "") != 0) return -EIO;
    n = snprintf(sockets, sizeof(sockets), "%s/socket", backing[1]);
    if (n <= 0 || (size_t)n >= sizeof(sockets)) return -ENAMETOOLONG;
    int sockets_fd = guest_safe_dir_open_beneath_root(guest_root, sockets, 1, 0700);
    if (sockets_fd < 0) return sockets_fd;
    close(sockets_fd);
    puts("VIRTUAL MOUNTS: standalone guest /system,/dev,/proc,/sys,/data,/cache use app-private software backings");
    return 0;
}

static int virtual_mount(pid_t pid, const struct compat_pt_regs *regs) {
    char source[128], target[PATH_MAX], type[128];
    if (read_remote_string(pid, regs->uregs[0], source, sizeof(source)) != 0 ||
        read_remote_string(pid, regs->uregs[1], target, sizeof(target)) != 0 ||
        read_remote_string(pid, regs->uregs[2], type, sizeof(type)) != 0) return -EFAULT;
    unsigned flags = regs->uregs[3];
    if (strcmp(source, "rootfs") == 0 && strcmp(target, "/") == 0 && strcmp(type, "rootfs") == 0) {
        if ((flags & (GUEST_MS_REMOUNT | GUEST_MS_RDONLY)) ==
            (GUEST_MS_REMOUNT | GUEST_MS_RDONLY)) {
            guest_root_readonly = 1;
            virtual_mount_count++;
            puts("VIRTUAL REMOUNT: guest rootfs is read-only; no host mount syscall called");
            return 0;
        }
        return -EPERM;
    }
    if (strcmp(type, "ext4") == 0) {
        const char *backing_suffix = NULL;
        if (!strcmp(source, "/dev/block/mtdblock0") && !strcmp(target, "/system"))
            backing_suffix = "/.images/system";
        else if (!strcmp(source, "/dev/block/mtdblock1") && !strcmp(target, "/data"))
            backing_suffix = "/data";
        else if (!strcmp(source, "/dev/block/mtdblock2") && !strcmp(target, "/cache"))
            backing_suffix = "/cache";
        else return -EPERM;
        if (!strcmp(target, "/system") && (flags & GUEST_MS_REMOUNT)) {
            int found = 0;
            for (size_t i = 0; i < mount_count; ++i)
                if (!strcmp(mounts[i].target, "/system")) found = 1;
            if (!found || (flags & ~(GUEST_MS_REMOUNT | GUEST_MS_RDONLY))) return -EINVAL;
            guest_system_readonly = (flags & GUEST_MS_RDONLY) != 0;
            virtual_mount_count++;
            puts("VIRTUAL REMOUNT: guest /system readonly state updated without host mount");
            return 0;
        }
        if (flags & GUEST_MS_REMOUNT) return -EINVAL;
        if (!strcmp(target, "/system") && flags != 0) return -EPERM;
        if ((!strcmp(target, "/data") || !strcmp(target, "/cache")) &&
            (flags & ~(GUEST_MS_NOSUID | GUEST_MS_NODEV))) return -EPERM;
        char mountpoint[PATH_MAX];
        int rc = guest_path_to_host(guest_root, target, mountpoint, sizeof(mountpoint));
        if (rc != 0) return rc;
        struct stat mountpoint_stat;
        if (stat(mountpoint, &mountpoint_stat) != 0 || !S_ISDIR(mountpoint_stat.st_mode)) return -ENOENT;
        char backing[PATH_MAX];
        int n = snprintf(backing, sizeof(backing), "%s%s", guest_root, backing_suffix);
        if (n <= 0 || (size_t)n >= sizeof(backing)) return -ENAMETOOLONG;
        struct stat image_stat;
        if (stat(backing, &image_stat) != 0 || !S_ISDIR(image_stat.st_mode)) return -ENOENT;
        rc = add_standalone_mount(target, backing);
        if (rc != 0) return rc;
        if (!strcmp(target, "/system")) guest_system_readonly = (flags & GUEST_MS_RDONLY) != 0;
        printf("VIRTUAL MOUNT: ext4 %s %s -> app-private guest backing; host mount syscall not called\n", source, target);
        return 0;
    }
    if (strcmp(type, "tmpfs") && strcmp(type, "proc") && strcmp(type, "sysfs") &&
        strcmp(type, "devpts") && strcmp(type, "cgroup")) return -EPERM;
    if (mount_count >= MAX_GUEST_MOUNTS || target[0] != '/' || guest_path_has_parent(target))
        return -ENOSPC;
    char target_host[PATH_MAX];
    int rc = map_guest_path(target, target_host, sizeof(target_host));
    if (rc != 0) return rc;
    struct stat st;
    if (stat(target_host, &st) != 0 || !S_ISDIR(st.st_mode)) return -ENOENT;
    char backing[PATH_MAX];
    int n = snprintf(backing, sizeof(backing), "%s/.vfs/mount-%zu", guest_root, mount_count);
    if (n <= 0 || (size_t)n >= sizeof(backing)) return -ENAMETOOLONG;
    int backing_fd = guest_safe_dir_open_beneath_root(guest_root, backing, 1, 0700);
    if (backing_fd < 0) return backing_fd;
    close(backing_fd);
    if (strcmp(target, "/sys") == 0 && strcmp(type, "sysfs") == 0) {
        rc = seed_virtual_sysfs_tree(backing);
        if (rc != 0) return rc;
    }
    if (strcmp(target, "/dev") == 0) {
        char marker_path[PATH_MAX];
        int marker_len = snprintf(marker_path, sizeof(marker_path), "%s/.coldboot_done", backing);
        if (marker_len <= 0 || (size_t)marker_len >= sizeof(marker_path)) return -ENAMETOOLONG;
        if (unlink(marker_path) != 0 && errno != ENOENT) return -errno;
        memset(&coldboot_observation, 0, sizeof(coldboot_observation));
        guest_uevent_queue_init(&guest_uevent_queue);
        static const char *const devices[] = {"null", "zero", "full", "random", "urandom",
            "__properties__", "binder", "ashmem", NULL};
        for (size_t i = 0; devices[i]; ++i) {
            rc = seed_regular_file(backing, devices[i], "");
            if (rc != 0) return rc;
        }
        char logdir[PATH_MAX];
        n = snprintf(logdir, sizeof(logdir), "%s/log", backing);
        if (n <= 0 || (size_t)n >= sizeof(logdir)) return -ENAMETOOLONG;
        int log_fd = guest_safe_dir_open_beneath_root(guest_root, logdir, 1, 0700);
        if (log_fd < 0) return log_fd;
        close(log_fd);
        rc = seed_regular_file(logdir, "main", "");
        if (rc != 0) return rc;
        char sockets[PATH_MAX];
        n = snprintf(sockets, sizeof(sockets), "%s/socket", backing);
        if (n <= 0 || (size_t)n >= sizeof(sockets)) return -ENAMETOOLONG;
        int sockets_fd = guest_safe_dir_open_beneath_root(guest_root, sockets, 1, 0700);
        if (sockets_fd < 0) return sockets_fd;
        close(sockets_fd);
    } else if (strcmp(target, "/proc") == 0) {
        rc = seed_virtual_proc_tree(backing);
        if (rc != 0) return rc;
    }
    strcpy(mounts[mount_count].target, target);
    strcpy(mounts[mount_count].backing, backing);
    mount_count++;
    virtual_mount_count++;
    printf("VIRTUAL MOUNT: %s %s -> guest-only backing; host mount syscall not called\n",
           type, target);
    (void)source;
    return 0;
}

static int virtual_umount(pid_t pid, const struct compat_pt_regs *regs) {
    char target[PATH_MAX];
    if (read_remote_string(pid, regs->uregs[0], target, sizeof(target)) != 0) return -EFAULT;
    for (size_t i = mount_count; i > 0; --i) {
        if (strcmp(mounts[i - 1].target, target) != 0) continue;
        for (size_t j = i; j < mount_count; ++j) mounts[j - 1] = mounts[j];
        mount_count--;
        return 0;
    }
    return -EINVAL;
}

static int virtual_fd_slot(int fd) { return guest_vsocket_fd_slot(fd); }

static int is_virtual_fd_number(int fd) { return guest_vsocket_fd_number_reserved(fd); }

static int is_virtual_fd(int fd) {
    return guest_vsocket_fd_get(&guest_sockets, fd) != NULL;
}

static int tracee_owns_virtual_fd(const struct tracee_state *state, int fd) {
    int slot = virtual_fd_slot(fd);
    return state && slot >= 0 && (state->virtual_fd_mask & (UINT64_C(1) << (unsigned)slot)) != 0;
}

static void track_virtual_fd_for_group(struct tracee_state *owner, int fd) {
    int slot = virtual_fd_slot(fd);
    if (!owner || slot < 0) return;
    for (size_t i = 0; i < tracee_count; ++i) {
        struct tracee_state *state = &tracees[i];
        if (!state->alive || state->virtual_fd_table_id != owner->virtual_fd_table_id) continue;
        state->virtual_fd_mask |= UINT64_C(1) << (unsigned)slot;
        state->virtual_fd_flags[slot] = 0;
    }
}

static void set_virtual_fd_open_flags(struct tracee_state *owner, int fd,
                                      unsigned flags) {
    int slot = virtual_fd_slot(fd);
    if (!owner || slot < 0) return;
    struct guest_vsocket_fd *entry = guest_vsocket_fd_get(&guest_sockets, fd);
    if (!entry) return;
    entry->open_flags = flags;
    uint8_t descriptor_flags = (flags & O_CLOEXEC)
        ? GUEST_VSOCKET_FD_CLOEXEC : 0;
    for (size_t i = 0; i < tracee_count; ++i) {
        struct tracee_state *state = &tracees[i];
        if (state->alive && state->virtual_fd_table_id == owner->virtual_fd_table_id &&
            (state->virtual_fd_mask & (UINT64_C(1) << (unsigned)slot)))
            state->virtual_fd_flags[slot] = descriptor_flags;
    }
}

static int virtual_fd_referenced(int fd) {
    int slot = virtual_fd_slot(fd);
    if (slot < 0) return 0;
    uint64_t bit = UINT64_C(1) << (unsigned)slot;
    for (size_t i = 0; i < tracee_count; ++i)
        if (tracees[i].alive && (tracees[i].virtual_fd_mask & bit)) return 1;
    return 0;
}

static void clear_virtual_fd_group(struct tracee_state *owner, int slot) {
    if (!owner || slot < 0) return;
    uint64_t bit = UINT64_C(1) << (unsigned)slot;
    for (size_t i = 0; i < tracee_count; ++i) {
        struct tracee_state *state = &tracees[i];
        if (!state->alive || state->virtual_fd_table_id != owner->virtual_fd_table_id) continue;
        state->virtual_fd_mask &= ~bit;
        state->virtual_fd_flags[slot] = 0;
    }
}

static void release_virtual_fd_if_unreferenced(int fd);

static void close_virtual_fds_on_exec(struct tracee_state *state) {
    if (!state) return;
    uint64_t owned = state->virtual_fd_mask;
    for (int slot = 0; slot < MAX_VIRTUAL_FDS; ++slot) {
        uint64_t bit = UINT64_C(1) << (unsigned)slot;
        if (!(owned & bit) || !(state->virtual_fd_flags[slot] & GUEST_VSOCKET_FD_CLOEXEC))
            continue;
        clear_virtual_fd_group(state, slot);
        release_virtual_fd_if_unreferenced(VIRTUAL_FD_BASE + slot);
    }
}

static void release_virtual_fd_if_unreferenced(int fd) {
    if (virtual_fd_referenced(fd)) return;
    if (guest_vsocket_close_fd(&guest_sockets, fd) != 0) return;
    if (virtual_uevent_fd == fd) {
        virtual_uevent_fd = -1;
        virtual_uevent_bound = 0;
        virtual_uevent_passcred = 0;
        virtual_uevent_rcvbuf_configured = 0;
    }
}

static int close_virtual_fd(struct tracee_state *state, int fd) {
    if (!is_virtual_fd_number(fd)) return 1;
    if (!is_virtual_fd(fd) || !tracee_owns_virtual_fd(state, fd)) return -EBADF;
    clear_virtual_fd_group(state, virtual_fd_slot(fd));
    release_virtual_fd_if_unreferenced(fd);
    virtual_socket_calls++;
    return 0;
}

static int virtual_fd_fcntl(struct tracee_state *state, int fd, int command, int argument) {
    if (!is_virtual_fd_number(fd)) return 1;
    if (!is_virtual_fd(fd) || !tracee_owns_virtual_fd(state, fd)) return -EBADF;
    int slot = virtual_fd_slot(fd);
    int status_flags = 0;
    int descriptor_flags = state->virtual_fd_flags[slot];
    int result = guest_vsocket_fcntl(&guest_sockets, fd, command, argument,
                                    &status_flags, &descriptor_flags);
    if (result >= 0 && command == GUEST_VSOCKET_F_SETFD) {
        for (size_t i = 0; i < tracee_count; ++i) {
            struct tracee_state *peer = &tracees[i];
            if (peer->alive && peer->virtual_fd_table_id == state->virtual_fd_table_id &&
                (peer->virtual_fd_mask & (UINT64_C(1) << (unsigned)slot)))
                peer->virtual_fd_flags[slot] = (uint8_t)descriptor_flags;
        }
    }
    virtual_socket_calls++;
    return result;
}

static const char *virtual_fd_source(int fd) {
    if (fd < 0) return "negative descriptor (ignored by poll)";
    struct guest_vsocket_fd *entry = guest_vsocket_fd_get(&guest_sockets, fd);
    if (!entry) return is_virtual_fd_number(fd)
        ? "closed/invalid software descriptor; no host fd"
        : "untracked guest fd (path-backed/inherited provenance unavailable)";
    switch (entry->kind) {
        case VIRTUAL_FD_UEVENT: return "software AF_NETLINK/NETLINK_KOBJECT_UEVENT; no host fd";
        case VIRTUAL_FD_SYSFS_UEVENT: return "app-private synthetic sysfs uevent attribute; no host fd";
        case VIRTUAL_FD_PROPERTY: return entry->listening
            ? "software AF_UNIX property-service listener; no host socket"
            : "software AF_UNIX property-service endpoint; no host socket";
        case VIRTUAL_FD_PROPERTY_ACCEPTED: return "software AF_UNIX accepted property client; no host socket";
        case VIRTUAL_FD_SIGNAL: return "software AF_UNIX SIGCHLD socketpair; no host socket";
        case VIRTUAL_FD_DEV_NULL: return "guest /dev/null software stream; no host device";
        case VIRTUAL_FD_DEV_ZERO: return "guest /dev/zero software stream; no host device";
        case VIRTUAL_FD_DEV_KMSG: return "guest kmsg software sink; no host device";
        case VIRTUAL_FD_DEV_RANDOM: return "unsupported guest random source; no host device";
        default: return "other software virtual fd; no host fd";
    }
}

static int alloc_virtual_fd(enum virtual_fd_kind kind) {
    int fd = guest_vsocket_alloc_fd(&guest_sockets, kind);
    if (fd < 0) return fd;
    track_virtual_fd_for_group(active_tracee, fd);
    return fd;
}

static int is_guest_ueventd(pid_t pid) {
    return active_tracee && active_tracee->pid == pid &&
           strcmp(active_tracee->exec_target, "/sbin/ueventd") == 0;
}

static int virtual_uevent_socket(pid_t pid, const struct compat_pt_regs *regs) {
    uint32_t domain = regs->uregs[0], type = regs->uregs[1], protocol = regs->uregs[2];
    printf("GUEST SOCKET ARGS: host-pid=%d guest-pid=%d target=%s syscall=%d domain=%u type=%u protocol=%u\n",
           pid, active_tracee ? active_tracee->guest_pid : -1,
           active_tracee && active_tracee->exec_target[0] ? active_tracee->exec_target : "unknown",
           ARM_NR_SOCKET, domain, type, protocol);
    if (!is_guest_ueventd(pid) || !guest_uevent_socket_args_valid(domain, type, protocol))
        return -EAFNOSUPPORT;
    if (virtual_uevent_fd >= 0) return -EMFILE;
    int fd = alloc_virtual_fd(VIRTUAL_FD_UEVENT);
    if (fd < 0) return fd;
    virtual_uevent_fd = fd;
    virtual_uevent_bound = 0;
    virtual_uevent_passcred = 0;
    virtual_uevent_rcvbuf_configured = 0;
    guest_uevent_queue_init(&guest_uevent_queue);
    virtual_uevent_socket_count++;
    virtual_socket_calls++;
    printf("VIRTUAL UEVENT SOCKET: fd=%d family=AF_NETLINK type=SOCK_DGRAM protocol=NETLINK_KOBJECT_UEVENT; app-private software descriptor; host socket API not called\n",
           fd);
    return fd;
}

static int virtual_uevent_bind(pid_t pid, const struct compat_pt_regs *regs) {
    int32_t fd = (int32_t)regs->uregs[0];
    uint32_t address = regs->uregs[1], address_length = regs->uregs[2];
    struct guest_uevent_sockaddr_nl addr;
    if (fd != virtual_uevent_fd || !is_virtual_fd(fd) ||
        !tracee_owns_virtual_fd(active_tracee, fd)) return -EBADF;
    if (!is_guest_ueventd(pid) || address_length < sizeof(addr)) return -EINVAL;
    if (read_remote(pid, address, &addr, sizeof(addr)) != 0) return -EFAULT;
    if (!guest_uevent_bind_args_valid(&addr, address_length,
                                      (uint32_t)active_tracee->guest_pid)) return -EINVAL;
    virtual_uevent_bound = 1;
    virtual_uevent_bind_count++;
    virtual_socket_calls++;
    printf("VIRTUAL UEVENT BIND: fd=%d nl_family=%u nl_pid=%u guest-pid=%d nl_groups=0x%08x; host bind API not called\n",
           fd, (unsigned)addr.family, addr.pid, active_tracee->guest_pid, addr.groups);
    return 0;
}

static int virtual_uevent_setsockopt(pid_t pid, const struct compat_pt_regs *regs) {
    int32_t fd = (int32_t)regs->uregs[0];
    uint32_t level = regs->uregs[1], option = regs->uregs[2];
    uint32_t value_address = regs->uregs[3], value_length = regs->uregs[4];
    int32_t value = 0;
    if (fd != virtual_uevent_fd || !is_virtual_fd(fd) ||
        !tracee_owns_virtual_fd(active_tracee, fd)) return -EBADF;
    if (!is_guest_ueventd(pid)) return -EPERM;
    if (value_length < sizeof(value) || read_remote(pid, value_address, &value, sizeof(value)) != 0)
        return -EFAULT;
    if (!guest_uevent_setsockopt_args_valid(level, option, value, value_length))
        return -ENOPROTOOPT;
    if (option == GUEST_UEVENT_SO_PASSCRED) virtual_uevent_passcred = value == 1;
    if (option == GUEST_UEVENT_SO_RCVBUFFORCE)
        virtual_uevent_rcvbuf_configured = value == GUEST_UEVENT_RCVBUFFORCE_BYTES;
    virtual_uevent_setsockopt_count++;
    virtual_socket_calls++;
    printf("VIRTUAL UEVENT SETSOCKOPT: fd=%d level=%u option=%u value=%d length=%u accepted in software; host setsockopt API not called\n",
           fd, level, option, value, value_length);
    return 0;
}

static int virtual_property_socket_address(pid_t pid, uint32_t address,
                                           uint32_t address_length,
                                           uint32_t *family, char *path,
                                           size_t path_capacity) {
    unsigned char raw[sizeof(uint16_t) + 108];
    if (address_length > sizeof(raw)) return -EINVAL;
    if (address_length < sizeof(uint16_t) + 2u) return -EINVAL;
    if (read_remote(pid, address, raw, address_length) != 0) return -EFAULT;
    return guest_vsocket_parse_path(raw, address_length, family, path, path_capacity);
}

static int virtual_guest_socket_create(pid_t pid, uint32_t domain,
                                       uint32_t type, uint32_t protocol) {
    if (domain == GUEST_UEVENT_AF_NETLINK) {
        struct compat_pt_regs args;
        memset(&args, 0, sizeof(args));
        args.uregs[0] = domain;
        args.uregs[1] = type;
        args.uregs[2] = protocol;
        return virtual_uevent_socket(pid, &args);
    }
    if (domain == GUEST_NET_AF_INET) {
        if (!guest_net_socket_args_valid(domain, type, protocol)) {
            int error = type != GUEST_NET_SOCK_DGRAM ? -ESOCKTNOSUPPORT : -EPROTONOSUPPORT;
            virtual_socket_rejected_count++;
            virtual_socket_calls++;
            printf("VIRTUAL GUEST NETWORK SOCKET REJECTED: guest-pid=%d domain=%u type=%u protocol=%u result=%d; host socket API not called\n",
                   active_tracee ? active_tracee->guest_pid : -1, domain, type,
                   protocol, error);
            return error;
        }
        int fd = guest_vsocket_alloc_fd(&guest_sockets, VIRTUAL_FD_NETCFG);
        if (fd < 0) return fd;
        track_virtual_fd_for_group(active_tracee, fd);
        virtual_network_socket_count++;
        virtual_socket_calls++;
        printf("VIRTUAL GUEST NETWORK CONTROL SOCKET: guest-pid=%d fd=%d family=AF_INET type=SOCK_DGRAM protocol=0; eth0 control only; packet I/O and host socket/network APIs unavailable\n",
               active_tracee ? active_tracee->guest_pid : -1, fd);
        return fd;
    }
    int fd = guest_vsocket_create(&guest_sockets, domain, type, protocol);
    if (fd < 0) {
        virtual_socket_rejected_count++;
        virtual_socket_calls++;
        printf("VIRTUAL GUEST SOCKET REJECTED: pid=%d domain=%u type=%u protocol=%u result=%d; host socket API not called\n",
               pid, domain, type, protocol, fd);
        return fd;
    }
    track_virtual_fd_for_group(active_tracee, fd);
    virtual_property_socket_count++;
    virtual_socket_calls++;
    printf("VIRTUAL PROPERTY SOCKET CREATE: host-pid=%d guest-pid=%d fd=%d family=AF_UNIX type=SOCK_STREAM protocol=0; app-private software descriptor; host socket API not called\n",
           pid, active_tracee ? active_tracee->guest_pid : -1, fd);
    return fd;
}

static int virtual_guest_network_ioctl(pid_t pid, int fd, uint32_t request,
                                      uint32_t argument) {
    struct guest_vsocket_fd *virtual_fd = guest_vsocket_fd_get(&guest_sockets, fd);
    if (!virtual_fd || !tracee_owns_virtual_fd(active_tracee, fd)) return -EBADF;
    if (virtual_fd->kind != VIRTUAL_FD_NETCFG) return -ENOTTY;
    if (!active_tracee || active_tracee->pid != pid) return -ESRCH;
    virtual_network_ioctl_count++;
    int rc = -ENOTTY;
    const int is_get = request == GUEST_NET_SIOCGIFFLAGS ||
                       request == GUEST_NET_SIOCGIFADDR ||
                       request == GUEST_NET_SIOCGIFNETMASK;
    const int is_set = request == GUEST_NET_SIOCSIFFLAGS ||
                       request == GUEST_NET_SIOCSIFADDR ||
                       request == GUEST_NET_SIOCSIFNETMASK;
    if (is_get || is_set) {
        struct guest_arm32_ifreq ifr;
        if (read_remote(pid, argument, &ifr, sizeof(ifr)) != 0) {
            rc = -EFAULT;
        } else {
            uint16_t old_flags = guest_network_state.flags;
            rc = guest_net_apply_ifreq(&guest_network_state, request, &ifr);
            if (rc == 0 && is_get && write_remote(pid, argument, &ifr, sizeof(ifr)) != 0)
                rc = -EFAULT;
            if (rc == 0 && request == GUEST_NET_SIOCSIFFLAGS) {
                rc = guest_network_sync_operstate();
                if (rc != 0) guest_network_state.flags = old_flags;
            }
            if (virtual_network_ioctl_count <= 48u) {
                printf("GUEST NETWORK IOCTL: guest-pid=%d executable=%s fd=%d request=0x%08x ifname=%.16s result=%d ip=%s netmask=%s up=%d\n",
                       active_tracee->guest_pid, active_tracee->exec_target, fd,
                       request, ifr.name, rc,
                       guest_network_state.address_set ? GUEST_PROFILE_NET_ADDRESS : "unset",
                       guest_network_state.netmask_set ? GUEST_PROFILE_NET_NETMASK : "unset",
                       (guest_network_state.flags & GUEST_NET_IFF_UP) != 0);
            }
        }
    } else if (request == GUEST_NET_SIOCADDRT) {
        struct guest_arm32_rtentry route;
        char device[GUEST_NET_IFNAMSIZ];
        if (read_remote(pid, argument, &route, sizeof(route)) != 0) {
            rc = -EFAULT;
        } else if (route.device_pointer == 0u ||
                   read_remote_string(pid, route.device_pointer, device, sizeof(device)) != 0) {
            rc = -EFAULT;
        } else {
            rc = guest_net_add_route(&guest_network_state, &route, device);
            if (rc == 0) {
                rc = guest_network_sync_proc_route();
                if (rc != 0) {
                    guest_network_state.default_route_set = 0;
                    memset(guest_network_state.gateway, 0,
                           sizeof(guest_network_state.gateway));
                }
            }
            if (virtual_network_ioctl_count <= 48u)
                printf("GUEST NETWORK ROUTE: guest-pid=%d executable=%s fd=%d request=SIOCADDRT device=%s gateway=%s result=%d default-route=%d; guest state only\n",
                       active_tracee->guest_pid, active_tracee->exec_target, fd,
                       device, GUEST_PROFILE_NET_GATEWAY, rc,
                       guest_network_state.default_route_set);
        }
    }
    if (rc < 0) virtual_network_ioctl_rejected_count++;
    if (virtual_network_ioctl_count > 48u && virtual_network_ioctl_count == 49u)
        puts("GUEST NETWORK IOCTL: further detail suppressed after 48 requests; aggregate counters retained");
    return rc;
}

static int virtual_guest_socket_bind(pid_t pid, int fd, uint32_t address,
                                     uint32_t address_length) {
    uint32_t family = 0;
    char guest_path[108], host_path[PATH_MAX];
    int rc = virtual_property_socket_address(pid, address, address_length,
                                             &family, guest_path, sizeof(guest_path));
    if (rc != 0) return rc;
    if (!active_tracee || active_tracee->pid != pid || active_tracee->guest_pid != 1 ||
        strcmp(active_tracee->exec_target, "/init") != 0) return -EPERM;
    if (!tracee_owns_virtual_fd(active_tracee, fd)) return -EBADF;
    rc = guest_vsocket_bind_validate(&guest_sockets, fd, family, guest_path);
    if (rc != 0) return rc;
    rc = map_guest_path(guest_path, host_path, sizeof(host_path));
    if (rc != 0 || !path_is_within(host_path, guest_root)) return rc != 0 ? rc : -EACCES;
    rc = guest_socket_marker_create_app_private(host_path, guest_root);
    if (rc != 0) return rc;
    rc = guest_vsocket_bind_commit(&guest_sockets, fd);
    if (rc != 0) {
        (void)unlink(host_path);
        return rc;
    }
    virtual_property_bind_count++;
    virtual_socket_calls++;
    printf("VIRTUAL PROPERTY BIND: host-pid=%d guest-pid=1 fd=%d path=%s marker=app-private regular VFS placeholder; host bind API not called\n",
           pid, fd, guest_path);
    return 0;
}

static int virtual_guest_socket_connect(pid_t pid, int fd, uint32_t address,
                                        uint32_t address_length) {
    uint32_t family = 0;
    char guest_path[108];
    int rc = virtual_property_socket_address(pid, address, address_length,
                                             &family, guest_path, sizeof(guest_path));
    if (rc != 0) return rc;
    if (!active_tracee || active_tracee->pid != pid ||
        !tracee_owns_virtual_fd(active_tracee, fd)) return -EBADF;
    rc = guest_vsocket_connect(&guest_sockets, fd, family, guest_path,
                               active_tracee->guest_pid,
                               (int32_t)active_tracee->guest_euid,
                               (int32_t)active_tracee->guest_egid);
    virtual_socket_calls++;
    if (rc == 0) {
        virtual_property_connect_count++;
        printf("VIRTUAL PROPERTY CONNECT: host-pid=%d guest-pid=%d fd=%d path=%s queued-for-listener; host connect API not called\n",
               pid, active_tracee->guest_pid, fd, guest_path);
    } else {
        virtual_socket_rejected_count++;
    }
    return rc;
}

static int virtual_guest_socket_listen(pid_t pid, int fd, int backlog) {
    if (!active_tracee || active_tracee->pid != pid ||
        !tracee_owns_virtual_fd(active_tracee, fd)) return -EBADF;
    int rc = guest_vsocket_listen(&guest_sockets, fd, backlog);
    virtual_socket_calls++;
    if (rc == 0)
        printf("VIRTUAL PROPERTY LISTEN: fd=%d backlog=%d; listener readiness comes only from software client queue; host listen API not called\n",
               fd, backlog);
    else
        virtual_socket_rejected_count++;
    return rc;
}

static int virtual_guest_socketpair(pid_t pid, uint32_t domain, uint32_t type,
                                    uint32_t protocol, uint32_t pair_address) {
    if (!active_tracee || active_tracee->pid != pid || active_tracee->guest_pid != 1 ||
        strcmp(active_tracee->exec_target, "/init") != 0) return -EPERM;
    int32_t pair[2] = {-1, -1};
    int rc = guest_vsocket_create_pair(&guest_sockets, domain, type, protocol, pair);
    if (rc != 0) {
        virtual_socket_rejected_count++;
        virtual_socket_calls++;
        return rc;
    }
    track_virtual_fd_for_group(active_tracee, pair[0]);
    track_virtual_fd_for_group(active_tracee, pair[1]);
    if (pair_address == 0 || write_remote(pid, pair_address, pair, sizeof(pair)) != 0) {
        (void)close_virtual_fd(active_tracee, pair[0]);
        (void)close_virtual_fd(active_tracee, pair[1]);
        return -EFAULT;
    }
    virtual_socketpair_count++;
    virtual_socket_calls++;
    printf("VIRTUAL SIGNAL SOCKETPAIR: guest-pid=1 fds=%d,%d family=AF_UNIX type=SOCK_STREAM; software SIGCHLD byte queue; host socketpair API not called\n",
           pair[0], pair[1]);
    return 0;
}

static int virtual_guest_socket_accept(pid_t pid, int fd, uint32_t address,
                                       uint32_t address_length_pointer) {
    if (!active_tracee || active_tracee->pid != pid ||
        !tracee_owns_virtual_fd(active_tracee, fd)) return -EBADF;
    uint32_t address_capacity = 0;
    if (address || address_length_pointer) {
        if (!address || !address_length_pointer ||
            read_remote(pid, address_length_pointer, &address_capacity,
                        sizeof(address_capacity)) != 0) return -EFAULT;
        if (address_capacity < sizeof(uint16_t)) return -EINVAL;
    }
    int accepted = guest_vsocket_accept(&guest_sockets, fd);
    if (accepted < 0) {
        virtual_socket_calls++;
        return accepted;
    }
    track_virtual_fd_for_group(active_tracee, accepted);
    if (address) {
        uint16_t family = (uint16_t)GUEST_VSOCKET_AF_UNIX;
        uint32_t returned_length = sizeof(family);
        if (write_remote(pid, address, &family, sizeof(family)) != 0 ||
            write_remote(pid, address_length_pointer, &returned_length,
                         sizeof(returned_length)) != 0) {
            (void)close_virtual_fd(active_tracee, accepted);
            return -EFAULT;
        }
    }
    struct guest_vsocket_channel *channel = NULL;
    struct guest_vsocket_fd *entry = guest_vsocket_fd_get(&guest_sockets, accepted);
    if (entry) channel = guest_vsocket_channel_get(&guest_sockets, entry->channel);
    virtual_socket_calls++;
    virtual_property_accept_count++;
    printf("VIRTUAL PROPERTY ACCEPT: host-pid=%d guest-pid=%d listener=%d accepted=%d peer-guest-pid=%d; host accept API not called\n",
           pid, active_tracee ? active_tracee->guest_pid : -1, fd, accepted,
           channel ? channel->peer_pid : -1);
    return accepted;
}

static int virtual_guest_socket_getsockopt(pid_t pid, int fd, uint32_t level,
                                           uint32_t option, uint32_t value_address,
                                           uint32_t length_address) {
    struct tracee_state *state = active_tracee && active_tracee->pid == pid ? active_tracee : NULL;
    if (!is_virtual_fd(fd) || !tracee_owns_virtual_fd(state, fd)) return -EBADF;
    if (level != GUEST_VSOCKET_SOL_SOCKET || option != GUEST_VSOCKET_SO_PEERCRED)
        return -ENOPROTOOPT;
    if (value_address == 0 || length_address == 0) return -EFAULT;
    uint32_t value_length = 0;
    if (read_remote(pid, length_address, &value_length, sizeof(value_length)) != 0)
        return -EFAULT;
    struct guest_vsocket_peercred cred;
    int rc = guest_vsocket_peercred(&guest_sockets, fd, &cred);
    if (rc != 0) return rc;
    if (value_length < sizeof(cred)) return -EINVAL;
    if (write_remote(pid, value_address, &cred, sizeof(cred)) != 0) return -EFAULT;
    value_length = sizeof(cred);
    if (write_remote(pid, length_address, &value_length, sizeof(value_length)) != 0)
        return -EFAULT;
    virtual_socket_calls++;
    printf("VIRTUAL PROPERTY SO_PEERCRED: fd=%d guest-pid=%d uid=%d gid=%d; guest identity only; host getsockopt API not called\n",
           fd, cred.pid, cred.uid, cred.gid);
    return 0;
}

static int virtual_uevent_recvmsg(pid_t pid, const struct compat_pt_regs *regs) {
    int fd = (int32_t)regs->uregs[0];
    uint32_t message_address = regs->uregs[1];
    uint32_t flags = regs->uregs[2];
    struct tracee_state *state = active_tracee && active_tracee->pid == pid
        ? active_tracee : NULL;
    struct guest_vsocket_fd *entry = guest_vsocket_fd_get(&guest_sockets, fd);
    if (!entry || entry->kind != VIRTUAL_FD_UEVENT ||
        !tracee_owns_virtual_fd(state, fd)) return -EBADF;
    if (!is_guest_ueventd(pid)) return -EPERM;
    if (!virtual_uevent_bound || !virtual_uevent_passcred ||
        !virtual_uevent_rcvbuf_configured) return -ENOTCONN;
    if ((flags & ~GUEST_MSG_DONTWAIT) != 0) return -EOPNOTSUPP;
    struct guest_arm32_msghdr message;
    if (!message_address || read_remote(pid, message_address, &message, sizeof(message)) != 0)
        return -EFAULT;
    if (message.iov_length == 0 || message.iov_length > 16 || !message.iov)
        return -EINVAL;
    struct guest_arm32_iovec vectors[16];
    if (read_remote(pid, message.iov, vectors,
                    message.iov_length * sizeof(vectors[0])) != 0) return -EFAULT;
    uint64_t capacity = 0;
    for (uint32_t i = 0; i < message.iov_length; ++i) {
        if (vectors[i].length && !vectors[i].base) return -EFAULT;
        capacity += vectors[i].length;
        if (capacity > UINT32_MAX) return -EINVAL;
    }
    if (!message.name || message.name_length < sizeof(struct guest_uevent_sockaddr_nl) ||
        !message.control ||
        message.control_length < sizeof(struct guest_arm32_cmsghdr) + sizeof(struct guest_arm32_ucred))
        return -EINVAL;
    const struct guest_uevent_event *event = guest_uevent_queue_front(&guest_uevent_queue);
    if (!event) {
        printf("GUEST UEVENT RECVMSG EMPTY: host-pid=%d guest-pid=%d nonblock=%d flags=0x%x result=-EAGAIN queue=0\n",
               pid, state->guest_pid, entry->nonblocking, flags);
        return -EAGAIN;
    }
    size_t copied = event->length;
    int32_t returned_flags = 0;
    if (capacity < copied) {
        copied = (size_t)capacity;
        returned_flags |= GUEST_MSG_TRUNC;
    }
    size_t remaining = copied;
    size_t offset = 0;
    for (uint32_t i = 0; i < message.iov_length && remaining; ++i) {
        size_t part = vectors[i].length < remaining ? vectors[i].length : remaining;
        if (part && write_remote(pid, vectors[i].base, event->data + offset, part) != 0)
            return -EFAULT;
        offset += part;
        remaining -= part;
    }
    struct guest_uevent_sockaddr_nl source = {
        .family = GUEST_UEVENT_AF_NETLINK, .pad = 0, .pid = 0, .groups = 1,
    };
    uint32_t source_length = sizeof(source);
    struct guest_arm32_cmsghdr control = {
        .length = sizeof(control) + sizeof(struct guest_arm32_ucred),
        .level = GUEST_UEVENT_SOL_SOCKET, .type = GUEST_SCM_CREDENTIALS,
    };
    struct guest_arm32_ucred credentials = {.pid = 0, .uid = 0, .gid = 0};
    if (write_remote(pid, message.name, &source, sizeof(source)) != 0 ||
        write_remote(pid, message.control, &control, sizeof(control)) != 0 ||
        write_remote(pid, message.control + sizeof(control), &credentials, sizeof(credentials)) != 0)
        return -EFAULT;
    message.name_length = source_length;
    message.control_length = sizeof(control) + sizeof(credentials);
    message.flags = returned_flags;
    if (write_remote(pid, message_address, &message, sizeof(message)) != 0) return -EFAULT;
    if (guest_uevent_queue_consume(&guest_uevent_queue) != 0) return -EIO;
    virtual_uevent_recvmsg_count++;
    virtual_socket_calls++;
    printf("GUEST UEVENT RECVMSG: host-pid=%d guest-pid=%d fd=%d bytes=%zu source={nl_pid=0,nl_groups=1} SCM_CREDENTIALS={pid=0,uid=0,gid=0} flags=0x%x queue=%zu; app-private queue only\n",
           pid, state->guest_pid, fd, copied, returned_flags, guest_uevent_queue.count);
    return (int)copied;
}

static int virtual_guest_socket_stream_io(pid_t pid, int fd, uint32_t buffer_address,
                                          uint32_t length, int flags, int receive) {
    if (!is_virtual_fd_number(fd)) return 1;
    struct tracee_state *state = active_tracee && active_tracee->pid == pid ? active_tracee : NULL;
    if (!is_virtual_fd(fd) || !tracee_owns_virtual_fd(state, fd)) return -EBADF;
    struct guest_vsocket_fd *entry = guest_vsocket_fd_get(&guest_sockets, fd);
    if (entry && entry->kind == VIRTUAL_FD_SYSFS_UEVENT) {
        if (receive) return -EBADF;
        if (!is_guest_ueventd(pid)) return -EPERM;
        if (!virtual_uevent_bound || !virtual_uevent_passcred ||
            !virtual_uevent_rcvbuf_configured) return -ENOTCONN;
        unsigned char request[16];
        if (length > sizeof(request) || (length != 0 && buffer_address == 0))
            return -EINVAL;
        if (length && read_remote(pid, buffer_address, request, length) != 0) return -EFAULT;
        int result = guest_uevent_enqueue_coldboot_add(&guest_uevent_queue, 1,
            GUEST_UEVENT_SYSFS_ATTRIBUTE_PATH, request, length);
        virtual_socket_calls++;
        if (result >= 0) {
            virtual_uevent_write_count++;
            printf("GUEST SYSFS UEVENT WRITE: guest-pid=%d path=%s bytes=%u result=%d queued=%zu; app-private event only, no host sysfs/netlink/device node\n",
                   state->guest_pid, GUEST_UEVENT_SYSFS_ATTRIBUTE_PATH, length,
                   result, guest_uevent_queue.count);
        }
        return result;
    }
    if (entry && entry->kind == VIRTUAL_FD_UEVENT) return receive ? -EAGAIN : -EOPNOTSUPP;
    if (entry && entry->kind >= VIRTUAL_FD_DEV_NULL &&
        entry->kind <= VIRTUAL_FD_DEV_RANDOM) return -ENOTSOCK;
    if (length == 0) return 0;
    if (buffer_address == 0) return -EFAULT;
    size_t amount = length > GUEST_VSOCKET_BUFFER_SIZE ? GUEST_VSOCKET_BUFFER_SIZE : length;
    unsigned char buffer[GUEST_VSOCKET_BUFFER_SIZE];
    int result;
    if (!receive) {
        if (read_remote(pid, buffer_address, buffer, amount) != 0) return -EFAULT;
        result = guest_vsocket_send(&guest_sockets, fd, buffer, amount, flags);
    } else {
        result = guest_vsocket_peek(&guest_sockets, fd, buffer, amount, flags);
        if (result > 0) {
            if (write_remote(pid, buffer_address, buffer, (size_t)result) != 0) return -EFAULT;
            if (guest_vsocket_consume(&guest_sockets, fd, (size_t)result) != 0) return -EIO;
        }
    }
    virtual_socket_calls++;
    if (result > 0 && receive)
        printf("VIRTUAL PROPERTY RECV: fd=%d bytes=%d; software queue only; host recv API not called\n",
               fd, result);
    return result;
}

static int virtual_guest_pseudo_device_io(pid_t pid, int fd,
                                          uint32_t buffer_address,
                                          uint32_t length, int receive) {
    struct tracee_state *state = active_tracee && active_tracee->pid == pid
        ? active_tracee : NULL;
    if (!is_virtual_fd(fd)) return 1;
    if (!state || !tracee_owns_virtual_fd(state, fd)) return -EBADF;
    struct guest_vsocket_fd *entry = guest_vsocket_fd_get(&guest_sockets, fd);
    if (!entry || entry->kind < VIRTUAL_FD_DEV_NULL ||
        entry->kind > VIRTUAL_FD_DEV_FULL) return 1;
    if (entry->kind == VIRTUAL_FD_DEV_RANDOM) {
        unsupported_guest_device_open_count++;
        printf("GUEST RANDOM DEVICE READ UNSUPPORTED: guest-pid=%d executable=%s fd=%d; no guest entropy broker, host random device not substituted; result=%d\n",
               state->guest_pid, state->exec_target, fd, -EOPNOTSUPP);
        return -EOPNOTSUPP;
    }
    unsigned access = entry->open_flags & 3u;
    if (receive && access == GUEST_VSOCKET_O_WRONLY) return -EBADF;
    if (!receive && access == GUEST_VSOCKET_O_RDONLY) return -EBADF;
    if (length > (uint32_t)INT32_MAX) return -EINVAL;
    if (length == 0) return 0;

    int result;
    if (!receive) {
        if (entry->kind == VIRTUAL_FD_DEV_KMSG) {
            unsigned char discarded[1024];
            uint32_t offset = 0;
            while (offset < length) {
                uint32_t amount = length - offset;
                if (amount > sizeof(discarded)) amount = sizeof(discarded);
                uint64_t address = (uint64_t)buffer_address + offset;
                if (buffer_address == 0 || address > UINT32_MAX ||
                    read_remote(pid, (uint32_t)address, discarded, amount) != 0)
                    return -EFAULT;
                offset += amount;
            }
        }
        result = guest_pseudo_device_write(entry->kind, length);
        if (result > 0) {
            virtual_pseudo_device_io_count++;
            if (entry->kind == VIRTUAL_FD_DEV_KMSG && virtual_pseudo_device_io_count <= 32u)
                printf("GUEST KMSG WRITE: guest-pid=%d executable=%s fd=%d bytes=%d; bounded software log sink, host /dev/kmsg untouched\n",
                       state->guest_pid, state->exec_target, fd, result);
        }
        return result;
    }

    if (entry->kind == VIRTUAL_FD_DEV_NULL)
        result = guest_pseudo_device_read(entry->kind, NULL, length, 0);
    else if (entry->kind == VIRTUAL_FD_DEV_KMSG)
        result = guest_pseudo_device_read(entry->kind, NULL, length, 0);
    else {
        unsigned char zeros[4096] = {0};
        uint32_t offset = 0;
        result = (int)length;
        while (offset < length) {
            uint32_t amount = length - offset;
            if (amount > sizeof(zeros)) amount = sizeof(zeros);
            uint64_t address = (uint64_t)buffer_address + offset;
            if (buffer_address == 0 || address > UINT32_MAX ||
                write_remote(pid, (uint32_t)address, zeros, amount) != 0) {
                result = -EFAULT;
                break;
            }
            offset += amount;
        }
    }
    virtual_pseudo_device_io_count++;
    if (virtual_pseudo_device_io_count <= 32u)
        printf("GUEST PSEUDO-DEVICE READ: guest-pid=%d executable=%s fd=%d kind=%d requested=%u result=%d; app-private software semantics\n",
               state->guest_pid, state->exec_target, fd, entry->kind, length, result);
    return result;
}

static int virtual_guest_socket_setsockopt(pid_t pid, const struct compat_pt_regs *regs) {
    int fd = (int32_t)regs->uregs[0];
    if (fd == virtual_uevent_fd && is_virtual_fd(fd) &&
        tracee_owns_virtual_fd(active_tracee, fd)) return virtual_uevent_setsockopt(pid, regs);
    if (is_virtual_fd_number(fd)) {
        virtual_socket_calls++;
        return is_virtual_fd(fd) && tracee_owns_virtual_fd(active_tracee, fd)
            ? -ENOPROTOOPT : -EBADF;
    }
    return -EBADF;
}

static int virtual_socketcall(pid_t pid, const struct compat_pt_regs *regs) {
    enum { SOCKETCALL_SOCKET = 1, SOCKETCALL_BIND = 2, SOCKETCALL_CONNECT = 3,
           SOCKETCALL_LISTEN = 4, SOCKETCALL_ACCEPT = 5, SOCKETCALL_SOCKETPAIR = 8,
           SOCKETCALL_SEND = 9, SOCKETCALL_RECV = 10, SOCKETCALL_SETSOCKOPT = 14,
           SOCKETCALL_GETSOCKOPT = 15 };
    uint32_t op = regs->uregs[0];
    uint32_t args[5] = {0, 0, 0, 0, 0};
    int count = guest_vsocket_socketcall_arg_count((int)op);
    if (count < 0) {
        virtual_socket_calls++;
        virtual_socket_rejected_count++;
        return count;
    }
    if (read_remote(pid, regs->uregs[1], args, (size_t)count * sizeof(args[0])) != 0)
        return -EFAULT;
    switch (op) {
        case SOCKETCALL_SOCKET:
            return virtual_guest_socket_create(pid, args[0], args[1], args[2]);
        case SOCKETCALL_BIND:
            return virtual_guest_socket_bind(pid, (int32_t)args[0], args[1], args[2]);
        case SOCKETCALL_CONNECT:
            return virtual_guest_socket_connect(pid, (int32_t)args[0], args[1], args[2]);
        case SOCKETCALL_LISTEN:
            return virtual_guest_socket_listen(pid, (int32_t)args[0], (int32_t)args[1]);
        case SOCKETCALL_ACCEPT:
            return virtual_guest_socket_accept(pid, (int32_t)args[0], args[1], args[2]);
        case SOCKETCALL_SOCKETPAIR:
            return virtual_guest_socketpair(pid, args[0], args[1], args[2], args[3]);
        case SOCKETCALL_SEND:
            return virtual_guest_socket_stream_io(pid, (int32_t)args[0], args[1], args[2],
                                                  (int)args[3], 0);
        case SOCKETCALL_RECV:
            return virtual_guest_socket_stream_io(pid, (int32_t)args[0], args[1], args[2],
                                                  (int)args[3], 1);
        case SOCKETCALL_SETSOCKOPT: {
            struct compat_pt_regs nested;
            memset(&nested, 0, sizeof(nested));
            for (size_t i = 0; i < 5; ++i) nested.uregs[i] = args[i];
            return virtual_guest_socket_setsockopt(pid, &nested);
        }
        case SOCKETCALL_GETSOCKOPT:
            return virtual_guest_socket_getsockopt(pid, (int32_t)args[0], args[1], args[2],
                                                   args[3], args[4]);
        default:
            return -EOPNOTSUPP;
    }
}

static int virtual_poll(pid_t pid, const struct compat_pt_regs *regs) {
    struct guest_pollfd { int32_t fd; int16_t events; int16_t revents; };
    uint32_t count = regs->uregs[1];
    if (count > 128u) return -EINVAL;
    struct guest_pollfd fds[128];
    if (count && (regs->uregs[0] == 0 ||
        read_remote(pid, regs->uregs[0], fds, count * sizeof(fds[0])) != 0)) return -EFAULT;
    int16_t input_revents[128];
    struct tracee_state *state = active_tracee && active_tracee->pid == pid ? active_tracee : NULL;
    unsigned int call = state ? ++state->poll_diagnostic_count : 0;
    int32_t timeout_ms = (int32_t)regs->uregs[2];
    int32_t sleep_ms = timeout_ms < 0 || timeout_ms > 100 ? 100 : timeout_ms;
    int ready = 0;
    for (uint32_t i = 0; i < count; ++i) {
        input_revents[i] = fds[i].revents;
        fds[i].revents = 0;
        int fd = fds[i].fd;
        if (fd < 0) continue;
        if (is_virtual_fd_number(fd)) {
            if (!is_virtual_fd(fd) || !tracee_owns_virtual_fd(state, fd))
                fds[i].revents = GUEST_VSOCKET_POLLNVAL;
            else if (fd == virtual_uevent_fd && is_virtual_fd(fd))
                fds[i].revents = virtual_uevent_bound &&
                    guest_uevent_queue_readable(&guest_uevent_queue) &&
                    (fds[i].events & GUEST_VSOCKET_POLLIN)
                    ? GUEST_VSOCKET_POLLIN : 0;
            else
                fds[i].revents = (int16_t)guest_vsocket_poll_events(
                    &guest_sockets, fd, fds[i].events);
        }
        if (fds[i].revents != 0) ready++;
    }
    if (state && call <= 4) {
        printf("GUEST POLL DIAGNOSTIC: host-pid=%d guest-pid=%d target=%s call=%u nfds=%u timeout-ms=%d",
               pid, state->guest_pid,
               state->exec_target[0] ? state->exec_target : "unknown",
               call, count, timeout_ms);
        for (uint32_t i = 0; i < count; ++i)
            printf(" fd[%u]={fd=%d events=0x%04x revents-in=0x%04x revents-out=0x%04x source=%s}",
                   i, fds[i].fd, (unsigned)(uint16_t)fds[i].events,
                   (unsigned)(uint16_t)input_revents[i], (unsigned)(uint16_t)fds[i].revents,
                   virtual_fd_source(fds[i].fd));
        printf(" result=%d scheduler-slice-ms=%d event-queue=%s; host poll API not called\n",
               ready, ready ? 0 : sleep_ms,
               ready ? "software listener/data readiness" :
                   (guest_uevent_queue.count ? "event not requested by this poll mask" : "empty guest-only uevent queue"));
    }
    if (ready == 0 && sleep_ms > 0) {
        struct timespec delay = { .tv_sec = sleep_ms / 1000,
            .tv_nsec = (long)(sleep_ms % 1000) * 1000000L };
        nanosleep(&delay, NULL);
    }
    virtual_poll_waits++;
    if (count && write_remote(pid, regs->uregs[0], fds, count * sizeof(fds[0])) != 0) return -EFAULT;
    return ready;
}

static int prepare_init_dirs(void) {
    char vfs[PATH_MAX];
    int n = snprintf(vfs, sizeof(vfs), "%s/.vfs", guest_root);
    if (n <= 0 || (size_t)n >= sizeof(vfs)) return -ENAMETOOLONG;
    return mkdir_p(vfs);
}

static struct tracee_state *find_tracee(pid_t pid) {
    for (size_t i = 0; i < tracee_count; ++i)
        if (tracees[i].alive && tracees[i].pid == pid) return &tracees[i];
    return NULL;
}

static struct tracee_state *add_tracee(pid_t pid, int needs_options,
                                       pid_t guest_pid, pid_t guest_tid,
                                       pid_t guest_parent_pid, int is_thread) {
    struct tracee_state *existing = find_tracee(pid);
    if (existing) return existing;
    if (tracee_count >= MAX_TRACEES) return NULL;
    struct tracee_state *state = &tracees[tracee_count++];
    memset(state, 0, sizeof(*state));
    state->pid = pid;
    state->guest_pid = guest_pid;
    state->guest_tid = guest_tid;
    state->guest_parent_pid = guest_parent_pid;
    state->guest_pgid = (uint32_t)guest_pid;
    snprintf(state->guest_cwd, sizeof(state->guest_cwd), "/");
    state->is_thread = is_thread;
    state->alive = 1;
    state->needs_options = needs_options;
    state->last_syscall = -1;
    active_tracee_count++;
    return state;
}

static struct tracee_state *find_tracee_guest_pid(pid_t guest_pid) {
    for (size_t i = 0; i < tracee_count; ++i)
        if (tracees[i].alive && !tracees[i].is_thread && tracees[i].guest_pid == guest_pid)
            return &tracees[i];
    return NULL;
}

static struct tracee_state *find_tracee_host_pid(pid_t pid) {
    for (size_t i = 0; i < tracee_count; ++i)
        if (tracees[i].pid == pid) return &tracees[i];
    return NULL;
}

static struct tracee_state *find_guest_child(pid_t parent_guest_pid, pid_t child_guest_pid) {
    for (size_t i = 0; i < tracee_count; ++i)
        if (!tracees[i].is_thread && !tracees[i].guest_reaped &&
            tracees[i].guest_parent_pid == parent_guest_pid &&
            tracees[i].guest_pid == child_guest_pid) return &tracees[i];
    return NULL;
}

static void remove_tracee(pid_t pid) {
    for (size_t i = 0; i < tracee_count; ++i) {
        if (!tracees[i].alive || tracees[i].pid != pid) continue;
        if (active_tracee == &tracees[i]) active_tracee = NULL;
        uint64_t owned = tracees[i].virtual_fd_mask;
        uint32_t file_table_id = tracees[i].virtual_fd_table_id;
        tracees[i].virtual_fd_mask = 0;
        tracees[i].alive = 0;
        if (active_tracee_count > 0) active_tracee_count--;
        for (int slot = 0; slot < MAX_VIRTUAL_FDS; ++slot)
            if (owned & (UINT64_C(1) << (unsigned)slot))
                release_virtual_fd_if_unreferenced(VIRTUAL_FD_BASE + slot);
        int table_still_referenced = 0;
        for (size_t j = 0; j < tracee_count; ++j)
            if (tracees[j].alive && tracees[j].virtual_fd_table_id == file_table_id)
                table_still_referenced = 1;
        if (!table_still_referenced && file_table_id != 0)
            guest_path_fd_remove_owner(&guest_path_fds, (pid_t)file_table_id);
        return;
    }
}

static int original_init_native_path(char *out, size_t capacity) {
    int n = snprintf(out, capacity, "%s/libgingervm_guest_init.so", native_guest_root);
    if (n <= 0 || (size_t)n >= capacity) return -ENAMETOOLONG;
    struct stat st;
    if (stat(out, &st) != 0) return -errno;
    if (!S_ISREG(st.st_mode) || !(st.st_mode & 0111)) return -EACCES;
    return 0;
}

static int patched_dynamic_native_path(const char *original, char *out, size_t capacity) {
    const char *base = strrchr(original, '/');
    const char prefix[] = "libgingervm_exec_";
    if (!base || strncmp(base + 1, prefix, sizeof(prefix) - 1) != 0) return -EACCES;
    int n = snprintf(out, capacity, "%s/libgingervm_exec_patched_%s", native_guest_root,
                     base + 1 + sizeof(prefix) - 1);
    return n > 0 && (size_t)n < capacity ? 0 : -ENAMETOOLONG;
}

static int guest_script_remote_read_word(void *context, uint32_t address,
                                         uint32_t *value) {
    if (!context || !value) return -1;
    pid_t pid = *(const pid_t *)context;
    return read_remote(pid, address, value, sizeof(*value));
}

static int mediate_guest_script_execve(pid_t pid, struct tracee_state *state,
                                       struct compat_pt_regs *regs,
                                       const char *guest_path,
                                       const char *mapped_script,
                                       const char *resolved_script,
                                       const char **failure_reason) {
    int script_fd = -1;
    int rc = -EACCES;
    const char *reason = "guest-script-launch-rejected";
    char canonical_guest_root[PATH_MAX], system_candidate[PATH_MAX];
    char canonical_system_root[PATH_MAX], fd_path[64], fd_resolved[PATH_MAX];
    char mapped_shell[PATH_MAX], shell_resolved[PATH_MAX], shell_interpreter[PATH_MAX];
    char patched_shell[PATH_MAX], patched_shell_resolved[PATH_MAX];
    char patched_interpreter[PATH_MAX];

    if (!guest_script_path_is_whitelisted(guest_path)) {
        reason = "guest-script-path-not-whitelisted";
        goto fail;
    }
    if (!realpath(guest_root, canonical_guest_root)) {
        reason = "guest-script-root-resolution-failed";
        rc = -errno;
        goto fail;
    }
    int n = snprintf(system_candidate, sizeof(system_candidate), "%s/.images/system",
                     canonical_guest_root);
    if (n <= 0 || (size_t)n >= sizeof(system_candidate)) {
        reason = "guest-script-system-root-resolution-failed";
        rc = -ENAMETOOLONG;
        goto fail;
    }
    if (!realpath(system_candidate, canonical_system_root)) {
        reason = "guest-script-system-root-resolution-failed";
        rc = -errno;
        goto fail;
    }
    if (!guest_script_file_is_authorized(guest_path, canonical_guest_root,
            canonical_system_root, resolved_script, 1)) {
        reason = "guest-script-resolved-outside-approved-api10-system-path";
        rc = -EACCES;
        goto fail;
    }

    struct stat path_st, opened_st;
    if (lstat(mapped_script, &path_st) != 0) {
        reason = "guest-script-lstat-failed";
        rc = -errno;
        goto fail;
    }
    if (!S_ISREG(path_st.st_mode)) {
        reason = S_ISLNK(path_st.st_mode) ? "guest-script-final-component-is-symlink"
                                         : "guest-script-is-not-regular-file";
        rc = -EACCES;
        goto fail;
    }
    script_fd = open(mapped_script, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (script_fd < 0) {
        reason = "guest-script-open-no-follow-failed";
        rc = -errno;
        goto fail;
    }
    if (fstat(script_fd, &opened_st) != 0) {
        reason = "guest-script-fstat-failed";
        rc = -errno;
        goto fail;
    }
    if (!S_ISREG(opened_st.st_mode) || opened_st.st_dev != path_st.st_dev ||
        opened_st.st_ino != path_st.st_ino) {
        reason = "guest-script-changed-during-validation";
        rc = -EACCES;
        goto fail;
    }
    n = snprintf(fd_path, sizeof(fd_path), "/proc/self/fd/%d", script_fd);
    if (n <= 0 || (size_t)n >= sizeof(fd_path) || !realpath(fd_path, fd_resolved)) {
        reason = "guest-script-open-fd-resolution-failed";
        rc = errno ? -errno : -ENAMETOOLONG;
        goto fail;
    }
    if (!guest_script_file_is_authorized(guest_path, canonical_guest_root,
            canonical_system_root, fd_resolved, S_ISREG(path_st.st_mode)) ||
        strcmp(fd_resolved, resolved_script) != 0) {
        reason = "guest-script-resolved-outside-approved-api10-system-path";
        rc = -EACCES;
        goto fail;
    }
    if (!guest_script_mode_is_executable((uint32_t)opened_st.st_mode)) {
        reason = "guest-script-has-no-execute-bit";
        rc = -EACCES;
        goto fail;
    }
    static const char expected_shebang[] = "#!/system/bin/sh\n";
    char shebang[sizeof(expected_shebang) - 1];
    ssize_t shebang_bytes = pread(script_fd, shebang, sizeof(shebang), 0);
    if (shebang_bytes != (ssize_t)sizeof(shebang) ||
        !guest_script_has_approved_shebang(shebang, (size_t)shebang_bytes)) {
        reason = "guest-script-shebang-is-not-approved-system-shell";
        rc = -EACCES;
        goto fail;
    }
    if (!guest_script_launch_is_authorized(guest_path, canonical_guest_root,
            canonical_system_root, fd_resolved, S_ISREG(opened_st.st_mode),
            (uint32_t)opened_st.st_mode, shebang, sizeof(shebang))) {
        reason = "guest-script-combined-route-authorization-failed";
        rc = -EACCES;
        goto fail;
    }
    if (close(script_fd) != 0) {
        script_fd = -1;
        reason = "guest-script-close-after-validation-failed";
        rc = -errno;
        goto fail;
    }
    script_fd = -1;

    rc = map_guest_path(GUEST_API10_SHELL_PATH, mapped_shell, sizeof(mapped_shell));
    if (rc != 0) {
        reason = "guest-system-shell-vfs-mapping-failed";
        goto fail;
    }
    if (!realpath(mapped_shell, shell_resolved)) {
        reason = "guest-system-shell-payload-resolution-failed";
        rc = -errno;
        goto fail;
    }
    if (!path_is_within(shell_resolved, native_guest_root)) {
        reason = "guest-system-shell-outside-approved-native-root";
        rc = -EACCES;
        goto fail;
    }
    struct stat shell_st;
    if (stat(shell_resolved, &shell_st) != 0) {
        reason = "guest-system-shell-payload-not-executable-regular-file";
        rc = -errno;
        goto fail;
    }
    if (!S_ISREG(shell_st.st_mode) || !(shell_st.st_mode & 0111)) {
        reason = "guest-system-shell-payload-not-executable-regular-file";
        rc = -EACCES;
        goto fail;
    }
    int shell_kind = guest_elf32_arm_interpreter(shell_resolved, shell_interpreter,
                                                  sizeof(shell_interpreter));
    if (shell_kind != 1 || strcmp(shell_interpreter, "/system/bin/linker") != 0) {
        reason = "guest-system-shell-is-not-verified-api10-dynamic-arm-elf";
        rc = shell_kind < 0 ? shell_kind : -ENOEXEC;
        goto fail;
    }
    rc = patched_dynamic_native_path(shell_resolved, patched_shell, sizeof(patched_shell));
    if (rc != 0 || !realpath(patched_shell, patched_shell_resolved) ||
        !path_is_within(patched_shell_resolved, native_guest_root)) {
        reason = "guest-system-shell-patched-linker-alias-invalid";
        rc = rc != 0 ? rc : -EACCES;
        goto fail;
    }
    struct stat patched_st;
    int patched_kind = guest_elf32_arm_interpreter(patched_shell_resolved,
        patched_interpreter, sizeof(patched_interpreter));
    if (stat(patched_shell_resolved, &patched_st) != 0 || !S_ISREG(patched_st.st_mode) ||
        !(patched_st.st_mode & 0111) || patched_kind != 1 ||
        strcmp(patched_interpreter, "/proc/self/fd/198") != 0) {
        reason = "guest-system-shell-patched-linker-payload-unverified";
        rc = -ENOEXEC;
        goto fail;
    }

    uint32_t preserved[GUEST_SCRIPT_MAX_PRESERVED_ARGS];
    size_t preserved_count = 0;
    pid_t remote_pid = pid;
    rc = guest_script_collect_preserved_args(regs->uregs[1],
        guest_script_remote_read_word, &remote_pid, preserved,
        GUEST_SCRIPT_MAX_PRESERVED_ARGS, &preserved_count);
    if (rc != 0) {
        reason = rc == -E2BIG ? "guest-script-argv-exceeds-bounded-limit"
                              : "guest-script-argv-unreadable";
        goto fail;
    }
    if (regs->uregs[13] <= SCRATCH_BELOW_SP + 16u) {
        reason = "guest-script-argv-scratch-address-underflow";
        rc = -EFAULT;
        goto fail;
    }
    uint32_t scratch = (regs->uregs[13] - SCRATCH_BELOW_SP) &
                       ~((uint32_t)sizeof(long) - 1u);
    struct guest_script_argv_plan plan;
    rc = guest_script_plan_argv(scratch, patched_shell_resolved, preserved,
                                preserved_count, &plan);
    if (rc != 0) {
        reason = "guest-script-argv-layout-invalid-or-too-large";
        goto fail;
    }
    size_t exec_path_bytes = strlen(patched_shell_resolved) + 1;
    if (write_remote(pid, plan.exec_path_address, patched_shell_resolved,
                     exec_path_bytes) != 0 ||
        write_remote(pid, plan.shell_argv0_address, GUEST_API10_SHELL_PATH,
                     sizeof(GUEST_API10_SHELL_PATH)) != 0 ||
        write_remote(pid, plan.script_argv1_address, GUEST_API10_GOLDFISH_SCRIPT,
                     sizeof(GUEST_API10_GOLDFISH_SCRIPT)) != 0 ||
        write_remote(pid, plan.argv_address, plan.argv_words,
                     (plan.argc + 1u) * sizeof(uint32_t)) != 0) {
        reason = "guest-script-launcher-argv-write-failed";
        rc = -EFAULT;
        goto fail;
    }
    regs->uregs[0] = plan.exec_path_address;
    regs->uregs[1] = plan.argv_address;
    if (set_regs(pid, regs) != 0) {
        reason = "guest-script-launcher-register-update-failed";
        rc = -EFAULT;
        goto fail;
    }
    if (state) {
        snprintf(state->pending_exec_target, sizeof(state->pending_exec_target), "%s",
                 GUEST_API10_SHELL_PATH);
        snprintf(state->pending_exec_script, sizeof(state->pending_exec_script), "%s",
                 GUEST_API10_GOLDFISH_SCRIPT);
        state->exec_was_dynamic = 1;
        state->exec_was_script = 1;
    }
    dynamic_exec_allowed_count++;
    guest_script_routes_approved++;
    path_rewrites++;
    guest_script_log_exec_route(pid, state ? state->guest_pid : 0,
                                GUEST_API10_SHELL_PATH,
                                GUEST_API10_GOLDFISH_SCRIPT, preserved_count);
    return 0;

fail:
    if (script_fd >= 0) close(script_fd);
    return guest_exec_failure(failure_reason, reason, rc);
}

static int mediate_guest_execve(pid_t pid, struct tracee_state *state,
                                struct compat_pt_regs *regs, char *diagnostic_path,
                                size_t diagnostic_capacity, const char **failure_reason) {
    char guest[PATH_MAX], host[PATH_MAX], resolved[PATH_MAX], patched[PATH_MAX], patched_resolved[PATH_MAX];
    if (diagnostic_path && diagnostic_capacity) diagnostic_path[0] = '\0';
    if (failure_reason) *failure_reason = "unspecified";
    if (read_remote_string(pid, regs->uregs[0], guest, sizeof(guest)) != 0) {
        if (diagnostic_path && diagnostic_capacity)
            snprintf(diagnostic_path, diagnostic_capacity, "<unreadable-or-too-long>");
        return guest_exec_failure(failure_reason, "exec-path-unreadable-or-too-long", -EFAULT);
    }
    if (diagnostic_path && diagnostic_capacity)
        snprintf(diagnostic_path, diagnostic_capacity, "%s", guest);
    if (guest[0] != '/')
        return guest_exec_failure(failure_reason, "guest-path-not-absolute", -EACCES);
    if (guest_path_has_parent(guest))
        return guest_exec_failure(failure_reason, "guest-path-contains-parent-traversal", -EACCES);
    int rc = map_guest_path(guest, host, sizeof(host));
    if (rc != 0)
        return guest_exec_failure(failure_reason, "guest-vfs-path-mapping-failed", rc);
    if (!realpath(host, resolved)) {
        int saved_errno = errno;
        return guest_exec_failure(failure_reason, "guest-vfs-path-resolution-failed", -saved_errno);
    }
    if (guest_script_path_is_whitelisted(guest))
        return mediate_guest_script_execve(pid, state, regs, guest, host, resolved,
                                           failure_reason);

    char staged_init[PATH_MAX], resolved_init[PATH_MAX];
    int n = snprintf(staged_init, sizeof(staged_init), "%s/init", guest_root);
    if (n <= 0 || (size_t)n >= sizeof(staged_init))
        return guest_exec_failure(failure_reason, "guest-init-path-too-long", -ENAMETOOLONG);
    if (realpath(staged_init, resolved_init) && strcmp(resolved, resolved_init) == 0) {
        rc = original_init_native_path(host, sizeof(host));
        if (rc != 0)
            return guest_exec_failure(failure_reason, "original-init-native-payload-invalid", rc);
        if (!realpath(host, resolved)) {
            int saved_errno = errno;
            return guest_exec_failure(failure_reason, "original-init-payload-resolution-failed", -saved_errno);
        }
    }

    if (!path_is_within(resolved, native_guest_root))
        return guest_exec_failure(failure_reason, "resolved-executable-outside-approved-native-root", -EACCES);
    struct stat st;
    if (stat(resolved, &st) != 0) {
        int saved_errno = errno;
        return guest_exec_failure(failure_reason, "resolved-executable-stat-failed", -saved_errno);
    }
    if (!S_ISREG(st.st_mode))
        return guest_exec_failure(failure_reason, "resolved-executable-is-not-regular-file", -EACCES);
    if (!(st.st_mode & 0111))
        return guest_exec_failure(failure_reason, "resolved-executable-has-no-execute-bit", -EACCES);

    char interpreter[PATH_MAX];
    int elf_kind = guest_elf32_arm_interpreter(resolved, interpreter, sizeof(interpreter));
    if (elf_kind < 0)
        return guest_exec_failure(failure_reason, "target-is-not-a-valid-ELF32-ARM-image", elf_kind);
    int dynamic_exec = 0;
    if (elf_kind > 0) {
        const char *dynamic_failure = "dynamic-PT_INTERP-not-supported-or-alias-not-confined";
        int patched_path_rc = -ENOEXEC;
        int patched_resolved_ok = 0;
        int patched_within_native = 0;
        if (strcmp(interpreter, "/system/bin/linker") == 0) {
            patched_path_rc = patched_dynamic_native_path(resolved, patched, sizeof(patched));
            if (patched_path_rc == 0) {
                if (realpath(patched, patched_resolved)) {
                    patched_resolved_ok = 1;
                    patched_within_native = path_is_within(patched_resolved, native_guest_root);
                    if (!patched_within_native)
                        dynamic_failure = "patched-executable-alias-outside-approved-native-root";
                } else {
                    dynamic_failure = "patched-executable-alias-not-found";
                }
            } else {
                dynamic_failure = "patched-executable-alias-path-invalid";
            }
        } else {
            dynamic_failure = "unsupported-dynamic-PT_INTERP";
        }
        if (strcmp(interpreter, "/system/bin/linker") != 0 || patched_path_rc != 0 ||
            !patched_resolved_ok || !patched_within_native) {
            dynamic_exec_blocked = 1;
            snprintf(dynamic_exec_guest_path, sizeof(dynamic_exec_guest_path), "%s", guest);
            snprintf(dynamic_exec_interpreter, sizeof(dynamic_exec_interpreter), "%s", interpreter);
            fprintf(stderr, "CONTINUOUS CHAIN BLOCKER: guest exec %s has unsupported or unpatched PT_INTERP %s; denied before host linker substitution\n",
                    guest, interpreter);
            return guest_exec_failure(failure_reason, dynamic_failure, -ENOEXEC);
        }
        struct stat patched_st;
        char patched_interpreter[PATH_MAX];
        int patched_kind = guest_elf32_arm_interpreter(patched_resolved, patched_interpreter,
                                                       sizeof(patched_interpreter));
        if (stat(patched_resolved, &patched_st) != 0 || !S_ISREG(patched_st.st_mode) ||
            !(patched_st.st_mode & 0111) || patched_kind != 1 ||
            strcmp(patched_interpreter, "/proc/self/fd/198") != 0) {
            dynamic_exec_blocked = 1;
            snprintf(dynamic_exec_guest_path, sizeof(dynamic_exec_guest_path), "%s", guest);
            snprintf(dynamic_exec_interpreter, sizeof(dynamic_exec_interpreter), "%s", interpreter);
            fprintf(stderr, "CONTINUOUS CHAIN BLOCKER: verified guest-linker alias missing or invalid for %s; denied before host linker substitution\n",
                    guest);
            return guest_exec_failure(failure_reason, "verified-guest-linker-alias-invalid", -ENOEXEC);
        }
        snprintf(resolved, sizeof(resolved), "%s", patched_resolved);
        dynamic_exec = 1;
        dynamic_exec_allowed_count++;
    }

    uint32_t scratch = (regs->uregs[13] - SCRATCH_BELOW_SP) & ~((uint32_t)sizeof(long) - 1u);
    size_t bytes = strlen(resolved) + 1;
    if (bytes >= 2048)
        return guest_exec_failure(failure_reason, "rewritten-exec-path-exceeds-scratch-limit", -EFAULT);
    if (write_remote(pid, scratch, resolved, bytes) != 0)
        return guest_exec_failure(failure_reason, "rewritten-exec-path-could-not-be-written", -EFAULT);
    regs->uregs[0] = scratch;
    if (set_regs(pid, regs) != 0)
        return guest_exec_failure(failure_reason, "execve-path-register-update-failed", -EFAULT);
    if (state) {
        snprintf(state->pending_exec_target, sizeof(state->pending_exec_target), "%s", guest);
        state->pending_exec_script[0] = '\0';
        state->exec_was_dynamic = dynamic_exec;
        state->exec_was_script = 0;
    }
    path_rewrites++;
    if (dynamic_exec)
        printf("GUEST EXEC ALLOW: pid=%d target=%s -> PT_INTERP-patched copy; original API10 linker via inherited fd=198\n",
               pid, guest);
    else
        printf("GUEST EXEC ALLOW: pid=%d target=%s -> verified ELF32 ARM payload in APK native dir\n",
               pid, guest);
    return 0;
}
static int prepare_guest_linker_fd(void) {
    char linker[PATH_MAX];
    int n = snprintf(linker, sizeof(linker), "%s/libgingervm_guest_linker.so", native_guest_root);
    if (n <= 0 || (size_t)n >= sizeof(linker)) { errno = ENAMETOOLONG; return -1; }
    int fd = open(linker, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    struct stat st;
    if (fstat(fd, &st) != 0) { int saved = errno; close(fd); errno = saved; return -1; }
    if (!S_ISREG(st.st_mode) || !(st.st_mode & 0111)) { close(fd); errno = EACCES; return -1; }
    if (fd != GUEST_LINKER_FD) {
        if (fcntl(GUEST_LINKER_FD, F_GETFD) != -1) (void)close(GUEST_LINKER_FD);
        else if (errno != EBADF) { int saved = errno; close(fd); errno = saved; return -1; }
        if (dup2(fd, GUEST_LINKER_FD) < 0) { int saved = errno; close(fd); errno = saved; return -1; }
        close(fd);
    }
    if (fcntl(GUEST_LINKER_FD, F_SETFD, 0) < 0) return -1;
    return 0;
}

static int start_guest(const char *binary, char *const guest_argv[]) {
    pid_t pid = fork();
    if (pid < 0) { fprintf(stderr, "fork supervisor failed: errno=%d\n", errno); return -1; }
    if (pid == 0) {
        if (chdir(guest_root) != 0 || prepare_guest_linker_fd() != 0) {
            dprintf(STDERR_FILENO, "cannot reserve original guest linker fd=%d: errno=%d\n",
                    GUEST_LINKER_FD, errno);
            _exit(125);
        }
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) != 0) _exit(125);
        char *const envp[] = {
            (char *)"HOME=/",
            (char *)"PATH=/sbin:/vendor/bin:/system/sbin:/system/bin:/system/xbin",
            (char *)"LD_LIBRARY_PATH=/vendor/lib:/system/lib",
            (char *)"ANDROID_ROOT=/system",
            (char *)"ANDROID_DATA=/data",
            (char *)"ANDROID_ASSETS=/system/app",
            (char *)"ANDROID_BOOTLOGO=1",
            (char *)"BOOTCLASSPATH=/system/framework/core.jar:/system/framework/bouncycastle.jar:/system/framework/ext.jar:/system/framework/framework.jar:/system/framework/android.policy.jar:/system/framework/services.jar:/system/framework/core-junit.jar",
            NULL
        };
        execve(binary, guest_argv, envp);
        dprintf(STDERR_FILENO, "guest execve failed: errno=%d\n", errno);
        _exit(127);
    }
    traced_pid = pid;
    return (int)pid;
}

static void kill_tracee(pid_t pid) {
    if (pid <= 0) return;
    (void)ptrace(PTRACE_KILL, pid, NULL, NULL);
    (void)kill(pid, SIGKILL);
    int status;
    (void)waitpid(pid, &status, __WALL);
}
static int kill_all_tracees(void) {
    pid_t pids[MAX_TRACEES];
    size_t count = 0;
    for (size_t i = 0; i < tracee_count; ++i)
        if (tracees[i].alive) pids[count++] = tracees[i].pid;
    struct ptrace_cleanup_result cleanup = ptrace_terminate_and_reap(pids, count);
    printf("TRACE CLEANUP: tracked=%zu reaped=%zu already-gone=%zu unresolved=%zu\n",
           cleanup.requested, cleanup.reaped, cleanup.already_gone, cleanup.unresolved);
    trace_cleanup_confirmed = cleanup.unresolved == 0;
    trace_cleanup_unresolved = cleanup.unresolved;
    tracee_count = 0;
    active_tracee_count = 0;
    active_tracee = NULL;
    traced_pid = -1;
    return cleanup.unresolved == 0 ? 0 : -1;
}

static void kill_untracked_tracee(pid_t pid) {
    (void)ptrace(PTRACE_KILL, pid, NULL, NULL);
    (void)kill(pid, SIGKILL);
    for (unsigned attempt = 0; attempt < 4; ++attempt) {
        int status;
        pid_t waited;
        do { waited = waitpid(pid, &status, __WALL); } while (waited < 0 && errno == EINTR);
        if (waited != pid || WIFEXITED(status) || WIFSIGNALED(status)) return;
        if (WIFSTOPPED(status)) {
            (void)ptrace(PTRACE_CONT, pid, NULL, (void *)(uintptr_t)SIGKILL);
            (void)kill(pid, SIGKILL);
        }
    }
}

static int fake_entry(pid_t pid, struct compat_pt_regs *regs, int32_t result,
                      int32_t *pending_return) {
    if (fake_syscall(pid, regs) != 0) return -1;
    *pending_return = result;
    return 0;
}

static int guest_path_under(const char *path, const char *root) {
    size_t n = strlen(root);
    return strncmp(path, root, n) == 0 && (path[n] == '\0' || path[n] == '/');
}

static int guest_path_readonly(const char *path) {
    if (guest_system_readonly && guest_path_under(path, "/system")) return 1;
    if (!guest_root_readonly) return 0;
    for (size_t i = 0; i < mount_count; ++i)
        if (guest_path_under(path, mounts[i].target)) return 0;
    return 1;
}

static int32_t mediate_guest_symlink(pid_t pid, const struct compat_pt_regs *regs,
                                     int at_variant) {
    char target_guest[PATH_MAX] = "<unreadable>";
    char link_guest[PATH_MAX] = "<unreadable>";
    char target_host[PATH_MAX] = "";
    char link_host[PATH_MAX] = "";
    const char *target_backing = "<unmapped>";
    const char *link_backing = "<unmapped>";
    int32_t result = -EACCES;
    unsigned link_arg = at_variant ? 2u : 1u;
    int syscall_number = at_variant ? ARM_NR_SYMLINKAT : ARM_NR_SYMLINK;

    if (at_variant && (int32_t)regs->uregs[1] != -100) goto report;
    if (read_remote_string(pid, regs->uregs[0], target_guest, sizeof(target_guest)) != 0 ||
        read_remote_string(pid, regs->uregs[link_arg], link_guest, sizeof(link_guest)) != 0) {
        result = -EFAULT;
        goto report;
    }
    if (guest_path_readonly(link_guest)) {
        result = -EROFS;
        goto report;
    }

    result = map_guest_symlink_target(target_guest, target_host, sizeof(target_host));
    if (result != 0) goto report;
    result = map_guest_path(link_guest, link_host, sizeof(link_host));
    if (result != 0) goto report;
    if (!path_is_within(link_host, guest_root)) {
        result = -EACCES;
        goto report;
    }
    if (path_is_within(target_host, guest_root)) {
        target_backing = target_host + strlen(guest_root);
        if (*target_backing == '\0') target_backing = "/";
    } else if (native_guest_root[0] && path_is_within(target_host, native_guest_root)) {
        target_backing = "<native-app-private-guest-payload>";
    } else {
        result = -EACCES;
        goto report;
    }
    link_backing = link_host + strlen(guest_root);
    if (*link_backing == '\0') link_backing = "/";
    result = guest_symlink_create_app_private(target_host, link_host, guest_root,
                                               native_guest_root);
    if (active_tracee && active_tracee->pid == pid)
        snprintf(active_tracee->last_guest_path, sizeof(active_tracee->last_guest_path),
                 "%s", link_guest);

report:
    printf("GUEST VFS SYMLINK: host-pid=%d guest-pid=%d syscall=%d target=%s link=%s target-backing=%s link-backing=%s result=%d\n",
           pid, active_tracee ? active_tracee->guest_pid : 1, syscall_number,
           target_guest, link_guest, target_backing, link_backing, result);
    return result;
}

static int path_operation_writes(const struct compat_pt_regs *regs, int nr) {
    if (nr == ARM_NR_OPEN || nr == ARM_NR_OPENAT) {
        unsigned arg = nr == ARM_NR_OPEN ? 1u : 2u;
        unsigned flags = regs->uregs[arg];
        return (flags & 3u) != 0 || (flags & (O_CREAT | O_TRUNC | O_APPEND)) != 0;
    }
    switch (nr) {
        case ARM_NR_CREAT: case ARM_NR_UNLINK: case ARM_NR_MKDIR: case ARM_NR_RMDIR:
        case ARM_NR_MKNOD: case ARM_NR_MKNODAT: case ARM_NR_UNLINKAT: case ARM_NR_RENAMEAT:
            return 1;
        default:
            return 0;
    }
}

static int path_syscall(pid_t pid, struct compat_pt_regs *regs, int nr,
                        int32_t *pending_return, int *is_virtual) {
    unsigned arg;
    switch (nr) {
        case ARM_NR_OPEN: case ARM_NR_CREAT: case ARM_NR_UNLINK: case ARM_NR_CHDIR:
        case ARM_NR_ACCESS: case ARM_NR_MKDIR: case ARM_NR_RMDIR: case ARM_NR_CHMOD:
        case ARM_NR_LCHOWN: case ARM_NR_CHOWN: case ARM_NR_STAT64: case ARM_NR_LSTAT64:
        case ARM_NR_READLINK: case ARM_NR_MKNOD:
        case ARM_NR_OPENAT: case ARM_NR_MKDIRAT: case ARM_NR_MKNODAT:
        case ARM_NR_FCHOWNAT: case ARM_NR_FSTATAT64: case ARM_NR_UNLINKAT:
        case ARM_NR_READLINKAT: case ARM_NR_FCHMODAT: case ARM_NR_FACCESSAT:
        case ARM_NR_CHOWN32: case ARM_NR_LCHOWN32:
            break;
        default:
            return -ENOSYS;
    }
    arg = (nr == ARM_NR_OPENAT || nr == ARM_NR_MKDIRAT || nr == ARM_NR_MKNODAT ||
           nr == ARM_NR_FCHOWNAT || nr == ARM_NR_FSTATAT64 || nr == ARM_NR_UNLINKAT ||
           nr == ARM_NR_READLINKAT || nr == ARM_NR_FCHMODAT || nr == ARM_NR_FACCESSAT)
          ? 1u : 0u;
    char guest[PATH_MAX];
    int rc = decode_guest_path_arg(pid, regs, nr, arg, guest, sizeof(guest));
    if (rc != 0) return rc;
    if (active_tracee && active_tracee->pid == pid)
        snprintf(active_tracee->last_guest_path, sizeof(active_tracee->last_guest_path), "%s", guest);
    if (nr == ARM_NR_STAT64 || nr == ARM_NR_LSTAT64 || nr == ARM_NR_FSTATAT64) {
        struct guest_pseudo_device_metadata metadata;
        int recognized = guest_pseudo_device_metadata_for_path(guest, &metadata);
        if (recognized < 0) return recognized;
        if (recognized > 0) {
            rc = guest_pseudo_device_backing_present(guest);
            if (rc != 0) return rc;
            unsigned char stat64[GUEST_ARM32_STAT64_BYTES];
            rc = guest_pseudo_device_stat64(metadata.mode, metadata.major,
                                             metadata.minor, stat64);
            if (rc != 0) return rc;
            uint32_t output = regs->uregs[nr == ARM_NR_FSTATAT64 ? 2 : 1];
            if (output == 0 || write_remote(pid, output, stat64, sizeof(stat64)) != 0)
                return -EFAULT;
            *is_virtual = 1;
            *pending_return = 0;
            virtual_file_ops++;
            printf("GUEST PSEUDO-DEVICE STAT64: guest-pid=%d path=%s mode=0%o rdev=%u:%u; ARM32 guest metadata, app-private placeholder verified no-follow\n",
                   active_tracee ? active_tracee->guest_pid : -1, guest,
                   metadata.mode & 07777u, metadata.major, metadata.minor);
            return 0;
        }
    }
    if (nr == ARM_NR_OPENAT &&
        strcmp(guest, GUEST_UEVENT_SYSFS_ATTRIBUTE_PATH) == 0) {
        unsigned flags = regs->uregs[2];
        if (!is_guest_ueventd(pid)) return -EPERM;
        if ((flags & 3u) != O_WRONLY || (flags & (O_CREAT | O_TRUNC | O_APPEND)) != 0)
            return -EACCES;
        if (!virtual_uevent_bound || !virtual_uevent_passcred ||
            !virtual_uevent_rcvbuf_configured) return -ENOTCONN;
        int fd = alloc_virtual_fd(VIRTUAL_FD_SYSFS_UEVENT);
        if (fd < 0) return fd;
        *is_virtual = 1;
        *pending_return = fd;
        virtual_file_ops++;
        printf("GUEST SYSFS UEVENT OPEN: guest-pid=%d guest-path=%s dirfd=%d flags=0x%x virtual-fd=%d; no backing file/device accessed\n",
               active_tracee->guest_pid, guest, (int32_t)regs->uregs[0], flags, fd);
        return 0;
    }
    if (nr == ARM_NR_OPEN || nr == ARM_NR_OPENAT) {
        struct guest_pseudo_device_metadata metadata;
        int recognized = guest_pseudo_device_metadata_for_path(guest, &metadata);
        if (recognized < 0) return recognized;
        if (recognized > 0) {
            unsigned flags = regs->uregs[nr == ARM_NR_OPEN ? 1 : 2];
            if (flags & O_DIRECTORY) return -ENOTDIR;
            rc = guest_pseudo_device_backing_present(guest);
            if (rc != 0) return rc;
            if (strcmp(guest, "/dev/__null__") == 0 ||
                strcmp(guest, "/dev/__kmsg__") == 0) {
                printf("GUEST TEMP DEVICE OPEN: guest-pid=%d path=%s; API10 init/ueventd dup2 requires a real descriptor backed only by the app-private temporary placeholder; host /dev is not used\n",
                       active_tracee ? active_tracee->guest_pid : -1, guest);
            } else {
                int fd = alloc_virtual_fd(metadata.kind);
                if (fd < 0) return fd;
                set_virtual_fd_open_flags(active_tracee, fd, flags);
                struct guest_vsocket_fd *entry = guest_vsocket_fd_get(&guest_sockets, fd);
                if (entry) {
                    entry->device_mode = metadata.mode;
                    entry->device_major = metadata.major;
                    entry->device_minor = metadata.minor;
                }
                virtual_pseudo_device_open_count++;
                virtual_device_count++;
                *is_virtual = 1;
                *pending_return = fd;
                printf("GUEST PSEUDO-DEVICE OPEN: guest-pid=%d executable=%s path=%s kind=%d mode=0%o rdev=%u:%u flags=0x%x fd=%d; app-private software descriptor, host /dev untouched\n",
                       active_tracee ? active_tracee->guest_pid : -1,
                       active_tracee ? active_tracee->exec_target : "<unknown>",
                       guest, metadata.kind, metadata.mode & 07777u,
                       metadata.major, metadata.minor, flags, fd);
                return 0;
            }
        }
    }
    if (guest_path_readonly(guest) && path_operation_writes(regs, nr)) return -EROFS;
    rc = rewrite_path_arg(pid, regs, arg, guest, sizeof(guest));
    if (rc != 0) return rc;

    /* Ownership, mode and device-node effects exist only in the software model. */
    switch (nr) {
        case ARM_NR_CHMOD: case ARM_NR_LCHOWN: case ARM_NR_CHOWN: case ARM_NR_FCHMOD: case ARM_NR_FCHOWN:
        case ARM_NR_FCHOWNAT: case ARM_NR_FCHMODAT: case ARM_NR_CHOWN32: case ARM_NR_LCHOWN32:
            *is_virtual = 1; *pending_return = 0; return 0;
        case ARM_NR_MKNOD: case ARM_NR_MKNODAT:
            rc = make_guest_device(guest);
            *is_virtual = 1; *pending_return = rc; return 0;
        default:
            return 1; /* translated path; allow the ordinary app-private file call */
    }
}

static int mediate_guest_wait4(pid_t pid, struct compat_pt_regs *regs) {
    int32_t requested = (int32_t)regs->uregs[0];
    if (requested == -1) return 0; /* wait for any guest child */
    if (requested <= 0 || !active_tracee) return -ENOSYS; /* no process-group model */
    struct tracee_state *child = find_guest_child(active_tracee->guest_pid, requested);
    if (!child) return -ECHILD;
    regs->uregs[0] = (uint32_t)child->pid;
    return set_regs(pid, regs) == 0 ? 0 : -EFAULT;
}

static void record_guest_path_fd_result(struct tracee_state *state,
                                        const struct compat_pt_regs *regs,
                                        int32_t result) {
    if (!state || state->virtual_fd_table_id == 0) return;
    pid_t table_id = (pid_t)state->virtual_fd_table_id;
    if ((state->last_syscall == ARM_NR_OPEN || state->last_syscall == ARM_NR_OPENAT) &&
        result >= 0) {
        int flags = (int)state->last_syscall_args[
            state->last_syscall == ARM_NR_OPEN ? 1 : 2];
        guest_path_fd_remove(&guest_path_fds, table_id, result);
        if ((flags & O_DIRECTORY) && state->last_guest_path[0]) {
            int rc = guest_path_fd_track(&guest_path_fds, table_id, result,
                                         state->last_guest_path);
            printf("GUEST DIRFD PROVENANCE: guest-pid=%d table=%u fd=%d path=%s result=%d\n",
                   state->guest_pid, state->virtual_fd_table_id, result,
                   state->last_guest_path, rc);
        }
        return;
    }
    if (state->last_syscall == ARM_NR_CLOSE && result == 0) {
        guest_path_fd_remove(&guest_path_fds, table_id,
                             (int32_t)state->last_syscall_args[0]);
        return;
    }
    if (state->last_syscall == ARM_NR_CHDIR && result == 0 &&
        state->last_guest_path[0]) {
        snprintf(state->guest_cwd, sizeof(state->guest_cwd), "%s",
                 state->last_guest_path);
        return;
    }
    if (state->last_syscall == ARM_NR_DUP2 && result >= 0) {
        int source_fd = (int32_t)state->last_syscall_args[0];
        int target_fd = (int32_t)state->last_syscall_args[1];
        char path[GUEST_PATH_FD_PATH_CAPACITY];
        if (guest_path_fd_lookup(&guest_path_fds, table_id, source_fd,
                                 path, sizeof(path)) == 0)
            (void)guest_path_fd_track(&guest_path_fds, table_id, target_fd, path);
        else
            guest_path_fd_remove(&guest_path_fds, table_id, target_fd);
    }
    (void)regs;
}

static int mediate_guest_kill(struct compat_pt_regs *regs) {
    int32_t target_pid = (int32_t)regs->uregs[0];
    int32_t signal_number = (int32_t)regs->uregs[1];
    if (target_pid <= 0 || signal_number < 0 || signal_number > 64) return -EINVAL;
    struct tracee_state *target = find_tracee_guest_pid(target_pid);
    if (!target) return -ESRCH;
    if (signal_number == 0) return 0;
    return kill(target->pid, signal_number) == 0 ? 0 : -errno;
}

static int translate_guest_pid_result(pid_t pid, struct tracee_state *state,
                                      struct compat_pt_regs *regs) {
    int32_t result = (int32_t)regs->uregs[0];
    if (result <= 0) return 0;
    if (state->last_syscall == ARM_NR_FORK || state->last_syscall == ARM_NR_CLONE ||
        state->last_syscall == ARM_NR_VFORK) {
        struct tracee_state *child = find_tracee_host_pid((pid_t)result);
        if (!child) return 0;
        regs->uregs[0] = (uint32_t)(child->is_thread ? child->guest_tid : child->guest_pid);
        return set_regs(pid, regs) == 0 ? 0 : -EFAULT;
    }
    if (state->last_syscall == ARM_NR_WAIT4) {
        struct tracee_state *child = find_tracee_host_pid((pid_t)result);
        if (!child || child->is_thread || child->guest_parent_pid != state->guest_pid || child->guest_reaped) {
            regs->uregs[0] = (uint32_t)-ECHILD;
        } else {
            regs->uregs[0] = (uint32_t)child->guest_pid;
            child->guest_reaped = 1;
        }
        return set_regs(pid, regs) == 0 ? 0 : -EFAULT;
    }
    return 0;
}

static int dispatch_entry(pid_t pid, struct tracee_state *state,
                          struct compat_pt_regs *regs, int nr,
                          int32_t *pending_return, int *fake) {
    *fake = 0;
    if (nr == ARM_NR_SIGACTION) {
        int forward = 0;
        int32_t guest_error = -EFAULT;
        if (mediate_guest_sigaction(pid, state, regs, &guest_error, &forward) != 0)
            return -1;
        if (!forward) {
            guest_sigaction_compat_failures++;
            *pending_return = guest_error;
            *fake = 1;
        }
        return 0;
    }
    if (nr == ARM_NR_SIGPROCMASK) {
        if (mediate_guest_sigprocmask(pid, state, regs, pending_return) != 0) return -1;
        *fake = 1;
        return 0;
    }
    if (nr == ARM_NR_SETPGID) {
        int32_t requested_pid = (int32_t)regs->uregs[0];
        int32_t requested_pgid = (int32_t)regs->uregs[1];
        struct tracee_state *target = requested_pid == 0 ? state :
            find_tracee_guest_pid(requested_pid);
        uint32_t new_pgid = 0;
        *pending_return = guest_process_group_set(
            (uint32_t)state->guest_pid,
            target ? (uint32_t)target->guest_pid : 0,
            target ? (uint32_t)target->guest_parent_pid : 0,
            target && target->alive && !target->is_thread,
            requested_pid, requested_pgid,
            target ? target->guest_pgid : 0, &new_pgid);
        if (*pending_return == 0) target->guest_pgid = new_pgid;
        guest_setpgid_calls++;
        printf("GUEST SETPGID: guest-pid=%d request-pid=%d request-pgid=%d target=%d target-parent=%d result=%d guest-pgid=%u; host setpgid not called\n",
               state->guest_pid, requested_pid, requested_pgid,
               target ? target->guest_pid : 0,
               target ? target->guest_parent_pid : 0, *pending_return,
               target ? target->guest_pgid : 0);
        *fake = 1;
        return 0;
    }
    if (nr == ARM_NR_SETTIMEOFDAY) {
        uint32_t timeval_address = regs->uregs[0];
        uint32_t timezone_address = regs->uregs[1];
        struct guest_arm32_timezone requested = {0, 0};
        if (timeval_address != 0) {
            *pending_return = -EPERM;
        } else if (timezone_address == 0) {
            *pending_return = -EPERM;
        } else if (read_remote(pid, timezone_address, &requested, sizeof(requested)) != 0) {
            *pending_return = -EFAULT;
        } else {
            *pending_return = guest_timezone_set_request(0, 1, requested, &guest_timezone);
        }
        guest_timezone_calls++;
        printf("GUEST SETTIMEOFDAY: guest-pid=%d timeval=0x%08x timezone=0x%08x west=%d dst=%d result=%d guest-timezone-only host clock unchanged\n",
               state->guest_pid, timeval_address, timezone_address,
               requested.minutes_west, requested.dst_time, *pending_return);
        *fake = 1;
        return 0;
    }
    if (nr == ARM_NR_FCHDIR) {
        char guest_cwd[GUEST_PATH_FD_PATH_CAPACITY];
        int fd = (int32_t)regs->uregs[0];
        *pending_return = guest_path_fd_lookup(
            &guest_path_fds, (pid_t)state->virtual_fd_table_id,
            fd, guest_cwd, sizeof(guest_cwd));
        if (*pending_return == 0)
            snprintf(state->guest_cwd, sizeof(state->guest_cwd), "%s", guest_cwd);
        printf("GUEST FCHDIR: guest-pid=%d fd=%d cwd=%s result=%d; host fchdir not called\n",
               state->guest_pid, fd, *pending_return == 0 ? state->guest_cwd : "<unchanged>",
               *pending_return);
        *fake = 1;
        return 0;
    }
    enum guest_syscall_class policy = guest_syscall_policy(nr);
    if (nr == ARM_NR_FSTAT64 && is_virtual_fd_number((int32_t)regs->uregs[0])) {
        int fd = (int32_t)regs->uregs[0];
        struct guest_vsocket_fd *entry = guest_vsocket_fd_get(&guest_sockets, fd);
        if (!entry || !tracee_owns_virtual_fd(state, fd)) {
            *pending_return = -EBADF;
        } else if (entry->kind >= VIRTUAL_FD_DEV_NULL &&
                   entry->kind <= VIRTUAL_FD_DEV_FULL) {
            unsigned char stat64[GUEST_ARM32_STAT64_BYTES];
            *pending_return = guest_pseudo_device_stat64(entry->device_mode,
                entry->device_major, entry->device_minor, stat64);
            if (*pending_return == 0 &&
                (regs->uregs[1] == 0 || write_remote(pid, regs->uregs[1],
                    stat64, sizeof(stat64)) != 0)) *pending_return = -EFAULT;
            if (*pending_return == 0) virtual_file_ops++;
            printf("GUEST PSEUDO-DEVICE FSTAT64: guest-pid=%d fd=%d kind=%d mode=0%o rdev=%u:%u result=%d; guest metadata only\n",
                   state->guest_pid, fd, entry->kind, entry->device_mode & 07777u,
                   entry->device_major, entry->device_minor, *pending_return);
        } else {
            *pending_return = -EBADF;
        }
        *fake = 1;
        return 0;
    }
    if (nr == ARM_NR_EXECVE) {
        char guest_path[PATH_MAX];
        const char *reason = "unspecified";
        int rc = mediate_guest_execve(pid, state, regs, guest_path,
                                      sizeof(guest_path), &reason);
        if (rc == 0) return 0;
        denied_count++;
        log_broker_denial_detail(pid, state, nr, rc, guest_path, reason, 1);
        *pending_return = rc;
        *fake = 1;
        return 0;
    }
    if (nr == ARM_NR_WAIT4) {
        int rc = mediate_guest_wait4(pid, regs);
        if (rc == 0) return 0;
        *pending_return = rc; *fake = 1; return 0;
    }
    if (nr == ARM_NR_KILL) {
        *pending_return = mediate_guest_kill(regs); *fake = 1; return 0;
    }
    if (nr == ARM_NR_MOUNT) {
        *pending_return = virtual_mount(pid, regs); *fake = 1; return 0;
    }
    if (nr == ARM_NR_UMOUNT2) {
        *pending_return = virtual_umount(pid, regs); *fake = 1; return 0;
    }
    if (nr == ARM_NR_SOCKET) {
        *pending_return = virtual_guest_socket_create(pid, regs->uregs[0],
                                                       regs->uregs[1], regs->uregs[2]);
        *fake = 1; return 0;
    }
    if (nr == ARM_NR_IOCTL && is_virtual_fd_number((int32_t)regs->uregs[0])) {
        int fd = (int32_t)regs->uregs[0];
        struct guest_vsocket_fd *ioctl_fd = guest_vsocket_fd_get(&guest_sockets, fd);
        if (!ioctl_fd || !tracee_owns_virtual_fd(state, fd))
            *pending_return = -EBADF;
        else if (ioctl_fd->kind == VIRTUAL_FD_NETCFG)
            *pending_return = virtual_guest_network_ioctl(pid, fd,
                regs->uregs[1], regs->uregs[2]);
        else
            *pending_return = -ENOTTY;
        *fake = 1;
        return 0;
    }
    if (nr == ARM_NR_BIND) {
        int fd = (int32_t)regs->uregs[0];
        *pending_return = fd == virtual_uevent_fd
            ? virtual_uevent_bind(pid, regs)
            : virtual_guest_socket_bind(pid, fd, regs->uregs[1], regs->uregs[2]);
        *fake = 1; return 0;
    }
    if (nr == ARM_NR_CONNECT) {
        *pending_return = virtual_guest_socket_connect(pid, (int32_t)regs->uregs[0],
                                                       regs->uregs[1], regs->uregs[2]);
        *fake = 1; return 0;
    }
    if (nr == ARM_NR_LISTEN) {
        *pending_return = virtual_guest_socket_listen(pid, (int32_t)regs->uregs[0],
                                                       (int32_t)regs->uregs[1]);
        *fake = 1; return 0;
    }
    if (nr == ARM_NR_ACCEPT) {
        *pending_return = virtual_guest_socket_accept(pid, (int32_t)regs->uregs[0],
                                                      regs->uregs[1], regs->uregs[2]);
        *fake = 1; return 0;
    }
    if (nr == ARM_NR_SOCKETPAIR) {
        *pending_return = virtual_guest_socketpair(pid, regs->uregs[0], regs->uregs[1],
                                                   regs->uregs[2], regs->uregs[3]);
        *fake = 1; return 0;
    }
    if (nr == ARM_NR_SEND || nr == ARM_NR_RECV) {
        int fd = (int32_t)regs->uregs[0];
        if (is_virtual_fd_number(fd)) {
            *pending_return = virtual_guest_socket_stream_io(pid, fd, regs->uregs[1],
                regs->uregs[2], (int)regs->uregs[3], nr == ARM_NR_RECV);
            *fake = 1; return 0;
        }
    }
    if (nr == ARM_NR_RECVMSG) {
        int fd = (int32_t)regs->uregs[0];
        *pending_return = fd == virtual_uevent_fd
            ? virtual_uevent_recvmsg(pid, regs)
            : (is_virtual_fd_number(fd) ? -EOPNOTSUPP : -ENOTSOCK);
        *fake = 1;
        return 0;
    }
    if (nr == ARM_NR_SETSOCKOPT) {
        *pending_return = virtual_guest_socket_setsockopt(pid, regs); *fake = 1; return 0;
    }
    if (nr == ARM_NR_GETSOCKOPT) {
        *pending_return = virtual_guest_socket_getsockopt(pid, (int32_t)regs->uregs[0],
            regs->uregs[1], regs->uregs[2], regs->uregs[3], regs->uregs[4]);
        *fake = 1; return 0;
    }
    if (nr == ARM_NR_FTRUNCATE) {
        char guest_relative[PATH_MAX] = "";
        int guest_fd = (int32_t)regs->uregs[0];
        int32_t length = (int32_t)regs->uregs[1];
        *pending_return = guest_ftruncate_app_private(pid, guest_fd, length, guest_root,
                                                       guest_relative, sizeof(guest_relative));
        *fake = 1;
        virtual_file_ops++;
        printf("GUEST FILE FTRUNCATE: host-pid=%d guest-pid=%d fd=%d length=%d result=%d backing=%s\n",
               pid, active_tracee ? active_tracee->guest_pid : 1, guest_fd, length,
               *pending_return, guest_relative[0] ? guest_relative : "<not-guest-root-regular-file>");
        return 0;
    }
    if (nr == ARM_NR_SOCKETCALL) {
        *pending_return = virtual_socketcall(pid, regs); *fake = 1; return 0;
    }
    if (nr == ARM_NR_POLL) {
        *pending_return = virtual_poll(pid, regs); *fake = 1; return 0;
    }
    if ((nr == ARM_NR_READ || nr == ARM_NR_WRITE) &&
        is_virtual_fd_number((int32_t)regs->uregs[0])) {
        int fd = (int32_t)regs->uregs[0];
        struct guest_vsocket_fd *entry = guest_vsocket_fd_get(&guest_sockets, fd);
        if (entry && entry->kind >= VIRTUAL_FD_DEV_NULL &&
            entry->kind <= VIRTUAL_FD_DEV_RANDOM)
            *pending_return = virtual_guest_pseudo_device_io(pid, fd,
                regs->uregs[1], regs->uregs[2], nr == ARM_NR_READ);
        else
            *pending_return = virtual_guest_socket_stream_io(pid, fd,
                regs->uregs[1], regs->uregs[2], 0, nr == ARM_NR_READ);
        *fake = 1; return 0;
    }
    if ((nr == ARM_NR_FCNTL || nr == ARM_NR_FCNTL64) &&
        is_virtual_fd_number((int32_t)regs->uregs[0])) {
        *pending_return = virtual_fd_fcntl(active_tracee, (int32_t)regs->uregs[0],
            (int)regs->uregs[1], (int)regs->uregs[2]);
        *fake = 1; return 0;
    }
    if (nr == ARM_NR_CLOSE && is_virtual_fd_number((int32_t)regs->uregs[0])) {
        *pending_return = close_virtual_fd(active_tracee, (int32_t)regs->uregs[0]);
        *fake = 1; return 0;
    }
    if (nr == ARM_NR_CLOSE && (int32_t)regs->uregs[0] == GUEST_LINKER_FD) {
        *pending_return = 0; *fake = 1; return 0;
    }
    if ((nr == ARM_NR_FCNTL || nr == ARM_NR_FCNTL64) &&
        (int32_t)regs->uregs[0] == GUEST_LINKER_FD) {
        int command = (int)regs->uregs[1];
        int32_t value = -EINVAL;
        if (command == F_GETFD) value = 0; /* keep inherited interpreter fd across exec */
        else if (command == F_SETFD) value = 0; /* guest cannot set close-on-exec */
        else if (command == F_GETFL) value = O_RDONLY;
        else if (command == F_SETFL) value = 0;
        *pending_return = value; *fake = 1; return 0;
    }
    if (nr == ARM_NR_DUP2 && (int32_t)regs->uregs[1] == GUEST_LINKER_FD) {
        *pending_return = (int32_t)regs->uregs[0] == GUEST_LINKER_FD ? GUEST_LINKER_FD : -EBUSY;
        *fake = 1; return 0;
    }
    if (nr == ARM_NR_SYMLINK || nr == ARM_NR_SYMLINKAT) {
        *pending_return = mediate_guest_symlink(pid, regs, nr == ARM_NR_SYMLINKAT);
        *fake = 1;
        virtual_symlink_ops++;
        return 0;
    }
    if (policy == GUEST_SYSCALL_PATH_REWRITE) {
        int is_virtual = 0;
        int32_t result = 0;
        int rc = path_syscall(pid, regs, nr, &result, &is_virtual);
        if (rc == 1) return set_regs(pid, regs);
        if (rc == 0 && is_virtual) {
            *pending_return = result; *fake = 1; virtual_device_count++; return 0;
        }
        if (rc == 0) return 0;
        *pending_return = rc; *fake = 1; return 0;
    }
    if (policy == GUEST_SYSCALL_VIRTUALIZE) {
        int32_t value = 0;
        switch (nr) {
            case ARM_NR_GETPID: value = active_tracee ? active_tracee->guest_pid : 1; break;
            case ARM_NR_GETTID: value = active_tracee ? active_tracee->guest_tid : 1; break;
            case ARM_NR_GETPPID: value = active_tracee ? active_tracee->guest_parent_pid : 0; break;
            default: value = 0; break;
        }
        virtual_identity_count++;
        *pending_return = value; *fake = 1; return 0;
    }
    if (policy == GUEST_SYSCALL_BLOCK_PROCESS) {
        blocked_process_count++;
        log_broker_denial_detail(pid, state, nr, -EAGAIN, NULL,
                                 "process-start-blocked-by-policy", 0);
        *pending_return = -EAGAIN; *fake = 1; return 0;
    }
    if (policy == GUEST_SYSCALL_TRACE_PROCESS) return 0;
    if (policy == GUEST_SYSCALL_VIRTUAL_MOUNT) {
        *pending_return = -EPERM; *fake = 1; return 0;
    }
    if (policy == GUEST_SYSCALL_VIRTUAL_DEVICE) {
        int32_t value = -ENOTTY;
        if (nr == ARM_NR_MKNOD || nr == ARM_NR_MKNODAT) {
            char guest[PATH_MAX];
            unsigned arg = nr == ARM_NR_MKNODAT ? 1u : 0u;
            int rc = read_remote_string(pid, regs->uregs[arg], guest, sizeof(guest)) == 0
                ? make_guest_device(guest) : -EFAULT;
            value = rc;
        } else if (nr == ARM_NR_FCHMOD || nr == ARM_NR_FCHOWN) {
            value = 0;
        }
        virtual_device_count++;
        *pending_return = value; *fake = 1; return 0;
    }
    if (nr == ARM_NR_UMASK) {
        *pending_return = 0; *fake = 1; virtual_identity_count++; return 0;
    }
    if (nr == ARM_NR_EXECVE || nr == ARM_NR_PTRACE ||
        nr == ARM_NR_PIVOT_ROOT || nr == ARM_NR_KILL) {
        denied_count++;
        log_broker_denial_detail(pid, state, nr, -EPERM, NULL,
                                 "privileged-or-process-control-syscall-denied", 0);
        *pending_return = -EPERM; *fake = 1; return 0;
    }
    if (policy == GUEST_SYSCALL_ALLOW_SAFE) {
        /* ftruncate64/getdents64/fstat64 and standard descriptor operations touch
         * only fds produced by app-private path rewriting or inherited stdio. */
        return 0;
    }
    denied_count++;
    log_broker_denial_detail(pid, state, nr, -ENOSYS, NULL,
                             policy == GUEST_SYSCALL_DENY
                                 ? "explicit-syscall-deny-policy"
                                 : "unknown-syscall-class-default-deny",
                             0);
    *pending_return = -ENOSYS; *fake = 1;
    return 0;
}

static long guest_trace_options(void) {
    return PTRACE_O_TRACESYSGOOD | PTRACE_O_EXITKILL | PTRACE_O_TRACEFORK |
           PTRACE_O_TRACEVFORK | PTRACE_O_TRACECLONE | PTRACE_O_TRACEEXEC;
}

static int set_guest_trace_options(pid_t pid) {
    return ptrace(PTRACE_SETOPTIONS, pid, NULL,
                  (void *)(uintptr_t)guest_trace_options()) == 0 ? 0 : -1;
}

static int probe_tracee_sigmask_api(pid_t pid) {
    uint64_t initial = 0, verified = 0;
    if (guest_sigmask_ptrace_get(pid, &initial) != 0) {
        int saved = errno;
        fprintf(stderr, "PTRACE_GETSIGMASK probe failed for initial stopped tracee pid=%d size=%zu errno=%d(%s)\n",
                pid, sizeof(initial), saved, guest_diag_errno_name(saved));
        errno = saved;
        return -1;
    }
    /* Apply the identical mask once to confirm SETSIGMASK is available before /init runs. */
    if (guest_sigmask_ptrace_set(pid, initial) != 0) {
        int saved = errno;
        fprintf(stderr, "PTRACE_SETSIGMASK probe failed for initial stopped tracee pid=%d size=%zu errno=%d(%s)\n",
                pid, sizeof(initial), saved, guest_diag_errno_name(saved));
        errno = saved;
        return -1;
    }
    if (guest_sigmask_ptrace_get(pid, &verified) != 0 || verified != initial) {
        int saved = errno ? errno : EIO;
        fprintf(stderr, "PTRACE signal-mask probe changed or could not verify the stopped tracee mask pid=%d errno=%d(%s)\n",
                pid, saved, guest_diag_errno_name(saved));
        errno = saved;
        return -1;
    }
    printf("PTRACE SIGNAL MASK API PROBE: pid=%d GETSIGMASK/SETSIGMASK size=%zu real-mask-preserved=1\n",
           pid, sizeof(initial));
    return 0;
}

static int run_trace(pid_t pid, int *exit_code, int *exit_signal) {
    int status = 0;
    pid_t waited;
    do { waited = waitpid(pid, &status, __WALL); } while (waited < 0 && errno == EINTR);
    if (waited != pid || !WIFSTOPPED(status) || WSTOPSIG(status) != SIGTRAP) {
        fprintf(stderr, "initial ARM32 /init did not reach successful post-exec SIGTRAP; status=0x%x errno=%d\n",
                status, errno);
        kill_tracee(pid); return -1;
    }
    if (probe_tracee_sigmask_api(pid) != 0) {
        fprintf(stderr, "legacy ARM sigprocmask compatibility is unavailable; refusing to start /init without real mask operations\n");
        kill_tracee(pid);
        return -1;
    }
    saw_exec = 1;
    tracee_count = 0;
    active_tracee_count = 0;
    next_guest_pid = 2;
    next_guest_tid = 2;
    next_virtual_fd_table_id = 2;
    struct tracee_state *root = add_tracee(pid, 0, 1, 1, 0, 0);
    if (!root) { kill_tracee(pid); return -1; }
    root->virtual_fd_table_id = 1;
    root->guest_pgid = 1;
    snprintf(root->guest_cwd, sizeof(root->guest_cwd), "/");
    snprintf(root->exec_target, sizeof(root->exec_target), "/init");
    printf("CONTINUOUS TRACE START: original static ARM32 /init pid=%d\n", pid);
    if (set_guest_trace_options(pid) != 0 || resume_trace(pid, 0) != 0) {
        fprintf(stderr, "ptrace setup failed: errno=%d\n", errno); kill_all_tracees(); return -1;
    }
    unsigned long stops = 0;
    struct timespec start, now, pause = { .tv_sec = 0, .tv_nsec = 1000000 };
    clock_gettime(CLOCK_MONOTONIC, &start);
    for (;;) {
        if (user_cancel_requested) {
            trace_cancelled = 1;
            break;
        }
        if (active_tracee_count == 0) {
            return 0;
        }
        waited = waitpid(-1, &status, __WALL | WNOHANG);
        if (waited == 0) {
            clock_gettime(CLOCK_MONOTONIC, &now);
            long elapsed = (now.tv_sec - start.tv_sec) * 1000L + (now.tv_nsec - start.tv_nsec) / 1000000L;
            if (elapsed >= trace_timeout_ms || stops >= TRACE_STOP_LIMIT) {
                trace_timed_out = 1;
                break;
            }
            nanosleep(&pause, NULL);
            continue;
        }
        if (waited < 0 && errno == EINTR) continue;
        if (waited < 0 && errno == ECHILD && active_tracee_count == 0) return 0;
        if (waited < 0) {
            fprintf(stderr, "waitpid on guest process tree failed: errno=%d\n", errno);
            kill_all_tracees(); return -1;
        }
        struct tracee_state *state = find_tracee(waited);
        if (!state) {
            fprintf(stderr, "unregistered traced pid=%d; killing it fail-closed\n", waited);
            (void)ptrace(PTRACE_KILL, waited, NULL, NULL);
            (void)kill(waited, SIGKILL);
            continue;
        }
        if (WIFEXITED(status)) {
            printf("GUEST PROCESS EXIT: pid=%d code=%d\n", waited, WEXITSTATUS(status));
            if (waited == pid) *exit_code = WEXITSTATUS(status);
            remove_tracee(waited);
            continue;
        }
        if (WIFSIGNALED(status)) {
            printf("GUEST PROCESS EXIT: pid=%d signal=%d\n", waited, WTERMSIG(status));
            if (waited == pid) { *exit_code = -1; *exit_signal = WTERMSIG(status); }
            remove_tracee(waited);
            continue;
        }
        if (!WIFSTOPPED(status)) continue;
        int sig = WSTOPSIG(status);
        unsigned event = (unsigned)status >> 16;
        active_tracee = state;
        if (event == PTRACE_EVENT_FORK || event == PTRACE_EVENT_VFORK || event == PTRACE_EVENT_CLONE) {
            unsigned long child_message = 0;
            if (ptrace(PTRACE_GETEVENTMSG, waited, NULL, &child_message) != 0) {
                fprintf(stderr, "cannot read ptrace child event: errno=%d\n", errno);
                kill_all_tracees(); return -1;
            }
            pid_t child_pid = (pid_t)child_message;
            int child_is_thread = event == PTRACE_EVENT_CLONE &&
                state->last_syscall == ARM_NR_CLONE && (state->clone_flags & 0x00010000UL);
            pid_t child_guest_pid = child_is_thread ? state->guest_pid : next_guest_pid++;
            pid_t child_guest_tid = child_is_thread ? next_guest_tid++ : child_guest_pid;
            pid_t child_parent_guest_pid = child_is_thread ? state->guest_parent_pid : state->guest_pid;
            struct tracee_state *child_state = tracee_count >= MAX_TRACEES ? NULL :
                add_tracee(child_pid, 1, child_guest_pid, child_guest_tid,
                           child_parent_guest_pid, child_is_thread);
            if (!child_state) {
                    process_limit_hit = 1;
                blocked_process_count++;
                fprintf(stderr, "PROCESS TREE LIMIT: refusing guest child pid=%d at cap=%d\n",
                        child_pid, MAX_TRACEES);
                kill_untracked_tracee(child_pid);
            } else {
                int shares_files = event == PTRACE_EVENT_CLONE &&
                    (state->clone_flags & 0x00000400UL) != 0;
                child_state->virtual_fd_table_id = shares_files
                    ? state->virtual_fd_table_id : next_virtual_fd_table_id++;
                child_state->guest_pgid = state->guest_pgid;
                snprintf(child_state->guest_cwd, sizeof(child_state->guest_cwd), "%s",
                         state->guest_cwd[0] ? state->guest_cwd : "/");
                if (!shares_files && guest_path_fd_clone_owner(
                        &guest_path_fds, (pid_t)state->virtual_fd_table_id,
                        (pid_t)child_state->virtual_fd_table_id) != 0) {
                    fprintf(stderr, "cannot clone guest directory-fd provenance parent=%d child=%d\n",
                            state->guest_pid, child_state->guest_pid);
                    kill_all_tracees(); return -1;
                }
                child_state->virtual_fd_mask = state->virtual_fd_mask;
                memcpy(child_state->virtual_fd_flags, state->virtual_fd_flags,
                       sizeof(child_state->virtual_fd_flags));
                child_state->guest_ruid = state->guest_ruid;
                child_state->guest_euid = state->guest_euid;
                child_state->guest_rgid = state->guest_rgid;
                child_state->guest_egid = state->guest_egid;
                snprintf(child_state->exec_target, sizeof(child_state->exec_target), "%s",
                         state->exec_target[0] ? state->exec_target : "<unknown>");
                snprintf(child_state->exec_script_path, sizeof(child_state->exec_script_path),
                         "%s", state->exec_script_path);
                process_events++;
                printf("GUEST PROCESS EVENT: parent=%d guest-pid=%d child=%d guest-pid=%d type=%s tracees=%zu/%d\n",
                       waited, state->guest_pid, child_pid, child_guest_pid,
                       event == PTRACE_EVENT_FORK ? "fork" : event == PTRACE_EVENT_VFORK ? "vfork" : "clone",
                       active_tracee_count, MAX_TRACEES);
            }
            if (resume_trace(waited, 0) != 0) { kill_all_tracees(); return -1; }
            if (process_limit_hit) {
                *exit_code = -1; *exit_signal = 0; kill_all_tracees(); return 0;
            }
            continue;
        }
        if (event == PTRACE_EVENT_EXEC) {
            broker_sigsys_clear(&state->broker_sigsys);
            int script_launch = state->exec_was_script || state->pending_exec_script[0] != '\0';
            if (state->pending_exec_target[0]) {
                snprintf(state->exec_target, sizeof(state->exec_target), "%s",
                         state->pending_exec_target);
                state->pending_exec_target[0] = '\0';
            }
            if (script_launch) {
                snprintf(state->exec_script_path, sizeof(state->exec_script_path), "%s",
                         state->pending_exec_script[0] ? state->pending_exec_script
                                                       : GUEST_API10_GOLDFISH_SCRIPT);
            } else {
                state->exec_script_path[0] = '\0';
            }
            state->pending_exec_script[0] = '\0';
            close_virtual_fds_on_exec(state);
            state->target_elf_text_seen = 0;
            state->target_elf_text_pc = 0;
            state->target_elf_text_file_offset = 0;
            successful_guest_execs++;
            if (state->exec_was_dynamic) {
                dynamic_exec_started_count++;
                if (script_launch) {
                    guest_script_exec_started_count++;
                    guest_script_log_launch_event(waited, state->guest_pid,
                        state->exec_target[0] ? state->exec_target : GUEST_API10_SHELL_PATH,
                        state->exec_script_path[0] ? state->exec_script_path
                                                   : GUEST_API10_GOLDFISH_SCRIPT,
                        GUEST_LINKER_FD);
                    printf("GUEST STARTUP STAGE: guest-script-shell-linker-entry=observed pid=%d guest-pid=%d shell=%s script=%s; exact-target-ELF-text-map=awaiting-syscall-PC; C-main/Zygote/framework=unproven\n",
                           waited, state->guest_pid,
                           state->exec_target[0] ? state->exec_target : GUEST_API10_SHELL_PATH,
                           state->exec_script_path[0] ? state->exec_script_path
                                                      : GUEST_API10_GOLDFISH_SCRIPT);
                } else {
                    printf("GUEST DYNAMIC EXEC EVENT: pid=%d target=%s; kernel entered the original API10 linker via fd=%d; waiting for exact executable-text map at a syscall PC\n",
                           waited, state->exec_target[0] ? state->exec_target : "unknown guest path",
                           GUEST_LINKER_FD);
                    printf("GUEST STARTUP STAGE: linker-entry=observed pid=%d guest-pid=%d target=%s; target-ELF-text-map=awaiting-syscall-PC; C-main/Zygote/framework=unproven\n",
                           waited, state->guest_pid,
                           state->exec_target[0] ? state->exec_target : "unknown guest path");
                }
            } else {
                printf("GUEST EXEC EVENT: pid=%d target=%s (verified ELF32 ARM payload)\n",
                       waited, state->exec_target[0] ? state->exec_target : "unknown guest path");
            }
            state->exec_was_dynamic = 0;
            state->exec_was_script = 0;
            if (resume_trace(waited, 0) != 0) { kill_all_tracees(); return -1; }
            continue;
        }
        if (event != 0) {
            fprintf(stderr, "unsupported ptrace event=%u for pid=%d; stopping tree fail-closed\n", event, waited);
            kill_all_tracees(); return -1;
        }
        if (state->needs_options && sig == SIGSTOP) {
            if (set_guest_trace_options(waited) != 0 || resume_trace(waited, 0) != 0) {
                fprintf(stderr, "cannot attach child pid=%d to syscall trace: errno=%d\n", waited, errno);
                kill_all_tracees(); return -1;
            }
            state->needs_options = 0;
            continue;
        }
        if (sig == ARM_SYSCALL_STOP) {
            struct compat_pt_regs regs;
            if (get_regs(waited, &regs) != 0) { fprintf(stderr, "ARM compat register read failed for pid=%d: errno=%d\n", waited, errno); kill_all_tracees(); return -1; }
            observe_guest_target_elf_text(waited, state, &regs);
            if (!state->expect_exit) {
                if (broker_sigsys_expire_before_next_entry(&state->broker_sigsys))
                    printf("BROKERED SIGSYS CANDIDATE EXPIRED: pid=%d next-syscall-entry=%u wait-status=0x%x\n",
                           waited, regs.uregs[7], status);
                state->last_syscall = (int32_t)regs.uregs[7];
                memcpy(state->last_syscall_args, regs.uregs, sizeof(state->last_syscall_args));
                state->last_guest_path[0] = '\0';
                if (state->last_syscall == ARM_NR_CLONE) state->clone_flags = regs.uregs[0];
                syscall_stops++;
                int fake = 0;
                int32_t result = 0;
                int rc = dispatch_entry(waited, state, &regs, state->last_syscall, &result, &fake);
                if (rc != 0) { fprintf(stderr, "broker failure at ARM syscall %d pid=%d: errno=%d\n", state->last_syscall, waited, errno); kill_all_tracees(); return -1; }
                if (fake) {
                    if (fake_entry(waited, &regs, result, &state->pending_return) != 0) { fprintf(stderr, "could not cancel syscall %d pid=%d: errno=%d\n", state->last_syscall, waited, errno); kill_all_tracees(); return -1; }
                    state->pending = 1;
                    broker_sigsys_arm(&state->broker_sigsys, state->last_syscall, result);
                    enum guest_syscall_class cls = guest_syscall_policy(state->last_syscall);
                    if ((cls == GUEST_SYSCALL_DENY && result < 0) ||
                        cls == GUEST_SYSCALL_BLOCK_PROCESS) denied_count++;
                    if (syscall_stops <= MAX_TRACE_LINES)
                        printf("TRACE pid=%d entry #%lu: ARM syscall=%d class=%d brokered result=%d\n",
                               waited, syscall_stops, state->last_syscall, (int)cls, result);
                } else {
                    state->pending = 0;
                    if (syscall_stops <= MAX_TRACE_LINES)
                        printf("TRACE pid=%d entry #%lu: ARM syscall=%d class=%d forwarded-supervised\n",
                               waited, syscall_stops, state->last_syscall, (int)guest_syscall_policy(state->last_syscall));
                }
                state->expect_exit = 1;
                if (dynamic_exec_blocked) {
                    *exit_code = -1; *exit_signal = 0;
                    kill_all_tracees();
                    return 0;
                }
            } else {
                int32_t syscall_result = state->pending ? state->pending_return :
                    (int32_t)regs.uregs[0];
                if (complete_guest_sigaction(waited, state, &regs, &syscall_result) != 0) {
                    fprintf(stderr, "cannot complete guest legacy sigaction translation pid=%d; terminating traced tree\n",
                            waited);
                    kill_all_tracees(); return -1;
                }
                record_guest_path_fd_result(state, &regs, syscall_result);
                int marker_release_observed = 0;
                if (state->last_syscall == ARM_NR_OPEN &&
                    strcmp(state->last_guest_path, GUEST_COLD_BOOT_MARKER_PATH) == 0 &&
                    syscall_result >= 0) {
                    marker_release_observed = guest_coldboot_note_marker_open(
                        &coldboot_observation,
                        strcmp(state->exec_target, "/sbin/ueventd") == 0,
                        state->last_guest_path, syscall_result);
                    printf("GUEST COLD-BOOT MARKER OPEN: host-pid=%d guest-pid=%d executable=%s path=%s fd=%d flags=0x%x create=%d app-private-virtual-dev=%d\n",
                           waited, state->guest_pid, state->exec_target,
                           state->last_guest_path, syscall_result,
                           state->last_syscall_args[1],
                           (state->last_syscall_args[1] & O_CREAT) != 0,
                           coldboot_observation.marker_opened_by_ueventd);
                }
                int marker_stat_syscall = state->last_syscall == ARM_NR_STAT64 ||
                    state->last_syscall == ARM_NR_LSTAT64 ||
                    state->last_syscall == ARM_NR_FSTATAT64;
                if (marker_stat_syscall &&
                    strcmp(state->last_guest_path, GUEST_COLD_BOOT_MARKER_PATH) == 0 &&
                    strcmp(state->exec_target, "/sbin/ueventd") == 0) {
                    printf("GUEST UEVENTD COLD-BOOT MARKER PRECHECK: syscall=%d(%s) result=%d path=%s; API10 device_init checks this before walking /sys\n",
                           state->last_syscall,
                           guest_diag_syscall_name(state->last_syscall),
                           syscall_result, state->last_guest_path);
                }
                if (state->guest_pid == 1 && marker_stat_syscall &&
                    strcmp(state->last_guest_path, GUEST_COLD_BOOT_MARKER_PATH) == 0) {
                    marker_release_observed = guest_coldboot_note_pid1_stat(
                        &coldboot_observation, 1, state->last_guest_path, syscall_result) ||
                        marker_release_observed;
                    if (coldboot_observation.pid1_stat_checks <= 8)
                        printf("GUEST COLD-BOOT PID1 STAT: syscall=%d(%s) result=%d path=%s marker-open-by-ueventd=%d stat-success-after-marker=%d checks=%lu\n",
                               state->last_syscall,
                               guest_diag_syscall_name(state->last_syscall),
                               syscall_result, state->last_guest_path,
                               coldboot_observation.marker_opened_by_ueventd,
                               coldboot_observation.pid1_stat_succeeded_after_marker,
                               coldboot_observation.pid1_stat_checks);
                }
                if (marker_release_observed)
                    puts("INIT COLD-BOOT WAIT CONDITION OBSERVED: after ueventd created the guest marker, API10 wait_for_file's PID1 stat(/dev/.coldboot_done) returned 0; source loop condition is satisfied, builtin return itself is not directly traced");
                if (state->pending) regs.uregs[0] = (uint32_t)state->pending_return;
                if (state->pending && set_regs(waited, &regs) != 0) { fprintf(stderr, "cannot set virtual return value pid=%d: errno=%d\n", waited, errno); kill_all_tracees(); return -1; }
                if (state->pending) {
                    broker_sigsys_mark_response_committed(&state->broker_sigsys);
                    printf("BROKERED RESPONSE COMMITTED: pid=%d wait-status=0x%x ARM syscall=%d virtual result=%d SIGSYS-candidate=%d\n",
                           waited, status, state->last_syscall, state->pending_return,
                           state->broker_sigsys.armed);
                }
                if (!state->pending && translate_guest_pid_result(waited, state, &regs) != 0) {
                    fprintf(stderr, "cannot translate guest process result pid=%d: errno=%d\n", waited, errno);
                    kill_all_tracees(); return -1;
                }
                if (!state->pending && state->last_syscall == ARM_NR_EXECVE &&
                    (int32_t)regs.uregs[0] < 0) {
                    int32_t exec_result = (int32_t)regs.uregs[0];
                    const char *failed_exec_path = state->pending_exec_script[0]
                        ? state->pending_exec_script
                        : state->pending_exec_target[0] ? state->pending_exec_target : NULL;
                    const char *failed_exec_reason = state->pending_exec_script[0]
                        ? "kernel-execve-returned-error-after-guest-script-shell-substitution"
                        : "kernel-execve-returned-error-after-path-rewrite";
                    log_broker_denial_detail(waited, state, ARM_NR_EXECVE, exec_result,
                        failed_exec_path, failed_exec_reason, 1);
                    state->pending_exec_target[0] = '\0';
                    state->pending_exec_script[0] = '\0';
                    state->exec_was_dynamic = 0;
                    state->exec_was_script = 0;
                }
                state->expect_exit = 0;
                state->pending = 0;
            }
            if (resume_trace(waited, 0) != 0) { fprintf(stderr, "ptrace resume failed pid=%d: errno=%d\n", waited, errno); kill_all_tracees(); return -1; }
            stops++;
            continue;
        }
        if (sig == SIGSYS) {
            siginfo_t siginfo;
            memset(&siginfo, 0, sizeof(siginfo));
            errno = 0;
            int siginfo_rc = ptrace(PTRACE_GETSIGINFO, waited, NULL, &siginfo);
            int siginfo_errno = siginfo_rc == 0 ? 0 : errno;
            int siginfo_code = siginfo_rc == 0 ? siginfo.si_code : 0;
            int seccomp_details = siginfo_rc == 0 && siginfo_code == SYS_SECCOMP;
            int sigsys_syscall = seccomp_details ? siginfo.si_syscall : -1;
            unsigned int sigsys_arch = seccomp_details ? (unsigned int)siginfo.si_arch : 0;
            void *sigsys_call_addr = seccomp_details ? siginfo.si_call_addr : NULL;
            struct compat_pt_regs signal_regs;
            int signal_regs_rc = get_regs(waited, &signal_regs);
            uint32_t live_r7 = signal_regs_rc == 0 ? signal_regs.uregs[7] : UINT32_MAX;
            uint32_t live_r0 = signal_regs_rc == 0 ? signal_regs.uregs[0] : UINT32_MAX;
            uint32_t live_pc = signal_regs_rc == 0 ? signal_regs.uregs[15] : UINT32_MAX;
            printf("PTRACE SIGSYS WAIT STATUS: pid=%d raw=0x%x stop=%d event=%u expect-exit=%d pending=%d candidate=%d response-committed=%d candidate-syscall=%d candidate-result=%d siginfo-rc=%d siginfo-errno=%d si-code=%d si-syscall=%d si-arch=0x%x si-call-addr=%p last-syscall=%d last-args=%u,%u,%u,%u,%u,%u live-r7=%u live-r0=%u live-pc=0x%08x regs-rc=%d\n",
                   waited, status, sig, event, state->expect_exit, state->pending,
                   state->broker_sigsys.armed, state->broker_sigsys.response_committed,
                   state->broker_sigsys.syscall_number, state->broker_sigsys.virtual_result,
                   siginfo_rc, siginfo_errno, siginfo_code, sigsys_syscall, sigsys_arch,
                   sigsys_call_addr, state->last_syscall,
                   state->last_syscall_args[0], state->last_syscall_args[1],
                   state->last_syscall_args[2], state->last_syscall_args[3],
                   state->last_syscall_args[4], state->last_syscall_args[5],
                   live_r7, live_r0, live_pc, signal_regs_rc);
            if (siginfo_rc == 0 && broker_sigsys_take(&state->broker_sigsys, sig,
                                                       siginfo_code, sigsys_syscall)) {
                brokered_sigsys_suppressed++;
                printf("BROKERED SYSCALL SIGSYS SUPPRESSED: pid=%d signal=%d ARM syscall=%d virtual result=%d response-committed=%d wait-status=0x%x si-code=%d\n",
                       waited, sig, state->broker_sigsys.syscall_number,
                       state->broker_sigsys.virtual_result,
                       state->broker_sigsys.response_committed, status, siginfo_code);
                if (resume_trace(waited, 0) != 0) {
                    fprintf(stderr, "could not resume after brokered SIGSYS: errno=%d\n", errno);
                    kill_all_tracees(); return -1;
                }
                continue;
            }
            if (siginfo_rc == 0 && seccomp_details && sigsys_syscall >= 0) {
                log_unbrokered_seccomp_sigsys_context(waited, state, siginfo_code,
                    sigsys_syscall, sigsys_arch, sigsys_call_addr,
                    signal_regs_rc == 0 ? &signal_regs : NULL, signal_regs_rc);
            }
            if (state->broker_sigsys.armed) {
                printf("BROKERED SIGSYS CANDIDATE REJECTED: pid=%d si-code=%d si-syscall=%d expected-placeholder-syscall=-1 expected-seccomp=%d; forwarding signal\n",
                       waited, siginfo_code, sigsys_syscall, SYS_SECCOMP);
                broker_sigsys_clear(&state->broker_sigsys);
            }
        }
        if (sig == SIGSTOP) {
            if (resume_trace(waited, 0) != 0) { kill_all_tracees(); return -1; }
            continue;
        }
        if (sig == SIGCHLD) {
            if (resume_trace(waited, sig) != 0) { kill_all_tracees(); return -1; }
            continue;
        }
        if (sig > 0 && sig <= 64 && sig != SIGSTOP) {
            printf("GUEST SIGNAL FORWARDED: pid=%d signal=%d within traced process tree\n", waited, sig);
            if (resume_trace(waited, sig) != 0) { kill_all_tracees(); return -1; }
            continue;
        }
        if (sig == SIGSTOP) {
            if (resume_trace(waited, 0) != 0) { kill_all_tracees(); return -1; }
            continue;
        }
        fprintf(stderr, "stopping guest pid=%d on unsupported signal %d\n", waited, sig);
        kill_all_tracees(); return -1;
    }
    if (user_cancel_requested) {
        trace_cancelled = 1;
        int cleanup_rc = kill_all_tracees();
        printf("USER CANCEL REQUESTED: SIGTERM/SIGINT received; tracked process tree cleanup %s\n",
               cleanup_rc == 0 ? "completed" : "FAILED");
        *exit_code = cleanup_rc == 0 ? 130 : -1;
        *exit_signal = 0;
        return cleanup_rc;
    }
    (void)kill_all_tracees();
    *exit_code = -1; *exit_signal = 0;
    return 0;
}

int main(int argc, char **argv) {
    (void)setvbuf(stdout, NULL, _IOLBF, 0);
    guest_vsocket_table_init(&guest_sockets);
    guest_uevent_queue_init(&guest_uevent_queue);
    guest_net_state_init(&guest_network_state);
    guest_path_fd_table_init(&guest_path_fds);
    memset(&coldboot_observation, 0, sizeof(coldboot_observation));
    memset(&guest_timezone, 0, sizeof(guest_timezone));
    if (argc != 6 || strcmp(argv[5], "/init") != 0) {
        fprintf(stderr, "usage: gingervm-init-supervisor <original-init-in-native-libs> <app-private-guest-root> <allowed-guest-native-lib-dir> <trace-ms> /init\n");
        return 2;
    }
    if (install_cancel_signal_handlers() != 0) {
        fprintf(stderr, "cannot install user-cancel signal handlers: errno=%d\n", errno);
        return 2;
    }
    if (!realpath(argv[2], guest_root)) {
        fprintf(stderr, "guest root is not accessible: errno=%d\n", errno); return 2;
    }
    if (!realpath(argv[3], native_guest_root)) {
        fprintf(stderr, "guest ABI native-library directory is not accessible: errno=%d\n", errno); return 2;
    }
    char *timeout_end = NULL;
    errno = 0;
    trace_timeout_ms = strtol(argv[4], &timeout_end, 10);
    if (errno != 0 || timeout_end == argv[4] || *timeout_end != '\0' ||
        trace_timeout_ms < 500 || trace_timeout_ms > 120000) {
        fprintf(stderr, "trace timeout must be between 500 and 120000 milliseconds\n"); return 2;
    }
    guest_program = argv[5];
    char binary[PATH_MAX];
    if (!realpath(argv[1], binary)) {
        fprintf(stderr, "guest executable is not accessible: errno=%d\n", errno); return 2;
    }
    size_t lib_len = strlen(native_guest_root);
    if (strncmp(binary, native_guest_root, lib_len) != 0 ||
        (binary[lib_len] != '\0' && binary[lib_len] != '/')) {
        fprintf(stderr, "refusing guest executable outside the APK-extracted guest ABI library directory\n"); return 2;
    }
    struct stat st;
    if (stat(binary, &st) != 0 || !S_ISREG(st.st_mode) || !(st.st_mode & 0111)) {
        fprintf(stderr, "guest executable is not an executable regular file\n"); return 2;
    }
    if (prepare_init_dirs() != 0) { fprintf(stderr, "could not prepare app-private guest dirs: errno=%d\n", errno); return 2; }
    if (strcmp(guest_program, "/init") != 0 && prepare_standalone_guest() != 0) {
        fprintf(stderr, "could not prepare software-only standalone guest mounts: errno=%d\n", errno); return 2;
    }
    if (user_cancel_requested) {
        trace_cancelled = 1;
        puts("USER CANCEL REQUESTED: received before guest /init was started; no tracees were created");
        puts("STOP: user-requested cancellation before guest exec; no supervisor timeout occurred");
        return 130;
    }
    puts("MODE: one continuous native ARM64-supervised ARM32 guest process tree; no host root requested");
    puts("ROOT PROCESS: original official static ARM32 /init");
    puts("EXECUTION: supervisor and executable payloads are loaded from APK-extracted ABI library directories; guest data remains app-private");
    puts("POLICY: guest paths rewritten inside app-private root; unknown/privileged calls fail closed");
    puts("VIRTUALIZATION: guest rootfs,/system,/data,/cache, /dev,/proc,/sys mounts, IDs, modes, devices and property/signaling operations are software-only");
    printf("GUEST HARDWARE PROFILE: official image identity hardware=%s; guest CPU count=%u and RAM=%u kB are explicit synthetic profile values, not host-phone data\n",
           GUEST_PROFILE_HARDWARE, GUEST_PROFILE_CPU_COUNT,
           GUEST_PROFILE_SYNTHETIC_RAM_TOTAL_KB);
    printf("GUEST NETWORK PROFILE: source-backed Goldfish %s address=%s netmask=%s gateway=%s dns1=%s; all interface/route changes app-private, packet I/O=unavailable, host network calls=0\n",
           GUEST_PROFILE_NET_IFACE, GUEST_PROFILE_NET_ADDRESS,
           GUEST_PROFILE_NET_NETMASK, GUEST_PROFILE_NET_GATEWAY,
           GUEST_PROFILE_NET_DNS1);
    printf("PROCESS TREE: fork/clone/vfork followed with ptrace; cap=%d; verified static ARM32 execs and validated original-linker PT_INTERP aliases are admitted\n", MAX_TRACEES);
    puts("DYNAMIC ELF POLICY: original API10 linker is inherited as fd 198; unsupported PT_INTERP is denied before host-linker substitution");
    int child = start_guest(binary, &argv[5]);
    if (child < 0) return 2;
    int exit_code = -1, exit_signal = 0;
    int rc = run_trace((pid_t)child, &exit_code, &exit_signal);
    traced_pid = -1;
    printf("INITIAL /init POST-EXEC: %s\n", saw_exec ? "SIGTRAP observed" : "not observed");
    printf("CONTINUOUS PROCESS TREE: fork/clone/vfork events=%lu; guest exec events=%lu; dynamic execs redirected=%lu; kernel entries into original guest linker=%lu; target ELF text entries=%lu (shell=%lu app_process=%lu; C main symbol unproven); maximum tracees=%d\n",
           process_events, successful_guest_execs, dynamic_exec_allowed_count,
           dynamic_exec_started_count, guest_target_elf_text_entry_count,
           guest_shell_elf_text_entry_count, guest_app_process_elf_text_entry_count,
           MAX_TRACEES);
    printf("GUEST STARTUP STAGE SUMMARY: original-init-post-exec=%s; original-linker-entry-events=%lu; target-ELF-executable-mapping entries=%lu; C-main symbol/Zygote/framework/system_server/desktop=unproven\n",
           saw_exec ? "observed" : "not-observed", dynamic_exec_started_count,
           guest_target_elf_text_entry_count);
    printf("GUEST SCRIPT LAUNCH SUMMARY: approved-routes=%lu; exec-events=%lu; guest-shell=%s; guest-script=%s; host-shell-exec=0; network-effects=guest-software-broker-only\n",
           guest_script_routes_approved, guest_script_exec_started_count,
           GUEST_API10_SHELL_PATH, GUEST_API10_GOLDFISH_SCRIPT);
    printf("SYSCALL ENTRIES: %lu; PATH REWRITES: %lu; VIRTUAL MOUNTS: %lu; VIRTUAL DEVICE/MODE OPS: %lu; VIRTUAL ID OPS: %lu; VIRTUAL FILE OPS: %lu; VIRTUAL SYMLINK OPS: %lu; VIRTUAL SOCKET CALLS: %lu; VIRTUAL POLL WAITS: %lu; BROKERED SIGSYS SUPPRESSED: %lu; BLOCKED PROCESS STARTS: %lu; DENIED: %lu\n",
           syscall_stops, path_rewrites, virtual_mount_count, virtual_device_count,
           virtual_identity_count, virtual_file_ops, virtual_symlink_ops, virtual_socket_calls, virtual_poll_waits,
           brokered_sigsys_suppressed, blocked_process_count, denied_count);
    printf("BROKER DIAGNOSTIC SUMMARY: denial-details=%lu suppressed=%lu (limit=%u); failed-exec-details=%lu suppressed=%lu (limit=%u)\n",
           broker_denial_diagnostics_emitted, broker_denial_diagnostics_suppressed,
           MAX_BROKER_DENIAL_DIAGNOSTICS, exec_failure_diagnostics_emitted,
           exec_failure_diagnostics_suppressed, MAX_EXEC_FAILURE_DIAGNOSTICS);
    printf("SIGSYS CONTEXT DIAGNOSTICS: emitted=%lu suppressed=%lu (limit=%u); non-placeholder SYS_SECCOMP records only; signal forwarding unchanged\n",
           sigsys_context_diagnostics_emitted, sigsys_context_diagnostics_suppressed,
           MAX_SIGSYS_CONTEXT_DIAGNOSTICS);
    printf("LEGACY SIGPROCMASK COMPAT: syscall=126 calls=%lu diagnostics=%lu suppressed=%lu (limit=%u) ptrace-failures=%lu; real-mask=%s; SIGSYS forwarding unchanged\n",
           guest_sigprocmask_compat_calls, guest_sigprocmask_diagnostics_emitted,
           guest_sigprocmask_diagnostics_suppressed, MAX_SIGPROCMASK_DIAGNOSTICS,
           guest_sigprocmask_ptrace_failures,
           guest_sigprocmask_ptrace_failures == 0 ? "PTRACE_GETSIGMASK/SETSIGMASK" : "fail-closed");
    printf("LEGACY SIGACTION COMPAT: syscall=67 via rt_sigaction=174 calls=%lu failures=%lu; legacy mask low-word preserved; unmatched SIGSYS forwarding unchanged\n",
           guest_sigaction_compat_calls, guest_sigaction_compat_failures);
    printf("GUEST PROCESS/TIME COMPAT: setpgid calls=%lu guest-pgid table only; settimeofday calls=%lu timezone-only; host process groups and wall clock unchanged\n",
           guest_setpgid_calls, guest_timezone_calls);
    printf("GUEST NETWORK CONTROL SUMMARY: virtual-af-inet-dgram-sockets=%lu ioctl=%lu rejected=%lu eth0-up=%d address-set=%d netmask-set=%d default-route-set=%d; host socket/ioctl/packet/network calls=0\n",
           virtual_network_socket_count, virtual_network_ioctl_count,
           virtual_network_ioctl_rejected_count,
           (guest_network_state.flags & GUEST_NET_IFF_UP) != 0,
           guest_network_state.address_set, guest_network_state.netmask_set,
           guest_network_state.default_route_set);
    printf("VIRTUAL UEVENT SUMMARY: sockets=%lu binds=%lu setsockopt=%lu fd=%d bound=%d passcred=%d rcvbufforce=%d writes=%lu recvmsg-delivered=%lu queued=%lu delivered=%lu rejected=%lu queue-left=%zu; marker-open-by-ueventd=%d PID1-stat-success-after-marker=%d marker/stat-condition-observed=%d PID1-stat-checks=%lu\n",
           virtual_uevent_socket_count, virtual_uevent_bind_count,
           virtual_uevent_setsockopt_count, virtual_uevent_fd,
           virtual_uevent_bound, virtual_uevent_passcred,
           virtual_uevent_rcvbuf_configured, virtual_uevent_write_count,
           virtual_uevent_recvmsg_count, guest_uevent_queue.enqueued,
           guest_uevent_queue.delivered, guest_uevent_queue.rejected,
           guest_uevent_queue.count, coldboot_observation.marker_opened_by_ueventd,
           coldboot_observation.pid1_stat_succeeded_after_marker,
           coldboot_observation.marker_stat_pair_observed,
           coldboot_observation.pid1_stat_checks);
    printf("VIRTUAL PROPERTY/SIGNAL SOCKET SUMMARY: created=%lu binds=%lu connects=%lu accepts=%lu signal-pairs=%lu; host AF_UNIX socket/socketpair/bind/connect/listen/accept/setsockopt/getsockopt/send/recv calls=0\n",
           virtual_property_socket_count, virtual_property_bind_count,
           virtual_property_connect_count, virtual_property_accept_count,
           virtual_socketpair_count);
    if (strcmp(guest_program, "/init") == 0 && (trace_timed_out || trace_cancelled))
        printf("INIT COLD-BOOT OBSERVATION: marker-open-by-ueventd=%d; PID1-stat-success-after-marker=%d; marker/stat-condition-observed=%d; one source-backed guest eth0 net event is modeled and drained by API10 ueventd during coldboot; wait builtin return is inferred from the API10 source condition, not directly traced\n",
               coldboot_observation.marker_opened_by_ueventd,
               coldboot_observation.pid1_stat_succeeded_after_marker,
               coldboot_observation.marker_stat_pair_observed);
    if (dynamic_exec_blocked)
        printf("UNSUPPORTED DYNAMIC EXEC: guest exec %s requires PT_INTERP %s; denied before host linker substitution\n",
               dynamic_exec_guest_path, dynamic_exec_interpreter);
    if (trace_cancelled || trace_timed_out || process_limit_hit)
        printf("TRACE CLEANUP STATUS: confirmed=%d unresolved=%zu\n",
               trace_cleanup_confirmed, trace_cleanup_unresolved);
    if (trace_cancelled) {
        if (trace_cleanup_confirmed)
            puts("STOP: user cancellation cleanup confirmed; supervisor terminated and reaped the tracked process tree");
        else
            printf("STOP: user cancellation cleanup incomplete; unresolved tracees=%zu\n", trace_cleanup_unresolved);
    }
    else if (trace_timed_out) {
        if (trace_cleanup_confirmed)
            puts("STOP: bounded continuous process-tree trace ended by supervisor timeout; all tracees stopped and reaped");
        else
            printf("STOP: supervisor timeout cleanup incomplete; unresolved tracees=%zu\n", trace_cleanup_unresolved);
    }
    else if (process_limit_hit) {
        if (trace_cleanup_confirmed)
            puts("STOP: process tree reached the safe cap; all tracees stopped and reaped");
        else
            printf("STOP: process cap cleanup incomplete; unresolved tracees=%zu\n", trace_cleanup_unresolved);
    }
    else if (exit_signal) printf("STOP: root /init terminated by signal %d\n", exit_signal);
    else if (exit_code >= 0) printf("STOP: root /init exited with code %d\n", exit_code);
    else if (dynamic_exec_blocked) printf("STOP: unsupported dynamic guest exec; process tree stopped fail-closed\n");
    else printf("STOP: supervisor error\n");
    printf("HOST PRIVILEGED MOUNTS: 0 (host mount/umount were never invoked)\n");
    if (rc != 0) return 1;
    if (!saw_exec) return 1;
    if (trace_cancelled) return exit_code == 130 ? 130 : 1;
    if (dynamic_exec_blocked) return 3;
    if (process_limit_hit) return 4;
    if (exit_signal) return 128 + exit_signal;
    if (exit_code > 0) return 1;
    return 0;
}
