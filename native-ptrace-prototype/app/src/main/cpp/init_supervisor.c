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
#define ARM_NR_RT_SIGPROCMASK 175
#define ARM_NR_SIGALTSTACK 186
#define ARM_NR_VFORK 190
#define ARM_NR_MMAP2 192
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
#define VIRTUAL_FD_BASE 5000
#define MAX_VIRTUAL_FDS 16
#define MAX_TRACEES 32
#define GUEST_LINKER_FD 198

struct compat_pt_regs { uint32_t uregs[18]; };
struct guest_mount { char target[PATH_MAX]; char backing[PATH_MAX]; };
struct tracee_state {
    pid_t pid;
    pid_t guest_pid;
    pid_t guest_tid;
    pid_t guest_parent_pid;
    unsigned long clone_flags;
    int alive;
    int is_thread;
    int guest_reaped;
    int expect_exit;
    int pending;
    int needs_options;
    int last_syscall;
    int exec_was_dynamic;
    int32_t pending_return;
    struct broker_sigsys_candidate broker_sigsys;
    char exec_target[PATH_MAX];
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
static unsigned long path_rewrites;
static unsigned long guest_target_path_opens;
static unsigned long virtual_mount_count;
static unsigned long virtual_device_count;
static unsigned long virtual_identity_count;
static unsigned long virtual_socket_calls;
static unsigned long virtual_poll_waits;
static unsigned long blocked_process_count;
static unsigned long process_events;
static unsigned long successful_guest_execs;
static unsigned long dynamic_exec_allowed_count;
static unsigned long dynamic_exec_started_count;
static unsigned long brokered_sigsys_suppressed;
static int virtual_fds[MAX_VIRTUAL_FDS];
static size_t virtual_fd_count;
static int virtual_property_fd = -1;
static int virtual_property_bound;
static int virtual_property_listening;
static int saw_exec;
static int trace_timed_out;
static volatile sig_atomic_t user_cancel_requested;
static int trace_cancelled;
static int guest_root_readonly;
static int guest_system_readonly;
static struct tracee_state tracees[MAX_TRACEES];
static size_t tracee_count;
static size_t active_tracee_count;
static pid_t next_guest_pid = 2;
static pid_t next_guest_tid = 2;
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

static int read_remote_string(pid_t pid, uint32_t address, char *out, size_t capacity) {
    if (capacity == 0) return -1;
    for (size_t i = 0; i < capacity; ++i) {
        if (read_remote(pid, address + (uint32_t)i, &out[i], 1) != 0) return -1;
        if (out[i] == '\0') return 0;
    }
    out[capacity - 1] = '\0';
    return -1;
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

static int rewrite_path_arg(pid_t pid, struct compat_pt_regs *regs, unsigned arg,
                            char *guest_out, size_t guest_capacity) {
    if (arg >= 6 || read_remote_string(pid, regs->uregs[arg], guest_out, guest_capacity) != 0)
        return -EFAULT;
    char host[PATH_MAX];
    int rc = map_guest_path(guest_out, host, sizeof(host));
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

static int rewrite_symlink(pid_t pid, struct compat_pt_regs *regs, int at_variant) {
    char target_guest[PATH_MAX], link_guest[PATH_MAX], target_host[PATH_MAX], link_host[PATH_MAX];
    unsigned link_arg = at_variant ? 2u : 1u;
    if (at_variant && (int32_t)regs->uregs[1] != -100) return -EACCES;
    if (read_remote_string(pid, regs->uregs[0], target_guest, sizeof(target_guest)) != 0 ||
        read_remote_string(pid, regs->uregs[link_arg], link_guest, sizeof(link_guest)) != 0)
        return -EFAULT;
    /* Keep pre-mount /system links aimed at the staged image, never the empty
     * guest mountpoint and never a host-global path. */
    int rc = map_guest_symlink_target(target_guest, target_host, sizeof(target_host));
    if (rc != 0) return rc;
    rc = map_guest_path(link_guest, link_host, sizeof(link_host));
    if (rc != 0) return rc;
    uint32_t target_scratch = (regs->uregs[13] - 2u * SCRATCH_BELOW_SP) & ~((uint32_t)sizeof(long) - 1u);
    uint32_t link_scratch = (regs->uregs[13] - SCRATCH_BELOW_SP) & ~((uint32_t)sizeof(long) - 1u);
    if (write_remote(pid, target_scratch, target_host, strlen(target_host) + 1) != 0 ||
        write_remote(pid, link_scratch, link_host, strlen(link_host) + 1) != 0) return -EFAULT;
    regs->uregs[0] = target_scratch;
    regs->uregs[link_arg] = link_scratch;
    path_rewrites += 2;
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
    char parent[PATH_MAX];
    if (strlen(host) >= sizeof(parent)) return -ENAMETOOLONG;
    strcpy(parent, host);
    char *slash = strrchr(parent, '/');
    if (!slash || slash == parent) return -EACCES;
    *slash = '\0';
    rc = mkdir_p(parent);
    if (rc != 0) return rc;
    int fd = open(host, O_CREAT | O_WRONLY, 0600);
    if (fd < 0 && errno != EEXIST) return -errno;
    if (fd >= 0) close(fd);
    return 0;
}

static int seed_regular_file(const char *dir, const char *name, const char *contents) {
    char path[PATH_MAX];
    int n = snprintf(path, sizeof(path), "%s/%s", dir, name);
    if (n <= 0 || (size_t)n >= sizeof(path)) return -ENAMETOOLONG;
    int fd = open(path, O_CREAT | O_TRUNC | O_WRONLY, 0600);
    if (fd < 0) return -errno;
    size_t length = strlen(contents);
    ssize_t written = write(fd, contents, length);
    int saved = errno;
    close(fd);
    return written == (ssize_t)length ? 0 : -(written < 0 ? saved : EIO);
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
            int rc = mkdir_p(backing[i]);
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
    if (n <= 0 || (size_t)n >= sizeof(logdir) || mkdir_p(logdir) != 0) return -EIO;
    if (seed_regular_file(logdir, "main", "") != 0) return -EIO;
    n = snprintf(sockets, sizeof(sockets), "%s/socket", backing[1]);
    if (n <= 0 || (size_t)n >= sizeof(sockets) || mkdir_p(sockets) != 0) return -EIO;
    if (seed_regular_file(backing[2], "cmdline", "androidboot.hardware=goldfish\n") != 0 ||
        seed_regular_file(backing[2], "cpuinfo", "Processor : ARMv7 Processor rev 0 (v7l)\nHardware : goldfish\n") != 0)
        return -EIO;
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
    rc = mkdir_p(backing);
    if (rc != 0) return rc;
    if (strcmp(target, "/dev") == 0) {
        static const char *const devices[] = {"null", "zero", "random", "urandom", "kmsg",
            "__properties__", "binder", "ashmem", NULL};
        for (size_t i = 0; devices[i]; ++i) {
            rc = seed_regular_file(backing, devices[i], "");
            if (rc != 0) return rc;
        }
        char logdir[PATH_MAX];
        n = snprintf(logdir, sizeof(logdir), "%s/log", backing);
        if (n <= 0 || (size_t)n >= sizeof(logdir) || mkdir_p(logdir) != 0) return -EIO;
        rc = seed_regular_file(logdir, "main", "");
        if (rc != 0) return rc;
        char sockets[PATH_MAX];
        n = snprintf(sockets, sizeof(sockets), "%s/socket", backing);
        if (n <= 0 || (size_t)n >= sizeof(sockets) || mkdir_p(sockets) != 0) return -EIO;
    } else if (strcmp(target, "/proc") == 0) {
        rc = seed_regular_file(backing, "cmdline", "androidboot.hardware=goldfish\n");
        if (rc != 0) return rc;
        rc = seed_regular_file(backing, "cpuinfo", "Processor : ARMv7 Processor rev 0 (v7l)\nHardware : goldfish\n");
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

static int is_virtual_fd(int fd) {
    for (size_t i = 0; i < virtual_fd_count; ++i)
        if (virtual_fds[i] == fd) return 1;
    return 0;
}

static int alloc_virtual_fd(void) {
    if (virtual_fd_count >= MAX_VIRTUAL_FDS) return -EMFILE;
    int fd = VIRTUAL_FD_BASE + (int)virtual_fd_count;
    virtual_fds[virtual_fd_count++] = fd;
    return fd;
}

static int virtual_socketcall(pid_t pid, const struct compat_pt_regs *regs) {
    enum { SOCKETCALL_SOCKET = 1, SOCKETCALL_BIND = 2, SOCKETCALL_LISTEN = 4,
           SOCKETCALL_ACCEPT = 5, SOCKETCALL_SOCKETPAIR = 8 };
    uint32_t op = regs->uregs[0];
    uint32_t args_addr = regs->uregs[1];
    uint32_t args[4] = {0, 0, 0, 0};
    size_t arg_count = op == SOCKETCALL_LISTEN ? 2u :
        (op == SOCKETCALL_SOCKETPAIR ? 4u : 3u);
    if (op != SOCKETCALL_SOCKET && op != SOCKETCALL_BIND && op != SOCKETCALL_LISTEN &&
        op != SOCKETCALL_ACCEPT && op != SOCKETCALL_SOCKETPAIR) return -EAFNOSUPPORT;
    if (read_remote(pid, args_addr, args, arg_count * sizeof(uint32_t)) != 0) return -EFAULT;
    virtual_socket_calls++;

    if (op == SOCKETCALL_SOCKET) {
        if (args[0] != 1u || (args[1] & 0xfu) != 1u || args[2] != 0u) return -EAFNOSUPPORT;
        return alloc_virtual_fd();
    }
    if (op == SOCKETCALL_SOCKETPAIR) {
        if (args[0] != 1u || (args[1] & 0xfu) != 1u || args[2] != 0u) return -EAFNOSUPPORT;
        int32_t pair[2] = { alloc_virtual_fd(), -1 };
        if (pair[0] < 0) return pair[0];
        pair[1] = alloc_virtual_fd();
        if (pair[1] < 0 || write_remote(pid, args[3], pair, sizeof(pair)) != 0) return -EFAULT;
        return 0;
    }
    if (op == SOCKETCALL_BIND) {
        if (!is_virtual_fd((int32_t)args[0]) || args[2] < 3u) return -EBADF;
        uint16_t family = 0;
        if (read_remote(pid, args[1], &family, sizeof(family)) != 0 || family != 1u) return -EAFNOSUPPORT;
        char guest_path[108], host_path[PATH_MAX];
        if (read_remote_string(pid, args[1] + sizeof(family), guest_path, sizeof(guest_path)) != 0)
            return -EFAULT;
        if (strcmp(guest_path, "/dev/socket/property_service") != 0 ||
            map_guest_path(guest_path, host_path, sizeof(host_path)) != 0) return -EACCES;
        virtual_property_fd = (int32_t)args[0];
        virtual_property_bound = 1;
        return 0;
    }
    if (op == SOCKETCALL_LISTEN) {
        if (!virtual_property_bound || (int32_t)args[0] != virtual_property_fd) return -EBADF;
        virtual_property_listening = 1;
        return 0;
    }
    if (op == SOCKETCALL_ACCEPT) {
        if (!virtual_property_listening || (int32_t)args[0] != virtual_property_fd) return -EBADF;
        return -EAGAIN;
    }
    return -EAFNOSUPPORT;
}

static int virtual_poll(pid_t pid, const struct compat_pt_regs *regs) {
    struct guest_pollfd { int32_t fd; int16_t events; int16_t revents; };
    uint32_t count = regs->uregs[1];
    if (count > 128u) return -EINVAL;
    struct guest_pollfd fds[128];
    if (count && (regs->uregs[0] == 0 ||
        read_remote(pid, regs->uregs[0], fds, count * sizeof(fds[0])) != 0)) return -EFAULT;
    for (uint32_t i = 0; i < count; ++i) fds[i].revents = 0;
    if (count && write_remote(pid, regs->uregs[0], fds, count * sizeof(fds[0])) != 0) return -EFAULT;
    int32_t timeout_ms = (int32_t)regs->uregs[2];
    int32_t sleep_ms = timeout_ms < 0 || timeout_ms > 100 ? 100 : timeout_ms;
    if (sleep_ms > 0) {
        struct timespec delay = { .tv_sec = sleep_ms / 1000,
            .tv_nsec = (long)(sleep_ms % 1000) * 1000000L };
        nanosleep(&delay, NULL);
    }
    virtual_poll_waits++;
    return 0; /* No virtual guest events are currently available. */
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
        tracees[i].alive = 0;
        if (active_tracee_count > 0) active_tracee_count--;
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

static int mediate_guest_execve(pid_t pid, struct compat_pt_regs *regs) {
    char guest[PATH_MAX], host[PATH_MAX], resolved[PATH_MAX], patched[PATH_MAX], patched_resolved[PATH_MAX];
    if (read_remote_string(pid, regs->uregs[0], guest, sizeof(guest)) != 0) return -EFAULT;
    if (guest[0] != '/' || guest_path_has_parent(guest)) return -EACCES;
    int rc = map_guest_path(guest, host, sizeof(host));
    if (rc != 0) return rc;
    if (!realpath(host, resolved)) return -errno;

    char staged_init[PATH_MAX], resolved_init[PATH_MAX];
    int n = snprintf(staged_init, sizeof(staged_init), "%s/init", guest_root);
    if (n <= 0 || (size_t)n >= sizeof(staged_init)) return -ENAMETOOLONG;
    if (realpath(staged_init, resolved_init) && strcmp(resolved, resolved_init) == 0) {
        rc = original_init_native_path(host, sizeof(host));
        if (rc != 0) return rc;
        if (!realpath(host, resolved)) return -errno;
    }

    if (!path_is_within(resolved, native_guest_root)) return -EACCES;
    struct stat st;
    if (stat(resolved, &st) != 0) return -errno;
    if (!S_ISREG(st.st_mode) || !(st.st_mode & 0111)) return -EACCES;

    char interpreter[PATH_MAX];
    int elf_kind = guest_elf32_arm_interpreter(resolved, interpreter, sizeof(interpreter));
    if (elf_kind < 0) return elf_kind;
    int dynamic_exec = 0;
    if (elf_kind > 0) {
        if (strcmp(interpreter, "/system/bin/linker") != 0 ||
            patched_dynamic_native_path(resolved, patched, sizeof(patched)) != 0 ||
            !realpath(patched, patched_resolved) || !path_is_within(patched_resolved, native_guest_root)) {
            dynamic_exec_blocked = 1;
            snprintf(dynamic_exec_guest_path, sizeof(dynamic_exec_guest_path), "%s", guest);
            snprintf(dynamic_exec_interpreter, sizeof(dynamic_exec_interpreter), "%s", interpreter);
            fprintf(stderr, "CONTINUOUS CHAIN BLOCKER: guest exec %s has unsupported or unpatched PT_INTERP %s; denied before host linker substitution\n",
                    guest, interpreter);
            return -ENOEXEC;
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
            return -ENOEXEC;
        }
        snprintf(resolved, sizeof(resolved), "%s", patched_resolved);
        dynamic_exec = 1;
        dynamic_exec_allowed_count++;
    }

    uint32_t scratch = (regs->uregs[13] - SCRATCH_BELOW_SP) & ~((uint32_t)sizeof(long) - 1u);
    size_t bytes = strlen(resolved) + 1;
    if (bytes >= 2048 || write_remote(pid, scratch, resolved, bytes) != 0) return -EFAULT;
    regs->uregs[0] = scratch;
    if (set_regs(pid, regs) != 0) return -EFAULT;
    if (active_tracee) {
        snprintf(active_tracee->exec_target, sizeof(active_tracee->exec_target), "%s", guest);
        active_tracee->exec_was_dynamic = dynamic_exec;
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

static int path_operation_writes(const struct compat_pt_regs *regs, int nr) {
    if (nr == ARM_NR_OPEN || nr == ARM_NR_OPENAT) {
        unsigned arg = nr == ARM_NR_OPEN ? 1u : 2u;
        unsigned flags = regs->uregs[arg];
        return (flags & 3u) != 0 || (flags & (O_CREAT | O_TRUNC | O_APPEND)) != 0;
    }
    switch (nr) {
        case ARM_NR_CREAT: case ARM_NR_UNLINK: case ARM_NR_MKDIR: case ARM_NR_RMDIR:
        case ARM_NR_MKNOD: case ARM_NR_MKNODAT: case ARM_NR_UNLINKAT:
        case ARM_NR_SYMLINK: case ARM_NR_SYMLINKAT: case ARM_NR_RENAMEAT:
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
        case ARM_NR_SYMLINK: case ARM_NR_READLINK: case ARM_NR_MKNOD:
        case ARM_NR_OPENAT: case ARM_NR_MKDIRAT: case ARM_NR_MKNODAT:
        case ARM_NR_FCHOWNAT: case ARM_NR_FSTATAT64: case ARM_NR_UNLINKAT:
        case ARM_NR_SYMLINKAT: case ARM_NR_READLINKAT: case ARM_NR_FCHMODAT: case ARM_NR_FACCESSAT:
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
    if (nr == ARM_NR_SYMLINK || nr == ARM_NR_SYMLINKAT) {
        char link_guest[PATH_MAX];
        unsigned link_arg = nr == ARM_NR_SYMLINKAT ? 2u : 1u;
        if (read_remote_string(pid, regs->uregs[link_arg], link_guest, sizeof(link_guest)) != 0)
            return -EFAULT;
        if (guest_path_readonly(link_guest)) return -EROFS;
        int rc = rewrite_symlink(pid, regs, nr == ARM_NR_SYMLINKAT);
        if (rc != 0) return rc;
        return set_regs(pid, regs) == 0 ? 1 : -EFAULT;
    }
    int rc = rewrite_path_arg(pid, regs, arg, guest, sizeof(guest));
    if (rc != 0) return rc;
    if (guest_path_readonly(guest) && path_operation_writes(regs, nr)) return -EROFS;

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

static int dispatch_entry(pid_t pid, struct compat_pt_regs *regs, int nr,
                          int32_t *pending_return, int *fake) {
    *fake = 0;
    enum guest_syscall_class policy = guest_syscall_policy(nr);
    if (nr == ARM_NR_EXECVE) {
        int rc = mediate_guest_execve(pid, regs);
        if (rc == 0) return 0;
        denied_count++;
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
    if (nr == ARM_NR_SOCKETCALL) {
        *pending_return = virtual_socketcall(pid, regs); *fake = 1; return 0;
    }
    if (nr == ARM_NR_POLL) {
        *pending_return = virtual_poll(pid, regs); *fake = 1; return 0;
    }
    if ((nr == ARM_NR_FCNTL || nr == ARM_NR_FCNTL64) && is_virtual_fd((int32_t)regs->uregs[0])) {
        *pending_return = 0; *fake = 1; virtual_socket_calls++; return 0;
    }
    if (nr == ARM_NR_CLOSE && is_virtual_fd((int32_t)regs->uregs[0])) {
        *pending_return = 0; *fake = 1; return 0;
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
        *pending_return = -EPERM; *fake = 1; return 0;
    }
    if (policy == GUEST_SYSCALL_ALLOW_SAFE) {
        /* ftruncate64/getdents64/fstat64 and standard descriptor operations touch
         * only fds produced by app-private path rewriting or inherited stdio. */
        return 0;
    }
    denied_count++;
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

static int run_trace(pid_t pid, int *exit_code, int *exit_signal) {
    int status = 0;
    pid_t waited;
    do { waited = waitpid(pid, &status, __WALL); } while (waited < 0 && errno == EINTR);
    if (waited != pid || !WIFSTOPPED(status) || WSTOPSIG(status) != SIGTRAP) {
        fprintf(stderr, "initial ARM32 /init did not reach successful post-exec SIGTRAP; status=0x%x errno=%d\n",
                status, errno);
        kill_tracee(pid); return -1;
    }
    saw_exec = 1;
    tracee_count = 0;
    active_tracee_count = 0;
    next_guest_pid = 2;
    next_guest_tid = 2;
    struct tracee_state *root = add_tracee(pid, 0, 1, 1, 0, 0);
    if (!root) { kill_tracee(pid); return -1; }
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
            successful_guest_execs++;
            if (state->exec_was_dynamic) {
                dynamic_exec_started_count++;
                printf("GUEST DYNAMIC EXEC EVENT: pid=%d target=%s; kernel entered the original API10 linker via fd=%d; target main entry remains unproven\n",
                       waited, state->exec_target[0] ? state->exec_target : "unknown guest path",
                       GUEST_LINKER_FD);
            } else {
                printf("GUEST EXEC EVENT: pid=%d target=%s (verified ELF32 ARM payload)\n",
                       waited, state->exec_target[0] ? state->exec_target : "unknown guest path");
            }
            state->exec_was_dynamic = 0;
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
            if (!state->expect_exit) {
                if (broker_sigsys_expire_before_next_entry(&state->broker_sigsys))
                    printf("BROKERED SIGSYS CANDIDATE EXPIRED: pid=%d next-syscall-entry=%u wait-status=0x%x\n",
                           waited, regs.uregs[7], status);
                state->last_syscall = (int32_t)regs.uregs[7];
                if (state->last_syscall == ARM_NR_CLONE) state->clone_flags = regs.uregs[0];
                syscall_stops++;
                int fake = 0;
                int32_t result = 0;
                int rc = dispatch_entry(waited, &regs, state->last_syscall, &result, &fake);
                if (rc != 0) { fprintf(stderr, "broker failure at ARM syscall %d pid=%d: errno=%d\n", state->last_syscall, waited, errno); kill_all_tracees(); return -1; }
                if (fake) {
                    if (fake_entry(waited, &regs, result, &state->pending_return) != 0) { fprintf(stderr, "could not cancel syscall %d pid=%d: errno=%d\n", state->last_syscall, waited, errno); kill_all_tracees(); return -1; }
                    state->pending = 1;
                    broker_sigsys_arm(&state->broker_sigsys, state->last_syscall, result);
                    enum guest_syscall_class cls = guest_syscall_policy(state->last_syscall);
                    if (cls == GUEST_SYSCALL_DENY || cls == GUEST_SYSCALL_BLOCK_PROCESS) denied_count++;
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
                    (int32_t)regs.uregs[0] < 0) state->exec_was_dynamic = 0;
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
            printf("PTRACE SIGSYS WAIT STATUS: pid=%d raw=0x%x stop=%d event=%u expect-exit=%d pending=%d candidate=%d response-committed=%d candidate-syscall=%d candidate-result=%d siginfo-rc=%d siginfo-errno=%d si-code=%d\n",
                   waited, status, sig, event, state->expect_exit, state->pending,
                   state->broker_sigsys.armed, state->broker_sigsys.response_committed,
                   state->broker_sigsys.syscall_number, state->broker_sigsys.virtual_result,
                   siginfo_rc, siginfo_errno, siginfo_code);
            if (siginfo_rc == 0 && broker_sigsys_take(&state->broker_sigsys, sig, siginfo_code)) {
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
            if (state->broker_sigsys.armed) {
                printf("BROKERED SIGSYS CANDIDATE REJECTED: pid=%d si-code=%d expected-seccomp=%d; forwarding signal\n",
                       waited, siginfo_code, SYS_SECCOMP);
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
    printf("PROCESS TREE: fork/clone/vfork followed with ptrace; cap=%d; verified static ARM32 execs and validated original-linker PT_INTERP aliases are admitted\n", MAX_TRACEES);
    puts("DYNAMIC ELF POLICY: original API10 linker is inherited as fd 198; unsupported PT_INTERP is denied before host-linker substitution");
    int child = start_guest(binary, &argv[5]);
    if (child < 0) return 2;
    int exit_code = -1, exit_signal = 0;
    int rc = run_trace((pid_t)child, &exit_code, &exit_signal);
    traced_pid = -1;
    printf("INITIAL /init POST-EXEC: %s\n", saw_exec ? "SIGTRAP observed" : "not observed");
    printf("CONTINUOUS PROCESS TREE: fork/clone/vfork events=%lu; guest exec events=%lu; dynamic execs redirected=%lu; kernel entries into original guest linker=%lu; dynamic target main remains unproven; maximum tracees=%d\n",
           process_events, successful_guest_execs, dynamic_exec_allowed_count,
           dynamic_exec_started_count, MAX_TRACEES);
    printf("SYSCALL ENTRIES: %lu; PATH REWRITES: %lu; VIRTUAL MOUNTS: %lu; VIRTUAL DEVICE/MODE OPS: %lu; VIRTUAL ID OPS: %lu; VIRTUAL SOCKET CALLS: %lu; VIRTUAL POLL WAITS: %lu; BROKERED SIGSYS SUPPRESSED: %lu; BLOCKED PROCESS STARTS: %lu; DENIED: %lu\n",
           syscall_stops, path_rewrites, virtual_mount_count, virtual_device_count,
           virtual_identity_count, virtual_socket_calls, virtual_poll_waits,
           brokered_sigsys_suppressed, blocked_process_count, denied_count);
    if (strcmp(guest_program, "/init") == 0 && (trace_timed_out || trace_cancelled) && virtual_poll_waits > 0)
        printf("INIT STATE: initial actions reached a software-emulated event wait; no virtual event source has delivered an event\n");
    if (dynamic_exec_blocked)
        printf("UNSUPPORTED DYNAMIC EXEC: guest exec %s requires PT_INTERP %s; denied before host linker substitution\n",
               dynamic_exec_guest_path, dynamic_exec_interpreter);
    if (trace_cancelled) printf("STOP: user requested cancellation; supervisor terminated and reaped the traced process tree\n");
    else if (trace_timed_out) printf("STOP: bounded continuous process-tree trace ended by supervisor timeout; all tracees stopped by supervisor\n");
    else if (process_limit_hit) printf("STOP: process tree reached the safe cap; all tracees stopped by supervisor\n");
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
