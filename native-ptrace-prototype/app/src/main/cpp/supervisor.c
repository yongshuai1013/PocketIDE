#define _GNU_SOURCE
#include <elf.h>
#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifndef __WALL
#define __WALL 0x40000000
#endif
#ifndef PTRACE_O_EXITKILL
#define PTRACE_O_EXITKILL 0x00100000
#endif
#ifndef PTRACE_O_TRACEEXEC
#define PTRACE_O_TRACEEXEC 0x00000010
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
#ifndef PTRACE_O_TRACESYSGOOD
#define PTRACE_O_TRACESYSGOOD 0x00000001
#endif
#ifndef NT_ARM_SYSTEM_CALL
#define NT_ARM_SYSTEM_CALL 0x404
#endif

#define ARM_NR_EXIT 1
#define ARM_NR_READ 3
#define ARM_NR_WRITE 4
#define ARM_NR_CLOSE 6
#define ARM_NR_EXECVE 11
#define ARM_NR_GETPID 20
#define ARM_NR_MOUNT 21
#define ARM_NR_EXIT_GROUP 248
#define ARM_NR_OPENAT 322
#define ARM_AT_FDCWD (-100)
#define ARM_SYSCALL_STOP (SIGTRAP | 0x80)
#define MAX_REMOTE_PATH 512
#define CPU_LOOP_ITERATIONS 50000000
#define GETPID_ITERATIONS 1000

struct compat_pt_regs {
    uint32_t uregs[18];
};

enum pending_action {
    PENDING_NONE = 0,
    PENDING_RETURN = 1,
};

static pid_t traced_pid = -1;
static char root_path[PATH_MAX];
static char guest_path[PATH_MAX];
static int virtual_mount_ready;
static int path_rewrite_seen;
static int guest_reported_pass;
static int guest_data_fd = -1;
static int exec_seen;
static int syscall_entries;
static int syscall_exits;
static int getpid_entries;
static int getpid_exits;
static int virtual_mounts;
static int host_mount_calls;
static int denied_syscalls;
static int seccomp_sigsys_suppressed;
static int cpu_start_seen;
static int cpu_end_seen;
static int getpid_timer_started;
static int getpid_timer_ended;
static struct timespec cpu_start_time;
static struct timespec cpu_end_time;
static struct timespec getpid_start_time;
static struct timespec getpid_end_time;

static int get_compat_regs(pid_t pid, struct compat_pt_regs *regs) {
    struct iovec iov;
    iov.iov_base = regs;
    iov.iov_len = sizeof(*regs);
    if (ptrace(PTRACE_GETREGSET, pid, (void *)(uintptr_t)NT_PRSTATUS, &iov) != 0) {
        return -1;
    }
    return iov.iov_len == sizeof(*regs) ? 0 : -1;
}

static int set_compat_regs(pid_t pid, const struct compat_pt_regs *regs) {
    struct iovec iov;
    iov.iov_base = (void *)regs;
    iov.iov_len = sizeof(*regs);
    if (ptrace(PTRACE_SETREGSET, pid, (void *)(uintptr_t)NT_PRSTATUS, &iov) != 0) {
        return -1;
    }
    return iov.iov_len == sizeof(*regs) ? 0 : -1;
}

static int set_kernel_syscall_number(pid_t pid, int32_t syscall_number) {
    int32_t number = syscall_number;
    struct iovec iov;
    iov.iov_base = &number;
    iov.iov_len = sizeof(number);
    return ptrace(PTRACE_SETREGSET, pid,
                  (void *)(uintptr_t)NT_ARM_SYSTEM_CALL, &iov) == 0 ? 0 : -1;
}

static int read_remote(pid_t pid, uint32_t address, void *out, size_t length) {
    unsigned char *dst = (unsigned char *)out;
    size_t copied = 0;
    while (copied < length) {
        uint32_t at = address + (uint32_t)copied;
        uint32_t aligned = at & ~((uint32_t)sizeof(long) - 1u);
        size_t offset = (size_t)(at - aligned);
        errno = 0;
        long word = ptrace(PTRACE_PEEKDATA, pid,
                           (void *)(uintptr_t)aligned, NULL);
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
    const unsigned char *src = (const unsigned char *)data;
    size_t copied = 0;
    while (copied < length) {
        uint32_t at = address + (uint32_t)copied;
        uint32_t aligned = at & ~((uint32_t)sizeof(long) - 1u);
        size_t offset = (size_t)(at - aligned);
        errno = 0;
        long old_word = ptrace(PTRACE_PEEKDATA, pid,
                               (void *)(uintptr_t)aligned, NULL);
        if (old_word == -1 && errno != 0) return -1;
        unsigned char bytes[sizeof(long)];
        memcpy(bytes, &old_word, sizeof(old_word));
        size_t take = sizeof(long) - offset;
        if (take > length - copied) take = length - copied;
        memcpy(bytes + offset, src + copied, take);
        long new_word;
        memcpy(&new_word, bytes, sizeof(new_word));
        if (ptrace(PTRACE_POKEDATA, pid, (void *)(uintptr_t)aligned,
                   (void *)(uintptr_t)(unsigned long)new_word) != 0) {
            return -1;
        }
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

static int path_has_parent_component(const char *path) {
    const char *p = path;
    while (*p) {
        while (*p == '/') ++p;
        const char *start = p;
        while (*p && *p != '/') ++p;
        size_t n = (size_t)(p - start);
        if (n == 2 && start[0] == '.' && start[1] == '.') return 1;
    }
    return 0;
}

static int map_guest_path(const char *guest, char *host, size_t capacity) {
    if (guest[0] != '/' || path_has_parent_component(guest)) return -1;
    const char *suffix = NULL;
    if (virtual_mount_ready &&
        (strcmp(guest, "/mnt") == 0 || strncmp(guest, "/mnt/", 5) == 0)) {
        suffix = guest + 4;
        if (*suffix == '\0') suffix = "/";
        int n = snprintf(host, capacity, "%s/.vfs/mnt%s", root_path, suffix);
        return n > 0 && (size_t)n < capacity ? 0 : -1;
    }
    return -1; // The probe exposes no other guest paths.
}

static int fake_syscall(pid_t pid, struct compat_pt_regs *regs,
                        int32_t return_value, enum pending_action *pending) {
    regs->uregs[7] = UINT32_MAX; // keep the tracee-visible r7 canceled too
    if (set_compat_regs(pid, regs) != 0) return -1;
    if (set_kernel_syscall_number(pid, -1) != 0) return -1;
    *pending = PENDING_RETURN;
    (void)return_value;
    return 0;
}

static int resume_syscall(pid_t pid, int signal_number) {
    return ptrace(PTRACE_SYSCALL, pid, NULL,
                  (void *)(uintptr_t)(unsigned int)signal_number) == 0 ? 0 : -1;
}

static int read_guest_word_string(pid_t pid, uint32_t address, char *out, size_t cap) {
    return read_remote_string(pid, address, out, cap);
}

static int validate_mount(pid_t pid, const struct compat_pt_regs *regs) {
    char source[64], target[64], type[64];
    if (read_guest_word_string(pid, regs->uregs[0], source, sizeof(source)) != 0 ||
        read_guest_word_string(pid, regs->uregs[1], target, sizeof(target)) != 0 ||
        read_guest_word_string(pid, regs->uregs[2], type, sizeof(type)) != 0) {
        return 0;
    }
    return strcmp(source, "tmpfs") == 0 && strcmp(target, "/mnt") == 0 &&
           strcmp(type, "tmpfs") == 0 && regs->uregs[3] == 0 && regs->uregs[4] == 0;
}

static double elapsed_ms(const struct timespec *start, const struct timespec *end) {
    int64_t ns = ((int64_t)end->tv_sec - (int64_t)start->tv_sec) * 1000000000LL +
                 ((int64_t)end->tv_nsec - (int64_t)start->tv_nsec);
    return (double)ns / 1000000.0;
}

static void kill_tracee(pid_t pid) {
    if (pid <= 0) return;
    (void)ptrace(PTRACE_KILL, pid, NULL, NULL);
    (void)kill(pid, SIGKILL);
    int status;
    (void)waitpid(pid, &status, __WALL);
}

struct arm64_user_regs {
    uint64_t regs[31];
    uint64_t sp;
    uint64_t pc;
    uint64_t pstate;
};

static void report_trace_signal(pid_t pid, int signal_number, const char *phase) {
    siginfo_t info;
    memset(&info, 0, sizeof(info));
    fprintf(stderr, "tracee signal %d during %s\n", signal_number, phase);
    if (ptrace(PTRACE_GETSIGINFO, pid, NULL, &info) == 0) {
        fprintf(stderr, "signal detail: signo=%d code=%d errno=%d\n",
                info.si_signo, info.si_code, info.si_errno);
    } else {
        fprintf(stderr, "PTRACE_GETSIGINFO failed: errno=%d\n", errno);
    }
    if (signal_number != SIGSYS) return;

    uint64_t raw[40] = {0};
    struct iovec iov = { .iov_base = raw, .iov_len = sizeof(raw) };
    if (ptrace(PTRACE_GETREGSET, pid, (void *)(uintptr_t)NT_PRSTATUS, &iov) != 0) {
        fprintf(stderr, "SIGSYS syscall-register read failed: errno=%d\n", errno);
    } else if (iov.iov_len == sizeof(struct compat_pt_regs)) {
        const uint32_t *arm = (const uint32_t *)raw;
        fprintf(stderr, "SIGSYS ABI=AArch32/ARM; syscall r7=%u (0x%x)\n",
                arm[7], arm[7]);
    } else if (iov.iov_len >= sizeof(struct arm64_user_regs)) {
        fprintf(stderr, "SIGSYS ABI=AArch64; syscall x8=%llu (0x%llx)\n",
                (unsigned long long)raw[8], (unsigned long long)raw[8]);
    } else {
        fprintf(stderr, "SIGSYS syscall ABI unknown; NT_PRSTATUS bytes=%zu\n", iov.iov_len);
    }
}

static int start_guest(const char *binary) {
    pid_t pid = fork();
    if (pid < 0) {
        fprintf(stderr, "fork failed: errno=%d\n", errno);
        return -1;
    }
    if (pid == 0) {
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) != 0) _exit(125);
        // Do not stop before exec: this task is still the AArch64 launcher here.
        // The kernel's post-exec SIGTRAP is the safe point to begin ARM32 tracing.
        char *const child_argv[] = {(char *)binary, NULL};
        char *const child_envp[] = {"HOME=/", "PATH=/", "PAXVM_PROBE=1", NULL};
        execve(binary, child_argv, child_envp);
        dprintf(STDERR_FILENO, "guest execve failed: errno=%d\n", errno);
        _exit(127);
    }
    traced_pid = pid;
    return (int)pid;
}

static int run_trace(pid_t pid, int *guest_exit_code, int *guest_signaled) {
    int status = 0;
    pid_t waited;
    do {
        waited = waitpid(pid, &status, __WALL);
    } while (waited < 0 && errno == EINTR);
    if (waited != pid || !WIFSTOPPED(status) || WSTOPSIG(status) != SIGTRAP) {
        if (waited == pid && WIFSTOPPED(status)) {
            report_trace_signal(pid, WSTOPSIG(status), "before the ARM32 post-exec stop");
        }
        fprintf(stderr, "tracee did not reach the successful post-exec SIGTRAP: errno=%d status=0x%x\n",
                errno, status);
        kill_tracee(pid);
        return -1;
    }
    // PTRACE_TRACEME's SIGTRAP proves execve installed the ARM32 image.
    // PTRACE_O_TRACEEXEC is enabled below for subsequent guest execs only.
    exec_seen = 1;
    printf("initial exec stop: ARM32 image installed; starting compat syscall tracing\n");

    long options = PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEEXEC |
                   PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK |
                   PTRACE_O_TRACECLONE | PTRACE_O_EXITKILL;
    if (ptrace(PTRACE_SETOPTIONS, pid, NULL, (void *)(uintptr_t)options) != 0) {
        fprintf(stderr, "PTRACE_SETOPTIONS failed: errno=%d\n", errno);
        return -1;
    }
    if (resume_syscall(pid, 0) != 0) {
        fprintf(stderr, "initial PTRACE_SYSCALL failed: errno=%d\n", errno);
        return -1;
    }

    int expect_exit = 0;
    int last_nr = -1;
    enum pending_action pending = PENDING_NONE;
    int32_t pending_return = 0;
    int open_pending = 0;
    int fatal = 0;

    for (;;) {
        do {
            waited = waitpid(pid, &status, __WALL);
        } while (waited < 0 && errno == EINTR);
        if (waited < 0) {
            fprintf(stderr, "waitpid failed: errno=%d\n", errno);
            fatal = 1;
            break;
        }
        if (WIFEXITED(status)) {
            *guest_exit_code = WEXITSTATUS(status);
            *guest_signaled = 0;
            break;
        }
        if (WIFSIGNALED(status)) {
            *guest_exit_code = -1;
            *guest_signaled = WTERMSIG(status);
            break;
        }
        if (!WIFSTOPPED(status)) continue;

        int signal_number = WSTOPSIG(status);
        unsigned int event = (unsigned int)status >> 16;
        if (event == PTRACE_EVENT_EXEC) {
            exec_seen = 1;
            if (resume_syscall(pid, 0) != 0) { fatal = 1; break; }
            continue;
        }
        if (event != 0) {
            fprintf(stderr, "unexpected process event=%u; guest fork/clone is not enabled in this probe\n",
                    event);
            fatal = 1;
            break;
        }
        if (signal_number == ARM_SYSCALL_STOP) {
            struct compat_pt_regs regs;
            if (get_compat_regs(pid, &regs) != 0) {
                fprintf(stderr, "compat NT_PRSTATUS read failed: errno=%d\n", errno);
                fatal = 1;
                break;
            }
            if (!expect_exit) {
                syscall_entries++;
                last_nr = (int32_t)regs.uregs[7];
                pending = PENDING_NONE;
                open_pending = 0;
                if (last_nr == ARM_NR_EXECVE) {
                    char exec_path[PATH_MAX];
                    if (read_remote_string(pid, regs.uregs[0], exec_path, sizeof(exec_path)) != 0 ||
                        strcmp(exec_path, guest_path) != 0) {
                        denied_syscalls++;
                        pending_return = -EACCES;
                        if (fake_syscall(pid, &regs, pending_return, &pending) < 0) {
                            fatal = 1;
                            break;
                        }
                    }
                } else if (last_nr == ARM_NR_MOUNT) {
                    char backing[PATH_MAX];
                    int n = snprintf(backing, sizeof(backing), "%s/.vfs/mnt", root_path);
                    struct stat st;
                    int ok = validate_mount(pid, &regs) && n > 0 &&
                             (size_t)n < sizeof(backing) && stat(backing, &st) == 0 &&
                             S_ISDIR(st.st_mode);
                    if (ok) {
                        virtual_mount_ready = 1;
                        virtual_mounts++;
                        pending_return = 0;
                        if (fake_syscall(pid, &regs, pending_return, &pending) < 0) {
                            fatal = 1;
                            break;
                        }
                    } else {
                        denied_syscalls++;
                        pending_return = -EPERM;
                        if (fake_syscall(pid, &regs, pending_return, &pending) < 0) {
                            fatal = 1;
                            break;
                        }
                    }
                } else if (last_nr == ARM_NR_GETPID) {
                    getpid_entries++;
                    if (getpid_entries == 1) {
                        clock_gettime(CLOCK_MONOTONIC, &getpid_start_time);
                        getpid_timer_started = 1;
                    }
                    pending_return = 1; // guest-visible PID; never expose host PID
                    if (fake_syscall(pid, &regs, pending_return, &pending) < 0) {
                        fatal = 1;
                        break;
                    }
                } else if (last_nr == ARM_NR_OPENAT) {
                    int32_t dirfd = (int32_t)regs.uregs[0];
                    uint32_t guest_string = regs.uregs[1];
                    uint32_t flags = regs.uregs[2];
                    char guest_name[MAX_REMOTE_PATH];
                    char host_name[PATH_MAX];
                    if (dirfd != ARM_AT_FDCWD || flags != 0 ||
                        read_remote_string(pid, guest_string, guest_name, sizeof(guest_name)) != 0 ||
                        map_guest_path(guest_name, host_name, sizeof(host_name)) != 0) {
                        denied_syscalls++;
                        pending_return = -EACCES;
                        if (fake_syscall(pid, &regs, pending_return, &pending) < 0) {
                            fatal = 1;
                            break;
                        }
                    } else {
                        uint32_t sp = regs.uregs[13];
                        uint32_t scratch = (sp - 2048u) & ~((uint32_t)sizeof(long) - 1u);
                        size_t bytes = strlen(host_name) + 1;
                        if (bytes >= 1024 || write_remote(pid, scratch, host_name, bytes) != 0) {
                            fprintf(stderr, "failed to write translated path into tracee stack\n");
                            fatal = 1;
                            break;
                        }
                        regs.uregs[1] = scratch;
                        if (set_compat_regs(pid, &regs) != 0) {
                            fprintf(stderr, "failed to update openat path register: errno=%d\n", errno);
                            fatal = 1;
                            break;
                        }
                        path_rewrite_seen++;
                        open_pending = 1;
                        printf("BROKER openat: %s -> app-private guest root\n", guest_name);
                    }
                } else if (last_nr == ARM_NR_READ) {
                    uint32_t fd = regs.uregs[0];
                    uint32_t count = regs.uregs[2];
                    if (guest_data_fd < 0 || fd != (uint32_t)guest_data_fd || count > 32) {
                        denied_syscalls++;
                        pending_return = -EACCES;
                        if (fake_syscall(pid, &regs, pending_return, &pending) < 0) {
                            fatal = 1;
                            break;
                        }
                    }
                } else if (last_nr == ARM_NR_WRITE) {
                    uint32_t fd = regs.uregs[0];
                    uint32_t buffer = regs.uregs[1];
                    uint32_t count = regs.uregs[2];
                    char payload[64];
                    if (fd != STDOUT_FILENO || count == 0 || count > 32 ||
                        read_remote(pid, buffer, payload, count) != 0) {
                        denied_syscalls++;
                        pending_return = -EACCES;
                        if (fake_syscall(pid, &regs, pending_return, &pending) < 0) {
                            fatal = 1;
                            break;
                        }
                    } else {
                        if (count == 1 && payload[0] == 'B') {
                            clock_gettime(CLOCK_MONOTONIC, &cpu_start_time);
                            cpu_start_seen = 1;
                        } else if (count == 1 && payload[0] == 'C' && cpu_start_seen) {
                            clock_gettime(CLOCK_MONOTONIC, &cpu_end_time);
                            cpu_end_seen = 1;
                        } else if (count == 11 && memcmp(payload, "PROBE_PASS\n", 11) == 0) {
                            guest_reported_pass = 1;
                        } else if (!(count == 1 && (payload[0] == 'B' || payload[0] == 'C'))) {
                            denied_syscalls++;
                            pending_return = -EACCES;
                            if (fake_syscall(pid, &regs, pending_return, &pending) < 0) {
                                fatal = 1;
                                break;
                            }
                        }
                    }
                } else if (last_nr == ARM_NR_CLOSE) {
                    uint32_t fd = regs.uregs[0];
                    if (guest_data_fd < 0 || fd != (uint32_t)guest_data_fd) {
                        denied_syscalls++;
                        pending_return = -EACCES;
                        if (fake_syscall(pid, &regs, pending_return, &pending) < 0) {
                            fatal = 1;
                            break;
                        }
                    }
                } else if (last_nr == ARM_NR_EXIT || last_nr == ARM_NR_EXIT_GROUP) {
                    // The only process-exit calls allowed in this single-process probe.
                } else {
                    denied_syscalls++;
                    fprintf(stderr, "DENY: ARM32 guest syscall nr=%d (0x%x) is not in the probe allowlist\n",
                            last_nr, (unsigned int)last_nr);
                    pending_return = -ENOSYS;
                    if (fake_syscall(pid, &regs, pending_return, &pending) < 0) {
                        fprintf(stderr, "cannot cancel guest syscall %d before host dispatch: errno=%d\n",
                                last_nr, errno);
                        fatal = 1;
                        break;
                    }
                }
                expect_exit = 1;
            } else {
                syscall_exits++;
                if (pending == PENDING_RETURN) {
                    regs.uregs[0] = (uint32_t)pending_return;
                    if (set_compat_regs(pid, &regs) != 0) {
                        fprintf(stderr, "cannot set virtual syscall result: errno=%d\n", errno);
                        fatal = 1;
                        break;
                    }
                } else if (last_nr == ARM_NR_OPENAT && open_pending) {
                    int32_t result = (int32_t)regs.uregs[0];
                    if (result < 0) {
                        fprintf(stderr, "translated app-private openat failed: guest result=%d\n", result);
                    } else {
                        guest_data_fd = result;
                    }
                    open_pending = 0;
                } else if (last_nr == ARM_NR_GETPID) {
                    getpid_exits++;
                    if (getpid_exits == GETPID_ITERATIONS) {
                        clock_gettime(CLOCK_MONOTONIC, &getpid_end_time);
                        getpid_timer_ended = 1;
                    }
                }
                pending = PENDING_NONE;
                expect_exit = 0;
            }
            if (resume_syscall(pid, 0) != 0) {
                fprintf(stderr, "PTRACE_SYSCALL resume failed: errno=%d\n", errno);
                fatal = 1;
                break;
            }
            continue;
        }
        if (signal_number == SIGSTOP) {
            if (resume_syscall(pid, 0) != 0) { fatal = 1; break; }
            continue;
        }
        if (signal_number == SIGSYS) {
            report_trace_signal(pid, signal_number, "during a guest syscall");
            if (expect_exit && pending == PENDING_RETURN) {
                seccomp_sigsys_suppressed++;
                fprintf(stderr,
                        "BROKER: suppressed SIGSYS for canceled ARM32 syscall nr=%d; virtual result=%d\n",
                        last_nr, pending_return);
                if (resume_syscall(pid, 0) != 0) {
                    fprintf(stderr, "could not resume after brokered SIGSYS: errno=%d\n", errno);
                    fatal = 1;
                    break;
                }
                continue;
            }
        }
        report_trace_signal(pid, signal_number, "while tracing the guest");
        fprintf(stderr, "stopping tracee without passing signal %d to the host\n", signal_number);
        fatal = 1;
        break;
    }

    if (fatal) {
        kill_tracee(pid);
        return -1;
    }
    return 0;
}

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "usage: %s <arm32-guest-elf> <app-private-guest-root>\n", argv[0]);
        return 2;
    }
    if (strlen(argv[1]) >= sizeof(guest_path) || strlen(argv[2]) >= sizeof(root_path)) {
        fprintf(stderr, "input path too long\n");
        return 2;
    }
    strcpy(guest_path, argv[1]);
    if (realpath(argv[2], root_path) == NULL) {
        fprintf(stderr, "guest root is not accessible: errno=%d\n", errno);
        return 2;
    }
    char backing[PATH_MAX];
    int backing_len = snprintf(backing, sizeof(backing), "%s/.vfs/mnt", root_path);
    struct stat st;
    if (backing_len <= 0 || (size_t)backing_len >= sizeof(backing) ||
        stat(backing, &st) != 0 || !S_ISDIR(st.st_mode)) {
        fprintf(stderr, "app-private virtual mount backing directory is missing\n");
        return 2;
    }

    printf("MODE: standalone arm64 supervisor; ELF32/ARM child; no root requested\n");
    printf("POLICY: strict probe allowlist; unlisted guest syscalls are canceled before host dispatch\n");
    printf("GUEST ROOT: app-private only; host mount syscall calls=%d\n", host_mount_calls);

    int child = start_guest(guest_path);
    if (child < 0) return 2;
    int guest_exit_code = -1;
    int guest_signaled = 0;
    int rc = run_trace((pid_t)child, &guest_exit_code, &guest_signaled);
    traced_pid = -1;

    printf("EXEC: %s\n", exec_seen ? "ARM32 tracee exec event observed" : "not observed");
    printf("PTRACE syscall stops: entries=%d exits=%d\n", syscall_entries, syscall_exits);
    printf("VIRTUAL getpid calls: %d entries / %d exits; guest PID=1; host PID hidden\n",
           getpid_entries, getpid_exits);
    printf("VIRTUAL mount calls: %d; host mount calls=%d\n", virtual_mounts, host_mount_calls);
    printf("PATH rewrite count: %d\n", path_rewrite_seen);
    printf("Denied syscalls (canceled in supervisor): %d\n", denied_syscalls);
    if (cpu_start_seen && cpu_end_seen) {
        printf("CPU loop: %d guest iterations, marker-to-marker wall time %.3f ms\n",
               CPU_LOOP_ITERATIONS, elapsed_ms(&cpu_start_time, &cpu_end_time));
    } else {
        printf("CPU loop timing: unavailable (guest marker missing)\n");
    }
    if (getpid_timer_started && getpid_timer_ended) {
        printf("Syscall microbenchmark: %d virtual getpid calls, %.3f ms including ptrace/broker stops\n",
               GETPID_ITERATIONS, elapsed_ms(&getpid_start_time, &getpid_end_time));
    } else {
        printf("Syscall microbenchmark: incomplete (%d virtual getpid exits)\n", getpid_exits);
    }
    if (guest_signaled) {
        printf("GUEST EXIT: signal %d\n", guest_signaled);
    } else {
        printf("GUEST EXIT: code %d\n", guest_exit_code);
    }

    int passed = rc == 0 && exec_seen && guest_exit_code == 0 && !guest_signaled &&
                 virtual_mounts == 1 && host_mount_calls == 0 && path_rewrite_seen == 1 &&
                 guest_data_fd >= 0 && guest_reported_pass &&
                 getpid_exits == GETPID_ITERATIONS && cpu_start_seen && cpu_end_seen;
    printf("RESULT: %s\n", passed ? "PASS" : "FAIL");
    return passed ? 0 : 1;
}
