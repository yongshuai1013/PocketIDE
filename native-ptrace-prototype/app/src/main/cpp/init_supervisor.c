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
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
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
#include "guest_goldfish_tty_virtual.h"
#include "guest_socket_path_ops.h"
#include "guest_diagnostics.h"
#include "guest_sigsys_context.h"
#include "guest_script_launch.h"
#include "guest_sigprocmask_compat.h"
#include "guest_sigprocmask_ptrace.h"
#include "guest_sigaction_compat.h"
#include "guest_process_compat.h"
#include "guest_safe_dir.h"
#include "guest_goldfish_tty_fs.h"
#include "guest_hardware_profile.h"
#include "guest_qemud_diagnostics.h"
#include "guest_network_virtual.h"
#include "guest_pseudo_device.h"
#include "guest_null_stdio.h"
#include "guest_kmsg_virtual.h"
#include "guest_path_fd.h"
#include "guest_entry_probe.h"
#include "guest_tracee_slots.h"
#include "guest_device_boundary.h"
#include "ptrace_child_stop_queue.h"
#include "guest_frame_channel.h"
#include "guest_framebuffer_virtual.h"
#include "guest_identity_compat.h"
#include "guest_binder_virtual.h"
#include "guest_syscall_abi.h"

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
#define ARM_NR_DUP 41
#define ARM_NR_FSTAT 108
#define ARM_NR_FSYNC 118
#define ARM_NR_FDATASYNC 148
#define ARM_NR_PREAD64 180
#define ARM_NR_PWRITE64 181
#define ARM_NR_FCNTL 55
#define ARM_NR_FCNTL64 221
#define ARM_NR_GETPPID 64
#define ARM_NR_SIGACTION 67
#define ARM_NR_SETRLIMIT 75
#define ARM_NR_GETPGID 132
#define ARM_NR_IOPRIO_SET 314
#define ARM_NR_SETGID 46
#define ARM_NR_GETGID 47
#define ARM_NR_SETREUID 70
#define ARM_NR_SETREGID 71
#define ARM_NR_GETGROUPS 80
#define ARM_NR_SETGROUPS 81
#define ARM_NR_GETEUID 49
#define ARM_NR_GETEGID 50
#define ARM_NR_UMOUNT2 52
#define ARM_NR_IOCTL 54
#define ARM_NR_UMASK 60
#define ARM_NR_FCHMOD 94
#define ARM_NR_FCHOWN 95
#define ARM_NR_SOCKETCALL 102
#define ARM_NR_POLL 168
#define ARM_NR_EPOLL_CREATE 250
#define ARM_NR_EPOLL_CTL 251
#define ARM_NR_EPOLL_WAIT 252
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
#define ARM_NR_SETFSUID 138
#define ARM_NR_SETFSGID 139
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
#define GUEST_RANDOM_GRND_NONBLOCK 0x0001u
#ifndef SYS_getrandom
#if defined(__aarch64__)
#define SYS_getrandom 278
#elif defined(__x86_64__)
#define SYS_getrandom 318
#else
#error "No audited host getrandom syscall number for this supervisor ABI"
#endif
#endif

struct compat_pt_regs { uint32_t uregs[18]; };
struct guest_mount { char target[PATH_MAX]; char backing[PATH_MAX]; };
struct guest_init_config_read_state {
    int active;
    int fd;
    int size_known;
    int start_seek_succeeded;
    int32_t expected_file_size;
    uint32_t read_calls;
    uint32_t requested_bytes;
    int32_t last_read_result;
    uint64_t bytes_read;
    char path[32];
};
struct guest_null_stdio_exec_progress {
    int mknod_succeeded;
    int open_succeeded;
    int unlink_succeeded;
    int source_fd;
    uint8_t dup2_mask;
    int source_closed;
    int ready_logged;
};
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
    uint8_t null_stdio_mask;
    struct guest_null_stdio_exec_progress null_stdio_exec;
    struct guest_init_config_read_state init_config_read;
    uint32_t guest_ruid;
    uint32_t guest_euid;
    uint32_t guest_rgid;
    uint32_t guest_egid;
    struct guest_identity_state identity;
    struct guest_binder_process_state binder;
    int binder_waiting;
    int binder_mmap_pending;
    int binder_munmap_pending;
    uint32_t binder_pending_map_length;
    int fb_mmap_pending;
    int fb_munmap_pending;
    uint32_t fb_pending_map_length;
    uint32_t fb_pending_map_flags;
    uint32_t fb_pending_map_offset_pages;
    uint32_t fb_mapping_start;
    uint32_t fb_mapping_length;
    int fb_mapping_valid;
    struct guest_process_compat_state process_compat;
    struct guest_qemud_diag_state qemud_diag;
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
    char exec_backing_path[PATH_MAX];
    char pending_exec_target[PATH_MAX];
    char pending_exec_backing_path[PATH_MAX];
    char exec_script_path[PATH_MAX];
    char pending_exec_script[PATH_MAX];
    int sigaction_compat_pending;
    uint32_t sigaction_compat_old_address;
    uint32_t sigaction_compat_rt_old_address;
    int target_elf_text_seen;
    uint32_t target_elf_text_pc;
    uint64_t target_elf_text_file_offset;
    int target_elf_entry_valid;
    int exec_image_committed;
    int target_elf_entry_pc_seen;
    uint16_t target_elf_type;
    uint32_t target_elf_entry;
};

static struct guest_qemud_diag_run_budget guest_qemud_diag_run_budget;

static void log_guest_qemud_syscall(pid_t host_pid, const struct tracee_state *state,
        const struct guest_qemud_diag_record *record) {
    char safe_path[GUEST_QEMUD_DIAG_PATH_CAP * 4u];
    char safe_fd_path[GUEST_QEMUD_DIAG_PATH_CAP * 4u];
    int path_truncated = guest_diag_escape(record->path, safe_path, sizeof(safe_path));
    int fd_path_truncated = guest_diag_escape(record->fd_path, safe_fd_path,
                                               sizeof(safe_fd_path));
    int error_number = record->result < 0 && record->result >= -4095
        ? -record->result : 0;
    printf("GUEST QEMUD SYSCALL: host-pid=%d guest-pid=%d seq=%u syscall=%d(%s) pc=0x%08x lr=0x%08x args=%u,%u,%u,%u,%u,%u path=\"%s\" path-truncated=%d fd-path=\"%s\" fd-path-truncated=%d result=%d errno=%d(%s); diagnostic-only, guest result unchanged, no host device/socket substitute\n",
           host_pid, state->guest_pid, record->sequence, record->syscall_number,
           guest_diag_syscall_name(record->syscall_number), record->pc, record->lr,
           record->args[0], record->args[1], record->args[2], record->args[3],
           record->args[4], record->args[5], safe_path, path_truncated,
           safe_fd_path, fd_path_truncated, record->result, error_number,
           error_number ? guest_diag_errno_name(error_number) : "none");
}

static void log_guest_qemud_startup_diagnostics(const struct tracee_state *state,
        const char *wait_kind, int wait_status) {
    const struct guest_qemud_diag_state *diag = &state->qemud_diag;
    char safe_tty_path[GUEST_QEMUD_DIAG_PATH_CAP * 4u];
    int tty_path_truncated = guest_diag_escape(diag->tty_open_path,
        safe_tty_path, sizeof(safe_tty_path));
    printf("GUEST QEMUD STARTUP DIAGNOSTICS: guest-pid=%d wait=%s status=%d observed-syscalls=%u records-selected=%u per-process-records-dropped=%u pending=%d cmdline-open-count=%u cmdline-read-data-observations=%u cmdline-read-observed-bytes=%u observed-qemu-1=%d observed-android.qemud=%d observed-port=%s tty-open-attempts=%u tty-open-path=\"%s\" tty-open-path-truncated=%d tty-open-result=%d exit-request-seen=%d exit-syscall=%d(%s) requested-status=%u exit-pc=0x%08x exit-lr=0x%08x stderr-capture-armed=%d stderr-capture-reason=%s stderr-preview-attempts=%u target-text-PC-seen=%d target-e_entry-PC-seen=%d; raw cmdline omitted, stderr previews are escaped guest bytes, no broker behavior inferred from log-device failures\n",
           state->guest_pid, wait_kind, wait_status, diag->syscall_count,
           diag->records_emitted, diag->records_suppressed, diag->pending,
           diag->cmdline_open_count, diag->cmdline_read_calls,
           diag->cmdline_read_bytes, diag->cmdline_qemu_enabled,
           diag->cmdline_qemud_parameter_present,
           guest_qemud_diag_safe_port_label(diag),
           diag->tty_open_attempts, safe_tty_path, tty_path_truncated,
           diag->tty_open_result, diag->exit_request_seen,
           diag->exit_request_syscall,
           diag->exit_request_seen
               ? guest_diag_syscall_name(diag->exit_request_syscall) : "none",
           diag->exit_request_status, diag->exit_request_pc,
           diag->exit_request_lr, diag->stderr_capture_armed,
           guest_qemud_diag_stderr_reason_name(diag->stderr_capture_reason),
           diag->stderr_preview_chunks,
           state->target_elf_text_seen, state->target_elf_entry_pc_seen);
}

struct guest_coldboot_marker_runtime {
    char backing_path[PATH_MAX];
    pid_t host_pid;
    pid_t guest_pid;
    int guest_fd;
    int fd_valid;
    int open_seen;
    int32_t open_result;
    uint32_t open_flags;
    uint32_t open_mode;
    int close_seen;
    int32_t close_result;
    int wait_release_logged;
    unsigned long write_calls;
    unsigned long fsync_calls;
    unsigned long fdatasync_calls;
    int last_lstat_observed;
    int last_lstat_result;
    int last_lstat_errno;
    struct stat last_lstat;
};
enum pending_kind { PENDING_NONE, PENDING_RESULT };

static pid_t traced_pid = -1;
static char guest_root[PATH_MAX];
static char native_guest_root[PATH_MAX];
static const char *guest_program = "/init";
static char guest_frame_directory[PATH_MAX];
static int guest_frame_directory_fd = -1;
static int guest_frame_channel_ready;
static unsigned long guest_frame_published_count;
static struct guest_framebuffer_model guest_fb0_model;
static struct guest_binder_global_state guest_binder_state;
static int guest_fb0_backing_fd = -1;
static struct stat guest_fb0_backing_stat;
static int guest_fb0_backend_ready;
static unsigned long guest_fb0_open_count;
static unsigned long guest_fb0_ioctl_count;
static unsigned long guest_fb0_mmap_count;
static unsigned long guest_fb0_pan_count;
static int guest_fb0_graphics_uevent_received;
static int guest_fb0_node_created;
static struct guest_goldfish_tty_runtime guest_goldfish_tty_runtime;
static struct guest_goldfish_tty_epoll_table guest_goldfish_tty_epolls;
static unsigned long guest_qemud_socket_bind_count;
static unsigned guest_goldfish_tty_diagnostics_emitted;

static const char *guest_frame_channel_scope_name(
        enum guest_frame_channel_validation_scope scope) {
    switch (scope) {
        case GUEST_FRAME_CHANNEL_SCOPE_ROOT_PARENT: return "guest-root-parent";
        case GUEST_FRAME_CHANNEL_SCOPE_CHANNEL_PARENT: return "channel-parent";
        case GUEST_FRAME_CHANNEL_SCOPE_PARENT_IDENTITY: return "parent-identity";
        case GUEST_FRAME_CHANNEL_SCOPE_PARENT_OWNER: return "parent-owner";
        case GUEST_FRAME_CHANNEL_SCOPE_PARENT_MODE: return "parent-write-mode";
        case GUEST_FRAME_CHANNEL_SCOPE_GUEST_ROOT_LEAF: return "guest-root-leaf";
        case GUEST_FRAME_CHANNEL_SCOPE_CHANNEL_LEAF: return "channel-leaf";
        default: return "none";
    }
}

static void print_guest_frame_path_components(const char *role,
        const struct guest_frame_channel_path_audit *audit) {
    if (!role || !audit || !audit->path[0]) return;
    char component_path[PATH_MAX] = "/";
    for (unsigned int i = 0; i < audit->component_count &&
         i < GUEST_FRAME_CHANNEL_MAX_PATH_COMPONENTS; ++i) {
        const struct guest_frame_channel_component_audit *component =
            &audit->components[i];
        if (i != 0) {
            size_t used = strlen(component_path);
            size_t name_length = strlen(component->name);
            size_t separator = used > 1u ? 1u : 0u;
            if (used + separator + name_length >= sizeof(component_path)) break;
            if (separator) component_path[used++] = '/';
            memcpy(component_path + used, component->name, name_length + 1u);
        }
        printf("GUEST FRAME CHANNEL PATH COMPONENT: role=%s path=%s stat=%d uid=%u gid=%u mode=0%o permissions=0%04o device=%llu inode=%llu opened=%d symlink=%d errno=%d\n",
               role, component_path, component->has_stat,
               (unsigned)component->owner, (unsigned)component->group,
               (unsigned)component->mode,
               (unsigned)(component->mode & 07777u),
               (unsigned long long)component->device,
               (unsigned long long)component->inode, component->opened,
               component->symlink, component->error_number);
    }
}

static void print_guest_frame_channel_audit(
        const struct guest_frame_channel_validation_detail *detail) {
    if (!detail) return;
    print_guest_frame_path_components("guest-root-parent", &detail->root_parent_audit);
    print_guest_frame_path_components("channel-parent", &detail->channel_parent_audit);
    printf("GUEST FRAME CHANNEL LEAF AUDIT: role=guest-root path=%s stat=%d symlink=%d uid=%u gid=%u mode=0%o permissions=0%04o device=%llu inode=%llu\n",
           detail->guest_root_path, detail->root_has_stat, detail->root_is_symlink,
           (unsigned)detail->root_owner, (unsigned)detail->root_group,
           (unsigned)detail->root_mode, (unsigned)(detail->root_mode & 07777u),
           (unsigned long long)detail->root_device,
           (unsigned long long)detail->root_inode);
    printf("GUEST FRAME CHANNEL LEAF AUDIT: role=channel path=%s stat=%d symlink=%d uid=%u gid=%u mode=0%o permissions=0%04o device=%llu inode=%llu\n",
           detail->channel_path, detail->channel_has_stat, detail->channel_is_symlink,
           (unsigned)detail->channel_owner, (unsigned)detail->channel_group,
           (unsigned)detail->channel_mode,
           (unsigned)(detail->channel_mode & 07777u),
           (unsigned long long)detail->channel_device,
           (unsigned long long)detail->channel_inode);
}

static void configure_guest_frame_channel(void) {
    const char *configured = getenv(GUEST_FRAME_CHANNEL_ENV);
    if (configured && configured[0]) {
        struct guest_frame_channel_validation_detail validation;
        int rc = guest_frame_channel_open_app_private_sibling_ex(
            configured, guest_root, getuid(), &validation);
        print_guest_frame_channel_audit(&validation);
        if (rc >= 0) {
            size_t length = strlen(configured);
            memcpy(guest_frame_directory, configured, length + 1);
            guest_frame_directory_fd = rc;
            guest_frame_channel_ready = 1;
            printf("GUEST FRAME CHANNEL CONFIG: ready=1 path=%s guest-root=%s owner=%u mode=0700; parent directory identities match, guest-root/channel leaves opened O_NOFOLLOW; atomic GVMF/1 packets; no pixels claimed\n",
                   configured, guest_root, (unsigned)getuid());
            guest_framebuffer_model_init(&guest_fb0_model);
            char backing_path[PATH_MAX];
            rc = guest_fb0_prepare_app_private_backing_at(guest_frame_directory_fd,
                guest_frame_directory, backing_path, sizeof(backing_path),
                &guest_fb0_backing_fd);
            if (rc == 0 && fstat(guest_fb0_backing_fd, &guest_fb0_backing_stat) == 0) {
                guest_fb0_backend_ready = 1;
                printf("GUEST FB0 SOFTWARE BACKEND: ready=1 path=%s profile=%s %ux%u RGB565 double-buffer-bytes=%u source=Goldfish-fbdev-model; no host framebuffer/MMIO/IRQ/QEMU used\n",
                       backing_path, GUEST_PROFILE_DISPLAY_SKIN,
                       GUEST_PROFILE_DISPLAY_WIDTH, GUEST_PROFILE_DISPLAY_HEIGHT,
                       guest_fb0_smem_len());
            } else {
                if (rc == 0) rc = -errno;
                if (guest_fb0_backing_fd >= 0) close(guest_fb0_backing_fd);
                guest_fb0_backing_fd = -1;
                printf("GUEST FB0 SOFTWARE BACKEND: ready=0 private backing creation/validation failed errno=%d; guest fb0 open will fail closed\n",
                       -rc);
            }
        } else {
            printf("GUEST FRAME CHANNEL CONFIG: ready=0 path=%s guest-root=%s expected-sibling=%s reason=%s scope=%s errno=%d has-stat=%d owner=%u expected-owner=%u mode=0%o; component-wise O_NOFOLLOW and owner/private leaf checks remain enforced; trace continues without frame output\n",
                   configured, guest_root,
                   validation.expected_path[0] ? validation.expected_path : "<unavailable>",
                   guest_frame_channel_validation_reason_name(validation.reason),
                   guest_frame_channel_scope_name(validation.scope),
                   validation.error_number, validation.has_stat,
                   (unsigned)validation.actual_owner,
                   (unsigned)validation.expected_owner,
                   (unsigned)(validation.actual_mode & 07777u));
        }
    } else {
        puts("GUEST FRAME CHANNEL CONFIG: ready=0; app frame directory not supplied; trace continues without frame output");
    }
    if (unsetenv(GUEST_FRAME_CHANNEL_ENV) != 0)
        printf("GUEST FRAME CHANNEL CONFIG: supervisor environment cleanup failed errno=%d; guest exec still uses a fixed environment\n",
               errno);
}

int gingervm_publish_guest_frame_from_fb(const guest_frame_packet *frame) {
    if (!guest_frame_channel_ready || guest_frame_directory_fd < 0) return -ENODEV;
    int rc = guest_frame_channel_publish_file_at(guest_frame_directory_fd, frame);
    if (rc == 0) {
        ++guest_frame_published_count;
        if (guest_frame_published_count == 1)
            puts("GUEST FRAME PUBLISHED: first validated source=guest-framebuffer packet written atomically; app renderer will verify checksum/format");
    } else if (guest_frame_published_count == 0) {
        printf("GUEST FRAME PUBLISH REJECTED: guest framebuffer packet invalid/unavailable errno=%d; no frame was emitted\n",
               -rc);
    }
    return rc;
}

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
static unsigned long guest_mknod_diagnostics_emitted;
static unsigned long guest_mknod_diagnostics_suppressed;
static unsigned long guest_null_stdio_diagnostics_emitted;
static unsigned long blocked_process_count;
static unsigned long process_events;
static unsigned long successful_guest_execs;
static unsigned long dynamic_exec_allowed_count;
static unsigned long dynamic_exec_started_count;
static unsigned long guest_script_routes_approved;
static unsigned long guest_script_exec_started_count;
static unsigned long brokered_sigsys_suppressed;
static struct guest_vsocket_table guest_sockets;
static struct guest_null_stdio_runtime guest_null_stdio_runtime;
static struct guest_kmsg_runtime guest_kmsg_runtime;
static unsigned long guest_kmsg_diagnostics_emitted;
static unsigned long virtual_fd_duplicate_denials;
static unsigned long virtual_property_bind_count;
static unsigned long virtual_af_unix_socket_count;
static unsigned long virtual_property_connect_count;
static unsigned long virtual_property_accept_count;
static unsigned long virtual_property_sendto_count;
static unsigned long virtual_property_recvfrom_count;
static unsigned long virtual_property_sendto_bytes;
static unsigned long virtual_property_recvfrom_bytes;
static unsigned long virtual_property_stream_errors;
static unsigned long virtual_property_stream_diagnostics;
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
static struct guest_coldboot_marker_runtime coldboot_marker_runtime;
static struct guest_network_state guest_network_state;
static struct guest_path_fd_table guest_path_fds;
static struct guest_arm32_timezone guest_timezone;
static unsigned long guest_sigaction_compat_calls;
static unsigned long guest_sigaction_compat_failures;
static unsigned long guest_setpgid_calls;
static unsigned long guest_timezone_calls;
static unsigned long guest_setrlimit_calls;
static unsigned long guest_ioprio_set_calls;
static unsigned long guest_getpgid_calls;
static unsigned long guest_wait4_calls;
static unsigned long guest_wait4_reap_diagnostics;
static unsigned long guest_sigchld_deliveries;
static size_t guest_unreaped_child_peak;
static unsigned long guest_thread_ptrace_exits;
static unsigned long guest_qemud_exec_count;
static unsigned long guest_qemu_props_exec_count;
static unsigned long guest_qemud_exit_count;
static int guest_qemud_last_exit_code = -1;
static unsigned long guest_target_elf_text_entry_count;
static unsigned long guest_target_elf_declared_entry_pc_count;
static unsigned long guest_app_process_declared_entry_pc_count;
static unsigned long guest_ueventd_declared_entry_pc_count;
static unsigned long guest_ueventd_exec_image_validated_count;
static unsigned long guest_ueventd_null_stdio_ready_count;
static unsigned long guest_null_stdio_alias_replaced_count;
static unsigned long guest_other_declared_entry_pc_count;
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
static struct guest_tracee_slot_pool tracee_slot_pool;
static size_t tracee_count;
static size_t active_tracee_count;
static struct ptrace_child_stop_queue pending_child_stops;
static unsigned long pending_child_stop_deferred;
static unsigned long pending_child_stop_adopted;
static unsigned long pending_child_stop_rejected;
static unsigned long pending_child_stop_queued_for_cleanup;
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

struct guest_binder_trace_memory { pid_t pid; };

static int guest_binder_trace_copyin(void *opaque, uint32_t address,
                                     void *destination, size_t length) {
    struct guest_binder_trace_memory *memory = opaque;
    if (!memory || !guest_binder_u32_range_valid(address, length)) return -EFAULT;
    return read_remote(memory->pid, address, destination, length) == 0 ? 0 : -EFAULT;
}

static int guest_binder_trace_copyout(void *opaque, uint32_t address,
                                      const void *source, size_t length) {
    struct guest_binder_trace_memory *memory = opaque;
    if (!memory || !guest_binder_u32_range_valid(address, length)) return -EFAULT;
    return write_remote(memory->pid, address, source, length) == 0 ? 0 : -EFAULT;
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

static const char *guest_mknod_mode_type(uint32_t mode) {
    switch (mode & S_IFMT) {
        case S_IFREG: return "regular";
        case S_IFDIR: return "directory";
        case S_IFCHR: return "character";
        case S_IFBLK: return "block";
        case S_IFIFO: return "fifo";
        case S_IFLNK: return "symlink";
        case S_IFSOCK: return "socket";
        default: return "unknown";
    }
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

static int tracee_has_verified_api10_init_image(const struct tracee_state *state) {
    return state && strcmp(state->exec_target, "/init") == 0 &&
        state->exec_image_committed && state->target_elf_entry_valid &&
        state->target_elf_type == ET_EXEC && state->exec_backing_path[0] &&
        ((guest_root[0] && path_is_within(state->exec_backing_path, guest_root)) ||
         (native_guest_root[0] &&
          path_is_within(state->exec_backing_path, native_guest_root)));
}

static int tracee_is_verified_api10_init(const struct tracee_state *state) {
    return state && guest_vsocket_actor_is_verified_api10_init_pid1(
        state->guest_pid, state->guest_parent_pid, state->guest_euid,
        state->is_thread, tracee_has_verified_api10_init_image(state));
}

static int tracee_is_verified_api10_init_service_child(
        const struct tracee_state *state) {
    return state && guest_vsocket_actor_is_verified_api10_init_service_child(
        state->guest_pid, state->guest_parent_pid, state->guest_euid,
        state->is_thread, tracee_has_verified_api10_init_image(state));
}

static int tracee_is_verified_api10_qemud(const struct tracee_state *state) {
    return state && state->guest_pid > 1 && state->guest_parent_pid == 1 &&
        strcmp(state->exec_target, "/system/bin/qemud") == 0 &&
        state->exec_image_committed && state->target_elf_entry_valid &&
        state->target_elf_type == ET_EXEC && state->exec_backing_path[0] &&
        ((guest_root[0] && path_is_within(state->exec_backing_path, guest_root)) ||
         (native_guest_root[0] &&
          path_is_within(state->exec_backing_path, native_guest_root)));
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

static const char *guest_coldboot_file_type(mode_t mode) {
    if (S_ISREG(mode)) return "regular";
    if (S_ISDIR(mode)) return "directory";
    if (S_ISLNK(mode)) return "symlink";
    if (S_ISCHR(mode)) return "character";
    if (S_ISBLK(mode)) return "block";
    if (S_ISFIFO(mode)) return "fifo";
    if (S_ISSOCK(mode)) return "socket";
    return "unknown";
}

static int guest_coldboot_stat_leaf_nofollow(const char *backing_path,
                                              struct stat *st) {
    if (!backing_path || !st || !path_is_within(backing_path, guest_root))
        return -EACCES;
    char parent[PATH_MAX];
    size_t path_length = strlen(backing_path);
    if (path_length == 0 || path_length >= sizeof(parent)) return -ENAMETOOLONG;
    memcpy(parent, backing_path, path_length + 1u);
    char *slash = strrchr(parent, '/');
    if (!slash || !slash[1]) return -EACCES;
    size_t leaf_length = strlen(slash + 1);
    if (leaf_length > NAME_MAX) return -ENAMETOOLONG;
    char leaf[NAME_MAX + 1];
    memcpy(leaf, slash + 1, leaf_length + 1u);
    if (slash == parent) slash[1] = '\0';
    else *slash = '\0';
    int dirfd = guest_safe_dir_open_beneath_root(guest_root, parent, 0, 0700);
    if (dirfd < 0) return dirfd;
    int rc = fstatat(dirfd, leaf, st, AT_SYMLINK_NOFOLLOW);
    int saved_errno = errno;
    close(dirfd);
    return rc == 0 ? 0 : -saved_errno;
}

static void log_guest_coldboot_marker_snapshot(const char *stage,
                                                pid_t guest_pid,
                                                int32_t guest_result,
                                                const char *backing_path,
                                                int same_open_backing) {
    char relative[PATH_MAX] = "<unavailable>";
    int contained = backing_path && backing_path[0] &&
        path_is_within(backing_path, guest_root);
    if (contained) {
        size_t root_length = strlen(guest_root);
        const char *suffix = backing_path + root_length;
        if (*suffix == '\0') suffix = "/";
        if (snprintf(relative, sizeof(relative), "%s", suffix) >=
            (int)sizeof(relative)) {
            contained = 0;
            snprintf(relative, sizeof(relative), "<too-long>");
        }
    }
    struct stat st;
    memset(&st, 0, sizeof(st));
    int lstat_result = -1;
    int metadata_rc = contained
        ? guest_coldboot_stat_leaf_nofollow(backing_path, &st) : -EACCES;
    int lstat_errno = metadata_rc == 0 ? 0 : -metadata_rc;
    if (metadata_rc == 0) lstat_result = 0;
    const char *type = lstat_result == 0
        ? guest_coldboot_file_type(st.st_mode) : "missing-or-inaccessible";
    if (contained && coldboot_marker_runtime.backing_path[0] &&
        strcmp(backing_path, coldboot_marker_runtime.backing_path) == 0) {
        coldboot_marker_runtime.last_lstat_observed = 1;
        coldboot_marker_runtime.last_lstat_result = lstat_result;
        coldboot_marker_runtime.last_lstat_errno = lstat_errno;
        if (lstat_result == 0) coldboot_marker_runtime.last_lstat = st;
        else memset(&coldboot_marker_runtime.last_lstat, 0,
                    sizeof(coldboot_marker_runtime.last_lstat));
    }
    printf("%s: guest-pid=%d path=%s guest-result=%d backing=guest-root:%s contained=%d nofollow-stat-result=%d nofollow-stat-errno=%d leaf-type=%s mode=0%o inode=%llu size=%lld same-open-backing=%d; metadata uses a descriptor-relative fstatat(AT_SYMLINK_NOFOLLOW) walk beneath the app-private root\n",
           stage, guest_pid, GUEST_COLD_BOOT_MARKER_PATH, guest_result,
           relative, contained, lstat_result, lstat_errno, type,
           lstat_result == 0 ? (unsigned)st.st_mode : 0u,
           lstat_result == 0 ? (unsigned long long)st.st_ino : 0ull,
           lstat_result == 0 ? (long long)st.st_size : 0ll,
           same_open_backing);
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
    if (!state || !regs || state->target_elf_text_seen ||
        !state->exec_target[0] || !state->exec_backing_path[0]) return;
    uint32_t pc = regs->uregs[15] & ~1u;
    struct guest_diag_proc_map mapping;
    memset(&mapping, 0, sizeof(mapping));
    if (guest_diag_find_proc_map(host_pid, pc, &mapping) != 0) return;
    char canonical_expected[PATH_MAX];
    int match = guest_entry_mapping_matches(mapping.path, state->exec_backing_path,
                                             mapping.permissions);
    if (!match && realpath(state->exec_backing_path, canonical_expected))
        match = guest_entry_mapping_matches(mapping.path, canonical_expected,
                                             mapping.permissions);
    if (!match) return;
    state->target_elf_text_seen = 1;
    state->target_elf_text_pc = pc;
    state->target_elf_text_file_offset = guest_diag_proc_map_file_offset(&mapping, pc);
    int exact_entry_pc = state->target_elf_entry_valid &&
        state->target_elf_type == ET_EXEC && pc == state->target_elf_entry;
    if (exact_entry_pc && !state->target_elf_entry_pc_seen) {
        state->target_elf_entry_pc_seen = 1;
        guest_target_elf_declared_entry_pc_count++;
        if (strcmp(state->exec_target, "/system/bin/app_process") == 0)
            guest_app_process_declared_entry_pc_count++;
        else if (strcmp(state->exec_target, "/sbin/ueventd") == 0)
            guest_ueventd_declared_entry_pc_count++;
        else
            guest_other_declared_entry_pc_count++;
    }
    guest_target_elf_text_entry_count++;
    if (strcmp(state->exec_target, GUEST_API10_SHELL_PATH) == 0)
        guest_shell_elf_text_entry_count++;
    if (strcmp(state->exec_target, "/system/bin/app_process") == 0)
        guest_app_process_elf_text_entry_count++;
    char safe_target[GUEST_DIAGNOSTIC_TEXT_CAPACITY];
    char safe_module[GUEST_DIAGNOSTIC_TEXT_CAPACITY];
    int target_truncated = guest_diag_escape(state->exec_target, safe_target, sizeof(safe_target));
    int module_truncated = guest_diag_escape(mapping.path, safe_module, sizeof(safe_module));
    printf("GUEST TARGET ELF CODE PC: host-pid=%d guest-pid=%d target=\"%s\" pc=0x%08x map=0x%llx-0x%llx perms=%s file-offset=0x%llx module=\"%s\" declared-e_entry=0x%08x e_entry-PC-at-syscall=%d; target ELF code reached after linker; this is not proof of C main() truncated=%d,%d\n",
           host_pid, state->guest_pid, safe_target, pc,
           (unsigned long long)mapping.start, (unsigned long long)mapping.end,
           mapping.permissions, (unsigned long long)state->target_elf_text_file_offset,
           safe_module, state->target_elf_entry_valid ? state->target_elf_entry : 0u,
           exact_entry_pc, target_truncated, module_truncated || mapping.path_truncated);
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
    struct tracee_state *state = active_tracee && active_tracee->pid == pid
        ? active_tracee : NULL;
    if (state && nr == ARM_NR_OPEN &&
        state->guest_pid != 0 &&
        strcmp(state->exec_target, "/sbin/ueventd") == 0 &&
        strcmp(guest_out, GUEST_COLD_BOOT_MARKER_PATH) == 0) {
        coldboot_marker_runtime.backing_path[0] = '\0';
        if (path_is_within(host, guest_root)) {
            snprintf(coldboot_marker_runtime.backing_path,
                     sizeof(coldboot_marker_runtime.backing_path), "%s", host);
            coldboot_marker_runtime.host_pid = pid;
            coldboot_marker_runtime.guest_pid = state->guest_pid;
        }
    }
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

static int guest_fb0_fd_matches(pid_t pid, int fd) {
    return guest_fb0_backend_ready &&
        guest_fb0_fd_matches_proc(pid, fd, &guest_fb0_backing_stat);
}

static int rewrite_fb0_path_arg(pid_t pid, struct compat_pt_regs *regs,
                                unsigned path_arg, unsigned flags_arg) {
    if (!guest_fb0_backend_ready || !guest_frame_channel_ready ||
        !guest_frame_directory[0]) return -ENODEV;
    int valid = guest_frame_channel_validate_app_private_directory(
        guest_frame_directory, guest_root);
    if (valid != 1) return valid < 0 ? valid : -EACCES;
    char backing_path[PATH_MAX];
    int n = snprintf(backing_path, sizeof(backing_path), "%s/%s",
                     guest_frame_directory, GUEST_FB0_BACKING_FILE);
    if (n <= 0 || (size_t)n >= sizeof(backing_path)) return -ENAMETOOLONG;
    struct stat st;
    if (lstat(backing_path, &st) != 0) return -errno;
    if (!S_ISREG(st.st_mode) || st.st_uid != getuid() || st.st_nlink != 1 ||
        st.st_dev != guest_fb0_backing_stat.st_dev ||
        st.st_ino != guest_fb0_backing_stat.st_ino || (st.st_mode & 077u) != 0)
        return -EACCES;
    unsigned flags = regs->uregs[flags_arg];
    if ((flags & O_ACCMODE) == O_ACCMODE) return -EINVAL;
    flags &= ~(uint32_t)(O_CREAT | O_EXCL | O_TRUNC | O_APPEND | O_DIRECTORY);
    flags |= O_NOFOLLOW;
    regs->uregs[flags_arg] = flags;
    size_t bytes = strlen(backing_path) + 1u;
    if (bytes >= 2048u) return -ENAMETOOLONG;
    uint32_t scratch = (regs->uregs[13] - SCRATCH_BELOW_SP) &
                       ~((uint32_t)sizeof(long) - 1u);
    if (write_remote(pid, scratch, backing_path, bytes) != 0) return -EFAULT;
    regs->uregs[path_arg] = scratch;
    path_rewrites++;
    return 0;
}

static int mediate_guest_fb0_ioctl(pid_t pid, struct tracee_state *state,
                                  struct compat_pt_regs *regs, int32_t *result) {
    int fd = (int32_t)regs->uregs[0];
    if (!guest_fb0_fd_matches(pid, fd)) return 1;
    uint32_t command = regs->uregs[1];
    uint32_t argument = regs->uregs[2];
    if (!argument) return -EFAULT;
    guest_fb0_ioctl_count++;
    if (command == GUEST_FB0_IOCTL_GET_VSCREENINFO) {
        struct guest_arm32_fb_var_screeninfo info;
        guest_fb0_make_var(&guest_fb0_model, &info);
        *result = write_remote(pid, argument, &info, sizeof(info)) == 0 ? 0 : -EFAULT;
    } else if (command == GUEST_FB0_IOCTL_PUT_VSCREENINFO) {
        struct guest_arm32_fb_var_screeninfo requested;
        if (read_remote(pid, argument, &requested, sizeof(requested)) != 0)
            *result = -EFAULT;
        else
            *result = guest_fb0_commit_put(&guest_fb0_model, &requested);
    } else if (command == GUEST_FB0_IOCTL_GET_FSCREENINFO) {
        struct guest_arm32_fb_fix_screeninfo info;
        guest_fb0_make_fix(&guest_fb0_model, &info);
        *result = write_remote(pid, argument, &info, sizeof(info)) == 0 ? 0 : -EFAULT;
    } else if (command == GUEST_FB0_IOCTL_PAN_DISPLAY) {
        struct guest_arm32_fb_var_screeninfo requested;
        if (read_remote(pid, argument, &requested, sizeof(requested)) != 0) {
            *result = -EFAULT;
        } else {
            *result = guest_fb0_commit_pan(&guest_fb0_model, &requested);
            if (*result == 0) {
                guest_fb0_pan_count++;
                printf("GUEST FB0 SOFTWARE BASE-UPDATE ACK: guest-pid=%d yoffset=%u count=%lu source=software model; no Goldfish MMIO write or IRQ was executed\n",
                       state ? state->guest_pid : -1,
                       guest_fb0_model.yoffset,
                       guest_fb0_model.software_base_update_acks);
                if (state && state->fb_mapping_valid) {
                    int publish_rc = guest_fb0_capture_publish(
                        guest_fb0_backing_fd, guest_frame_directory_fd,
                        &guest_fb0_model, guest_fb0_model.yoffset);
                    if (publish_rc == 0) {
                        guest_frame_published_count++;
                        printf("GUEST FB0 PAGE FLIP FRAME: guest-pid=%d executable=%s yoffset=%u sequence=%llu bytes=%u publish=success; pixels copied only from guest MAP_SHARED fb0 backing, no host display device\n",
                               state->guest_pid, state->exec_target,
                               guest_fb0_model.yoffset,
                               (unsigned long long)guest_fb0_model.sequence,
                               guest_fb0_smem_len() / GUEST_FB0_DOUBLE_BUFFER_COUNT);
                    } else {
                        printf("GUEST FB0 PAGE FLIP: guest-pid=%d yoffset=%u model=committed frame-publish=failed errno=%d; ioctl remains successful and no substitute pixels are sent\n",
                               state->guest_pid, guest_fb0_model.yoffset,
                               -publish_rc);
                    }
                }
            }
        }
    } else {
        *result = -ENOTTY;
    }
    if (guest_fb0_ioctl_count <= 48u)
        printf("GUEST FB0 IOCTL: guest-pid=%d executable=%s fd=%d request=0x%x yoffset=%u mapped=%d result=%d; API10 ARM32 fbdev state only, no Goldfish MMIO/IRQ or host ioctl\n",
               state ? state->guest_pid : -1,
               state ? state->exec_target : "<unknown>", fd, command,
               guest_fb0_model.yoffset, state ? state->fb_mapping_valid : 0,
               *result);
    return 0;
}

static int mediate_guest_fb0_mmap(pid_t pid, struct tracee_state *state,
                                  const struct compat_pt_regs *regs) {
    int fd = (int32_t)regs->uregs[4];
    if (!guest_fb0_fd_matches(pid, fd)) return 1;
    int rc = guest_fb0_validate_mmap(regs->uregs[1], regs->uregs[2],
                                    regs->uregs[3], regs->uregs[5]);
    if (rc != 0) return rc;
    if ((regs->uregs[3] & MAP_TYPE) != MAP_SHARED) return -EINVAL;
    state->fb_mmap_pending = 1;
    state->fb_pending_map_length = regs->uregs[1];
    state->fb_pending_map_flags = regs->uregs[2];
    state->fb_pending_map_offset_pages = regs->uregs[5];
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

static int seed_regular_file(const char *dir, const char *name, const char *contents) {
    if (!contents) return -EINVAL;
    return guest_safe_file_replace_beneath_root(guest_root, dir, name,
                                                 contents, strlen(contents), 0600);
}

static int seed_virtual_tty_sysfs_tree(const char *backing) {
    char class_tty[PATH_MAX];
    int n = snprintf(class_tty, sizeof(class_tty), "%s/class/tty", backing);
    if (n <= 0 || (size_t)n >= sizeof(class_tty)) return -ENAMETOOLONG;
    for (uint32_t minor = 0; minor < GUEST_GOLDFISH_TTY_LINE_COUNT; ++minor) {
        char tty_name[16], device_path[PATH_MAX], dev_text[32], link_target[64];
        n = snprintf(tty_name, sizeof(tty_name), "ttyS%u", minor);
        if (n <= 0 || (size_t)n >= sizeof(tty_name)) return -ENAMETOOLONG;
        n = snprintf(device_path, sizeof(device_path),
            "%s/devices/virtual/tty/%s", backing, tty_name);
        if (n <= 0 || (size_t)n >= sizeof(device_path)) return -ENAMETOOLONG;
        int directory_fd = guest_safe_dir_open_beneath_root(
            guest_root, device_path, 1, 0700);
        if (directory_fd < 0) return directory_fd;
        close(directory_fd);
        n = snprintf(dev_text, sizeof(dev_text), "%u:%u\n",
            GUEST_GOLDFISH_TTY_SYNTHETIC_MAJOR, minor);
        if (n <= 0 || (size_t)n >= sizeof(dev_text)) return -ENAMETOOLONG;
        int rc = seed_regular_file(device_path, "dev", dev_text);
        if (rc != 0) return rc;
        rc = seed_regular_file(device_path, "uevent", "");
        if (rc != 0) return rc;
        n = snprintf(link_target, sizeof(link_target),
            "../../devices/virtual/tty/%s", tty_name);
        if (n <= 0 || (size_t)n >= sizeof(link_target)) return -ENAMETOOLONG;
        rc = guest_safe_symlink_beneath_root(guest_root, class_tty,
            tty_name, link_target);
        if (rc != 0) return rc;
    }
    printf("GUEST GOLDFISH TTY PROFILE: lines=%u class=/sys/class/tty/ttyS0-ttyS7 sysfs=/sys/devices/virtual/tty/ttyS0-ttyS7 dev-text=%u:<minor> major-is-synthetic=1 qemud-line=ttyS1; no Goldfish runtime kernel or host tty used\n",
           GUEST_GOLDFISH_TTY_LINE_COUNT, GUEST_GOLDFISH_TTY_SYNTHETIC_MAJOR);
    return 0;
}

static int seed_virtual_sysfs_tree(const char *backing) {
    static const char *const suffixes[] = {
        "class", "class/net", "class/graphics", "class/tty", "block", "devices",
        "devices/virtual", "devices/virtual/net", "devices/virtual/net/eth0",
        "devices/virtual/graphics", "devices/virtual/graphics/fb0",
        "devices/virtual/tty", NULL,
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
    char class_net[PATH_MAX], class_graphics[PATH_MAX], device[PATH_MAX];
    int n = snprintf(class_net, sizeof(class_net), "%s/class/net", backing);
    if (n <= 0 || (size_t)n >= sizeof(class_net)) return -ENAMETOOLONG;
    int rc = guest_safe_symlink_beneath_root(guest_root, class_net, "eth0",
                                              "../../devices/virtual/net/eth0");
    if (rc != 0) return rc;
    n = snprintf(device, sizeof(device), "%s/devices/virtual/net/eth0", backing);
    if (n <= 0 || (size_t)n >= sizeof(device)) return -ENAMETOOLONG;
    rc = seed_regular_file(device, "operstate", "down\n");
    if (rc != 0) return rc;
    n = snprintf(class_graphics, sizeof(class_graphics), "%s/class/graphics", backing);
    if (n <= 0 || (size_t)n >= sizeof(class_graphics)) return -ENAMETOOLONG;
    rc = guest_safe_symlink_beneath_root(guest_root, class_graphics, "fb0",
        "../../devices/virtual/graphics/fb0");
    if (rc != 0) return rc;
    n = snprintf(device, sizeof(device), "%s/devices/virtual/graphics/fb0", backing);
    if (n <= 0 || (size_t)n >= sizeof(device)) return -ENAMETOOLONG;
    rc = seed_regular_file(device, "uevent", "");
    if (rc != 0) return rc;
    return seed_virtual_tty_sysfs_tree(backing);
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
    rc = seed_regular_file(backing, "devices", GUEST_PROFILE_PROC_DEVICES);
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
        memset(&coldboot_marker_runtime, 0, sizeof(coldboot_marker_runtime));
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
        int fd = VIRTUAL_FD_BASE + slot;
        clear_virtual_fd_group(state, slot);
        release_virtual_fd_if_unreferenced(fd);
        guest_kmsg_note_fd_closed(&guest_kmsg_runtime, fd, 0,
                                  virtual_fd_referenced(fd), 1);
    }
}

static void release_virtual_fd_if_unreferenced(int fd) {
    if (virtual_fd_referenced(fd)) return;
    struct guest_vsocket_fd *entry = guest_vsocket_fd_get(&guest_sockets, fd);
    if (entry && (entry->kind == VIRTUAL_FD_DEV_TTY ||
                  entry->kind == VIRTUAL_FD_QEMUD_LISTENER))
        guest_goldfish_tty_epoll_remove_watched_fd(&guest_goldfish_tty_epolls, fd);
    if (entry && entry->kind == VIRTUAL_FD_DEV_TTY &&
        guest_goldfish_tty_runtime.tty_fd == fd)
        (void)guest_goldfish_tty_note_close(&guest_goldfish_tty_runtime, fd);
    if (entry && entry->kind == VIRTUAL_FD_EPOLL)
        (void)guest_goldfish_tty_epoll_close(&guest_goldfish_tty_epolls, fd);
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
        case VIRTUAL_FD_DEV_BINDER: return "guest-only API10 Binder bootstrap descriptor; no host Binder fd; transactions unsupported";
        default: return "other software virtual fd; no host fd";
    }
}

static int alloc_virtual_fd(enum virtual_fd_kind kind) {
    int fd = guest_vsocket_alloc_fd(&guest_sockets, kind);
    if (fd < 0) return fd;
    track_virtual_fd_for_group(active_tracee, fd);
    return fd;
}

static void set_guest_null_stdio_mask_for_group(struct tracee_state *owner,
                                                 uint8_t mask) {
    if (!owner) return;
    for (size_t i = 0; i < tracee_count; ++i) {
        struct tracee_state *state = &tracees[i];
        if (state->alive && state->virtual_fd_table_id == owner->virtual_fd_table_id)
            state->null_stdio_mask = mask;
    }
    guest_null_stdio_runtime.stdio_mask_last = mask;
}

static int guest_null_stdio_virtual_fd_valid(const struct tracee_state *state,
                                              int fd) {
    if (!state || !is_virtual_fd_number(fd) || !tracee_owns_virtual_fd(state, fd))
        return 0;
    struct guest_vsocket_fd *entry = guest_vsocket_fd_get(&guest_sockets, fd);
    return entry && entry->kind == VIRTUAL_FD_DEV_NULL &&
           entry->device_major == 1u && entry->device_minor == 3u &&
           (entry->open_flags & GUEST_ARM32_O_ACCMODE) == GUEST_ARM32_O_RDWR;
}

static struct guest_null_stdio_identity guest_null_stdio_identity_for_tracee(
        const struct tracee_state *state) {
    struct guest_null_stdio_identity identity;
    memset(&identity, 0, sizeof(identity));
    if (!state) return identity;
    identity.guest_pid = state->guest_pid;
    identity.guest_parent_pid = state->guest_parent_pid;
    identity.guest_euid = state->identity.euid;
    identity.executable = state->exec_target;
    identity.exec_image_committed = state->exec_image_committed &&
        state->pending_exec_target[0] == '\0' &&
        state->pending_exec_backing_path[0] == '\0';
    identity.arm32_elf_valid = state->target_elf_entry_valid;
    identity.backing_path_approved = state->exec_backing_path[0] != '\0' &&
        ((guest_root[0] && path_is_within(state->exec_backing_path, guest_root)) ||
         (native_guest_root[0] &&
          path_is_within(state->exec_backing_path, native_guest_root)));
    return identity;
}

static enum guest_null_stdio_actor guest_null_stdio_actor_for_tracee(
        const struct tracee_state *state) {
    struct guest_null_stdio_identity identity =
        guest_null_stdio_identity_for_tracee(state);
    return guest_null_stdio_actor_for_identity(&identity);
}

enum guest_ueventd_stdio_step {
    GUEST_UEVENTD_STDIO_MKNOD,
    GUEST_UEVENTD_STDIO_OPEN,
    GUEST_UEVENTD_STDIO_UNLINK,
    GUEST_UEVENTD_STDIO_DUP2,
    GUEST_UEVENTD_STDIO_SOURCE_CLOSE
};

static void guest_ueventd_null_stdio_note_step(struct tracee_state *state,
        enum guest_ueventd_stdio_step step, int value, int32_t result) {
    if (!state || guest_null_stdio_actor_for_tracee(state) !=
                      GUEST_NULL_STDIO_ACTOR_UEVENTD || result < 0)
        return;
    struct guest_null_stdio_exec_progress *progress = &state->null_stdio_exec;
    switch (step) {
        case GUEST_UEVENTD_STDIO_MKNOD:
            if (result == 0) progress->mknod_succeeded = 1;
            break;
        case GUEST_UEVENTD_STDIO_OPEN:
            progress->open_succeeded = 1;
            progress->source_fd = value;
            break;
        case GUEST_UEVENTD_STDIO_UNLINK:
            if (result == 0) progress->unlink_succeeded = 1;
            break;
        case GUEST_UEVENTD_STDIO_DUP2:
            if (value == progress->source_fd && result >= 0 && result <= 2)
                progress->dup2_mask |= (uint8_t)(1u << (unsigned)result);
            break;
        case GUEST_UEVENTD_STDIO_SOURCE_CLOSE:
            if (value == progress->source_fd && result == 0)
                progress->source_closed = 1;
            break;
    }
    if (!progress->ready_logged && progress->mknod_succeeded &&
        progress->open_succeeded && progress->unlink_succeeded &&
        progress->dup2_mask == GUEST_NULL_STDIO_FD_MASK &&
        progress->source_closed) {
        progress->ready_logged = 1;
        guest_ueventd_null_stdio_ready_count++;
        printf("GUEST UEVENTD NULL STDIO READY: guest-pid=%d parent-guest-pid=%d executable=%s backing=%s image=verified steps=mknod-1:3/0600,open-rw,unlink,dup2-0/1/2,close-source-fd; guest-only descriptor semantics, no host device\n",
               state->guest_pid, state->guest_parent_pid, state->exec_target,
               state->exec_backing_path);
    }
}

static int is_guest_ueventd(pid_t pid) {
    return active_tracee && active_tracee->pid == pid &&
           guest_null_stdio_actor_for_tracee(active_tracee) ==
               GUEST_NULL_STDIO_ACTOR_UEVENTD;
}

static int virtual_uevent_socket(pid_t pid, const struct compat_pt_regs *regs) {
    uint32_t domain = regs->uregs[0], type = regs->uregs[1], protocol = regs->uregs[2];
    printf("GUEST SOCKET ARGS: host-pid=%d guest-pid=%d parent-guest-pid=%d target=%s backing=%s exec-image-validated=%d syscall=%d domain=%u type=%u protocol=%u\n",
           pid, active_tracee ? active_tracee->guest_pid : -1,
           active_tracee ? active_tracee->guest_parent_pid : -1,
           active_tracee && active_tracee->exec_target[0] ? active_tracee->exec_target : "unknown",
           active_tracee && active_tracee->exec_backing_path[0]
               ? active_tracee->exec_backing_path : "<unknown>",
           is_guest_ueventd(pid),
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
    printf("VIRTUAL UEVENT BIND: fd=%d nl_family=%u nl_pid=%u guest-pid=%d parent-guest-pid=%d target=%s backing=%s exec-image-validated=1 nl_groups=0x%08x; host bind API not called\n",
           fd, (unsigned)addr.family, addr.pid, active_tracee->guest_pid,
           active_tracee->guest_parent_pid, active_tracee->exec_target,
           active_tracee->exec_backing_path, addr.groups);
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
    virtual_af_unix_socket_count++;
    virtual_socket_calls++;
    printf("VIRTUAL AF_UNIX SOCKET CREATE: host-pid=%d guest-pid=%d fd=%d family=AF_UNIX type=SOCK_STREAM protocol=0; app-private software descriptor; host socket API not called\n",
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
    if (!active_tracee || active_tracee->pid != pid) return -EPERM;
    if (!tracee_owns_virtual_fd(active_tracee, fd)) return -EBADF;
    rc = guest_vsocket_bind_validate(&guest_sockets, fd, family, guest_path);
    if (rc != 0) return rc;
    int verified_init_pid1 = tracee_is_verified_api10_init(active_tracee);
    int verified_init_service_child =
        tracee_is_verified_api10_init_service_child(active_tracee);
    if (!guest_vsocket_bind_actor_allowed(verified_init_pid1,
            verified_init_service_child, guest_path)) {
        virtual_socket_calls++;
        virtual_socket_rejected_count++;
        printf("VIRTUAL GUEST SERVICE BIND DENIED: host-pid=%d guest-pid=%d parent-guest-pid=%d service=%s result=-EPERM; only verified PID1 property-service and verified init-child qemud binds are allowed; host bind API not called\n",
               pid, active_tracee->guest_pid, active_tracee->guest_parent_pid,
               guest_vsocket_path_is_qemud_service(guest_path) ? "qemud" :
                   "property-service");
        return -EPERM;
    }
    rc = map_guest_path(guest_path, host_path, sizeof(host_path));
    if (rc != 0 || !path_is_within(host_path, guest_root)) {
        rc = rc != 0 ? rc : -EACCES;
        printf("VIRTUAL GUEST SERVICE BIND FAILED: guest-pid=%d service=%s stage=path-map result=%d; app-private containment required\n",
               active_tracee->guest_pid,
               guest_vsocket_path_is_qemud_service(guest_path) ? "qemud" :
                   "property-service", rc);
        return rc;
    }
    rc = guest_socket_marker_create_app_private(host_path, guest_root);
    if (rc != 0) {
        printf("VIRTUAL GUEST SERVICE BIND FAILED: guest-pid=%d service=%s stage=app-private-marker result=%d; no host socket created\n",
               active_tracee->guest_pid,
               guest_vsocket_path_is_qemud_service(guest_path) ? "qemud" :
                   "property-service", rc);
        return rc;
    }
    rc = guest_vsocket_bind_commit_path(&guest_sockets, fd, guest_path);
    if (rc != 0) {
        (void)unlink(host_path);
        return rc;
    }
    if (guest_vsocket_path_is_property_service(guest_path)) {
        virtual_property_bind_count++;
    } else {
        guest_qemud_socket_bind_count++;
    }
    virtual_socket_calls++;
    printf("VIRTUAL GUEST SERVICE BIND: host-pid=%d guest-pid=%d parent-guest-pid=%d actor=%s fd=%d path=%s service=%s marker=app-private regular VFS placeholder; host bind API not called\n",
           pid, active_tracee->guest_pid, active_tracee->guest_parent_pid,
           verified_init_service_child ? "verified-api10-init-service-child" :
               "verified-api10-init-pid1", fd, guest_path,
           guest_vsocket_path_is_qemud_service(guest_path) ? "qemud" : "property-service");
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
    struct guest_vsocket_fd *entry = guest_vsocket_fd_get(&guest_sockets, fd);
    if (entry && entry->kind == VIRTUAL_FD_QEMUD_LISTENER &&
        (!tracee_is_verified_api10_qemud(active_tracee) ||
         active_tracee->guest_euid != 0)) {
        virtual_socket_calls++;
        virtual_socket_rejected_count++;
        return -EPERM;
    }
    int rc = guest_vsocket_listen(&guest_sockets, fd, backlog);
    virtual_socket_calls++;
    if (rc == 0) {
        printf("VIRTUAL GUEST SERVICE LISTEN: guest-pid=%d executable=%s fd=%d service=%s backlog=%d; no synthetic peer/client; host listen API not called\n",
               active_tracee->guest_pid, active_tracee->exec_target, fd,
               entry && entry->kind == VIRTUAL_FD_QEMUD_LISTENER ? "qemud" : "property-service",
               backlog);
    }
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
    struct guest_vsocket_fd *listener = guest_vsocket_fd_get(&guest_sockets, fd);
    if (listener && listener->kind == VIRTUAL_FD_QEMUD_LISTENER &&
        (!tracee_is_verified_api10_qemud(active_tracee) ||
         active_tracee->guest_euid != 0)) {
        virtual_socket_calls++;
        virtual_socket_rejected_count++;
        return -EPERM;
    }
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
    int is_graphics_fb0_event =
        memmem(event->data, event->length, "DEVPATH=" GUEST_FB0_SYSFS_DEVICE_PATH,
               sizeof("DEVPATH=" GUEST_FB0_SYSFS_DEVICE_PATH) - 1u) != NULL;
    uint32_t tty_event_minor = 0;
    int is_goldfish_tty_event = guest_goldfish_tty_event_matches(
        event->data, event->length, &tty_event_minor);
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
    if (is_graphics_fb0_event) {
        guest_fb0_graphics_uevent_received = 1;
        puts("GUEST FB0 GRAPHICS UEVENT RECEIVED: ueventd consumed add event with DEVPATH=/devices/virtual/graphics/fb0 MAJOR=29 MINOR=0; node may now be created only through guest mknod mediation");
    }
    if (is_goldfish_tty_event && guest_goldfish_tty_note_event(
            &guest_goldfish_tty_runtime, event->data, event->length,
            &tty_event_minor))
        printf("GUEST GOLDFISH TTY UEVENT RECEIVED: guest-pid=%d action=add path=/devices/virtual/tty/ttyS%u subsystem=tty dev=synthetic:%u:%u; authorized ueventd consumed app-private event, no runtime-kernel dev_t claimed\n",
               state->guest_pid, tty_event_minor,
               GUEST_GOLDFISH_TTY_SYNTHETIC_MAJOR, tty_event_minor);
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
        char tty_attribute_path[PATH_MAX];
        const char *attribute_path = GUEST_UEVENT_SYSFS_ATTRIBUTE_PATH;
        if (entry->device_major == GUEST_FB0_MAJOR) {
            attribute_path = GUEST_FB0_SYSFS_ATTRIBUTE_PATH;
        } else if (entry->device_major == GUEST_GOLDFISH_TTY_SYNTHETIC_MAJOR) {
            int n = snprintf(tty_attribute_path, sizeof(tty_attribute_path),
                "%s%u/uevent", GUEST_GOLDFISH_TTY_SYSFS_ATTRIBUTE_PREFIX,
                entry->device_minor);
            if (n <= 0 || (size_t)n >= sizeof(tty_attribute_path)) return -ENAMETOOLONG;
            attribute_path = tty_attribute_path;
        }
        int result = guest_uevent_enqueue_coldboot_add(&guest_uevent_queue, 1,
            attribute_path, request, length);
        virtual_socket_calls++;
        if (result >= 0) {
            virtual_uevent_write_count++;
            printf("GUEST SYSFS UEVENT WRITE: guest-pid=%d path=%s bytes=%u result=%d queued=%zu; app-private event only, no host sysfs/netlink/device node\n",
                   state->guest_pid, attribute_path, length,
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
    if (result > 0) {
        const char *endpoint = !entry ? "unknown" :
            entry->kind == VIRTUAL_FD_SIGNAL ? "sigchld-socketpair" :
            entry->kind == VIRTUAL_FD_PROPERTY ? "property-control" :
            entry->kind == VIRTUAL_FD_PROPERTY_ACCEPTED ? "property-service-client" :
            "other-guest-virtual-socket";
        printf("VIRTUAL GUEST SOCKET IO: guest-pid=%d executable=%s fd=%d endpoint=%s direction=%s bytes=%d; app-private software queue only, host socket API not called\n",
               state->guest_pid, state->exec_target, fd, endpoint,
               receive ? "recv" : "send", result);
    }
    return result;
}

static int virtual_guest_property_stream_io(pid_t pid,
        const struct compat_pt_regs *regs, int receive) {
    struct tracee_state *state = active_tracee && active_tracee->pid == pid
        ? active_tracee : NULL;
    int fd = (int32_t)regs->uregs[0];
    uint32_t buffer_address = regs->uregs[1];
    uint32_t guest_length = regs->uregs[2];
    int flags = (int)regs->uregs[3];
    uintptr_t address = (uintptr_t)regs->uregs[4];
    uintptr_t address_length_or_pointer = (uintptr_t)regs->uregs[5];
    int result = -ESRCH;
    struct guest_vsocket_fd *entry = NULL;

    if (state) {
        if (!is_virtual_fd_number(fd)) {
            result = -ENOTSOCK;
        } else if (!is_virtual_fd(fd) || !tracee_owns_virtual_fd(state, fd)) {
            result = -EBADF;
        } else if (guest_length > (uint32_t)INT32_MAX) {
            result = -EINVAL;
        } else {
            result = guest_vsocket_property_stream_validate(&guest_sockets, fd,
                flags, address, address_length_or_pointer);
            entry = guest_vsocket_fd_get(&guest_sockets, fd);
            if (result == 0 && guest_length == 0) {
                result = 0;
            } else if (result == 0 && buffer_address == 0) {
                result = -EFAULT;
            } else if (result == 0) {
                size_t amount = guest_length > GUEST_VSOCKET_BUFFER_SIZE
                    ? GUEST_VSOCKET_BUFFER_SIZE : (size_t)guest_length;
                unsigned char buffer[GUEST_VSOCKET_BUFFER_SIZE];
                if (!receive) {
                    if (read_remote(pid, buffer_address, buffer, amount) != 0)
                        result = -EFAULT;
                    else
                        result = guest_vsocket_sendto(&guest_sockets, fd, buffer,
                            amount, flags, address, (uint32_t)address_length_or_pointer);
                } else {
                    result = guest_vsocket_peek(&guest_sockets, fd, buffer, amount, 0);
                    if (result > 0) {
                        if (write_remote(pid, buffer_address, buffer,
                                         (size_t)result) != 0) {
                            result = -EFAULT;
                        } else if (guest_vsocket_consume(&guest_sockets, fd,
                                                        (size_t)result) != 0) {
                            result = -EIO;
                        }
                    }
                }
            }
        }
    }

    virtual_socket_calls++;
    if (receive) virtual_property_recvfrom_count++;
    else virtual_property_sendto_count++;
    if (result < 0) virtual_property_stream_errors++;
    else if (result > 0) {
        if (receive) virtual_property_recvfrom_bytes += (unsigned long)result;
        else virtual_property_sendto_bytes += (unsigned long)result;
    }
    size_t queued = 0;
    if (entry) {
        struct guest_vsocket_channel *channel =
            guest_vsocket_channel_get(&guest_sockets, entry->channel);
        if (channel)
            queued = channel->data_len[receive ? entry->side : 1 - entry->side];
    }
    if (virtual_property_stream_diagnostics < 64u) {
        virtual_property_stream_diagnostics++;
        printf("VIRTUAL PROPERTY STREAM SYSCALL: host-pid=%d guest-pid=%d executable=%s syscall=%s fd=%d len=%u flags=0x%x address=0x%08x address-length-or-pointer=0x%08x result=%d%s%s queue-after=%zu; app-private connected AF_UNIX stream only, host socket API not called\n",
               pid, state ? state->guest_pid : -1,
               state && state->exec_target[0] ? state->exec_target : "<unknown>",
               receive ? "recvfrom" : "sendto", fd, guest_length,
               (unsigned)flags, (unsigned)address,
               (unsigned)address_length_or_pointer, result,
               result < 0 ? " errno=" : "",
               result < 0 ? guest_diag_errno_name(-result) : "", queued);
    }
    return result;
}

static int guest_host_getrandom_fill(void *context, unsigned char *out,
                                     size_t length) {
    (void)context;
    long result;
    do {
        result = syscall(SYS_getrandom, out, length,
                         GUEST_RANDOM_GRND_NONBLOCK);
    } while (result < 0 && errno == EINTR);
    if (result < 0) return -errno;
    if ((unsigned long)result > (unsigned long)INT32_MAX) return -EOVERFLOW;
    return (int)result;
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
    unsigned access = entry->open_flags & 3u;
    if (receive && access == GUEST_VSOCKET_O_WRONLY) return -EBADF;
    if (!receive && access == GUEST_VSOCKET_O_RDONLY) return -EBADF;
    if (length > (uint32_t)INT32_MAX) return -EINVAL;
    if (length == 0) return 0;

    if (entry->kind == VIRTUAL_FD_DEV_RANDOM) {
        if (!receive || entry->device_minor != 9u) {
            unsupported_guest_device_open_count++;
            if (unsupported_guest_device_open_count <= 32u)
                printf("GUEST RANDOM DEVICE OP UNSUPPORTED: guest-pid=%d executable=%s fd=%d minor=%u requested=%u read=%d result=%d; /dev/random and writes have no faithful guest backend, no host device is opened\n",
                       state->guest_pid, state->exec_target, fd,
                       entry->device_minor, length, receive, -EOPNOTSUPP);
            return -EOPNOTSUPP;
        }
        unsigned char random_bytes[GUEST_URANDOM_MAX_READ_BYTES];
        int random_result = guest_pseudo_device_read_urandom(entry->device_minor,
            random_bytes, length, sizeof(random_bytes),
            guest_host_getrandom_fill, NULL);
        if (random_result > 0 && (buffer_address == 0 ||
            write_remote(pid, buffer_address, random_bytes,
                         (size_t)random_result) != 0)) random_result = -EFAULT;
        virtual_pseudo_device_io_count++;
        if (virtual_pseudo_device_io_count <= 32u)
            printf("GUEST URANDOM READ: guest-pid=%d executable=%s fd=%d rdev=1:9 requested=%u returned=%d; bounded explicit host getrandom(GRND_NONBLOCK) provider, no host /dev access or hardware-identity claim\n",
                   state->guest_pid, state->exec_target, fd, length, random_result);
        return random_result;
    }

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
        if (entry->kind == VIRTUAL_FD_DEV_KMSG)
            guest_kmsg_note_write(&guest_kmsg_runtime, fd, result);
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
    int slot = guest_tracee_slot_allocate(&tracee_slot_pool);
    if (slot < 0 || (unsigned)slot >= MAX_TRACEES) return NULL;
    if ((size_t)slot >= tracee_count) tracee_count = (size_t)slot + 1u;
    struct tracee_state *state = &tracees[slot];
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
    guest_process_compat_init(&state->process_compat);
    guest_identity_init(&state->identity);
    active_tracee_count++;
    return state;
}

static struct tracee_state *find_tracee_guest_pid(pid_t guest_pid) {
    for (size_t i = 0; i < tracee_count; ++i)
        if (tracees[i].alive && !tracees[i].is_thread && tracees[i].guest_pid == guest_pid)
            return &tracees[i];
    return NULL;
}

static struct tracee_state *find_tracee_guest_pid_retained(pid_t guest_pid) {
    for (size_t i = 0; i < tracee_count; ++i)
        if (!tracees[i].is_thread && !tracees[i].guest_reaped &&
            tracees[i].guest_pid == guest_pid) return &tracees[i];
    return NULL;
}

static struct tracee_state *find_tracee_host_pid(pid_t pid) {
    for (size_t i = 0; i < tracee_count; ++i)
        if (!tracees[i].guest_reaped && tracees[i].pid == pid) return &tracees[i];
    return NULL;
}

static size_t count_unreaped_guest_children(pid_t parent_guest_pid) {
    size_t count = 0;
    for (size_t i = 0; i < tracee_count; ++i)
        if (!tracees[i].is_thread && !tracees[i].guest_reaped &&
            tracees[i].guest_parent_pid == parent_guest_pid &&
            tracees[i].guest_pid > 0) count++;
    return count;
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
        if (tracees[i].is_thread && !tracees[i].guest_reaped) {
            tracees[i].guest_reaped = 1;
            guest_thread_ptrace_exits++;
            if (guest_thread_ptrace_exits <= 64u)
                printf("GUEST THREAD TRACE RELEASE: guest-pid=%d guest-tid=%d host-tid=%d; ptrace confirmed terminal exit, thread has no independent guest wait4 status\n",
                       tracees[i].guest_pid, tracees[i].guest_tid,
                       (int)tracees[i].pid);
        }
        int guest_wait_status_pending = !tracees[i].guest_reaped;
        if (guest_tracee_slot_mark_ptrace_exit(&tracee_slot_pool, i,
                                               guest_wait_status_pending) != 0)
            fprintf(stderr, "tracee registry exit-state mismatch for guest-pid=%d slot=%zu\n",
                    tracees[i].guest_pid, i);
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

static void guest_binder_release_context_manager_if_dead(int32_t guest_pid) {
    if (guest_pid <= 0 ||
        guest_binder_state.context_manager_guest_pid != guest_pid) return;
    for (size_t i = 0; i < tracee_count; ++i)
        if (tracees[i].alive && tracees[i].guest_pid == guest_pid) return;
    guest_binder_state.context_manager_guest_pid = 0;
    printf("GUEST BINDER CONTEXT MANAGER RELEASED: guest-pid=%d; all traced guest threads exited, software owner cleared\n",
           guest_pid);
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
        snprintf(state->pending_exec_backing_path,
                 sizeof(state->pending_exec_backing_path), "%s",
                 patched_shell_resolved);
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
        snprintf(state->pending_exec_backing_path,
                 sizeof(state->pending_exec_backing_path), "%s", resolved);
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
    pid_t pids[MAX_TRACEES + PTRACE_PENDING_CHILD_STOP_LIMIT];
    size_t count = 0;
    for (size_t i = 0; i < tracee_count; ++i)
        if (tracees[i].alive) pids[count++] = tracees[i].pid;
    pending_child_stop_queued_for_cleanup += pending_child_stops.count;
    for (size_t i = 0; i < pending_child_stops.count; ++i)
        pids[count++] = pending_child_stops.entries[i].pid;
    struct ptrace_cleanup_result cleanup = ptrace_terminate_and_reap(pids, count);
    printf("TRACE CLEANUP: tracked=%zu reaped=%zu already-gone=%zu unresolved=%zu\n",
           cleanup.requested, cleanup.reaped, cleanup.already_gone, cleanup.unresolved);
    trace_cleanup_confirmed = cleanup.unresolved == 0;
    trace_cleanup_unresolved = cleanup.unresolved;
    tracee_count = 0;
    active_tracee_count = 0;
    memset(&pending_child_stops, 0, sizeof(pending_child_stops));
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
    if (nr == ARM_NR_UNLINK && strcmp(guest, GUEST_NULL_STDIO_PATH) == 0) {
        if (!active_tracee || active_tracee->pid != pid) {
            guest_null_stdio_runtime.unlink_attempts++;
            rc = -EPERM;
        } else {
            struct guest_null_stdio_identity identity =
                guest_null_stdio_identity_for_tracee(active_tracee);
            rc = guest_null_stdio_unlink(&guest_null_stdio_runtime,
                &identity, guest);
            guest_ueventd_null_stdio_note_step(active_tracee,
                GUEST_UEVENTD_STDIO_UNLINK, 0, rc);
        }
        *is_virtual = 1;
        *pending_return = rc;
        virtual_file_ops++;
        if (guest_null_stdio_diagnostics_emitted < 64u) {
            guest_null_stdio_diagnostics_emitted++;
            printf("GUEST NULL DEVICE UNLINK: guest-pid=%d parent-guest-pid=%d executable=%s actor=%s image-verified=%d backing=%s path=%s result=%d node-present=%d opened-fd=%d source-fd-open=%d; app-private software namespace only, no host unlink/device node\n",
                   active_tracee ? active_tracee->guest_pid : -1,
                   active_tracee ? active_tracee->guest_parent_pid : -1,
                   active_tracee && active_tracee->exec_target[0]
                       ? active_tracee->exec_target : "<unknown>",
                   guest_null_stdio_actor_for_tracee(active_tracee) == GUEST_NULL_STDIO_ACTOR_INIT ? "init" :
                       guest_null_stdio_actor_for_tracee(active_tracee) == GUEST_NULL_STDIO_ACTOR_UEVENTD ? "ueventd" : "denied",
                   guest_null_stdio_actor_for_tracee(active_tracee) != GUEST_NULL_STDIO_ACTOR_DENIED,
                   active_tracee && active_tracee->exec_backing_path[0]
                       ? active_tracee->exec_backing_path : "<unverified>",
                   guest, rc, guest_null_stdio_runtime.node_present,
                   guest_null_stdio_runtime.source_fd,
                   guest_null_stdio_runtime.source_fd_open);
        }
        return 0;
    }
    if (nr == ARM_NR_STAT64 || nr == ARM_NR_LSTAT64 || nr == ARM_NR_FSTATAT64) {
        struct guest_pseudo_device_metadata metadata;
        int recognized = guest_pseudo_device_metadata_for_path(guest, &metadata);
        if (recognized < 0) return recognized;
        if (recognized > 0) {
            if (strcmp(guest, GUEST_FB0_PATH) == 0 && !guest_fb0_node_created)
                return -ENOENT;
            if (strcmp(guest, GUEST_NULL_STDIO_PATH) == 0) {
                if (!guest_null_stdio_runtime.node_present ||
                    guest_null_stdio_runtime.unlinked) return -ENOENT;
            } else if (strcmp(guest, GUEST_KMSG_PATH) == 0) {
                if (!guest_kmsg_runtime.node_present ||
                    guest_kmsg_runtime.unlinked) return -ENOENT;
            } else if (metadata.kind == VIRTUAL_FD_DEV_TTY) {
                if (metadata.minor >= GUEST_GOLDFISH_TTY_LINE_COUNT ||
                    (guest_goldfish_tty_runtime.node_mask &
                     (uint8_t)(1u << metadata.minor)) == 0) return -ENOENT;
                rc = guest_pseudo_device_backing_present(guest);
                if (rc != 0) return rc;
            } else {
                rc = guest_pseudo_device_backing_present(guest);
                if (rc != 0) return rc;
            }
            unsigned char stat64[GUEST_ARM32_STAT64_BYTES];
            rc = guest_pseudo_device_stat64_owner(metadata.mode, metadata.uid,
                metadata.gid, metadata.major, metadata.minor, stat64);
            if (rc != 0) return rc;
            uint32_t output = regs->uregs[nr == ARM_NR_FSTATAT64 ? 2 : 1];
            if (output == 0 || write_remote(pid, output, stat64, sizeof(stat64)) != 0)
                return -EFAULT;
            *is_virtual = 1;
            *pending_return = 0;
            virtual_file_ops++;
            const char *stat_source = metadata.kind == VIRTUAL_FD_DEV_TTY
                ? "uevent-created app-private placeholder; synthetic dev_t"
                : strcmp(guest, GUEST_NULL_STDIO_PATH) == 0
                ? "in-memory guest node state"
                : "app-private placeholder verified no-follow";
            printf("GUEST PSEUDO-DEVICE STAT64: guest-pid=%d path=%s mode=0%o rdev=%u:%u source=%s; ARM32 guest metadata, synthetic Goldfish TTY major is not a runtime observation\n",
                   active_tracee ? active_tracee->guest_pid : -1, guest,
                   metadata.mode & 07777u, metadata.major, metadata.minor,
                   stat_source);
            return 0;
        }
    }
    if ((nr == ARM_NR_OPEN || nr == ARM_NR_OPENAT) &&
        strcmp(guest, GUEST_NULL_STDIO_PATH) == 0) {
        if (!active_tracee || active_tracee->pid != pid) {
            guest_null_stdio_runtime.open_attempts++;
            guest_null_stdio_runtime.open_failed++;
            return -EPERM;
        }
        unsigned flags = regs->uregs[nr == ARM_NR_OPEN ? 1u : 2u];
        struct guest_null_stdio_identity identity =
            guest_null_stdio_identity_for_tracee(active_tracee);
        rc = guest_null_stdio_open_validate(&guest_null_stdio_runtime,
            &identity, guest, flags);
        if (rc != 0) {
            if (guest_null_stdio_diagnostics_emitted < 64u) {
                guest_null_stdio_diagnostics_emitted++;
                enum guest_null_stdio_actor actor =
                    guest_null_stdio_actor_for_identity(&identity);
                printf("GUEST NULL DEVICE OPEN: guest-pid=%d parent-guest-pid=%d executable=%s actor=%s image-verified=%d backing=%s path=%s flags=0x%x result=%d; rejected by guest-only null-device policy, no host open/device\n",
                       active_tracee->guest_pid, active_tracee->guest_parent_pid,
                       active_tracee->exec_target, guest_null_stdio_actor_name(actor),
                       actor != GUEST_NULL_STDIO_ACTOR_DENIED,
                       active_tracee->exec_backing_path[0]
                           ? active_tracee->exec_backing_path : "<unverified>",
                       guest, flags, rc);
            }
            return rc;
        }
        int fd = alloc_virtual_fd(VIRTUAL_FD_DEV_NULL);
        rc = guest_null_stdio_open_complete(&guest_null_stdio_runtime, fd);
        if (rc < 0) {
            if (fd >= 0) close_virtual_fd(active_tracee, fd);
            return rc;
        }
        set_virtual_fd_open_flags(active_tracee, fd, flags);
        struct guest_vsocket_fd *entry = guest_vsocket_fd_get(&guest_sockets, fd);
        if (entry) {
            entry->device_mode = GUEST_NULL_STDIO_MODE;
            entry->device_major = 1u;
            entry->device_minor = 3u;
        }
        virtual_pseudo_device_open_count++;
        virtual_device_count++;
        *is_virtual = 1;
        *pending_return = fd;
        guest_ueventd_null_stdio_note_step(active_tracee,
            GUEST_UEVENTD_STDIO_OPEN, fd, fd);
        if (guest_null_stdio_diagnostics_emitted < 64u) {
            guest_null_stdio_diagnostics_emitted++;
            printf("GUEST NULL DEVICE OPEN: guest-pid=%d parent-guest-pid=%d executable=%s actor=%s image-verified=1 backing=%s path=%s flags=0x%x virtual-fd=%d mode=0600 rdev=1:3; app-private guest FD only, no host open/device\n",
                   active_tracee->guest_pid, active_tracee->guest_parent_pid,
                   active_tracee->exec_target,
                   guest_null_stdio_actor_name(guest_null_stdio_actor_for_identity(&identity)),
                   active_tracee->exec_backing_path, guest, flags, fd);
        }
        return 0;
    }
    if ((nr == ARM_NR_OPEN || nr == ARM_NR_OPENAT) &&
        strcmp(guest, GUEST_KMSG_PATH) == 0) {
        if (nr != ARM_NR_OPEN) {
            guest_kmsg_runtime.open_attempts++;
            guest_kmsg_runtime.open_failed++;
            return -EOPNOTSUPP;
        }
        if (!active_tracee || active_tracee->pid != pid) {
            guest_kmsg_runtime.open_attempts++;
            guest_kmsg_runtime.open_failed++;
            return -EPERM;
        }
        unsigned flags = regs->uregs[1];
        rc = guest_kmsg_open_validate(&guest_kmsg_runtime,
            active_tracee->guest_pid, active_tracee->exec_target,
            active_tracee->identity.euid, guest, flags);
        if (rc != 0) return rc;
        int fd = alloc_virtual_fd(VIRTUAL_FD_DEV_KMSG);
        rc = guest_kmsg_open_complete(&guest_kmsg_runtime, fd);
        if (rc < 0) {
            if (fd >= 0) close_virtual_fd(active_tracee, fd);
            return rc;
        }
        set_virtual_fd_open_flags(active_tracee, fd, flags);
        struct guest_vsocket_fd *entry = guest_vsocket_fd_get(&guest_sockets, fd);
        if (!entry) {
            (void)close_virtual_fd(active_tracee, fd);
            guest_kmsg_note_fd_closed(&guest_kmsg_runtime, fd, 0,
                                      virtual_fd_referenced(fd), 0);
            return -EBADF;
        }
        entry->device_mode = GUEST_KMSG_MODE;
        entry->device_major = 1u;
        entry->device_minor = 11u;
        virtual_pseudo_device_open_count++;
        virtual_device_count++;
        *is_virtual = 1;
        *pending_return = fd;
        if (guest_kmsg_diagnostics_emitted < 64u) {
            guest_kmsg_diagnostics_emitted++;
            printf("GUEST KMSG OPEN: guest-pid=%d executable=%s path=%s flags=0x%x virtual-fd=%d mode=0600 rdev=1:11; exact API10 logger FD, no host file/device opened\n",
                   active_tracee->guest_pid, active_tracee->exec_target,
                   guest, flags, fd);
        }
        return 0;
    }
    if ((nr == ARM_NR_OPEN || nr == ARM_NR_OPENAT) &&
        strcmp(guest, "/dev/binder") == 0) {
        unsigned flags_arg = nr == ARM_NR_OPEN ? 1u : 2u;
        unsigned flags = regs->uregs[flags_arg];
        if (!active_tracee || active_tracee->pid != pid) return -EPERM;
        rc = guest_binder_validate_open_flags(flags);
        if (rc != 0) return rc;
        int fd = alloc_virtual_fd(VIRTUAL_FD_DEV_BINDER);
        if (fd < 0) return fd;
        set_virtual_fd_open_flags(active_tracee, fd, flags);
        guest_binder_state.opens++;
        virtual_pseudo_device_open_count++;
        virtual_device_count++;
        *is_virtual = 1;
        *pending_return = fd;
        printf("GUEST BINDER OPEN: guest-pid=%d executable=%s path=/dev/binder flags=0x%x virtual-fd=%d source=API10 ueventd.rc mode=0666 root:root; guest-only software bootstrap endpoint, kernel misc minor unresolved, no host Binder/device opened\n",
               active_tracee->guest_pid, active_tracee->exec_target,
               flags, fd);
        return 0;
    }
    if ((nr == ARM_NR_OPEN || nr == ARM_NR_OPENAT) &&
        strcmp(guest, GUEST_FB0_PATH) == 0) {
        unsigned flags_arg = nr == ARM_NR_OPEN ? 1u : 2u;
        unsigned flags = regs->uregs[flags_arg];
        if (flags & O_DIRECTORY) return -ENOTDIR;
        if (!active_tracee || active_tracee->pid != pid) return -EPERM;
        rc = guest_fb0_open_authorized(guest_fb0_backend_ready,
            guest_fb0_graphics_uevent_received, guest_fb0_node_created,
            &active_tracee->identity, (int)flags);
        if (rc != 0) return rc;
        rc = guest_pseudo_device_backing_present(guest);
        if (rc != 0) return rc;
        rc = rewrite_fb0_path_arg(pid, regs, arg, flags_arg);
        if (rc != 0) return rc;
        guest_fb0_open_count++;
        if (guest_fb0_open_count <= 48u)
            printf("GUEST FB0 OPEN REDIRECT: guest-pid=%d executable=%s path=%s flags=0x%x euid=%u egid=%u fsuid=%u fsgid=%u graphics-member=%d node={major=%u,minor=%u,mode=0%o} backing=%s; no host device opened\n",
                   active_tracee ? active_tracee->guest_pid : -1,
                   active_tracee ? active_tracee->exec_target : "<unknown>",
                   guest, flags, active_tracee ? active_tracee->identity.euid : 0,
                   active_tracee ? active_tracee->identity.egid : 0,
                   active_tracee ? active_tracee->identity.fsuid : 0,
                   active_tracee ? active_tracee->identity.fsgid : 0,
                   active_tracee ? guest_identity_has_group(&active_tracee->identity,
                                                            GUEST_FB0_OWNER_GID) : 0,
                   GUEST_FB0_MAJOR, GUEST_FB0_MINOR, GUEST_FB0_MODE & 07777u,
                   GUEST_FB0_BACKING_FILE);
        return 1;
    }
    if ((nr == ARM_NR_OPEN || nr == ARM_NR_OPENAT) &&
        (strcmp(guest, "/dev") == 0 || strncmp(guest, "/dev/", 5u) == 0)) {
        const char *unsupported = guest_device_unimplemented_reason(guest);
        if (unsupported) {
            unsupported_guest_device_open_count++;
            if (unsupported_guest_device_open_count <= 64u)
                printf("GUEST DEVICE BACKEND DENIED: guest-pid=%d executable=%s syscall=%s path=%s reason=%s result=%d; host /dev, Binder, ashmem, PTY and emulator pipe are never substituted\n",
                       active_tracee ? active_tracee->guest_pid : -1,
                       active_tracee ? active_tracee->exec_target : "<unknown>",
                       guest_diag_syscall_name(nr), guest, unsupported,
                       -EOPNOTSUPP);
            return -EOPNOTSUPP;
        }
    }
    uint32_t tty_minor = 0;
    int tty_sysfs_uevent = guest_goldfish_tty_parse_sysfs_uevent_path(
        guest, &tty_minor);
    if (nr == ARM_NR_OPENAT &&
        (strcmp(guest, GUEST_UEVENT_SYSFS_ATTRIBUTE_PATH) == 0 ||
         strcmp(guest, GUEST_FB0_SYSFS_ATTRIBUTE_PATH) == 0 || tty_sysfs_uevent)) {
        unsigned flags = regs->uregs[2];
        if (!is_guest_ueventd(pid)) return -EPERM;
        if ((flags & 3u) != O_WRONLY || (flags & (O_CREAT | O_TRUNC | O_APPEND)) != 0)
            return -EACCES;
        if (!virtual_uevent_bound || !virtual_uevent_passcred ||
            !virtual_uevent_rcvbuf_configured) return -ENOTCONN;
        int fd = alloc_virtual_fd(VIRTUAL_FD_SYSFS_UEVENT);
        if (fd < 0) return fd;
        struct guest_vsocket_fd *sysfs_fd = guest_vsocket_fd_get(&guest_sockets, fd);
        if (sysfs_fd) {
            if (strcmp(guest, GUEST_FB0_SYSFS_ATTRIBUTE_PATH) == 0)
                sysfs_fd->device_major = GUEST_FB0_MAJOR;
            else if (tty_sysfs_uevent) {
                sysfs_fd->device_major = GUEST_GOLDFISH_TTY_SYNTHETIC_MAJOR;
                sysfs_fd->device_minor = tty_minor;
            }
        }
        *is_virtual = 1;
        *pending_return = fd;
        virtual_file_ops++;
        printf("GUEST SYSFS UEVENT OPEN: guest-pid=%d guest-path=%s device=%s dirfd=%d flags=0x%x virtual-fd=%d; no backing file/device accessed\n",
               active_tracee->guest_pid, guest,
               sysfs_fd && sysfs_fd->device_major == GUEST_FB0_MAJOR ? "graphics-fb0" :
                   sysfs_fd && sysfs_fd->device_major == GUEST_GOLDFISH_TTY_SYNTHETIC_MAJOR
                       ? "goldfish-tty-synthetic" : "net-eth0",
               (int32_t)regs->uregs[0], flags, fd);
        return 0;
    }
    if (nr == ARM_NR_OPEN || nr == ARM_NR_OPENAT) {
        uint32_t tty_minor = 0;
        if (guest_goldfish_tty_parse_device_path(guest, &tty_minor)) {
            unsigned flags = regs->uregs[nr == ARM_NR_OPEN ? 1u : 2u];
            guest_goldfish_tty_runtime.open_attempts++;
            int rc = guest_goldfish_tty_open_validate(
                &guest_goldfish_tty_runtime,
                active_tracee && active_tracee->pid == pid &&
                    tracee_is_verified_api10_qemud(active_tracee) &&
                    active_tracee->identity.euid == 0,
                guest, flags, &tty_minor);
            if (rc == 0) rc = guest_pseudo_device_backing_present(guest);
            int fd = -1;
            if (rc == 0) {
                fd = alloc_virtual_fd(VIRTUAL_FD_DEV_TTY);
                if (fd < 0) rc = fd;
            }
            if (rc == 0) {
                rc = guest_goldfish_tty_note_open(&guest_goldfish_tty_runtime,
                                                   tty_minor, fd);
                if (rc != 0) (void)close_virtual_fd(active_tracee, fd);
            }
            if (rc == 0) {
                set_virtual_fd_open_flags(active_tracee, fd, flags);
                struct guest_vsocket_fd *tty_fd = guest_vsocket_fd_get(
                    &guest_sockets, fd);
                if (tty_fd) {
                    tty_fd->device_mode = GUEST_GOLDFISH_TTY_MODE;
                    tty_fd->device_major = GUEST_GOLDFISH_TTY_SYNTHETIC_MAJOR;
                    tty_fd->device_minor = tty_minor;
                }
                virtual_pseudo_device_open_count++;
                virtual_device_count++;
                *is_virtual = 1;
                *pending_return = fd;
            }
            printf("GUEST GOLDFISH TTY OPEN: guest-pid=%d executable=%s image-verified=%d path=%s flags=0x%x synthetic-dev=%u:%u fd=%d result=%d; qemud-only ttyS1 software endpoint, no host tty or Goldfish runtime dev_t used\n",
                   active_tracee ? active_tracee->guest_pid : -1,
                   active_tracee ? active_tracee->exec_target : "<unknown>",
                   active_tracee ? tracee_is_verified_api10_qemud(active_tracee) : 0,
                   guest, flags, GUEST_GOLDFISH_TTY_SYNTHETIC_MAJOR,
                   tty_minor, fd, rc);
            return rc == 0 ? 0 : rc;
        }
        struct guest_pseudo_device_metadata metadata;
        int recognized = guest_pseudo_device_metadata_for_path(guest, &metadata);
        if (recognized < 0) return recognized;
        if (recognized > 0) {
            unsigned flags = regs->uregs[nr == ARM_NR_OPEN ? 1 : 2];
            if (flags & O_DIRECTORY) return -ENOTDIR;
            rc = guest_pseudo_device_backing_present(guest);
            if (rc != 0) return rc;
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
    if ((nr == ARM_NR_MKNOD || nr == ARM_NR_MKNODAT)) {
        uint32_t tty_minor = 0;
        if (guest_goldfish_tty_parse_device_path(guest, &tty_minor)) {
            unsigned mode_arg = nr == ARM_NR_MKNOD ? 1u : 2u;
            unsigned device_arg = nr == ARM_NR_MKNOD ? 2u : 3u;
            uint32_t requested_mode = regs->uregs[mode_arg];
            uint32_t requested_device = regs->uregs[device_arg];
            int32_t result = -EOPNOTSUPP;
            char backing[PATH_MAX] = "<unmapped>";
            int map_rc = nr == ARM_NR_MKNOD
                ? map_guest_path(guest, backing, sizeof(backing)) : -EOPNOTSUPP;
            if (nr == ARM_NR_MKNOD && map_rc == 0 &&
                active_tracee && active_tracee->pid == pid)
                result = guest_goldfish_tty_create_app_private_placeholder(
                    guest_root, guest, backing, &guest_goldfish_tty_runtime,
                    is_guest_ueventd(pid), requested_mode, requested_device,
                    &tty_minor);
            else if (nr == ARM_NR_MKNOD && map_rc != 0)
                result = map_rc;
            else if (nr == ARM_NR_MKNOD)
                result = -EPERM;
            else
                guest_goldfish_tty_runtime.mknod_attempts++;
            if (result < 0) guest_goldfish_tty_runtime.unsupported++;
            *is_virtual = 1;
            *pending_return = result;
            virtual_device_count++;
            printf("GUEST GOLDFISH TTY MKNOD: guest-pid=%d parent-guest-pid=%d executable=%s actor-verified-ueventd=%d syscall=%s path=%s mode=0%o synthetic-dev=%u:%u result=%d node-mask=0x%02x backing=%s; app-private regular placeholder only, host mknod never called\n",
                   active_tracee ? active_tracee->guest_pid : -1,
                   active_tracee ? active_tracee->guest_parent_pid : -1,
                   active_tracee ? active_tracee->exec_target : "<unknown>",
                   is_guest_ueventd(pid), guest_diag_syscall_name(nr), guest,
                   requested_mode, GUEST_GOLDFISH_TTY_SYNTHETIC_MAJOR,
                   tty_minor, result, guest_goldfish_tty_runtime.node_mask,
                   backing);
            return 0;
        }
    }
    if ((nr == ARM_NR_MKNOD || nr == ARM_NR_MKNODAT) &&
        strcmp(guest, GUEST_KMSG_PATH) == 0) {
        unsigned mode_arg = nr == ARM_NR_MKNOD ? 1u : 2u;
        unsigned device_arg = nr == ARM_NR_MKNOD ? 2u : 3u;
        uint32_t requested_mode = regs->uregs[mode_arg];
        uint32_t requested_device = regs->uregs[device_arg];
        if (nr != ARM_NR_MKNOD) {
            guest_kmsg_runtime.mknod_attempts++;
            guest_kmsg_runtime.mknod_rejected++;
            rc = -EOPNOTSUPP;
        } else if (!active_tracee || active_tracee->pid != pid) {
            guest_kmsg_runtime.mknod_attempts++;
            guest_kmsg_runtime.mknod_rejected++;
            rc = -EPERM;
        } else {
            rc = guest_kmsg_mknod(&guest_kmsg_runtime,
                active_tracee->guest_pid, active_tracee->exec_target,
                active_tracee->identity.euid, guest, requested_mode,
                requested_device);
        }
        *is_virtual = 1;
        *pending_return = rc;
        virtual_device_count++;
        if (guest_kmsg_diagnostics_emitted < 64u) {
            guest_kmsg_diagnostics_emitted++;
            printf("GUEST KMSG MKNOD: guest-pid=%d executable=%s syscall=%s path=%s mode=0%o rdev=%u:%u result=%d node-present=%d; exact PID1 API10 request, in-memory guest node, host mknod never called\n",
                   active_tracee ? active_tracee->guest_pid : -1,
                   active_tracee && active_tracee->exec_target[0]
                       ? active_tracee->exec_target : "<unknown>",
                   guest_diag_syscall_name(nr), guest, requested_mode,
                   (requested_device >> 8) & 0xffu, requested_device & 0xffu,
                   rc, guest_kmsg_runtime.node_present);
        }
        return 0;
    }
    if ((nr == ARM_NR_UNLINK || nr == ARM_NR_UNLINKAT) &&
        strcmp(guest, GUEST_KMSG_PATH) == 0) {
        if (nr != ARM_NR_UNLINK) {
            guest_kmsg_runtime.unlink_attempts++;
            rc = -EOPNOTSUPP;
        } else if (!active_tracee || active_tracee->pid != pid) {
            guest_kmsg_runtime.unlink_attempts++;
            rc = -EPERM;
        } else {
            rc = guest_kmsg_unlink(&guest_kmsg_runtime,
                active_tracee->guest_pid, active_tracee->exec_target,
                active_tracee->identity.euid, guest);
        }
        *is_virtual = 1;
        *pending_return = rc;
        virtual_file_ops++;
        if (guest_kmsg_diagnostics_emitted < 64u) {
            guest_kmsg_diagnostics_emitted++;
            printf("GUEST KMSG UNLINK: guest-pid=%d executable=%s syscall=%s path=%s result=%d node-present=%d open-fd-remains=%d; guest name removed in software only, host unlink never called\n",
                   active_tracee ? active_tracee->guest_pid : -1,
                   active_tracee && active_tracee->exec_target[0]
                       ? active_tracee->exec_target : "<unknown>",
                   guest_diag_syscall_name(nr), guest, rc,
                   guest_kmsg_runtime.node_present,
                   guest_kmsg_runtime.fd_open);
        }
        return 0;
    }
    if ((nr == ARM_NR_MKNOD || nr == ARM_NR_MKNODAT) &&
        strcmp(guest, GUEST_NULL_STDIO_PATH) == 0) {
        unsigned mode_arg = nr == ARM_NR_MKNOD ? 1u : 2u;
        unsigned device_arg = nr == ARM_NR_MKNOD ? 2u : 3u;
        uint32_t requested_mode = regs->uregs[mode_arg];
        uint32_t requested_device = regs->uregs[device_arg];
        if (nr != ARM_NR_MKNOD || !active_tracee || active_tracee->pid != pid) {
            guest_null_stdio_runtime.mknod_attempts++;
            guest_null_stdio_runtime.mknod_rejected++;
            rc = -EPERM;
        } else {
            struct guest_null_stdio_identity identity =
                guest_null_stdio_identity_for_tracee(active_tracee);
            rc = guest_null_stdio_mknod(&guest_null_stdio_runtime,
                &identity, guest, requested_mode, requested_device);
            guest_ueventd_null_stdio_note_step(active_tracee,
                GUEST_UEVENTD_STDIO_MKNOD, 0, rc);
        }
        *is_virtual = 1;
        *pending_return = rc;
        virtual_device_count++;
        if (guest_null_stdio_diagnostics_emitted < 64u) {
            guest_null_stdio_diagnostics_emitted++;
            enum guest_null_stdio_actor actor =
                guest_null_stdio_actor_for_tracee(active_tracee);
            printf("GUEST NULL DEVICE MKNOD: guest-pid=%d parent-guest-pid=%d executable=%s actor=%s image-verified=%d backing=%s syscall=%s path=%s mode=0%o device=0x%08x result=%d node-present=%d; exact API10 PID1/verified-ueventd request only, in-memory guest node, host mknod never called\n",
                   active_tracee ? active_tracee->guest_pid : -1,
                   active_tracee ? active_tracee->guest_parent_pid : -1,
                   active_tracee && active_tracee->exec_target[0]
                       ? active_tracee->exec_target : "<unknown>",
                   guest_null_stdio_actor_name(actor),
                   actor != GUEST_NULL_STDIO_ACTOR_DENIED,
                   active_tracee && active_tracee->exec_backing_path[0]
                       ? active_tracee->exec_backing_path : "<unverified>",
                   guest_diag_syscall_name(nr), guest, requested_mode,
                   requested_device, rc, guest_null_stdio_runtime.node_present);
        }
        return 0;
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
            {
                unsigned mode_arg = nr == ARM_NR_MKNOD ? 1u : 2u;
                unsigned dev_arg = nr == ARM_NR_MKNOD ? 2u : 3u;
                uint32_t requested_mode = regs->uregs[mode_arg];
                uint32_t requested_device = regs->uregs[dev_arg];
                if (!active_tracee) {
                    rc = -EPERM;
                } else {
                    rc = guest_mknod_create_app_private_device(guest_root, guest,
                        active_tracee->identity.euid,
                        active_tracee->identity.fsgid,
                        guest_fb0_graphics_uevent_received,
                        requested_mode, requested_device);
                    if (rc == 0) {
                        guest_fb0_node_created = 1;
                        printf("GUEST FB0 NODE CREATED: guest-pid=%d path=%s mode=0%o major=%u minor=%u fsgid=%u source=consumed Goldfish graphics add event; regular app-private placeholder only, no host mknod\n",
                               active_tracee->guest_pid, guest,
                               GUEST_FB0_MODE & 07777u,
                               GUEST_FB0_MAJOR, GUEST_FB0_MINOR,
                               active_tracee->identity.fsgid);
                    }
                }
            }
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
        int source_is_modeled_null = guest_null_stdio_fd_is_null(
            state->null_stdio_mask, source_fd,
            guest_null_stdio_virtual_fd_valid(state, source_fd));
        if (guest_null_stdio_note_dup2_result(&state->null_stdio_mask,
                target_fd, source_is_modeled_null, result)) {
            set_guest_null_stdio_mask_for_group(state, state->null_stdio_mask);
            guest_null_stdio_alias_replaced_count++;
            if (guest_null_stdio_alias_replaced_count <= 64u)
                printf("GUEST NULL STDIO REPLACED: guest-pid=%d source-fd=%d target-fd=%d result=%d null-source=%d; successful ordinary dup2 cleared the stale software null alias\n",
                       state->guest_pid, source_fd, target_fd, result,
                       source_is_modeled_null);
        }
    }
    (void)regs;
}

static void observe_guest_init_config_io(struct tracee_state *state,
                                         int32_t syscall_result) {
    if (!state || state->guest_pid != 1 || strcmp(state->exec_target, "/init") != 0)
        return;
    struct guest_init_config_read_state *track = &state->init_config_read;
    if ((state->last_syscall == ARM_NR_OPEN ||
         state->last_syscall == ARM_NR_OPENAT) &&
        (strcmp(state->last_guest_path, "/init.rc") == 0 ||
         strcmp(state->last_guest_path, "/init.goldfish.rc") == 0)) {
        if (syscall_result < 0) {
            printf("GUEST INIT CONFIG OPEN: guest-pid=1 path=%s result=%d; API10 parser input was not opened; caller may continue because init_parse_config_file return is ignored\n",
                   state->last_guest_path, syscall_result);
            memset(track, 0, sizeof(*track));
            return;
        }
        memset(track, 0, sizeof(*track));
        track->active = 1;
        track->fd = syscall_result;
        snprintf(track->path, sizeof(track->path), "%s", state->last_guest_path);
        printf("GUEST INIT CONFIG OPEN: guest-pid=1 path=%s fd=%d result=0; original API10 config path resolved into the app-private guest root\n",
               track->path, track->fd);
        return;
    }
    if (!track->active) return;
    if (state->last_syscall == ARM_NR_LSEEK &&
        (int32_t)state->last_syscall_args[0] == track->fd &&
        state->last_syscall_args[1] == 0u &&
        state->last_syscall_args[2] == 2u) { /* lseek(fd, 0, SEEK_END) */
        track->size_known = syscall_result >= 0;
        track->expected_file_size = syscall_result;
        printf("GUEST INIT CONFIG SEEK END: guest-pid=1 path=%s fd=%d result=%d; API10 read_file expected file length captured\n",
               track->path, track->fd, syscall_result);
        return;
    }
    if (state->last_syscall == ARM_NR_LSEEK &&
        (int32_t)state->last_syscall_args[0] == track->fd &&
        state->last_syscall_args[1] == 0u &&
        state->last_syscall_args[2] == 0u) { /* lseek(fd, 0, SEEK_SET) */
        track->start_seek_succeeded = syscall_result == 0;
        printf("GUEST INIT CONFIG SEEK START: guest-pid=1 path=%s fd=%d result=%d; API10 read_file rewind status\n",
               track->path, track->fd, syscall_result);
        return;
    }
    if (state->last_syscall == ARM_NR_READ &&
        (int32_t)state->last_syscall_args[0] == track->fd) {
        track->read_calls++;
        track->requested_bytes = state->last_syscall_args[2];
        track->last_read_result = syscall_result;
        if (syscall_result > 0) track->bytes_read += (uint32_t)syscall_result;
        printf("GUEST INIT CONFIG READ: guest-pid=1 path=%s fd=%d call=%u requested=%u result=%d total-bytes=%llu; API10 read_file input bytes only, parser/action execution is not inferred from this syscall\n",
               track->path, track->fd, track->read_calls,
               track->requested_bytes, syscall_result,
               (unsigned long long)track->bytes_read);
        return;
    }
    if (state->last_syscall == ARM_NR_CLOSE &&
        (int32_t)state->last_syscall_args[0] == track->fd) {
        int full_read = track->size_known && track->start_seek_succeeded &&
            track->expected_file_size >= 0 &&
            track->read_calls == 1u &&
            (uint32_t)track->expected_file_size == track->requested_bytes &&
            track->last_read_result >= 0 &&
            track->last_read_result == track->expected_file_size &&
            track->bytes_read == (uint32_t)track->expected_file_size;
        int file_input_complete = full_read && syscall_result == 0;
        printf("GUEST INIT CONFIG FILE CLOSE: guest-pid=1 path=%s fd=%d expected-size=%d size-known=%d start-seek-ok=%d read-calls=%u requested=%u read-result=%d total-bytes=%llu close-result=%d file-size-read-close-complete=%d; source models read_file input only, not parsed actions or Android framework boot\n",
               track->path, track->fd, track->expected_file_size,
               track->size_known, track->start_seek_succeeded,
               track->read_calls,
               track->requested_bytes, track->last_read_result,
               (unsigned long long)track->bytes_read, syscall_result,
               file_input_complete);
        memset(track, 0, sizeof(*track));
    }
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
            uint32_t guest_status = 0;
            int status_valid = regs->uregs[1] != 0u &&
                read_remote(pid, regs->uregs[1], &guest_status, sizeof(guest_status)) == 0;
            int terminal_status = status_valid && guest_wait_status_is_terminal(guest_status);
            int confirmed_dead = !child->alive;
            if (confirmed_dead || terminal_status) {
                child->guest_reaped = 1;
                size_t slot = (size_t)(child - tracees);
                if (confirmed_dead && guest_tracee_slot_mark_reaped(&tracee_slot_pool, slot) != 0)
                    fprintf(stderr, "tracee registry guest-reap-state mismatch for guest-pid=%d slot=%zu\n",
                            child->guest_pid, slot);
                guest_wait4_reap_diagnostics++;
                if (guest_wait4_reap_diagnostics <= 128u)
                    printf("GUEST WAIT4 REAP: parent=%d child=%d host-child=%d slot=%zu status=0x%08x status-valid=%d terminal=%d ptrace-dead=%d; guest status reaped, slot-reusable=%d\n",
                           state->guest_pid, child->guest_pid, (int)result, slot,
                           guest_status, status_valid, terminal_status, confirmed_dead,
                           confirmed_dead);
            } else {
                guest_wait4_reap_diagnostics++;
                if (guest_wait4_reap_diagnostics <= 128u)
                    printf("GUEST WAIT4 NONTERMINAL: parent=%d child=%d host-child=%d status=0x%08x status-valid=%d child-still-traced=1; guest pid translated but registry slot retained\n",
                           state->guest_pid, child->guest_pid, (int)result,
                           guest_status, status_valid);
            }
        }
        return set_regs(pid, regs) == 0 ? 0 : -EFAULT;
    }
    return 0;
}

static void sync_guest_identity_scalars(struct tracee_state *state) {
    if (!state) return;
    state->guest_ruid = state->identity.ruid;
    state->guest_euid = state->identity.euid;
    state->guest_rgid = state->identity.rgid;
    state->guest_egid = state->identity.egid;
}

static int guest_identity_getgroups_remote(pid_t pid, struct tracee_state *state,
                                           int size, uint32_t address, int legacy) {
    if (size < 0) return -EINVAL;
    int count = guest_identity_getgroups_count(&state->identity, (uint32_t)size);
    if (count < 0) return count;
    if (size == 0 || count == 0) return count;
    if (address == 0) return -EFAULT;
    if (legacy) {
        uint16_t groups[GUEST_ID_MAX_SUPPLEMENTARY_GROUPS];
        for (int i = 0; i < count; ++i) groups[i] = (uint16_t)state->identity.groups[i];
        return write_remote(pid, address, groups, (size_t)count * sizeof(groups[0])) == 0
            ? count : -EFAULT;
    }
    return write_remote(pid, address, state->identity.groups,
                        (size_t)count * sizeof(state->identity.groups[0])) == 0
        ? count : -EFAULT;
}

static int guest_identity_setgroups_remote(pid_t pid, struct tracee_state *state,
                                           int count, uint32_t address, int legacy) {
    if (count < 0 || (unsigned)count > GUEST_ID_MAX_SUPPLEMENTARY_GROUPS)
        return -EINVAL;
    if (count && address == 0) return -EFAULT;
    uint32_t groups[GUEST_ID_MAX_SUPPLEMENTARY_GROUPS] = {0};
    if (count && legacy) {
        uint16_t old_groups[GUEST_ID_MAX_SUPPLEMENTARY_GROUPS];
        if (read_remote(pid, address, old_groups, (size_t)count * sizeof(old_groups[0])) != 0)
            return -EFAULT;
        for (int i = 0; i < count; ++i) groups[i] = old_groups[i];
    } else if (count && read_remote(pid, address, groups,
                                    (size_t)count * sizeof(groups[0])) != 0) {
        return -EFAULT;
    }
    return guest_identity_setgroups(&state->identity, state->identity.euid,
                                    groups, (uint32_t)count);
}

static int guest_identity_getres_remote(pid_t pid, const struct guest_identity_state *identity,
                                        uint32_t ruid_address, uint32_t euid_address,
                                        uint32_t suid_address, int group, int legacy) {
    uint32_t values[3] = {
        group ? identity->rgid : identity->ruid,
        group ? identity->egid : identity->euid,
        group ? identity->sgid : identity->suid,
    };
    uint32_t addresses[3] = {ruid_address, euid_address, suid_address};
    for (size_t i = 0; i < 3; ++i) {
        if (!addresses[i]) continue;
        if (legacy) {
            uint16_t value = (uint16_t)values[i];
            if (write_remote(pid, addresses[i], &value, sizeof(value)) != 0) return -EFAULT;
        } else if (write_remote(pid, addresses[i], &values[i], sizeof(values[i])) != 0) {
            return -EFAULT;
        }
    }
    return 0;
}

static int guest_identity_setres_from_regs(struct tracee_state *state,
                                           const struct compat_pt_regs *regs,
                                           int group, int legacy) {
    uint32_t values[3] = {regs->uregs[0], regs->uregs[1], regs->uregs[2]};
    if (legacy) {
        for (size_t i = 0; i < 3; ++i)
            values[i] = values[i] == UINT32_MAX ? GUEST_ID_INVALID : values[i] & 0xffffu;
    } else {
        for (size_t i = 0; i < 3; ++i)
            if (values[i] == UINT32_MAX) values[i] = GUEST_ID_INVALID;
    }
    return group ? guest_identity_setresgid(&state->identity, values[0], values[1], values[2])
                 : guest_identity_setresuid(&state->identity, values[0], values[1], values[2]);
}

static int mediate_guest_identity_syscall(pid_t pid, struct tracee_state *state,
                                          const struct compat_pt_regs *regs, int nr,
                                          int32_t *result) {
    int legacy = 0;
    int handled = 1;
    switch (nr) {
        case ARM_NR_GETUID: case ARM_NR_GETGID: case ARM_NR_GETEUID: case ARM_NR_GETEGID:
        case ARM_NR_SETUID: case ARM_NR_SETGID: case ARM_NR_SETREUID: case ARM_NR_SETREGID:
        case ARM_NR_GETGROUPS: case ARM_NR_SETGROUPS: case ARM_NR_SETRESUID:
        case ARM_NR_GETRESUID: case ARM_NR_SETRESGID: case ARM_NR_GETRESGID:
        case ARM_NR_SETFSUID: case ARM_NR_SETFSGID:
            legacy = 1;
            break;
        case ARM_NR_GETUID32: case ARM_NR_GETGID32: case ARM_NR_GETEUID32: case ARM_NR_GETEGID32:
        case ARM_NR_SETREUID32: case ARM_NR_SETREGID32: case ARM_NR_GETGROUPS32:
        case ARM_NR_SETGROUPS32: case ARM_NR_SETRESUID32:
        case ARM_NR_GETRESUID32: case ARM_NR_SETRESGID32: case ARM_NR_GETRESGID32:
        case ARM_NR_SETUID32: case ARM_NR_SETGID32: case ARM_NR_SETFSUID32: case ARM_NR_SETFSGID32:
            break;
        default:
            handled = 0;
            break;
    }
    if (!handled) return 1;
    const uint32_t invalid = GUEST_ID_INVALID;
    switch (nr) {
        case ARM_NR_GETUID: case ARM_NR_GETUID32: *result = (int32_t)state->identity.ruid; break;
        case ARM_NR_GETGID: case ARM_NR_GETGID32: *result = (int32_t)state->identity.rgid; break;
        case ARM_NR_GETEUID: case ARM_NR_GETEUID32: *result = (int32_t)state->identity.euid; break;
        case ARM_NR_GETEGID: case ARM_NR_GETEGID32: *result = (int32_t)state->identity.egid; break;
        case ARM_NR_SETUID:
            *result = guest_identity_setuid(&state->identity, regs->uregs[0] & 0xffffu); break;
        case ARM_NR_SETUID32:
            *result = guest_identity_setuid(&state->identity, regs->uregs[0]); break;
        case ARM_NR_SETGID:
            *result = guest_identity_setgid(&state->identity, regs->uregs[0] & 0xffffu); break;
        case ARM_NR_SETGID32:
            *result = guest_identity_setgid(&state->identity, regs->uregs[0]); break;
        case ARM_NR_SETREUID: case ARM_NR_SETREUID32:
            *result = guest_identity_setreuid(&state->identity,
                regs->uregs[0] == UINT32_MAX ? invalid : legacy ? regs->uregs[0] & 0xffffu : regs->uregs[0],
                regs->uregs[1] == UINT32_MAX ? invalid : legacy ? regs->uregs[1] & 0xffffu : regs->uregs[1]);
            break;
        case ARM_NR_SETREGID: case ARM_NR_SETREGID32:
            *result = guest_identity_setregid(&state->identity,
                regs->uregs[0] == UINT32_MAX ? invalid : legacy ? regs->uregs[0] & 0xffffu : regs->uregs[0],
                regs->uregs[1] == UINT32_MAX ? invalid : legacy ? regs->uregs[1] & 0xffffu : regs->uregs[1]);
            break;
        case ARM_NR_SETRESUID: case ARM_NR_SETRESUID32:
            *result = guest_identity_setres_from_regs(state, regs, 0, legacy); break;
        case ARM_NR_SETRESGID: case ARM_NR_SETRESGID32:
            *result = guest_identity_setres_from_regs(state, regs, 1, legacy); break;
        case ARM_NR_GETRESUID: case ARM_NR_GETRESUID32:
            *result = guest_identity_getres_remote(pid, &state->identity,
                regs->uregs[0], regs->uregs[1], regs->uregs[2], 0, legacy); break;
        case ARM_NR_GETRESGID: case ARM_NR_GETRESGID32:
            *result = guest_identity_getres_remote(pid, &state->identity,
                regs->uregs[0], regs->uregs[1], regs->uregs[2], 1, legacy); break;
        case ARM_NR_GETGROUPS: case ARM_NR_GETGROUPS32:
            *result = guest_identity_getgroups_remote(pid, state,
                (int32_t)regs->uregs[0], regs->uregs[1], legacy); break;
        case ARM_NR_SETGROUPS: case ARM_NR_SETGROUPS32:
            *result = guest_identity_setgroups_remote(pid, state,
                (int32_t)regs->uregs[0], regs->uregs[1], legacy); break;
        case ARM_NR_SETFSUID: case ARM_NR_SETFSUID32:
            *result = guest_identity_setfsuid(&state->identity,
                legacy ? regs->uregs[0] & 0xffffu : regs->uregs[0]); break;
        case ARM_NR_SETFSGID: case ARM_NR_SETFSGID32:
            *result = guest_identity_setfsgid(&state->identity,
                legacy ? regs->uregs[0] & 0xffffu : regs->uregs[0]); break;
        default: *result = -ENOSYS; return 0;
    }
    sync_guest_identity_scalars(state);
    return 0;
}

static int mediate_guest_binder_ioctl(pid_t pid, struct tracee_state *state,
                                      struct compat_pt_regs *regs,
                                      int *park_read, int32_t *result) {
    *park_read = 0;
    int fd = (int32_t)regs->uregs[0];
    if (!is_virtual_fd_number(fd)) return 1;
    struct guest_vsocket_fd *entry = guest_vsocket_fd_get(&guest_sockets, fd);
    if (!entry || entry->kind != VIRTUAL_FD_DEV_BINDER) return 1;
    if (!state || !tracee_owns_virtual_fd(state, fd)) {
        *result = -EBADF;
        return 0;
    }
    struct guest_binder_trace_memory memory = { .pid = pid };
    int rc = guest_binder_ioctl_bootstrap(&state->binder, &guest_binder_state,
        state->guest_pid, regs->uregs[1], regs->uregs[2],
        guest_binder_trace_copyin, guest_binder_trace_copyout, &memory,
        park_read);
    *result = rc;
    if (rc < 0) {
        if (state->binder.ioctl_count <= 64u)
            printf("GUEST BINDER IOCTL DENIED: guest-pid=%d executable=%s fd=%d cmd=0x%08x argument=0x%08x result=%d errno=%s transactions-supported=0; no host ioctl called\n",
                   state->guest_pid, state->exec_target, fd,
                   regs->uregs[1], regs->uregs[2], rc,
                   guest_diag_errno_name(-rc));
        return 0;
    }
    if (*park_read) {
        state->binder_waiting = 1;
        guest_arm32_binder_write_read request = {0};
        (void)guest_binder_trace_copyin(&memory, regs->uregs[2],
            &request, sizeof(request));
        printf("GUEST BINDER BLOCKED READ: guest-pid=%d executable=%s fd=%d mapped-bytes=%u loop-entered=%d read-buffer=0x%08x read-size=%u; no guest transaction queue exists, remains parked until bounded timeout/cancel; no host Binder or busy-loop\n",
               state->guest_pid, state->exec_target, fd,
               state->binder.mapping_length, state->binder.loop_entered,
               request.read_buffer, (unsigned)(request.read_size < 0 ? 0 : request.read_size));
    } else if (regs->uregs[1] == GUEST_BINDER_IOCTL_VERSION) {
        printf("GUEST BINDER VERSION: guest-pid=%d protocol=%d result=0 source=Goldfish-2.6.29-API10-UAPI\n",
               state->guest_pid, GUEST_BINDER_PROTOCOL_VERSION);
    } else if (regs->uregs[1] == GUEST_BINDER_IOCTL_SET_CONTEXT_MGR) {
        printf("GUEST BINDER CONTEXT MANAGER: guest-pid=%d ioctl-argument=0 result=0 guest-only-owner=%d; scalar-zero API10 call, no host Binder context manager registered\n",
               state->guest_pid, guest_binder_state.context_manager_guest_pid);
    } else if (regs->uregs[1] == GUEST_BINDER_IOCTL_WRITE_READ) {
        printf("GUEST BINDER WRITE_READ: guest-pid=%d fd=%d loop-entered=%d commands-consumed=%lu blocked-reads=%lu transactions-supported=0\n",
               state->guest_pid, fd, state->binder.loop_entered,
               state->binder.loop_commands, state->binder.empty_reads_parked);
    }
    return 0;
}

static int mediate_guest_binder_mmap(struct tracee_state *state,
                                     struct compat_pt_regs *regs) {
    int fd = (int32_t)regs->uregs[4];
    if (!is_virtual_fd_number(fd)) return 1;
    struct guest_vsocket_fd *entry = guest_vsocket_fd_get(&guest_sockets, fd);
    if (!entry || entry->kind != VIRTUAL_FD_DEV_BINDER) return 1;
    if (!state || !tracee_owns_virtual_fd(state, fd)) return -EBADF;
    uint32_t length = regs->uregs[1];
    uint32_t prot = regs->uregs[2];
    uint32_t flags = regs->uregs[3];
    uint32_t offset_pages = regs->uregs[5];
    int rc = guest_binder_validate_mmap(length, prot, flags, fd,
                                        offset_pages, 1);
    if (rc == 0 && state->binder.mapping_valid) rc = -EBUSY;
    if (rc == 0 && regs->uregs[0] != 0) rc = -EINVAL;
    if (rc != 0) {
        printf("GUEST BINDER MMAP DENIED: guest-pid=%d fd=%d address-hint=0x%08x length=%u prot=0x%x flags=0x%x offset-pages=%u result=%d errno=%s; only API10 read-only receive sizes are supported\n",
               state->guest_pid, fd, regs->uregs[0], length, prot, flags,
               offset_pages, rc, guest_diag_errno_name(-rc));
        return rc;
    }
    state->binder_mmap_pending = 1;
    state->binder_pending_map_length = length;
    regs->uregs[0] = 0;
    regs->uregs[2] = (uint32_t)PROT_READ;
    regs->uregs[3] = flags | (uint32_t)MAP_ANONYMOUS;
    regs->uregs[4] = UINT32_MAX;
    regs->uregs[5] = 0;
    printf("GUEST BINDER MMAP ROUTE: guest-pid=%d fd=%d bytes=%u prot=READ guest-flags=0x%x; forwarded only as anonymous app-process memory, not host Binder mapping\n",
           state->guest_pid, fd, length, flags);
    return 0;
}

static int dispatch_entry(pid_t pid, struct tracee_state *state,
                          struct compat_pt_regs *regs, int nr,
                          int32_t *pending_return, int *fake) {
    *fake = 0;
    int32_t identity_result = 0;
    int identity_handled = mediate_guest_identity_syscall(
        pid, state, regs, nr, &identity_result);
    if (identity_handled == 0) {
        *pending_return = identity_result;
        *fake = 1;
        virtual_identity_count++;
        if (virtual_identity_count <= 96u)
            printf("GUEST IDENTITY SYSCALL: guest-pid=%d executable=%s syscall=%d uid=%u:%u:%u gid=%u:%u:%u supplementary-groups=%u result=%d; tracee-only identity, host credentials unchanged\n",
                   state->guest_pid, state->exec_target, nr,
                   state->identity.ruid, state->identity.euid, state->identity.suid,
                   state->identity.rgid, state->identity.egid, state->identity.sgid,
                   state->identity.group_count, identity_result);
        return 0;
    }
    int binder_candidate_fd = -1;
    switch (nr) {
        case ARM_NR_READ: case ARM_NR_WRITE: case ARM_NR_LSEEK:
        case ARM_NR_FSTAT: case ARM_NR_FSTAT64: case ARM_NR_FCHMOD:
        case ARM_NR_FCHOWN: case ARM_NR_FCHOWN32: case ARM_NR_FTRUNCATE:
        case ARM_NR_FTRUNCATE64: case ARM_NR_FSYNC: case ARM_NR_FDATASYNC:
        case ARM_NR_PREAD64: case ARM_NR_PWRITE64: case ARM_NR_DUP:
            binder_candidate_fd = (int32_t)regs->uregs[0];
            break;
        case ARM_NR_DUP2: {
            int source_fd = (int32_t)regs->uregs[0];
            int target_fd = (int32_t)regs->uregs[1];
            struct guest_vsocket_fd *source = guest_vsocket_fd_get(
                &guest_sockets, source_fd);
            struct guest_vsocket_fd *target = guest_vsocket_fd_get(
                &guest_sockets, target_fd);
            if ((source && source->kind == VIRTUAL_FD_DEV_BINDER) ||
                (target && target->kind == VIRTUAL_FD_DEV_BINDER))
                binder_candidate_fd = source &&
                    source->kind == VIRTUAL_FD_DEV_BINDER ? source_fd : target_fd;
            break;
        }
        default:
            break;
    }
    if (is_virtual_fd_number(binder_candidate_fd)) {
        struct guest_vsocket_fd *binder_entry = guest_vsocket_fd_get(
            &guest_sockets, binder_candidate_fd);
        if (binder_entry && binder_entry->kind == VIRTUAL_FD_DEV_BINDER) {
            *pending_return = tracee_owns_virtual_fd(state, binder_candidate_fd)
                ? (nr == ARM_NR_LSEEK ? -ESPIPE :
                   (nr == ARM_NR_FTRUNCATE || nr == ARM_NR_FTRUNCATE64)
                       ? -EINVAL : -EOPNOTSUPP)
                : -EBADF;
            *fake = 1;
            virtual_device_count++;
            printf("GUEST BINDER FD OP DENIED: guest-pid=%d executable=%s syscall=%s fd=%d result=%d; only explicit Binder version/map/context/looper ioctl subset is modeled; no host fd operation\n",
                   state->guest_pid, state->exec_target,
                   guest_diag_syscall_name(nr), binder_candidate_fd,
                   *pending_return);
            return 0;
        }
    }
    if (nr == ARM_NR_IOCTL) {
        int binder_park_read = 0;
        int32_t binder_result = 0;
        int binder_rc = mediate_guest_binder_ioctl(pid, state, regs,
            &binder_park_read, &binder_result);
        if (binder_rc != 1) {
            *pending_return = binder_result;
            *fake = binder_park_read ? 2 : 1;
            if (!binder_park_read) virtual_device_count++;
            return 0;
        }
        int32_t ioctl_result = 0;
        int fb_result = mediate_guest_fb0_ioctl(pid, state, regs, &ioctl_result);
        if (fb_result != 1) {
            *pending_return = fb_result == 0 ? ioctl_result : fb_result;
            *fake = 1;
            virtual_device_count++;
            return 0;
        }
        int tty_fd_number = (int32_t)regs->uregs[0];
        struct guest_vsocket_fd *tty_fd = guest_vsocket_fd_get(
            &guest_sockets, tty_fd_number);
        if (tty_fd && tty_fd->kind == VIRTUAL_FD_DEV_TTY) {
            uint32_t request = regs->uregs[1];
            uint32_t guest_buffer = regs->uregs[2];
            struct guest_arm32_termios termios;
            int verified_qemud = state && state->pid == pid &&
                tracee_is_verified_api10_qemud(state) &&
                state->identity.euid == 0;
            int tty_result = 0;
            if (!state || !tracee_owns_virtual_fd(state, tty_fd_number)) {
                tty_result = -EBADF;
            } else if (!verified_qemud) {
                tty_result = -EPERM;
            } else if (request == GUEST_GOLDFISH_TTY_TCGETS) {
                if (guest_buffer == 0) {
                    tty_result = -EFAULT;
                } else {
                    tty_result = guest_goldfish_tty_ioctl(
                        &guest_goldfish_tty_runtime, verified_qemud,
                        tty_fd_number, request, &termios, sizeof(termios));
                    if (tty_result == 0 && write_remote(pid, guest_buffer,
                            &termios, sizeof(termios)) != 0) tty_result = -EFAULT;
                }
            } else if (request == GUEST_GOLDFISH_TTY_TCSETS) {
                if (guest_buffer == 0 || read_remote(pid, guest_buffer,
                        &termios, sizeof(termios)) != 0) {
                    tty_result = -EFAULT;
                } else {
                    tty_result = guest_goldfish_tty_ioctl(
                        &guest_goldfish_tty_runtime, verified_qemud,
                        tty_fd_number, request, &termios, sizeof(termios));
                }
            } else {
                tty_result = -ENOTTY;
            }
            if (tty_result < 0) guest_goldfish_tty_runtime.unsupported++;
            *pending_return = tty_result;
            *fake = 1;
            virtual_device_count++;
            if (guest_goldfish_tty_diagnostics_emitted < 64u) {
                guest_goldfish_tty_diagnostics_emitted++;
                printf("GUEST GOLDFISH TTY IOCTL: guest-pid=%d executable=%s fd=%d request=0x%x guest-buffer=0x%08x verified-root-qemud=%d result=%d termios-bytes=%u; API10 ARM32 software termios only, host ioctl never called\n",
                       state ? state->guest_pid : -1,
                       state ? state->exec_target : "<unknown>",
                       tty_fd_number, request, guest_buffer, verified_qemud,
                       tty_result, GUEST_GOLDFISH_TTY_TERMios_BYTES);
            }
            return 0;
        }
    }
    if (nr == ARM_NR_MMAP2) {
        int binder_map_result = mediate_guest_binder_mmap(state, regs);
        if (binder_map_result != 1) {
            if (binder_map_result < 0) {
                *pending_return = binder_map_result;
                *fake = 1;
                virtual_device_count++;
            }
            return 0;
        }
        int fb_result = mediate_guest_fb0_mmap(pid, state, regs);
        if (fb_result != 1) {
            if (fb_result < 0) {
                *pending_return = fb_result;
                *fake = 1;
                printf("GUEST FB0 MMAP DENIED: guest-pid=%d fd=%d length=%u prot=0x%x flags=0x%x offset-pages=%u result=%d; unsupported framebuffer mappings fail closed\n",
                       state->guest_pid, (int32_t)regs->uregs[4],
                       regs->uregs[1], regs->uregs[2], regs->uregs[3],
                       regs->uregs[5], fb_result);
            } else {
                guest_fb0_mmap_count++;
            }
            return 0;
        }
    }
    if (state->binder.mapping_valid && nr == ARM_NR_MPROTECT) {
        uint32_t address = regs->uregs[0], length = regs->uregs[1];
        uint64_t request_end = (uint64_t)address + length;
        uint64_t mapping_end = (uint64_t)state->binder.mapping_start +
            state->binder.mapping_length;
        if (length != 0 && (uint64_t)address < mapping_end &&
            (uint64_t)state->binder.mapping_start < request_end &&
            (regs->uregs[2] & (uint32_t)PROT_WRITE) != 0) {
            *pending_return = -EACCES;
            *fake = 1;
            printf("GUEST BINDER MPROTECT DENIED: guest-pid=%d range=0x%08x+%u prot=0x%x; Binder receive mapping remains read-only\n",
                   state->guest_pid, address, length, regs->uregs[2]);
            return 0;
        }
    }
    if (state->binder.mapping_valid && nr == ARM_NR_MREMAP) {
        uint32_t address = regs->uregs[0], length = regs->uregs[1];
        uint64_t request_end = (uint64_t)address + length;
        uint64_t mapping_end = (uint64_t)state->binder.mapping_start +
            state->binder.mapping_length;
        if (length != 0 && (uint64_t)address < mapping_end &&
            (uint64_t)state->binder.mapping_start < request_end) {
            *pending_return = -EOPNOTSUPP;
            *fake = 1;
            printf("GUEST BINDER MREMAP DENIED: guest-pid=%d range=0x%08x+%u; receive-map relocation is unsupported\n",
                   state->guest_pid, address, length);
            return 0;
        }
    }
    if (state->binder.mapping_valid && nr == ARM_NR_MUNMAP) {
        uint32_t address = regs->uregs[0], length = regs->uregs[1];
        uint64_t request_end = (uint64_t)address + length;
        uint64_t mapping_end = (uint64_t)state->binder.mapping_start +
            state->binder.mapping_length;
        if (length != 0 && (uint64_t)address < mapping_end &&
            (uint64_t)state->binder.mapping_start < request_end) {
            if (address != state->binder.mapping_start ||
                length != state->binder.mapping_length) {
                *pending_return = -EINVAL;
                *fake = 1;
                printf("GUEST BINDER MUNMAP DENIED: guest-pid=%d range=0x%08x+%u expected-exact=0x%08x+%u\n",
                       state->guest_pid, address, length,
                       state->binder.mapping_start, state->binder.mapping_length);
                return 0;
            }
            state->binder_munmap_pending = 1;
        }
    }
    if (nr == ARM_NR_MUNMAP && state->fb_mapping_valid &&
        regs->uregs[0] == state->fb_mapping_start &&
        regs->uregs[1] >= state->fb_mapping_length) {
        state->fb_munmap_pending = 1;
    }
    if (nr == ARM_NR_FSTAT64 &&
        guest_fb0_fd_matches(pid, (int32_t)regs->uregs[0])) {
        struct guest_pseudo_device_metadata metadata = {0};
        unsigned char stat64[GUEST_ARM32_STAT64_BYTES];
        int recognized = guest_pseudo_device_metadata_for_path(GUEST_FB0_PATH, &metadata);
        int rc = recognized == 1 ? guest_pseudo_device_stat64_owner(
            metadata.mode, metadata.uid, metadata.gid, metadata.major,
            metadata.minor, stat64) : -ENODEV;
        if (rc == 0 && (regs->uregs[1] == 0 ||
            write_remote(pid, regs->uregs[1], stat64, sizeof(stat64)) != 0))
            rc = -EFAULT;
        *pending_return = rc;
        *fake = 1;
        printf("GUEST FB0 FSTAT64: guest-pid=%d fd=%d mode=0%o uid=%u gid=%u rdev=%u:%u result=%d; descriptor reported as guest char node, backing inode hidden\n",
               state->guest_pid, (int32_t)regs->uregs[0],
               metadata.mode & 07777u, metadata.uid, metadata.gid,
               metadata.major, metadata.minor, rc);
        return 0;
    }
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
        guest_wait4_calls++;
        int32_t requested = (int32_t)regs->uregs[0];
        int rc = mediate_guest_wait4(pid, regs);
        if (rc != 0) {
            *pending_return = rc;
            *fake = 1;
        }
        if (guest_wait4_calls <= 64u)
            printf("GUEST WAIT4 ABI: guest-pid=%d executable=%s requested=%d host-request=%d options=0x%x route=%s; this is the API10 ARM waitpid wrapper's wait4 syscall; only registered guest children are visible\n",
                   state->guest_pid, state->exec_target, requested,
                   (int32_t)regs->uregs[0], state->last_syscall_args[2],
                   rc == 0 ? "supervised-child-wait" : "guest-error");
        return 0;
    }
    if (nr == ARM_NR_SETRLIMIT) {
        struct guest_arm32_rlimit requested = {0u, 0u};
        uint32_t resource = regs->uregs[0];
        uint32_t address = regs->uregs[1];
        if (address == 0u) *pending_return = -EFAULT;
        else if (read_remote(pid, address, &requested, sizeof(requested)) != 0)
            *pending_return = -EFAULT;
        else *pending_return = guest_process_setrlimit(&state->process_compat,
            resource, requested, state->guest_euid);
        guest_setrlimit_calls++;
        printf("GUEST SETRLIMIT: guest-pid=%d executable=%s resource=%u current=%u maximum=%u guest-euid=%u result=%d; per-tracee RLIMIT_NICE state only, host limit unchanged\n",
               state->guest_pid, state->exec_target, resource,
               requested.current, requested.maximum, state->guest_euid,
               *pending_return);
        *fake = 1;
        return 0;
    }
    if (nr == ARM_NR_IOPRIO_SET) {
        uint32_t which = regs->uregs[0];
        int32_t who = (int32_t)regs->uregs[1];
        uint32_t priority = regs->uregs[2];
        struct tracee_state *target = who == 0 ? state :
            (who > 0 ? find_tracee_guest_pid_retained((pid_t)who) : NULL);
        *pending_return = guest_process_ioprio_set(
            target ? &target->process_compat : NULL, state->guest_euid,
            target ? target->guest_ruid : 0u, target ? target->guest_euid : 0u,
            which, who, target != NULL, priority);
        guest_ioprio_set_calls++;
        printf("GUEST IOPRIO_SET: guest-pid=%d executable=%s which=%u who=%d priority=0x%x target-guest-pid=%d guest-euid=%u result=%d; guest state only, host scheduler untouched\n",
               state->guest_pid, state->exec_target, which, who, priority,
               target ? target->guest_pid : 0, state->guest_euid,
               *pending_return);
        *fake = 1;
        return 0;
    }
    if (nr == ARM_NR_GETPGID) {
        int32_t requested = (int32_t)regs->uregs[0];
        struct tracee_state *target = requested == 0 ? state :
            (requested > 0 ? find_tracee_guest_pid_retained((pid_t)requested) : NULL);
        *pending_return = guest_process_group_get(requested,
            (uint32_t)state->guest_pid, state->guest_pgid,
            target ? target->guest_pgid : 0u, target != NULL);
        guest_getpgid_calls++;
        printf("GUEST GETPGID: guest-pid=%d request-pid=%d target=%d result=%d; guest process table only, host getpgid not called\n",
               state->guest_pid, requested, target ? target->guest_pid : 0,
               *pending_return);
        *fake = 1;
        return 0;
    }
    if (nr == ARM_NR_KILL) {
        *pending_return = mediate_guest_kill(regs); *fake = 1; return 0;
    }
    if (nr == ARM_NR_EPOLL_CREATE) {
        int32_t size = (int32_t)regs->uregs[0];
        int verified_qemud = state && state->pid == pid &&
            tracee_is_verified_api10_qemud(state) && state->identity.euid == 0;
        int fd = verified_qemud
            ? guest_goldfish_tty_epoll_create(&guest_goldfish_tty_epolls,
                &guest_sockets, size, state->virtual_fd_table_id)
            : -EPERM;
        if (verified_qemud)
            guest_qemud_diag_note_epoll_create(&state->qemud_diag,
                verified_qemud, fd);
        guest_goldfish_tty_runtime.epoll_creates++;
        if (fd >= 0) track_virtual_fd_for_group(state, fd);
        else guest_goldfish_tty_runtime.unsupported++;
        *pending_return = fd;
        *fake = 1;
        virtual_device_count++;
        if (guest_goldfish_tty_diagnostics_emitted < 64u) {
            guest_goldfish_tty_diagnostics_emitted++;
            printf("GUEST QEMUD VIRTUAL EPOLL CREATE: guest-pid=%d executable=%s size=%d verified-root-qemud=%d fd=%d result=%d; guest descriptor table only, host epoll_create never called\n",
                   state ? state->guest_pid : -1,
                   state ? state->exec_target : "<unknown>", size,
                   verified_qemud, fd >= 0 ? fd : -1, fd);
        }
        return 0;
    }
    if (nr == ARM_NR_EPOLL_CTL) {
        int epfd = (int32_t)regs->uregs[0];
        int operation = (int32_t)regs->uregs[1];
        int watched_fd = (int32_t)regs->uregs[2];
        uint32_t event_pointer = regs->uregs[3];
        int verified_qemud = state && state->pid == pid &&
            tracee_is_verified_api10_qemud(state) && state->identity.euid == 0;
        struct guest_arm32_epoll_event event = {0};
        int ctl_result;
        if (!verified_qemud) {
            ctl_result = -EPERM;
        } else if (!tracee_owns_virtual_fd(state, epfd) ||
                   !tracee_owns_virtual_fd(state, watched_fd)) {
            ctl_result = -EBADF;
        } else if (operation != GUEST_GOLDFISH_TTY_EPOLL_CTL_DEL &&
                   (event_pointer == 0 || read_remote(pid, event_pointer,
                       &event, sizeof(event)) != 0)) {
            ctl_result = -EFAULT;
        } else {
            ctl_result = guest_goldfish_tty_epoll_ctl(
                &guest_goldfish_tty_epolls, &guest_sockets, verified_qemud,
                state->virtual_fd_table_id, epfd, operation, watched_fd,
                event.events, event.data, guest_goldfish_tty_runtime.tty_fd,
                guest_sockets.qemud_listener_fd);
        }
        int stderr_armed_by_tty_setup = state &&
            guest_qemud_diag_note_tty_epoll_ctl(&state->qemud_diag,
                verified_qemud, epfd, operation, watched_fd, event.events,
                ctl_result);
        if (stderr_armed_by_tty_setup &&
            guest_qemud_diag_run_budget_take(&guest_qemud_diag_run_budget))
            printf("GUEST QEMUD STDERR CAPTURE ARMED: guest-pid=%d reason=%s epoll-fd=%d tty-fd=%d op=%d events=0x%x termios-TCGETS=1 termios-TCSETS=1; subsequent guest fd=2 writes are capped at four 96-byte escaped previews, syscall results unchanged\n",
                   state->guest_pid,
                   guest_qemud_diag_stderr_reason_name(
                       state->qemud_diag.stderr_capture_reason),
                   epfd, watched_fd, operation, event.events);
        guest_goldfish_tty_runtime.epoll_controls++;
        if (ctl_result < 0) guest_goldfish_tty_runtime.unsupported++;
        *pending_return = ctl_result;
        *fake = 1;
        virtual_device_count++;
        if (guest_goldfish_tty_diagnostics_emitted < 64u) {
            guest_goldfish_tty_diagnostics_emitted++;
            printf("GUEST QEMUD VIRTUAL EPOLL CTL: guest-pid=%d executable=%s epfd=%d op=%d fd=%d events=0x%x data=0x%016llx verified-root-qemud=%d tty-fd=%d listener-fd=%d result=%d; no host epoll object or event source\n",
                   state ? state->guest_pid : -1,
                   state ? state->exec_target : "<unknown>", epfd, operation, watched_fd,
                   event.events, (unsigned long long)event.data,
                   verified_qemud, guest_goldfish_tty_runtime.tty_fd,
                   guest_sockets.qemud_listener_fd, ctl_result);
        }
        return 0;
    }
    if (nr == ARM_NR_EPOLL_WAIT) {
        int epfd = (int32_t)regs->uregs[0];
        int32_t maxevents = (int32_t)regs->uregs[2];
        int32_t timeout_ms = (int32_t)regs->uregs[3];
        int verified_qemud = state && state->pid == pid &&
            tracee_is_verified_api10_qemud(state) && state->identity.euid == 0;
        int wait_result = !verified_qemud ? -EPERM :
            (!tracee_owns_virtual_fd(state, epfd) ? -EBADF :
             guest_goldfish_tty_epoll_wait_result(&guest_goldfish_tty_epolls,
                state->virtual_fd_table_id, epfd, maxevents, timeout_ms));
        if (wait_result == GUEST_GOLDFISH_TTY_EPOLL_WAIT_PARK) {
            guest_goldfish_tty_runtime.epoll_empty_waits++;
            *fake = 2; /* keep the verified qemud tracee ptrace-stopped: no event exists */
            if (guest_goldfish_tty_diagnostics_emitted < 64u) {
                guest_goldfish_tty_diagnostics_emitted++;
                printf("GUEST QEMUD VIRTUAL EPOLL WAIT PARKED: guest-pid=%d executable=%s epfd=%d maxevents=%d timeout=%d watches=%zu result=parked-no-peer; qemud tty input and listener queue are empty, no synthetic bytes/event and no host epoll_wait\n",
                       state->guest_pid, state->exec_target, epfd, maxevents, timeout_ms,
                       guest_goldfish_tty_epoll_watch_count(
                           &guest_goldfish_tty_epolls, epfd));
            }
            return 0;
        }
        if (wait_result < 0) guest_goldfish_tty_runtime.unsupported++;
        *pending_return = wait_result;
        *fake = 1;
        virtual_device_count++;
        if (guest_goldfish_tty_diagnostics_emitted < 64u) {
            guest_goldfish_tty_diagnostics_emitted++;
            printf("GUEST QEMUD VIRTUAL EPOLL WAIT: guest-pid=%d executable=%s epfd=%d maxevents=%d timeout=%d result=%d; no queued peer events, no host epoll_wait\n",
                   state ? state->guest_pid : -1,
                   state ? state->exec_target : "<unknown>", epfd, maxevents,
                   timeout_ms, wait_result);
        }
        return 0;
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
    if (nr == ARM_NR_SENDTO || nr == ARM_NR_RECVFROM) {
        *pending_return = virtual_guest_property_stream_io(pid, regs,
                                                            nr == ARM_NR_RECVFROM);
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
    if ((nr == ARM_NR_READ || nr == ARM_NR_WRITE) && state) {
        int fd = (int32_t)regs->uregs[0];
        int32_t null_result = 0;
        if (guest_null_stdio_io(&guest_null_stdio_runtime,
                state->null_stdio_mask, fd, nr == ARM_NR_WRITE,
                regs->uregs[2], &null_result)) {
            *pending_return = null_result;
            *fake = 1;
            if (guest_null_stdio_diagnostics_emitted < 64u) {
                guest_null_stdio_diagnostics_emitted++;
                printf("GUEST NULL STDIO IO: guest-pid=%d executable=%s fd=%d operation=%s bytes=%u result=%d mask=0x%x; app-private null semantics (EOF/discard), host stdio untouched\n",
                       state->guest_pid, state->exec_target, fd,
                       nr == ARM_NR_WRITE ? "write" : "read",
                       regs->uregs[2], null_result, state->null_stdio_mask);
            }
            return 0;
        }
    }
    if ((nr == ARM_NR_READ || nr == ARM_NR_WRITE) &&
        guest_fb0_fd_matches(pid, (int32_t)regs->uregs[0])) {
        *pending_return = -EOPNOTSUPP;
        *fake = 1;
        printf("GUEST FB0 STREAM IO DENIED: guest-pid=%d fd=%d syscall=%s result=-EOPNOTSUPP; only validated mmap2/page-flip framebuffer data is supported\n",
               state->guest_pid, (int32_t)regs->uregs[0],
               guest_diag_syscall_name(nr));
        return 0;
    }
    if ((nr == ARM_NR_READ || nr == ARM_NR_WRITE) &&
        is_virtual_fd_number((int32_t)regs->uregs[0])) {
        int fd = (int32_t)regs->uregs[0];
        struct guest_vsocket_fd *entry = guest_vsocket_fd_get(&guest_sockets, fd);
        if (entry && entry->kind == VIRTUAL_FD_DEV_TTY) {
            int verified_qemud = state && state->pid == pid &&
                tracee_is_verified_api10_qemud(state) && state->identity.euid == 0;
            int32_t tty_result = 0;
            if (!state || !tracee_owns_virtual_fd(state, fd)) {
                tty_result = -EBADF;
            } else if (!verified_qemud) {
                tty_result = -EPERM;
            } else if (regs->uregs[2] == 0) {
                tty_result = 0;
            } else if (nr == ARM_NR_READ) {
                tty_result = guest_goldfish_tty_read_result(
                    &guest_goldfish_tty_runtime, fd, entry->nonblocking);
            } else {
                tty_result = guest_goldfish_tty_write_result(
                    &guest_goldfish_tty_runtime, fd, regs->uregs[2]);
            }
            virtual_device_count++;
            if (tty_result == GUEST_GOLDFISH_TTY_READ_PARK) {
                *fake = 2;
                if (guest_goldfish_tty_diagnostics_emitted < 64u) {
                    guest_goldfish_tty_diagnostics_emitted++;
                    printf("GUEST GOLDFISH TTY READ PARKED: guest-pid=%d fd=%d count=%u nonblocking=%d result=parked-no-peer; no bytes fabricated and no host read\n",
                           state->guest_pid, fd, regs->uregs[2],
                           entry->nonblocking);
                }
                return 0;
            }
            *pending_return = tty_result;
            *fake = 1;
            if (guest_goldfish_tty_diagnostics_emitted < 64u) {
                guest_goldfish_tty_diagnostics_emitted++;
                printf("GUEST GOLDFISH TTY IO: guest-pid=%d executable=%s fd=%d operation=%s count=%u nonblocking=%d result=%d; no serial peer modeled, no host read/write\n",
                       state ? state->guest_pid : -1,
                       state ? state->exec_target : "<unknown>", fd,
                       nr == ARM_NR_READ ? "read" : "write", regs->uregs[2],
                       entry->nonblocking, tty_result);
            }
            return 0;
        } else if (entry && entry->kind == VIRTUAL_FD_DEV_BINDER) {
            *pending_return = -EOPNOTSUPP;
            printf("GUEST BINDER STREAM IO DENIED: guest-pid=%d fd=%d syscall=%s result=-EOPNOTSUPP; API10 backend accepts only version/context-manager/loop ioctls, no raw stream or host fd\n",
                   state->guest_pid, fd, guest_diag_syscall_name(nr));
        } else if (entry && entry->kind >= VIRTUAL_FD_DEV_NULL &&
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
        int fd = (int32_t)regs->uregs[0];
        int command = (int)regs->uregs[1];
        int argument = (int)regs->uregs[2];
        *pending_return = virtual_fd_fcntl(active_tracee, fd, command, argument);
        guest_kmsg_note_fcntl(&guest_kmsg_runtime, fd, command, argument,
                              *pending_return);
        if (fd == guest_kmsg_runtime.fd && command == GUEST_KMSG_F_SETFD &&
            guest_kmsg_diagnostics_emitted < 64u) {
            guest_kmsg_diagnostics_emitted++;
            printf("GUEST KMSG FD FLAGS: guest-pid=%d fd=%d command=F_SETFD value=0x%x result=%d cloexec=%d; guest descriptor-table state only\n",
                   state ? state->guest_pid : -1, fd, argument,
                   *pending_return, guest_kmsg_runtime.fd_cloexec);
        }
        *fake = 1; return 0;
    }
    if (nr == ARM_NR_CLOSE && state) {
        int fd = (int32_t)regs->uregs[0];
        uint8_t mask = state->null_stdio_mask;
        int32_t close_result = 0;
        if (guest_null_stdio_close(&guest_null_stdio_runtime, &mask, fd,
                                   &close_result)) {
            set_guest_null_stdio_mask_for_group(state, mask);
            *pending_return = close_result;
            *fake = 1;
            if (guest_null_stdio_diagnostics_emitted < 64u) {
                guest_null_stdio_diagnostics_emitted++;
                printf("GUEST NULL STDIO CLOSE: guest-pid=%d fd=%d result=%d mask=0x%x; guest descriptor state only, no host close\n",
                       state->guest_pid, fd, close_result, mask);
            }
            return 0;
        }
    }
    if (nr == ARM_NR_CLOSE && is_virtual_fd_number((int32_t)regs->uregs[0])) {
        int fd = (int32_t)regs->uregs[0];
        *pending_return = close_virtual_fd(active_tracee, fd);
        guest_kmsg_note_fd_closed(&guest_kmsg_runtime, fd, *pending_return,
                                  virtual_fd_referenced(fd), 0);
        if (*pending_return == 0 && fd == guest_null_stdio_runtime.source_fd &&
            !virtual_fd_referenced(fd)) {
            guest_null_stdio_source_fd_closed(&guest_null_stdio_runtime, fd);
            guest_ueventd_null_stdio_note_step(state,
                GUEST_UEVENTD_STDIO_SOURCE_CLOSE, fd, *pending_return);
        }
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
    if (nr == ARM_NR_DUP) {
        int fd = (int32_t)regs->uregs[0];
        int null_stdio_source = state && guest_null_stdio_fd_is_null(
            state->null_stdio_mask, fd,
            guest_null_stdio_virtual_fd_valid(state, fd));
        if (is_virtual_fd_number(fd) || null_stdio_source) {
            int live = state && is_virtual_fd(fd) && tracee_owns_virtual_fd(state, fd);
            *pending_return = is_virtual_fd_number(fd)
                ? (live ? -EOPNOTSUPP : -EBADF) : -EOPNOTSUPP;
            *fake = 1;
            virtual_fd_duplicate_denials++;
            if (virtual_fd_duplicate_denials <= 64u)
                printf("GUEST VIRTUAL FD DUP DENIED: guest-pid=%d syscall=dup source-fd=%d live=%d null-stdio=%d result=%d; duplication backend unsupported, no host dup called\n",
                       state ? state->guest_pid : -1, fd, live, null_stdio_source,
                       *pending_return);
            return 0;
        }
    }
    if (nr == ARM_NR_DUP2 &&
        (is_virtual_fd_number((int32_t)regs->uregs[0]) ||
         is_virtual_fd_number((int32_t)regs->uregs[1])) &&
        !(state && guest_null_stdio_virtual_fd_valid(
            state, (int32_t)regs->uregs[0]))) {
        int old_fd = (int32_t)regs->uregs[0];
        int new_fd = (int32_t)regs->uregs[1];
        int source_live = state && is_virtual_fd(old_fd) &&
            tracee_owns_virtual_fd(state, old_fd);
        *pending_return = is_virtual_fd_number(old_fd) && !source_live
            ? -EBADF : -EOPNOTSUPP;
        *fake = 1;
        virtual_fd_duplicate_denials++;
        if (virtual_fd_duplicate_denials <= 64u)
            printf("GUEST VIRTUAL FD DUP DENIED: guest-pid=%d syscall=dup2 source-fd=%d target-fd=%d source-live=%d result=%d; virtual duplication/overwrite unsupported, no host dup2 called\n",
                   state ? state->guest_pid : -1, old_fd, new_fd,
                   source_live, *pending_return);
        return 0;
    }
    if (nr == ARM_NR_DUP2 && state) {
        int old_fd = (int32_t)regs->uregs[0];
        int new_fd = (int32_t)regs->uregs[1];
        uint8_t mask = state->null_stdio_mask;
        int32_t dup_result = 0;
        int source_is_virtual_null = guest_null_stdio_virtual_fd_valid(state, old_fd);
        if (guest_null_stdio_dup2(&guest_null_stdio_runtime, &mask,
                old_fd, new_fd, source_is_virtual_null, &dup_result)) {
            if (dup_result >= 0) {
                set_guest_null_stdio_mask_for_group(state, mask);
                guest_ueventd_null_stdio_note_step(state,
                    GUEST_UEVENTD_STDIO_DUP2, old_fd, dup_result);
            }
            *pending_return = dup_result;
            *fake = 1;
            if (guest_null_stdio_diagnostics_emitted < 64u) {
                guest_null_stdio_diagnostics_emitted++;
                printf("GUEST NULL STDIO DUP2: guest-pid=%d executable=%s source-fd=%d target-fd=%d result=%d mask=0x%x source-virtual-null=%d; guest FD semantics only, no host dup2/device\n",
                       state->guest_pid, state->exec_target, old_fd, new_fd,
                       dup_result, mask, source_is_virtual_null);
            }
            return 0;
        }
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
        if ((nr == ARM_NR_MKNOD || nr == ARM_NR_MKNODAT) && state)
            state->last_guest_path[0] = '\0';
        int rc = path_syscall(pid, regs, nr, &result, &is_virtual);
        if ((nr == ARM_NR_MKNOD || nr == ARM_NR_MKNODAT) && rc != 1) {
            uint32_t requested_mode = regs->uregs[nr == ARM_NR_MKNOD ? 1u : 2u];
            uint32_t requested_device = regs->uregs[nr == ARM_NR_MKNOD ? 2u : 3u];
            int32_t effective_result = rc == 0 ? result : rc;
            const char *path = state && state->last_guest_path[0]
                ? state->last_guest_path : "<path-unavailable>";
            char safe_path[GUEST_DIAGNOSTIC_TEXT_CAPACITY];
            int path_truncated = guest_diag_escape(path, safe_path, sizeof(safe_path));
            uint32_t device_major = guest_fb0_device_major(requested_device);
            uint32_t device_minor = guest_fb0_device_minor(requested_device);
            const char *reason = "app-private-placeholder";
            if (strcmp(path, GUEST_FB0_PATH) == 0) {
                reason = state ? guest_fb0_mknod_rejection_reason(
                    state->identity.euid, state->identity.fsgid,
                    guest_fb0_graphics_uevent_received,
                    requested_mode, requested_device) : "tracee-state-unavailable";
                if (!reason) reason = effective_result == 0
                    ? "exact-source-backed-fb0" : "private-node-create-failed";
            } else if (strcmp(path, "/dev/binder") == 0) {
                reason = "binder-misc-minor-is-dynamic; no-transaction-node-event-modeled";
            } else if (effective_result == -EOPNOTSUPP) {
                reason = "guest-device-mknod-backend-not-implemented";
            } else if (effective_result < 0) {
                reason = "app-private-node-creation-failed";
            }
            if (guest_mknod_diagnostics_emitted < 64u) {
                guest_mknod_diagnostics_emitted++;
                printf("GUEST MKNOD MEDIATION: guest-pid=%d executable=%s path=\"%s\" path-truncated=%d syscall=%s dirfd=%d mode=0%o type=%s permissions=0%04o device=0x%08x major=%u minor=%u guest-euid=%u guest-fsgid=%u graphics-event=%d virtual=%d result=%d errno=%s reason=%s; device effects stay in app-private guest model\n",
                       state ? state->guest_pid : -1,
                       state && state->exec_target[0] ? state->exec_target : "<unknown>",
                       safe_path, path_truncated, guest_diag_syscall_name(nr),
                       nr == ARM_NR_MKNODAT ? (int32_t)regs->uregs[0] : AT_FDCWD,
                       requested_mode, guest_mknod_mode_type(requested_mode),
                       requested_mode & 07777u, requested_device,
                       device_major, device_minor,
                       state ? state->identity.euid : 0u,
                       state ? state->identity.fsgid : 0u,
                       guest_fb0_graphics_uevent_received, is_virtual,
                       effective_result,
                       effective_result < 0 ? guest_diag_errno_name(-effective_result) : "none",
                       reason ? reason : "accepted-source-backed-fb0");
            } else {
                guest_mknod_diagnostics_suppressed++;
            }
        }
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
            value = -EOPNOTSUPP;
            denied_count++;
            log_broker_denial_detail(pid, state, nr, value, NULL,
                                     "mknod-must-use-path-containment-broker", 0);
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
    memset(tracees, 0, sizeof(tracees));
    memset(&tracee_slot_pool, 0, sizeof(tracee_slot_pool));
    memset(&pending_child_stops, 0, sizeof(pending_child_stops));
    pending_child_stop_deferred = pending_child_stop_adopted = 0;
    pending_child_stop_rejected = pending_child_stop_queued_for_cleanup = 0;
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
    if (original_init_native_path(root->exec_backing_path,
                                  sizeof(root->exec_backing_path)) != 0)
        root->exec_backing_path[0] = '\0';
    if (root->exec_backing_path[0]) {
        char canonical_init[PATH_MAX];
        if (realpath(root->exec_backing_path, canonical_init))
            snprintf(root->exec_backing_path, sizeof(root->exec_backing_path),
                     "%s", canonical_init);
    }
    root->target_elf_entry_valid = guest_elf32_arm_entrypoint(
        root->exec_backing_path, &root->target_elf_type,
        &root->target_elf_entry) == 0;
    root->exec_image_committed = root->target_elf_entry_valid;
    root->null_stdio_exec.source_fd = -1;
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
            if (pending_child_stops.count == 0) return 0;
            fprintf(stderr, "orphaned pending ptrace child stops=%zu with no registered parent; terminating fail-closed\n",
                    pending_child_stops.count);
            pending_child_stop_rejected += pending_child_stops.count;
            (void)kill_all_tracees();
            return -1;
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
        if (waited < 0 && errno == ECHILD && active_tracee_count == 0 &&
            pending_child_stops.count == 0) return 0;
        if (waited < 0) {
            fprintf(stderr, "waitpid on guest process tree failed: errno=%d\n", errno);
            kill_all_tracees(); return -1;
        }
        struct tracee_state *state = find_tracee(waited);
        if (!state) {
            int wait_event = (unsigned)status >> 16;
            int wait_signal = WIFSTOPPED(status) ? WSTOPSIG(status) : 0;
            if (ptrace_child_wait_status_is_initial_stop(status)) {
                size_t retained = guest_tracee_slot_retained_count(&tracee_slot_pool);
                if (!ptrace_child_stop_capacity_available(
                        retained, pending_child_stops.count, MAX_TRACEES)) {
                    process_limit_hit = 1;
                    blocked_process_count++;
                    pending_child_stop_rejected++;
                    fprintf(stderr, "PROCESS TREE LIMIT: pending child initial stop host-pid=%d wait-status=0x%x retained-unreaped=%zu pending=%zu maximum=%d; refusing untracked child fail-closed\n",
                            waited, status, retained, pending_child_stops.count,
                            MAX_TRACEES);
                    kill_untracked_tracee(waited);
                    break;
                }
                int queue_rc = ptrace_child_stop_queue_add(
                    &pending_child_stops, waited, status);
                if (queue_rc == 0) {
                    pending_child_stop_deferred++;
                    printf("PTRACE CHILD INITIAL STOP DEFERRED: host-pid=%d wait-status=0x%x signal=%d event=%u pending=%zu; waiting for exact parent PTRACE_EVENT_FORK/VFORK/CLONE match before registration or resume\n",
                           waited, status, wait_signal, (unsigned)wait_event,
                           pending_child_stops.count);
                    continue;
                }
                pending_child_stop_rejected++;
                fprintf(stderr, "cannot defer ptrace child initial stop host-pid=%d wait-status=0x%x errno=%d; killing fail-closed\n",
                        waited, status, -queue_rc);
            } else {
                pending_child_stop_rejected++;
                fprintf(stderr, "unregistered traced pid=%d wait-status=0x%x stopped=%d signal=%d event=%u; killing fail-closed\n",
                        waited, status, WIFSTOPPED(status), wait_signal,
                        (unsigned)wait_event);
            }
            (void)ptrace(PTRACE_KILL, waited, NULL, NULL);
            (void)kill(waited, SIGKILL);
            continue;
        }
        if (WIFEXITED(status)) {
            printf("GUEST PROCESS EXIT: pid=%d code=%d\n", waited, WEXITSTATUS(status));
            if (!state->is_thread && state->guest_parent_pid > 0) {
                size_t unreaped = count_unreaped_guest_children(state->guest_parent_pid);
                if (unreaped > guest_unreaped_child_peak)
                    guest_unreaped_child_peak = unreaped;
                printf("GUEST CHILD EXIT STATUS: parent-guest-pid=%d child-guest-pid=%d code=%d direct-unreaped-before-parent-wait=%zu; awaiting observed SIGCHLD/API10 ARM wait4, no registry slot recycled yet\n",
                       state->guest_parent_pid, state->guest_pid,
                       WEXITSTATUS(status), unreaped);
            }
            if (strcmp(state->exec_target, "/system/bin/qemud") == 0) {
                if (guest_qemud_diag_run_budget_take(&guest_qemud_diag_run_budget))
                    log_guest_qemud_startup_diagnostics(state, "exited", WEXITSTATUS(status));
                guest_qemud_exit_count++;
                guest_qemud_last_exit_code = WEXITSTATUS(status);
                if (guest_qemud_diag_run_budget_take(&guest_qemud_diag_run_budget))
                    printf("GUEST EMULATOR SERVICE EXIT: guest-pid=%d service=qemud code=%d; no host emulator pipe was accessed\n",
                           state->guest_pid, guest_qemud_last_exit_code);
            } else if (strcmp(state->exec_target, "/system/bin/qemu-props") == 0) {
                printf("GUEST EMULATOR SERVICE EXIT: guest-pid=%d service=qemu-props code=%d; boot-properties protocol completion not assumed\n",
                       state->guest_pid, WEXITSTATUS(status));
            }
            if (waited == pid) *exit_code = WEXITSTATUS(status);
            int32_t exited_guest_pid = state->guest_pid;
            remove_tracee(waited);
            guest_binder_release_context_manager_if_dead(exited_guest_pid);
            continue;
        }
        if (WIFSIGNALED(status)) {
            printf("GUEST PROCESS EXIT: pid=%d signal=%d\n", waited, WTERMSIG(status));
            if (!state->is_thread && state->guest_parent_pid > 0) {
                size_t unreaped = count_unreaped_guest_children(state->guest_parent_pid);
                if (unreaped > guest_unreaped_child_peak)
                    guest_unreaped_child_peak = unreaped;
                printf("GUEST CHILD EXIT STATUS: parent-guest-pid=%d child-guest-pid=%d signal=%d direct-unreaped-before-parent-wait=%zu; awaiting observed SIGCHLD/API10 ARM wait4, no registry slot recycled yet\n",
                       state->guest_parent_pid, state->guest_pid,
                       WTERMSIG(status), unreaped);
            }
            if (strcmp(state->exec_target, "/system/bin/qemud") == 0) {
                if (guest_qemud_diag_run_budget_take(&guest_qemud_diag_run_budget))
                    log_guest_qemud_startup_diagnostics(state, "signaled", WTERMSIG(status));
                guest_qemud_exit_count++;
                guest_qemud_last_exit_code = -WTERMSIG(status);
                if (guest_qemud_diag_run_budget_take(&guest_qemud_diag_run_budget))
                    printf("GUEST EMULATOR SERVICE EXIT: guest-pid=%d service=qemud signal=%d\n",
                           state->guest_pid, WTERMSIG(status));
            } else if (strcmp(state->exec_target, "/system/bin/qemu-props") == 0) {
                printf("GUEST EMULATOR SERVICE EXIT: guest-pid=%d service=qemu-props signal=%d\n",
                       state->guest_pid, WTERMSIG(status));
            }
            if (waited == pid) { *exit_code = -1; *exit_signal = WTERMSIG(status); }
            int32_t exited_guest_pid = state->guest_pid;
            remove_tracee(waited);
            guest_binder_release_context_manager_if_dead(exited_guest_pid);
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
            int pending_child_status = 0;
            int pending_child_match = ptrace_child_stop_queue_take(
                &pending_child_stops, child_pid, &pending_child_status);
            if (pending_child_match < 0) {
                fprintf(stderr, "invalid deferred child-stop queue for ptrace child=%d\n",
                        child_pid);
                kill_all_tracees(); return -1;
            }
            int child_is_thread = event == PTRACE_EVENT_CLONE &&
                state->last_syscall == ARM_NR_CLONE && (state->clone_flags & 0x00010000UL);
            pid_t child_guest_pid = child_is_thread ? state->guest_pid : next_guest_pid++;
            pid_t child_guest_tid = child_is_thread ? next_guest_tid++ : child_guest_pid;
            pid_t child_parent_guest_pid = child_is_thread ? state->guest_parent_pid : state->guest_pid;
            size_t retained_before_admission =
                guest_tracee_slot_retained_count(&tracee_slot_pool);
            struct tracee_state *child_state = NULL;
            if (ptrace_child_stop_capacity_available(retained_before_admission,
                    pending_child_stops.count, MAX_TRACEES)) {
                child_state = add_tracee(child_pid, 1, child_guest_pid,
                    child_guest_tid, child_parent_guest_pid, child_is_thread);
            }
            if (!child_state) {
                process_limit_hit = 1;
                blocked_process_count++;
                fprintf(stderr, "PROCESS TREE LIMIT: refusing child host-pid=%d guest-pid=%d active=%zu maximum-active=%zu retained=%zu pending-stops=%zu slots=%zu/%d; no exited-unreaped record was recycled\n",
                        child_pid, child_guest_pid, tracee_slot_pool.active_count,
                        tracee_slot_pool.maximum_active, retained_before_admission,
                        pending_child_stops.count, tracee_slot_pool.high_water,
                        MAX_TRACEES);
                if (pending_child_match) pending_child_stop_rejected++;
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
                child_state->null_stdio_mask = state->null_stdio_mask;
                child_state->guest_ruid = state->guest_ruid;
                child_state->guest_euid = state->guest_euid;
                child_state->guest_rgid = state->guest_rgid;
                child_state->guest_egid = state->guest_egid;
                child_state->identity = state->identity;
                child_state->fb_mapping_start = state->fb_mapping_start;
                child_state->fb_mapping_length = state->fb_mapping_length;
                child_state->fb_mapping_valid = state->fb_mapping_valid;
                child_state->binder = state->binder;
                child_state->binder_waiting = 0;
                child_state->process_compat = state->process_compat;
                snprintf(child_state->exec_backing_path,
                         sizeof(child_state->exec_backing_path), "%s",
                         state->exec_backing_path);
                child_state->target_elf_entry_valid = state->target_elf_entry_valid;
                child_state->exec_image_committed = state->exec_image_committed;
                child_state->target_elf_type = state->target_elf_type;
                child_state->target_elf_entry = state->target_elf_entry;
                snprintf(child_state->exec_target, sizeof(child_state->exec_target), "%s",
                         state->exec_target[0] ? state->exec_target : "<unknown>");
                snprintf(child_state->exec_script_path, sizeof(child_state->exec_script_path),
                         "%s", state->exec_script_path);
                process_events++;
                printf("GUEST PROCESS EVENT: parent=%d guest-pid=%d child=%d guest-pid=%d type=%s active=%zu/%d registry-high-water=%zu retained-unreaped=%zu reused-slots=%zu\n",
                       waited, state->guest_pid, child_pid, child_guest_pid,
                       event == PTRACE_EVENT_FORK ? "fork" : event == PTRACE_EVENT_VFORK ? "vfork" : "clone",
                       tracee_slot_pool.active_count, MAX_TRACEES,
                       tracee_slot_pool.high_water,
                       guest_tracee_slot_retained_count(&tracee_slot_pool),
                       tracee_slot_pool.reused_count);
                if (pending_child_match) {
                    if (!ptrace_child_wait_status_is_initial_stop(pending_child_status) ||
                        set_guest_trace_options(child_pid) != 0) {
                        fprintf(stderr, "cannot configure exact-event-adopted child pid=%d initial-status=0x%x errno=%d\n",
                                child_pid, pending_child_status, errno);
                        kill_all_tracees(); return -1;
                    }
                    child_state->needs_options = 0;
                    if (resume_trace(child_pid, 0) != 0) {
                        fprintf(stderr, "cannot resume exact-event-adopted child pid=%d errno=%d\n",
                                child_pid, errno);
                        kill_all_tracees(); return -1;
                    }
                    pending_child_stop_adopted++;
                    printf("PTRACE CHILD INITIAL STOP ADOPTED: parent-host-pid=%d parent-guest-pid=%d child-host-pid=%d child-guest-pid=%d child-wait-status=0x%x event=%s exact-PTRACE_GETEVENTMSG-match=1 options-set=1 resumed=1\n",
                           waited, state->guest_pid, child_pid, child_guest_pid,
                           pending_child_status,
                           event == PTRACE_EVENT_FORK ? "fork" :
                               event == PTRACE_EVENT_VFORK ? "vfork" : "clone");
                }
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
            if (state->pending_exec_backing_path[0]) {
                snprintf(state->exec_backing_path,
                         sizeof(state->exec_backing_path), "%s",
                         state->pending_exec_backing_path);
                state->pending_exec_backing_path[0] = '\0';
            }
            state->target_elf_entry_valid =
                guest_elf32_arm_entrypoint(state->exec_backing_path,
                    &state->target_elf_type, &state->target_elf_entry) == 0;
            state->exec_image_committed = state->target_elf_entry_valid;
            memset(&state->null_stdio_exec, 0,
                   sizeof(state->null_stdio_exec));
            state->null_stdio_exec.source_fd = -1;
            state->target_elf_entry_pc_seen = 0;
            if (guest_null_stdio_actor_for_tracee(state) ==
                    GUEST_NULL_STDIO_ACTOR_UEVENTD) {
                guest_ueventd_exec_image_validated_count++;
                printf("GUEST UEVENTD EXEC IMAGE VALIDATED: guest-pid=%d parent-guest-pid=%d executable=%s backing=%s image=ARM32-ELF-verified euid=%u; exact API10 direct child of PID1, app-private payload only\n",
                       state->guest_pid, state->guest_parent_pid,
                       state->exec_target, state->exec_backing_path,
                       state->identity.euid);
            }
            if (state->exec_target[0] == '/')
                printf("GUEST TARGET ELF ENTRY METADATA: guest-pid=%d target=%s backing=%s ELF32-ARM type=%s e_entry=0x%08x; metadata only, execution at e_entry/C-main not inferred\n",
                       state->guest_pid, state->exec_target,
                       state->exec_backing_path[0] ? state->exec_backing_path : "<unknown>",
                       state->target_elf_entry_valid
                           ? (state->target_elf_type == ET_EXEC ? "ET_EXEC" : "ET_DYN")
                           : "unavailable",
                       state->target_elf_entry_valid ? state->target_elf_entry : 0u);
            if (script_launch) {
                snprintf(state->exec_script_path, sizeof(state->exec_script_path), "%s",
                         state->pending_exec_script[0] ? state->pending_exec_script
                                                       : GUEST_API10_GOLDFISH_SCRIPT);
            } else {
                state->exec_script_path[0] = '\0';
            }
            state->pending_exec_script[0] = '\0';
            close_virtual_fds_on_exec(state);
            guest_binder_process_exec_reset(&state->binder);
            state->binder_waiting = 0;
            state->binder_mmap_pending = 0;
            state->binder_munmap_pending = 0;
            state->binder_pending_map_length = 0;
            state->target_elf_text_seen = 0;
            state->target_elf_text_pc = 0;
            state->target_elf_text_file_offset = 0;
            if (strcmp(state->exec_target, "/system/bin/qemud") == 0) {
                guest_qemud_diag_state_init(&state->qemud_diag);
                char profile_qemu[16] = "";
                char profile_qemud[GUEST_QEMUD_DIAG_PORT_CAP] = "";
                int profile_qemu_present = guest_qemud_diag_token_value(
                    GUEST_PROFILE_PROC_CMDLINE, "qemu", profile_qemu,
                    sizeof(profile_qemu));
                int profile_qemud_present = guest_qemud_diag_token_value(
                    GUEST_PROFILE_PROC_CMDLINE, "android.qemud", profile_qemud,
                    sizeof(profile_qemud));
                if (guest_qemud_diag_run_budget_take(&guest_qemud_diag_run_budget))
                    printf("GUEST QEMUD TRANSPORT PROFILE: guest-pid=%d seeded-proc-cmdline=1 qemu-token=%s android.qemud-token=%s expected-port=ttyS1 hardware=%s; API10 source documents the selector and paired binary contains /proc/cmdline, android.qemud= and serial-path format strings; profile audit only, runtime branch/open not observed\n",
                       state->guest_pid,
                       profile_qemu_present && strcmp(profile_qemu, "1") == 0
                           ? "qemu=1" : "missing-or-not-1",
                       profile_qemud_present ? profile_qemud : "missing",
                       GUEST_PROFILE_HARDWARE);
                guest_qemud_exec_count++;
                if (guest_qemud_diag_run_budget_take(&guest_qemud_diag_run_budget))
                    printf("GUEST EMULATOR SERVICE EXEC: guest-pid=%d service=qemud target=%s linker-entry follows; Goldfish qemu_pipe backend remains explicitly unsupported\n",
                           state->guest_pid, state->exec_target);
            } else if (strcmp(state->exec_target, "/system/bin/qemu-props") == 0) {
                guest_qemu_props_exec_count++;
                printf("GUEST EMULATOR SERVICE EXEC: guest-pid=%d service=qemu-props target=%s linker-entry follows; boot-properties require the external emulator pipe protocol, not host substitution\n",
                       state->guest_pid, state->exec_target);
            }
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
                if (fake == 2) {
                    state->pending = 0;
                    state->expect_exit = 0;
                    const char *blocked_kind = state->last_syscall == ARM_NR_EPOLL_WAIT
                        ? "guest-software-blocked-epoll-wait"
                        : "guest-software-blocked-read";
                    if (syscall_stops <= MAX_TRACE_LINES)
                        printf("TRACE pid=%d entry #%lu: ARM syscall=%d class=%d %s (tracee remains ptrace-stopped; no syscall forwarded)\n",
                               waited, syscall_stops, state->last_syscall,
                               (int)guest_syscall_policy(state->last_syscall),
                               blocked_kind);
                    stops++;
                    continue;
                }
                if (strcmp(state->exec_target, "/system/bin/qemud") == 0) {
                    const char *fd_path = guest_qemud_diag_fd_path(
                        &state->qemud_diag, (int32_t)state->last_syscall_args[0]);
                    guest_qemud_diag_begin(&state->qemud_diag,
                        state->last_syscall, state->last_syscall_args,
                        regs.uregs[15], regs.uregs[14],
                        state->last_guest_path, fd_path);
                    if ((state->last_syscall == 1 || state->last_syscall == 248) &&
                        guest_qemud_diag_run_budget_take(&guest_qemud_diag_run_budget))
                        printf("GUEST QEMUD EXIT REQUEST: guest-pid=%d syscall=%d(%s) requested-status=%u pc=0x%08x lr=0x%08x; wait status will verify actual exit\n",
                               state->guest_pid, state->last_syscall,
                               guest_diag_syscall_name(state->last_syscall),
                               state->last_syscall_args[0], regs.uregs[15],
                               regs.uregs[14]);
                }
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
                    if (state->binder_mmap_pending && set_regs(waited, &regs) != 0) {
                        fprintf(stderr, "cannot install guest Binder anonymous mmap arguments pid=%d errno=%d\n",
                                waited, errno);
                        kill_all_tracees(); return -1;
                    }
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
                uint32_t syscall_result_bits = state->pending
                    ? (uint32_t)state->pending_return : (uint32_t)regs.uregs[0];
                int32_t syscall_result = (int32_t)syscall_result_bits;
                if (strcmp(state->exec_target, "/system/bin/qemud") == 0) {
                    struct guest_qemud_diag_state *diag = &state->qemud_diag;
                    if (state->last_syscall == ARM_NR_OPEN ||
                        state->last_syscall == ARM_NR_OPENAT)
                        guest_qemud_diag_note_open(diag, state->last_guest_path,
                                                   syscall_result);
                    if (state->last_syscall == ARM_NR_READ &&
                        strcmp(diag->pending_fd_path, "/proc/cmdline") == 0 &&
                        syscall_result > 0) {
                        unsigned char cmdline_bytes[GUEST_QEMUD_DIAG_CMDLINE_CAP - 1u];
                        size_t amount = (size_t)syscall_result;
                        if (amount > state->last_syscall_args[2])
                            amount = state->last_syscall_args[2];
                        if (amount > sizeof(cmdline_bytes)) amount = sizeof(cmdline_bytes);
                        if (amount && read_remote(waited,
                                state->last_syscall_args[1], cmdline_bytes,
                                amount) == 0) {
                            guest_qemud_diag_note_cmdline_read(diag,
                                cmdline_bytes, amount);
                            if (guest_qemud_diag_claim_cmdline_observation(diag) &&
                                guest_qemud_diag_run_budget_take(&guest_qemud_diag_run_budget))
                                printf("GUEST QEMUD CMDLINE READ: guest-pid=%d fd=%u result=%d observed-bytes=%zu qemu-1=%d android.qemud-present=%d port=%s; raw command line omitted\n",
                                       state->guest_pid, state->last_syscall_args[0],
                                       syscall_result, amount,
                                       diag->cmdline_qemu_enabled,
                                       diag->cmdline_qemud_parameter_present,
                                       guest_qemud_diag_safe_port_label(diag));
                        } else {
                            if (guest_qemud_diag_claim_cmdline_observation(diag) &&
                                guest_qemud_diag_run_budget_take(&guest_qemud_diag_run_budget))
                                printf("GUEST QEMUD CMDLINE READ: guest-pid=%d fd=%u result=%d observed-bytes=unavailable ptrace-read-failed=1; raw command line omitted\n",
                                       state->guest_pid, state->last_syscall_args[0],
                                       syscall_result);
                        }
                    }
                    struct guest_qemud_diag_record qemud_record;
                    int qemud_record_result = guest_qemud_diag_finish(diag,
                        syscall_result, &qemud_record);
                    if (qemud_record_result > 0 &&
                        qemud_record.syscall_number == ARM_NR_IOCTL)
                        guest_qemud_diag_note_tty_termios(diag,
                            state->pid == waited &&
                                tracee_is_verified_api10_qemud(state) &&
                                state->identity.euid == 0,
                            (int32_t)qemud_record.args[0],
                            qemud_record.args[1], syscall_result);
                    if (qemud_record_result > 0 &&
                        guest_qemud_diag_run_budget_take(&guest_qemud_diag_run_budget))
                        log_guest_qemud_syscall(waited, state, &qemud_record);
                    if (qemud_record_result > 0 &&
                        qemud_record.syscall_number == 4 &&
                        qemud_record.args[0] == 2u) {
                        size_t preview_length = 0;
                        if (guest_qemud_diag_claim_stderr_preview(diag, 2,
                                qemud_record.result, qemud_record.args[2],
                                &preview_length)) {
                            unsigned char guest_bytes[GUEST_QEMUD_DIAG_STDERR_MAX_BYTES];
                            char escaped[GUEST_QEMUD_DIAG_STDERR_ESCAPED_CAP];
                            int range_valid = guest_qemud_diag_guest_range_valid(
                                qemud_record.args[1], preview_length);
                            int read_ok = range_valid && read_remote(waited,
                                qemud_record.args[1], guest_bytes,
                                preview_length) == 0;
                            if (read_ok) {
                                int escaped_truncated = guest_qemud_diag_escape_bytes(
                                    guest_bytes, preview_length, escaped,
                                    sizeof(escaped));
                                int truncated = escaped_truncated ||
                                    preview_length < (size_t)qemud_record.result;
                                if (guest_qemud_diag_run_budget_take(
                                        &guest_qemud_diag_run_budget))
                                    printf("GUEST QEMUD STDERR PREVIEW (escaped guest bytes): guest-pid=%d seq=%u fd=2 result=%d captured=%zu truncated=%d text=\"%s\"; guest-memory observation only, no host stdio forwarded\n",
                                        state->guest_pid, qemud_record.sequence,
                                        qemud_record.result, preview_length,
                                        truncated, escaped);
                            } else if (guest_qemud_diag_run_budget_take(
                                           &guest_qemud_diag_run_budget)) {
                                printf("GUEST QEMUD STDERR PREVIEW UNAVAILABLE: guest-pid=%d seq=%u fd=2 result=%d requested=%u captured=%zu reason=%s; no guest bytes logged\n",
                                    state->guest_pid, qemud_record.sequence,
                                    qemud_record.result, qemud_record.args[2],
                                    preview_length,
                                    range_valid ? "ptrace-read-failed" : "guest-address-wrap");
                            }
                        }
                    }
                    if (qemud_record_result == -1 && diag->records_suppressed == 1u &&
                        guest_qemud_diag_run_budget_take(&guest_qemud_diag_run_budget))
                        printf("GUEST QEMUD DIAGNOSTIC LIMIT: guest-pid=%d record-cap=%u; further records counted but suppressed\n",
                               state->guest_pid, GUEST_QEMUD_DIAG_MAX_RECORDS);
                    if (state->last_syscall == ARM_NR_CLOSE && syscall_result == 0)
                        guest_qemud_diag_untrack_fd(diag,
                            (int32_t)state->last_syscall_args[0]);
                    if (state->last_syscall == 41 && syscall_result >= 0)
                        guest_qemud_diag_dup_fd(diag,
                            (int32_t)state->last_syscall_args[0], syscall_result);
                    if (state->last_syscall == ARM_NR_DUP2 && syscall_result >= 0)
                        guest_qemud_diag_dup_fd(diag,
                            (int32_t)state->last_syscall_args[0],
                            (int32_t)state->last_syscall_args[1]);
                    if ((state->last_syscall == ARM_NR_FCNTL ||
                         state->last_syscall == ARM_NR_FCNTL64) && syscall_result >= 0 &&
                        (state->last_syscall_args[1] == 0u ||
                         state->last_syscall_args[1] == 1030u))
                        guest_qemud_diag_dup_fd(diag,
                            (int32_t)state->last_syscall_args[0], syscall_result);
                }
                if (complete_guest_sigaction(waited, state, &regs, &syscall_result) != 0) {
                    fprintf(stderr, "cannot complete guest legacy sigaction translation pid=%d; terminating traced tree\n",
                            waited);
                    kill_all_tracees(); return -1;
                }
                record_guest_path_fd_result(state, &regs, syscall_result);
                observe_guest_init_config_io(state, syscall_result);
                if (state->fb_mmap_pending) {
                    if (state->last_syscall == ARM_NR_MMAP2 &&
                        !guest_arm32_syscall_result_is_error(syscall_result_bits)) {
                        state->fb_mapping_start = syscall_result_bits;
                        state->fb_mapping_length = state->fb_pending_map_length;
                        state->fb_mapping_valid = 1;
                        printf("GUEST FB0 MMAP2: guest-pid=%d executable=%s fd=%d address=0x%08x length=%u prot=0x%x offset-pages=%u; shared mapping is the app-private software framebuffer backing, not /dev/fb0 on host\n",
                               state->guest_pid, state->exec_target,
                               (int32_t)state->last_syscall_args[4],
                               state->fb_mapping_start, state->fb_mapping_length,
                               state->fb_pending_map_flags,
                               state->fb_pending_map_offset_pages);
                    } else {
                        printf("GUEST FB0 MMAP2 FAILED: guest-pid=%d result=%d; no framebuffer mapping registered\n",
                               state->guest_pid, syscall_result);
                    }
                    state->fb_mmap_pending = 0;
                }
                if (state->binder_mmap_pending) {
                    if (state->last_syscall == ARM_NR_MMAP2 &&
                        !guest_arm32_syscall_result_is_error(syscall_result_bits)) {
                        int map_rc = guest_binder_note_mapping(&state->binder,
                            syscall_result_bits,
                            state->binder_pending_map_length);
                        if (map_rc == 0) guest_binder_state.mapping_successes++;
                        printf("GUEST BINDER MAPPING: guest-pid=%d address=0x%08x length=%u read-only=%d registration=%d; anonymous guest receive memory only, no Binder transaction buffers delivered\n",
                               state->guest_pid, syscall_result_bits,
                               state->binder_pending_map_length,
                               map_rc == 0, map_rc);
                    } else {
                        printf("GUEST BINDER MMAP FAILED: guest-pid=%d syscall=%d result=%d; Binder bootstrap cannot proceed\n",
                               state->guest_pid, state->last_syscall,
                               syscall_result);
                    }
                    state->binder_mmap_pending = 0;
                    state->binder_pending_map_length = 0;
                }
                if (state->binder_munmap_pending) {
                    if (state->last_syscall == ARM_NR_MUNMAP && syscall_result == 0) {
                        int unmap_rc = guest_binder_note_unmap(&state->binder,
                            state->binder.mapping_start,
                            state->binder.mapping_length);
                        printf("GUEST BINDER MUNMAP: guest-pid=%d result=0 state-clear=%d; guest-only mapping record cleared\n",
                               state->guest_pid, unmap_rc);
                    }
                    state->binder_munmap_pending = 0;
                }
                if (state->fb_munmap_pending) {
                    if (state->last_syscall == ARM_NR_MUNMAP && syscall_result == 0) {
                        state->fb_mapping_valid = 0;
                        state->fb_mapping_start = 0;
                        state->fb_mapping_length = 0;
                        puts("GUEST FB0 MUNMAP: successful guest unmap cleared the tracee framebuffer mapping record");
                    }
                    state->fb_munmap_pending = 0;
                }
                int marker_release_observed = 0;
                if (state->last_syscall == ARM_NR_OPEN &&
                    strcmp(state->last_guest_path, GUEST_COLD_BOOT_MARKER_PATH) == 0 &&
                    guest_null_stdio_actor_for_tracee(state) ==
                        GUEST_NULL_STDIO_ACTOR_UEVENTD) {
                    uint32_t marker_flags = state->last_syscall_args[1];
                    uint32_t marker_mode = state->last_syscall_args[2];
                    int was_observed = coldboot_observation.marker_opened_by_ueventd;
                    (void)guest_coldboot_note_marker_open(
                        &coldboot_observation,
                        1, state->last_guest_path, marker_flags, marker_mode,
                        syscall_result);
                    if (!was_observed && coldboot_observation.marker_opened_by_ueventd) {
                        coldboot_marker_runtime.open_seen = 1;
                        coldboot_marker_runtime.open_result = syscall_result;
                        coldboot_marker_runtime.open_flags = marker_flags;
                        coldboot_marker_runtime.open_mode = marker_mode;
                        coldboot_marker_runtime.guest_fd = syscall_result;
                        coldboot_marker_runtime.fd_valid = 1;
                        coldboot_marker_runtime.host_pid = waited;
                        coldboot_marker_runtime.guest_pid = state->guest_pid;
                    }
                    printf("GUEST COLD-BOOT MARKER OPEN: host-pid=%d guest-pid=%d executable=%s path=%s result=%d fd=%d flags=0x%x mode=0%o create=%d api10-args-match=%d fd-kind=guest-app-private-file virtual-fd=0\n",
                           waited, state->guest_pid, state->exec_target,
                           state->last_guest_path, syscall_result, syscall_result,
                           marker_flags, marker_mode, (marker_flags & O_CREAT) != 0,
                           guest_coldboot_marker_open_args_valid(marker_flags,
                                                                 marker_mode));
                    char mapped_marker[PATH_MAX];
                    const char *open_backing = coldboot_marker_runtime.backing_path;
                    if (!open_backing[0] &&
                        map_guest_path(state->last_guest_path, mapped_marker,
                                       sizeof(mapped_marker)) == 0)
                        open_backing = mapped_marker;
                    log_guest_coldboot_marker_snapshot(
                        "GUEST COLD-BOOT MARKER OPEN BACKING", state->guest_pid,
                        syscall_result, open_backing,
                        coldboot_marker_runtime.backing_path[0] != '\0' &&
                        strcmp(open_backing, coldboot_marker_runtime.backing_path) == 0);
                }
                if (coldboot_marker_runtime.open_seen &&
                    coldboot_marker_runtime.fd_valid &&
                    waited == coldboot_marker_runtime.host_pid &&
                    (int32_t)state->last_syscall_args[0] ==
                        coldboot_marker_runtime.guest_fd) {
                    if (state->last_syscall == ARM_NR_WRITE)
                        coldboot_marker_runtime.write_calls++;
                    else if (state->last_syscall == ARM_NR_FSYNC)
                        coldboot_marker_runtime.fsync_calls++;
                    else if (state->last_syscall == ARM_NR_FDATASYNC)
                        coldboot_marker_runtime.fdatasync_calls++;
                    else if (state->last_syscall == ARM_NR_CLOSE) {
                        coldboot_marker_runtime.close_seen = 1;
                        coldboot_marker_runtime.close_result = syscall_result;
                        (void)guest_coldboot_note_marker_close(
                            &coldboot_observation,
                            guest_null_stdio_actor_for_tracee(state) ==
                                GUEST_NULL_STDIO_ACTOR_UEVENTD,
                            (int32_t)state->last_syscall_args[0], syscall_result);
                        log_guest_coldboot_marker_snapshot(
                            "GUEST COLD-BOOT MARKER CLOSE", state->guest_pid,
                            syscall_result, coldboot_marker_runtime.backing_path, 1);
                        coldboot_marker_runtime.fd_valid = 0;
                    }
                }
                int marker_stat_syscall = state->last_syscall == ARM_NR_STAT64 ||
                    state->last_syscall == ARM_NR_LSTAT64 ||
                    state->last_syscall == ARM_NR_FSTATAT64;
                if (marker_stat_syscall &&
                    strcmp(state->last_guest_path, GUEST_COLD_BOOT_MARKER_PATH) == 0 &&
                    guest_null_stdio_actor_for_tracee(state) ==
                        GUEST_NULL_STDIO_ACTOR_UEVENTD) {
                    printf("GUEST UEVENTD COLD-BOOT MARKER PRECHECK: syscall=%d(%s) result=%d path=%s; API10 device_init checks this before walking /sys\n",
                           state->last_syscall,
                           guest_diag_syscall_name(state->last_syscall),
                           syscall_result, state->last_guest_path);
                    char precheck_backing[PATH_MAX];
                    int precheck_rc = map_guest_path(state->last_guest_path,
                        precheck_backing, sizeof(precheck_backing));
                    log_guest_coldboot_marker_snapshot(
                        "GUEST UEVENTD COLD-BOOT MARKER PRECHECK BACKING",
                        state->guest_pid, syscall_result,
                        precheck_rc == 0 ? precheck_backing : NULL, 0);
                }
                if (state->guest_pid == 1 && marker_stat_syscall &&
                    strcmp(state->last_guest_path, GUEST_COLD_BOOT_MARKER_PATH) == 0) {
                    marker_release_observed = guest_coldboot_note_pid1_stat(
                        &coldboot_observation, 1, state->last_guest_path, syscall_result) ||
                        marker_release_observed;
                    char pid1_marker_backing[PATH_MAX];
                    int pid1_map_rc = map_guest_path(state->last_guest_path,
                        pid1_marker_backing, sizeof(pid1_marker_backing));
                    int same_open_backing = pid1_map_rc == 0 &&
                        coldboot_marker_runtime.backing_path[0] &&
                        strcmp(pid1_marker_backing,
                               coldboot_marker_runtime.backing_path) == 0;
                    if (coldboot_observation.pid1_stat_checks <= 8 ||
                        syscall_result == 0)
                        printf("GUEST COLD-BOOT PID1 STAT: syscall=%d(%s) result=%d path=%s marker-open-by-ueventd=%d stat-success-after-marker=%d checks=%lu same-open-backing=%d marker-close-seen=%d marker-close-result=%d\n",
                               state->last_syscall,
                               guest_diag_syscall_name(state->last_syscall),
                               syscall_result, state->last_guest_path,
                               coldboot_observation.marker_opened_by_ueventd,
                               coldboot_observation.pid1_stat_succeeded_after_marker,
                               coldboot_observation.pid1_stat_checks,
                               same_open_backing,
                               coldboot_marker_runtime.close_seen,
                               coldboot_marker_runtime.close_result);
                    if (coldboot_observation.pid1_stat_checks <= 8 ||
                        syscall_result == 0)
                        log_guest_coldboot_marker_snapshot(
                            "GUEST COLD-BOOT PID1 STAT BACKING", state->guest_pid,
                            syscall_result,
                            pid1_map_rc == 0 ? pid1_marker_backing : NULL,
                            same_open_backing);
                }
                if (marker_release_observed &&
                    !coldboot_marker_runtime.wait_release_logged) {
                    coldboot_marker_runtime.wait_release_logged = 1;
                    puts("INIT COLD-BOOT WAIT CONDITION OBSERVED: source-shaped ueventd O_WRONLY|O_CREAT mode-0000 marker open succeeded and API10 wait_for_file's PID1 stat(/dev/.coldboot_done) returned 0; the loop condition is satisfied, builtin return itself is not directly traced");
                    printf("INIT COLD-BOOT WAIT RELEASED: guest-pid=1 path=%s stat-result=0 marker-open-by-verified-ueventd=1 marker-close-seen=%d marker-close-result=%d; API10 wait_for_file predicate is satisfied, function return is source-inferred rather than directly traced\n",
                           GUEST_COLD_BOOT_MARKER_PATH,
                           coldboot_marker_runtime.close_seen,
                           coldboot_marker_runtime.close_result);
                }
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
                    state->pending_exec_backing_path[0] = '\0';
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
            size_t unreaped = count_unreaped_guest_children(state->guest_pid);
            guest_sigchld_deliveries++;
            if (unreaped > guest_unreaped_child_peak)
                guest_unreaped_child_peak = unreaped;
            if (guest_sigchld_deliveries <= 128u)
                printf("GUEST SIGCHLD FORWARDED: host-pid=%d guest-pid=%d direct-unreaped-children=%zu delivery=%lu; signal is forwarded to original guest handler\n",
                       waited, state->guest_pid, unreaped,
                       guest_sigchld_deliveries);
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
    guest_goldfish_tty_runtime_init(&guest_goldfish_tty_runtime);
    guest_goldfish_tty_epoll_table_init(&guest_goldfish_tty_epolls);
    guest_qemud_socket_bind_count = 0;
    guest_goldfish_tty_diagnostics_emitted = 0;
    guest_null_stdio_runtime_init(&guest_null_stdio_runtime);
    guest_null_stdio_diagnostics_emitted = 0;
    guest_ueventd_exec_image_validated_count = 0;
    guest_ueventd_null_stdio_ready_count = 0;
    guest_null_stdio_alias_replaced_count = 0;
    guest_kmsg_runtime_init(&guest_kmsg_runtime);
    guest_kmsg_diagnostics_emitted = 0;
    virtual_fd_duplicate_denials = 0;
    guest_uevent_queue_init(&guest_uevent_queue);
    guest_net_state_init(&guest_network_state);
    guest_path_fd_table_init(&guest_path_fds);
    memset(&coldboot_observation, 0, sizeof(coldboot_observation));
    memset(&coldboot_marker_runtime, 0, sizeof(coldboot_marker_runtime));
    memset(&guest_timezone, 0, sizeof(guest_timezone));
    if (argc != 6 || strcmp(argv[5], "/init") != 0) {
        fprintf(stderr, "usage: gingervm-init-supervisor <original-init-in-native-libs> <app-private-guest-root> <allowed-guest-native-lib-dir> <trace-ms> /init\n");
        return 2;
    }
    if (install_cancel_signal_handlers() != 0) {
        fprintf(stderr, "cannot install user-cancel signal handlers: errno=%d\n", errno);
        return 2;
    }
    struct guest_frame_channel_path_audit root_path_audit;
    int guest_root_fd = guest_frame_channel_open_directory_path_nofollow(
        argv[2], &root_path_audit);
    print_guest_frame_path_components("guest-root", &root_path_audit);
    if (guest_root_fd < 0) {
        fprintf(stderr, "GUEST ROOT REJECTED: path=%s reason=component-wise no-follow walk failed errno=%d\n",
                argv[2], -guest_root_fd);
        return 2;
    }
    struct stat guest_root_stat;
    memset(&guest_root_stat, 0, sizeof(guest_root_stat));
    int guest_root_stat_rc = fstat(guest_root_fd, &guest_root_stat);
    int guest_root_reject_errno = guest_root_stat_rc != 0 ? errno : 0;
    if (guest_root_stat_rc != 0 || !S_ISDIR(guest_root_stat.st_mode) ||
        guest_root_stat.st_uid != getuid() ||
        (guest_root_stat.st_mode & 0077) != 0) {
        if (guest_root_reject_errno == 0) guest_root_reject_errno = EACCES;
        close(guest_root_fd);
        fprintf(stderr, "GUEST ROOT REJECTED: path=%s reason=leaf-not-app-owned-private-directory uid=%u mode=0%o errno=%d\n",
                argv[2], (unsigned)guest_root_stat.st_uid,
                (unsigned)(guest_root_stat.st_mode & 07777u), guest_root_reject_errno);
        return 2;
    }
    close(guest_root_fd);
    if (!realpath(argv[2], guest_root)) {
        fprintf(stderr, "guest root is not accessible: errno=%d\n", errno); return 2;
    }
    configure_guest_frame_channel();
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
    printf("GUEST FRAME CHANNEL: ready=%d; GVMF/1 app-private receiver; frames-published=%lu; only guest fb0 backing bytes may be published; host framebuffer/Binder=0\n",
           guest_frame_channel_ready, guest_frame_published_count);
    printf("GUEST FB0 SOFTWARE MODEL: ready=%d; path=%s profile=%s %ux%u RGB565 double-buffered; graphics-uevent-received=%d node-created=%d; viewport remains no-frame until guest bytes are published\n",
           guest_fb0_backend_ready, GUEST_FB0_PATH, GUEST_PROFILE_DISPLAY_SKIN,
           GUEST_PROFILE_DISPLAY_WIDTH, GUEST_PROFILE_DISPLAY_HEIGHT,
           guest_fb0_graphics_uevent_received, guest_fb0_node_created);
    printf("PROCESS TREE: fork/clone/vfork followed with ptrace; active-and-unreaped registry cap=%d; process slots reusable after guest wait4 reap, non-waitable thread slots after ptrace terminal exit; verified ARM32 execs and confined original-linker aliases\n", MAX_TRACEES);
    puts("DYNAMIC ELF POLICY: original API10 linker is inherited as fd 198; unsupported PT_INTERP is denied before host-linker substitution");
    int child = start_guest(binary, &argv[5]);
    if (child < 0) return 2;
    int exit_code = -1, exit_signal = 0;
    int rc = run_trace((pid_t)child, &exit_code, &exit_signal);
    printf("GUEST BINDER BOOTSTRAP SUMMARY: opens=%lu ioctls=%lu version-queries=%lu anonymous-mappings=%lu context-manager-claims=%lu conflicts=%lu loop-commands=%lu parked-empty-reads=%lu unsupported-commands=%lu unsupported-transactions=%lu owner-guest-pid=%d; transaction delivery/service registration unsupported; host Binder calls=0\n",
           guest_binder_state.opens, guest_binder_state.ioctl_calls,
           guest_binder_state.version_queries, guest_binder_state.mapping_successes,
           guest_binder_state.context_manager_claims,
           guest_binder_state.context_manager_conflicts,
           guest_binder_state.loop_commands, guest_binder_state.empty_reads_parked,
           guest_binder_state.unsupported_commands,
           guest_binder_state.unsupported_transactions,
           guest_binder_state.context_manager_guest_pid);
    traced_pid = -1;
    printf("INITIAL /init POST-EXEC: %s\n", saw_exec ? "SIGTRAP observed" : "not observed");
    printf("CONTINUOUS PROCESS TREE: fork/clone/vfork events=%lu; guest exec events=%lu; dynamic execs redirected=%lu; kernel entries into original guest linker=%lu; target ELF code syscall-PCs=%lu (shell=%lu app_process=%lu); literal ET_EXEC e_entry syscall-PC hits=%lu (app_process=%lu ueventd=%lu other=%lu); C main symbol unproven\n",
           process_events, successful_guest_execs, dynamic_exec_allowed_count,
           dynamic_exec_started_count, guest_target_elf_text_entry_count,
           guest_shell_elf_text_entry_count, guest_app_process_elf_text_entry_count,
           guest_target_elf_declared_entry_pc_count,
           guest_app_process_declared_entry_pc_count,
           guest_ueventd_declared_entry_pc_count,
           guest_other_declared_entry_pc_count);
    printf("TRACE REGISTRY: hard-cap=%d; active-at-stop=%zu; maximum-active=%zu; registry-high-water=%zu; safely-reused-slots=%zu; terminal-thread-releases=%lu; retained-unreaped=%zu; process-limit-hit=%d\n",
           MAX_TRACEES, tracee_slot_pool.active_count,
           tracee_slot_pool.maximum_active, tracee_slot_pool.high_water,
           tracee_slot_pool.reused_count, guest_thread_ptrace_exits,
           guest_tracee_slot_retained_count(&tracee_slot_pool), process_limit_hit);
    printf("PTRACE CHILD STOP ORDER: deferred=%lu exact-event-adopted=%lu rejected=%lu queued-for-cleanup=%lu pending-at-summary=%zu; only an exact parent PTRACE_GETEVENTMSG match resumes an out-of-order child\n",
           pending_child_stop_deferred, pending_child_stop_adopted,
           pending_child_stop_rejected, pending_child_stop_queued_for_cleanup,
           pending_child_stops.count);
    printf("GUEST STARTUP STAGE SUMMARY: original-init-post-exec=%s; original-linker-entry-events=%lu; target-ELF-code-syscall-PCs=%lu; app_process-code-PCs=%lu; ET_EXEC-e_entry-PC-hits=%lu (app_process=%lu ueventd=%lu other=%lu); qemud-execs=%lu exits=%lu last-exit=%d; qemu-props-execs=%lu; C-main/Zygote/framework/system_server/desktop=unproven\n",
           saw_exec ? "observed" : "not-observed", dynamic_exec_started_count,
           guest_target_elf_text_entry_count, guest_app_process_elf_text_entry_count,
           guest_target_elf_declared_entry_pc_count,
           guest_app_process_declared_entry_pc_count,
           guest_ueventd_declared_entry_pc_count,
           guest_other_declared_entry_pc_count,
           guest_qemud_exec_count, guest_qemud_exit_count,
           guest_qemud_last_exit_code, guest_qemu_props_exec_count);
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
    printf("GUEST MKNOD DIAGNOSTICS: emitted=%lu suppressed=%lu (limit=64); fb0 node is counted only for exact guest path, root:graphics identity, consumed add event and API10 mode/device tuple\n",
           guest_mknod_diagnostics_emitted, guest_mknod_diagnostics_suppressed);
    printf("GUEST NULL STDIO SUMMARY: node-present=%d unlinked=%d decoded-null-path-mknod-requests=%u accepted=%u rejected=%u decoded-null-path-open-requests=%u succeeded=%u failed=%u source-fd=%d source-fd-open=%d source-fd-closes=%u decoded-null-path-unlink-requests=%u succeeded=%u validated-null-dup2=%u succeeded=%u ordinary-dup2-cleared-null-alias=%lu stdio-mask-last=0x%x reads=%u writes=%u closes=%u diagnostics=%lu; counters cover decoded exact-path broker requests, not all syscalls; API10 /init char 1:3 mode 0600; in-memory guest FD state only, no host mknod/open/unlink/device\n",
           guest_null_stdio_runtime.node_present, guest_null_stdio_runtime.unlinked,
           guest_null_stdio_runtime.mknod_attempts,
           guest_null_stdio_runtime.mknod_accepted,
           guest_null_stdio_runtime.mknod_rejected,
           guest_null_stdio_runtime.open_attempts,
           guest_null_stdio_runtime.open_succeeded,
           guest_null_stdio_runtime.open_failed,
           guest_null_stdio_runtime.source_fd,
           guest_null_stdio_runtime.source_fd_open,
           guest_null_stdio_runtime.source_fd_closes,
           guest_null_stdio_runtime.unlink_attempts,
           guest_null_stdio_runtime.unlink_succeeded,
           guest_null_stdio_runtime.dup2_attempts,
           guest_null_stdio_runtime.dup2_succeeded,
           guest_null_stdio_alias_replaced_count,
           guest_null_stdio_runtime.stdio_mask_last,
           guest_null_stdio_runtime.stdio_reads,
           guest_null_stdio_runtime.stdio_writes,
           guest_null_stdio_runtime.stdio_closes,
           guest_null_stdio_diagnostics_emitted);
    printf("GUEST UEVENTD NULL STDIO SUMMARY: verified-exec-images=%lu complete-sequences=%lu; actor requires committed ARM32 ELF at app-private backing path, euid=0, guest parent PID1 and /sbin/ueventd; completion requires exact mknod/open/unlink/dup2-0,1,2/close-source-FD, no host device\n",
           guest_ueventd_exec_image_validated_count,
           guest_ueventd_null_stdio_ready_count);
    printf("GUEST KMSG SUMMARY: node-present=%d unlinked=%d fd=%d fd-open=%d cloexec=%d mknod-attempts=%llu accepted=%llu rejected=%llu open-attempts=%llu succeeded=%llu failed=%llu fcntl-setfd=%llu/%llu unlink=%llu/%llu writes=%llu bytes=%llu closes=%llu close-on-exec=%llu diagnostics=%lu; API10 /init char 1:11 mode 0600, in-memory guest node/FD and discarded log bytes only; host /dev/kmsg untouched\n",
           guest_kmsg_runtime.node_present, guest_kmsg_runtime.unlinked,
           guest_kmsg_runtime.fd, guest_kmsg_runtime.fd_open,
           guest_kmsg_runtime.fd_cloexec,
           (unsigned long long)guest_kmsg_runtime.mknod_attempts,
           (unsigned long long)guest_kmsg_runtime.mknod_accepted,
           (unsigned long long)guest_kmsg_runtime.mknod_rejected,
           (unsigned long long)guest_kmsg_runtime.open_attempts,
           (unsigned long long)guest_kmsg_runtime.open_succeeded,
           (unsigned long long)guest_kmsg_runtime.open_failed,
           (unsigned long long)guest_kmsg_runtime.fcntl_setfd_succeeded,
           (unsigned long long)guest_kmsg_runtime.fcntl_setfd_attempts,
           (unsigned long long)guest_kmsg_runtime.unlink_succeeded,
           (unsigned long long)guest_kmsg_runtime.unlink_attempts,
           (unsigned long long)guest_kmsg_runtime.write_calls,
           (unsigned long long)guest_kmsg_runtime.write_bytes,
           (unsigned long long)guest_kmsg_runtime.close_calls,
           (unsigned long long)guest_kmsg_runtime.close_on_exec_calls,
           guest_kmsg_diagnostics_emitted);
    printf("GUEST VIRTUAL FD DUP DENIALS: %lu; unsupported virtual descriptors fail closed, host dup/dup2 not used\n",
           virtual_fd_duplicate_denials);
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
    printf("GUEST PROCESS/TIME COMPAT: setpgid=%lu guest-only; setrlimit=%lu RLIMIT_NICE only; ioprio_set=%lu process-only; getpgid=%lu guest PID table; wait4=%lu API10 ARM waitpid path; SIGCHLD forwarded=%lu direct-unreaped peak=%zu; settimeofday=%lu timezone-only; host process groups/IO priority/wall clock unchanged\n",
           guest_setpgid_calls, guest_setrlimit_calls, guest_ioprio_set_calls,
           guest_getpgid_calls, guest_wait4_calls, guest_sigchld_deliveries,
           guest_unreaped_child_peak, guest_timezone_calls);
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
    char marker_relative[PATH_MAX] = "<unavailable>";
    int marker_backing_contained = coldboot_marker_runtime.backing_path[0] &&
        path_is_within(coldboot_marker_runtime.backing_path, guest_root);
    if (marker_backing_contained) {
        size_t root_length = strlen(guest_root);
        const char *suffix = coldboot_marker_runtime.backing_path + root_length;
        if (*suffix == '\0') suffix = "/";
        if (snprintf(marker_relative, sizeof(marker_relative), "%s", suffix) >=
            (int)sizeof(marker_relative)) {
            marker_backing_contained = 0;
            snprintf(marker_relative, sizeof(marker_relative), "<too-long>");
        }
    }
    const char *marker_leaf_type = coldboot_marker_runtime.last_lstat_observed &&
        coldboot_marker_runtime.last_lstat_result == 0
        ? guest_coldboot_file_type(coldboot_marker_runtime.last_lstat.st_mode)
        : "not-present-or-inaccessible";
    printf("GUEST COLD-BOOT MARKER FILE SUMMARY: open-seen=%d flags=0x%x mode-arg=0%o args-match=%d open-result=%d guest-fd=%d close-seen=%d close-result=%d marker-close-observed=%d writes=%lu fsyncs=%lu fdatasyncs=%lu backing-contained=%d backing=guest-root:%s lstat-observed=%d lstat-result=%d lstat-errno=%d leaf-type=%s mode=0%o inode=%llu size=%lld; metadata uses lstat beneath app-private guest root; API10 devices.c performs no marker write/fsync before close\n",
           coldboot_marker_runtime.open_seen, coldboot_marker_runtime.open_flags,
           coldboot_marker_runtime.open_mode,
           guest_coldboot_marker_open_args_valid(
               coldboot_marker_runtime.open_flags,
               coldboot_marker_runtime.open_mode),
           coldboot_marker_runtime.open_result, coldboot_marker_runtime.guest_fd,
           coldboot_marker_runtime.close_seen, coldboot_marker_runtime.close_result,
           coldboot_observation.marker_close_observed,
           coldboot_marker_runtime.write_calls, coldboot_marker_runtime.fsync_calls,
           coldboot_marker_runtime.fdatasync_calls, marker_backing_contained,
           marker_relative, coldboot_marker_runtime.last_lstat_observed,
           coldboot_marker_runtime.last_lstat_result,
           coldboot_marker_runtime.last_lstat_errno, marker_leaf_type,
           coldboot_marker_runtime.last_lstat_observed &&
               coldboot_marker_runtime.last_lstat_result == 0
                   ? (unsigned)coldboot_marker_runtime.last_lstat.st_mode : 0u,
           coldboot_marker_runtime.last_lstat_observed &&
               coldboot_marker_runtime.last_lstat_result == 0
                   ? (unsigned long long)coldboot_marker_runtime.last_lstat.st_ino : 0ull,
           coldboot_marker_runtime.last_lstat_observed &&
               coldboot_marker_runtime.last_lstat_result == 0
                   ? (long long)coldboot_marker_runtime.last_lstat.st_size : 0ll);
    printf("GUEST GOLDFISH TTY SUMMARY: profile=synthetic dev=%u:0-%u qemud=/dev/ttyS1 qemud-service-binds=%lu listener-fd=%d synthetic-dev=%u:%u events=%lu event-mask=0x%02x mknod-attempts=%lu nodes-created=%lu node-mask=0x%02x opens=%lu tty-open=%d TCGETS=%lu TCSETS=%lu empty-reads=%lu writes-without-peer=%lu epoll-create-attempts=%lu epoll-ctl=%lu empty-waits=%lu unsupported=%lu diagnostics-emitted=%u; Goldfish runtime major is unknown/not claimed; no serial peer/data or emulator reply is modeled; host tty/mknod/epoll calls=0\n",
           GUEST_GOLDFISH_TTY_SYNTHETIC_MAJOR,
           GUEST_GOLDFISH_TTY_LINE_COUNT - 1u,
           guest_qemud_socket_bind_count,
           guest_sockets.qemud_listener_fd,
           GUEST_GOLDFISH_TTY_SYNTHETIC_MAJOR,
           GUEST_GOLDFISH_TTY_QEMUD_MINOR,
           guest_goldfish_tty_runtime.events_received,
           guest_goldfish_tty_runtime.uevent_mask,
           guest_goldfish_tty_runtime.mknod_attempts,
           guest_goldfish_tty_runtime.nodes_created,
           guest_goldfish_tty_runtime.node_mask,
           guest_goldfish_tty_runtime.open_attempts,
           guest_goldfish_tty_runtime.tty_fd >= 0,
           guest_goldfish_tty_runtime.ioctl_gets,
           guest_goldfish_tty_runtime.ioctl_sets,
           guest_goldfish_tty_runtime.empty_reads,
           guest_goldfish_tty_runtime.writes_without_peer,
           guest_goldfish_tty_runtime.epoll_creates,
           guest_goldfish_tty_runtime.epoll_controls,
           guest_goldfish_tty_runtime.epoll_empty_waits,
           guest_goldfish_tty_runtime.unsupported,
           guest_goldfish_tty_diagnostics_emitted);
    printf("VIRTUAL PROPERTY STREAM SUMMARY: ARM sendto=%lu bytes=%lu recvfrom=%lu bytes=%lu errors=%lu diagnostics-emitted=%lu (limit=64); fixed API10 setprop request size=128 bytes; sendto/recvfrom supported only with flags=0 and NULL address outputs/inputs\n",
           virtual_property_sendto_count, virtual_property_sendto_bytes,
           virtual_property_recvfrom_count, virtual_property_recvfrom_bytes,
           virtual_property_stream_errors, virtual_property_stream_diagnostics);
    printf("GUEST FB0 OUTPUT SUMMARY: backend-ready=%d graphics-uevent-received=%d node-created=%d opens=%lu ioctls=%lu mmap2=%lu page-flips=%lu software-base-update-acks=%lu; channel-ready=%d frames-published=%lu; producer bytes come only from guest MAP_SHARED backing; Binder/SurfaceFlinger/framework/desktop remain unproven\n",
           guest_fb0_backend_ready, guest_fb0_graphics_uevent_received,
           guest_fb0_node_created, guest_fb0_open_count, guest_fb0_ioctl_count,
           guest_fb0_mmap_count, guest_fb0_pan_count,
           guest_fb0_model.software_base_update_acks,
           guest_frame_channel_ready, guest_frame_published_count);
    printf("VIRTUAL AF_UNIX/SIGNAL SOCKET SUMMARY: created=%lu property-binds=%lu property-connects=%lu property-accepts=%lu signal-pairs=%lu; host AF_UNIX socket/socketpair/bind/connect/listen/accept/setsockopt/getsockopt/send/recv/sendto/recvfrom calls=0\n",
           virtual_af_unix_socket_count, virtual_property_bind_count,
           virtual_property_connect_count, virtual_property_accept_count,
           virtual_socketpair_count);
    if (strcmp(guest_program, "/init") == 0 && (trace_timed_out || trace_cancelled))
        printf("INIT COLD-BOOT MARKER DETAILS: open-seen=%d open-result=%d flags=0x%x mode=0%o; close-seen=%d close-result=%d writes=%lu fsyncs=%lu fdatasyncs=%lu; final-contained-nofollow-stat-observed=%d result=%d errno=%d type=%s permissions=0%04o inode=%llu size=%lld\n",
               coldboot_marker_runtime.open_seen,
               coldboot_marker_runtime.open_result,
               coldboot_marker_runtime.open_flags,
               coldboot_marker_runtime.open_mode,
               coldboot_marker_runtime.close_seen,
               coldboot_marker_runtime.close_result,
               coldboot_marker_runtime.write_calls,
               coldboot_marker_runtime.fsync_calls,
               coldboot_marker_runtime.fdatasync_calls,
               coldboot_marker_runtime.last_lstat_observed,
               coldboot_marker_runtime.last_lstat_result,
               coldboot_marker_runtime.last_lstat_errno,
               coldboot_marker_runtime.last_lstat_observed &&
                       coldboot_marker_runtime.last_lstat_result == 0
                   ? guest_coldboot_file_type(coldboot_marker_runtime.last_lstat.st_mode)
                   : "unavailable",
               coldboot_marker_runtime.last_lstat_observed &&
                       coldboot_marker_runtime.last_lstat_result == 0
                   ? (unsigned)(coldboot_marker_runtime.last_lstat.st_mode & 07777u)
                   : 0u,
               coldboot_marker_runtime.last_lstat_observed &&
                       coldboot_marker_runtime.last_lstat_result == 0
                   ? (unsigned long long)coldboot_marker_runtime.last_lstat.st_ino
                   : 0ull,
               coldboot_marker_runtime.last_lstat_observed &&
                       coldboot_marker_runtime.last_lstat_result == 0
                   ? (long long)coldboot_marker_runtime.last_lstat.st_size
                   : 0ll);
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
    if (guest_qemud_exec_count)
        printf("GUEST QEMUD DIAGNOSTIC RUN BUDGET: emitted=%u suppressed=%u maximum=%u per-process-record-cap=%u; suppressed details are counted, not replayed\n",
               guest_qemud_diag_run_budget.emitted,
               guest_qemud_diag_run_budget.suppressed,
               GUEST_QEMUD_DIAG_RUN_MAX_LINES,
               GUEST_QEMUD_DIAG_MAX_RECORDS);
    printf("HOST PRIVILEGED MOUNTS: 0 (host mount/umount were never invoked)\n");
    if (guest_frame_directory_fd >= 0) {
        if (close(guest_frame_directory_fd) != 0)
            fprintf(stderr, "GUEST FRAME CHANNEL CLOSE: validated directory fd close failed errno=%d\n", errno);
        guest_frame_directory_fd = -1;
    }
    if (rc != 0) return 1;
    if (!saw_exec) return 1;
    if (trace_cancelled) return exit_code == 130 ? 130 : 1;
    if (dynamic_exec_blocked) return 3;
    if (process_limit_hit) return 4;
    if (exit_signal) return 128 + exit_signal;
    if (exit_code > 0) return 1;
    return 0;
}
