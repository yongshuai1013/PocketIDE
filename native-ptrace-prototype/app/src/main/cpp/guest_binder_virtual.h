#ifndef GINGERVM_GUEST_BINDER_VIRTUAL_H
#define GINGERVM_GUEST_BINDER_VIRTUAL_H

#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>

/* Android 2.3.7_r1 ARM32 Binder UAPI, from Goldfish 2.6.29 binder.h.
 * These constants deliberately encode 32-bit guest structures; AArch64 host
 * ioctl values and sizeof(long) are not used for guest dispatch. */
#define GUEST_BINDER_PROTOCOL_VERSION 7
#define GUEST_BINDER_IOCTL_WRITE_READ 0xc0186201u
#define GUEST_BINDER_IOCTL_SET_MAX_THREADS 0x40046205u
#define GUEST_BINDER_IOCTL_SET_CONTEXT_MGR 0x40046207u
#define GUEST_BINDER_IOCTL_THREAD_EXIT 0x40046208u
#define GUEST_BINDER_IOCTL_VERSION 0xc0046209u
#define GUEST_BINDER_BC_REGISTER_LOOPER 0x0000630bu
#define GUEST_BINDER_BC_ENTER_LOOPER 0x0000630cu
#define GUEST_BINDER_BC_EXIT_LOOPER 0x0000630du
#define GUEST_BINDER_BC_TRANSACTION 0x40286300u
#define GUEST_BINDER_BC_REPLY 0x40286301u
#define GUEST_BINDER_SERVICEMANAGER_MAP_BYTES (128u * 1024u)
#define GUEST_BINDER_PROCESS_MAP_BYTES ((1024u * 1024u) - (2u * 4096u))
#define GUEST_BINDER_MAX_WRITE_BYTES (64u * 1024u)
#define GUEST_BINDER_READ_PARKED 1

typedef struct guest_arm32_binder_write_read {
    int32_t write_size;
    int32_t write_consumed;
    uint32_t write_buffer;
    int32_t read_size;
    int32_t read_consumed;
    uint32_t read_buffer;
} guest_arm32_binder_write_read;

typedef struct guest_arm32_binder_version {
    int32_t protocol_version;
} guest_arm32_binder_version;

struct guest_binder_process_state {
    int mapping_valid;
    uint32_t mapping_start;
    uint32_t mapping_length;
    uint32_t max_threads;
    int loop_entered;
    unsigned long version_queries;
    unsigned long ioctl_count;
    unsigned long loop_commands;
    unsigned long empty_reads_parked;
    unsigned long unsupported_commands;
};

struct guest_binder_global_state {
    int32_t context_manager_guest_pid;
    unsigned long opens;
    unsigned long ioctl_calls;
    unsigned long version_queries;
    unsigned long mapping_successes;
    unsigned long context_manager_claims;
    unsigned long context_manager_conflicts;
    unsigned long loop_commands;
    unsigned long empty_reads_parked;
    unsigned long unsupported_commands;
    unsigned long unsupported_transactions;
};

typedef int (*guest_binder_copyin_fn)(void *context, uint32_t address,
                                      void *destination, size_t length);
typedef int (*guest_binder_copyout_fn)(void *context, uint32_t address,
                                       const void *source, size_t length);

_Static_assert(sizeof(guest_arm32_binder_write_read) == 24,
               "API10 ARM32 binder_write_read must remain 24 bytes");
_Static_assert(offsetof(guest_arm32_binder_write_read, write_buffer) == 8,
               "API10 ARM32 Binder write_buffer offset mismatch");
_Static_assert(offsetof(guest_arm32_binder_write_read, read_buffer) == 20,
               "API10 ARM32 Binder read_buffer offset mismatch");
_Static_assert(sizeof(guest_arm32_binder_version) == 4,
               "API10 ARM32 binder_version must remain 4 bytes");

static inline int guest_binder_validate_open_flags(uint32_t flags) {
    uint32_t allowed = (uint32_t)O_ACCMODE | (uint32_t)O_CLOEXEC;
#ifdef O_LARGEFILE
    allowed |= (uint32_t)O_LARGEFILE;
#endif
    if ((flags & (uint32_t)O_ACCMODE) != (uint32_t)O_RDWR) return -EACCES;
    if ((flags & ~allowed) != 0) return -EINVAL;
    return 0;
}

static inline int guest_binder_validate_mmap(uint32_t length, uint32_t prot,
                                            uint32_t flags, int32_t fd,
                                            uint32_t offset_pages,
                                            int binder_fd_owned) {
    if (!binder_fd_owned || fd < 0) return -EBADF;
    if (length != GUEST_BINDER_SERVICEMANAGER_MAP_BYTES &&
        length != GUEST_BINDER_PROCESS_MAP_BYTES) return -EINVAL;
    if (prot != (uint32_t)PROT_READ) return -EACCES;
    uint32_t allowed = (uint32_t)MAP_PRIVATE;
#ifdef MAP_NORESERVE
    allowed |= (uint32_t)MAP_NORESERVE;
#endif
    if ((flags & (uint32_t)MAP_PRIVATE) == 0 ||
        (flags & (uint32_t)MAP_SHARED) != 0 || (flags & ~allowed) != 0)
        return -EINVAL;
    if (offset_pages != 0) return -EINVAL;
    return 0;
}

static inline void guest_binder_process_exec_reset(
        struct guest_binder_process_state *state) {
    if (!state) return;
    state->mapping_valid = 0;
    state->mapping_start = 0;
    state->mapping_length = 0;
    state->max_threads = 0;
    state->loop_entered = 0;
}

static inline int guest_binder_note_mapping(
        struct guest_binder_process_state *state, uint32_t address,
        uint32_t length) {
    if (!state || address == 0 ||
        (length != GUEST_BINDER_SERVICEMANAGER_MAP_BYTES &&
         length != GUEST_BINDER_PROCESS_MAP_BYTES) ||
        (uint64_t)address + length > UINT32_MAX)
        return -EINVAL;
    if (state->mapping_valid) return -EBUSY;
    state->mapping_start = address;
    state->mapping_length = length;
    state->mapping_valid = 1;
    return 0;
}

static inline int guest_binder_note_unmap(
        struct guest_binder_process_state *state, uint32_t address,
        uint32_t length) {
    if (!state || !state->mapping_valid || address != state->mapping_start ||
        length < state->mapping_length) return -EINVAL;
    state->mapping_valid = 0;
    state->mapping_start = 0;
    state->mapping_length = 0;
    state->loop_entered = 0;
    return 0;
}

static inline int guest_binder_u32_range_valid(uint32_t address, size_t length) {
    if (length == 0) return 1;
    return address != 0 && length <= UINT32_MAX &&
           (uint64_t)address + (uint64_t)length - 1u <= UINT32_MAX;
}

static inline int guest_binder_ioctl_write_read(
        struct guest_binder_process_state *process,
        struct guest_binder_global_state *global, int32_t guest_pid,
        uint32_t argument, guest_binder_copyin_fn copyin,
        guest_binder_copyout_fn copyout, void *copy_context, int *park_read) {
    (void)guest_pid;
    if (!process || !global || !copyin || !copyout || !park_read ||
        !guest_binder_u32_range_valid(argument,
            sizeof(guest_arm32_binder_write_read))) return -EFAULT;
    *park_read = 0;
    guest_arm32_binder_write_read request;
    if (copyin(copy_context, argument, &request, sizeof(request)) != 0) return -EFAULT;
    if (request.write_size < 0 || request.read_size < 0 ||
        (uint32_t)request.write_size > GUEST_BINDER_MAX_WRITE_BYTES ||
        request.read_size > (int32_t)GUEST_BINDER_PROCESS_MAP_BYTES ||
        request.write_consumed != 0 || request.read_consumed != 0) return -EINVAL;
    if (!guest_binder_u32_range_valid(request.write_buffer,
                                      (size_t)request.write_size) ||
        !guest_binder_u32_range_valid(request.read_buffer,
                                      (size_t)request.read_size)) return -EFAULT;
    if (!process->mapping_valid || process->mapping_length == 0) return -EINVAL;

    unsigned char commands[GUEST_BINDER_MAX_WRITE_BYTES];
    if (request.write_size > 0 &&
        copyin(copy_context, request.write_buffer, commands,
               (size_t)request.write_size) != 0) return -EFAULT;

    /* Validate the whole command stream before changing looper state. Only the
     * three source-defined looper control words are implemented. In particular,
     * BC_TRANSACTION and every unknown command fail closed without consumption. */
    int next_loop_entered = process->loop_entered;
    size_t offset = 0;
    while (offset < (size_t)request.write_size) {
        if ((size_t)request.write_size - offset < sizeof(uint32_t))
            return -EINVAL;
        uint32_t command;
        memcpy(&command, commands + offset, sizeof(command));
        if (command == GUEST_BINDER_BC_ENTER_LOOPER ||
            command == GUEST_BINDER_BC_REGISTER_LOOPER) {
            next_loop_entered = 1;
        } else if (command == GUEST_BINDER_BC_EXIT_LOOPER) {
            next_loop_entered = 0;
        } else {
            process->unsupported_commands++;
            global->unsupported_commands++;
            if ((command & 0x0000ffffu) == 0x00006300u ||
                (command & 0x0000ffffu) == 0x00006301u)
                global->unsupported_transactions++;
            return -EOPNOTSUPP;
        }
        offset += sizeof(uint32_t);
    }

    process->loop_entered = next_loop_entered;
    unsigned long accepted_commands = (unsigned long)(request.write_size /
        (int32_t)sizeof(uint32_t));
    process->loop_commands += accepted_commands;
    global->loop_commands += accepted_commands;

    if (request.read_size > 0) {
        /* No Binder transaction/event queue exists yet. Park the tracee at this
         * syscall-entry stop; do not return a false empty success, write a
         * completed ioctl result, or busy-loop. */
        process->empty_reads_parked++;
        global->empty_reads_parked++;
        *park_read = GUEST_BINDER_READ_PARKED;
        return 0;
    }
    request.write_consumed = request.write_size;
    request.read_consumed = 0;
    if (copyout(copy_context, argument, &request, sizeof(request)) != 0) return -EFAULT;
    return 0;
}

static inline int guest_binder_ioctl_bootstrap(
        struct guest_binder_process_state *process,
        struct guest_binder_global_state *global, int32_t guest_pid,
        uint32_t command, uint32_t argument,
        guest_binder_copyin_fn copyin, guest_binder_copyout_fn copyout,
        void *copy_context, int *park_read) {
    if (!process || !global || !park_read) return -EINVAL;
    *park_read = 0;
    process->ioctl_count++;
    global->ioctl_calls++;
    switch (command) {
        case GUEST_BINDER_IOCTL_VERSION: {
            if (!copyout || !guest_binder_u32_range_valid(argument,
                    sizeof(guest_arm32_binder_version))) return -EFAULT;
            guest_arm32_binder_version version = {
                .protocol_version = GUEST_BINDER_PROTOCOL_VERSION
            };
            if (copyout(copy_context, argument, &version, sizeof(version)) != 0)
                return -EFAULT;
            process->version_queries++;
            global->version_queries++;
            return 0;
        }
        case GUEST_BINDER_IOCTL_SET_MAX_THREADS: {
            uint32_t maximum = 0;
            if (!copyin || !guest_binder_u32_range_valid(argument,
                    sizeof(maximum))) return -EFAULT;
            if (copyin(copy_context, argument, &maximum, sizeof(maximum)) != 0)
                return -EFAULT;
            process->max_threads = maximum;
            return 0;
        }
        case GUEST_BINDER_IOCTL_SET_CONTEXT_MGR: {
            /* API10 servicemanager calls ioctl(fd, BINDER_SET_CONTEXT_MGR, 0):
             * the third ioctl argument is a scalar zero, not a user pointer. */
            if (guest_pid <= 0 || argument != 0) return -EINVAL;
            if (!process->mapping_valid) return -EINVAL;
            if (global->context_manager_guest_pid != 0) {
                global->context_manager_conflicts++;
                return -EBUSY;
            }
            global->context_manager_guest_pid = guest_pid;
            global->context_manager_claims++;
            return 0;
        }
        case GUEST_BINDER_IOCTL_WRITE_READ:
            return guest_binder_ioctl_write_read(process, global, guest_pid,
                argument, copyin, copyout, copy_context, park_read);
        case GUEST_BINDER_IOCTL_THREAD_EXIT:
            process->loop_entered = 0;
            return 0;
        default:
            return -ENOTTY;
    }
}

#endif
