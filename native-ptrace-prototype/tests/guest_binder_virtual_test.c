#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>

#include "../app/src/main/cpp/guest_binder_virtual.h"

#define MOCK_MEMORY_BYTES 4096u
struct mock_memory { unsigned char bytes[MOCK_MEMORY_BYTES]; };

static int mock_copyin(void *opaque, uint32_t address, void *destination, size_t length) {
    struct mock_memory *memory = opaque;
    if (!memory || address > MOCK_MEMORY_BYTES || length > MOCK_MEMORY_BYTES - address)
        return -EFAULT;
    memcpy(destination, memory->bytes + address, length);
    return 0;
}

static int mock_copyout(void *opaque, uint32_t address, const void *source, size_t length) {
    struct mock_memory *memory = opaque;
    if (!memory || address > MOCK_MEMORY_BYTES || length > MOCK_MEMORY_BYTES - address)
        return -EFAULT;
    memcpy(memory->bytes + address, source, length);
    return 0;
}

int main(void) {
    assert(sizeof(guest_arm32_binder_write_read) == 24);
    assert(GUEST_BINDER_IOCTL_WRITE_READ == 0xc0186201u);
    assert(GUEST_BINDER_IOCTL_VERSION == 0xc0046209u);
    assert(GUEST_BINDER_IOCTL_SET_CONTEXT_MGR == 0x40046207u);
    assert(GUEST_BINDER_BC_ENTER_LOOPER == 0x630cu);
    assert(GUEST_BINDER_BC_TRANSACTION == 0x40286300u);
    assert(guest_binder_validate_open_flags(O_RDWR | O_CLOEXEC) == 0);
    assert(guest_binder_validate_open_flags(O_RDONLY | O_CLOEXEC) == -EACCES);
    assert(guest_binder_validate_open_flags(O_RDWR | O_CREAT) == -EINVAL);

    assert(guest_binder_validate_mmap(GUEST_BINDER_SERVICEMANAGER_MAP_BYTES,
        PROT_READ, MAP_PRIVATE, 5000, 0, 1) == 0);
    assert(guest_binder_validate_mmap(GUEST_BINDER_PROCESS_MAP_BYTES,
        PROT_READ, MAP_PRIVATE | MAP_NORESERVE, 5000, 0, 1) == 0);
    assert(guest_binder_validate_mmap(GUEST_BINDER_SERVICEMANAGER_MAP_BYTES,
        PROT_READ | PROT_WRITE, MAP_PRIVATE, 5000, 0, 1) == -EACCES);
    assert(guest_binder_validate_mmap(GUEST_BINDER_SERVICEMANAGER_MAP_BYTES,
        PROT_READ, MAP_SHARED, 5000, 0, 1) == -EINVAL);
    assert(guest_binder_validate_mmap(GUEST_BINDER_SERVICEMANAGER_MAP_BYTES,
        PROT_READ, MAP_PRIVATE, 5000, 1, 1) == -EINVAL);
    assert(guest_binder_validate_mmap(GUEST_BINDER_SERVICEMANAGER_MAP_BYTES,
        PROT_READ, MAP_PRIVATE, 5000, 0, 0) == -EBADF);
    assert(guest_binder_validate_mmap(65536, PROT_READ, MAP_PRIVATE,
        5000, 0, 1) == -EINVAL);

    struct guest_binder_process_state process = {0};
    struct guest_binder_global_state global = {0};
    struct mock_memory memory = {0};
    int parked = 0;
    uint32_t zero = 0;
    uint32_t max_threads = 15;
    memcpy(memory.bytes + 1024, &zero, sizeof(zero));
    memcpy(memory.bytes + 1028, &max_threads, sizeof(max_threads));
    assert(guest_binder_note_mapping(&process, 0x10000000u,
        GUEST_BINDER_SERVICEMANAGER_MAP_BYTES) == 0);
    assert(guest_binder_note_mapping(&process, 0x20000000u,
        GUEST_BINDER_PROCESS_MAP_BYTES) == -EBUSY);

    assert(guest_binder_ioctl_bootstrap(&process, &global, 42,
        GUEST_BINDER_IOCTL_VERSION, 1100, mock_copyin, mock_copyout,
        &memory, &parked) == 0);
    guest_arm32_binder_version version;
    memcpy(&version, memory.bytes + 1100, sizeof(version));
    assert(version.protocol_version == 7 && process.version_queries == 1);
    assert(global.version_queries == 1 && global.ioctl_calls == 1);

    assert(guest_binder_ioctl_bootstrap(&process, &global, 42,
        GUEST_BINDER_IOCTL_SET_MAX_THREADS, 1028, mock_copyin, mock_copyout,
        &memory, &parked) == 0);
    assert(process.max_threads == 15);
    assert(guest_binder_ioctl_bootstrap(&process, &global, 42,
        GUEST_BINDER_IOCTL_SET_CONTEXT_MGR, 0, mock_copyin, mock_copyout,
        &memory, &parked) == 0);
    assert(global.context_manager_guest_pid == 42 && global.context_manager_claims == 1);
    assert(guest_binder_ioctl_bootstrap(&process, &global, 43,
        GUEST_BINDER_IOCTL_SET_CONTEXT_MGR, 0, mock_copyin, mock_copyout,
        &memory, &parked) == -EBUSY);
    assert(global.context_manager_conflicts == 1);
    assert(guest_binder_ioctl_bootstrap(&process, &global, 43,
        GUEST_BINDER_IOCTL_SET_CONTEXT_MGR, 1024, mock_copyin, mock_copyout,
        &memory, &parked) == -EINVAL);

    uint32_t enter = GUEST_BINDER_BC_ENTER_LOOPER;
    memcpy(memory.bytes + 512, &enter, sizeof(enter));
    guest_arm32_binder_write_read request = {
        .write_size = 4, .write_consumed = 0, .write_buffer = 512,
        .read_size = 0, .read_consumed = 0, .read_buffer = 0
    };
    memcpy(memory.bytes + 128, &request, sizeof(request));
    assert(guest_binder_ioctl_bootstrap(&process, &global, 42,
        GUEST_BINDER_IOCTL_WRITE_READ, 128, mock_copyin, mock_copyout,
        &memory, &parked) == 0);
    assert(parked == 0 && process.loop_entered == 1 && process.loop_commands == 1);
    assert(global.loop_commands == 1);
    memcpy(&request, memory.bytes + 128, sizeof(request));
    assert(request.write_consumed == 4 && request.read_consumed == 0);

    request = (guest_arm32_binder_write_read){
        .write_size = 0, .write_consumed = 0, .write_buffer = 0,
        .read_size = 64, .read_consumed = 0, .read_buffer = 640
    };
    memcpy(memory.bytes + 128, &request, sizeof(request));
    assert(guest_binder_ioctl_bootstrap(&process, &global, 42,
        GUEST_BINDER_IOCTL_WRITE_READ, 128, mock_copyin, mock_copyout,
        &memory, &parked) == 0);
    assert(parked == GUEST_BINDER_READ_PARKED && process.empty_reads_parked == 1);
    assert(global.empty_reads_parked == 1);
    memcpy(&request, memory.bytes + 128, sizeof(request));
    assert(request.write_consumed == 0 && request.read_consumed == 0);

    uint32_t transaction = GUEST_BINDER_BC_TRANSACTION; /* BC_TRANSACTION: not implemented. */
    memcpy(memory.bytes + 512, &transaction, sizeof(transaction));
    request = (guest_arm32_binder_write_read){
        .write_size = 4, .write_consumed = 0, .write_buffer = 512,
        .read_size = 0, .read_consumed = 0, .read_buffer = 0
    };
    memcpy(memory.bytes + 128, &request, sizeof(request));
    assert(guest_binder_ioctl_bootstrap(&process, &global, 42,
        GUEST_BINDER_IOCTL_WRITE_READ, 128, mock_copyin, mock_copyout,
        &memory, &parked) == -EOPNOTSUPP);
    assert(global.unsupported_transactions == 1 && global.unsupported_commands == 1 &&
           process.loop_commands == 1);
    memcpy(&request, memory.bytes + 128, sizeof(request));
    assert(request.write_consumed == 0);

    request = (guest_arm32_binder_write_read){
        .write_size = 2, .write_consumed = 0, .write_buffer = 512,
        .read_size = 0, .read_consumed = 0, .read_buffer = 0
    };
    memcpy(memory.bytes + 128, &request, sizeof(request));
    assert(guest_binder_ioctl_bootstrap(&process, &global, 42,
        GUEST_BINDER_IOCTL_WRITE_READ, 128, mock_copyin, mock_copyout,
        &memory, &parked) == -EINVAL);
    request = (guest_arm32_binder_write_read){
        .write_size = 0, .write_consumed = 0, .write_buffer = 0,
        .read_size = 4, .read_consumed = 0, .read_buffer = 0
    };
    memcpy(memory.bytes + 128, &request, sizeof(request));
    assert(guest_binder_ioctl_bootstrap(&process, &global, 42,
        GUEST_BINDER_IOCTL_WRITE_READ, 128, mock_copyin, mock_copyout,
        &memory, &parked) == -EFAULT);
    request = (guest_arm32_binder_write_read){
        .write_size = 4, .write_consumed = 0, .write_buffer = 0,
        .read_size = 0, .read_consumed = 0, .read_buffer = 0
    };
    memcpy(memory.bytes + 128, &request, sizeof(request));
    assert(guest_binder_ioctl_bootstrap(&process, &global, 42,
        GUEST_BINDER_IOCTL_WRITE_READ, 128, mock_copyin, mock_copyout,
        &memory, &parked) == -EFAULT);
    assert(guest_binder_ioctl_bootstrap(&process, &global, 42,
        GUEST_BINDER_IOCTL_VERSION, UINT32_MAX - 1u, mock_copyin, mock_copyout,
        &memory, &parked) == -EFAULT);
    assert(guest_binder_ioctl_bootstrap(&process, &global, 42,
        0xdeadbeefu, 0, mock_copyin, mock_copyout, &memory, &parked) == -ENOTTY);
    assert(guest_binder_note_unmap(&process, 0x10000000u,
        GUEST_BINDER_SERVICEMANAGER_MAP_BYTES) == 0);
    assert(!process.mapping_valid);
    guest_binder_process_exec_reset(&process);
    puts("guest_binder_virtual_test: PASS (API10 bootstrap only; no Binder transactions)");
    return 0;
}
