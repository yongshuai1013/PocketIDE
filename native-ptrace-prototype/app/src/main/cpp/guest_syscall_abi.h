#ifndef GINGERVM_GUEST_SYSCALL_ABI_H
#define GINGERVM_GUEST_SYSCALL_ABI_H

#include <stdint.h>

#define GUEST_LINUX_MAX_ERRNO 4095u
#define GUEST_ARM32_ERRNO_MIN 0xfffff001u

/* ARM32 mmap returns a 32-bit user pointer; high-bit pointers are not errno. */
static inline int guest_arm32_syscall_result_is_error(uint32_t result_bits) {
    return result_bits >= GUEST_ARM32_ERRNO_MIN;
}

static inline uint32_t guest_arm32_syscall_result_errno(uint32_t result_bits) {
    return guest_arm32_syscall_result_is_error(result_bits) ? 0u - result_bits : 0u;
}

#endif
