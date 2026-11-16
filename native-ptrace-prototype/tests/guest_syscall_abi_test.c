#include <assert.h>
#include <stdint.h>

#include "../app/src/main/cpp/guest_syscall_abi.h"

int main(void) {
    assert(!guest_arm32_syscall_result_is_error(0u));
    assert(!guest_arm32_syscall_result_is_error(0x7fffffffu));
    assert(!guest_arm32_syscall_result_is_error(0xe9380000u));
    assert(!guest_arm32_syscall_result_is_error(0xf3641000u));
    assert(!guest_arm32_syscall_result_is_error(0xf7cca000u));
    assert(guest_arm32_syscall_result_errno(0xe9380000u) == 0u);

    assert(guest_arm32_syscall_result_is_error(0xfffff001u)); /* -4095 */
    assert(guest_arm32_syscall_result_is_error(0xffffffeaU)); /* -EINVAL */
    assert(guest_arm32_syscall_result_is_error(0xffffffffu)); /* -1 */
    assert(guest_arm32_syscall_result_errno(0xffffffeaU) == 22u);
    assert(!guest_arm32_syscall_result_is_error(0xfffff000u)); /* -4096 is outside errno range */
    return 0;
}
