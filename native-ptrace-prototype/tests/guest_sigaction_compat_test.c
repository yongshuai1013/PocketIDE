#include <assert.h>
#include <stdint.h>
#include <stdio.h>

#include "../app/src/main/cpp/guest_sigaction_compat.h"

int main(void) {
    assert(sizeof(struct guest_arm32_legacy_sigaction) == 16);
    assert(sizeof(struct guest_arm32_rt_sigaction) == 20);
    assert(GUEST_ARM32_RT_SIGSET_SIZE == 8);

    struct guest_arm32_legacy_sigaction legacy = {
        .handler = 0x12345678u,
        .mask = 0x80000021u,
        .flags = 0x04000000u,
        .restorer = 0x87654321u,
    };
    struct guest_arm32_rt_sigaction rt;
    assert(guest_sigaction_legacy_to_rt(&legacy, &rt) == 0);
    assert(rt.handler == legacy.handler);
    assert(rt.flags == legacy.flags);
    assert(rt.restorer == legacy.restorer);
    assert(rt.mask[0] == legacy.mask);
    assert(rt.mask[1] == 0); /* legacy struct has only the low 32 signal bits */

    struct guest_arm32_rt_sigaction returned = {
        .handler = 0x10203040u,
        .flags = 0x01000000u,
        .restorer = 0x50607080u,
        .mask = {0xA5A55A5Au, 0xFFFFFFFFu},
    };
    struct guest_arm32_legacy_sigaction old;
    assert(guest_sigaction_rt_to_legacy(&returned, &old) == 0);
    assert(old.handler == returned.handler);
    assert(old.mask == returned.mask[0]);
    assert(old.flags == returned.flags);
    assert(old.restorer == returned.restorer);

    assert(guest_sigaction_legacy_to_rt(NULL, &rt) == -EINVAL);
    assert(guest_sigaction_rt_to_legacy(&returned, NULL) == -EINVAL);
    puts("ARM32 legacy sigaction compatibility regression: PASS (16-byte legacy / 20-byte rt ABI, 8-byte rt mask, low-word semantics)");
    return 0;
}
