#ifndef GINGERVM_GUEST_SIGACTION_COMPAT_H
#define GINGERVM_GUEST_SIGACTION_COMPAT_H

#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define GUEST_ARM32_RT_SIGSET_SIZE 8u

struct guest_arm32_legacy_sigaction {
    uint32_t handler;
    uint32_t mask;
    uint32_t flags;
    uint32_t restorer;
};

struct guest_arm32_rt_sigaction {
    uint32_t handler;
    uint32_t flags;
    uint32_t restorer;
    uint32_t mask[2];
};

static inline int guest_sigaction_legacy_to_rt(
        const struct guest_arm32_legacy_sigaction *legacy,
        struct guest_arm32_rt_sigaction *rt) {
    if (!legacy || !rt) return -EINVAL;
    memset(rt, 0, sizeof(*rt));
    rt->handler = legacy->handler;
    rt->flags = legacy->flags;
    rt->restorer = legacy->restorer;
    rt->mask[0] = legacy->mask;
    /* The legacy ARM ABI exposes only its low 32 signal-mask bits. */
    rt->mask[1] = 0;
    return 0;
}

static inline int guest_sigaction_rt_to_legacy(
        const struct guest_arm32_rt_sigaction *rt,
        struct guest_arm32_legacy_sigaction *legacy) {
    if (!legacy || !rt) return -EINVAL;
    legacy->handler = rt->handler;
    legacy->mask = rt->mask[0];
    legacy->flags = rt->flags;
    legacy->restorer = rt->restorer;
    return 0;
}

#endif
