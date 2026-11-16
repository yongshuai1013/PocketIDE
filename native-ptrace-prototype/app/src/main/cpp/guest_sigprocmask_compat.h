#ifndef GINGERVM_GUEST_SIGPROCMASK_COMPAT_H
#define GINGERVM_GUEST_SIGPROCMASK_COMPAT_H

#include <errno.h>
#include <stdint.h>
#include <stddef.h>

#define GUEST_ARM_SIGPROCMASK_SIG_BLOCK 0
#define GUEST_ARM_SIGPROCMASK_SIG_UNBLOCK 1
#define GUEST_ARM_SIGPROCMASK_SIG_SETMASK 2
#define GUEST_ARM_SIGPROCMASK_LOW_WORD_MASK UINT64_C(0x00000000ffffffff)
#define GUEST_ARM_SIGPROCMASK_HIGH_WORD_MASK UINT64_C(0xffffffff00000000)
/* ARM API10 numbers: SIGKILL=9 and SIGSTOP=19; those bits are discarded by Linux. */
#define GUEST_ARM_SIGPROCMASK_UNBLOCKABLE_MASK ((UINT32_C(1) << 8) | (UINT32_C(1) << 18))

enum guest_sigprocmask_ptrace_request {
    GUEST_SIGPROCMASK_PTRACE_NONE = 0,
    GUEST_SIGPROCMASK_PTRACE_GET = 1,
    GUEST_SIGPROCMASK_PTRACE_SET = 2,
};

struct guest_sigprocmask_ops {
    void *context;
    /* Return 0 on success; failure is translated to the guest's EFAULT. */
    int (*read_u32)(void *context, uintptr_t address, uint32_t *value);
    int (*write_u32)(void *context, uintptr_t address, uint32_t value);
    /* Operate on the real stopped tracee's complete 64-bit kernel signal mask. */
    int (*get_mask)(void *context, uint64_t *mask);
    int (*set_mask)(void *context, uint64_t mask);
};

struct guest_sigprocmask_report {
    int32_t result;
    int32_t how;
    uint32_t requested_set;
    uint32_t old_set;
    uint64_t mask_before;
    uint64_t mask_after;
    int has_set;
    int has_old_set;
    int mask_read;
    int mask_written;
    int old_set_written;
    int internal_request;
    int internal_errno;
};

static inline int guest_sigprocmask_how_valid(int32_t how) {
    return how == GUEST_ARM_SIGPROCMASK_SIG_BLOCK ||
           how == GUEST_ARM_SIGPROCMASK_SIG_UNBLOCK ||
           how == GUEST_ARM_SIGPROCMASK_SIG_SETMASK;
}

/* Legacy ARM EABI sigprocmask changes only the low 32 bits of the kernel mask. */
static inline uint64_t guest_sigprocmask_apply_low_word(uint64_t current,
                                                        uint32_t requested,
                                                        int32_t how) {
    uint32_t low = (uint32_t)(current & GUEST_ARM_SIGPROCMASK_LOW_WORD_MASK);
    requested &= ~GUEST_ARM_SIGPROCMASK_UNBLOCKABLE_MASK;
    if (how == GUEST_ARM_SIGPROCMASK_SIG_BLOCK) {
        low |= requested;
    } else if (how == GUEST_ARM_SIGPROCMASK_SIG_UNBLOCK) {
        low &= ~requested;
    } else if (how == GUEST_ARM_SIGPROCMASK_SIG_SETMASK) {
        low = requested;
    }
    return (current & GUEST_ARM_SIGPROCMASK_HIGH_WORD_MASK) | (uint64_t)low;
}

/*
 * Faithfully model Linux ARM's old 3-argument syscall:
 * - copy the 4-byte set before validating `how`;
 * - preserve the kernel mask's upper word;
 * - apply the real mask before copying oldset, so bad oldset can return EFAULT
 *   after the mask update;
 * - with set==NULL, ignore `how` and only query oldset if requested;
 * - PTRACE errors are infrastructure failures and return -1, never fake success.
 * Return 0 when `report->result` is a guest-visible result; return -1 only for
 * missing/failed ptrace mask operations or invalid broker configuration.
 */
static inline int guest_sigprocmask_compat_apply(
        const struct guest_sigprocmask_ops *ops, int32_t how,
        uintptr_t set_address, uintptr_t old_set_address,
        struct guest_sigprocmask_report *report) {
    if (!report) {
        errno = EINVAL;
        return -1;
    }
    *report = (struct guest_sigprocmask_report){0};
    report->how = how;
    report->has_set = set_address != 0;
    report->has_old_set = old_set_address != 0;

    uint32_t requested = 0;
    if (set_address != 0) {
        if (!ops || !ops->read_u32) {
            report->internal_request = GUEST_SIGPROCMASK_PTRACE_NONE;
            report->internal_errno = ENOSYS;
            errno = ENOSYS;
            return -1;
        }
        if (ops->read_u32(ops->context, set_address, &requested) != 0) {
            report->result = -EFAULT;
            return 0;
        }
        report->requested_set = requested;
        if (!guest_sigprocmask_how_valid(how)) {
            report->result = -EINVAL;
            return 0;
        }
    } else if (old_set_address == 0) {
        /* Linux's legacy syscall succeeds without consulting `how` when both
         * pointers are null. */
        report->result = 0;
        return 0;
    }

    if (!ops || !ops->get_mask) {
        report->internal_request = GUEST_SIGPROCMASK_PTRACE_GET;
        report->internal_errno = ENOSYS;
        errno = ENOSYS;
        return -1;
    }
    uint64_t before = 0;
    errno = 0;
    if (ops->get_mask(ops->context, &before) != 0) {
        int saved = errno ? errno : EIO;
        report->internal_request = GUEST_SIGPROCMASK_PTRACE_GET;
        report->internal_errno = saved;
        errno = saved;
        return -1;
    }
    report->mask_read = 1;
    report->mask_before = before;
    report->mask_after = before;
    report->old_set = (uint32_t)(before & GUEST_ARM_SIGPROCMASK_LOW_WORD_MASK);

    if (set_address != 0) {
        uint64_t after = guest_sigprocmask_apply_low_word(before, requested, how);
        if (!ops->set_mask) {
            report->internal_request = GUEST_SIGPROCMASK_PTRACE_SET;
            report->internal_errno = ENOSYS;
            errno = ENOSYS;
            return -1;
        }
        errno = 0;
        if (ops->set_mask(ops->context, after) != 0) {
            int saved = errno ? errno : EIO;
            report->internal_request = GUEST_SIGPROCMASK_PTRACE_SET;
            report->internal_errno = saved;
            errno = saved;
            return -1;
        }
        report->mask_after = after;
        report->mask_written = 1;
    }

    if (old_set_address != 0) {
        if (!ops->write_u32 ||
            ops->write_u32(ops->context, old_set_address, report->old_set) != 0) {
            report->result = -EFAULT;
            return 0;
        }
        report->old_set_written = 1;
    }
    report->result = 0;
    return 0;
}

#endif
