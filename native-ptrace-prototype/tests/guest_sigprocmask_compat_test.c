#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "../app/src/main/cpp/guest_sigprocmask_compat.h"

struct memory_cell {
    uintptr_t address;
    uint32_t value;
    int readable;
    int writable;
};

struct simulated_tracee {
    uint64_t mask;
    struct memory_cell cells[2];
    int get_calls;
    int set_calls;
    int fail_get;
    int fail_set;
};

static struct memory_cell *find_cell(struct simulated_tracee *tracee, uintptr_t address) {
    for (size_t i = 0; i < sizeof(tracee->cells) / sizeof(tracee->cells[0]); ++i) {
        if (tracee->cells[i].address == address) return &tracee->cells[i];
    }
    return NULL;
}

static int read_cell(void *context, uintptr_t address, uint32_t *value) {
    struct simulated_tracee *tracee = context;
    struct memory_cell *cell = find_cell(tracee, address);
    if (!cell || !cell->readable || !value) {
        errno = EFAULT;
        return -1;
    }
    *value = cell->value;
    return 0;
}

static int write_cell(void *context, uintptr_t address, uint32_t value) {
    struct simulated_tracee *tracee = context;
    struct memory_cell *cell = find_cell(tracee, address);
    if (!cell || !cell->writable) {
        errno = EFAULT;
        return -1;
    }
    cell->value = value;
    return 0;
}

static int get_mask(void *context, uint64_t *mask) {
    struct simulated_tracee *tracee = context;
    tracee->get_calls++;
    if (tracee->fail_get) {
        errno = tracee->fail_get;
        return -1;
    }
    *mask = tracee->mask;
    return 0;
}

static int set_mask(void *context, uint64_t mask) {
    struct simulated_tracee *tracee = context;
    tracee->set_calls++;
    if (tracee->fail_set) {
        errno = tracee->fail_set;
        return -1;
    }
    tracee->mask = mask;
    return 0;
}

static struct guest_sigprocmask_ops make_ops(struct simulated_tracee *tracee) {
    return (struct guest_sigprocmask_ops){
        .context = tracee,
        .read_u32 = read_cell,
        .write_u32 = write_cell,
        .get_mask = get_mask,
        .set_mask = set_mask,
    };
}

static struct simulated_tracee fresh_tracee(void) {
    struct simulated_tracee tracee = {0};
    tracee.cells[0] = (struct memory_cell){ .address = 0x1000, .value = 0,
                                            .readable = 1, .writable = 1 };
    tracee.cells[1] = (struct memory_cell){ .address = 0x2000, .value = 0xdeadbeef,
                                            .readable = 1, .writable = 1 };
    return tracee;
}

static void test_low_word_semantics_and_unmaskable_bits(void) {
    const uint64_t high = UINT64_C(1) << 39; /* Signal 40: beyond legacy ARM sigset_t. */
    const uint32_t old_low = UINT32_C(1) << 11; /* SIGUSR2. */
    const uint32_t usr1 = UINT32_C(1) << 9;
    const uint32_t kill_stop = GUEST_ARM_SIGPROCMASK_UNBLOCKABLE_MASK;
    uint64_t current = high | old_low;

    uint64_t blocked = guest_sigprocmask_apply_low_word(
        current, usr1 | kill_stop, GUEST_ARM_SIGPROCMASK_SIG_BLOCK);
    assert(blocked == (high | old_low | usr1));

    uint64_t unblocked = guest_sigprocmask_apply_low_word(
        blocked, usr1 | kill_stop, GUEST_ARM_SIGPROCMASK_SIG_UNBLOCK);
    assert(unblocked == (high | old_low));

    uint64_t replaced = guest_sigprocmask_apply_low_word(
        blocked, (UINT32_C(1) << 12) | kill_stop, GUEST_ARM_SIGPROCMASK_SIG_SETMASK);
    assert(replaced == (high | (UINT32_C(1) << 12)));
}

static void test_block_unblock_setmask_and_oldset(void) {
    struct simulated_tracee tracee = fresh_tracee();
    struct guest_sigprocmask_ops ops = make_ops(&tracee);
    struct guest_sigprocmask_report report;
    const uint64_t high = UINT64_C(1) << 39;
    const uint32_t usr1 = UINT32_C(1) << 9;
    const uint32_t usr2 = UINT32_C(1) << 11;
    tracee.mask = high | usr2;
    tracee.cells[0].value = usr1;

    assert(guest_sigprocmask_compat_apply(&ops, GUEST_ARM_SIGPROCMASK_SIG_BLOCK,
        0x1000, 0x2000, &report) == 0);
    assert(report.result == 0 && report.mask_read && report.mask_written);
    assert(report.old_set_written && report.old_set == usr2);
    assert(tracee.cells[1].value == usr2);
    assert(tracee.mask == (high | usr2 | usr1));

    assert(guest_sigprocmask_compat_apply(&ops, GUEST_ARM_SIGPROCMASK_SIG_UNBLOCK,
        0x1000, 0, &report) == 0);
    assert(report.result == 0 && tracee.mask == (high | usr2));

    tracee.cells[0].value = (UINT32_C(1) << 12) |
                             GUEST_ARM_SIGPROCMASK_UNBLOCKABLE_MASK;
    assert(guest_sigprocmask_compat_apply(&ops, GUEST_ARM_SIGPROCMASK_SIG_SETMASK,
        0x1000, 0x2000, &report) == 0);
    assert(report.old_set == usr2 && tracee.cells[1].value == usr2);
    assert(tracee.mask == (high | (UINT32_C(1) << 12)));
}

static void test_null_pointer_and_error_ordering(void) {
    struct simulated_tracee tracee = fresh_tracee();
    struct guest_sigprocmask_ops ops = make_ops(&tracee);
    struct guest_sigprocmask_report report;
    tracee.mask = UINT64_C(1) << 39;

    /* With both pointers null, the legacy syscall ignores even an invalid `how`. */
    assert(guest_sigprocmask_compat_apply(&ops, -99, 0, 0, &report) == 0);
    assert(report.result == 0 && tracee.get_calls == 0 && tracee.set_calls == 0);

    /* A null set only queries oldset and also ignores `how`. */
    assert(guest_sigprocmask_compat_apply(&ops, -99, 0, 0x2000, &report) == 0);
    assert(report.result == 0 && report.old_set_written);
    assert(tracee.cells[1].value == 0 && tracee.mask == (UINT64_C(1) << 39));

    /* The input set is copied before `how` validation; a bad pointer is EFAULT. */
    int get_before = tracee.get_calls;
    assert(guest_sigprocmask_compat_apply(&ops, -99, 0x3000, 0x2000, &report) == 0);
    assert(report.result == -EFAULT && tracee.get_calls == get_before);
    assert(tracee.cells[1].value == 0);

    /* A readable set with invalid `how` returns EINVAL without mask or oldset work. */
    assert(guest_sigprocmask_compat_apply(&ops, -99, 0x1000, 0x2000, &report) == 0);
    assert(report.result == -EINVAL && tracee.set_calls == 0);
    assert(tracee.cells[1].value == 0);
}

static void test_bad_oldset_occurs_after_mask_update(void) {
    struct simulated_tracee tracee = fresh_tracee();
    struct guest_sigprocmask_ops ops = make_ops(&tracee);
    struct guest_sigprocmask_report report;
    const uint32_t usr1 = UINT32_C(1) << 9;
    tracee.cells[0].value = usr1;

    assert(guest_sigprocmask_compat_apply(&ops, GUEST_ARM_SIGPROCMASK_SIG_BLOCK,
        0x1000, 0x3000, &report) == 0);
    assert(report.result == -EFAULT);
    assert(report.mask_written && tracee.mask == usr1);
    assert(!report.old_set_written);
}

static void test_set_old_alias_reads_before_writing(void) {
    struct simulated_tracee tracee = fresh_tracee();
    struct guest_sigprocmask_ops ops = make_ops(&tracee);
    struct guest_sigprocmask_report report;
    const uint32_t usr1 = UINT32_C(1) << 9;
    const uint32_t usr2 = UINT32_C(1) << 11;
    tracee.mask = usr2;
    tracee.cells[0].value = usr1;

    assert(guest_sigprocmask_compat_apply(&ops, GUEST_ARM_SIGPROCMASK_SIG_BLOCK,
        0x1000, 0x1000, &report) == 0);
    assert(report.requested_set == usr1 && report.old_set == usr2);
    assert(tracee.mask == (usr1 | usr2));
    assert(tracee.cells[0].value == usr2);
}

static void test_ptrace_failures_are_internal_not_guest_success(void) {
    struct simulated_tracee tracee = fresh_tracee();
    struct guest_sigprocmask_ops ops = make_ops(&tracee);
    struct guest_sigprocmask_report report;
    tracee.cells[0].value = UINT32_C(1) << 9;
    tracee.fail_get = EIO;
    errno = 0;
    assert(guest_sigprocmask_compat_apply(&ops, GUEST_ARM_SIGPROCMASK_SIG_BLOCK,
        0x1000, 0, &report) == -1);
    assert(errno == EIO && report.internal_request == GUEST_SIGPROCMASK_PTRACE_GET);
    assert(tracee.set_calls == 0 && tracee.mask == 0);

    tracee.fail_get = 0;
    tracee.fail_set = EACCES;
    errno = 0;
    assert(guest_sigprocmask_compat_apply(&ops, GUEST_ARM_SIGPROCMASK_SIG_BLOCK,
        0x1000, 0, &report) == -1);
    assert(errno == EACCES && report.internal_request == GUEST_SIGPROCMASK_PTRACE_SET);
    assert(tracee.mask == 0);
}

int main(void) {
    test_low_word_semantics_and_unmaskable_bits();
    test_block_unblock_setmask_and_oldset();
    test_null_pointer_and_error_ordering();
    test_bad_oldset_occurs_after_mask_update();
    test_set_old_alias_reads_before_writing();
    test_ptrace_failures_are_internal_not_guest_success();
    puts("guest_sigprocmask_compat_test: PASS");
    return 0;
}
