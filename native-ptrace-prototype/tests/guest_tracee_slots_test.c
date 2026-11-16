#include "../app/src/main/cpp/guest_tracee_slots.h"

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

static void test_only_reaped_children_are_reusable(void) {
    struct guest_tracee_slot_pool pool;
    memset(&pool, 0, sizeof(pool));
    int slots[20];
    for (size_t i = 0; i < 20u; ++i) slots[i] = guest_tracee_slot_allocate(&pool);
    assert(pool.high_water == 20u && pool.active_count == 20u);
    for (size_t i = 0; i < 15u; ++i) {
        assert(guest_tracee_slot_mark_exit(&pool, (size_t)slots[i]) == 0);
        assert(guest_tracee_slot_mark_reaped(&pool, (size_t)slots[i]) == 0);
    }
    for (size_t i = 0; i < 15u; ++i) {
        int reused = guest_tracee_slot_allocate(&pool);
        assert(reused == slots[i]);
    }
    assert(pool.high_water == 20u && pool.active_count == 20u);
    assert(pool.maximum_active == 20u && pool.reused_count == 15u);
    assert(guest_tracee_slot_retained_count(&pool) == 20u);
}

static void test_unreaped_zombie_and_active_cap_are_retained(void) {
    struct guest_tracee_slot_pool pool;
    memset(&pool, 0, sizeof(pool));
    int first = guest_tracee_slot_allocate(&pool);
    assert(first == 0);
    assert(guest_tracee_slot_mark_exit(&pool, (size_t)first) == 0);
    assert(guest_tracee_slot_retained_count(&pool) == 1u);
    assert(guest_tracee_slot_allocate(&pool) == 1);
    assert(guest_tracee_slot_mark_reaped(&pool, (size_t)first) == 0);
    assert(guest_tracee_slot_allocate(&pool) == first);

    memset(&pool, 0, sizeof(pool));
    for (size_t i = 0; i < GUEST_TRACEE_SLOT_LIMIT; ++i)
        assert(guest_tracee_slot_allocate(&pool) == (int)i);
    assert(guest_tracee_slot_allocate(&pool) == -ENOSPC);
    assert(pool.active_count == GUEST_TRACEE_SLOT_LIMIT);
    assert(pool.maximum_active == GUEST_TRACEE_SLOT_LIMIT);
}

static void test_trace_lifetime_pressure_requires_guest_reap(void) {
    struct guest_tracee_slot_pool pool;
    memset(&pool, 0, sizeof(pool));
    int slots[GUEST_TRACEE_SLOT_LIMIT];
    for (size_t i = 0; i < GUEST_TRACEE_SLOT_LIMIT; ++i)
        slots[i] = guest_tracee_slot_allocate(&pool);
    for (size_t i = 0; i < 15u; ++i)
        assert(guest_tracee_slot_mark_exit(&pool, (size_t)slots[i]) == 0);
    assert(pool.active_count == 17u && pool.high_water == GUEST_TRACEE_SLOT_LIMIT);
    assert(guest_tracee_slot_retained_count(&pool) == GUEST_TRACEE_SLOT_LIMIT);
    assert(guest_tracee_slot_allocate(&pool) == -ENOSPC);
    for (size_t i = 0; i < 15u; ++i)
        assert(guest_tracee_slot_mark_reaped(&pool, (size_t)slots[i]) == 0);
    for (size_t i = 0; i < 15u; ++i)
        assert(guest_tracee_slot_allocate(&pool) == slots[i]);
    assert(pool.active_count == GUEST_TRACEE_SLOT_LIMIT);
    assert(pool.maximum_active == GUEST_TRACEE_SLOT_LIMIT);
    assert(pool.reused_count == 15u);
}

static void test_only_terminal_wait_statuses_allow_reap(void) {
    assert(guest_wait_status_is_terminal(0u));       /* exit(0) */
    assert(guest_wait_status_is_terminal(7u << 8)); /* exit(7) */
    assert(guest_wait_status_is_terminal(9u));       /* killed by SIGKILL */
    assert(!guest_wait_status_is_terminal(0x7fu));   /* stopped */
    assert(!guest_wait_status_is_terminal(UINT32_C(0xffff))); /* continued */

    struct guest_tracee_slot_pool pool;
    memset(&pool, 0, sizeof(pool));
    int slot = guest_tracee_slot_allocate(&pool);
    assert(slot == 0);
    assert(guest_tracee_slot_mark_exit(&pool, (size_t)slot) == 0);
    assert(!guest_wait_status_is_terminal(0x7fu));
    assert(guest_tracee_slot_allocate(&pool) == 1); /* stop is not guest reap */
    assert(guest_wait_status_is_terminal(9u));
    assert(guest_tracee_slot_mark_reaped(&pool, (size_t)slot) == 0);
    assert(guest_tracee_slot_allocate(&pool) == slot);
}

static void test_non_waitable_thread_released_only_after_ptrace_exit(void) {
    struct guest_tracee_slot_pool pool;
    memset(&pool, 0, sizeof(pool));
    int thread_slot = guest_tracee_slot_allocate(&pool);
    assert(thread_slot == 0);
    assert(guest_tracee_slot_mark_ptrace_exit(&pool, (size_t)thread_slot, 0) == 0);
    assert(pool.active_count == 0u && guest_tracee_slot_retained_count(&pool) == 0u);
    assert(guest_tracee_slot_allocate(&pool) == thread_slot);

    int child_slot = guest_tracee_slot_allocate(&pool);
    assert(child_slot == 1);
    assert(guest_tracee_slot_mark_ptrace_exit(&pool, (size_t)child_slot, 1) == 0);
    assert(guest_tracee_slot_allocate(&pool) == 2);
    assert(guest_tracee_slot_mark_reaped(&pool, (size_t)child_slot) == 0);
    assert(guest_tracee_slot_allocate(&pool) == child_slot);
}

int main(void) {
    test_only_reaped_children_are_reusable();
    test_unreaped_zombie_and_active_cap_are_retained();
    test_trace_lifetime_pressure_requires_guest_reap();
    test_only_terminal_wait_statuses_allow_reap();
    test_non_waitable_thread_released_only_after_ptrace_exit();
    puts("guest tracee registry regression: PASS (32-slot cap; waitable child exit retained until guest reap; non-waitable thread released after ptrace exit; stopped/continued children retained)");
    return 0;
}
