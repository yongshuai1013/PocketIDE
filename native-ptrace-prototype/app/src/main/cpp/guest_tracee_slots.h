#ifndef GINGERVM_GUEST_TRACEE_SLOTS_H
#define GINGERVM_GUEST_TRACEE_SLOTS_H

#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define GUEST_TRACEE_SLOT_LIMIT 32u

static inline int guest_wait_status_is_terminal(uint32_t status) {
    if (status == UINT32_C(0xffff)) return 0; /* WIFCONTINUED */
    uint32_t signal_number = status & UINT32_C(0x7f);
    if (signal_number == 0u) return 1; /* WIFEXITED */
    return signal_number != UINT32_C(0x7f); /* not WIFSTOPPED */
}

struct guest_tracee_slot_meta {
    uint8_t allocated;
    uint8_t active;
    uint8_t guest_reaped;
};

struct guest_tracee_slot_pool {
    struct guest_tracee_slot_meta slots[GUEST_TRACEE_SLOT_LIMIT];
    size_t high_water;
    size_t active_count;
    size_t maximum_active;
    size_t reused_count;
};

static inline int guest_tracee_slot_allocate(struct guest_tracee_slot_pool *pool) {
    if (!pool) return -EINVAL;
    size_t slot = pool->high_water;
    int reused = 0;
    for (size_t i = 0; i < pool->high_water; ++i) {
        const struct guest_tracee_slot_meta *candidate = &pool->slots[i];
        if (!candidate->allocated || (!candidate->active && candidate->guest_reaped)) {
            slot = i;
            reused = candidate->allocated;
            break;
        }
    }
    if (slot == pool->high_water) {
        if (pool->high_water >= GUEST_TRACEE_SLOT_LIMIT) return -ENOSPC;
        pool->high_water++;
    }
    struct guest_tracee_slot_meta *target = &pool->slots[slot];
    target->allocated = 1u;
    target->active = 1u;
    target->guest_reaped = 0u;
    if (reused) pool->reused_count++;
    pool->active_count++;
    if (pool->active_count > pool->maximum_active)
        pool->maximum_active = pool->active_count;
    return (int)slot;
}

static inline int guest_tracee_slot_mark_exit(struct guest_tracee_slot_pool *pool,
                                               size_t slot) {
    if (!pool || slot >= pool->high_water || !pool->slots[slot].allocated ||
        !pool->slots[slot].active || pool->active_count == 0u) return -EINVAL;
    pool->slots[slot].active = 0u;
    pool->active_count--;
    return 0;
}

static inline int guest_tracee_slot_mark_reaped(struct guest_tracee_slot_pool *pool,
                                                 size_t slot) {
    if (!pool || slot >= pool->high_water || !pool->slots[slot].allocated ||
        pool->slots[slot].active) return -EINVAL;
    pool->slots[slot].guest_reaped = 1u;
    return 0;
}

/* Linux threads are traced individually but are not separate guest wait4 children.
 * Once ptrace confirms their terminal exit, no guest wait status remains to retain. */
static inline int guest_tracee_slot_mark_ptrace_exit(
        struct guest_tracee_slot_pool *pool, size_t slot,
        int guest_wait_status_pending) {
    int rc = guest_tracee_slot_mark_exit(pool, slot);
    if (rc != 0 || guest_wait_status_pending) return rc;
    return guest_tracee_slot_mark_reaped(pool, slot);
}

static inline size_t guest_tracee_slot_retained_count(
        const struct guest_tracee_slot_pool *pool) {
    if (!pool) return 0u;
    size_t retained = 0u;
    for (size_t i = 0; i < pool->high_water; ++i)
        if (pool->slots[i].allocated &&
            (pool->slots[i].active || !pool->slots[i].guest_reaped))
            retained++;
    return retained;
}

#endif
