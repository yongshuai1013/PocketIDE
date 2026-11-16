#define _GNU_SOURCE
#include "../app/src/main/cpp/ptrace_child_stop_queue.h"

#include <assert.h>
#include <stdint.h>
#include <stdio.h>

#ifndef PTRACE_EVENT_FORK
#define PTRACE_EVENT_FORK 1
#endif

static int make_status(int signal_number, unsigned event) {
    return (int)((event << 16) | ((unsigned)signal_number << 8) | 0x7fu);
}

static void test_only_new_child_initial_stops_are_deferred(void) {
    int child_sigstop = make_status(SIGSTOP, 0u);
    int event_stop = make_status(SIGTRAP, PTRACE_EVENT_STOP);
    int forwarded_signal = make_status(SIGSYS, 0u);
    int parent_fork_event = make_status(SIGTRAP, PTRACE_EVENT_FORK);
    assert(ptrace_child_wait_status_is_initial_stop(child_sigstop));
    assert(ptrace_child_wait_status_is_initial_stop(event_stop));
    assert(!ptrace_child_wait_status_is_initial_stop(forwarded_signal));
    assert(!ptrace_child_wait_status_is_initial_stop(parent_fork_event));
    assert(!ptrace_child_wait_status_is_initial_stop(0));
}

static void test_exact_event_pid_association(void) {
    struct ptrace_child_stop_queue queue = {0};
    int status = make_status(SIGSTOP, 0u);
    int output = 0;
    assert(ptrace_child_stop_queue_add(&queue, 4102, status) == 0);
    assert(queue.count == 1u);
    assert(ptrace_child_stop_queue_add(&queue, 4102, status) == -EEXIST);
    assert(ptrace_child_stop_queue_take(&queue, 4103, &output) == 0);
    assert(queue.count == 1u);
    assert(ptrace_child_stop_queue_take(&queue, 4102, &output) == 1);
    assert(output == status && queue.count == 0u);
    assert(ptrace_child_stop_queue_take(&queue, 4102, &output) == 0);
}

static void test_bad_status_and_capacity_fail_closed(void) {
    struct ptrace_child_stop_queue queue = {0};
    int status = make_status(SIGSTOP, 0u);
    assert(ptrace_child_stop_queue_add(&queue, 0, status) == -EINVAL);
    assert(ptrace_child_stop_queue_add(&queue, 1, make_status(SIGSYS, 0u)) == -EPROTO);
    for (size_t i = 0; i < PTRACE_PENDING_CHILD_STOP_LIMIT; ++i)
        assert(ptrace_child_stop_queue_add(&queue, (pid_t)(5000 + i), status) == 0);
    assert(queue.count == PTRACE_PENDING_CHILD_STOP_LIMIT);
    assert(ptrace_child_stop_queue_add(&queue, 9000, status) == -ENOSPC);
}

static void test_pending_stops_share_the_tracee_budget(void) {
    assert(ptrace_child_stop_capacity_available(30u, 1u, 32u));
    assert(ptrace_child_stop_capacity_available(31u, 0u, 32u));
    assert(!ptrace_child_stop_capacity_available(31u, 1u, 32u));
    assert(!ptrace_child_stop_capacity_available(32u, 0u, 32u));
    assert(!ptrace_child_stop_capacity_available(0u, 32u, 32u));
    assert(!ptrace_child_stop_capacity_available(SIZE_MAX, SIZE_MAX, 32u));
    assert(!ptrace_child_stop_capacity_available(0u, 0u, 0u));
}

int main(void) {
    test_only_new_child_initial_stops_are_deferred();
    test_exact_event_pid_association();
    test_bad_status_and_capacity_fail_closed();
    test_pending_stops_share_the_tracee_budget();
    puts("ptrace child-stop ordering regression: PASS (initial stop deferred, exact parent-event PID match required, shared 32-tracee bound, other signals fail closed)");
    return 0;
}
