#ifndef GINGERVM_PTRACE_CHILD_STOP_QUEUE_H
#define GINGERVM_PTRACE_CHILD_STOP_QUEUE_H

#include <errno.h>
#include <signal.h>
#include <stddef.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>

#ifndef PTRACE_EVENT_STOP
#define PTRACE_EVENT_STOP 128
#endif

#define PTRACE_PENDING_CHILD_STOP_LIMIT 32u

struct ptrace_pending_child_stop {
    pid_t pid;
    int wait_status;
};

struct ptrace_child_stop_queue {
    struct ptrace_pending_child_stop entries[PTRACE_PENDING_CHILD_STOP_LIMIT];
    size_t count;
};

/* Reserve one slot from the same hard tracee budget for a new registered
 * tracee or a child stop awaiting its exact parent event. */
static inline int ptrace_child_stop_capacity_available(
        size_t retained_tracees, size_t pending_stops, size_t hard_limit) {
    if (hard_limit == 0u || retained_tracees >= hard_limit) return 0;
    return pending_stops < hard_limit - retained_tracees;
}

/* A new auto-attached fork/clone child may report its initial stop before the
 * parent's PTRACE_EVENT_FORK/CLONE/VFORK wait status. Hold only the initial
 * stop; never resume it until the exact parent event message matches its PID. */
static inline int ptrace_child_wait_status_is_initial_stop(int status) {
    if (!WIFSTOPPED(status)) return 0;
    unsigned event = (unsigned)status >> 16;
    int signal_number = WSTOPSIG(status);
    if (event == 0u) return signal_number == SIGSTOP;
    return event == PTRACE_EVENT_STOP &&
        (signal_number == SIGSTOP || signal_number == SIGTRAP);
}

static inline int ptrace_child_stop_queue_add(
        struct ptrace_child_stop_queue *queue, pid_t pid, int wait_status) {
    if (!queue || pid <= 0) return -EINVAL;
    if (!ptrace_child_wait_status_is_initial_stop(wait_status)) return -EPROTO;
    for (size_t i = 0; i < queue->count; ++i)
        if (queue->entries[i].pid == pid) return -EEXIST;
    if (queue->count >= PTRACE_PENDING_CHILD_STOP_LIMIT) return -ENOSPC;
    queue->entries[queue->count++] = (struct ptrace_pending_child_stop){
        .pid = pid,
        .wait_status = wait_status,
    };
    return 0;
}

/* Returns 1 when removed, 0 when absent, or a negative errno on bad inputs. */
static inline int ptrace_child_stop_queue_take(
        struct ptrace_child_stop_queue *queue, pid_t pid, int *wait_status) {
    if (!queue || pid <= 0 || !wait_status) return -EINVAL;
    for (size_t i = 0; i < queue->count; ++i) {
        if (queue->entries[i].pid != pid) continue;
        *wait_status = queue->entries[i].wait_status;
        queue->entries[i] = queue->entries[queue->count - 1u];
        memset(&queue->entries[queue->count - 1u], 0,
               sizeof(queue->entries[queue->count - 1u]));
        queue->count--;
        return 1;
    }
    return 0;
}

#endif
