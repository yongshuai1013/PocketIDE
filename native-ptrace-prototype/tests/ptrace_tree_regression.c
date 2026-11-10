#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifndef __WALL
#define __WALL 0x40000000
#endif

#define MAX_TEST_TRACEES 8

struct traced_child {
    pid_t pid;
    int alive;
};

static struct traced_child children[MAX_TEST_TRACEES];
static size_t child_count;

static struct traced_child *find_child(pid_t pid) {
    for (size_t i = 0; i < child_count; ++i)
        if (children[i].pid == pid) return &children[i];
    return NULL;
}

static int add_child(pid_t pid) {
    if (find_child(pid) || child_count >= MAX_TEST_TRACEES) return -1;
    children[child_count++] = (struct traced_child){ .pid = pid, .alive = 1 };
    return 0;
}

static int resume_syscall(pid_t pid, int signal_number) {
    return ptrace(PTRACE_SYSCALL, pid, NULL, (void *)(long)signal_number) == 0 ? 0 : -1;
}

static void kill_tree(void) {
    for (size_t i = 0; i < child_count; ++i) {
        if (!children[i].alive) continue;
        (void)ptrace(PTRACE_KILL, children[i].pid, NULL, NULL);
        (void)kill(children[i].pid, SIGKILL);
    }
}

int main(int argc, char **argv) {
    assert(argc == 2);
    pid_t root = fork();
    assert(root >= 0);
    if (root == 0) {
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) != 0) _exit(100);
        execl(argv[1], argv[1], (char *)NULL);
        _exit(101);
    }

    int status = 0;
    assert(waitpid(root, &status, __WALL) == root);
    assert(WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP);
    const long options = PTRACE_O_TRACESYSGOOD | PTRACE_O_EXITKILL |
                         PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK |
                         PTRACE_O_TRACECLONE | PTRACE_O_TRACEEXEC;
    assert(ptrace(PTRACE_SETOPTIONS, root, NULL, (void *)options) == 0);
    assert(add_child(root) == 0);
    assert(resume_syscall(root, 0) == 0);

    unsigned fork_events = 0, exec_events = 0, exits = 0;
    int root_exit = -1;
    struct timespec deadline;
    clock_gettime(CLOCK_MONOTONIC, &deadline);
    deadline.tv_sec += 8;
    struct timespec pause = { .tv_sec = 0, .tv_nsec = 1000000 };

    while (1) {
        size_t alive = 0;
        for (size_t i = 0; i < child_count; ++i) alive += children[i].alive != 0;
        if (alive == 0) break;

        pid_t waited = waitpid(-1, &status, __WALL | WNOHANG);
        if (waited == 0) {
            struct timespec now;
            clock_gettime(CLOCK_MONOTONIC, &now);
            if (now.tv_sec > deadline.tv_sec ||
                (now.tv_sec == deadline.tv_sec && now.tv_nsec > deadline.tv_nsec)) {
                kill_tree();
                fprintf(stderr, "ptrace tree regression timed out\n");
                return 2;
            }
            nanosleep(&pause, NULL);
            continue;
        }
        if (waited < 0 && errno == EINTR) continue;
        if (waited < 0) {
            kill_tree();
            perror("waitpid(-1)");
            return 2;
        }
        struct traced_child *entry = find_child(waited);
        if (!entry) {
            kill_tree();
            fprintf(stderr, "unregistered child pid=%d\n", waited);
            return 2;
        }
        if (WIFEXITED(status)) {
            if (waited == root) root_exit = WEXITSTATUS(status);
            entry->alive = 0;
            exits++;
            continue;
        }
        if (WIFSIGNALED(status)) {
            entry->alive = 0;
            fprintf(stderr, "tracee pid=%d terminated by signal=%d\n", waited, WTERMSIG(status));
            return 2;
        }
        if (!WIFSTOPPED(status)) continue;

        unsigned event = (unsigned)status >> 16;
        int sig = WSTOPSIG(status);
        if (event == PTRACE_EVENT_FORK || event == PTRACE_EVENT_VFORK || event == PTRACE_EVENT_CLONE) {
            unsigned long child_message = 0;
            assert(ptrace(PTRACE_GETEVENTMSG, waited, NULL, &child_message) == 0);
            pid_t new_pid = (pid_t)child_message;
            assert(add_child(new_pid) == 0);
            fork_events++;
            assert(resume_syscall(waited, 0) == 0);
            continue;
        }
        if (event == PTRACE_EVENT_EXEC) {
            exec_events++;
            assert(resume_syscall(waited, 0) == 0);
            continue;
        }
        assert(event == 0);
        if (sig == SIGSTOP) {
            assert(ptrace(PTRACE_SETOPTIONS, waited, NULL, (void *)options) == 0);
            assert(resume_syscall(waited, 0) == 0);
        } else if (sig == (SIGTRAP | 0x80)) {
            assert(resume_syscall(waited, 0) == 0);
        } else if (sig == SIGCHLD) {
            assert(resume_syscall(waited, SIGCHLD) == 0);
        } else {
            assert(resume_syscall(waited, sig) == 0);
        }
    }

    assert(fork_events >= 1);
    assert(exec_events >= 1);
    assert(exits >= 2);
    assert(root_exit == 0);
    printf("host ptrace process-tree regression: PASS (fork events=%u, exec events=%u, exits=%u, parent wait=0)\n",
           fork_events, exec_events, exits);
    return 0;
}
