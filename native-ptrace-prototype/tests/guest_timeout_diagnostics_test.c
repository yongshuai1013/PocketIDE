#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <sys/mman.h>
#include <unistd.h>
#include "../app/src/main/cpp/guest_timeout_diagnostics.h"

static void *map_low_pc(void) {
#ifdef MAP_32BIT
    void *memory = mmap(NULL, 4096u, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS | MAP_32BIT, -1, 0);
    if (memory == MAP_FAILED) return NULL;
    if ((uintptr_t)memory > UINT32_MAX) {
        munmap(memory, 4096u);
        return NULL;
    }
    return memory;
#else
    return NULL;
#endif
}

static void test_key_tracee_lifecycle_and_mapping(uint32_t pc) {
    struct guest_timeout_diagnostics diagnostics;
    guest_timeout_diagnostics_init(&diagnostics);
    const char *key = "ro.kernel.qemu";

    guest_timeout_diagnostics_note_exec(&diagnostics,
        GUEST_TIMEOUT_TRACE_SETPROP, getpid(), 12, 1,
        "/system/bin/setprop", "/system/etc/init.goldfish.sh", key);
    struct guest_timeout_trace_snapshot *snapshot =
        &diagnostics.roles[GUEST_TIMEOUT_TRACE_SETPROP];
    assert(snapshot->valid);
    assert(snapshot->syscall_number == 11);
    assert(!snapshot->pc_valid);
    assert(snapshot->result_state == GUEST_TIMEOUT_TRACE_RESULT_EXEC_COMMITTED);
    assert(strcmp(snapshot->property_key, key) == 0);
    guest_timeout_diagnostics_note_exec_stop_pc(&diagnostics,
        GUEST_TIMEOUT_TRACE_SETPROP, getpid(), pc);
    assert(snapshot->pc_valid && snapshot->pc == pc);
    assert(snapshot->pc_source == GUEST_TIMEOUT_TRACE_PC_EXEC_STOP);

    guest_timeout_diagnostics_note_syscall(&diagnostics,
        GUEST_TIMEOUT_TRACE_SETPROP, getpid(), 12, 1,
        "/system/bin/setprop", "/system/etc/init.goldfish.sh", key,
        3, pc);
    assert(snapshot->pc_valid && snapshot->pc == pc);
    assert(snapshot->pc_source == GUEST_TIMEOUT_TRACE_PC_SYSCALL_ENTRY);
    assert(snapshot->mapping_valid);
    assert(guest_diag_proc_map_contains(&snapshot->mapping, pc));
    assert(snapshot->result_state == GUEST_TIMEOUT_TRACE_RESULT_PENDING);

    guest_timeout_diagnostics_note_result(&diagnostics,
        GUEST_TIMEOUT_TRACE_SETPROP, getpid(), -ENOENT);
    assert(snapshot->result_valid);
    assert(snapshot->syscall_result == -ENOENT);
    assert(snapshot->result_state == GUEST_TIMEOUT_TRACE_RESULT_COMPLETE);
    guest_timeout_diagnostics_note_exit(&diagnostics,
        GUEST_TIMEOUT_TRACE_SETPROP, getpid(), 1);
    assert(snapshot->terminal_state == GUEST_TIMEOUT_TRACE_TERMINAL_EXITED);
    assert(snapshot->exit_code == 1);
    assert(snapshot->exit_signal == 0);
}

static void test_setup_shell_and_app_process_stops(uint32_t pc) {
    struct guest_timeout_diagnostics diagnostics;
    guest_timeout_diagnostics_init(&diagnostics);

    guest_timeout_diagnostics_note_exec(&diagnostics,
        GUEST_TIMEOUT_TRACE_SETUP_SHELL, getpid(), 2, 1,
        "/system/bin/sh", "/system/etc/init.goldfish.sh", NULL);
    guest_timeout_diagnostics_note_syscall(&diagnostics,
        GUEST_TIMEOUT_TRACE_SETUP_SHELL, getpid(), 2, 1,
        "/system/bin/sh", "/system/etc/init.goldfish.sh", NULL,
        114, pc);
    guest_timeout_diagnostics_note_parked(&diagnostics,
        GUEST_TIMEOUT_TRACE_SETUP_SHELL, getpid());
    guest_timeout_diagnostics_note_signal(&diagnostics,
        GUEST_TIMEOUT_TRACE_SETUP_SHELL, getpid(), SIGCHLD);
    struct guest_timeout_trace_snapshot *shell =
        &diagnostics.roles[GUEST_TIMEOUT_TRACE_SETUP_SHELL];
    assert(shell->result_state == GUEST_TIMEOUT_TRACE_RESULT_PARKED);
    assert(shell->last_signal == SIGCHLD);

    guest_timeout_diagnostics_note_exec(&diagnostics,
        GUEST_TIMEOUT_TRACE_APP_PROCESS, getpid(), 19, 1,
        "/system/bin/app_process", "", NULL);
    guest_timeout_diagnostics_note_syscall(&diagnostics,
        GUEST_TIMEOUT_TRACE_APP_PROCESS, getpid(), 19, 1,
        "/system/bin/app_process", "", NULL, 3, pc);
    guest_timeout_diagnostics_note_signal_exit(&diagnostics,
        GUEST_TIMEOUT_TRACE_APP_PROCESS, getpid(), SIGKILL);
    struct guest_timeout_trace_snapshot *app_process =
        &diagnostics.roles[GUEST_TIMEOUT_TRACE_APP_PROCESS];
    assert(app_process->terminal_state == GUEST_TIMEOUT_TRACE_TERMINAL_SIGNALED);
    assert(app_process->exit_signal == SIGKILL);
    assert(app_process->pc_valid && app_process->mapping_valid);
}

int main(void) {
    void *low_pc = map_low_pc();
    if (!low_pc) {
        puts("timeout trace diagnostics regression: SKIP (host does not provide a 32-bit test mapping)");
        return 0;
    }
    uint32_t pc = (uint32_t)(uintptr_t)low_pc;
    test_key_tracee_lifecycle_and_mapping(pc);
    test_setup_shell_and_app_process_stops(pc);
    munmap(low_pc, 4096u);
    puts("timeout trace diagnostics regression: PASS (three key roles, syscall/result, mapping, parked, signal/exit)");
    return 0;
}
