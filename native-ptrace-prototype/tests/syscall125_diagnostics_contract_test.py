#!/usr/bin/env python3
from pathlib import Path
import sys

source = Path(sys.argv[1]).read_text()

helpers = source.split("static int guest_syscall125_diag_is_setprop(", 1)[1].split(
    "static int resume_trace(", 1
)[0]
resume = source.split("static int resume_trace(", 1)[1].split(
    "static int seed_regular_file(", 1
)[0]
trace = source.split("static int run_trace(", 1)[1]

# The entry snapshot is limited to the existing ARM register snapshot and wait status.
assert "state->setup_property_tool == GUEST_SETUP_PROPERTY_TOOL_SETPROP" in helpers
assert 'strcmp(state->exec_target, "/system/bin/setprop") == 0' in helpers
for field in (
    "r0=%u", "r1=%u", "r2=%u", "r3=%u", "r4=%u", "r5=%u", "r7=%u",
    "pc=0x%08x", "lr=0x%08x", "sp=0x%08x", "cpsr=0x%08x",
    "wait-status=0x%x", "expect_exit=%d",
):
    assert field in helpers
for register in (0, 1, 2, 3, 4, 5, 7, 13, 14, 15, 17):
    assert f"regs->uregs[{register}]" in helpers
assert "diag->last_signal" in helpers and "diag->last_event" in helpers

# Subsequent stops and syscall-125 exit are reported from wait status/current regs only.
assert "GUEST SETPROP SYSCALL125 PTRACE STOP:" in helpers
assert "GUEST SETPROP ARM SYSCALL125 EXIT:" in helpers
assert "r0-raw=0x%08x r0-signed=%d" in helpers
assert "(int32_t)regs->uregs[0]" in helpers
assert "state->last_syscall != ARM_NR_MPROTECT" in helpers
assert "guest_syscall125_diag_log_stop(waited, state, status);" in trace
assert trace.index("if (!WIFSTOPPED(status)) continue;") < trace.index(
    "guest_syscall125_diag_log_stop(waited, state, status);"
)
assert "guest_syscall125_diag_log_exit(waited, state, &regs, status);" in trace
assert trace.index("guest_syscall125_diag_log_exit(waited, state, &regs, status);") < trace.index(
    "uint32_t syscall_result_bits = state->pending"
)

# Every selected-PID resume still performs exactly PTRACE_SYSCALL; the logger preserves errno.
assert "ptrace(PTRACE_SYSCALL, pid, NULL," in resume
assert "GUEST SETPROP SYSCALL125 PTRACE RESUME:" in resume
assert "rc=%ld errno=%d" in resume
assert "int incoming_errno = errno;" in resume
assert "int ptrace_errno = ptrace_result == -1 ? errno : 0;" in resume
assert "errno = incoming_errno;" in resume
assert "errno = ptrace_errno;" in resume
assert "from-wait-status=0x%x from-signal=%d from-event=%u" in resume

# Entry is observed before dispatch; there is no diagnostic memory read or syscall routing.
entry_call = "guest_syscall125_diag_log_entry(waited, state, &regs,\n                                                    status);"
assert entry_call in trace
assert trace.index("if (get_regs(waited, &regs) != 0)") < trace.index(entry_call)
assert "if (state->last_syscall == ARM_NR_MPROTECT)" in trace
for forbidden in (
    "read_remote", "read_remote_string", "write_remote", "get_regs(",
    "set_regs(", "fake_syscall(", "dispatch_entry(", "property_value",
    "value_length", "value-length", "property_set", "property-service",
):
    assert forbidden not in helpers, f"diagnostic helper must not use {forbidden}"

# Keep the existing value-free process-exit and shell wait4 observations covered.
assert "GUEST SETUP SHELL PROPERTY EXIT:" in source
assert "guest_setup_property_log_exit(state, 1, WEXITSTATUS(status), 0);" in trace
assert "guest_setup_property_log_exit(state, 0, -1, WTERMSIG(status));" in trace
assert "GUEST SETUP SHELL WAIT4:" in source
assert "guest_setup_shell_log_wait_result(waited, state, &regs);" in trace
assert "int diagnostic_errno = errno;" in trace
assert "errno = diagnostic_errno;" in trace

print("syscall 125 diagnostic source contract: PASS (entry ARM registers, every selected-PID stop/resume, raw/signed exit r0, errno preservation, setprop exit and shell wait4; no property value access or guest syscall routing changes)")
