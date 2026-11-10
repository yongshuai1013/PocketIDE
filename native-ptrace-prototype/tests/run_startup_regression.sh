#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

if [[ "$(uname -m)" != "x86_64" ]]; then
  echo "ptrace exec-start regression: SKIP (host runtime test is x86_64 Linux only)"
  exit 0
fi
command -v cc >/dev/null || { echo "cc is required for the host regression test" >&2; exit 2; }
command -v python3 >/dev/null || { echo "python3 is required for the source contract test" >&2; exit 2; }

python3 - "$ROOT/app/src/main/cpp/supervisor.c" <<'PY'
import pathlib, sys
source = pathlib.Path(sys.argv[1]).read_text()
start = source.split("static int start_guest(const char *binary) {", 1)[1].split("static int run_trace(", 1)[0]
trace = source.split("static int run_trace(", 1)[1].split("int main(", 1)[0]
assert "PTRACE_TRACEME" in start
assert "execve(binary, child_argv, child_envp)" in start
assert "raise(SIGSTOP)" not in start, "pre-exec SIGSTOP reintroduces tracing of the AArch64 launcher"
assert start.index("PTRACE_TRACEME") < start.index("execve(binary, child_argv, child_envp)")
assert "WSTOPSIG(status) != SIGTRAP" in trace, "successful exec must be the first ptrace stop"
assert trace.index("WSTOPSIG(status) != SIGTRAP") < trace.index("PTRACE_SETOPTIONS")
assert trace.index("exec_seen = 1;") < trace.index("PTRACE_SETOPTIONS")
assert trace.index("PTRACE_SETOPTIONS") < trace.index("get_compat_regs(pid, &regs)")
sigsys = trace.split("if (signal_number == SIGSYS)", 1)[1].split(
    'report_trace_signal(pid, signal_number, "while tracing the guest")', 1
)[0]
assert "expect_exit && pending == PENDING_RETURN" in sigsys
assert "resume_syscall(pid, 0)" in sigsys, "brokered SIGSYS must be suppressed"
assert "resume_syscall(pid, signal_number)" not in sigsys, "never pass SIGSYS to the host"
print("legacy probe ptrace exec-start source check: PASS (not the continuous /init supervisor)")
print("legacy probe SIGSYS source check: PASS (continuous wait-status handling is tested separately)")
PY

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
cc -nostdlib -static -no-pie "$ROOT/tests/tracee_x86_64.S" -o "$TMP/tracee"
cc -std=c11 -O2 -Wall -Wextra -Werror \
  "$ROOT/tests/ptrace_exec_regression.c" -o "$TMP/ptrace_exec_regression"
"$TMP/ptrace_exec_regression" "$TMP/tracee"
cc -std=c11 -O2 -Wall -Wextra -Werror \
  "$ROOT/tests/ptrace_tree_tracee.c" -o "$TMP/ptrace_tree_tracee"
cc -std=c11 -O2 -Wall -Wextra -Werror \
  "$ROOT/tests/ptrace_tree_regression.c" -o "$TMP/ptrace_tree_regression"
"$TMP/ptrace_tree_regression" "$TMP/ptrace_tree_tracee"
