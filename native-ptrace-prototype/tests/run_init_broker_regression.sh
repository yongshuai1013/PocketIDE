#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
GUEST_BASE="${GINGERVM_GUEST_BASE:-$ROOT/guest-image/google-api10-android-2.3.7}"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

cc -std=c11 -O2 -Wall -Wextra -Werror \
  "$ROOT/tests/init_broker_policy_test.c" -o "$TMP/init_broker_policy_test"
"$TMP/init_broker_policy_test"
cc -std=c11 -O2 -Wall -Wextra -Werror \
  "$ROOT/tests/broker_sigsys_state_test.c" -o "$TMP/broker_sigsys_state_test"
"$TMP/broker_sigsys_state_test"
cc -std=c11 -O2 -Wall -Wextra -Werror \
  "$ROOT/tests/guest_sigprocmask_compat_test.c" -o "$TMP/guest_sigprocmask_compat_test"
"$TMP/guest_sigprocmask_compat_test"
cc -std=c11 -O2 -Wall -Wextra -Werror \
  "$ROOT/tests/guest_sigaction_compat_test.c" -o "$TMP/guest_sigaction_compat_test"
"$TMP/guest_sigaction_compat_test"
cc -std=c11 -O2 -Wall -Wextra -Werror \
  "$ROOT/tests/guest_process_compat_test.c" -o "$TMP/guest_process_compat_test"
"$TMP/guest_process_compat_test"
cc -std=c11 -O2 -Wall -Wextra -Werror \
  "$ROOT/tests/guest_tracee_slots_test.c" -o "$TMP/guest_tracee_slots_test"
"$TMP/guest_tracee_slots_test"
cc -std=c11 -O2 -Wall -Wextra -Werror \
  "$ROOT/tests/ptrace_child_stop_queue_test.c" -o "$TMP/ptrace_child_stop_queue_test"
"$TMP/ptrace_child_stop_queue_test"
cc -std=c11 -O2 -Wall -Wextra -Werror \
  "$ROOT/tests/guest_network_virtual_test.c" -o "$TMP/guest_network_virtual_test"
"$TMP/guest_network_virtual_test" "$GUEST_BASE/system-tree/etc/init.goldfish.sh"
cc -std=c11 -O2 -Wall -Wextra -Werror \
  "$ROOT/tests/guest_qemud_diagnostics_test.c" -o "$TMP/guest_qemud_diagnostics_test"
"$TMP/guest_qemud_diagnostics_test"
cc -std=c11 -O2 -Wall -Wextra -Werror \
  "$ROOT/tests/guest_identity_compat_test.c" -o "$TMP/guest_identity_compat_test"
"$TMP/guest_identity_compat_test"
cc -std=c11 -O2 -Wall -Wextra -Werror \
  "$ROOT/tests/guest_frame_channel_test.c" -o "$TMP/guest_frame_channel_test"
"$TMP/guest_frame_channel_test" "$TMP/guest-frame-root"
cc -std=c11 -O2 -Wall -Wextra -Werror \
  "$ROOT/tests/guest_framebuffer_virtual_test.c" -o "$TMP/guest_framebuffer_virtual_test"
"$TMP/guest_framebuffer_virtual_test" "$TMP/fb0-frame-root" --keep-packet
cc -std=c11 -O2 -Wall -Wextra -Werror \
  "$ROOT/tests/guest_device_boundary_test.c" -o "$TMP/guest_device_boundary_test"
"$TMP/guest_device_boundary_test"
cc -std=c11 -O2 -Wall -Wextra -Werror \
  "$ROOT/tests/guest_binder_virtual_test.c" -o "$TMP/guest_binder_virtual_test"
"$TMP/guest_binder_virtual_test"
cc -std=c11 -O2 -Wall -Wextra -Werror \
  "$ROOT/tests/guest_syscall_abi_test.c" -o "$TMP/guest_syscall_abi_test"
"$TMP/guest_syscall_abi_test"
cc -std=c11 -O2 -Wall -Wextra -Werror \
  "$ROOT/tests/guest_uevent_virtual_test.c" -o "$TMP/guest_uevent_virtual_test"
"$TMP/guest_uevent_virtual_test"
cc -std=c11 -O2 -Wall -Wextra -Werror \
  "$ROOT/tests/guest_path_fd_test.c" -o "$TMP/guest_path_fd_test"
"$TMP/guest_path_fd_test"
cc -std=c11 -O2 -Wall -Wextra -Werror \
  "$ROOT/tests/guest_safe_dir_test.c" -o "$TMP/guest_safe_dir_test"
"$TMP/guest_safe_dir_test"
cc -std=c11 -O2 -Wall -Wextra -Werror \
  "$ROOT/tests/guest_pseudo_device_test.c" -o "$TMP/guest_pseudo_device_test"
"$TMP/guest_pseudo_device_test"
cc -std=c11 -O2 -Wall -Wextra -Werror \
  "$ROOT/tests/guest_null_stdio_test.c" -o "$TMP/guest_null_stdio_test"
"$TMP/guest_null_stdio_test"
cc -std=c11 -O2 -Wall -Wextra -Werror \
  "$ROOT/tests/guest_init_post_stdio_test.c" -o "$TMP/guest_init_post_stdio_test"
"$TMP/guest_init_post_stdio_test" \
  "$GUEST_BASE/guest-root-staging/init.rc" \
  "$GUEST_BASE/guest-root-staging/init.goldfish.rc"
cc -std=c11 -O2 -Wall -Wextra -Werror \
  "$ROOT/tests/guest_entry_probe_test.c" -o "$TMP/guest_entry_probe_test"
"$TMP/guest_entry_probe_test"
cc -std=c11 -O2 -Wall -Wextra -Werror \
  "$ROOT/tests/guest_socket_virtual_test.c" -o "$TMP/guest_socket_virtual_test"
"$TMP/guest_socket_virtual_test"
cc -std=c11 -O2 -Wall -Wextra -Werror \
  "$ROOT/tests/guest_socket_path_ops_test.c" -o "$TMP/guest_socket_path_ops_test"
"$TMP/guest_socket_path_ops_test"
cc -std=c11 -O2 -Wall -Wextra -Werror \
  "$ROOT/tests/guest_property_socket_regression_test.c" -o "$TMP/guest_property_socket_regression_test"
"$TMP/guest_property_socket_regression_test"
cc -std=c11 -O2 -Wall -Wextra -Werror \
  "$ROOT/tests/guest_diagnostics_test.c" -o "$TMP/guest_diagnostics_test"
"$TMP/guest_diagnostics_test"
mkdir -p "$TMP/java"
javac -d "$TMP/java" \
  "$ROOT/app/src/main/java/dev/gingervm/nativeprobe/AppPrivateFileModeRestorer.java" \
  "$ROOT/app/src/main/java/dev/gingervm/nativeprobe/AppPrivateTreeCleanup.java" \
  "$ROOT/app/src/main/java/dev/gingervm/nativeprobe/TraceOutputCapture.java" \
  "$ROOT/app/src/main/java/dev/gingervm/nativeprobe/GuestFramePacket.java" \
  "$ROOT/tests/AppPrivateFileModeRestorerTest.java" \
  "$ROOT/tests/AppPrivateTreeCleanupTest.java" \
  "$ROOT/tests/TraceOutputCaptureTest.java" \
  "$ROOT/tests/GuestFramePacketTest.java" \
  "$ROOT/tests/GuestFramebufferPacketTest.java"
java -ea -cp "$TMP/java" dev.gingervm.nativeprobe.AppPrivateFileModeRestorerTest
java -cp "$TMP/java" dev.gingervm.nativeprobe.AppPrivateTreeCleanupTest
java -cp "$TMP/java" dev.gingervm.nativeprobe.TraceOutputCaptureTest
java -cp "$TMP/java" dev.gingervm.nativeprobe.GuestFramePacketTest \
  "$TMP/guest-frame-root/gingervm-display/latest.gvmf"
java -cp "$TMP/java" dev.gingervm.nativeprobe.GuestFramebufferPacketTest \
  "$TMP/fb0-frame-root/gingervm-display/latest.gvmf"
if [[ "$(uname -m)" == "x86_64" ]]; then
  cc -std=c11 -O2 -Wall -Wextra -Werror \
    "$ROOT/tests/ptrace_seccomp_sigsys_regression.c" -o "$TMP/ptrace_seccomp_sigsys_regression"
  "$TMP/ptrace_seccomp_sigsys_regression"
  cc -std=c11 -O2 -Wall -Wextra -Werror \
    "$ROOT/tests/ptrace_sigprocmask_seccomp_regression.c" -o "$TMP/ptrace_sigprocmask_seccomp_regression"
  "$TMP/ptrace_sigprocmask_seccomp_regression"
  cc -std=c11 -O2 -Wall -Wextra -Werror \
    "$ROOT/tests/guest_file_ops_test.c" -o "$TMP/guest_file_ops_test"
  "$TMP/guest_file_ops_test"
  cc -std=c11 -O2 -Wall -Wextra -Werror \
    "$ROOT/tests/guest_symlink_ops_test.c" -o "$TMP/guest_symlink_ops_test"
  "$TMP/guest_symlink_ops_test"
  cc -std=c11 -O2 -Wall -Wextra -Werror \
    "$ROOT/tests/ptrace_cancel_cleanup_regression.c" -o "$TMP/ptrace_cancel_cleanup_regression"
  "$TMP/ptrace_cancel_cleanup_regression"
  cc -std=c11 -O2 -Wall -Wextra -Werror \
    "$ROOT/tests/ptrace_tree_regression.c" -o "$TMP/ptrace_tree_regression"
  cc -std=c11 -O2 -Wall -Wextra -Werror \
    "$ROOT/tests/ptrace_tree_tracee.c" -o "$TMP/ptrace_tree_tracee"
  "$TMP/ptrace_tree_regression" "$TMP/ptrace_tree_tracee"
else
  echo 'ptrace seccomp/cancellation kernel regressions: SKIP (host tests are x86_64 Linux only)'
fi
cc -std=c11 -O2 -Wall -Wextra -Werror \
  "$ROOT/tests/guest_exec_elf_test.c" -o "$TMP/guest_exec_elf_test"
"$TMP/guest_exec_elf_test" \
"$GUEST_BASE/guest-root-staging/init" \
  "$GUEST_BASE/system-tree/bin/app_process"
cc -std=c11 -O2 -Wall -Wextra -Werror \
  "$ROOT/tests/guest_script_launch_test.c" -o "$TMP/guest_script_launch_test"
"$TMP/guest_script_launch_test"
python3 "$ROOT/tests/test_stage_interp_patch.py"
python3 "$ROOT/tests/test_procfd_interp_execution.py"

python3 - "$ROOT/app/src/main/cpp/init_supervisor.c" \
  "$ROOT/app/src/main/java/dev/gingervm/nativeprobe/MainActivity.java" \
  "$ROOT/app/build.gradle" "$ROOT/app/src/main/AndroidManifest.xml" \
  "$ROOT/tests/stage_init_assets.py" "$ROOT/build-native.sh" <<'PY'
from pathlib import Path
import os, re, sys
src = Path(sys.argv[1]).read_text()
trace = src.split("static int run_trace(", 1)[1].split("int main(", 1)[0]
uevent = Path(sys.argv[1]).with_name('guest_uevent_virtual.h').read_text()
safe_dir = Path(sys.argv[1]).with_name('guest_safe_dir.h').read_text()
safe_dir_test = Path(sys.argv[1]).parents[4].joinpath('tests/guest_safe_dir_test.c').read_text()
socket_model = Path(sys.argv[1]).with_name('guest_socket_virtual.h').read_text()
socket_path = Path(sys.argv[1]).with_name('guest_socket_path_ops.h').read_text()
property_protocol = Path(sys.argv[1]).with_name('guest_property_protocol.h').read_text()
property_socket_test = Path(sys.argv[1]).parents[4].joinpath('tests/guest_property_socket_regression_test.c').read_text()
diagnostics = Path(sys.argv[1]).with_name('guest_diagnostics.h').read_text()
sigsys_context = Path(sys.argv[1]).with_name('guest_sigsys_context.h').read_text()
script_launch = Path(sys.argv[1]).with_name('guest_script_launch.h').read_text()
profile = Path(sys.argv[1]).with_name('guest_hardware_profile.h').read_text()
qemud_diagnostics = Path(sys.argv[1]).with_name('guest_qemud_diagnostics.h').read_text()
qemud_test = Path(sys.argv[1]).parents[4].joinpath('tests/guest_qemud_diagnostics_test.c').read_text()
pseudo_device = Path(sys.argv[1]).with_name('guest_pseudo_device.h').read_text()
null_stdio = Path(sys.argv[1]).with_name('guest_null_stdio.h').read_text()
null_stdio_test = Path(sys.argv[1]).parents[4].joinpath('tests/guest_null_stdio_test.c').read_text()
kmsg_model = Path(sys.argv[1]).with_name('guest_kmsg_virtual.h').read_text()
kmsg_test = Path(sys.argv[1]).parents[4].joinpath('tests/guest_init_post_stdio_test.c').read_text()
path_syscall_start = src.index('static int path_syscall(')
path_syscall_source = src[path_syscall_start:]
dup_guard_start = src.index('if (nr == ARM_NR_DUP)')
dup_guard_end = src.index('if (nr == ARM_NR_DUP2 && state)', dup_guard_start)
dup_guard_source = src[dup_guard_start:dup_guard_end]
tracee_slots = Path(sys.argv[1]).with_name('guest_tracee_slots.h').read_text()
slots_test = Path(sys.argv[1]).parents[4].joinpath('tests/guest_tracee_slots_test.c').read_text()
pending_child_stops = Path(sys.argv[1]).with_name('ptrace_child_stop_queue.h').read_text()
pending_child_stop_test = Path(sys.argv[1]).parents[4].joinpath('tests/ptrace_child_stop_queue_test.c').read_text()
device_boundary = Path(sys.argv[1]).with_name('guest_device_boundary.h').read_text()
binder_model = Path(sys.argv[1]).with_name('guest_binder_virtual.h').read_text()
binder_test = Path(sys.argv[1]).parents[4].joinpath('tests/guest_binder_virtual_test.c').read_text()
syscall_abi = Path(sys.argv[1]).with_name('guest_syscall_abi.h').read_text()
syscall_abi_test = Path(sys.argv[1]).parents[4].joinpath('tests/guest_syscall_abi_test.c').read_text()
sigmask_compat = Path(sys.argv[1]).with_name('guest_sigprocmask_compat.h').read_text()
sigmask_ptrace = Path(sys.argv[1]).with_name('guest_sigprocmask_ptrace.h').read_text()
frame_channel = Path(sys.argv[1]).with_name('guest_frame_channel.h').read_text()
repo_root = Path(sys.argv[1]).parents[4]
network_test = (repo_root / 'tests/guest_network_virtual_test.c').read_text()
policy_test = (repo_root / 'tests/init_broker_policy_test.c').read_text()
network_test_runner = (repo_root / 'tests/run_init_broker_regression.sh').read_text()
frame_native_test = (repo_root / 'tests/guest_frame_channel_test.c').read_text()
framebuffer_test = (repo_root / 'tests/guest_framebuffer_virtual_test.c').read_text()
frame_java_test = (repo_root / 'tests/GuestFramePacketTest.java').read_text()
framebuffer_model = Path(sys.argv[1]).with_name('guest_framebuffer_virtual.h').read_text()
identity_model = Path(sys.argv[1]).with_name('guest_identity_compat.h').read_text()
guest_image = repo_root / 'guest-image/google-api10-android-2.3.7'
aosp_source_root = Path(os.environ.get('GINGERVM_AOSP_SOURCE_ROOT', repo_root.parent / 'build/aosp'))
api10_init_path = aosp_source_root / 'system-core/init/init.c'
api10_util_path = aosp_source_root / 'system-core/init/util.c'
api10_ueventd_path = aosp_source_root / 'system-core/init/ueventd.c'
api10_devices_path = aosp_source_root / 'system-core/init/devices.c'
api10_source_available = all(path.is_file() for path in
    (api10_init_path, api10_util_path, api10_ueventd_path, api10_devices_path))
api10_init_source = api10_init_path.read_text() if api10_source_available else ''
api10_util_source = api10_util_path.read_text() if api10_source_available else ''
api10_ueventd_source = api10_ueventd_path.read_text() if api10_source_available else ''
api10_devices_source = api10_devices_path.read_text() if api10_source_available else ''
system_build_prop = (guest_image / 'system-tree/build.prop').read_text()
ramdisk_default_prop = (guest_image / 'ramdisk-root/default.prop').read_text()
goldfish_rc = (guest_image / 'ramdisk-root/init.goldfish.rc').read_text()
goldfish_script = (guest_image / 'system-tree/etc/init.goldfish.sh').read_text()
ueventd_rc = (guest_image / 'guest-root-staging/ueventd.rc').read_text()
activity = Path(sys.argv[2]).read_text()
capture = Path(sys.argv[2]).with_name('TraceOutputCapture.java').read_text()
tree_cleanup = Path(sys.argv[2]).with_name('AppPrivateTreeCleanup.java').read_text()
provider = Path(sys.argv[2]).with_name('TraceLogProvider.java').read_text()
gradle = Path(sys.argv[3]).read_text()
manifest = Path(sys.argv[4]).read_text()
theme_path = Path(sys.argv[4]).parent / 'res/values/styles.xml'
theme = theme_path.read_text()
stager = Path(sys.argv[5]).read_text()
build_path = Path(sys.argv[6]).resolve()
build = build_path.read_text()
workflow = (build_path.parents[1] / '.github/workflows/gingervm.yml').read_text()
signing_mask_script = (build_path.parents[1] / '.github/scripts/mask_gingervm_test_signing.sh').read_text()

# No privileged host mounts or host sockets; guest behavior stays app-private/software-only.
assert not re.search(r'(?<![A-Za-z0-9_])mount\s*\(', src)
assert not re.search(r'(?<![A-Za-z0-9_])umount2?\s*\(', src)
for name in ("socket", "socketpair", "bind", "listen"):
    assert not re.search(r'(?<![A-Za-z0-9_])' + name + r'\s*\(', src), name
assert '#define ARM_NR_SOCKET 281' in src and '#define ARM_NR_BIND 282' in src
assert '#define ARM_NR_SETSOCKOPT 294' in src
assert 'guest_uevent_socket_args_valid(domain, type, protocol)' in src
assert 'guest_uevent_bind_args_valid(&addr, address_length' in src
assert 'guest_uevent_setsockopt_args_valid(level, option, value, value_length)' in src
assert '#define ARM_NR_FTRUNCATE 93' in src and 'guest_ftruncate_app_private' in src
assert 'GUEST FILE FTRUNCATE:' in src and 'VIRTUAL FILE OPS:' in src
assert 'GUEST VFS SYMLINK:' in src and 'guest_symlink_create_app_private' in src
assert 'VIRTUAL SYMLINK OPS:' in src and 'rewrite_symlink' not in src
assert 'path_is_within(link_host, guest_root)' in src
assert 'path_is_within(target_host, native_guest_root)' in src
assert 'guest_null_stdio_actor_for_tracee(active_tracee) ==' in src
assert 'GUEST_NULL_STDIO_ACTOR_UEVENTD' in src
assert 'GUEST UEVENTD EXEC IMAGE VALIDATED:' in src
assert 'GUEST UEVENTD NULL STDIO READY:' in src
assert 'guest_parent_pid == 1' in null_stdio
assert 'VIRTUAL UEVENT SOCKET:' in src and 'GUEST SOCKET ARGS:' in src
assert 'VIRTUAL UEVENT BIND:' in src and 'VIRTUAL UEVENT SETSOCKOPT:' in src
assert 'host socket API not called' in src and 'host bind API not called' in src
assert 'host setsockopt API not called' in src
assert 'GUEST POLL DIAGNOSTIC:' in src and 'virtual_fd_source(fds[i].fd)' in src
assert 'timeout-ms=%d' in src and 'revents-in=0x%04x revents-out=0x%04x' in src
assert 'empty guest-only uevent queue' in src
assert 'guest_vsocket_poll_events(' in src and '&guest_sockets, fd, fds[i].events' in src
assert 'VIRTUAL PROPERTY SOCKET CREATE:' in src and 'VIRTUAL PROPERTY BIND:' in src
assert 'VIRTUAL PROPERTY LISTEN:' in src and 'VIRTUAL PROPERTY ACCEPT:' in src
assert 'VIRTUAL PROPERTY CONNECT:' in src and 'VIRTUAL PROPERTY SO_PEERCRED:' in src
assert '#define ARM_NR_SENDTO 290' in src and '#define ARM_NR_RECVFROM 292' in src
assert 'virtual_guest_property_stream_io' in src and 'VIRTUAL PROPERTY STREAM SYSCALL:' in src
assert 'VIRTUAL PROPERTY STREAM SUMMARY:' in src and 'app-private connected AF_UNIX stream only' in src
assert 'ET_EXEC-e_entry-PC-hits=%lu (app_process=%lu ueventd=%lu other=%lu)' in src
assert 'ARM sendto=%lu bytes=%lu recvfrom=%lu bytes=%lu errors=%lu' in src
assert 'host AF_UNIX socket/socketpair/bind/connect/listen/accept/setsockopt/getsockopt/send/recv/sendto/recvfrom calls=0' in src
assert 'VIRTUAL SIGNAL SOCKETPAIR:' in src and 'VIRTUAL GUEST SOCKET IO:' in src
assert 'endpoint=%s direction=%s' in src and 'sigchld-socketpair' in src
assert 'guest_vsocket_property_stream_validate(&guest_sockets, fd' in src
assert 'guest_vsocket_sendto(&guest_sockets, fd' in src
assert 'guest_vsocket_peek(&guest_sockets, fd, buffer, amount, 0)' in src
assert 'read_remote(pid, buffer_address, buffer, amount)' in src
assert 'write_remote(pid, buffer_address, buffer' in src
assert 'guest_vsocket_property_stream_validate' in socket_model
assert 'GUEST_API10_PROP_NAME_MAX 32u' in property_protocol
assert 'GUEST_API10_PROP_VALUE_MAX 92u' in property_protocol
assert 'sizeof(struct guest_api10_prop_msg) == 128u' in property_protocol
assert 'request.cmd = GUEST_API10_PROP_MSG_SETPROP' in property_socket_test
assert 'strcmp(received.name, "sys.gingervm.test")' in property_socket_test
assert '== -EAGAIN' in property_socket_test and '== -EOPNOTSUPP' in property_socket_test
assert '== -ENOTSOCK' in property_socket_test and '== -EPIPE' in property_socket_test
assert 'guest_socket_marker_create_app_private(host_path, guest_root)' in src
assert 'close_virtual_fds_on_exec(state)' in src and 'child_state->virtual_fd_table_id' in src
assert 'tracee_owns_virtual_fd' in src and 'GUEST_VSOCKET_POLLNVAL' in src
diagnostic_test = Path(sys.argv[1]).parents[4] / 'tests/guest_diagnostics_test.c'
ptrace_sigsys_test = Path(sys.argv[1]).parents[4] / 'tests/ptrace_seccomp_sigsys_regression.c'
sigmask_test = Path(sys.argv[1]).parents[4] / 'tests/guest_sigprocmask_compat_test.c'
ptrace_sigmask_test = Path(sys.argv[1]).parents[4] / 'tests/ptrace_sigprocmask_seccomp_regression.c'
assert 'guest_diag_escape' in diagnostics and 'guest_diag_errno_name' in diagnostics
assert 'case 126: return "sigprocmask"' in diagnostics
assert '#define ARM_NR_SIGPROCMASK 126' in src
assert 'if (nr == ARM_NR_SIGPROCMASK)' in src and 'mediate_guest_sigprocmask(pid, state, regs, pending_return)' in src
assert 'GUEST SIGPROCMASK COMPAT:' in src and 'GUEST SIGPROCMASK PTRACE FAILURE:' in src
assert 'refusing fake success' in src and 'PTRACE_GETSIGMASK/SETSIGMASK' in src
assert 'probe_tracee_sigmask_api(pid)' in trace and 'real-mask-preserved=1' in src
assert 'guest_sigprocmask_apply_low_word' in sigmask_compat
assert 'GUEST_ARM_SIGPROCMASK_HIGH_WORD_MASK' in sigmask_compat
assert 'ops->set_mask(ops->context, after)' in sigmask_compat
assert 'ops->write_u32(ops->context, old_set_address, report->old_set)' in sigmask_compat
assert '#define PTRACE_GETSIGMASK 0x420a' in sigmask_ptrace
assert '#define PTRACE_SETSIGMASK 0x420b' in sigmask_ptrace
assert 'test_bad_oldset_occurs_after_mask_update' in sigmask_test.read_text()
assert 'test_ptrace_failures_are_internal_not_guest_success' in sigmask_test.read_text()
assert 'SYS_rt_sigprocmask' in ptrace_sigmask_test.read_text()
assert 'pending SIGUSR1 delivered after SIG_UNBLOCK' in ptrace_sigmask_test.read_text()
assert 'guest_diag_parse_proc_maps_line' in sigsys_context
assert 'guest_diag_find_proc_map' in sigsys_context and 'guest_diag_read_proc_seccomp_mode' in sigsys_context
assert '0xafd0bf6c' in diagnostic_test.read_text() and '0xbf6c' in diagnostic_test.read_text()
assert 'guest_diag_find_proc_map(getpid()' in diagnostic_test.read_text()
assert 'test_nonplaceholder_sigsys_is_forwarded' in ptrace_sigsys_test.read_text()
assert 'test_nonplaceholder_sigsys_is_forwarded(126)' in ptrace_sigsys_test.read_text()
assert 'broker_sigsys_take(&candidate, SIGSYS, info.si_code, info.si_syscall)' in ptrace_sigsys_test.read_text()
assert 'PTRACE_CONT, child, NULL, (void *)(uintptr_t)SIGSYS' in ptrace_sigsys_test.read_text()
assert 'MAX_BROKER_DENIAL_DIAGNOSTICS 24u' in src
assert 'MAX_EXEC_FAILURE_DIAGNOSTICS 16u' in src
assert 'GUEST EXEC FAILURE DETAIL' in src and 'BROKER DENIED DETAIL' in src
assert 'guest-executable=' in src and 'errno=%d(%s) reason=%s' in src
assert 'guest_diag_escape' in src and 'state->last_syscall_args' in src
assert 'pending_exec_target' in src and 'child_state->exec_target' in src
assert 'kernel-execve-returned-error-after-path-rewrite' in src
assert '#include "ptrace_child_stop_queue.h"' in src
assert 'PTRACE CHILD INITIAL STOP DEFERRED:' in src
assert 'PTRACE CHILD INITIAL STOP ADOPTED:' in src
assert 'ptrace_child_stop_queue_take' in src and 'set_guest_trace_options(child_pid)' in src
assert 'ptrace_child_stop_capacity_available' in src
assert 'pending_child_stops.entries[i].pid' in src and 'pending_child_stop_queued_for_cleanup' in src
assert 'ptrace_child_wait_status_is_initial_stop' in pending_child_stops
assert 'ptrace_child_stop_capacity_available' in pending_child_stops
assert 'PTRACE_PENDING_CHILD_STOP_LIMIT 32u' in pending_child_stops
assert 'exact parent-event PID match required' in pending_child_stop_test
assert 'ptrace_child_stop_queue_take' in pending_child_stop_test
assert 'test_pending_stops_share_the_tracee_budget' in pending_child_stop_test
assert '#include "guest_script_launch.h"' in src
assert 'mediate_guest_script_execve' in src and 'guest_script_path_is_whitelisted(guest)' in src
assert 'guest_script_file_is_authorized' in src and 'O_NOFOLLOW' in src
assert 'guest_script_launch_is_authorized' in src
assert 'guest_script_mode_is_executable((uint32_t)opened_st.st_mode)' in src
assert 'pread(script_fd, shebang' in src and 'guest_script_has_approved_shebang' in src
assert 'guest-script-shebang-is-not-approved-system-shell' in src
assert 'guest_script_log_exec_route' in src and 'guest_script_log_launch_event' in src
assert 'GUEST SCRIPT LAUNCH SUMMARY:' in src
assert 'host-shell-exec=0 same-tracee=1' in script_launch
assert 'guest_script_plan_argv' in src and 'regs->uregs[1] = plan.argv_address' in src
assert 'GUEST_API10_SHELL_PATH' in src and 'GUEST_API10_GOLDFISH_SCRIPT' in src
assert 'guest_script_collect_preserved_args' in src
assert 'PTRACE_O_TRACEEXEC' in src and 'if (event == PTRACE_EVENT_EXEC)' in src
assert 'guest_script_exec_started_count++' in src
assert 'guest-script-shell-linker-entry=observed' in src
assert 'guest-script-path-not-whitelisted' in src
assert 'resolved-executable-outside-approved-native-root' in src
assert 'GUEST_SCRIPT_LAUNCH_MAX_BYTES 2048u' in script_launch
assert 'strcmp(guest_path, GUEST_API10_GOLDFISH_SCRIPT) == 0' in script_launch
assert 'canonical_system_root' in script_launch and 'resolved_script' in script_launch
assert 'GUEST_API10_SHELL_PATH' in script_launch and 'GUEST_API10_GOLDFISH_SCRIPT' in script_launch
assert 'guest_script_mode_is_executable' in script_launch and 'guest_script_has_approved_shebang' in script_launch
assert 'guest_script_launch_is_authorized' in script_launch
assert 'GUEST SCRIPT EXEC ROUTE:' in script_launch and 'GUEST SCRIPT LAUNCH EVENT:' in script_launch
script_test = Path(sys.argv[1]).parents[4] / 'tests/guest_script_launch_test.c'
assert 'test_guest_script_path_and_symlink_containment' in script_test.read_text()
assert 'test_original_argv_collection' in script_test.read_text()
assert 'test_shell_launcher_argv_layout' in script_test.read_text()
assert 'assert_shared_route_markers' in script_test.read_text()
assert 'int route_authorized = guest_script_launch_is_authorized' in script_test.read_text()
assert 'if (route_authorized) assert_shared_route_markers()' in script_test.read_text()
assert 'guest_script_mode_is_executable((uint32_t)script_stat.st_mode)' in script_test.read_text()
assert 'guest script launch integration regression: PASS' in script_test.read_text()
mode_helper = Path(sys.argv[2]).with_name('AppPrivateFileModeRestorer.java').read_text()
mode_test = Path(sys.argv[1]).parents[4] / 'tests/AppPrivateFileModeRestorerTest.java'
assert 'ops.openReadOnlyNoFollow(target.file)' in mode_helper and 'ops.fchmod(descriptor, safeMode)' in mode_helper
assert 'validateRelativePath' in mode_helper and 'refusing guest mode traversal through a symlink' in mode_helper
assert 'O_NOFOLLOW' in activity and 'Os.fchmod((FileDescriptor) descriptor' in activity
assert 'restoreSystemAssetModes(systemRoot, manifest)' in activity
staging = activity.split('copyAssetTree("api10-system", systemRoot)', 1)[1].split(
    'installNativeSystemPayloads(systemRoot, guestLibraryDir)', 1)[0]
assert staging.index('restoreSystemAssetNames') < staging.index('restoreSystemAssetModes') < staging.index('restoreSystemSymlinks')
assert 'AppPrivateFileModeRestorer.verify(systemRoot, relative, sourceMode, fileModeOps)' in activity
assert 'source_stat = source.lstat()' in stager and 'stat.S_IMODE(source_stat.st_mode)' in stager
assert '"mode": source_mode' in stager
assert '0550' in mode_test.read_text() and 'final-link.sh' in mode_test.read_text()
assert 'outside-parent/outside.sh' in mode_test.read_text() and '../outside.sh' in mode_test.read_text()
assert 'GUEST STARTUP STAGE: linker-entry=observed' in src
assert 'GUEST TARGET ELF CODE PC:' in src and 'this is not proof of C main()' in src
assert 'GUEST TARGET ELF ENTRY METADATA:' in src and 'metadata only' in src
assert 'pending_exec_backing_path' in src and 'exec_backing_path' in src
assert 'guest_elf32_arm_entrypoint' in src and 'e_entry-PC-at-syscall' in src
assert 'GUEST SIGCHLD FORWARDED:' in src and 'count_unreaped_guest_children' in src
assert 'GUEST CHILD EXIT STATUS:' in src and 'GUEST WAIT4 ABI:' in src
assert 'GUEST WAIT4 REAP:' in src and 'guest_wait4_calls' in src
assert '#define ARM_NR_WAIT4 114' in src and 'ARM_NR_WAITPID' not in src
assert 'guest_syscall_policy(7) == GUEST_SYSCALL_DENY' in Path(sys.argv[1]).parents[4].joinpath('tests/init_broker_policy_test.c').read_text()
assert 'GUEST EMULATOR SERVICE EXEC:' in src and 'GUEST EMULATOR SERVICE EXIT:' in src
assert 'guest_qemud_exec_count' in src and 'guest_qemu_props_exec_count' in src
assert '#include "guest_qemud_diagnostics.h"' in src
assert 'GUEST QEMUD TRANSPORT PROFILE:' in src
assert 'GUEST QEMUD SYSCALL:' in src and 'GUEST QEMUD STARTUP DIAGNOSTICS:' in src
assert 'GUEST QEMUD STDERR PREVIEW (escaped guest bytes):' in src
assert 'guest_qemud_diag_claim_stderr_preview' in src
assert 'guest_qemud_diag_escape_bytes' in src and 'read_remote(waited' in src
assert 'guest_qemud_diag_guest_range_valid' in src and 'if (read_ok)' in src
assert 'no guest bytes logged' in src
assert 'strcmp(state->exec_target, "/system/bin/qemud") == 0' in src
assert 'regs.uregs[14]' in src and 'exit_request_lr' in qemud_diagnostics
assert 'guest_qemud_diag_begin' in src and 'guest_qemud_diag_finish' in src
assert 'guest_qemud_diag_note_cmdline_read' in src and 'guest_qemud_diag_note_open' in src
assert 'GUEST_QEMUD_DIAG_MAX_RECORDS 96u' in qemud_diagnostics
assert 'GUEST_QEMUD_DIAG_RUN_MAX_LINES 256u' in qemud_diagnostics
assert 'GUEST_QEMUD_DIAG_STDERR_MAX_CHUNKS 4u' in qemud_diagnostics
assert 'GUEST_QEMUD_DIAG_STDERR_MAX_BYTES 96u' in qemud_diagnostics
assert 'guest_qemud_diag_is_selected_tty_path' in qemud_diagnostics
assert 'address_space_end - (uint64_t)address' in qemud_diagnostics
assert 'record->lr = state->pending_lr;' in qemud_diagnostics
assert 'result < 0' in qemud_diagnostics and 'records_suppressed++' in qemud_diagnostics
assert 'guest_qemud_diag_fd_path' in qemud_diagnostics
assert 'guest_qemud_diag_token_value' in qemud_diagnostics
assert 'guest_qemud_diag_run_budget_take' in src
assert 'guest_qemud_diag_safe_port_label(diag)' in src
assert 'guest_qemud_diag_claim_cmdline_observation' in src
assert 'guest_qemud_diag_dup_fd' in src
assert 'ARM_NR_FCNTL64' in src
assert 'case 221: return "fcntl64";' in Path(sys.argv[1]).with_name('guest_diagnostics.h').read_text()
assert 'state->last_syscall == ARM_NR_CLOSE && syscall_result == 0' in src
assert 'guest_qemud_diag_is_tty_s_path' in qemud_diagnostics
assert 'else guest_qemud_diag_untrack_fd(state, new_fd)' in qemud_diagnostics
assert 'case 221: /* fcntl64 */' in qemud_diagnostics
assert 'test_source_backed_profile_tokens' in qemud_test
assert 'test_selected_calls_and_failed_unselected_calls' in qemud_test
assert 'test_cmdline_fd_and_parameter_observation' in qemud_test
assert 'test_failure_armed_stderr_preview_is_bounded_and_escaped' in qemud_test
assert 'guest_qemud_diag_guest_range_valid(UINT32_MAX, 1u)' in qemud_test
assert 'guest_qemud_diag_is_selected_tty_path(&state, "/dev/ttyS2")' in qemud_test
assert 'test_record_budget_is_hard_bounded' in qemud_test
assert 'guest_qemud_diag_run_budget_take' in qemud_test
assert 'guest_qemud_diag_safe_port_label' in qemud_test
assert 'guest_qemud_diag_syscall_selected(221)' in qemud_test
assert 'guest_qemud_diag_is_tty_s_path("/dev/ttyS1-extra")' in qemud_test
assert 'PROCESS TREE LIMIT: refusing child host-pid=' in src
assert 'guest_tracee_slot_allocate(&tracee_slot_pool)' in src
assert 'guest_tracee_slot_mark_reaped(&tracee_slot_pool' in src
assert 'TRACE REGISTRY: hard-cap=' in src and 'maximum-active=' in src
assert 'test_trace_lifetime_pressure_requires_guest_reap' in Path(sys.argv[1]).parents[4].joinpath('tests/guest_tracee_slots_test.c').read_text()
assert 'test_api10_ifup_lo_flags_are_guest_only' in Path(sys.argv[1]).parents[4].joinpath('tests/guest_network_virtual_test.c').read_text()
assert 'GUEST DEVICE BACKEND DENIED:' in src and 'guest_device_unimplemented_reason(guest)' in src
assert 'pty-kernel-backend-not-implemented' in device_boundary
assert 'binder-software-bootstrap-only-no-ipc-transactions' in device_boundary
assert 'GUEST BINDER OPEN:' in src and 'GUEST BINDER IOCTL DENIED:' in src
assert 'GUEST BINDER MMAP ROUTE:' in src and 'GUEST BINDER MAPPING:' in src
assert 'guest_arm32_syscall_result_is_error(syscall_result_bits)' in src
assert 'uint32_t syscall_result_bits' in src
assert '0xe9380000u' in binder_test and '0xffff0000u' in binder_test
assert '0xe9380000u' in syscall_abi_test and '0xfffff001u' in syscall_abi_test
assert 'result_bits >= GUEST_ARM32_ERRNO_MIN' in syscall_abi
assert 'GUEST BINDER BLOCKED READ:' in src and 'guest-software-blocked-read' in src
assert 'no guest transaction queue exists, remains parked until bounded timeout/cancel' in src
assert 'GUEST BINDER FD OP DENIED:' in src and 'GUEST BINDER STREAM IO DENIED:' in src
assert 'GUEST BINDER BOOTSTRAP SUMMARY:' in src and 'guest_binder_state.mapping_successes++' in src
assert 'guest_binder_validate_open_flags(flags)' in src
assert 'guest_binder_ioctl_bootstrap(&state->binder' in src
assert 'scalar zero, not a user pointer' in binder_model
context_mgr = binder_model.split('case GUEST_BINDER_IOCTL_SET_CONTEXT_MGR:', 1)[1].split('case GUEST_BINDER_IOCTL_WRITE_READ:', 1)[0]
assert 'argument != 0' in context_mgr and 'copyin(' not in context_mgr
assert 'GUEST_BINDER_IOCTL_SET_CONTEXT_MGR, 0' in binder_test
assert 'regs->uregs[3] = flags | (uint32_t)MAP_ANONYMOUS' in src
assert 'guest_binder_process_exec_reset(&state->binder)' in src
assert 'child_state->binder = state->binder' in src
assert 'guest_binder_release_context_manager_if_dead' in src
assert 'transactions-supported=0' in src and 'no host ioctl called' in src
assert 'GUEST_BINDER_IOCTL_WRITE_READ 0xc0186201u' in binder_model
assert 'GUEST_BINDER_IOCTL_VERSION 0xc0046209u' in binder_model
assert 'GUEST_BINDER_PROTOCOL_VERSION 7' in binder_model
assert 'GUEST_BINDER_SERVICEMANAGER_MAP_BYTES (128u * 1024u)' in binder_model
assert 'GUEST_BINDER_PROCESS_MAP_BYTES ((1024u * 1024u) - (2u * 4096u))' in binder_model
assert 'GUEST_BINDER_BC_ENTER_LOOPER 0x0000630cu' in binder_model
assert 'GUEST_BINDER_BC_TRANSACTION 0x40286300u' in binder_model
assert 'GUEST_BINDER_READ_PARKED' in binder_model and 'return -EOPNOTSUPP' in binder_model
assert 'test unsupported transaction' not in binder_test.lower()
assert 'BC_TRANSACTION: not implemented' in binder_test
assert '== -EOPNOTSUPP' in binder_test and '== GUEST_BINDER_READ_PARKED' in binder_test
assert '== -EBUSY' in binder_test and '== -EFAULT' in binder_test
assert 'ashmem-kernel-backend-not-implemented' in device_boundary
assert 'goldfish-emulator-pipe-backend-not-implemented' in device_boundary
assert 'GUEST URANDOM READ:' in src and 'syscall(SYS_getrandom' in src
assert 'guest_pseudo_device_read_urandom' in src and 'GUEST_URANDOM_MAX_READ_BYTES' in pseudo_device
assert 'GUEST RANDOM DEVICE OP UNSUPPORTED:' in src
assert 'GUEST STARTUP STAGE SUMMARY' in src and 'BROKER DIAGNOSTIC SUMMARY' in src
assert 'guest_diag_escape("bad\\n\\033\\\"path"' in diagnostic_test.read_text()
assert 'GUEST_VSOCKET_MAX_FDS 32' in socket_model
assert 'guest_vsocket_connect' in socket_model and 'guest_vsocket_accept' in socket_model
assert 'guest_vsocket_peercred' in socket_model and 'guest_vsocket_poll_events' in socket_model
assert 'guest_vsocket_send' in socket_model and 'guest_vsocket_peek' in socket_model
assert 'guest_vsocket_socketcall_arg_count' in socket_model
assert 'GUEST_VSOCKET_PROPERTY_PATH "/dev/socket/property_service"' in socket_model
assert 'guest_socket_marker_create_app_private' in socket_path
assert 'openat(dirfd, leaf' in socket_path and 'O_NOFOLLOW' in socket_path
assert 'realpath(fd_path, opened_parent)' in socket_path
assert 'GUEST COLD-BOOT MARKER OPEN:' in src
assert 'GUEST UEVENTD COLD-BOOT MARKER PRECHECK:' in src
assert 'GUEST COLD-BOOT PID1 STAT:' in src
assert 'INIT COLD-BOOT WAIT CONDITION OBSERVED:' in src
assert 'INIT COLD-BOOT WAIT RELEASED:' in src
assert 'function return is source-inferred rather than directly traced' in src
assert 'ARM_NR_FSTATAT64' in src and 'pid1_stat_succeeded_after_marker' in src
assert 'guest_uevent_note_marker_open' not in src
assert 'GUEST COLD-BOOT MARKER FILE SUMMARY:' in src
assert 'guest_coldboot_marker_open_args_valid' in src
assert 'guest_coldboot_note_marker_close' in src
assert 'guest_safe_dir_open_beneath_root(guest_root, parent, 0, 0700)' in src
assert 'fstatat(dirfd, leaf, st, AT_SYMLINK_NOFOLLOW)' in src
assert 'diagnostic uses lstat only' not in src
assert 'API10 devices.c performs no marker write/fsync before close' in src
assert 'fdatasyncs=%lu' in src and 'marker-close-seen=%d' in src
coldboot_test = Path(sys.argv[1]).parents[4].joinpath('tests/guest_uevent_virtual_test.c').read_text()
assert 'test_api10_coldboot_sequence_model_and_marker_persistence' in coldboot_test
assert 'queue.enqueued == 1 && queue.delivered == 1 && queue.count == 0' in coldboot_test
assert 'O_WRONLY | O_CREAT' in coldboot_test and 'after.st_ino == opened.st_ino' in coldboot_test
assert 'API10 guest-only uevent/coldboot sequence-model regression: PASS' in coldboot_test
assert '#define GUEST_PROFILE_HARDWARE "goldfish"' in profile
assert '"qemu=1 android.qemud=ttyS1 androidboot.hardware=" GUEST_PROFILE_HARDWARE' in profile
assert '#define GUEST_PROFILE_CPU_COUNT 1u' in profile
assert 'explicit GingerVM synthetic defaults' in profile
assert 'androidboot.hardware=" GUEST_PROFILE_HARDWARE "\\n' in profile
assert 'Hardware : " GUEST_PROFILE_HARDWARE "\\n' in profile
assert 'GUEST_PROFILE_SYNTHETIC_RAM_TOTAL_KB 262144u' in profile
assert 'GUEST_PROFILE_SYNTHETIC_RAM_FREE_KB 131072u' in profile
assert 'MemTotal:       262144 kB' in profile and 'MemFree:        131072 kB' in profile
assert 'ro.build.version.sdk=10' in system_build_prop
assert 'ro.build.version.release=2.3.7' in system_build_prop
assert 'ro.product.model=sdk' in system_build_prop
assert 'ro.product.brand=generic' in system_build_prop
assert 'ro.product.device=generic' in system_build_prop
assert 'ro.product.cpu.abi=armeabi-v7a' in system_build_prop
assert 'ro.secure=0' in ramdisk_default_prop and 'ro.debuggable=1' in ramdisk_default_prop
assert 'GUEST_PROFILE_NET_ADDRESS "10.0.2.15"' in profile
assert 'GUEST_PROFILE_NET_NETMASK "255.255.255.0"' in profile
assert 'GUEST_PROFILE_NET_GATEWAY "10.0.2.2"' in profile
assert 'GUEST_PROFILE_NET_DNS1 "10.0.2.3"' in profile
for literal in ('ifconfig eth0 10.0.2.15 netmask 255.255.255.0 up',
                'route add default gw 10.0.2.2 dev eth0',
                'net.eth0.dns1 10.0.2.3'):
    assert literal in goldfish_script + goldfish_rc, literal
assert 'test_staged_init_goldfish_network_sequence' in network_test
assert 'guest_net_socket_args_valid' in network_test and '== -ENETDOWN' in network_test
for ioctl in ('GUEST_NET_SIOCSIFADDR', 'GUEST_NET_SIOCSIFNETMASK',
              'GUEST_NET_SIOCGIFFLAGS', 'GUEST_NET_SIOCSIFFLAGS',
              'guest_net_add_route'):
    assert ioctl in network_test, ioctl
assert 'guest_network_virtual_test.c' in network_test_runner
assert '$GUEST_BASE/system-tree/etc/init.goldfish.sh' in network_test_runner
assert 'GUEST_FRAME_PROTOCOL_MAGIC "GVMF"' in frame_channel
assert 'GUEST_FRAME_SOURCE_GUEST_FRAMEBUFFER 1u' in frame_channel
assert 'GUEST_FRAME_SOURCE_TEST_ONLY 2u' in frame_channel
assert 'GUEST_FRAME_MAX_PAYLOAD_BYTES 8388608u' in frame_channel
assert 'guest_frame_channel_validate_app_private_directory' in frame_channel
assert 'guest_frame_channel_open_app_private_sibling_ex' in frame_channel
assert 'root_parent_stat.st_dev != channel_parent_stat.st_dev' in frame_channel
assert 'root_parent_stat.st_ino != channel_parent_stat.st_ino' in frame_channel
assert 'openat(root_parent_fd, root_leaf' in frame_channel and 'openat(channel_parent_fd, channel_leaf' in frame_channel
assert 'guest_frame_channel_publish_file_at' in frame_channel
assert 'O_NOFOLLOW' in frame_channel and 'renameat(dirfd' in frame_channel
assert 'guest_frame_channel_open_directory_path_nofollow' in frame_channel
assert 'fstatat(fd, component->name, &before_open, AT_SYMLINK_NOFOLLOW)' in frame_channel
assert 'GUEST_FRAME_CHANNEL_PARENT_UNSAFE_WRITABLE' in frame_channel
assert 'guest_frame_channel_parent_mode_safe(root_parent_stat.st_mode' in frame_channel
assert 'foreign_group, getgid()' in frame_native_test
assert 'GUEST_FRAME_CHANNEL_GUEST_ROOT_NOT_PRIVATE' in frame_channel
assert 'guest_frame_channel_test.c' in network_test_runner and 'GuestFramePacketTest.java' in network_test_runner
assert 'GUEST_FRAME_SOURCE_GUEST_FRAMEBUFFER' in frame_native_test and 'symlink(target_dir, link_dir)' in frame_native_test
assert 'test-only frame source must never be accepted' in frame_java_test and 'checksum' in frame_java_test
frame_packet = Path(sys.argv[2]).with_name('GuestFramePacket.java').read_text()
assert 'decodeGuestFramebuffer' in frame_packet and 'SOURCE_GUEST_FRAMEBUFFER' in frame_packet
assert 'MAX_PIXELS' in frame_packet and 'MAX_PAYLOAD_BYTES' in frame_packet
assert 'source is not a guest framebuffer' in frame_packet
assert 'payload checksum mismatch' in frame_packet and 'unsupported guest framebuffer bits-per-pixel' in frame_packet
assert 'GUEST FRAME CHANNEL CONFIG:' in src and 'unsetenv(GUEST_FRAME_CHANNEL_ENV)' in src
assert 'expected-sibling=%s reason=%s' in src and 'guest_frame_channel_validation_reason_name(validation.reason)' in src
assert 'GUEST FRAME CHANNEL PATH COMPONENT:' in src and 'GUEST FRAME CHANNEL LEAF AUDIT:' in src
assert 'scope=%s errno=%d' in src and 'guest_frame_channel_scope_name' in src
assert 'guest_frame_channel_open_directory_path_nofollow' in src and 'GUEST ROOT REJECTED:' in src
assert 'frameGuestRoot.getParentFile()' in activity and 'new File(frameParent, GuestFramePacket.CHANNEL_DIRECTORY)' in activity
assert 'GUEST MKNOD MEDIATION: guest-pid=%d executable=%s path=\\"%s\\" path-truncated=%d syscall=%s' in src
assert 'mode=0%o type=%s permissions=0%04o device=0x%08x major=%u minor=%u' in src
assert 'GUEST MKNOD DIAGNOSTICS: emitted=%lu suppressed=%lu' in src
assert 'mknod-must-use-path-containment-broker' in src
assert 'guest_syscall_policy(14) == GUEST_SYSCALL_PATH_REWRITE' in policy_test
assert 'guest_syscall_policy(324) == GUEST_SYSCALL_PATH_REWRITE' in policy_test
assert 'guest_syscall_policy(54) == GUEST_SYSCALL_VIRTUAL_DEVICE' in policy_test
assert 'gingervm_publish_guest_frame_from_fb' in src and 'guest_frame_channel_publish_file_at' in src
assert 'guest_fb0_backing_fd, guest_frame_directory_fd' in src
assert 'BuildConfig.VERSION_NAME' in activity and 'BuildConfig.VERSION_CODE' in activity
assert 'BuildConfig.GINGER_SOURCE_COMMIT' in activity
main_source = src.split('int main(', 1)[1]
assert main_source.index('configure_guest_frame_channel();') < main_source.index('start_guest(')
assert 'GUEST BINDER BOOTSTRAP SUMMARY:' in src
assert main_source.index('int rc = run_trace(') < main_source.index('GUEST BINDER BOOTSTRAP SUMMARY:')
assert 'GUEST FB0 OUTPUT SUMMARY:' in src and 'GUEST FB0 PAGE FLIP FRAME:' in src
assert 'GUEST FB0 SOFTWARE BASE-UPDATE ACK:' in src and 'software-base-update-acks=%lu' in src
assert 'mediate_guest_fb0_ioctl' in src and 'mediate_guest_fb0_mmap' in src
assert 'ARM_NR_MMAP2' in src and 'GUEST FB0 MMAP2:' in src
assert 'guest_fb0_open_authorized' in src and 'guest_fb0_mknod_rejection_reason' in src
assert 'guest_mknod_create_app_private_device' in src
assert 'guest-device-mknod-backend-not-implemented' in src
assert 'make_guest_device(' not in src
assert 'GUEST FB0 GRAPHICS UEVENT RECEIVED:' in src and 'GUEST FB0 NODE CREATED:' in src
assert 'GUEST_FB0_IOCTL_GET_VSCREENINFO' in framebuffer_model
assert 'GUEST_FB0_IOCTL_GET_FSCREENINFO' in framebuffer_model
assert 'GUEST_FB0_IOCTL_PAN_DISPLAY' in framebuffer_model and 'guest_fb0_capture_publish' in framebuffer_model
assert 'guest_fb0_mknod_path_rejection_reason' in framebuffer_model
assert 'guest_fb0_create_app_private_placeholder' in framebuffer_model
assert 'guest_mknod_create_app_private_device' in framebuffer_model
assert 'guest_uevent_enqueue_coldboot_add' in framebuffer_test
assert 'graphics_event_consumed' in framebuffer_test and 'GUEST_FB0_PATH' in framebuffer_test
assert 'guest_mknod_create_app_private_device' in framebuffer_test
assert '"/dev/graphics/fb1"' in framebuffer_test and '"/dev/binder"' in framebuffer_test
assert 'guest_syscall_policy(14) == GUEST_SYSCALL_PATH_REWRITE' in policy_test
assert 'guest_syscall_policy(324) == GUEST_SYSCALL_PATH_REWRITE' in policy_test
assert 'guest_frame_channel_publish_file_at(frame_directory_fd, &packet)' in framebuffer_model
assert 'guest_fsgid != GUEST_FB0_OWNER_GID' in framebuffer_model
assert 'GUEST_FB0_OWNER_GID GUEST_ID_AID_GRAPHICS' in framebuffer_model
assert 'software_base_update_acks++' in framebuffer_model
assert 'sizeof(struct guest_arm32_fb_var_screeninfo) == 160u' in framebuffer_model
assert 'fsuid == 0u' in identity_model and 'fsgid == GUEST_ID_AID_GRAPHICS' in identity_model
assert 'guest_identity_compat_test.c' in network_test_runner
assert 'guest_framebuffer_virtual_test.c' in network_test_runner
assert 'GuestFramebufferPacketTest.java' in network_test_runner
assert 'FileObserver.MOVED_TO' in activity and 'OsConstants.O_NOFOLLOW' in activity
assert 'ensurePrivateGuestRootDirectory(guestRoot)' in activity
assert 'Os.fchmod(fd, 0700)' in activity and 'Process.myUid()' in activity
assert 'O_DIRECTORY_FLAG = 0x00010000' in activity and 'guest root could not be restricted' in activity
assert 'GuestFramePacket.decodeGuestFramebuffer(bytes)' in activity
assert 'Bitmap.createBitmap(frame.argb, frame.width, frame.height' in activity
assert 'builder.environment().put(GuestFramePacket.CHANNEL_ENVIRONMENT' in activity
assert '尚無真實 guest 畫面' in activity and 'guest fb0 mmap／page-flip 產生並驗證的像素' in activity
assert 'setImageBitmap(bitmap)' in activity and 'Binder 僅有啟動握手' in activity
for node in ('/dev/null', '/dev/zero', '/dev/full', '/dev/random', '/dev/urandom', '/dev/ashmem', '/dev/binder'):
    assert node in ueventd_rc, node
assert 'GUEST_MODE_IFCHR 0020000u' in pseudo_device
assert 'GUEST PSEUDO-DEVICE STAT64:' in src and 'GUEST PSEUDO-DEVICE FSTAT64:' in src
assert 'guest_pseudo_device_backing_present(guest)' in src
assert 'guest_safe_file_open_beneath_root' in src and 'O_NOFOLLOW' in safe_dir
assert 'GUEST TEMP DEVICE OPEN:' not in src
assert '#include "guest_null_stdio.h"' in src
for marker in ('GUEST NULL DEVICE MKNOD:', 'GUEST NULL DEVICE OPEN:',
               'GUEST NULL DEVICE UNLINK:', 'GUEST NULL STDIO DUP2:',
               'GUEST NULL STDIO IO:', 'GUEST NULL STDIO SUMMARY:'):
    assert marker in src, marker
assert 'GUEST UEVENTD EXEC IMAGE VALIDATED:' in src
assert 'GUEST UEVENTD NULL STDIO READY:' in src
assert 'GUEST UEVENTD NULL STDIO SUMMARY:' in src
assert 'INIT COLD-BOOT WAIT RELEASED:' in src
assert 'guest_null_stdio_actor_for_identity' in src
assert 'exec_image_committed' in src and 'backing_path_approved' in src
assert 'guest_parent_pid == 1' in null_stdio and '"/sbin/ueventd"' in null_stdio
assert 'guest_ueventd_null_stdio_note_step' in src
assert 'guest_null_stdio_virtual_fd_valid' in src and 'child_state->null_stdio_mask = state->null_stdio_mask' in src
assert 'set_guest_null_stdio_mask_for_group' in src and 'guest_null_stdio_source_fd_closed' in src
assert 'guest_null_stdio_runtime_init(&guest_null_stdio_runtime)' in src
assert 'GUEST_NULL_STDIO_MODE 020600u' in null_stdio
assert 'GUEST_NULL_STDIO_DEVICE 0x00000103u' in null_stdio
assert 'GUEST_ARM32_O_LARGEFILE 0400000u' in null_stdio
assert 'guest_null_stdio_mknod' in null_stdio and 'guest_null_stdio_open_validate' in null_stdio
assert 'guest_null_stdio_unlink' in null_stdio and 'guest_null_stdio_dup2' in null_stdio
assert 'guest_null_stdio_io' in null_stdio and 'guest_null_stdio_close' in null_stdio
null_stdio_code = re.sub(r'/\*.*?\*/|//[^\n]*', '', null_stdio, flags=re.S)
assert not re.search(r'(?<![A-Za-z0-9_])(mknod|open|unlink)\s*\(', null_stdio_code)
assert 'test_exact_init_sequence' in null_stdio_test and 'test_open_failure_still_unlinks' in null_stdio_test
assert 'test_ueventd_identity_and_stdio_sequence' in null_stdio_test
assert 'backing_path_approved = 0' in null_stdio_test and 'guest_parent_pid = 9' in null_stdio_test
assert '"/dev/__kmsg__"' in null_stdio_test and '"/dev/__null__/../null"' in null_stdio_test
assert 'guest null-device init/ueventd stdio state-machine regression: PASS' in null_stdio_test
assert 'guest binaries are not executed' in null_stdio_test
assert path_syscall_source.index('strcmp(guest, GUEST_NULL_STDIO_PATH) == 0') < path_syscall_source.index('rewrite_path_arg(pid, regs, arg, guest')
assert 'decoded exact-path broker requests, not all syscalls' in src
assert '#include "guest_kmsg_virtual.h"' in src
assert 'guest_kmsg_runtime_init(&guest_kmsg_runtime)' in src
for marker in ('GUEST KMSG MKNOD:', 'GUEST KMSG OPEN:', 'GUEST KMSG FD FLAGS:',
               'GUEST KMSG UNLINK:', 'GUEST KMSG WRITE:', 'GUEST KMSG SUMMARY:'):
    assert marker in src, marker
assert 'guest_kmsg_note_write(&guest_kmsg_runtime, fd, result)' in src
assert 'guest_kmsg_note_fcntl(&guest_kmsg_runtime' in src
assert 'guest_kmsg_note_fd_closed(&guest_kmsg_runtime' in src
assert 'guest_kmsg_runtime.node_present' in src and 'guest_kmsg_runtime.unlinked' in src
assert 'GUEST_KMSG_MODE 0020600u' in kmsg_model
assert 'GUEST_KMSG_DEVICE 0x0000010bu' in kmsg_model
assert 'guest_kmsg_is_api10_init' in kmsg_model and 'guest_kmsg_open_validate' in kmsg_model
assert 'GUEST_KMSG_O_WRONLY' in kmsg_model and 'GUEST_KMSG_FD_CLOEXEC' in kmsg_model
kmsg_code = re.sub(r'/\*.*?\*/|//[^\n]*', '', kmsg_model, flags=re.S)
assert not re.search(r'(?<![A-Za-z0-9_])(mknod|open|unlink|write)\s*\(', kmsg_code)
assert path_syscall_source.index('strcmp(guest, GUEST_KMSG_PATH)') < path_syscall_source.index('rewrite_path_arg(pid, regs, arg, guest')
assert 'guest_kmsg_note_fd_closed' in src and 'virtual_fd_referenced(fd), 1' in src
assert 'GUEST VIRTUAL FD DUP DENIED:' in src and 'no host dup2 called' in src
assert 'if (nr == ARM_NR_DUP)' in src and 'is_virtual_fd_number(fd) || null_stdio_source' in src
assert 'is_virtual_fd_number((int32_t)regs->uregs[1])' in src
assert 'guest_null_stdio_virtual_fd_valid' in dup_guard_source
assert 'guest_null_stdio_fd_is_null' in dup_guard_source
assert 'guest_init_post_stdio_test.c' in network_test_runner
assert 'GUEST INIT CONFIG SEEK END:' in src and 'GUEST INIT CONFIG SEEK START:' in src
assert 'GUEST INIT CONFIG FILE CLOSE:' in src and 'file-size-read-close-complete=%d' in src
assert 'track->expected_file_size' in src and 'ARM_NR_LSEEK' in src
assert 'track->size_known' in src and 'track->start_seek_succeeded' in src
assert 'parser/action execution is not inferred from this syscall' in src
assert 'guest_init_config_read' in src and 'observe_guest_init_config_io(state, syscall_result)' in src
assert 'test_continuous_init_to_ueventd_coldboot_model' in kmsg_test
assert 'start ueventd' in kmsg_test
assert 'service goldfish-setup /system/etc/init.goldfish.sh' in kmsg_test
assert 'guest_uevent_socket_args_valid' in kmsg_test and 'guest_uevent_bind_args_valid' in kmsg_test
assert 'GUEST_COLD_BOOT_MARKER_PATH' in kmsg_test and 'marker_stat_pair_observed' in kmsg_test
if api10_source_available:
    api10_null_stdio = api10_util_source.split('void open_devnull_stdio(void)', 1)[1].split('\n}', 1)[0]
    for operation in ('mknod(name, S_IFCHR | 0600, (1 << 8) | 3)',
                      'open(name, O_RDWR)', 'unlink(name)', 'dup2(fd, 0)',
                      'dup2(fd, 1)', 'dup2(fd, 2)', 'exit(1)'):
        assert operation in api10_null_stdio, operation
    api10_log_init = api10_util_source.split('void log_init(void)', 1)[1].split('\n}', 1)[0]
    for operation in ('mknod(name, S_IFCHR | 0600, (1 << 8) | 11)',
                      'log_fd = open(name, O_WRONLY)',
                      'fcntl(log_fd, F_SETFD, FD_CLOEXEC)', 'unlink(name)'):
        assert operation in api10_log_init, operation
    assert 'exit(' not in api10_log_init
    api10_ueventd_main = api10_ueventd_source.split('int ueventd_main(', 1)[1].split('\n}', 1)[0]
    assert api10_ueventd_main.index('open_devnull_stdio();') < api10_ueventd_main.index('log_init();') < api10_ueventd_main.index('device_init();')
    api10_device_init = api10_devices_source.split('void device_init(void)', 1)[1].split('\n}', 1)[0]
    assert api10_device_init.index('open_uevent_socket()') < api10_device_init.index('coldboot("/sys/class")') < api10_device_init.index('open(coldboot_done, O_WRONLY|O_CREAT, 0000)') < api10_device_init.index('close(fd)')
    api10_main = api10_init_source.split('int main(', 1)[1]
    assert api10_main.index('open_devnull_stdio();') < api10_main.index('log_init();') < api10_main.index('init_parse_config_file("/init.rc")')
    assert api10_main.index('init_parse_config_file("/init.rc")') < api10_main.index('import_kernel_cmdline(0)') < api10_main.index('get_hardware_name(hardware, &revision)') < api10_main.index('init_parse_config_file(tmp)') < api10_main.index('action_for_each_trigger("early-init", action_add_queue_tail)')
    api10_read_file = api10_util_source.split('void *read_file(const char *fn, unsigned *_sz)', 1)[1].split('\n}', 1)[0]
    assert 'lseek(fd, 0, SEEK_END)' in api10_read_file
    assert 'lseek(fd, 0, SEEK_SET)' in api10_read_file
    assert 'read(fd, data, sz) != sz' in api10_read_file and 'close(fd)' in api10_read_file
    print('API10 AOSP init/ueventd/devices/util source contract: PASS')
else:
    print('API10 AOSP init/ueventd/devices/util source contract: SKIP (source tree absent from this checkout; the local source-backed build runs these assertions when present)')
assert 'GUEST NULL STDIO SUMMARY:' in src
assert 'GUEST HARDWARE PROFILE:' in src and 'not host-phone data' in src
assert 'packet I/O=unavailable, host network calls=0' in src
assert 'guest_safe_dir_open_beneath_root' in src and 'guest_safe_dir_open_beneath_root' in safe_dir
assert 'O_NOFOLLOW' in safe_dir and 'AT_SYMLINK_NOFOLLOW' in safe_dir
assert 'symlink(outside, link_path)' in safe_dir_test and 'symlink(real_directory, second_link)' in safe_dir_test
assert 'root, "../outside/escape"' in safe_dir_test and 'no outside writes' in safe_dir_test
assert 'unlink(marker_path)' in src and 'INIT STATE: initial actions reached' not in src
assert 'GUEST_UEVENT_NETLINK_KOBJECT_UEVENT 15u' in uevent
assert 'GUEST_UEVENT_RCVBUFFORCE_BYTES 65536' in uevent
assert 'guest_uevent_socket_args_valid' in uevent and 'guest_uevent_bind_args_valid' in uevent
assert 'guest_uevent_setsockopt_args_valid' in uevent
assert 'PTRACE_TRACEME' in src and 'execve(binary, guest_argv, envp)' in src
assert 'guest_path_to_host' in src and 'GUEST_SYSCALL_DENY' in src
for event in ('PTRACE_O_TRACEFORK', 'PTRACE_O_TRACEVFORK', 'PTRACE_O_TRACECLONE', 'PTRACE_O_TRACEEXEC'):
    assert event in src, event
assert 'PTRACE_GETEVENTMSG' in src and 'MAX_TRACEES 32' in src
assert 'find_tracee_host_pid' in src and 'find_guest_child' in src
assert 'mediate_guest_wait4' in src and 'mediate_guest_kill' in src
assert 'guest_reaped' in src and 'guest_parent_pid' in src
assert 'argc != 6' in src and 'strcmp(argv[5], "/init") != 0' in src
assert 'trace_timeout_ms > 120000' in src and 'one continuous native ARM64-supervised ARM32 guest process tree' in src
assert 'patched_dynamic_native_path' in src and 'GUEST_LINKER_FD 198' in src
assert 'PT_INTERP-patched copy' in src and 'GUEST DYNAMIC EXEC EVENT:' in src
assert 'dynamic_exec_blocked' in src and 'denied before host linker substitution' in src
assert 'prepare_guest_linker_fd' in src and 'GUEST_LINKER_FD, F_SETFD, 0' in src
assert 'command == F_SETFD' in src and 'GUEST_LINKER_FD' in src
assert 'GUEST SIGNAL FORWARDED' in src
assert 'static volatile sig_atomic_t user_cancel_requested' in src
assert 'sigaction(SIGTERM' in src and 'sigaction(SIGINT' in src
assert 'ptrace_terminate_and_reap(pids, count)' in src
assert 'TRACE CLEANUP: tracked=%zu reaped=%zu already-gone=%zu unresolved=%zu' in src
assert 'STOP: user cancellation cleanup confirmed; supervisor terminated and reaped the tracked process tree' in src
assert 'STOP: user cancellation cleanup incomplete; unresolved tracees=%zu' in src
assert 'bounded continuous process-tree trace ended by supervisor timeout' in src
cleanup = Path(sys.argv[1]).with_name('ptrace_tracee_cleanup.h').read_text()
assert 'ptrace_terminate_and_reap' in cleanup and 'waitpid(pid, &status, __WALL)' in cleanup
broker = Path(sys.argv[1]).with_name('init_broker.h').read_text()
file_operation_policy = broker.split('/* Symlinks and ftruncate are brokered', 1)[1].split('/* Guest mount table', 1)[0]
safe_file_policy = broker.split('/* Guest-local ordinary file operations', 1)[1].split('/* Absolute guest paths', 1)[0]
assert 'case 83: case 93: case 331:' in file_operation_policy and 'GUEST_SYSCALL_FILE_OPERATION' in file_operation_policy
assert 'case 93' not in safe_file_policy
symlink_ops = Path(sys.argv[1]).with_name('guest_symlink_ops.h').read_text()
assert 'guest_symlink_create_app_private' in symlink_ops
assert 'guest_symlink_resolve_target' in symlink_ops
assert 'symlinkat(resolved_target, dirfd, leaf)' in symlink_ops
assert 'realpath(fd_path, opened_parent)' in symlink_ops
assert 'guest_symlink_path_within_root(opened_parent, canonical_guest_root)' in symlink_ops
assert '#define ARM_NR_GETTID 224' in src and 'case 215: case 216: case 224:' in broker
fake = src.split('static int fake_syscall(', 1)[1].split('static int resume_trace(', 1)[0]
assert 'regs->uregs[7] = UINT32_MAX' in fake and 'set_kernel_syscall(pid, -1)' in fake
sigsys = trace.split('if (sig == SIGSYS', 1)[1].split('if (sig == SIGSTOP)', 1)[0]
assert 'broker_sigsys_take(&state->broker_sigsys, sig,' in sigsys
assert 'siginfo_code, sigsys_syscall' in sigsys
assert 'siginfo.si_code' in src and 'PTRACE_GETSIGINFO' in sigsys
assert 'PTRACE SIGSYS WAIT STATUS' in sigsys and 'raw=0x%x' in sigsys
assert 'si-syscall=%d si-arch=0x%x si-call-addr=%p' in sigsys
assert 'last-args=%u,%u,%u,%u,%u,%u' in sigsys and 'live-r7=%u live-r0=%u' in sigsys
assert 'brokered_sigsys_suppressed++' in sigsys and 'resume_trace(waited, 0)' in sigsys
assert 'BROKERED SYSCALL SIGSYS SUPPRESSED' in sigsys
assert 'log_unbrokered_seccomp_sigsys_context' in sigsys and 'sigsys_syscall >= 0' in sigsys
assert sigsys.index('broker_sigsys_take') < sigsys.index('log_unbrokered_seccomp_sigsys_context')
assert 'guest-executable=' in src and 'mapped-module=' in src and 'tracee-seccomp-mode=' in src
assert 'SIGSYS CONTEXT DIAGNOSTICS:' in src and 'signal forwarding unchanged' in src
assert 'MAX_SIGSYS_CONTEXT_DIAGNOSTICS 16u' in src
assert 'resume_trace(waited, sig)' in trace
assert 'broker_sigsys_arm(&state->broker_sigsys' in trace
assert 'broker_sigsys_mark_response_committed(&state->broker_sigsys)' in trace
assert 'broker_sigsys_expire_before_next_entry(&state->broker_sigsys)' in trace
assert 'state->expect_exit && state->pending' not in sigsys
sigsys_state = Path(sys.argv[1]).with_name('broker_sigsys_state.h').read_text()
sigsys_test = Path(sys.argv[1]).parents[4] / 'tests/broker_sigsys_state_test.c'
assert 'seccomp_syscall_number != -1' in sigsys_state
assert 'SIGSYS, SYS_SECCOMP, 83' in sigsys_test.read_text()
assert trace.index('if (sig == SIGSYS') < trace.index('GUEST SIGNAL FORWARDED')
all_done = trace.split('if (active_tracee_count == 0)', 1)[1].split('waited = waitpid', 1)[0]
assert '*exit_code = 0' not in all_done and '*exit_signal = 0' not in all_done
assert '*exit_signal = WTERMSIG(status)' in trace
assert 'if (exit_signal) return 128 + exit_signal;' in src
assert '"/dev/block/mtdblock0"' in src and '"/system"' in src and '"ext4"' in src
assert '"/dev/block/mtdblock1"' in src and '"/data"' in src
assert '"/dev/block/mtdblock2"' in src and '"/cache"' in src
assert 'GUEST_MS_REMOUNT' in src and 'guest_system_readonly' in src and 'guest_root_readonly' in src
assert '"%s/.images/system"' in src
assert 'guest_path_uses_native_payload' in src and 'native_guest_root' in src
assert 'system/lib' in src and 'system/bin' in src and 'system/xbin' in src
assert 'host mount syscall not called' in src
assert 'HOST PRIVILEGED MOUNTS: 0' in src
assert 'one tracee per smoke test' not in src

# The Android screen starts exactly one /init tree session, not a sequence of disconnected ELFs.
assert 'nativeLibraryDir' in activity and 'findExtractedAbiLibraryDir' in activity
assert 'getApplicationInfo().sourceDir' in activity and 'splitSourceDirs' in activity
assert 'isArm32Executable' in activity and 'header[18]' in activity
assert 'secondaryNativeLibraryDir' not in activity
assert 'libgingervm_guest_init.so' in activity
assert 'installNativeSystemPayloads' in activity and 'restoreSystemSymlinks' in activity
assert 'restoreSystemAssetNames' in activity and '.aaptdata' not in activity
assert 'api10-system-native-libraries.json' in activity
assert 'api10-system-native-executables.json' in activity
assert 'api10-system-symlinks.json' in activity and 'api10-system-manifest.json' in activity
assert 'verifyGuestSystemTree' in activity and 'MessageDigest.getInstance("SHA-256")' in activity
assert 'knownSystemAssetDirectories' in activity
assert 'google-api10-full-root' in activity and 'app_private_asset_bytes' in activity
assert 'Os.lstat' in activity and 'Os.remove' in activity
cleanup_adapter = activity.split('private void deleteRecursively(File file)', 1)[1].split(
    'private AppPrivateTreeCleanup.Node lstatForCleanup', 1)[0]
assert 'AppPrivateTreeCleanup.deleteRecursively(file' in cleanup_adapter
assert 'Os.chmod(directory.getAbsolutePath()' in cleanup_adapter
assert 'OsConstants.O_NOFOLLOW' in cleanup_adapter
assert 'Os.fstat(descriptor)' in cleanup_adapter and 'directory.list()' in cleanup_adapter
assert 'file.listFiles()' not in cleanup_adapter
assert 'initial.symbolicLink || !initial.directory' in tree_cleanup
assert 'return;' in tree_cleanup and 'operations.remove(path)' in tree_cleanup
cleanup_test = Path(sys.argv[1]).parents[4] / 'tests/AppPrivateTreeCleanupTest.java'
assert 'setNoPermissions(sdcard)' in cleanup_test.read_text()
assert 'outside must survive' in cleanup_test.read_text()
init_rc = Path(sys.argv[1]).parents[4] / 'guest-image/google-api10-android-2.3.7/guest-root-staging/init.rc'
assert 'mkdir /mnt/sdcard 0000 system system' in init_rc.read_text()
copy = activity[activity.index('private void copyAssetTree'):activity.index('private void copyAssetFile')]
assert 'getAssets().open(assetPath)' in copy and 'catch (IOException openError)' not in copy
assert 'throwIfStopRequested();' in copy
assert 'collectGuestSystemTree' in activity
assert 'deleteRecursively(guestRoot)' in activity
assert 'matching /system tree' in activity
assert 'full /system image tree' in activity
assert 'verifyGuestSystemTree(systemRoot, manifest, guestLibraryDir)' in activity
assert 'guestLibraryDir.getAbsolutePath()' in activity
assert 'executeProbe' not in activity and 'probeButton' not in activity
assert 'separate bounded probes' not in activity and 'isolated executable probe' not in activity
continuous_run = activity.split('private String executeGuestEnvironmentTest()', 1)[1].split('private String runNative', 1)[0]
assert continuous_run.count('runNative(') == 1
assert 'guestLibraryDir, "/init"' in continuous_run
assert 'one original /init with its traced child tree' in continuous_run
assert 'changing only PT_INTERP' in continuous_run and '/proc/self/fd/198' in continuous_run
assert 'GUEST TARGET ELF CODE PC:' in src and 'this is not proof of C main()' in src
assert 'A linker entry is not proof of target main, Zygote, framework, desktop or display output' in activity
assert 'dynamic_executable_count' in activity and 'dynamic_sha256' in activity
assert 'captured.size() > 192 * 1024' not in activity and 'reader.join(100L)' in activity
assert 'writeLatestLog(completeLog)' in activity and 'out.getFD().sync()' in activity
assert '分享／儲存完整追蹤日誌' in activity and '匯出完整追蹤日誌' in activity
assert 'Intent.ACTION_SEND' in activity and 'Intent.EXTRA_STREAM' in activity
assert 'Intent.FLAG_GRANT_READ_URI_PERMISSION' in activity and 'ClipData.newUri' in activity
assert 'Intent.ACTION_CREATE_DOCUMENT' in activity and 'getContentResolver().openOutputStream' in activity
assert 'captureSession.readToEof' in activity and 'captureSession.snapshot()' in activity
assert 'OUTPUT CAPTURE RECOVERED:' in activity and 'OUTPUT CAPTURE ERROR:' in activity
assert 'MAX_CONSECUTIVE_INTERRUPTED_READS = 32' in capture
assert 'e.bytesTransferred' in capture and 'too many consecutive interrupted pipe reads' in capture
assert 'setText("查看日誌")' in activity and 'setText("停止")' in activity
assert 'private void showLogViewer()' in activity and 'readLatestLogTail()' in activity
assert 'VIRTUAL PROPERTY STREAM SUMMARY:' in src and 'virtual_property_connect_count' in src
assert 'host AF_UNIX socket/socketpair/bind/connect/listen/accept/setsockopt/getsockopt/send/recv/sendto/recvfrom calls=0' in src
assert 'MAX_LOG_VIEW_BYTES = 256 * 1024' in activity and 'MAX_REPORT_CHARS = 48 * 1024' in activity
assert 'private ScrollView reportScrollView' in activity
assert 'private void scrollToLatest(final ScrollView scrollView)' in activity
assert 'scrollView.fullScroll(View.FOCUS_DOWN)' in activity
assert 'scrollToLatest(reportScrollView)' in activity
assert 'liveLogBody.setText(displayText)' in activity and 'scrollToLatest(liveLogScroll)' in activity
assert 'dialog.setOnDismissListener' in activity
assert 'Theme.Material' in theme
assert '#38BDF8' in theme and '#FF0B0F14' in theme
assert 'FrameLayout guestDisplayFrame' in activity
assert 'Guest display · 等待真實 guest frame' in activity and 'Guest display · 等待 guest fb0 page flip' in activity
assert 'waiting for a verified guest framebuffer frame' in activity
assert '尚無真實 guest 畫面' in activity and '此區不是 Android 桌面' in activity
assert 'setTitle("GingerVM")' in activity
assert 'supervisor.destroy()' in activity and 'USER STOP REQUESTED' in activity
assert 'STOP_CLEANUP_GRACE_SECONDS' in activity and 'destroyForcibly()' in activity
assert 'USER CANCELLED DURING STAGING' in activity and 'throwIfStopRequested();' in activity
assert 'runProgressLog' in activity and 'writeLatestLog(completeLog)' in activity
assert 'appendReportText(chunk)' in activity and 'InputStreamReader' not in activity
assert 'LATEST OWNER TRACE (submitted after v0.6.19; installed app version is not stated in the log)' in activity
assert '3 deferred child stops were each adopted by the matching parent event' in activity
assert 'ready=0/errno=13' in activity and 'graphics add uevent was delivered' in activity
assert 'The trace did not record a pathname for the mknod returning 0' in activity
assert 'fb0 node/open/ioctl/mmap/page-flip/published-frame counts were all 0' in activity
assert 'servicemanager code ran, but `/dev/binder` was denied with EOPNOTSUPP' in activity
assert 'Binder transactions and service registration remain unsupported' in activity
assert '只有 guest MAP_SHARED 寫入並 page-flip 的像素會送到 viewport；測試 packet 不會顯示。' in activity
assert 'never substitutes host Binder, framebuffer, mount or network' in activity
assert 'The latest owner trace ended by bounded supervisor timeout' in activity
assert 'OsConstants.O_NOFOLLOW' in activity and 'Os.fstat(descriptor)' in activity
assert 'network-effects=guest-software-broker-only' in src
assert 'guest_tracee_slot_allocate' in src and 'guest_tracee_slot_mark_ptrace_exit' in src
assert 'guest_wait_status_pending = !tracees[i].guest_reaped' in src
assert 'GUEST THREAD TRACE RELEASE:' in src
assert 'guest_wait_status_is_terminal' in src and 'GUEST WAIT4 REAP:' in src
assert 'VIRTUAL GUEST SOCKET IO:' in src and 'sigchld-socketpair' in src
assert 'GUEST SETRLIMIT:' in src and 'GUEST IOPRIO_SET:' in src and 'GUEST GETPGID:' in src
process_compat = Path(sys.argv[1]).with_name('guest_process_compat.h').read_text()
assert 'GUEST_IOPRIO_CLASS_IDLE && data == 0u' in process_compat
assert 'GUEST URANDOM READ:' in src and 'getrandom(GRND_NONBLOCK)' in src
assert 'unknown-guest-dev-node-fails-closed' in device_boundary
assert 'api10-ueventd-declared-hardware-backend-not-implemented' in device_boundary
assert 'guest_wait_status_is_terminal(0x7fu)' in slots_test
assert 'guest_tracee_slot_mark_ptrace_exit(&pool, (size_t)thread_slot, 0)' in slots_test
assert 'only read access to the latest trace log' in provider and 'ParcelFileDescriptor.MODE_READ_ONLY' in provider
assert 'android:name=".TraceLogProvider"' in manifest and 'android:exported="false"' in manifest
assert 'android:grantUriPermissions="true"' in manifest and '${applicationId}.trace-logs' in manifest

# ABI-extracted payloads and candidate label identify the continuous version.
assert "abiFilters 'arm64-v8a', 'armeabi-v7a'" in gradle
assert "keepDebugSymbols += ['**/*.so']" in gradle
assert "System.getenv('GINGERVM_SIGNING_KEYSTORE')" in gradle
assert "System.getenv('GINGERVM_SIGNING_PASSWORD')" in gradle
assert "System.getenv('GINGERVM_SIGNING_KEY_ALIAS')" in gradle
assert 'signingConfig signingConfigs.debug' in gradle
push_branches = workflow.split('branches:', 1)[1].split('paths:', 1)[0]
assert '- main' in push_branches and 'validation/gingervm-apk' not in push_branches
assert 'GINGERVM_SIGNING_KEY_ALIAS: gingervm-test' in workflow
assert not re.search(r'GINGERVM_SIGNING_PASSWORD:\s*[^\n]+', workflow)
assert 'TEST_SIGNING_PASS' not in workflow
assert 'base64 --decode' not in workflow
assert '::add-mask::' not in workflow
android_job = workflow.split('  android-apk:', 1)[1]
checkout_step = android_job.index('name: Check out source')
mask_step = android_job.index('name: Mask test signing passphrase in job logs')
assert checkout_step < mask_step
assert mask_step < android_job.index('name: Set up Android SDK')
mask_block = android_job.split('name: Mask test signing passphrase in job logs', 1)[1].split('name: Set up Java 21', 1)[0]
assert 'bash .github/scripts/mask_gingervm_test_signing.sh' in mask_block
assert 'GINGERVM_SIGNING_PASSWORD' not in mask_block and 'TEST_SIGNING_PASS' not in mask_block
assert 'base64 --decode' not in mask_block
assert 'base64 --decode' in signing_mask_script
assert "printf '::add-mask::%s\\n' \"$TEST_SIGNING_PASS\"" in signing_mask_script
assert 'GINGERVM_SIGNING_PASSWORD=%s' in signing_mask_script and '>> "$GITHUB_ENV"' in signing_mask_script
assert 'set -x' not in signing_mask_script and 'echo "$TEST_SIGNING_PASS"' not in signing_mask_script
build_block = android_job.split('name: Build and verify continuous-trace APK', 1)[1].split('name: Remove runner copy of test signing key', 1)[0]
assert 'GINGERVM_SIGNING_PASSWORD' not in build_block
assert 'EXPECTED_CERT_SHA256=398effdd769fa7db5bc6e45622b0d222570ffd0af3d889a8c23d0a82782ccc98' in workflow
upload = workflow.split('      - name: Upload signed APK and checksum only', 1)[1]
assert 'gingervm-continuous-trace-v0.6.29-test-signed-apk' in upload
assert 'sha256sum "$APK" > "$RUNNER_TEMP/gingervm-v0.6.29-apk.sha256"' in workflow
assert '${{ runner.temp }}/gingervm-v0.6.29-apk.sha256' in upload
assert '.keystore' not in upload and 'build.log' not in upload
assert "versionCode 38" in gradle and "versionName '0.6.29'" in gradle
assert 'GINGER_SOURCE_COMMIT' in gradle and 'GITHUB_SHA' in gradle
assert "gingerSourceCommit = 'local-uncommitted'" in gradle
assert "gingerSourceCommit ==~ /[0-9a-fA-F]{40}/" in gradle
assert 'multiArch="true"' in manifest
assert 'GingerVM v0.6.29' in manifest and 'android:label="GingerVM"' in manifest
assert '"$OUT64/libprobe_supervisor.so"' in build
assert 'app/src/main/cpp/supervisor.c' not in build
assert '"$OUT32/libprobe_guest.so"' in build
assert 'Standalone legacy probe ELFs are excluded' in build
assert 'name: Verify ARM probe toolchain on hosted runner' in workflow
assert 'for tool in clang-18 ld.lld-18 readelf file; do' in workflow
assert 'name: Verify Android build host tools on hosted runner' in workflow
assert 'for tool in cc curl debugfs file readelf sha256sum unzip python3 awk; do' in workflow
assert 'sudo apt-get' not in workflow

# Image stager preserves official Google/API10 source and confines links.
assert 'EXPECTED_INIT_SHA256' in stager
assert 'ro.build.version.release=2.3.7' in stager and 'ro.build.version.sdk=10' in stager
assert 'ensure_confined_symlink' in stager
assert 'regular_file_count' in stager and 'native_library_count' in stager
assert 'system_directories' in stager and '"directories"' in stager
assert 'api10-system-manifest.json' in stager
assert 'libgingervm_guest_linker.so' in stager
assert 'patch_guest_interpreter' in stager and 'PATCHED_GUEST_INTERPRETER' in stager
assert 'dynamic_interpreter_original' in stager and 'dynamic_interpreter_patched' in stager
print('continuous API10 guest contract: PASS (one /init tree, bounded descendants, escaped/capped denial and exec-path diagnostics, distinct linker/main stage labels, dark no-frame guest viewport, software PID/mount/uevent and property socket models, original API10 linker via fd 198, full verified Google /system, no host root/mount/socket APIs)')
PY
