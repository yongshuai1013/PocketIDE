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
  "$ROOT/tests/guest_uevent_virtual_test.c" -o "$TMP/guest_uevent_virtual_test"
"$TMP/guest_uevent_virtual_test"
cc -std=c11 -O2 -Wall -Wextra -Werror \
  "$ROOT/tests/guest_socket_virtual_test.c" -o "$TMP/guest_socket_virtual_test"
"$TMP/guest_socket_virtual_test"
cc -std=c11 -O2 -Wall -Wextra -Werror \
  "$ROOT/tests/guest_socket_path_ops_test.c" -o "$TMP/guest_socket_path_ops_test"
"$TMP/guest_socket_path_ops_test"
mkdir -p "$TMP/java"
javac -d "$TMP/java" \
  "$ROOT/app/src/main/java/dev/gingervm/nativeprobe/TraceOutputCapture.java" \
  "$ROOT/tests/TraceOutputCaptureTest.java"
java -cp "$TMP/java" dev.gingervm.nativeprobe.TraceOutputCaptureTest
if [[ "$(uname -m)" == "x86_64" ]]; then
  cc -std=c11 -O2 -Wall -Wextra -Werror \
    "$ROOT/tests/ptrace_seccomp_sigsys_regression.c" -o "$TMP/ptrace_seccomp_sigsys_regression"
  "$TMP/ptrace_seccomp_sigsys_regression"
  cc -std=c11 -O2 -Wall -Wextra -Werror \
    "$ROOT/tests/guest_file_ops_test.c" -o "$TMP/guest_file_ops_test"
  "$TMP/guest_file_ops_test"
  cc -std=c11 -O2 -Wall -Wextra -Werror \
    "$ROOT/tests/guest_symlink_ops_test.c" -o "$TMP/guest_symlink_ops_test"
  "$TMP/guest_symlink_ops_test"
  cc -std=c11 -O2 -Wall -Wextra -Werror \
    "$ROOT/tests/ptrace_cancel_cleanup_regression.c" -o "$TMP/ptrace_cancel_cleanup_regression"
  "$TMP/ptrace_cancel_cleanup_regression"
else
  echo 'ptrace seccomp/cancellation kernel regressions: SKIP (host tests are x86_64 Linux only)'
fi
cc -std=c11 -O2 -Wall -Wextra -Werror \
  "$ROOT/tests/guest_exec_elf_test.c" -o "$TMP/guest_exec_elf_test"
"$TMP/guest_exec_elf_test" \
  "$GUEST_BASE/guest-root-staging/init" \
  "$GUEST_BASE/system-tree/bin/app_process"
python3 "$ROOT/tests/test_stage_interp_patch.py"
python3 "$ROOT/tests/test_procfd_interp_execution.py"

python3 - "$ROOT/app/src/main/cpp/init_supervisor.c" \
  "$ROOT/app/src/main/java/dev/gingervm/nativeprobe/MainActivity.java" \
  "$ROOT/app/build.gradle" "$ROOT/app/src/main/AndroidManifest.xml" \
  "$ROOT/tests/stage_init_assets.py" "$ROOT/build-native.sh" <<'PY'
from pathlib import Path
import re, sys
src = Path(sys.argv[1]).read_text()
trace = src.split("static int run_trace(", 1)[1].split("int main(", 1)[0]
uevent = Path(sys.argv[1]).with_name('guest_uevent_virtual.h').read_text()
socket_model = Path(sys.argv[1]).with_name('guest_socket_virtual.h').read_text()
socket_path = Path(sys.argv[1]).with_name('guest_socket_path_ops.h').read_text()
activity = Path(sys.argv[2]).read_text()
capture = Path(sys.argv[2]).with_name('TraceOutputCapture.java').read_text()
provider = Path(sys.argv[2]).with_name('TraceLogProvider.java').read_text()
gradle = Path(sys.argv[3]).read_text()
manifest = Path(sys.argv[4]).read_text()
theme_path = Path(sys.argv[4]).parent / 'res/values/styles.xml'
theme = theme_path.read_text()
stager = Path(sys.argv[5]).read_text()
build_path = Path(sys.argv[6]).resolve()
build = build_path.read_text()
workflow = (build_path.parents[1] / '.github/workflows/gingervm.yml').read_text()

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
assert 'strcmp(active_tracee->exec_target, "/sbin/ueventd") == 0' in src
assert 'VIRTUAL UEVENT SOCKET:' in src and 'GUEST SOCKET ARGS:' in src
assert 'VIRTUAL UEVENT BIND:' in src and 'VIRTUAL UEVENT SETSOCKOPT:' in src
assert 'host socket API not called' in src and 'host bind API not called' in src
assert 'host setsockopt API not called' in src
assert 'GUEST POLL DIAGNOSTIC:' in src and 'virtual_fd_source(fds[i].fd)' in src
assert 'timeout-ms=%d' in src and 'revents-in=0x%04x revents-out=0x%04x' in src
assert 'empty/no synthetic device events' in src
assert 'guest_vsocket_poll_events(' in src and '&guest_sockets, fd, fds[i].events' in src
assert 'VIRTUAL PROPERTY SOCKET CREATE:' in src and 'VIRTUAL PROPERTY BIND:' in src
assert 'VIRTUAL PROPERTY LISTEN:' in src and 'VIRTUAL PROPERTY ACCEPT:' in src
assert 'VIRTUAL PROPERTY CONNECT:' in src and 'VIRTUAL PROPERTY SO_PEERCRED:' in src
assert 'VIRTUAL SIGNAL SOCKETPAIR:' in src and 'VIRTUAL PROPERTY RECV:' in src
assert 'guest_socket_marker_create_app_private(host_path, guest_root)' in src
assert 'close_virtual_fds_on_exec(state)' in src and 'child_state->virtual_fd_table_id' in src
assert 'tracee_owns_virtual_fd' in src and 'GUEST_VSOCKET_POLLNVAL' in src
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
assert 'INIT COLD-BOOT WAIT RELEASED:' in src
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
copy = activity[activity.index('private void copyAssetTree'):activity.index('private void copyAssetFile')]
assert 'getAssets().open(assetPath)' in copy and 'catch (IOException openError)' not in copy
assert 'throwIfStopRequested();' in copy
assert 'collectGuestSystemTree' in activity
assert 'deleteRecursively(guestRoot)' in activity
assert 'complete matching /system tree' in activity
assert 'full /system image tree' in activity
assert 'guestLibraryDir.getAbsolutePath()' in activity
assert 'executeProbe' not in activity and 'probeButton' not in activity
assert 'separate bounded probes' not in activity and 'isolated executable probe' not in activity
continuous_run = activity.split('private String executeGuestEnvironmentTest()', 1)[1].split('private String runNative', 1)[0]
assert continuous_run.count('runNative(') == 1
assert 'guestLibraryDir, "/init"' in continuous_run
assert 'one original /init with its traced child tree' in continuous_run
assert 'changing only PT_INTERP' in continuous_run and '/proc/self/fd/198' in continuous_run
assert 'target main entry remains unproven' in src
assert 'dynamic-linker entry event is not proof' in activity
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
assert 'VIRTUAL PROPERTY/SIGNAL SOCKET SUMMARY' in src and 'virtual_property_connect_count' in src
assert 'host AF_UNIX socket/socketpair/bind/connect/listen/accept/setsockopt/getsockopt/send/recv calls=0' in src
assert 'MAX_LOG_VIEW_BYTES = 256 * 1024' in activity and 'MAX_REPORT_CHARS = 48 * 1024' in activity
assert 'private ScrollView reportScrollView' in activity
assert 'private void scrollToLatest(final ScrollView scrollView)' in activity
assert 'scrollView.fullScroll(View.FOCUS_DOWN)' in activity
assert 'scrollToLatest(reportScrollView)' in activity
assert 'liveLogBody.setText(displayText)' in activity and 'scrollToLatest(liveLogScroll)' in activity
assert 'dialog.setOnDismissListener' in activity
assert 'Theme.Holo.Light.DarkActionBar' in theme
assert '#33B5E5' in theme and '#FF303030' in theme
assert 'setTitle("GingerVM")' in activity
assert 'supervisor.destroy()' in activity and 'USER STOP REQUESTED' in activity
assert 'STOP_CLEANUP_GRACE_SECONDS' in activity and 'destroyForcibly()' in activity
assert 'USER CANCELLED DURING STAGING' in activity and 'throwIfStopRequested();' in activity
assert 'runProgressLog' in activity and 'writeLatestLog(completeLog)' in activity
assert 'appendReportText(chunk)' in activity and 'InputStreamReader' not in activity
assert 'HISTORICAL DEVICE BASELINE (user-provided v0.6.6 Android 12 log; not this run)' in activity
assert 'ftruncate' in activity and 'passed the coldboot wait' in activity
assert 'socket(1,1,0)' in activity and 'EAFNOSUPPORT' in activity
assert 'property-service and SIGCHLD socketpair model' in activity
assert 'has not yet been tested on-device' in activity
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
assert "base64 --decode" in workflow
assert "printf '::add-mask::%s\\n' \"$TEST_SIGNING_PASS\"" in workflow
android_job = workflow.split('  android-apk:', 1)[1]
mask_step = android_job.index('name: Mask test signing passphrase in job logs')
assert mask_step < android_job.index('name: Check out source')
assert mask_step < android_job.index('name: Set up Android SDK')
mask_block = android_job.split('name: Mask test signing passphrase in job logs', 1)[1].split('name: Check out source', 1)[0]
assert 'GINGERVM_SIGNING_PASSWORD:' not in mask_block
assert 'GINGERVM_SIGNING_PASSWORD=%s' in mask_block and '>> "$GITHUB_ENV"' in mask_block
build_block = android_job.split('name: Build and verify continuous-trace APK', 1)[1].split('name: Remove runner copy of test signing key', 1)[0]
assert 'GINGERVM_SIGNING_PASSWORD' not in build_block
assert 'EXPECTED_CERT_SHA256=398effdd769fa7db5bc6e45622b0d222570ffd0af3d889a8c23d0a82782ccc98' in workflow
upload = workflow.split('      - name: Upload signed APK and checksum only', 1)[1]
assert 'gingervm-continuous-trace-v0.6.7-test-signed-apk' in upload
assert 'gingervm-v0.6.7-apk.sha256' in upload and '.keystore' not in upload and 'build.log' not in upload
assert "versionCode 16" in gradle and "versionName '0.6.7'" in gradle
assert 'multiArch="true"' in manifest
assert 'GingerVM v0.6.7' in manifest and 'android:label="GingerVM"' in manifest
assert '"$OUT64/libprobe_supervisor.so"' in build
assert 'app/src/main/cpp/supervisor.c' not in build
assert '"$OUT32/libprobe_guest.so"' in build
assert 'Standalone legacy probe ELFs are excluded' in build

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
print('continuous API10 guest contract: PASS (one /init tree, bounded descendants, software PID/mount/uevent control plane, syscall-83 VFS symlink containment, in-memory AF_UNIX property endpoint and SIGCHLD socketpair, fail-closed socketcall allowlist, original API10 linker via fd 198, full verified Google /system, no host root/mount/socket APIs)')
PY
