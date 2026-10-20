#!/usr/bin/env python3
"""One-time bounded build supervisor; raw output stays in runner temporary storage."""
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import time

root = Path(os.environ['RUNNER_TEMP']) / 'swift-ios-probe'
logs = Path('probe-logs')
logs.mkdir(exist_ok=True)
raw = Path(os.environ['RUNNER_TEMP']) / 'swift-ios-probe-raw.log'
started = time.monotonic()
preexisting_objects = len(list((root / 'ios').rglob('*.o'))) if (root / 'ios').exists() else 0
reason = ''
peak_rss = 0
peak_disk = 0
with raw.open('w') as out:
    process = subprocess.Popen(['bash', 'scripts/temporary-swift-ios-probe.sh'], stdout=out, stderr=subprocess.STDOUT, start_new_session=True)
    while process.poll() is None:
        elapsed = time.monotonic() - started
        ps = subprocess.check_output(['ps', '-axo', 'pid=,ppid=,rss='], text=True)
        rows = [tuple(map(int, line.split())) for line in ps.splitlines() if len(line.split()) == 3]
        descendants = {process.pid}
        for _ in rows:
            more = {pid for pid, ppid, rss in rows if ppid in descendants}
            if more <= descendants:
                break
            descendants |= more
        rss = sum(rss for pid, ppid, rss in rows if pid in descendants) * 1024
        peak_rss = max(peak_rss, rss)
        disk = int(subprocess.check_output(['du', '-sk', str(root)], text=True).split()[0]) * 1024 if root.exists() else 0
        peak_disk = max(peak_disk, disk)
        free = shutil.disk_usage(os.environ['RUNNER_TEMP']).free
        if elapsed >= 9900:
            reason = '165-minute overall probe budget reached (job hard cap 180 minutes)'
        elif rss > 5 * 1024**3:
            reason = 'process-tree resident memory exceeded 5 GiB'
        elif disk > 20 * 1024**3 or free < 8 * 1024**3:
            reason = '20 GiB probe disk cap or 8 GiB free-space floor reached'
        elif raw.stat().st_size > 32 * 1024**2:
            reason = '32 MiB raw log cap reached'
        stage = (logs / 'stage.txt').read_text().strip() if (logs / 'stage.txt').exists() else 'starting'
        print(f'PROBE elapsed={elapsed:.0f}s stage={stage} rss_bytes={rss} disk_bytes={disk} free_bytes={free}', flush=True)
        if reason:
            os.killpg(process.pid, signal.SIGTERM)
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
            break
        time.sleep(min(20, max(0.1, 9900 - elapsed)))
    rc = process.wait()
# Prevent any children surviving a completed/failed parent shell.
try:
    os.killpg(process.pid, signal.SIGTERM)
except ProcessLookupError:
    pass
# Keep build step/diagnostic lines, not compiler-emitted source excerpts or raw source.
keep = re.compile(r'^(?:\[\d+/\d+|FAILED:|ninja:|PROBE_EXIT=|-- |CMake (?:Error|Warning)|ld:|Undefined symbols for architecture|\s+"[^"\n]+", referenced from:|\s+.+ in [^\s]+\.(?:a|o)(?:\[|\(|$)|.*?(?:fatal error:|error:|warning:)|[A-Za-z0-9_./+-]+\.(?:cpp|c|h|hpp):\d+:)')
retained = [line[:8192] for line in raw.read_text(errors='replace').splitlines() if keep.match(line) and not line.lstrip().startswith(('#include', '^', '|'))]
(logs / 'probe.log').write_text('\n'.join(retained) + '\n')
(logs / 'resource-metadata.txt').write_text(f'EXIT_CODE={rc}\nSTOP_REASON={reason or "process exited"}\nELAPSED_SECONDS={time.monotonic()-started:.1f}\nPEAK_PROCESS_TREE_RSS_BYTES={peak_rss}\nPEAK_PROBE_DISK_BYTES={peak_disk}\nNINJA_PARALLEL=2; native tablegen parallel=3\nOVERALL_PROBE_LIMIT_SECONDS=9900\nJOB_LIMIT_MINUTES=180\nRaw logs, source excerpts, SDKs and compiled artifacts are not uploaded.\n')
objects = sorted((root / 'ios').rglob('*.o')) if (root / 'ios').exists() else []
swift_objects = [p for p in objects if 'swift' in str(p.relative_to(root / 'ios')).lower()]
frontend_objects = [p for p in swift_objects if '/Frontend/' in str(p) or '/FrontendTool/' in str(p)]
metadata = [f'IOS_OBJECT_COUNT={len(objects)}', f'SWIFT_NAMED_OBJECT_COUNT={len(swift_objects)}', f'SWIFT_FRONTEND_OBJECT_COUNT={len(frontend_objects)}', f'FINAL_EXECUTABLE_EXISTS={(root / "ios/bin/ios_frontend_link_probe").is_file()}']
metadata += [str(p.relative_to(root / 'ios')) for p in swift_objects[:80]]
for directory in ('Frontend', 'FrontendTool', 'ASTGen'):
    selected = [p for p in objects if f'tools/swift/lib/{directory}/' in str(p.relative_to(root / 'ios'))]
    metadata.append(f'SWIFT_{directory.upper()}_OBJECT_COUNT={len(selected)}')
    metadata.extend(str(p.relative_to(root / 'ios')) for p in selected)
syntax_objects = [p for p in objects if '_deps/swiftsyntax-build/' in str(p)]
metadata.append(f'SWIFTSYNTAX_OBJECT_COUNT={len(syntax_objects)}')
metadata.extend(str(p.relative_to(root / 'ios')) for p in syntax_objects[:100])
if objects:
    metadata.append(subprocess.check_output(['file', str(objects[0])], text=True).strip())
(logs / 'target-metadata.txt').write_text('\n'.join(metadata) + '\n')
print((logs / 'resource-metadata.txt').read_text(), flush=True)
# Count progress only from the actual iOS build section, not native prerequisites.
raw_text = raw.read_text(errors='replace')
link_start = re.search(r'^\[\d+/\d+ elapsed=[^\]]+\] Linking CXX executable bin/ios_frontend_link_probe', raw_text, re.M)
link_text = raw_text[link_start.start():] if link_start else 'FINAL_LINK_NOT_STARTED\n'
# Complete final link output, not the line-filtered compile log. The artifact
# audit subsequently sanitizes paths and tokens; no SDK/binary data is copied.
(logs / 'linker-diagnostics.txt').write_text(link_text)

actual = raw_text.split('actual-ios-frontend-compile-link\n', 1)[-1] if 'actual-ios-frontend-compile-link\n' in raw_text else ''
progress = re.findall(r'^\[(\d+)/(\d+) elapsed=[^\]]+\] (.*)$', actual, re.M)
plan_path = logs / 'build-plan.txt'
planned_match = re.search(r'DRY_RUN_STEP_COUNT=(\d+)', plan_path.read_text()) if plan_path.exists() else None
planned = int(planned_match.group(1)) if planned_match else None
completed = int(progress[-1][0]) if progress else 0
failed = len(re.findall(r'^FAILED:', actual, re.M))
remaining = None
remaining_error = ''
if (root / 'ios/build.ninja').is_file():
    try:
        check = subprocess.run(['ninja', '-C', str(root / 'ios'), '-n', 'ios_frontend_link_probe'], capture_output=True, text=True, timeout=15)
        if check.returncode == 0:
            remaining = len(re.findall(r'^\[\d+/\d+\]', check.stdout, re.M))
        else:
            remaining_error = f'dry-run exit {check.returncode}'
    except Exception as exc:
        remaining_error = type(exc).__name__
step_lines = [f'INITIAL_PLANNED_STEPS={planned}', f'LAST_NINJA_FINISHED_COUNT={completed}', f'FAILED_EDGE_COUNT={failed}', f'REMAINING_DRY_RUN_STEPS={remaining}', f'REMAINING_CHECK_ERROR={remaining_error}', f'LAST_ACTUAL_PROGRESS={progress[-1] if progress else "none"}', f'FINAL_LINK_STAGE_REACHED={"final-link-succeeded-inspect-only" in raw_text}', f'CACHE_MATCHED_KEY={os.environ.get("PROBE_CACHE_MATCHED_KEY", "")}', f'CACHE_RESTORED={bool(os.environ.get("PROBE_CACHE_MATCHED_KEY", ""))}', f'PREEXISTING_IOS_OBJECT_COUNT={preexisting_objects}', 'Finished-count can include a failed edge; check FAILED_EDGE_COUNT and remaining dry-run.']
(logs / 'step-metadata.txt').write_text('\n'.join(step_lines) + '\n')
print((logs / 'step-metadata.txt').read_text(), flush=True)
raise SystemExit(1 if reason else rc)
