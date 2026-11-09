#!/usr/bin/env python3
"""Build the pinned Android 2.3.7 init and execute it under GingerVM."""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import re
from pathlib import Path
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
AOSP = ROOT / "build/aosp"
MANUAL = AOSP / "manual"
BIONIC = AOSP / "bionic"
SYSTEM_CORE = AOSP / "system-core"
TOOLCHAIN = MANUAL / "arm-eabi-4.4.3"
GCC = TOOLCHAIN / "bin/arm-eabi-gcc"
AR = TOOLCHAIN / "bin/arm-eabi-ar"
OUT = AOSP / "init-api10-probe"
ROOTFS = OUT / "rootfs"
OBJ = OUT / "objects"
LIB_DIR = OUT / "libraries"
INIT = OUT / "init"
EXPECTED_TOOLCHAIN_SHA256 = "fe166ff857ad022c79a95bf60c2b3ab25d22ed72c1bc4b4c5e989bfa949a6c32"
EXPECTED_REVISIONS = {
    BIONIC: "3f14ff34dfbd00fcffb18b10a1a3e17e2cc5ebdf",
    SYSTEM_CORE: "838a24ac661dfb5147dd584e6dc36dc74c61725e",
}

# These are the target (not host) source lists in the matching Android.mk files.
INIT_SOURCES = [
    "builtins.c", "init.c", "devices.c", "property_service.c", "util.c",
    "parser.c", "logo.c", "keychords.c", "signal_handler.c",
    "init_parser.c", "ueventd.c", "ueventd_parser.c",
]
LIBLOG_SOURCES = ["logd_write.c", "logprint.c", "event_tag_map.c"]
LIBCUTILS_SOURCES = [
    "array.c", "hashmap.c", "atomic.c.arm", "native_handle.c", "buffer.c",
    "socket_inaddr_any_server.c", "socket_local_client.c", "socket_local_server.c",
    "socket_loopback_client.c", "socket_loopback_server.c", "socket_network_client.c",
    "config_utils.c", "cpu_info.c", "load_file.c", "open_memstream.c",
    "strdup16to8.c", "strdup8to16.c", "record_stream.c", "process_name.c",
    "properties.c", "threads.c", "sched_policy.c", "iosched_policy.c",
    "abort_socket.c", "mspace.c", "selector.c", "tztime.c", "zygote.c",
    "ashmem-dev.c", "mq.c", "memset32.S",
]


def run(command: list[str], *, env: dict[str, str], capture: bool = False) -> str:
    result = subprocess.run(
        command, env=env, check=False,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.STDOUT if capture else None,
        text=True,
    )
    if result.returncode:
        if capture and result.stdout:
            print(result.stdout, file=sys.stderr)
        raise SystemExit(result.returncode)
    return result.stdout or ""


def load_libc_builder():
    path = MANUAL / "build-libc.py"
    spec = importlib.util.spec_from_file_location("gingervm_aosp_libc_builder", path)
    if spec is None or spec.loader is None:
        raise SystemExit(f"cannot load existing AOSP libc source builder: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def verify_inputs() -> None:
    archive = MANUAL / "arm-eabi-4.4.3.tar.gz"
    if not archive.is_file() or not GCC.is_file() or not AR.is_file():
        raise SystemExit("pinned AOSP arm-eabi-4.4.3 compiler/archive is not prepared")
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    if digest != EXPECTED_TOOLCHAIN_SHA256:
        raise SystemExit(f"AOSP toolchain checksum mismatch: {digest}")
    for repo, expected in EXPECTED_REVISIONS.items():
        actual = subprocess.check_output(
            ["git", "-C", str(repo), "rev-parse", "HEAD"], text=True
        ).strip()
        if actual != expected:
            raise SystemExit(f"unexpected AOSP revision at {repo}: {actual}")
    for path in [
        SYSTEM_CORE / "init/Android.mk",
        SYSTEM_CORE / "init/init.c",
        SYSTEM_CORE / "rootdir/init.rc",
        BIONIC / "libc/Android.mk",
        SYSTEM_CORE / "libcutils/Android.mk",
        SYSTEM_CORE / "liblog/Android.mk",
        MANUAL / "armelf.x",
    ]:
        if not path.is_file():
            raise SystemExit(f"missing pinned AOSP init dependency: {path}")


def system_core_flags(builder) -> tuple[dict[str, str], list[str]]:
    env = builder.toolchain_environment()
    includes = [
        SYSTEM_CORE / "include", SYSTEM_CORE / "include/arch/linux-arm",
        SYSTEM_CORE / "libcutils", SYSTEM_CORE / "liblog",
        BIONIC / "libc/private", BIONIC / "libc/include",
        BIONIC / "libc/arch-arm/include", BIONIC / "libc/kernel/common",
        BIONIC / "libc/kernel/arch-arm", BIONIC / "libc/stdlib",
        BIONIC / "libc/string", BIONIC / "libc/stdio", BIONIC / "libm/include",
        BIONIC / "libc",
    ]
    flags = [
        "-msoft-float", "-fpic", "-ffunction-sections", "-funwind-tables",
        "-fstack-protector", "-Wa,--noexecstack", "-Wformat",
        "-Werror=format-security", "-fno-short-enums", "-march=armv7-a",
        "-mfloat-abi=softfp", "-mfpu=vfpv3-d16", "-marm",
        "-mthumb-interwork", "-O2", "-fomit-frame-pointer", "-fstrict-aliasing",
        "-funswitch-loops", "-finline-limit=300", "-fno-builtin", "-nostdinc",
        "-isystem", builder.compiler_builtin_headers(), "-DANDROID=1",
        "-D__ANDROID__=1", "-DANDROID_SMP=1", "-DLOG_TAG=\"init\"",
        "-DBOOTCHART=0",
        "-include", str(SYSTEM_CORE / "include/arch/linux-arm/AndroidConfig.h"),
    ]
    flags.extend("-I" + str(path) for path in includes)
    return env, flags


def compile_system_core(builder, source_root: Path, sources: list[str], out_dir: Path,
                        label: str, env: dict[str, str], flags: list[str]) -> list[Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    objects = []
    for index, name in enumerate(sources):
        source = source_root / name
        if name.endswith(".c.arm"):
            source = source.with_suffix("")
        if not source.is_file():
            raise SystemExit(f"source listed in Android.mk is missing: {source}")
        obj = out_dir / f"{index:03d}_{name.replace('/', '_').replace('.', '_')}.o"
        command = [str(GCC), *flags]
        if name.endswith(".c.arm"):
            command.extend(["-x", "c"])
        elif source.suffix in {".S", ".s"}:
            command.extend(["-x", "assembler-with-cpp"])
        command.extend(["-c", str(source), "-o", str(obj)])
        try:
            run(command, env=env, capture=True)
        except SystemExit:
            print(f"FAILED compiling {label} source {source}", file=sys.stderr)
            raise
        objects.append(obj)
    return objects


def compile_bionic_static_extra(builder, source_name: str, index: int) -> Path:
    source = BIONIC / "libc" / source_name
    if source_name.endswith(".c.arm"):
        source = source.with_suffix("")
    obj = OBJ / "libc-static-extra" / f"{index:04d}_{Path(source_name).name.replace('.', '_')}.o"
    obj.parent.mkdir(parents=True, exist_ok=True)
    includes = [
        BIONIC / "libc/private", BIONIC / "libc/include",
        BIONIC / "libc/arch-arm/include", SYSTEM_CORE / "include",
        SYSTEM_CORE / "include/arch/linux-arm", BIONIC / "libc/kernel/common",
        BIONIC / "libc/kernel/arch-arm", BIONIC / "libc/stdlib",
        BIONIC / "libc/string", BIONIC / "libc/stdio", BIONIC / "libm/include",
        BIONIC / "libc",
    ]
    command = [
        str(GCC), "-msoft-float", "-fpic", "-ffunction-sections", "-funwind-tables",
        "-fstack-protector", "-Wa,--noexecstack", "-Wformat", "-Werror=format-security",
        "-fno-short-enums", "-march=armv7-a", "-mfloat-abi=softfp", "-mfpu=vfpv3-d16",
        "-marm", "-mthumb-interwork", "-O2", "-fomit-frame-pointer",
        "-fstrict-aliasing", "-funswitch-loops", "-finline-limit=300", "-fno-builtin",
        "-nostdinc", "-isystem", builder.compiler_builtin_headers(), "-DANDROID=1",
        "-DWITH_ERRLIST", "-DANDROID_CHANGES", "-DUSE_LOCKS", "-DREALLOC_ZERO_BYTES_FREES",
        "-D_LIBC=1", "-DSOFTFLOAT", "-DFLOATING_POINT", "-DINET6", "-DUSE_DL_PREFIX",
        "-DPOSIX_MISTAKE", "-DTM_GMTOFF=tm_gmtoff", "-DUSG_COMPAT=1", "-DANDROID_SMP=1",
        "-DHAVE_ARM_TLS_REGISTER", "-DLIBC_STATIC",
    ]
    command.extend("-I" + str(path) for path in includes)
    command.extend(["-include", str(SYSTEM_CORE / "include/arch/linux-arm/AndroidConfig.h")])
    if source.suffix in {".S", ".s"}:
        command.extend(["-x", "assembler-with-cpp"])
    elif source_name.endswith(".c.arm"):
        command.extend(["-x", "c"])
    command.extend(["-c", str(source), "-o", str(obj)])
    run(command, env=builder.toolchain_environment(), capture=True)
    return obj


def build() -> None:
    verify_inputs()
    builder = load_libc_builder()
    common_sources, static_sources = builder.source_list()
    common_objects = sorted((builder.OUT / "common").glob("*.o"))
    static_objects = sorted((builder.OUT / "static").glob("*.o"))
    if len(common_objects) != len(common_sources) or len(static_objects) != len(static_sources):
        raise SystemExit("AOSP libc_common objects are incomplete; run probes/run-aosp-libc-probe.py first")

    OUT.mkdir(parents=True, exist_ok=True)
    OBJ.mkdir(parents=True, exist_ok=True)
    LIB_DIR.mkdir(parents=True, exist_ok=True)
    env, flags = system_core_flags(builder)

    # AOSP libc.a differs from linker-only libc_nomalloc.a: include the exact
    # Gingerbread malloc implementation and malloc debug common code.
    malloc_objects = [
        compile_bionic_static_extra(builder, "bionic/dlmalloc.c", 5),
        compile_bionic_static_extra(builder, "bionic/malloc_debug_common.c", 6),
    ]
    libc_archive = LIB_DIR / "libc.a"
    run([str(AR), "crs", str(libc_archive),
         *(str(path) for path in [*common_objects, *static_objects, *malloc_objects])], env=env)

    log_objects = compile_system_core(
        builder, SYSTEM_CORE / "liblog", LIBLOG_SOURCES,
        OBJ / "liblog", "liblog", env, flags,
    )
    log_archive = LIB_DIR / "liblog.a"
    run([str(AR), "crs", str(log_archive), *(str(path) for path in log_objects)], env=env)

    cutils_objects = compile_system_core(
        builder, SYSTEM_CORE / "libcutils", LIBCUTILS_SOURCES,
        OBJ / "libcutils", "libcutils", env, flags,
    )
    cutils_archive = LIB_DIR / "libcutils.a"
    run([str(AR), "crs", str(cutils_archive), *(str(path) for path in cutils_objects)], env=env)

    init_objects = compile_system_core(
        builder, SYSTEM_CORE / "init", INIT_SOURCES,
        OBJ / "init", "init", env, flags,
    )
    crt_dir = OBJ / "crt"
    crt_dir.mkdir(parents=True, exist_ok=True)
    crt_begin = crt_dir / "crtbegin_static.o"
    crt_end = crt_dir / "crtend_android.o"
    run([str(GCC), "-mthumb-interwork", "-I" + str(BIONIC / "libc/private"),
         "-c", str(BIONIC / "libc/arch-arm/bionic/crtbegin_static.S"), "-o", str(crt_begin)], env=env)
    run([str(GCC), "-mthumb-interwork", "-I" + str(BIONIC / "libc/private"),
         "-c", str(BIONIC / "libc/arch-arm/bionic/crtend.S"), "-o", str(crt_end)], env=env)

    link = [
        str(GCC), "-nostdlib", "-static", "-Wl,-e,_start",
        f"-Wl,-T,{MANUAL / 'armelf.x'}", "-Wl,--gc-sections",
        "-Wl,--fix-cortex-a8", "-Wl,--no-undefined", "-Wl,-z,noexecstack",
        str(crt_begin), *(str(path) for path in init_objects),
        str(cutils_archive), str(log_archive), str(libc_archive),
        "-lgcc", str(crt_end), "-Wl,-Map," + str(OUT / "init.map"), "-o", str(INIT),
    ]
    run(link, env=env, capture=True)
    INIT.chmod(0o755)

    # Minimal initramfs-style root. The rc file is copied byte-for-byte from
    # the tag-pinned AOSP tree; absent pseudo mounts/services stay absent so
    # GingerVM exposes their actual first-stage limitations.
    shutil.rmtree(ROOTFS, ignore_errors=True)
    for guest_dir in ["dev", "proc", "sys", "system/bin", "system/lib", "sbin", "tmp"]:
        (ROOTFS / guest_dir).mkdir(parents=True, exist_ok=True)
    shutil.copy2(INIT, ROOTFS / "init")
    shutil.copy2(SYSTEM_CORE / "rootdir/init.rc", ROOTFS / "init.rc")
    shutil.copy2(AOSP / "rootfs/system/bin/linker", ROOTFS / "system/bin/linker")
    shutil.copy2(AOSP / "libc-api10-probe/rootfs/system/lib/libc.so", ROOTFS / "system/lib/libc.so")
    shutil.copy2(AOSP / "libc-api10-probe/rootfs/system/lib/libdl.so", ROOTFS / "system/lib/libdl.so")
    os.symlink("../init", ROOTFS / "sbin/ueventd")

    inspect = subprocess.check_output(["readelf", "-h", "-l", "-d", str(INIT)], text=True)
    if "Type:                              EXEC" not in inspect:
        raise SystemExit("AOSP init did not link as an ARM ET_EXEC")
    if "INTERP" in inspect or "NEEDED" in inspect:
        raise SystemExit("AOSP init unexpectedly has a dynamic interpreter/dependency")
    (OUT / "build-info.json").write_text(json.dumps({
        "system_core_revision": EXPECTED_REVISIONS[SYSTEM_CORE],
        "bionic_revision": EXPECTED_REVISIONS[BIONIC],
        "toolchain_sha256": EXPECTED_TOOLCHAIN_SHA256,
        "init_sha256": hashlib.sha256(INIT.read_bytes()).hexdigest(),
        "init_rc_sha256": hashlib.sha256((ROOTFS / "init.rc").read_bytes()).hexdigest(),
        "binary": str(INIT),
        "rootfs": str(ROOTFS),
        "link_mode": "AOSP Gingerbread static libc + libcutils; no PT_INTERP or DT_NEEDED",
    }, indent=2) + "\n")
    print(f"Built exact AOSP Android 2.3.7 init: {INIT}")
    print(f"Rootfs: {ROOTFS}")
    print(f"SHA-256: {hashlib.sha256(INIT.read_bytes()).hexdigest()}")


def execute() -> int:
    binary = ROOT / "target/release/gingervm"
    if not binary.is_file():
        raise SystemExit("missing GingerVM release binary")
    env = os.environ.copy()
    env["GINGERVM_TRACE_SYSCALLS"] = "1"
    log_path = OUT / "run.log"
    command = [str(binary), "run-elf", str(ROOTFS), str(INIT)]
    print(
        "Run exact static AOSP init under GingerVM "
        "(1,000,000-step cap; indefinite no-event poll stops as guest idle).",
        flush=True,
    )
    try:
        result = subprocess.run(
            command, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, timeout=180,
        )
        text = result.stdout
        status: int | str = result.returncode
    except subprocess.TimeoutExpired as error:
        text = (error.stdout or "")
        if isinstance(text, bytes):
            text = text.decode(errors="replace")
        text += "\nGingerVM run timed out after 180 seconds.\n"
        status = "timeout"
    log_path.write_text(text)
    trace_lines = [line for line in text.splitlines() if line.startswith("guest syscall #")]
    instruction_match = re.search(r"^Instructions executed: (\d+)$", text, re.MULTILINE)
    event_match = re.search(r"^Brokered syscall events: (\d+)$", text, re.MULTILINE)
    exit_match = re.search(r"^Guest exit code: (-?\d+)$", text, re.MULTILINE)
    stop_reason = (
        "waiting_for_events"
        if "Guest idle: blocked waiting for virtual fd events; no guest exit code" in text
        else "guest_exited" if exit_match else "runner_error"
    )
    syscall_counts: dict[str, int] = {}
    for line in trace_lines:
        match = re.match(r"guest syscall #(\d+) ([^ ]+)", line)
        if match:
            key = f"{match.group(1)}:{match.group(2)}"
            syscall_counts[key] = syscall_counts.get(key, 0) + 1
    summary = {
        "runner_status": status,
        "guest_stop_reason": stop_reason,
        "guest_exit_code": int(exit_match.group(1)) if exit_match else None,
        "instructions_executed": int(instruction_match.group(1)) if instruction_match else None,
        "brokered_syscall_events": int(event_match.group(1)) if event_match else None,
        "trace_call_count": len(trace_lines),
        "syscall_counts": syscall_counts,
        "last_trace_line": trace_lines[-1] if trace_lines else None,
        "command": command,
        "trace_lines": trace_lines,
        "log": str(log_path),
    }
    (OUT / "run-result.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(f"Runner result: {status}")
    print(f"Trace/log: {log_path}")
    print("--- last runtime output ---")
    print("\n".join(text.splitlines()[-100:]))
    return 0


def main() -> None:
    build()
    run(["cargo", "build", "--release", "--manifest-path", str(ROOT / "Cargo.toml")], env=os.environ.copy())
    execute()


if __name__ == "__main__":
    main()
