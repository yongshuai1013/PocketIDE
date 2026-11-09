#!/usr/bin/env python3
"""Build pinned Gingerbread Bionic shared libraries and run a real API 10 app."""
from __future__ import annotations

import base64
import hashlib
import importlib.util
import os
from pathlib import Path
import shutil
import subprocess
import re
import sys
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
AOSP = ROOT / "build/aosp"
MANUAL = AOSP / "manual"
BIONIC = AOSP / "bionic"
SYSTEM_CORE = AOSP / "system-core"
TOOLCHAIN_ARCHIVE = MANUAL / "arm-eabi-4.4.3.tar.gz"
GCC = MANUAL / "arm-eabi-4.4.3/bin/arm-eabi-gcc"
EXPECTED_TOOLCHAIN_SHA256 = "fe166ff857ad022c79a95bf60c2b3ab25d22ed72c1bc4b4c5e989bfa949a6c32"
EXPECTED_REVISIONS = {
    BIONIC: "3f14ff34dfbd00fcffb18b10a1a3e17e2cc5ebdf",
    SYSTEM_CORE: "838a24ac661dfb5147dd584e6dc36dc74c61725e",
}
LINKER_SCRIPT_BLOBS = {
    "armelf.xsc": "9fac3d292e73ff52e11483c361f4fe1985f6a803",
    "armelf.x": "d38dc1da90113fb8174ed1772d9a8bad69bed24c",
}
BUILD_DIR = AOSP / "libc-api10-probe"
ROOTFS = BUILD_DIR / "rootfs"
OUT = BUILD_DIR / "objects-and-libraries"
MARKER = ROOTFS / "tmp/gingervm-aosp-libc.txt"
APP_SOURCE = ROOT / "probes/aosp-api10-libc-probe.c"
APP = BUILD_DIR / "aosp-api10-libc-probe.elf"
LINKER = AOSP / "rootfs/system/bin/linker"


def run(command: list[str], *, env: dict[str, str] | None = None,
        capture: bool = False) -> str:
    result = subprocess.run(
        command, check=False, env=env,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.STDOUT if capture else None,
        text=True,
    )
    if result.returncode:
        if capture and result.stdout:
            print(result.stdout, file=sys.stderr)
        raise SystemExit(result.returncode)
    return result.stdout or "" if capture else ""


def builder_module():
    path = MANUAL / "build-libc.py"
    if not path.is_file():
        raise SystemExit(f"missing prepared AOSP source builder: {path}")
    spec = importlib.util.spec_from_file_location("gingervm_aosp_libc_build", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def ensure_linker_script(name: str, expected_blob: str) -> Path:
    path = MANUAL / name
    if path.is_file():
        contents = path.read_bytes()
        actual = hashlib.sha1(f"blob {len(contents)}\0".encode() + contents).hexdigest()
        if actual == expected_blob:
            return path
    url = ("https://android.googlesource.com/platform/build/+/refs/tags/"
           f"android-2.3.7_r1/core/{name}?format=TEXT")
    with urllib.request.urlopen(url) as response:
        contents = base64.b64decode(response.read())
    actual = hashlib.sha1(f"blob {len(contents)}\0".encode() + contents).hexdigest()
    if actual != expected_blob:
        raise SystemExit(f"AOSP {name} Git blob mismatch: {actual}")
    path.write_bytes(contents)
    return path


def verify_inputs() -> None:
    if not TOOLCHAIN_ARCHIVE.is_file() or not GCC.is_file():
        raise SystemExit("pinned AOSP arm-eabi-4.4.3 toolchain is not prepared")
    digest = hashlib.sha256(TOOLCHAIN_ARCHIVE.read_bytes()).hexdigest()
    if digest != EXPECTED_TOOLCHAIN_SHA256:
        raise SystemExit(f"AOSP toolchain checksum mismatch: {digest}")
    for repo, expected in EXPECTED_REVISIONS.items():
        actual = run(["git", "-C", str(repo), "rev-parse", "HEAD"], capture=True).strip()
        if actual != expected:
            raise SystemExit(f"unexpected AOSP revision at {repo}: {actual}")
    for name, expected in LINKER_SCRIPT_BLOBS.items():
        ensure_linker_script(name, expected)
    if not LINKER.is_file():
        raise SystemExit(f"build/stage the exact AOSP linker first: {LINKER}")
    if not APP_SOURCE.is_file():
        raise SystemExit(f"missing API 10 app source: {APP_SOURCE}")


def compile_direct(gcc: Path, env: dict[str, str], args: list[str]) -> None:
    run([str(gcc), *args], env=env)


def main() -> None:
    verify_inputs()
    builder = builder_module()
    common_sources, _ = builder.source_list()
    common_objects = sorted((builder.OUT / "common").glob("*.o"))
    if len(common_objects) != len(common_sources):
        print("== Build the exact AOSP libc_common source set ==", flush=True)
        run([sys.executable, str(MANUAL / "build-libc.py")])
        common_objects = sorted((builder.OUT / "common").glob("*.o"))
    if len(common_objects) != len(common_sources):
        raise SystemExit(f"incomplete libc_common objects: {len(common_objects)}/{len(common_sources)}")

    env = builder.toolchain_environment()
    shutil.rmtree(BUILD_DIR, ignore_errors=True)
    OUT.mkdir(parents=True)
    (ROOTFS / "system/bin").mkdir(parents=True)
    (ROOTFS / "system/lib").mkdir(parents=True)
    (ROOTFS / "tmp").mkdir(parents=True)

    # AOSP libc.so uses the dynamic variants of these sources in addition to
    # libc_common and the shared/static-common sources named in libc/Android.mk.
    dynamic_sources = [
        "arch-arm/bionic/exidx_dynamic.c",
        "unistd/sysconf.c",
        "bionic/__errno.c",
        "bionic/pthread.c.arm",
        "bionic/dlmalloc.c",
        "bionic/malloc_debug_common.c",
        "bionic/libc_init_dynamic.c",
    ]
    cflags = [
        "-msoft-float", "-fpic", "-ffunction-sections", "-funwind-tables",
        "-fstack-protector", "-Wa,--noexecstack", "-Wformat",
        "-Werror=format-security", "-fno-short-enums", "-march=armv7-a",
        "-mfloat-abi=softfp", "-mfpu=vfpv3-d16", "-marm",
        "-mthumb-interwork", "-O2", "-fomit-frame-pointer",
        "-fstrict-aliasing", "-funswitch-loops", "-finline-limit=300",
        "-fno-builtin", "-nostdinc", "-isystem", builder.compiler_builtin_headers(),
        "-DWITH_ERRLIST", "-DANDROID_CHANGES", "-DUSE_LOCKS",
        "-DREALLOC_ZERO_BYTES_FREES", "-D_LIBC=1", "-DSOFTFLOAT",
        "-DFLOATING_POINT", "-DINET6", "-DUSE_DL_PREFIX", "-DPOSIX_MISTAKE",
        "-DTM_GMTOFF=tm_gmtoff", "-DUSG_COMPAT=1", "-DANDROID_SMP=1",
        "-DHAVE_ARM_TLS_REGISTER",
    ]
    includes = [
        BIONIC / "libc/private", BIONIC / "libc/include",
        BIONIC / "libc/arch-arm/include", SYSTEM_CORE / "include",
        SYSTEM_CORE / "include/arch/linux-arm", BIONIC / "libc/kernel/common",
        BIONIC / "libc/kernel/arch-arm", BIONIC / "libc/stdlib",
        BIONIC / "libc/string", BIONIC / "libc/stdio", BIONIC / "libm/include",
        BIONIC / "libc",
    ]
    include_flags = [f"-I{path}" for path in includes]
    config = SYSTEM_CORE / "include/arch/linux-arm/AndroidConfig.h"
    builder.OUT = OUT / "libc-objects"
    print("== Compile AOSP Android 2.3.7 dynamic libc sources ==", flush=True)
    dynamic_objects = []
    for index, source in enumerate(dynamic_sources):
        if source == "bionic/dlmalloc.c":
            # The old AOSP build system injects -DANDROID globally; it makes
            # dlmalloc reuse Bionic's public struct mallinfo declaration.
            output = builder.OUT / "common/0604_dlmalloc_c.o"
            output.parent.mkdir(parents=True, exist_ok=True)
            compile_direct(GCC, env, [*cflags, "-DANDROID=1", *include_flags,
                                      "-include", str(config), "-c",
                                      str(BIONIC / "libc" / source), "-o", str(output)])
            dynamic_objects.append(output)
        else:
            dynamic_objects.append(builder.compile_one(source, 600 + index, False))
    crt_dir = OUT / "crt"
    crt_dir.mkdir()
    crt_sources = {
        "crtbegin_so.o": BIONIC / "libc/arch-arm/bionic/crtbegin_so.S",
        "crtend_so.o": BIONIC / "libc/arch-arm/bionic/crtend_so.S",
        "crtbegin_dynamic.o": BIONIC / "libc/arch-arm/bionic/crtbegin_dynamic.S",
        "crtend_android.o": BIONIC / "libc/arch-arm/bionic/crtend.S",
    }
    for name, source in crt_sources.items():
        compile_direct(GCC, env, ["-mthumb-interwork", f"-I{BIONIC / 'libc/private'}",
                                  "-c", str(source), "-o", str(crt_dir / name)])

    # AOSP's libdl module consists of the real Android 2.3.7 linker stubs.
    print("== Build AOSP libdl.so and libc.so ==", flush=True)
    libdl_object = OUT / "libdl.o"
    compile_direct(GCC, env, [*cflags, *include_flags, "-include", str(config),
                              "-c", str(BIONIC / "libdl/libdl.c"),
                              "-o", str(libdl_object)])
    libdl = OUT / "libdl.so"
    compile_direct(GCC, env, [
        "-nostdlib", "-Wl,-soname,libdl.so", f"-Wl,-T,{MANUAL / 'armelf.xsc'}",
        "-Wl,--gc-sections", "-Wl,-shared,-Bsymbolic", str(libdl_object),
        str(crt_dir / "crtbegin_so.o"), "-Wl,--exclude-libs=libgcc.a", "-lgcc",
        "-Wl,-z,noexecstack", "-Wl,--fix-cortex-a8", str(crt_dir / "crtend_so.o"),
        "-o", str(libdl),
    ])

    libc = OUT / "libc.so"
    link_libc = [
        "-nostdlib", "-Wl,-soname,libc.so", f"-Wl,-T,{MANUAL / 'armelf.xsc'}",
        "-Wl,--gc-sections", "-Wl,-shared,-Bsymbolic", "-Wl,--no-undefined",
        *(str(path) for path in common_objects),
        str(crt_dir / "crtbegin_so.o"),
        *(str(path) for path in dynamic_objects),
        f"-L{OUT}", "-ldl", "-Wl,--exclude-libs=libgcc.a", "-Wl,-z,noexecstack",
        "-Wl,--fix-cortex-a8", "-lgcc", str(crt_dir / "crtend_so.o"), "-o", str(libc),
    ]
    compile_direct(GCC, env, link_libc)

    # Compile against Bionic's tag-pinned API 10 headers and its own startup ABI.
    app_object = OUT / "aosp-api10-libc-probe.o"
    compile_direct(GCC, env, [*cflags, *include_flags, "-include", str(config),
                              "-O1", "-c", str(APP_SOURCE), "-o", str(app_object)])
    app_start = crt_dir / "crtbegin_dynamic.o"
    app_end = crt_dir / "crtend_android.o"
    compile_direct(GCC, env, [
        "-nostdlib", "-Bdynamic", f"-Wl,-T,{MANUAL / 'armelf.x'}",
        "-Wl,--dynamic-linker=/system/bin/linker", "-Wl,--gc-sections",
        "-Wl,-z,nocopyreloc", "-o", str(APP), f"-L{OUT}",
        f"-Wl,-rpath-link={OUT}", "-lc", "-ldl", str(app_start), str(app_object),
        "-Wl,-z,noexecstack", "-Wl,--fix-cortex-a8", "-lgcc", str(app_end),
    ])

    shutil.copy2(LINKER, ROOTFS / "system/bin/linker")
    shutil.copy2(libc, ROOTFS / "system/lib/libc.so")
    shutil.copy2(libdl, ROOTFS / "system/lib/libdl.so")
    for path in [APP, libc, libdl, ROOTFS / "system/bin/linker"]:
        print(f"{run(['file', str(path)], capture=True).strip()}", flush=True)
    run(["readelf", "-l", str(APP)], capture=False)
    run(["readelf", "-d", str(APP)], capture=False)
    print("== Run an API 10 app through the exact Gingerbread PT_INTERP linker ==", flush=True)
    run(["cargo", "build", "--release", "--manifest-path", str(ROOT / "Cargo.toml")])
    log = BUILD_DIR / "run.log"
    runtime_env = os.environ.copy()
    runtime_env["GINGERVM_TRACE_SYSCALLS"] = "1"
    result = subprocess.run(
        [str(ROOT / "target/release/gingervm"), "run-elf-interp", str(ROOTFS), str(APP)],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, env=runtime_env,
    )
    log.write_text(result.stdout)
    if result.returncode:
        print(result.stdout, file=sys.stderr)
        raise SystemExit(result.returncode)
    expected = b"AOSP Android 2.3.7 Bionic libc app reached main\n"
    if MARKER.read_bytes() != expected:
        raise SystemExit(f"Bionic app marker mismatch: {MARKER}")
    for required in [
        "Dependency loading: guest PT_INTERP (host preload disabled)",
        "Guest exit code: 0",
    ]:
        if required not in result.stdout:
            raise SystemExit(f"missing expected runtime evidence: {required}")
    if not re.search(r"guest syscall #67 sigaction .* -> 0 at ", result.stdout):
        raise SystemExit("Bionic sigaction registration/query did not succeed")
    if not re.search(r"guest syscall #67 sigaction .* -> -22 at ", result.stdout):
        raise SystemExit("Bionic SIGKILL registration did not return EINVAL")
    for name in ["null", "zero", "random", "urandom"]:
        if (ROOTFS / "dev" / name).exists():
            raise SystemExit(f"virtual /dev/{name} unexpectedly created a rootfs file")
    print("Verified: genuine AOSP libc.so and libdl.so loaded by Gingerbread linker;", flush=True)
    print("API 10 app registered/queried legacy sigaction, checked virtual device I/O,", flush=True)
    print("called Bionic getpid/open/write/close, and exited 0.", flush=True)
    print(f"Marker: {MARKER}")
    print(f"Log: {log}")


if __name__ == "__main__":
    main()
