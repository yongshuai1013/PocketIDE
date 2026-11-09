# GingerVM

GingerVM 是一個獨立的 Android-in-Android 虛擬化研究專案；不依賴也不修改 `/workspace/PaxVM`。目標 guest 為 Android 2.3.7 Gingerbread（API 10、32 位 ARM），方向是 App 沙盒內的 userspace supervisor，而不是桌面 QEMU 前端。

## 目前狀態：ARM/Thumb 執行核心 prototype 0.10

本機可編譯、可測的閉環目前包含：

- Gingerbread 2.3.7 guest profile、每個 guest 獨立的 rootfs 目錄骨架，以及限制在 guest rootfs 的絕對路徑映射。Broker 支援 rootfs 範圍內的 `open`、`read`、`write`、`close`、`stat64` 和 `lseek`，並提供虛擬 `uid`／`gid`／`pid`；`/dev/null`、`/dev/zero`、`/dev/random`、`/dev/urandom` 由 broker 虛擬化，不在宿主或 rootfs 建立裝置檔；每個 broker instance 各自管理 guest FD，單次 I/O 上限 1 MiB。
- Host 端可載入 32 位 little-endian ARM 靜態 `ET_EXEC`，從 A32 或 16-bit Thumb entry 執行有限指令子集。A32 包含 16 種資料處理運算、barrel shifter、NZCV 旗標、`MUL`／`MLA`、signed/unsigned 64 位乘法與累加、word／byte／halfword／signed-halfword／doubleword 存取、一般 `LDM`／`STM`、`MOVW`／`MOVT`、`CLZ`、`BFI`／`BFC`／`UBFX`、unsigned extend family、`B`／`BL`／`BX`／`BLX` 及 ARM/Thumb 互換。另新增 word `LDREX`／`STREX` 單執行緒 exclusive monitor，供 Gingerbread linker 的 atomic 操作使用。Thumb-1 覆蓋常用整數運算、條件與無條件分支、資料存取、`LDMIA`／`STMIA`、`PUSH`／`POP`、SP frame adjustment 及長 `BL`。未支援指令會明確停止，未支援 syscall 由 broker 拒絕，不會直接轉成宿主 syscall。
- ELF loader 可載入 32 位 ARM `ET_DYN` 主映像；不含 `PT_INTERP` 的自重定位 PIE 支援 `R_ARM_RELATIVE`。一般 `run-elf` 對帶 `PT_INTERP` 映像可由 host 從 guest `/system/lib`、`/vendor/lib` 或 `/lib` 載入 `DT_NEEDED`，依 SysV `DT_HASH` 處理 `R_ARM_RELATIVE`、`R_ARM_ABS32`、`R_ARM_REL32`、`R_ARM_COPY`、`R_ARM_GLOB_DAT`、`R_ARM_JUMP_SLOT` 等 REL/PLT relocation。這是 host 相容路徑，不代表由 Bionic 自行載入。
- `run-elf-interp <rootfs> <arm-elf>` 是真實 guest interpreter 路徑：guest `PT_INTERP` linker 自行處理依賴，host preload 關閉。第一個 probe 由精確 AOSP `android-2.3.7_r1` linker 從 rootfs 載入小型自有 DSO，驗證 `GLOB_DAT`／`JUMP_SLOT`、共享資料及函式呼叫；8,632 條 guest 指令、27 個 broker event、exit 0。可用 `./probes/run-bionic-needed-probe.sh` 重現。這個合成 DSO probe 不等於 Bionic libc。
- `probes/run-aosp-libc-probe.py` 依 AOSP 2.3.7 ARM 官方 linker scripts/flags，以 pinned Bionic 原始碼建置真實 `libc.so` 和 `libdl.so`，並以 Bionic `crtbegin_dynamic`／`crtend` 連結 ARM API 10 ELF app。精確 Gingerbread linker 從受控 rootfs 載入兩庫；probe 會以真實 Bionic 呼叫 `getpid/open/read/write/close`，驗證 legacy `sigaction` 註冊、查詢、act/oact 指標別名與 SIGKILL 的 `EINVAL`，測試四種虛擬裝置，並寫出 48-byte marker `AOSP Android 2.3.7 Bionic libc app reached main`。結果不代表任意 app 或完整 libc 初始化均已相容；產物與 log 僅在忽略的 `build/aosp/libc-api10-probe/`。
- ARM syscall 67 的 Gingerbread legacy `sigaction` ABI 現在可保存與查詢 16-byte action（signal、handler、32-bit mask、flags、restorer），並檢查非法 signal／guest 指標；這只模擬單一執行器內的註冊狀態，不會遞送 signal，也不支援多執行緒或 `rt_sigaction`。四種 `/dev` 節點在 broker 內提供 null EOF/discard、zero-filled read 與 host entropy-backed random read；random 寫入不會注入宿主熵池。跨頁 `mprotect` probe 仍通過。
- Guest process-memory syscall 在本地模擬 `brk`、匿名及 guest-FD/rootfs backing 私有 `mmap2`、`munmap` 與 `mprotect`；檔案映射依頁 offset 讀取，支援 EOF 頁尾補零及後續頁 fault。映射採 4 KiB 頁粒度並有限額；`MAP_SHARED` 尚未支援，guest syscall 不轉發到宿主。
- Gingerbread ARM TLS 有窄相容切片：處理 `ARM_set_tls`（983045），支援 A32 `MRC p15, 0, Rt, c13, c0, 3` 讀取 TPIDRURO。依據 AOSP [`bionic_tls.h`](https://android.googlesource.com/platform/bionic/+/refs/tags/android-2.3.7_r1/libc/private/bionic_tls.h)、[`pthread.c`](https://android.googlesource.com/platform/bionic/+/refs/tags/android-2.3.7_r1/libc/bionic/pthread.c)、[`__set_tls.S`](https://android.googlesource.com/platform/bionic/+/refs/tags/android-2.3.7_r1/libc/arch-arm/syscalls/__set_tls.S) 與 [`SYSCALLS.TXT`](https://android.googlesource.com/platform/bionic/+/refs/tags/android-2.3.7_r1/libc/SYSCALLS.TXT)，該版本使用 64 槽自有 TLS 區，linker 不支援 `PT_TLS`／ARM TLS relocation；Android `__thread` 採 compiler-rt/libgcc emulated TLS（見 LLVM [D53906](https://reviews.llvm.org/D53906)）。Loader 明確拒絕 native `PT_TLS`。`armv7-tls-probe.S` 與 API 10 `-femulated-tls` probe 驗證了 set_tls、TPIDRURO、TLS_SLOT_SELF，以及單執行緒 helper 下的 initialized／zero-initialized／aligned 變數；這不是完整 compiler-rt/Bionic TLS、pthread runtime 或 clone/thread scheduling。

- Guest filesystem 現在有每個 broker instance 私有的虛擬 mount table：受限支援 `tmpfs`（純 guest 記憶體）、`proc`、`sysfs` 與空的 `devpts`；`/proc/cmdline`、`/proc/cpuinfo` 提供空內容，`/sys` 只有有限的空裝置目錄骨架，`getdents64` 只列舉這些安全目錄；相對路徑 `openat` 以 guest directory fd 為基準解析。沒有宿主 mount、真實 kernel/sysfs 資料或合成 uevent；未知 filesystem（包括 YAFFS2/cgroup）及 rootfs remount 不支援。

**這還不是完整 Android 2.3.7 開機。** 目前能執行以固定 AOSP Gingerbread 原始碼和 Bionic libc 靜態連結的真實 `init`，本輪達 598,272 條 guest 指令、2,009 次 syscall trace，最後停在等待虛擬 fd 事件的 `poll`，沒有 guest exit code。9 次 mount 中 6 次成功（含 `/dev`、`/proc`、`/sys`、`/dev/pts` 與兩個 tmpfs），`cgroup`、YAFFS2 image 及 rootfs remount 仍不支援；此 init trace 未呼叫 `getdents64`，該介面目前由獨立 broker tests 驗證。尚無完整 system image、guest kernel、uevent 來源、Binder/ashmem、framework、Dalvik 或 APK 啟動。

## 探針與限制

- `probes/run-static-arm-probe.sh` 以 Clang/LLD 產生 ARM、Thumb、memory、PIE、PT_INTERP、emutls 及合成 app+library probes。靜態 ARM probe 涵蓋 124 條 A32 指令和 12 次 broker syscall；Thumb probe 涵蓋 140 條指令。合成 `DT_NEEDED` app 走 GingerVM host loader／測試 linker stub，不能與上面真實 Bionic probe 混為一談。COPY relocation 由 LLD 產生；REL32 probe 將一筆 `R_ARM_ABS32` 紀錄改寫成 `R_ARM_REL32`。這些工具鏈 probes 不是 Android NDK／Bionic system binaries。
- `probes/run-bionic-needed-probe.sh` 以 ARMv5T 產生 app 和 DSO，使用本機已建置、staged 的精確 AOSP linker（預設 `build/aosp/rootfs/system/bin/linker`），將 app 與 DSO 放入受控 guest rootfs 後執行 `run-elf-interp`。它檢查 `PT_INTERP`、`DT_NEEDED`、`GLOB_DAT`／`JUMP_SLOT`、Bionic syscall trace、exit 0 和 guest marker；完整 log/ELF/rootfs 位於忽略的 `build/bionic-needed-probe/`。若 linker 放在其他位置，可設定 `AOSP_LINKER=/path/to/linker`。
- Gingerbread linker 的 `R_ARM_COPY` 行為另有邊界：此 AOSP 版本在該 relocation 的 local-first lookup 會先找到 executable 自己的定義，這個 probe 不以它驗證 Bionic 的資料搬移；真實 Bionic app 使用的共享資料引用改採 linker 支援的 `GLOB_DAT`。一般 host-loader COPY 路徑仍有合成 probe。
- A32 load/store 仍是有限編碼子集：single-transfer register offset 僅支援 immediate shift，不支援 register-specified shift 或 unprivileged transfer；`LDM`／`STM` 不支援 S-bit/user-bank 形式，且只接受明確定義的 STM writeback/base overlap。尚未支援 Android packed relocations、GNU-hash-only symbol tables、`MAP_SHARED`、Thumb-2、VFP/NEON、完整 syscall 流程（例如 init trace 中仍被拒絕的 `futex`／`chown32`）、signal delivery/thread、Binder、ashmem、Android framework 或完整 system image。Rootfs canonicalize 路徑檢查仍有 symlink race 風險；這不是核心 syscall interceptor 或已完成的安全邊界。

## 設計分層與下一步

1. **Android shell（後續）**：管理 VM instance、rootfs、前景服務與畫面呈現。
2. **Supervisor（原型階段）**：在 host 執行有限 ARM/Thumb 指令，將檔案 syscall 路由至 broker，模擬程序映射 syscall；`run-elf` 的 host 依賴路徑與 `run-elf-interp` 的真實 Bionic 路徑分開。
3. **Guest service brokers（後續）**：按 Gingerbread 需求實作 Binder、ashmem、log 與 framebuffer 相容層。
4. **Guest image（後續）**：組成可追溯、可重現的 Android 2.3.7/API 10 ARM 系統檔案，與宿主 app 原生 ABI 分開管理。

下一階段從更完整的 API 10 native app trace 出發，補上確有需要且仍受 rootfs 限制的 syscall／裝置介面，並按實際 `DT_NEEDED` 增建 `libm` 等平台庫；之後再組成更完整的 system rootfs，驗證 `init` 與 Binder/ashmem 服務，最後才考慮 Android shell。每階段保留獨立 probe，不把部分相容性描述為完整 Android 啟動。

## 本機建置與測試

需要 Rust/Cargo：

```sh
./build-local.sh
```

此腳本執行主機測試、建置 release CLI，並在已安裝 `aarch64-linux-android` target 時做 ARM64 `cargo check`。該檢查不等於 Android 2.3.7 啟動或 32-bit ARM guest 執行；沒有 Android SDK/NDK 時也不能產生可安裝 APK／Android `.so`。

需要 Clang、LLD、`readelf`、`file`、`cmp` 和 Cargo，可執行合成 probes：

```sh
./probes/run-static-arm-probe.sh
```

要重跑真實 AOSP Bionic 的 `DT_NEEDED` 驗證，需先有精確 linker staged 在預設位置（或設定 `AOSP_LINKER`）：

```sh
./probes/run-bionic-needed-probe.sh
```

要建置並測試 AOSP 2.3.7 真實 Bionic `libc.so`／`libdl.so` 與 API 10 native app，需先備妥此 probe 所驗證的 AOSP source checkout 及 ARM EABI 4.4.3 toolchain：

```sh
python3 probes/run-aosp-libc-probe.py
```

要重建並重跑真實 AOSP Android 2.3.7 `init` 的有限執行 probe（使用相同 pinned source/toolchain）：

```sh
python3 probes/run-aosp-init.py
```

CLI 範例：

```sh
cargo run -- profile
cargo run -- doctor
cargo run -- init ./build/gb-rootfs
cargo run -- map ./build/gb-rootfs /tmp/example.txt
cargo run -- route openat
cargo run -- route mount
cargo run -- probe ./build/gb-rootfs
cargo run -- run-elf ./build/gb-rootfs ./static-arm-probe.elf
cargo run -- run-elf-interp ./build/bionic-needed-probe/rootfs ./build/bionic-needed-probe/main.elf
```

`run-elf` 對一般帶 `PT_INTERP` 的 app 仍由 host 預先載入並重定位 `DT_NEEDED`；`run-elf-interp` 則停用 host dependency preload，讓 guest `PT_INTERP` 自行載入依賴。兩種路徑都在 host process 解譯受限 guest 指令，不啟動 Android OS。遇到不支援的 ELF 功能或指令會明確停止。CLI 可在 ELF 路徑後附加 guest arguments，`argv[0]` 使用 ELF 檔名；CLI environment 目前為空。`probe` 只跑 scripted host-side broker 序列，不是執行 Android 程序。

## 建置輸出

主機 release CLI：`target/release/gingervm`。`target/` 和 `build/` 都是本機產物，不納入原始碼版本管理。
