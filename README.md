# GingerVM

GingerVM 是一個全新、獨立的 Android-in-Android 虛擬化研究專案；不依賴也不修改 `/workspace/PaxVM`。目標 guest 是 Android 2.3.7 Gingerbread（API 10、32 位 ARM），方向是 App 沙盒內的 userspace supervisor，而不是桌面 QEMU 前端。

## 目前狀態：A32 資料處理核心 prototype 0.5

本機可編譯、可測的閉環目前包含：

- Gingerbread 2.3.7 guest profile，以及每個 guest 獨立的 rootfs 目錄骨架與絕對 guest path 映射。
- Broker 支援 rootfs 範圍內的 `open`、`read`、`write`、`close`，以及虛擬 `uid`／`gid`／`pid`；guest FD table 由各 broker instance 各自持有，單次 I/O 上限 1 MiB。
- Host 端可載入 **32 位 little-endian ARM 靜態 `ET_EXEC` ELF**，從 ARM A32 或 16-bit Thumb entry 執行有限指令子集。A32 資料處理指令已獨立成可測的 ALU 核心，涵蓋 16 種運算、立即數／暫存器 Operand2、barrel-shifter 與 NZCV 算術旗標；EABI `svc #0` 的檔案與身分 syscall 會逐一送進同一個 broker。未支援指令會明確停止，未支援 syscall 由 broker 拒絕，不會直接轉成宿主 syscall。
- `GuestProgram` scripted harness 仍保留；`gingervm run-elf <rootfs> <static-arm-elf>` 可執行符合上述限制的 ELF，`gingervm probe <rootfs>` 則只驗證 scripted harness。

**這不是在執行 Android 2.3.7 作業系統。** Gingerbread 2.3.7 目前是目標 guest profile；尚未載入 Android 系統映像、核心、`init`、Bionic、framework 或系統服務。本機驗證的 `probes/armv7-static-probe.S` 是以 ARMv7 GNU/Linux EABI 組譯的極小靜態程式，由 GingerVM 在 Linux host process 中解譯；它不是 Android APK，也沒有啟動 Android runtime。

此探針以 Clang/LLD 產生真正的 32 位 little-endian ARM EABI5 靜態 `ET_EXEC`，目前成功跑過 86 條 A32 指令與 12 次 broker syscall，檢查 rootfs 檔案寫入、重開讀取、複製，以及虛擬 `uid=1000`／`gid=1000`／`pid=1`；host 端再比對兩個檔案。這只驗證該 probe 用到的窄指令／syscall 子集，不代表 Gingerbread binary、APK 或 Android 核心相容。

**執行器目前是窄範圍相容性原型，不是通用 ARM 模擬器，也不是可開機的 Android VM。** A32 資料處理是其中一個已有獨立 decoder/ALU 和單元測試的指令族；A32 load/store 與控制流程、以及 Thumb 仍只有有限子集。dynamic/PIE ELF、Thumb-2、共享函式庫、VFP/NEON、signal/thread、Binder、ashmem、Android framework 和完整 system image 尚未支援。自動測試仍使用程式建立的 ARM ELF fixture；額外的工具鏈 probe 也不是 Android NDK 所產生或驗證的 Android binary。它也不是核心 syscall interceptor 或安全邊界：rootfs 的 canonicalize 路徑檢查仍有 symlink race 風險，正式 supervisor 需要 descriptor-relative 操作及 Android 裝置上的核心相容性驗證。

## 設計分層

1. **Android shell（後續）**：管理 VM instance、rootfs、前景服務與畫面呈現；不直接承擔核心攔截邏輯。
2. **Supervisor（原型階段）**：在 host 端執行有限 ARM/Thumb 指令，將支援的 EABI syscall 路由到 broker；下一步要擴充執行能力與安全隔離，而非宣稱已能跑完整 Android 程序。
3. **Guest service brokers（後續）**：按 Gingerbread 需求實作 Binder、ashmem、log 與 framebuffer 相容層。每種 broker 都有獨立測試與版本化 ABI。
4. **Guest image（後續）**：由可追溯、可重現的 Android 2.3.7/API 10 ARM 系統檔案組成，與宿主 app 的原生 ABI 分開管理。

實作順序以可驗證閉環為準：rootfs／path policy → scripted broker harness → 受限 ARM/Thumb ELF 執行與 syscall broker → 靜態 ARM guest probe（已完成窄範圍 host 驗證）→ 擴充指令／syscall 與 Android toolchain 相容性 → Gingerbread 系統映像和 init 診斷 → Binder/ashmem 等必要 broker → Android shell 與裝置測試。每個階段都保留可單獨重現的本機測試。

## 本機建置與測試

需要 Rust/Cargo。執行：

```sh
./build-local.sh
```

腳本會執行主機端測試、建置 release CLI，並在已安裝 `aarch64-linux-android` Rust target 時做 Android ARM64 核心 `cargo check`。目前環境有 Rust Android target，但沒有 Android SDK/NDK；所以可驗證核心跨目標編譯，**不能產生或宣稱產生可安裝 APK／Android `.so`**。這項 ARM64 編譯檢查也不等於 Android 2.3.7 啟動或 32-bit ARM guest 執行。`elf` 模組的自動測試會在本機建立 ARM ELF fixture；另外的工具鏈 probe 會以 Clang/LLD 產生真實靜態 ARM ELF。

需要 Clang、LLD、`readelf`、`file`、`cmp` 和 Cargo，執行：

```sh
./probes/run-static-arm-probe.sh
```

腳本會建置 host CLI、產生並檢查 ARM ELF，透過 `run-elf` 執行，再比對 guest rootfs 中探針寫出的原始檔和讀回複製檔。此 probe 使用 `armv7-linux-gnueabi`，**不是 Android NDK／Bionic binary**；`run-elf` 在 Linux host process 解譯受限 guest 指令，不是執行 Android 2.3.7 OS、APK 或 framework。生成的 ELF 和執行紀錄位於 `build/arm-static-probe/`。

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
```

`run-elf` 僅接受目前 runner 支援的靜態 ARM ELF；遇到不支援指令會明確停止。它在 host process 執行，不會啟動 Android framework 或 guest service。`probe` 只跑 scripted host-side broker 序列，並在指定 rootfs 的 `/tmp` 暫存及清除測試檔；也不是執行 Android 程序。

## 建置輸出

主機 release CLI：`target/release/gingervm`。`target/` 是本機產物，不納入原始碼版本管理。
