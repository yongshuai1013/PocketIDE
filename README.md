# GingerVM

GingerVM 是一個全新、獨立的 Android-in-Android 虛擬化研究專案；不依賴也不修改 `/workspace/PaxVM`。目標 guest 是 Android 2.3.7 Gingerbread（API 10、32 位 ARM），方向是 App 沙盒內的 userspace supervisor，而不是桌面 QEMU 前端。

## 目前狀態：guest-to-broker prototype 0.3

本機可編譯、可測的閉環目前包含：

- Gingerbread 2.3.7 guest profile，以及每個 guest 獨立的 rootfs 目錄骨架與絕對 guest path 映射。
- Broker 支援 rootfs 範圍內的 `open`、`read`、`write`、`close`，以及虛擬 `uid`／`gid`／`pid`；guest FD table 由各 broker instance 各自持有，單次 I/O 上限 1 MiB。
- Host 端可載入 **32 位 little-endian ARM 靜態 `ET_EXEC` ELF**，從 ARM A32 或 16-bit Thumb entry 執行一小組 ARMv7 指令；EABI `svc #0` 的檔案與身分 syscall 會逐一送進同一個 broker。未支援 syscall 由 broker 拒絕，不會直接轉成宿主 syscall。
- `GuestProgram` scripted harness 仍保留；`gingervm run-elf <rootfs> <static-arm-elf>` 可執行符合上述限制的 ELF，`gingervm probe <rootfs>` 則只驗證 scripted harness。

**執行器目前是窄範圍相容性原型，不是通用 ARM 模擬器，也不是可開機的 Android VM。** 指令集只涵蓋測試所需的有限 A32／Thumb 指令；dynamic/PIE ELF、Thumb-2、共享函式庫、VFP/NEON、signal/thread、Binder、ashmem、Android framework 和完整 system image 尚未支援。自動測試使用程式建立的 ARM ELF fixture，不代表已用 Android NDK 產生或驗證真實 Android binary。它也不是核心 syscall interceptor 或安全邊界：rootfs 的 canonicalize 路徑檢查仍有 symlink race 風險，正式 supervisor 需要 descriptor-relative 操作及 Android 裝置上的核心相容性驗證。

## 設計分層

1. **Android shell（後續）**：管理 VM instance、rootfs、前景服務與畫面呈現；不直接承擔核心攔截邏輯。
2. **Supervisor（原型階段）**：在 host 端執行有限 ARM/Thumb 指令，將支援的 EABI syscall 路由到 broker；下一步要擴充執行能力與安全隔離，而非宣稱已能跑完整 Android 程序。
3. **Guest service brokers（後續）**：按 Gingerbread 需求實作 Binder、ashmem、log 與 framebuffer 相容層。每種 broker 都有獨立測試與版本化 ABI。
4. **Guest image（後續）**：由可追溯、可重現的 Android 2.3.7/API 10 ARM 系統檔案組成，與宿主 app 的原生 ABI 分開管理。

實作順序以可驗證閉環為準：rootfs／path policy → scripted broker harness → 受限 ARM/Thumb ELF 執行與 syscall broker → 可由 ARM toolchain 產生的靜態 guest probe → 擴充 syscall/載入能力 → init 診斷 → Binder/ashmem 等必要 broker → Android shell 與裝置測試。每個階段都保留可單獨重現的本機測試。

## 本機建置與測試

需要 Rust/Cargo。執行：

```sh
./build-local.sh
```

腳本會執行主機端測試、建置 release CLI，並在已安裝 `aarch64-linux-android` Rust target 時做 Android ARM64 核心 `cargo check`。目前環境有 Rust Android target，但沒有 Android SDK/NDK；所以可驗證核心跨目標編譯，**不能產生或宣稱產生可安裝 APK／Android `.so`**。這項 ARM64 編譯檢查也不等於 32-bit ARM guest 執行。`elf` 模組的測試會在本機建立 ARM ELF fixture，驗證 A32/Thumb 指令、brokered file round-trip、虛擬身分、拒絕策略與執行指令數上限。

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

範例中的 `static-arm-probe.elf` 是示意檔名，需由外部 ARM toolchain 先產生；目前環境沒有 ARM guest compiler，也沒有隨專案產生 guest ELF。`run-elf` 僅接受目前 runner 支援的靜態 ARM ELF；遇到不支援指令會明確停止。它在 host process 執行，不會啟動 Android framework 或 guest service。`probe` 只跑 scripted host-side broker 序列，並在指定 rootfs 的 `/tmp` 暫存及清除測試檔；不是執行 Android 程序。

## 建置輸出

主機 release CLI：`target/release/gingervm`。`target/` 是本機產物，不納入原始碼版本管理。
