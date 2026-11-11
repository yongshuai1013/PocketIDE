# GingerVM 連續 guest trace v0.6.6

> 這仍是測試原型，不是已完成開機的 Android 虛擬機。它在非 root Android 手機上，以 native ARM64 supervisor 連續追蹤官方 Google Android 2.3.7/API 10 ARM32 `/init` 程序樹，並在 app-private guest root 模擬部分核心行為；不呼叫 host root、mount、netlink 或 Binder，也不使用逐指令 CPU 模擬。

## v0.6.6 介面：KitKat Holo 與即時追尾

App 改用 Android 4.4 時代的 Holo Light / Dark ActionBar 風格：淺色內容、深色頂欄與系統列、Holo 藍色 `#33B5E5` 控制強調色，避免 Material 圓角卡片與新式視覺。主畫面日誌每次收到新文字都捲到最新一行；若「查看日誌」視窗在執行中打開，它也會同步更新並跟隨最新行。這只改 UI，不改 guest syscall 模型；完整日誌分享／儲存及手動停止行為維持原樣。

## 真機證據：syscall 93 成功，下一步是 syscall 83

使用者提供的 v0.6.4 Android 12 完整 trace 證實，ueventd 建立 `/dev/.coldboot_done` 後，PID 1 越過 coldboot 等待。PID 1 接著以 ARM syscall 93 將 app-private property-area 檔案調整為 32768 bytes，日誌記錄 `result=0`。之後核心回報真正的 `SIGSYS`：`si-syscall=83`、`si-arch=0x40000028`；不是前一個已 broker 的 `ftruncate` 假 syscall。

ptrace 保存的字串指標相差 12 bytes。將真機暫存器/參數與原始 guest ELF 記憶體、官方 API10 [`init.rc`](https://android.googlesource.com/platform/system/core/+/android-2.3.7_r1/rootdir/init.rc) 及 [`builtins.c`](https://android.googlesource.com/platform/system/core/+/android-2.3.7_r1/init/builtins.c) 的 `symlink(target, link)` 順序核對後，確認該呼叫是 `symlink("/system/etc", "/etc")`。因此 syscall 83 是下一個已被真機證據確認的 property/init 啟動阻塞；不把它猜成 linker 或 Binder 問題。

## v0.6.5 修正

ARM EABI syscall 83 `symlink` 與 331 `symlinkat` 現在被分類為 app-private file operation。Supervisor 讀取 guest 的 target/link 參數、把 guest 路徑映射到 staging backing，再由 broker 建立 symlink 並將成功或 errno 以 fake syscall 結果回傳；原始 ARM syscall 不會被送到 Android 核心。`symlinkat` 只接受 `AT_FDCWD`，其他 dirfd fail-closed。

安全邊界是：link 的父目錄必須解析在 app-private guest root 內；target 必須解析在 guest root 或 APK 擷取的 guest-native payload root 內。對 dangling target 只允許從已存在且位於允許 root 的祖先延伸；沿途 symlink 會被解析並重新檢查 containment。建立前會開啟並固定已驗證的 link 父目錄，再以 descriptor-relative `symlinkat` 建立。`..`、相對路徑、指向外部的 target/link parent 及 root-prefix 相似但實際在外的路徑會 fail-closed。沒有對 host `/etc`、`/system` 等根目錄寫入或重新導向。

SIGSYS correlation 也收緊：只有已掛起的 broker 候選、`SYS_SECCOMP` 且核心 `si_syscall == -1`（supervisor 用來取消 guest syscall 的 placeholder）才可被抑制。真實 `si_syscall=83` 不匹配候選，會清除候選並轉送原始 signal。

## 測試與限制

`bash tests/run_init_broker_regression.sh` 包含 syscall class、app-private symlink 成功/拒絕、native payload target、symlink 逃逸、link-parent 逃逸、`..` 路徑、已有連結、SIGSYS metadata 與 ptrace/seccomp、ftruncate、tracee cleanup、Java log capture、Holo 主題／即時自動捲動 source-contract、官方 init/linker/ELF 和其他 source-contract 回歸。`bash build-native.sh` 另外驗證官方映像、完整 `/system` staging、ABI、APK 簽章與內容。

上述是 host/build 回歸，不代表 v0.6.6 已在 Android 真機執行。v0.6.4 的 trace 在上述 symlink 阻塞處退出並由 supervisor timeout 收束，`tracked=1 reaped=1 unresolved=0`；沒有到 guest linker、Zygote、framework 或 desktop。下一個 guest 驗證點仍是新真機日誌顯示 `GUEST VFS SYMLINK ... target=/system/etc link=/etc result=0`，再觀察 property service 後續、dynamic linker 與 Zygote；另需在手機確認 Holo 樣式和即時日誌追尾。即使達到 linker entry，也不等於 Framework 或完整桌面已開機。

Guest mount、身份、裝置、uevent/event 與受限檔案操作仍是 app-private 軟體模型；Binder、graphics、真實硬體事件及完整 service/driver graph 尚未實作。GitHub Actions APK 使用核准的測試簽章，keystore 不進入 APK artifact。
