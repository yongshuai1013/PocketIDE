# GingerVM 連續 guest trace v0.6.4

> 這仍是 GingerVM 測試原型，不是已完成開機的 Android 虛擬機。它以一條連續程序樹執行官方 Google Android 2.3.7/API 10 ARM32 `/init`，在非 root 手機上用 app-private 軟體 broker 模擬部分 guest kernel 行為；不呼叫 host mount、不使用 host root、host netlink 或 host Binder，也不做逐指令 CPU 模擬。

## 真機證據與目前阻塞

使用者提供的 v0.6.2 trace 證實，PID 18817 是原始 `/init`，只做了一次 `poll`；PID 18818 是 `/sbin/ueventd`，它的 ARM EABI syscall 281 回傳 `-ENOSYS`，接著反覆對 `fd=-1` 做 `poll`。這與官方 API10 [`devices.c`](https://android.googlesource.com/platform/system/core/+/android-2.3.7_r1/init/devices.c) 的 `open_uevent_socket()`、[`ueventd.c`](https://android.googlesource.com/platform/system/core/+/android-2.3.7_r1/init/ueventd.c) 的 `get_device_fd()` poll loop 一致。

v0.6.3 的後續真機日誌確認：guest-only uevent socket/bind 成功，原始 ueventd 建立 `/dev/.coldboot_done`，PID 1 越過 coldboot wait。接著 PID 1 的 ARM EABI syscall 93 緊鄰一個 `SYS_SECCOMP` `SIGSYS`；當時沒有 `si_syscall`/`si_arch` 欄位，因此該次被陷阱的 syscall 尚未由核心 metadata 確認。PID 1 收到 signal 後退出；未到 linker、Zygote、framework 或 desktop。使用者按 Stop 後，Java 記錄 `InterruptedIOException`，漏掉了最後的 native trace cleanup 行。

下一個 API10 程式碼候選是 property-area 初始化：官方 [`property_service.c`](https://android.googlesource.com/platform/system/core/+/android-2.3.7_r1/init/property_service.c) 的 `init_workspace()` 依序 `open("/dev/__properties__", O_RDWR|O_CREAT)`、`ftruncate(fd, size)`、`mmap()`，然後唯讀重開並 `unlink()`。v0.6.4 會記錄核心 SIGSYS 的 `si_syscall`、`si_arch`、call address、saved args 和 live ARM registers，才能確認是否正是 syscall 93，而不靠猜測。

## v0.6.4 的軟體修正

新增的 ARM EABI `ftruncate` broker 僅允許非負長度、可寫的普通檔案描述符；它透過 `/proc/<tracee>/fd/N` 檢查目標位於 app-private guest root 內，再重查開啟後的檔案類型與路徑。目錄、唯讀 fd、guest root 以外的檔案及錯誤 fd 都 fail-closed。這不是 host root 操作；不改變 Android app 的 uid/gid，也不呼叫 host mount、socket、netlink 或 Binder。`ftruncate64` 尚未由此 trace 證明需要，仍維持 deny。

停止時，App 送出 SIGTERM，最多等待 15 秒讓 supervisor 終止並回收 trace tree；只有 native STOP 明確回報所有追蹤程序已收回且 `unresolved=0` 時，UI 才會稱 cleanup confirmed。超時才會 force-stop，並明確標為 cleanup 未確認。輸出讀取改為原始 bytes 的 capture session：遇到短暫 `InterruptedIOException` 會保留已傳輸 bytes、清除讀取執行緒的中斷狀態並重試；停止後最多等 15 秒讀到 EOF，失敗時保留已讀日誌並清楚標記不完整，不會把缺少 cleanup 記錄說成成功。

## 測試與限制

`bash tests/run_init_broker_regression.sh` 通過：guest syscall policy、SIGSYS 到達順序、真實 host ptrace/seccomp `SYS_SECCOMP` metadata、app-private ftruncate 成功/拒絕案例、tracee cleanup、Java 輸出中斷恢復、官方 init/ELF/linker 檢查及 source contract。`bash build-native.sh` 另驗證官方映像雜湊、完整 `/system` staging、ARM64 supervisor、APK payload/ABI 和簽章。這些是 host/build 回歸，不代表 Android 12 真機已測試 v0.6.4。

下一個可驗證里程碑是新真機 log 顯示核心 `si_syscall`/`si_arch`，且 syscall 93 的 app-private guest property-area 檔案調整成功；之後仍須觀察 property service、linker、Zygote 和更後續啟動鏈。除非有同一 trace 的直接證據，不宣稱已達這些階段。

Binder、graphics、真實硬體事件與完整 Android service/driver graph 尚未實作。Guest mount、身份、裝置、socket/event 及受限檔案操作只在 app-private 軟體 broker 處理。APK 的本機 debug 簽章與 GitHub Actions 測試簽章不同；Actions 使用明確核准的 throwaway 測試憑證，正式用途不可使用。Artifact 僅包含簽署 APK 和 SHA-256，不包含 keystore。
