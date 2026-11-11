# GingerVM 連續 guest trace v0.6.8

> 這仍是 Android guest 啟動原型，不是已完成開機的虛擬機。目標是在未 root 的 ARM64 Android 主機上，以 native ARM64 supervisor 追蹤官方 Google Android 2.3.7/API 10 ARM32 `/init` 與同一程序樹；不使用逐指令 CPU 模擬，也不呼叫 host root、mount、netlink 或 Binder。

## v0.6.7 為何沒有執行 guest

使用者提供的 Android 12 截圖顯示，v0.6.7 在 staging 清理舊 app-private guest tree 時失敗於 `.../google-api10-full-root/mnt/sdcard`，並明確回報「No guest program was executed」。這次錯誤發生在啟動 guest 之前，不是 `/init` 的新 trace。

根因已由 API10 原始設定確認：[官方 `android-2.3.7_r1/rootdir/init.rc`](https://android.googlesource.com/platform/system/core/+/android-2.3.7_r1/rootdir/init.rc) 指定 `mkdir /mnt/sdcard 0000 system system`；相同命令也在 APK 的[原始 init.rc 資產](app/src/main/assets/api10-init-root/init.rc)中。guest 執行時，VFS 將該路徑放在 app-private backing，因此前次執行留下了真實目錄，但 owner 沒有讀取／搜尋權限。下一次清理先用 `lstat` 看見目錄，再呼叫 `File.listFiles()`；Java 回傳 `null`，導致 staging 中止。

## v0.6.8 的修正

遞迴刪除已抽成共用 `AppPrivateTreeCleanup`：缺失路徑（`ENOENT`）是安全 no-op；只有 `lstat` 確認為真實目錄時才補回 app owner 的讀、寫、搜尋位元；列目錄前以 `O_NOFOLLOW` 開啟並用 `fstat` 核對目錄身分；guest symlink 只移除連結本身，不遞迴進入其目標。這只改動 app 私有 backing，不需要 host root 或 mount，也不改變 guest `/mnt/sdcard` 的預期 mode。

`bash tests/run_init_broker_regression.sh` 新增 host regression，重現 API10 的 mode-0000 目錄、巢狀不可讀目錄、缺失目錄重跑、guest tree 內指向外部的 symlink，以及 symlink 作為清理根目錄；測試確認外部 marker 保持原樣。其他既有 socket、ftruncate、SIGSYS、trace cleanup、日誌與 APK payload 回歸也一併執行。

## 真機狀態與下一步

v0.6.6 trace 曾通過 coldboot wait、property-area `ftruncate` 和 VFS symlink，之後 PID 1 的 `AF_UNIX socket(1,1,0)` 收到 `EAFNOSUPPORT`。v0.6.7 增加 app-private 記憶體 socket 模型，但使用者提供的 v0.6.7 截圖在 staging 階段失敗，因此那個 socket 模型尚未得到真機驗證。

v0.6.8 的 cleanup fix 目前只有 host regression 和 APK 建置可驗證，尚未在 Android 12 真機確認。安裝後應先看 staging 是否成功；若啟動到 guest，再以完整追蹤日誌判定 socket lifecycle 是否繼續。即使 coldboot 放行、syscall broker 成功或進入 linker，也不能據此宣稱已到 Zygote、Framework、桌面或完整 Android boot。
