# GingerVM 連續 guest trace v0.6.2

> 這是 GingerVM 的獨立測試原型，不是已完成開機的 Android 虛擬機。它以一條連續流程執行官方 Google API 10 ARM32 `/init`，並追蹤同一程序樹；不把 init、linker、Zygote 拆成互不相連的探測。手機端不需要 root、不呼叫 host mount，也不做逐指令 CPU 模擬。

## 最近確認的 Android 12 階段

以下是使用者提供的 **v0.6.1 真機日誌**，不是 v0.6.2 的新真機測試：1323 次 syscall entry、58 次路徑改寫、4 次虛擬 mount、5 次 device/mode 操作、6 次 identity 操作、1122 次 poll wait、1138 次 brokered SIGSYS suppression、4 次 denied；觀察到 1 個程序事件及 1 次 `/sbin/ueventd` exec，沒有 dynamic exec 或 guest linker entry。`/init` 到達軟體模擬的 event wait，但沒有虛擬事件來源送出事件；當時的 `STOP` 是 supervisor 時限，不是使用者取消。這不能證明 Zygote、framework、system-server 或桌面已啟動。

## 日誌查看與停止

GingerVM **不是循環日誌**：app cache 只保留最近一次完整 session，下一次執行會覆寫它。執行中的主畫面／「查看日誌」對話框保留最近約 48×1024 字元；結束後對話框讀取完整檔案的尾端最多 256 KiB。原始完整日誌仍可用「分享／儲存完整追蹤日誌」匯出；保存檔包含 staging 進度、停止請求、完整 supervisor 輸出及結果。停止也會出現在最新 session 日誌中。

「停止」在 staging 時會於複製、hash 驗證、系統樹核對及清理迴圈的取消檢查點停止；部分 app-private staging 會被標示為不完整，下一次執行會重新檢查或移除。trace 執行時，App 送出 SIGTERM；supervisor 設定取消旗標、終止並等待已追蹤程序，並輸出 `TRACE CLEANUP: tracked=… reaped=… already-gone=… unresolved=…`。手動停止訊息與 supervisor 時限訊息不同。完整日誌匯出仍只保留最近一次，不是多輪循環緩衝。

PaxVM 的**主日誌**也不是循環緩衝：主畫面只顯示最近約 24 KiB 並折疊重複行；Android 10+ 將完整主 session 逐行寫入 `Download/PaxVM-logs-<啟動時間>/session-log.txt`。舊版私有儲存 fallback 會把目前檔案輪替成一份 previous 檔案。設定裡的「保留最近 3 次」適用於獨立的 Startup Diagnostics，不是主 session 日誌。

## 回歸與限制

`bash build-native.sh` 通過：官方 Google API10 image hash、配對 ramdisk／完整 `/system` staging、broker/path、process tree、ARM32 ELF/linker、procfd、SIGSYS、Android ABI payload 與 APK 檢查均通過。新增的 Linux host ptrace cancellation regression 使用與 production 相同的 cleanup helper，測試 3 個 ptrace tracee 均被回收、`unresolved=0`，且沒有殘留 PID 或 zombie。這是 host kernel 證據，不是 Android 12 真機 Stop 按鈕測試；本次建置環境沒有 ADB。

Guest mount、uid/gid、device 與部分 property/socket 操作仍由 app-private broker 軟體模擬，host 不使用 root 或 mount。Binder、完整 property/event source、graphics 與裝置 driver 尚未實作。v0.6.2 尚未在 Android 真機執行，不能宣稱已越過 `/init` event wait，也不能宣稱 linker、Zygote、framework、system-server 或桌面成功啟動。

真機按「Stage guest + trace continuous Android startup」後，可在 staging 或 trace 期間按「停止」。停止後查看日誌，預期手動取消時會看到 `USER CANCEL REQUESTED`、`TRACE CLEANUP` 及 `STOP: user requested cancellation`；`unresolved=0` 表示 supervisor 對當時記錄的 tracee 都完成回收。若停止時 guest 尚未啟動或已自行結束，日誌會分別說明沒有 tracee 可回收或先前的 root-process stop 結果。

## 映像來源與 APK

來源是 Google Android SDK `armeabi-v7a-10_r05.zip`；配對 `system.img` 的 `build.prop` 標示 Android 2.3.7。來源與雜湊記錄在 [`IMAGE_SOURCE.txt`](guest-image/google-api10-android-2.3.7/IMAGE_SOURCE.txt)。官方 `/init` SHA-256：`2d9cbb198d8367f434c5fd7bada245c9e7618dc910253190f5d4dd3d0f6d1a00`；原始 system image SHA-256：`e41e8698c4d138a425c1ac3324209a7a2180db324360dc64dc7937ff6e3263fd`。

最終本機 APK：`app/build/outputs/apk/debug/app-debug.apk`，version `0.6.2`、versionCode `11`，大小 `63,008,981` bytes。簽章驗證通過 v1、v2；ABI 為 `arm64-v8a` 與 `armeabi-v7a`。SHA-256：`f212ba9d75a2a115742354afc38edcd70b1ada296fd5b4b2a27d44d8cb7b43e7`。本次只做本機建置，沒有推送 GitHub。
