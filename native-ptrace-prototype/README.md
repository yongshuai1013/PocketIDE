# GingerVM continuous guest trace v0.6.1

> 這是 GingerVM 的獨立測試原型，不是已完成開機的 Android 虛擬機。它以一條連續流程執行官方 Google API 10 ARM32 `/init`，並追蹤同一程序樹；不會把 init、linker、Zygote 拆成互不相連的探測。手機端不需要 root，不呼叫 host mount，也不做逐指令 CPU 模擬。

## v0.6.0 真機 signal 31：診斷與修正

使用者提供的 v0.6.0 trace 顯示：原版 `/init` 的 ARM32 syscall `224`（`gettid`）被 broker 虛擬回傳 `1`；隨後 signal `31` 被轉送，`BROKERED SIGSYS SUPPRESSED` 計數為 `0`，root `/init` 因 signal 31 結束，supervisor status 為 `159`。當時沒有 fork、exec 或 linker 事件。

原 tracer 在 broker syscall entry 設定 `pending=1`、`expect_exit=1`，但只在兩個旗標仍同時成立時抑制 SIGSYS。後續 syscall-stop 分支提交虛擬回傳值並清除 `pending`；所以當 SIGSYS 到達時，舊條件已不成立。舊日誌沒有輸出中間的 raw wait status，無法再分辨到底是 syscall-exit stop，還是另一個 syscall stop 先清掉狀態；本版不把其中一種說法當成已從真機證實的順序。

v0.6.1 增加獨立的 broker-SIGSYS 候選標記：在 brokered syscall 時記下原 syscall 與虛擬回傳值，讓標記跨過 pending response commit；在 tracee 進入下一個 guest syscall 時失效。收到 SIGSYS 時呼叫 `PTRACE_GETSIGINFO`，只有候選仍有效且 `si_code == SYS_SECCOMP` 才抑制並以 signal 0 恢復。其他來源的 SIGSYS 仍會轉送。日誌會輸出 raw wait status、stop signal、ptrace event、`expect_exit`、`pending`、候選／提交狀態與 `si_code`，可核對實際真機順序。

## 測試結果與限制

`bash build-native.sh` 完整通過。除原有的官方 Google API10 映像 hash、guest broker/path、ptrace process-tree、guest ELF/linker、`/proc/self/fd/198` 與 APK payload 回歸外，新增兩項 SIGSYS 回歸：

- 狀態機測試覆蓋 SIGSYS 在虛擬回傳值提交前或提交後到達、拒絕非 seccomp signal code，以及後續 syscall entry 使舊候選失效。
- Linux x86_64 host 的實際 ptrace/seccomp 測試觀察到 wait status `0x1f7f`、stop signal `31`、`si_code=1 (SYS_SECCOMP)`；在 response commit 後仍成功匹配候選並抑制 signal。這驗證通用 Linux wait-status 路徑，**不是** Android 12 ARM32 真機測試。

官方 Google API10 ramdisk 與配對的完整 `/system` 已驗證並打包；guest mount、uid/gid、device 與部分 property/socket 操作仍由 app-private broker 軟體模擬，不使用 host root 或 mount。v0.6.1 尚未在 Android 12 真機重跑，尚不能宣稱 `/init` 已越過 signal 31，更未證明 linker 主程式、Zygote、framework、system-server 或桌面成功啟動。Binder、完整 property/event source、graphics 與裝置 driver 仍未實作。

## 真機測試

安裝 v0.6.1 後，按 **Stage guest + trace continuous Android startup** 執行同一條 `/init` 程序樹，再按 **分享／儲存完整追蹤日誌** 匯出文字檔。請保留 `PTRACE SIGSYS WAIT STATUS`、`BROKERED SYSCALL SIGSYS SUPPRESSED` 或 `BROKERED SIGSYS CANDIDATE REJECTED`、其後第一個錯誤／unsupported syscall、程序事件及最後的 `STOP` 摘要。若 Android 回報 `SYS_SECCOMP`，預期看到候選被抑制且 signal 31 不再被轉送；後續能否繼續仍取決於下一個實際 guest 阻塞點。

## 映像來源與 APK

映像來源為 Google Android SDK `armeabi-v7a-10_r05.zip`；配對的 `system.img` 內 `build.prop` 標示 Android 2.3.7。來源與 hash 記錄位於 [`IMAGE_SOURCE.txt`](guest-image/google-api10-android-2.3.7/IMAGE_SOURCE.txt)。官方 `/init` SHA-256：`2d9cbb198d8367f434c5fd7bada245c9e7618dc910253190f5d4dd3d0f6d1a00`；原始 system image SHA-256：`e41e8698c4d138a425c1ac3324209a7a2180db324360dc64dc7937ff6e3263fd`。

候選 APK：`app/build/outputs/apk/debug/app-debug.apk`，version `0.6.1`、versionCode `10`，大小 `62,976,491` bytes。APK 簽章驗證通過（v1、v2）；支援 ABI 為 `arm64-v8a` 與 `armeabi-v7a`。SHA-256：`3998cf655b0926ac2ce2c5eed34c3c45ed41f8ed1ffedffc8d3b4005bc512be7`。

## 驗證分支與 CI APK

GitHub Actions 的 `android-apk` job 使用 Java 21、Android API 35 與 NDK 27.2.12479018。`tests/prepare_google_api10_ci.sh` 從 Google 官方網址下載 API10 SDK ZIP，核對 ZIP、ramdisk 與 system image 的固定 SHA-256；只抽取所需映像，使用 gzip/newc 解析及未提權的 `debugfs` 建立 guest staging，不掛載映像。APK、system image、ZIP、app-private 資產和 ABI 原生庫都不納入 Git；CI 建置完成後上傳 `gingervm-continuous-trace-v0.6.1-apk` 工件，包含 APK、SHA-256 與建置日誌。
