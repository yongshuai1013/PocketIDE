# GingerVM 連續 guest trace v0.6.3

> 這仍是 GingerVM 的測試原型，不是已完成開機的 Android 虛擬機。它以一條連續程序樹執行官方 Google API 10 ARM32 `/init`，並在非 root 手機上用 app-private 軟體 broker 模擬部分 guest kernel 行為；不呼叫 host mount、不使用 host root，也不做逐指令 CPU 模擬。

## 真機 trace 確認的 coldboot 阻塞

使用者提供的 v0.6.2 完整日誌顯示：PID 18817 是原始 `/init`，它只有 entry #59 一次 `poll`；PID 18818 是其後 exec 的 `/sbin/ueventd`，entry #132 的 ARM syscall 281 回傳 `-ENOSYS`，entry #133 起才反覆 `poll`。因此持續等待的 child 是 `ueventd`，不是 PID 1 在重複 poll。

這與 API10 原始程式碼吻合。`[devices.c](https://android.googlesource.com/platform/system/core/+/android-2.3.7_r1/init/devices.c)` 的 `open_uevent_socket()` 建立 `AF_NETLINK / SOCK_DGRAM / NETLINK_KOBJECT_UEVENT` socket，設定 `SO_RCVBUFFORCE=65536`、`SO_PASSCRED=1`，再以 guest `getpid()` 與群組 `0xffffffff` bind。該 socket 建立失敗時，`device_init()` 直接返回，略過 coldboot 和 `/dev/.coldboot_done` 標記建立。`[ueventd.c](https://android.googlesource.com/platform/system/core/+/android-2.3.7_r1/init/ueventd.c)` 隨後以 `fd=get_device_fd()`、`events=POLLIN`、timeout `-1` 進入 poll 迴圈；上一版 `fd=-1` 的真機行為正由這段原始碼解釋。

PID 1 的等待也有直接來源：`[init.c](https://android.googlesource.com/platform/system/core/+/android-2.3.7_r1/init/init.c)` 在 early-init 後、property initialization 前排入 `wait_for_coldboot_done`；`[util.h](https://android.googlesource.com/platform/system/core/+/android-2.3.7_r1/init/util.h)` 將標記定義為 `/dev/.coldboot_done`，而 `[util.c](https://android.googlesource.com/platform/system/core/+/android-2.3.7_r1/init/util.c)` 的 `wait_for_file()` 每 10ms `stat()` 一次，直到檔案出現或逾時。這解釋了真機 trace 中 PID 1 的 `clock_gettime/stat64/nanosleep` 等待序列。

## v0.6.3 的最小軟體修正

Supervisor 現在只為原始 `/sbin/ueventd` 模擬這一種精確的 guest socket 參數，並驗證 bind 的 guest PID/群組及 API10 實際使用的兩個 socket option。它回傳 app-private 軟體 fd；沒有建立 host netlink socket，也不呼叫 host `socket`、`bind`、`setsockopt` 或 `poll`。虛擬 `/dev` mount 時會先移除可能殘留的 `.coldboot_done`，避免舊檔讓測試假成功；標記只能由原始 guest `ueventd` 的 open 路徑建立。

日誌會列出 uevent socket 的 syscall 參數，以及每個 tracee 前四次 poll 的 `(fd, events, timeout, result, fd source)`；也會明確回報 ueventd 是否開啟標記、PID 1 是否成功 `stat64(/dev/.coldboot_done)`。目前不會偽造硬體 uevent payload：guest `/sys` 是空的 app-private 軟體目錄，這個切片只嘗試讓原始 ueventd 完成空樹 coldboot 並釋放 init 的 marker wait。若之後要呈現裝置，仍需另行建立受控的 guest 裝置／事件模型。

**v0.6.3 尚未在 Android 真機重跑**，因此還不能宣稱 marker 已建立、PID 1 已越過 coldboot wait，更不能宣稱 linker、Zygote、framework、system-server 或桌面啟動。下一個可驗證里程碑是新日誌同時出現 `VIRTUAL UEVENT SOCKET`、`VIRTUAL UEVENT BIND`、兩種 `VIRTUAL UEVENT SETSOCKOPT`、`GUEST COLD-BOOT MARKER OPEN` 及 `INIT COLD-BOOT WAIT RELEASED`；之後再依第一個實際缺失介面繼續，不預判 property service 或 Binder 已成功。

## 回歸與安全界線

`bash build-native.sh` 通過：官方 Google API10 ramdisk/system image 雜湊、完整 `/system` staging、broker/path、guest uevent 參數驗證、ptrace/SIGSYS、process-tree cancellation/reap、ARM32 ELF/linker 與 APK payload 檢查均通過。新增 host unit test 覆蓋 socket、bind、setsockopt 的成功條件及錯誤參數拒絕；source contract 也確認無 host socket API 呼叫。這些是 host/build 證據，不是 Android 12 真機重測；目前沒有 ADB 裝置可供安裝驗證。

Guest mount、uid/gid、device/mode、部分 property/socket 行為仍由軟體 broker 模擬；host 不使用 root 或 mount。Binder、實際硬體事件、graphics、完整 property/service graph 與裝置 driver 尚未實作。請勿把這個候選版標示為完整 Android boot。

## 日誌與停止

GingerVM 主日誌不是循環緩衝：app cache 只保留最近一次完整 session，下一次執行會覆寫；執行中畫面保留約 48 Ki 字元，結束後查看器顯示完整檔案尾端最多 256 KiB，完整日誌仍可分享／儲存。停止 staging 時會在檢查點取消；停止 trace 時送 SIGTERM，supervisor 終止並回收已追蹤程序，日誌會區分使用者取消與時限逾期。

PaxVM 的主 session log 也不是循環緩衝：Android 10+ 逐行保留於 `Download/PaxVM-logs-<啟動時間>/session-log.txt`；設定中的「最近 3 次」是獨立 Startup Diagnostics 的保留數，不是主日誌輪替政策。

## 映像、APK 與測試簽章

原始來源是 Google Android SDK `armeabi-v7a-10_r05.zip`；配對 `system.img` 的 `build.prop` 標示 Android 2.3.7。來源與雜湊記錄在 [`IMAGE_SOURCE.txt`](guest-image/google-api10-android-2.3.7/IMAGE_SOURCE.txt)。官方 `/init` SHA-256：`2d9cbb198d8367f434c5fd7bada245c9e7618dc910253190f5d4dd3d0f6d1a00`；原始 system image SHA-256：`e41e8698c4d138a425c1ac3324209a7a2180db324360dc64dc7937ff6e3263fd`。

本機 APK `app/build/outputs/apk/debug/app-debug.apk` 是本機 debug 簽章，用來驗證 payload／ABI；其 SHA-256 為 `02f302fde7f9a5ab5a9e44260c204e448c68c02077a96739c276d10d4ffd1e6e`。GitHub Actions v0.6.3 驗證版改用 `ci-test-signing/gingervm-test.keystore`，預期簽章憑證 SHA-256 為 `398effdd769fa7db5bc6e45622b0d222570ffd0af3d889a8c23d0a82782ccc98`，artifact 只上傳簽署後 APK 與 checksum；workflow 會遮罩測試密碼的 CI 輸出，runner 暫存副本在建置後刪除，並檢查 APK 未包含簽章檔。

此 key 是使用者明確批准公開的 **throwaway 測試 key**，不得用於正式發布。公開 repo 的驗證分支與 workflow source 可被任何人讀取，因此測試密碼也可從 workflow source 看見；它不會出現在 CI logs 或 APK/artifact。本次只推送 `validation/gingervm-apk-v0.6.3`，不修改 `main`。
