# GingerVM Android 測試 App

這個 Android App 將 GingerVM Rust ARM interpreter 接到手機 UI。目前可執行的模式是用 ARM user-mode interpreter 執行真實 AOSP Gingerbread `init`；必要輸入是 `/init`、`/init.rc` 與 `/system/build.prop`。這不是 guest-kernel 虛擬機：`kernel`、`ramdisk` 和 `userdata` 映像對此模式不適用，並非缺少的啟動條件。

完整 guest-kernel boot 是另一條尚未實作的路徑；只有實作那條路徑時，kernel、ramdisk 和持久 userdata 映像才會成為相關輸入。`init` 到達 `WaitingForEvents` 也不代表 Android 已完整開機，不會啟動 Zygote、Dalvik、framework 或一般 APK。App 另有「執行 GingerVM init 基準測試」及獨立的 SIMULATED property event 按鈕。

畫面另有一個獨立的 **SIMULATED：注入 property socket event** 按鈕。只有使用者明確按下它才會排入一筆固定、guest-local 的 AOSP property-service `SETPROP` 訊息：`debug.gingervm.simulated=1`。虛擬 peer 使用 AOSP shell UID 2000，訊息長度符合 Gingerbread `prop_msg`（128 bytes）；AOSP `init` 的真實 event loop 會經由 `poll`、`accept`、`SO_PEERCRED` 與 `recvfrom` 處理它，報告會明確標示 `SIMULATED` 並記錄 guest 回應。這不會建立 host socket、改動手機 property、產生 kernel uevent 或聲稱偵測到硬體；baseline 按鈕不注入事件。

## 系統映像來源

`/system` 目錄取自 Google Android SDK 的 API 10、ARM EABI v7a、default system-image revision 5：

- 下載 URL：<https://dl.google.com/android/repository/sys-img/android/armeabi-v7a-10_r05.zip>
- ZIP SHA-256：`b3c6188ca95bea7299b8325bd3bbd4f504fc85545befec979728f2ed169878df`
- 套件中 `source.properties` 標示 Android SDK Platform 2.3.3、API 10、revision 5；映像的 `build.prop` 實際標示 `ro.build.version.release=2.3.7`、`ro.product.device=generic`，fingerprint 為 `generic/sdk/generic:2.3.7/GINGERBREAD/3644351:eng/test-keys`。
- 已從 `system.img` 擷取 `/system`，包括 `app`、`bin`、`etc`、`framework`、`lib`、`media`、`fonts`、`usr`、`xbin` 等目錄；系統原有的 `/system/etc/NOTICE.html.gz` 內容也隨 App 打包（APK 會以 `NOTICE.html` 呈現），可從畫面檢視。該 SDK ZIP 的 kernel、ramdisk 和 userdata 映像沒有打包；它們不屬於目前 user-mode init 測試所需材料。
- 該 system-image 是 generic ARM emulator image，不是某款手機的廠商韌體。下載的 APK 不會在手機上直接啟動其中的 Android OS。

`/init` 是依官方 AOSP tag `android-2.3.7_r1` 原始碼建置的真實靜態 init，`/init.rc` 取自同 tag 的 `platform/system/core`；AOSP Bionic 與 system/core checkout 分別固定於 `3f14ff34dfbd00fcffb18b10a1a3e17e2cc5ebdf`、`838a24ac661dfb5147dd584e6dc36dc74c61725e`。以 App 隨附的完整 `/system` tree 在 GingerVM host interpreter 重跑，得到 663,153 條 ARM 指令、844 個 brokered syscall events，停止於 `WaitingForEvents`（等待尚未提供的虛擬 fd event）。這不是完整 Android 開機，也沒有 guest kernel、完整硬體服務、Binder/ashmem、Dalvik 或 APK 執行。

系統程式由各自開源授權規範；打包的 NOTICE 保留映像原有開源歸屬與通知。請另遵守 [Android SDK 使用條款](https://developer.android.com/studio/terms)；這份建置是個人測試交付，不應直接當成可公開散布的 ROM 或 SDK 映像。

## 本機模擬事件測試

在已準備好 App rootfs assets 的專案中執行：

```sh
cargo build --release --bin gingervm
python3 probes/run-aosp-init-simulated.py
```

腳本會以 hardlink 建立獨立的 ignored 測試 rootfs，執行隨 App 打包的精確 AOSP Gingerbread `init`，並驗證 `SIMULATED EVENT`、property 訊息已被 init 接收，以及最終回到 `WaitingForEvents`。也可直接指定另一份含有 `init` 與 `/system/build.prop` 的 guest rootfs。

## 建置

需要 Rust、Android SDK API 35、Build Tools 35.0.0、NDK 27.2.12479018、`debugfs` 與 Gradle 8.9。設定 `ANDROID_SDK_ROOT`（或 `ANDROID_HOME`），然後在 GingerVM 專案根目錄執行：

```sh
./build-android-apk.sh
```

腳本會抓取並驗證上面的 API 10 image checksum、擷取 `/system` 資產、交叉建置 arm64-v8a 與 armeabi-v7a native library，最後產生已簽章的 debug APK。
