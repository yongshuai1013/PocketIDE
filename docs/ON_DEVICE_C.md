# 裝置端 C 編譯：接入方式與限制

Pocket IDE 新增可選的 Clang／Mach-O LLD 進程內編譯路徑，目標為 **iOS 15、arm64、iPhone 7**。預設仍是沒有編譯器的 stub；只有連入真實函式庫、安裝資源與 SDK 後，Build 才會執行 C 編譯及連結。Swift frontend 尚未整合。簽名、安裝及執行不在這次範圍內。

## 編譯流程

App 的 `EmbeddedCInvoker` 經原創 C ABI 呼叫 Clang／LLD；`NativeCBackend` 在非主執行緒的 actor 上逐檔編譯，之後連結一次。命令參數以 argv 傳遞，不經 shell，也不啟動子行程。使用絕對路徑，沒有改變全進程工作目錄。橋接還須以全進程鎖保護 LLVM／LLD 共用狀態。

每次建置都使用 `Documents/PocketIDE/Builds/<UUID>`，保留來源、object、`PocketIDE.out` 與 `build.log`。編譯或連結失敗會清理該次目錄，診斷留在 console；非零返回值、產物缺失或不符合預期的 Mach-O header 都不能視為成功。Mach-O 檢查現會驗證完整 load-command 範圍／總數、常見資料引用邊界、arm64 subtype 0、object/executable 類型、iPhoneOS／iOS 15.0 目標及無簽名命令；仍不是完整 loader 或真機相容性證明。

連結參數使用 `-no_adhoc_codesign`，不為產物加上 ad-hoc 簽名。產物只是未簽名命令列 Mach-O，不是完整 `.app` 或可安裝 IPA。

## 固定版本與來源

上游為 [LLVM](https://github.com/llvm/llvm-project/tree/llvmorg-18.1.8)，固定版本 **18.1.8**、commit `3b5b5c1ec4a3095ab096dd780e84d7ab81f3d7ff`。使用 Clang 與 LLD 原始碼，不複製 [XForge](https://github.com/R0GUEEE/XForge) 程式碼。XForge 僅作為進程內架構的技術參考，其最低部署設定不沿用。

建置選項參考 [LLVM CMake 說明](https://llvm.org/docs/CMake.html) 與 [18.1.8 來源](https://github.com/llvm/llvm-project/blob/llvmorg-18.1.8/llvm/CMakeLists.txt)。腳本準備的函式庫及 headers 受 LLVM 的上游授權約束；來源授權檔也會放入工具鏈 `licenses/`。正式散布前仍須審查所有 notices 及依賴。

## 在 Mac 建置原生工具鏈

需要 Xcode 16.4、CMake、Ninja、足夠磁碟空間及記憶體。在專案根目錄執行：

```bash
export DEVELOPER_DIR=/Applications/Xcode_16.4.app/Contents/Developer
JOBS=4 bash scripts/build-native-toolchain.sh
# 完成後重新執行 XcodeGen，再建置 PocketIDE。
```

配方先建置 macOS host 的 `llvm-tblgen`／`clang-tblgen`，再用本機 Xcode 的 SDK cross-build iPhoneOS arm64、最低 iOS 15 的靜態函式庫。僅啟用 AArch64 後端；不建 Swift，不建 iOS-hosted CLI 工具。暫存預設在 `.toolchain-build/`，可用 `POCKETIDE_TOOLCHAIN_BUILD_DIR` 更改位置。這些大型檔案已加入 `.gitignore`。

腳本會編譯真實橋接，並強制載入所建靜態庫做 iOS arm64 連結檢查。這能抓出 C++ API 與靜態庫閉包問題，**不能證明編譯器已在手機執行**。函式庫與橋接任一檢查失敗都不應啟用工具鏈。

成功後才生成 `toolchain/NativeCompiler.generated.xcconfig`，供 `project.yml` 的 App target 使用。啟用設定僅套用 `iphoneos`；模擬器仍編譯 stub，不能連入裝置靜態庫。靜態庫使用 `-force_load` 避免註冊碼被漏掉，但會增加體積，也可能暴露缺失依賴或符號衝突。原生 CI run 39303725941 已以 Xcode 16.4 實際完成工具鏈建置及 App link-check；這證明該 commit 上建置／連結成功，不代表已發布、安裝或在 iPhone 執行。詳見[證據矩陣](EVIDENCE.md)。

XcodeGen 將 `toolchain/ios-arm64/Toolchain` 以 folder resource 複製進 App，Clang builtin headers 最終位於 `App Bundle/Toolchain/clang/include`。本輪配方另把含 `BUILTIN_HEADERS_VERSION` 的 manifest 複製到 `App Bundle/Toolchain/manifest.txt`，讓 App 預檢可讀；舊 artifact 不含這項新證據時顯示 Unverified，不回填虛構版本。XcodeGen 2.44.1 的 `optional: true` 不會避免 Xcode 在資源目錄不存在時複製失敗；一般建置應在產生專案前執行 `bash scripts/prepare-toolchain-resources.sh`，它只建立空目錄且不更動既有原生資源。原生建置成功後，該目錄由真實 Clang headers 填入，native workflow 另行驗證 bundle 內容；不可用空目錄準備步驟取代原生工具鏈建置／驗證。若先前已產生 Xcode 專案而目錄仍不存在，建立目錄後重新執行 XcodeGen。

### 在 GitHub Actions 建置

執行 `Native LLVM 18.1.8 iOS toolchain` 的手動工作流程，或推送工具鏈／橋接相關變更到 `main`。工作使用 `macos-15`、Xcode 16.4、3 個建置工作及 330 分鐘上限，先做上述原生工具鏈建置與橋接連結檢查，再建置完整未簽名裝置 App；沒有簽名或實機執行步驟。

成功產物 `PocketIDE-LLVM-18.1.8-ios15-arm64` 包含 `PocketIDE-LLVM-18.1.8-ios15-arm64.tar.gz`、未簽名 App ZIP 及 SHA-256，保存 7 天。工具鏈壓縮包可在專案根目錄解壓，以還原 `toolchain/ios-arm64` 與生成的 xcconfig，之後須重新執行 XcodeGen。工具鏈含 LLVM headers、靜態庫、builtin headers、授權及 manifest，**不含 Apple SDK**。失敗時查看 `native-toolchain-build-logs`；首次 Mac 建置仍可能暴露移植、資源或連結問題，不能在 workflow 通過前宣稱原生工具鏈可用。

## SDK 由使用者自行提供

本專案**不下載、打包或散布 Apple SDK**。建置函式庫時僅引用 Mac 本機 Xcode SDK；要在手機編譯，使用者另須自行確認授權與使用權限，透過自己的方式把合法可用的 SDK 放進 App 的 Files 容器：

```text
Documents/PocketIDE/Toolchain/iPhoneOS.sdk/
  SDKSettings.plist  # Version 與 CanonicalName（iphoneos…）
  usr/include/stdio.h
  usr/lib/libSystem.tbd
  ...完整 SDK 其餘內容...
```

App 已啟用檔案共享。SDK 版本讀自 `SDKSettings.plist` 的 `Version`，不是硬編碼。後端會先檢查代表性 SDK／Clang header，再讀可用的 SDKSettings 版本、device platform、arm64 與部署範圍，辨識 libSystem.tbd 的 target 列表，以及鄰近 manifest 的 LLVM／builtin-header 版本及固定目標。可辨識且互相衝突的證據會拒絕；缺資料或無法辨識的格式明示 Unverified，不當作已確認相容。包含 arm64 及 arm64e 的多架構 SDK 可用，只有 arm64e 或 simulator 的已知切片不可用；工具鏈建置用 SDK 與使用者 SDK 版本不同本身不判定為不相容，而標記配對未驗證。這不是完整 SDK 或已連入 compiler binary 的認證，實際缺檔仍由 Clang／LLD 診斷。SDK 不可加入 repo、App bundle、公開附件或建置日誌。

## 已驗證與仍須驗證

本輪本機 P0（未提交）Linux 的 **48 個核心測試全部通過**，驗證命令、檔案隔離、錯誤處理及 相容性預檢、配額與 Mach-O 邊界檢查，後端使用**刻意的測試替身**，不代表真實編譯器輸出。橋接 stub 的 host smoke 驗證 capability、診斷記憶體釋放及參數拒絕。真實 LLVM host smoke 與核心替身測試須分開記錄；Linux host 結果不能替代 iOS library cross-build 或真機測試。

另已通過真實 LLVM host smoke：使用 Ubuntu **18.1.3** 的 Clang／LLD 函式庫，在進程內產生真正的 arm64 Mach-O object 及 executable；覆蓋空格路徑、重複編譯／連結、語法與未定義符號錯誤後重試、診斷字串回傳、plugin／response-file 拒絕，以及四個並行呼叫者的序列化。此測試使用無 SDK 的 freestanding C，不執行生成的 iOS 產物，不代表使用真實 SDK 的 `stdio.h` 範例已通過。測試命令：

```bash
bash Packages/NativeCompilerBridge/scripts/embedded-host-smoke.sh
```

Swift adapter 已在 Linux 透過 C header importer 做型別檢查，並非完整 SwiftUI App 的 Apple 平台型別檢查。stub smoke 同時測試 macro 未定義及 `POCKETIDE_EMBEDDED_LLVM=0`，避免「旗標為 0 卻誤編真實分支」的錯誤。

本地成功原生 CI run **39303725941**（commit `6e0af8c33e7ab447fa2206acc3e8a82ddc084eaa`）已驗證固定 LLVM 18.1.8 iOS arm64 靜態庫、真實橋接 link-check、工具鏈資源 bundle staging，以及內嵌該橋接的未簽名 iOS App 在 Xcode 16.4 建置／連結成功。manifest 記錄 LLVM commit `3b5b5c1ec4a3095ab096dd780e84d7ab81f3d7ff`、target `arm64-apple-ios15.0`、SDK 18.5；binary verification 確認 75 個靜態庫的 1,963 個 object members 皆為 arm64/iOS 15.0 object，內嵌工具鏈 App 為 arm64/iOS 15.0 executable 且無 code-signature load command。這更新了先前「待完整 iOS 建置／連結」的說法：**建置及連結已由 CI 完成，並非尚未驗證**。完整 run／hash 及範圍見[證據矩陣](EVIDENCE.md)。

仍未驗證：

1. iPhone 7／iOS 15 的安裝／啟動、冷啟動、記憶體峰值、耗時、多次建置，以及語法／連結失敗後重試。
2. 使用使用者自備真實 SDK 在 iPhone 端編譯 `stdio.h` 範例、多檔符號解析與未簽名 Mach-O 連結。

GitHub Actions 的執行狀態應以該 commit 的實際 run 為準；新增工作流程本身不等於原生建置已通過。本地已稽核的成功 run 39303725941 有成功建置目錄及 artifacts；不得將它推廣成其他 commit 或實機測試的證明。

## 使用限制

目前不附帶 compiler-rt builtins、sanitizer 或其他額外 runtime；需要這些 runtime 的 C 程式可能在連結時回報未定義符號，不在首輪支援範圍。一般 `libSystem` 函式需由使用者 SDK 提供。

僅支援目前工作區模型中的 `.c` 檔；不新增 C++、Objective-C、header 編輯、混合 Swift/C 或 SwiftPM 相依解析。初始上限為 32 檔、2 MiB 原始碼。編譯後可以繼續編輯，但目前沒有取消進行中 LLVM 呼叫的 UI；Swift task 的取消只在呼叫之間檢查。

本輪本機 P0 已實作邊界（不是上述歷史 CI 的測試結論）：preflight 對已知不相容條件拒絕、未知條件明示未知；Mach-O 需要 arm64 subtype 0（非 arm64e）、預期 object／executable filetype、完整 load-command envelope／總數、segment／section 與 symtab bounds；要求 iOS 15.0 platform 2 或 legacy `IPHONEOS`，拒絕 `LC_CODE_SIGNATURE`。這不是完整 dyld loader；未知 commands 僅查 envelope。每份 UTF-8 log 限 64 KiB，截斷會有 marker；只管理自有 UUID build dirs，最多 10 份／64 MiB，超限當次拒絕並清理，舊紀錄 oldest-first 清理，非 UUID／外部檔不刪；不保證 native 執行期間瞬間磁碟峰值。拒絕 Builds 本身 symlink、以 canonical path 檢查 SDK/resources overlap、拒絕產物 symlink 逃逸；父級 OS path alias 可解析。**這不是不受信任程式碼的安全沙箱。** 編譯器與 App 共用進程及 App 可見檔案；惡意巨量宏、編譯器漏洞或記憶體耗盡可能導致整個 App 終止。上述檢查及有限 logs/history 不是 crash/OOM 隔離；檔案／空間限制不是 CPU／記憶體上限。正式推出前必須實機實測並評估風險。
