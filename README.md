# Pocket IDE

獨立建立的 iPhone IDE，最低目標為 **iOS 15.0、arm64（包含 iPhone 7）**。不是 XForge 的 fork，沒有複製其程式碼；只參考其「編譯器作為函式庫在 App 進程內呼叫」的技術方向。

## 現在做到甚麼

SwiftUI 編輯器支援 C／Swift 範例、檔案分頁及本機工作區儲存。`IDECore` 提供模型、檔名驗證、命令規劃，以及新增的 C 建置後端：逐檔編譯、一次連結、診斷捕捉、獨立建置目錄、失敗清理與 arm64 Mach-O 基本檢查。成功時保留 `PocketIDE.out` 和 `build.log`；不執行產物。

App 的 Build 現在接到可選的 **Clang／LLD C ABI 橋接**，不是 shell、遠端編譯或桌面子行程。橋接預設使用不可用的 stub；只有實際連入 LLVM 靜態庫並提供本機 SDK／Clang 資源時，才會嘗試編譯。缺少工具鏈或資源會回報原因，不偽造成功。Swift frontend 留待下一階段，Swift 建置仍明確拒絕。

**iOS 工具鏈與完整 App 已在 GitHub Actions 的 macOS／Xcode 工作中建置及連結成功；這仍不是已在 iPhone 7 驗證的編譯器發布物。** 該 CI 沒有安裝或執行 App／編譯器於實機。沒有簽名、安裝、JIT、執行使用者程式或上傳原始碼功能，也不下載或附帶 Apple SDK。

## 在 Mac 開啟

使用 **Xcode 16.4**；Apple 的[版本表](https://developer.apple.com/xcode/system-requirements/)列明此版支援 iOS 15 部署。不要未經檢查便改用提高最低部署版本的新工具鏈。

```bash
export DEVELOPER_DIR=/Applications/Xcode_16.4.app/Contents/Developer
export RUNNER_TEMP="${TMPDIR:-/tmp}/pocketide-tools"
bash scripts/bootstrap-xcodegen.sh
bash scripts/prepare-toolchain-resources.sh
"$RUNNER_TEMP/xcodegen-bin/xcodegen" generate --spec project.yml
open PocketIDE.xcodeproj
```

預設可建置不含 LLVM 的編輯器／stub。XcodeGen 固定版本 2.44.1 的來源 commit；其相依套件尚非位元級可重現。產生的 `.xcodeproj` 不提交。Bundle ID `dev.pocketide.app` 是暫定識別。

### 啟用裝置端 C 編譯

參閱 [裝置端 C 整合說明](docs/ON_DEVICE_C.md)。Mac 上的 `scripts/build-native-toolchain.sh` 固定 LLVM 18.1.8，先建 host TableGen，再 cross-build iOS 15 arm64 的 Clang／Mach-O LLD 靜態庫，最後編譯及連結真實橋接。成功後才啟用裝置設定。模擬器保持 stub，不會拿裝置函式庫來連結。

使用者須自行提供合法可用的 SDK 到 `Documents/PocketIDE/Toolchain/iPhoneOS.sdk`，並保留 `SDKSettings.plist`。App 的 Files 容器已啟用檔案共享；原始碼及產物都留在 App 的本機容器。SDK 的取得與授權不由此專案代辦。

工作區手動 Save 到 `Documents/PocketIDE/workspace.json`；切換範例或 Load 會替換當前內容，請先 Save。沒有自動儲存或自動還原。

### 受限 C 工作區匯入（本機 P1，未提交）

選單新增 **Import C workspace JSON…**，透過 iOS 檔案選擇器讀取 `pocketide.c-workspace.v1` 格式的單一 UTF-8 JSON。只支援平面 `.c` 檔，最多 32 檔；JSON 整體與解析後原始碼 UTF-8 合計各限 2 MiB。完整驗證後須確認才替換編輯器，不自動 Save 或 Build。未知欄位、重複 JSON key／檔名、不安全路徑、來源或上層目錄的符號連結、非普通檔案與錯誤格式都拒絕；失敗不替換現有工作區或儲存檔。格式範例與限制見 [C 工作區匯入](docs/C_WORKSPACE_IMPORT.md)。這不是一般 `.xcodeproj`／Swift 匯入，不執行腳本或解析相依。

## 測試

```bash
swift test --package-path Packages/IDECore
swift build --package-path Packages/NativeCompilerBridge
bash Packages/NativeCompilerBridge/scripts/host-smoke.sh
bash scripts/host-smoke.sh  # 僅 macOS，測試宿主編譯器，不是手機內工具鏈
```

核心後端測試使用明確的測試替身，覆蓋 compile/link 次序、多檔、重複建置、SDK 缺失、失敗診斷、產物缺失和危險檔名；它們不證明真實 Clang 或 iPhone 可用。真實橋接測試與 iOS 實機測試須分開看，詳見整合說明。

本輪本機 P0（未提交）Linux 驗證：48 個 IDECore 測試通過、Swift adapter 型別檢查通過、stub macro 未定義／設為 0 均通過。使用 Ubuntu LLVM 18.1.3 的真實橋接 host smoke 通過編譯／連結、錯誤恢復及並行呼叫；這不是固定 18.1.8 的 iOS 工具鏈驗證。可用 `bash Packages/NativeCompilerBridge/scripts/embedded-host-smoke.sh` 在安裝對應 LLVM 開發套件的 Linux 重跑。

## GitHub Actions

倉庫：<https://github.com/yongshuai1013/PocketIDE>。既有 CI 使用 `macos-15`、固定 Xcode 16.4，執行核心測試、原生橋接 stub、宿主 C／Swift 煙霧測試、模擬器及裝置 arm64 未簽名 App 建置，再檢查最低版本、架構及無簽名狀態。第三方 Actions 固定 commit，token 僅 contents read。

產物 ZIP 是**未簽名 `.app`，不是可安裝 IPA**，保存 7 天；不自動發布 Release。一般 CI 不建大型 LLVM 工具鏈，因此通過一般 CI 不代表內嵌編譯器已驗證。

新增的 [原生工具鏈 Actions](.github/workflows/native-toolchain.yml) 可手動執行，亦會在 `main` 的工具鏈配方、橋接或相關建置設定變更時執行。它以 Xcode 16.4 建置固定 LLVM 18.1.8、iOS 15 arm64 靜態庫及真實橋接，再產生專案並連結內嵌 Clang／LLD 的未簽名 App。成功後上傳工具鏈壓縮包、未簽名 App 及 SHA-256；失敗亦上傳建置診斷，保存 7 天。不含 Apple SDK、不簽名、不執行裝置產物，也不代表 iPhone 7 實機驗證已完成。大型 LLVM 建置設有 330 分鐘工作上限。

### 可稽核的原生 CI 證據

本地稽核副本記錄原生 workflow run **39303725941**（`success`，`main`，commit `6e0af8c33e7ab447fa2206acc3e8a82ddc084eaa`，標題「Fix Apple lipo argument order in native architecture checks」）。該 commit 固定 LLVM **18.1.8**、上游 commit `3b5b5c1ec4a3095ab096dd780e84d7ab81f3d7ff`；工具鏈 manifest 記錄目標 `arm64-apple-ios15.0`、Xcode 16.4、iOS SDK 18.5。CI 的原生 link-check、工具鏈 bundle／resource staging，以及內嵌真實橋接的 device-target App 建置均成功；binary verification 掃描 75 個靜態庫中的 1,963 個 object member，均為 arm64 Mach-O object、iOS 最低版本 15.0；內嵌工具鏈 App 為 arm64 Mach-O executable、iOS 15.0、無 code-signature load command。產物雜湊與驗證細節見[證據矩陣](docs/EVIDENCE.md)。

證據層級不可混為一談：IDECore 測試使用 test doubles；Ubuntu LLVM 18.1.3 是真實 **host** smoke，不是 iOS 產物；run 39303725941 才證明固定 LLVM 18.1.8 iOS 靜態庫、真實橋接和未簽名 App 在 Xcode CI 建置／連結成功。這些都不證明已安裝、啟動或在 iPhone 7／iOS 15 上運行，亦不證明使用者提供 SDK 的端上 C build 流程。

## 邊界與下一步

既有 run 已完成 Mac 上的 iOS 靜態工具鏈、完整 App 連結及資源配置驗證；本次 P0 修改尚未在 Apple 平台重建。下一步仍須在 iPhone 7／iOS 15 測量記憶體尖峰、編譯時間、冷啟動及多次建置穩定性。之後才處理 Swift frontend 與其配對版本、標準庫和 SDK 模組。

首版僅接受同語言工作區，C 後端限制 32 檔／2 MiB 原始碼；不是完整資源隔離機制。P0 邊界：preflight 對已知不相容明確拒絕、未知則明示未知；Mach-O 檢查要求 arm64 subtype 0（非 arm64e）、object／executable 類型、load-command 範圍與結構邊界、iOS 15.0 platform／legacy `IPHONEOS`，拒絕 `LC_CODE_SIGNATURE`。未知 load commands 只做 envelope 檢查，這不是完整 loader 驗證。logs 每份 UTF-8 上限 64 KiB、超限標記截斷；僅管理自有 UUID build dirs，最多 10 份／合計 64 MiB，當次超限拒絕並清理，舊紀錄 oldest-first 移除，不刪非 UUID／外部檔。這些限制及路徑檢查不是 crash/OOM 沙箱，也不保證 native 執行中瞬間磁碟峰值；內嵌編譯器與編輯器共用進程，原生崩潰或記憶體耗盡仍可能讓 App 終止，不適合不受信任原始碼。沒有 C／Swift 混合工程、LSP、一般專案轉換、標頭檔編輯或完整 Xcode 建置系統；僅新增上述版本化 C JSON 匯入。詳見[證據矩陣](docs/EVIDENCE.md)。

[Swift 官方平台說明](https://www.swift.org/platform-support/)將 iOS 列為部署平台，不是官方編譯器宿主。App Store 分發另須檢視 [Apple 2.5.2](https://developer.apple.com/app-store/review/guidelines/#software-requirements)。可編譯不代表可簽名、可安裝或可執行。

## 專案結構

```text
App/                         iOS 15 SwiftUI 編輯器與 C ABI Swift adapter
Packages/IDECore/             模型、儲存、建置規劃與 C 後端
Packages/NativeCompilerBridge/ 原創 Clang/LLD C ABI 橋接與 host 測試
toolchain/                   預設關閉的 xcconfig、來源版本模板
scripts/                     XcodeGen、工具鏈建置及產物檢查
docs/ON_DEVICE_C.md           接入方式與驗證限制
project.yml                  XcodeGen 專案來源
.github/workflows/ci.yml      未簽名 App CI
.github/workflows/native-toolchain.yml  LLVM 18.1.8 原生工具鏈及 App 連結驗證
```
