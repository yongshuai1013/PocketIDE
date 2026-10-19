# Pocket IDE

我們自己的 iPhone IDE，暫名 **Pocket IDE**。最低目標為 **iOS 15.0、arm64（包含 iPhone 7）**。這是獨立建立的第一階段專案，不是 XForge 的 fork，也沒有複製其程式碼。

## 這一版做到甚麼

- SwiftUI 原始碼編輯器，可切換 C／Swift 範例，支援檔案分頁與本機 JSON 工作區儲存／載入。
- 獨立 `IDECore` Swift 套件：資料模型、原子儲存、檔名驗證、C／Swift 建置命令規劃與單元測試。
- C 分檔編譯；Swift 全部來源一起交給 driver，避免逐檔編譯破壞跨檔符號。
- GitHub Actions：核心測試、macOS 宿主 C／Swift 煙霧測試、模擬器建置與裝置 arm64 未簽名 App 建置、最低版本／架構／無簽名檢查、產物及日誌上傳。

**尚未內建可工作的 C／Swift 編譯器。** App 的 Build 會明確回報工具鏈不可用，不會偽造成功。命令規劃包含 SDK 路徑佔位符，不能直接當作可執行工具鏈。沒有簽名、安裝、JIT、執行使用者程式或遠端上傳程式碼功能。首版只接受同語言 workspace；尚不支援 Swift/C 混合工程或完整 IDE 功能，例如語法高亮、LSP、專案匯入與檔案新增。

## 在 Mac 開啟

使用 **Xcode 16.4**，而不是自動追蹤最新 Swift。Apple 的[版本表](https://developer.apple.com/xcode/system-requirements/)列明此版支援 iOS 15 部署；最新 Swift 的最低版本不能直接套用到這個專案。

```bash
export DEVELOPER_DIR=/Applications/Xcode_16.4.app/Contents/Developer
export RUNNER_TEMP="${TMPDIR:-/tmp}/pocketide-tools"
bash scripts/bootstrap-xcodegen.sh
"$RUNNER_TEMP/xcodegen-bin/xcodegen" generate --spec project.yml
open PocketIDE.xcodeproj
```

XcodeGen 固定到 2.44.1 的 commit；它的 Swift Package 相依版本由上游版本解析決定，尚非完全離線／位元級可重現建置。`PocketIDE.xcodeproj` 由 `project.yml` 產生，不提交產生物。Bundle ID `dev.pocketide.app` 只是暫定識別，不代表已註冊。

```bash
swift test --package-path Packages/IDECore --parallel
bash scripts/host-smoke.sh  # 僅 macOS，測試的是宿主編譯器
```

工作區手動 Save 到 `Documents/PocketIDE/workspace.json`；切換範例或 Load 會替換當前編輯內容，請先 Save。這一版不自動還原或自動儲存。

## GitHub Actions

將專案放到使用者指定的新倉庫，主分支使用 `main`。`.github/workflows/ci.yml` 支援 `push`（main）、PR 和手動 `workflow_dispatch`。不需要憑證、Apple 帳戶、Developer Team 或額外 secrets。

CI 使用 `macos-15`，明確選取 `/Applications/Xcode_16.4.app`。若 Runner 未來移除此版本，流程會失敗並提示，不會默默改用提高最低 iOS 版本的新編譯器。可用版本參考 [Runner 官方清單](https://github.com/actions/runner-images/blob/main/images/macos/macos-15-Readme.md)。第三方 Actions 已固定 commit，Token 只有 contents read，PR 不使用 `pull_request_target` 或部署權限。

成功後可取得 `PocketIDE-unsigned-ios15-arm64` 產物及建置日誌，保存 7 天。ZIP 裡是**未簽名 `.app`，不是可安裝 IPA**。沒有自動發布 Release。

模擬器步驟只建置、不執行 UI 測試；arm64 建置不等於 iPhone 7 真機驗證。新版模擬器不能證明舊裝置的記憶體、效能或 API 行為。CI 中的 C／Swift 編譯測試只驗證 Mac 上的編譯器，不代表手機內的工具鏈已完成。

## 下一階段：真正的內建編譯器

1. 固定可移植的 LLVM／Swift 配對版本與來源 SHA，先驗證 iOS 15 arm64 的編譯器庫和依賴能建置，再建立 app 內 C ABI 橋接；不能用 iOS 上不存在的一般桌面子行程模型。
2. 接入 Clang，處理 SDK/sysroot、資源目錄、標頭、連結庫、診斷輸出和連續多次呼叫的全域狀態問題，完成 C compile/link 真實測試。
3. 接入 Swift frontend／driver，確認多檔同模組與標準庫、SDK 模組相容性；完成 Swift compile/link 真實測試，而非只有產生 object。
4. 為工具鏈及 SDK 加入來源、授權與散布審查，再決定以何種方式隨 App 提供。這版沒有下載或重新散布 Apple SDK。
5. 在 iPhone 7／iOS 15 驗證記憶體尖峰、冷啟動、編譯時間及輸出；執行或安裝產物仍屬獨立議題，不因完成編譯而自動成立。

[Swift 官方平台說明](https://www.swift.org/platform-support/)把 iOS 列為部署平台，不是官方編譯器宿主；因此內建 Swift 工具鏈是一項移植工作。App Store 分發亦須另行檢視 [Apple 2.5.2](https://developer.apple.com/app-store/review/guidelines/#software-requirements)，教育程式碼例外不等於自動獲准執行任意原生程式。

## 專案結構

```text
App/                         iOS 15 SwiftUI 編輯器
Packages/IDECore/             可跨平台測試的模型、儲存及建置規劃
project.yml                  XcodeGen 專案來源
.github/workflows/ci.yml      GitHub Actions
scripts/                     產生器安裝、宿主煙霧測試、產物驗證
```

## 已驗證與未驗證

在 Linux 以官方 Swift 6.0.3 編譯並執行 IDECore 的 **16 個 XCTest，全部通過**；Actions 已通過 actionlint 1.7.7，shell 腳本通過 bash 語法檢查，`project.yml` 已通過 YAML 與最低目標設定檢查。這些不是 iOS 編譯器測試。

目前沒有 macOS／Xcode 建置結果、GitHub Actions 執行結果或 iPhone 7 實機結果。SwiftUI 介面的 Apple 平台型別檢查、XcodeGen 專案產生及未簽名 App 產物，必須在第一次 Mac／CI 建置時驗證。

目前沒有連接 GitHub remote；倉庫名稱、擁有者與公開／私人可見性尚待指定。現有其他倉庫的憑證不會被挪用到本專案。
