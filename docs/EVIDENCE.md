# PocketIDE P0 證據矩陣

本頁只記錄 `/workspace/pocketide-artifact-audit` 中已保存的本地稽核證據。它證明到什麼程度便止於何處；workflow 成功不等於實機運行成功。

## 成功 workflow 與來源版本

| 項目 | 證據與結論 |
|---|---|
| 原生工具鏈 workflow | run **[39303725941](https://github.com/yongshuai1013/PocketIDE/actions/runs/39303725941)**，`completed / success`，`main`，run attempt 1；commit `6e0af8c33e7ab447fa2206acc3e8a82ddc084eaa`（「Fix Apple lipo argument order in native architecture checks」）。資料來源：`run-39303725941.json`。 |
| LLVM 來源 | LLVM **18.1.8**，commit `3b5b5c1ec4a3095ab096dd780e84d7ab81f3d7ff`。來源：工具鏈 `manifest.txt`。 |
| 目標環境 | `arm64-apple-ios15.0`，Xcode **16.4**、iOS SDK **18.5**；manifest 註明 `SWIFT_FRONTEND=0`。 |
| 建置結果 | 原生 toolchain build、真實 C ABI bridge／強制靜態庫載入的 iOS link check、bundle 資源 stage 及真實橋接編入的 device-target 未簽名 App 均有成功證據。`link-check.txt` 顯示 Mach-O `LC_BUILD_VERSION` platform IOS、minos 15.0、SDK 18.5；`app.log` 結尾為 `Clang/LLD iOS link-check passed` 並明言未測裝置執行。Xcode device build log 指向 `iphoneos`、`ARCHS=arm64`、deployment target 15.0 且 `CODE_SIGNING_ALLOWED=NO`；artifact 含內嵌 Toolchain。 |
| 產物 SHA-256 | `native-artifacts.sha256`：`fde0d5cb8593d12444dd88d7aea0a4adbf1cbb1d3ec094010421684bebd9c499`（`PocketIDE-LLVM-18.1.8-ios15-arm64.tar.gz`）；`3975e6ce62bbea835080cfcea47eece5788fd79bbfa9f9920a39133eef546775`（`PocketIDE-native-unsigned-app.zip`）。這是已稽核 artifact 的雜湊，不代表簽章或安裝驗證。 |

## Binary verification

`binary-verification.json` 由稽核腳本 `verify_binaries.py` 從保存的工具鏈與 App 二進位解析得到：75 個靜態庫，合計 1,963 個 object member。所有 member 的 Mach-O CPU 為 arm64（`0x100000c`）、filetype 為 MH_OBJECT、build-version platform 為 iOS（2）、最低版本 15.0，且沒有 code-signature load command。帶真實內嵌工具鏈的 App 執行檔為 arm64 MH_EXECUTE，iOS minos 15.0，無 code-signature load command；稽核腳本亦逐一比對 App bundle `Toolchain` 資源與工具鏈來源，檢查不一致項。這些結構檢查和 Xcode link 成功不是完整 Mach-O loader 模擬、App 安裝或實機相容性證明。

## 測試與驗證層級（不可互相替代）

| 層級 | 本地可確認項目 | 不代表 |
|---|---|---|
| IDECore 核心測試 | 歷史基線 29 個；本輪未提交 P0 為 48 個全部通過，後端使用明確 test doubles，另測試預檢、配額與畸形 Mach-O／路徑邊界。 | 不是真實 Clang／LLD 執行，也不是 iPhone 測試。 |
| Host smoke | Ubuntu LLVM 18.1.3 的真實 host bridge smoke：編譯／連結、錯誤恢復、重複及並行呼叫等。 | 不是固定 LLVM 18.1.8 的 iOS build；不使用真實 iPhoneOS SDK，也不在手機執行產物。 |
| iOS toolchain／App CI | run 39303725941 證明 Xcode 16.4 CI 成功 cross-build 固定 LLVM 18.1.8 iOS arm64 靜態庫、連結真實橋接與完整未簽名 device-target App，並 stage 工具鏈資源。 | 不證明透過使用者 SDK 編譯 C 程式已在 iOS 運行；不證明簽名、安裝或啟動。 |
| iPhone 7 實機 | **尚未驗證** iPhone 7／iOS 15 上冷啟動、端上 C 編譯、記憶體峰值、耗時、多次建置及失敗重試。 | CI／host 結果不可代替實機測試。 |

一般 CI（stub、模擬器及未簽名 device build）與此原生工具鏈 run 亦須區分。一般 CI 的成功本身不證明真實 LLVM 靜態庫已編入；原生 run 才提供該項證據。

## 本輪本機 P0 邊界（已實作，尚非以上 CI 所測功能）

- **Preflight 相容性**：對已知不相容情況明確拒絕；無法判定時明示未知，不把未知標成相容或成功。
- **Mach-O 輸入／輸出檢查**：要求 arm64 且 subtype 0（不接受 arm64e）、MH_OBJECT／MH_EXECUTE 對應檔案類型、完整 load-command 範圍與總數、segment／section 及 symbol table 邊界檢查；要求明確 iOS 15.0 platform 2 或 legacy `IPHONEOS`，拒絕 `LC_CODE_SIGNATURE`。這不是完整 dyld/loader 驗證；未知 load commands 只做 envelope 檢查，不宣稱語義相容。本機 Linux 測試已覆蓋這些檢查，但上述歷史 run 未驗證新實作。
- **有限 logs/history**：每份 UTF-8 log 上限 64 KiB，截斷時附 marker；只管理自有 UUID build directory，最多 10 份且合計 64 MiB。當次超限拒絕並清理；舊自有紀錄 oldest-first 清理；非 UUID／外部檔不刪。這些是本輪本機策略，不是既有 run 證據；不保證 native 執行中瞬間磁碟峰值。
- **路徑／資源邊界**：拒絕 Builds 本身為 symlink；以 canonical path 檢查 SDK／resources overlap，拒絕產物 symlink 逃逸；可解析父級 OS 路徑 alias。此處不宣稱為完整 OS 沙箱。
- **故障隔離**：App 與內嵌 native compiler 共用 process；logs/history、檔案／空間限制及上述檢查均非 crash/OOM 沙箱。原生崩潰或記憶體耗盡仍可終止 App。

## 本輪本機驗證

本次沒有 commit、push 或觸發 workflow。Linux Swift 6.0.3（Swift 5 語言模式）通過 48 個 IDECore 測試、NativeCompilerBridge stub 套件建置及 Swift adapter 型別檢查；stub smoke（macro 未定義／0）、Ubuntu LLVM 18.1.3 真實 bridge host smoke、資源準備腳本測試及所有 shell scripts 的語法檢查均通過。新 Mach-O validator 另接受本機 LLVM 18.1.3 產生的 freestanding arm64 iOS 15 object／未簽名 executable，以及保存的原生 CI App；只讀取結構，沒有執行任何 iOS 產物，也沒有使用或下載 Apple SDK。

本輪修改沒有在 macOS／Xcode 重建；新增 bundle manifest 複製、完整 SwiftUI App 建置、Apple SDK 實際格式及 iPhone 7 仍待 Apple 環境驗證。Preflight 依賴可讀中繼資料的宣告，不驗證完整 SDK、所有 builtin headers 的內容或已連入 compiler binary 的來源；無證據的項目保持 Unverified。TBD 只辨識常見 bracket-list YAML targets／legacy archs 格式，不是完整 YAML parser。保留歷史的配額只涵蓋自有 UUID 目錄，不能替其他 App 檔案或原生呼叫執行中的瞬間磁碟／記憶體用量提供保證。

## 本地證據檔

稽核副本位置：`/workspace/pocketide-artifact-audit/`。主要來源為 `run-39303725941.json`、`binary-verification.json`、`verify_binaries.py`、工具鏈 `manifest.txt`、`native-artifacts.sha256`、`native-toolchain-build-logs/link-check.txt`、`native-toolchain-build-logs/app.log`、`xcode-build-logs/device.log` 與 `xcode-build-logs/simulator.log`。證據為本地保存的 run／artifact 副本；並未在本次任務重新執行 workflow。
