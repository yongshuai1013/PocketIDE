# 受限的 C 工作區匯入

在工作區選單選 **Import C workspace JSON…**，用 iOS 的檔案選擇器挑選一個 `.json` 檔。完整驗證成功後，App 會要求確認才替換編輯器內容；確認前請先 Save 想保留的編輯。匯入不會自動儲存、建置或執行任何內容。失敗或取消不會替換目前工作區，也不會改寫 `Documents/PocketIDE/workspace.json`。

## 支援的格式

這是 Pocket IDE 自訂的版本化、UTF-8 JSON 格式，不是既有 Save 產生的內部 Workspace JSON，也不是 Xcode 專案轉換。以下內容可存成 `hello.json`：

```json
{
  "format": "pocketide.c-workspace.v1",
  "name": "Hello C",
  "files": [
    {
      "name": "main.c",
      "contents": "int main(void) { return 0; }\n"
    }
  ]
}
```

頂層只能有 `format`、`name`、`files`，每筆檔案只能有 `name`、`contents`；以上欄位全部必填，字串與陣列型別不得互換。版本值必須完全相同。重複 JSON key（包括以 Unicode escape 改寫的相同 key）、未知欄位、非 UTF-8、無效 JSON 或尾隨資料都會拒絕。匯入會產生新的檔案 ID，不接受外部 ID、language、編譯參數或路徑引用。

## 檔案與大小限制

- **1–32 個檔案**，全部必須是平面檔名的 `.c` 原始碼；副檔名必須小寫。
- **JSON 檔案本身最多 2 MiB（2,097,152 bytes）**，並且解析後原始碼 UTF-8 合計也不得超過 2 MiB。JSON 欄位和跳脫字元會佔空間，因此實際可裝入的原始碼略少；不是 2 MiB 原始碼外另加不限量包裝。
- 檔名限 ASCII，首字元為英文字母、數字或 `_`，其餘只能是英文字母、數字、`_`、`.`、`-`，最多 128 bytes。大小寫不同的同名檔案亦視為重複。
- 工作區名稱限 ASCII，首字元為英文字母、數字或 `_`，其餘只能是英文字母、數字、空格、`_`、`.`、`-`，最多 64 bytes，不能以空格或 `.` 結尾。
- 原始碼可以是 Unicode，但不能包含 NUL。副檔名與內容驗證不會證明它是可編譯或安全的 C。

## 路徑與原子性

來源只接受本機、普通 `.json` 檔案，不接受資料夾、封裝、ZIP、FIFO、裝置節點或符號連結。來源檔與所有上層目錄都不得是符號連結；因此即使連結指向安全位置也會拒絕。若檔案提供者給出的路徑包含系統別名或符號連結，請先透過 Files 將普通檔案複製到不含連結的本機位置，再選取；App 不會自行跟隨或解析連結。

IDECore 由根目錄開始逐層以 `openat`／`O_NOFOLLOW` 開啟目錄，再以不跟隨連結且不阻塞 FIFO 的方式開啟檔案；只從檔案描述符讀取最多上限加 1 byte，避免先檢查路徑、後跟隨被替換的連結。檔名不接受 `/`、`\`、絕對路徑、`..` 路徑元件、百分比路徑編碼或控制字元。JSON 只內嵌文字，沒有引用檔案、解壓或將來源寫入外部位置的功能。

匯入器是唯讀的：整份輸入通過所有檢查後才傳回新的 Workspace；錯誤時沒有部分匯入或持久化副作用。UI 用 security-scoped resource 與 `NSFileCoordinator` 讀取檔案，在確認後一次替換記憶體內工作區。之後按 Save 才會沿用既有儲存流程。

## 明確不支援

沒有一般 `.xcodeproj` 轉換、Swift／混合語言、標頭檔編輯、巢狀目錄、外部相依解析、build phases、Makefile、shell／匯入腳本或自訂編譯旗標。匯入不會呼叫編譯器。手動按 Build 才會沿用既有 C 後端與其限制；本功能不是不受信任原始碼的安全執行沙箱，也沒有 CPU／記憶體隔離。

最低部署目標仍為 iOS 15。這輪可在 Linux 驗證 IDECore 解析、大小與檔數邊界、唯讀失敗原子性、檔案型別與符號連結拒絕；Linux 不能驗證 SwiftUI／UniformTypeIdentifiers／NSFileCoordinator 的 iOS 型別檢查、檔案提供者互動或確認視窗行為，這些仍需 Apple 平台建置與介面測試。沒有簽名、安裝、裝置操作或 Apple SDK 打包。

本輪以 Linux Swift 6.0.3／Swift 5 language mode 執行 `swift test --package-path Packages/IDECore`：**83 個測試全部通過，其中 22 個為新增匯入測試**。`swiftc -frontend -parse App/EditorView.swift` 語法解析與 `git diff --check` 亦通過；語法解析不是 Apple 平台 UI 型別檢查。既有 61 個測試仍全數通過。沒有觸發 CI 或執行裝置操作。
