# GingerVM 連續 guest trace v0.6.7

> 這是仍在開發中的 Android guest 啟動原型，不是已完成開機的虛擬機。它在未 root 的 Android ARM64 主機上，以 native ARM64 supervisor 追蹤官方 Google Android 2.3.7/API 10 ARM32 `/init` 與同一程序樹；不使用逐指令 CPU 模擬，也不呼叫 host root、mount、netlink 或 Binder。

## 真機證據：property socket 是下一個阻塞點

使用者提供的 v0.6.6 Android 12 trace 證明 PID 1 已越過 coldboot wait；`/dev/__properties__` 的 app-private `ftruncate(fd=4, length=32768)` 成功；四個 guest VFS symlink 與虛擬 mount 操作也成功。之後 PID 1 對 ARM syscall 281 呼叫 `socket(domain=1, type=1, protocol=0)`，即 `AF_UNIX/SOCK_STREAM`，broker 回傳 `-97 (EAFNOSUPPORT)`，PID 1 以 code 1 退出。`ueventd` 繼續等待，最後由 supervisor timeout 收束，`tracked=1 reaped=1 unresolved=0`。沒有進入 guest linker、Zygote、Framework 或桌面。

這是實際 trace 確認的阻塞，不是由 `poll` 次數推測。v0.6.4 已先確認 ftruncate 與 syscall 83 symlink 問題；v0.6.6 日誌顯示這些步驟已通過，下一個明確失敗點才是 AF_UNIX socket。

## API 10 原始程式的要求

實作依據是官方 [`android-2.3.7_r1` `init/util.c`](https://android.googlesource.com/platform/system/core/+/android-2.3.7_r1/init/util.c)、[`init/property_service.c`](https://android.googlesource.com/platform/system/core/+/android-2.3.7_r1/init/property_service.c)、[`init/init.c`](https://android.googlesource.com/platform/system/core/+/android-2.3.7_r1/init/init.c) 與 [`init/signal_handler.c`](https://android.googlesource.com/platform/system/core/+/android-2.3.7_r1/init/signal_handler.c)：

- property service 使用 guest 路徑 `/dev/socket/property_service`，建立 `AF_UNIX/SOCK_STREAM` listener，設定 `FD_CLOEXEC`、`O_NONBLOCK`，並以 backlog 8 執行 listen。
- init event loop 將 listener 加入 poll；連線到來後 accept、讀取 `SO_PEERCRED`、接收 `prop_msg` 並關閉已接受的 fd。
- signal handler 建立另一組 `AF_UNIX/SOCK_STREAM` socketpair，設定 `FD_CLOEXEC` 和 `O_NONBLOCK`，由 `SIGCHLD` handler 寫入通知，再由 init 從另一端讀取。

## v0.6.7 的軟體 socket broker

支援的 socket/file descriptor 是 supervisor 內的固定大小記憶體表與 byte queue，不是 host socket。property pathname 只在 guest root 的 app-private backing 建立一般檔案標記，讓 guest VFS 保有路徑狀態；該標記不是 kernel socket。bind 限定 PID 1 及精確路徑 `/dev/socket/property_service`。connect、listen、accept、send/recv、`SO_PEERCRED`、close、fcntl、read/write 和 poll 都由軟體表處理；socketpair 僅為 init 的 SIGCHLD byte queue。poll 只在軟體佇列實際有資料或待處理連線時回報可讀，不合成裝置事件。

只允許已實作的 ARM direct-socket syscall 和 socketcall 子操作；未實作的 sendto/recvfrom/shutdown、未知 op、其他地址、domain、type 或 option 都 fail-closed，不會落到 host socket API。fd ownership 按 guest descriptor table 管理，fork/clone 依 `CLONE_FILES` 繼承，exec 套用 `FD_CLOEXEC`，程序退出時回收不再引用的 fd。API 10 的 `rt_sigaction` 只轉交 ARM compat kernel，以便 guest SIGCHLD handler 正常運行；這不需要 host 特權。

Guest socket pathname 的 marker 操作會解析並驗證 app-private guest root，固定已驗證的父目錄，再使用 `openat(..., O_NOFOLLOW)` 建立檔案；symlink 或路徑穿越不能把操作導向 guest root 以外。沒有建立或呼叫 host AF_UNIX socket，也沒有 host mount、netlink 或 Binder。

## 驗證狀態與下一步

新增 host 回歸覆蓋 property listener/connect/send/accept/peer credentials/recv/close/poll、signal socketpair、socketcall 允許清單、未知 socket operation 拒絕、pathname containment，以及既有 SIGSYS、ftruncate、symlink、tracee cleanup、日誌擷取和完整 API10 payload 測試。完整回歸命令：`bash tests/run_init_broker_regression.sh`；APK 建置與封裝檢查：`bash build-native.sh`。通過 host 測試只代表這些軟體模型和封裝檢查符合預期，不代表 Android guest 已在真機啟動。

v0.6.7 尚待 Android 12 真機 trace 驗證 property-service socket lifecycle；下一個證據應是 socket/bind/listen 成功，以及 PID 1 是否繼續到新的、可由 syscall args 和原始 API 10 程式碼確認的步驟。不得把 syscall broker 成功、linker entry 或 coldboot 放行稱為 Zygote、Framework、桌面或完整 Android boot。
