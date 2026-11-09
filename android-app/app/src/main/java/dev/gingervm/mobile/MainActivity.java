package dev.gingervm.mobile;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.res.ColorStateList;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.os.Bundle;
import android.system.ErrnoException;
import android.system.Os;
import android.text.Html;
import android.text.method.LinkMovementMethod;
import android.view.Gravity;
import android.view.View;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.zip.GZIPInputStream;

public final class MainActivity extends Activity {
    private static final String ROOTFS_VERSION = "api10-arm-r5-gingerbread-2.3.7-3644351-init-db975b4d";
    private static final String[] INIT_STARTUP_FILES = {
            "init", "init.rc", "system/build.prop"
    };
    private static final int BG = Color.rgb(11, 18, 32);
    private static final int CARD = Color.rgb(22, 32, 51);
    private static final int TEXT = Color.rgb(239, 244, 252);
    private static final int MUTED = Color.rgb(164, 179, 202);
    private static final int GREEN = Color.rgb(165, 255, 96);

    private final ExecutorService executor = Executors.newSingleThreadExecutor();
    private TextView statusText;
    private TextView reportText;
    private Button launchButton;
    private Button runButton;
    private Button simulateButton;
    private boolean nativeLoaded;
    private String nativeLoadError = "";

    private native String nativeRunInit(String rootfsPath);
    private native String nativeRunInitSimulated(String rootfsPath);

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        getWindow().setStatusBarColor(BG);
        getWindow().setNavigationBarColor(BG);
        try {
            System.loadLibrary("gingervm_core");
            System.loadLibrary("gingervm_jni");
            nativeLoaded = true;
        } catch (Throwable error) {
            nativeLoadError = error.toString();
        }
        buildScreen();
    }

    private void buildScreen() {
        ScrollView scroll = new ScrollView(this);
        scroll.setFillViewport(true);
        scroll.setBackgroundColor(BG);

        LinearLayout page = new LinearLayout(this);
        page.setOrientation(LinearLayout.VERTICAL);
        page.setPadding(dp(22), dp(24), dp(22), dp(32));
        scroll.addView(page);

        TextView eyebrow = text("GINGERVM  /  ANDROID ARM LAB", 12, GREEN, true);
        page.addView(eyebrow);
        TextView title = text("Android 2.3.7\n手機測試版", 30, TEXT, true);
        LinearLayout.LayoutParams titleParams = params(-1, -2);
        titleParams.topMargin = dp(10);
        page.addView(title, titleParams);
        TextView subtitle = text("在手機 App 內執行 GingerVM 的 ARM guest init 測試。", 15, MUTED, false);
        LinearLayout.LayoutParams subtitleParams = params(-1, -2);
        subtitleParams.topMargin = dp(8);
        page.addView(subtitle, subtitleParams);

        LinearLayout stateCard = card(page);
        stateCard.addView(text("目前里程碑", 13, MUTED, true));
        TextView warning = text(
                "啟動按鈕會由 GingerVM ARM user-mode interpreter 執行真實 AOSP Gingerbread init。這是 userspace 測試，不是完整 Android 開機；目前不會啟動 Zygote、Dalvik、framework 或一般 APK。另一個按鈕可進行明確標示為 SIMULATED 的 property socket event 測試。",
                15, TEXT, false);
        LinearLayout.LayoutParams warningParams = params(-1, -2);
        warningParams.topMargin = dp(10);
        stateCard.addView(warning, warningParams);

        LinearLayout kernelBootCard = card(page);
        kernelBootCard.addView(text("完整 guest-kernel boot（未實作）", 13, MUTED, true));
        kernelBootCard.addView(text(
                "kernel、ramdisk 與 userdata 映像只會用於另一條完整 guest-kernel boot 路徑。該路徑目前尚未實作；本 App 的 init/user-mode 測試不載入也不需要這些映像。",
                14, TEXT, false));

        LinearLayout sourceCard = card(page);
        sourceCard.addView(text("系統映像來源", 13, MUTED, true));
        TextView source = text(
                "/system 來自 Google Android SDK 的 API 10、ARM EABI v7a default system image，revision 5。映像內 build.prop 標示 Android 2.3.7、generic/sdk/generic；已帶入 system/bin、system/app、system/lib、system/framework 等完整系統目錄。\n\ninit 與 init.rc 則依 AOSP android-2.3.7_r1 原始碼建置/取用。兩者是可追溯的測試材料，不代表完整 ROM 開機。",
                14, TEXT, false);
        LinearLayout.LayoutParams sourceParams = params(-1, -2);
        sourceParams.topMargin = dp(10);
        sourceCard.addView(source, sourceParams);

        LinearLayout simulatedCard = card(page);
        simulatedCard.addView(text("SIMULATED EVENT  /  模擬事件", 13, GREEN, true));
        TextView simulatedDescription = text(
                "按下專用按鈕才會注入一筆固定的 guest-local property-service SETPROP：debug.gingervm.simulated=1（虛擬 shell uid 2000）。它只用來喚醒並測試 AOSP init 的 poll／accept／訊息處理；不是 uevent、硬體偵測，也不會改動手機系統屬性。",
                14, TEXT, false);
        LinearLayout.LayoutParams simulatedParams = params(-1, -2);
        simulatedParams.topMargin = dp(9);
        simulatedCard.addView(simulatedDescription, simulatedParams);

        launchButton = new Button(this);
        launchButton.setText("執行 Android init／userspace 測試");
        launchButton.setTextColor(Color.rgb(18, 31, 15));
        launchButton.setTextSize(16);
        launchButton.setAllCaps(false);
        launchButton.setTypeface(Typeface.DEFAULT, Typeface.BOLD);
        launchButton.setBackgroundTintList(ColorStateList.valueOf(GREEN));
        LinearLayout.LayoutParams buttonParams = params(-1, dp(56));
        buttonParams.topMargin = dp(18);
        page.addView(launchButton, buttonParams);

        runButton = new Button(this);
        runButton.setText("執行 GingerVM init 基準測試");
        runButton.setTextColor(TEXT);
        runButton.setTextSize(15);
        runButton.setAllCaps(false);
        runButton.setTypeface(Typeface.DEFAULT, Typeface.BOLD);
        runButton.setBackgroundTintList(ColorStateList.valueOf(CARD));
        LinearLayout.LayoutParams testButtonParams = params(-1, dp(52));
        testButtonParams.topMargin = dp(8);
        page.addView(runButton, testButtonParams);

        simulateButton = new Button(this);
        simulateButton.setText("SIMULATED：注入 property socket event");
        simulateButton.setTextColor(TEXT);
        simulateButton.setTextSize(15);
        simulateButton.setAllCaps(false);
        simulateButton.setTypeface(Typeface.DEFAULT, Typeface.BOLD);
        simulateButton.setBackgroundTintList(ColorStateList.valueOf(CARD));
        LinearLayout.LayoutParams simulateButtonParams = params(-1, dp(52));
        simulateButtonParams.topMargin = dp(8);
        page.addView(simulateButton, simulateButtonParams);

        statusText = text(nativeLoaded ? "狀態：尚未執行" : "狀態：native 元件未載入", 14,
                nativeLoaded ? MUTED : Color.rgb(255, 155, 145), true);
        LinearLayout.LayoutParams statusParams = params(-1, -2);
        statusParams.topMargin = dp(14);
        page.addView(statusText, statusParams);

        LinearLayout resultCard = card(page);
        resultCard.addView(text("執行結果", 13, MUTED, true));
        reportText = text("按下上方按鈕後，App 會在自己的私有目錄準備測試 rootfs，再由 Rust ARM interpreter 執行真實 init。", 14, TEXT, false);
        reportText.setTypeface(Typeface.MONOSPACE);
        reportText.setTextIsSelectable(true);
        LinearLayout.LayoutParams resultParams = params(-1, -2);
        resultParams.topMargin = dp(10);
        resultCard.addView(reportText, resultParams);

        Button noticesButton = new Button(this);
        noticesButton.setText("查看系統映像開源 NOTICE");
        noticesButton.setAllCaps(false);
        noticesButton.setTextColor(TEXT);
        noticesButton.setBackgroundTintList(ColorStateList.valueOf(CARD));
        LinearLayout.LayoutParams noticeParams = params(-1, dp(48));
        noticeParams.topMargin = dp(10);
        page.addView(noticesButton, noticeParams);
        noticesButton.setOnClickListener(view -> showNotices());

        TextView footer = text("測試資料留在 App 私有儲存空間；不需 root、不要求網路或裝置權限。", 12, MUTED, false);
        LinearLayout.LayoutParams footerParams = params(-1, -2);
        footerParams.topMargin = dp(16);
        page.addView(footer, footerParams);

        launchButton.setOnClickListener(view -> runInitTest(false, true));
        runButton.setOnClickListener(view -> runInitTest(false, false));
        simulateButton.setOnClickListener(view -> runInitTest(true, false));
        setContentView(scroll);
    }

    private void runInitTest(boolean simulatePropertyEvent, boolean launchGuest) {
        if (!nativeLoaded) {
            statusText.setText("狀態：native 元件未載入");
            reportText.setText(nativeLoadError.isEmpty() ? "此裝置 ABI 尚未包含 GingerVM native library。" : nativeLoadError);
            return;
        }
        launchButton.setEnabled(false);
        runButton.setEnabled(false);
        simulateButton.setEnabled(false);
        statusText.setText(simulatePropertyEvent
                ? "狀態：準備 SIMULATED property event…"
                : launchGuest ? "狀態：檢查 init userspace 測試檔案…" : "狀態：準備 API 10 system rootfs…");
        reportText.setText(simulatePropertyEvent
                ? "正在執行 Gingerbread init，並準備注入一筆受限的 SIMULATED property socket 事件。\n\n不會產生硬體 uevent。"
                : launchGuest
                        ? "正在檢查 /init、/init.rc 與 /system/build.prop，再由 GingerVM ARM interpreter 執行 AOSP init。\n\n目前是 user-mode init 測試，並非 guest kernel boot。"
                        : "正在複製系統檔案並執行有限 init 測試；首次準備需要一些時間。\n\n這不是完整 Android 開機。");
        executor.execute(() -> {
            try {
                File rootfs = prepareRootfs();
                String inputReport = startupInputReport(rootfs);
                String nativeReport = simulatePropertyEvent
                        ? nativeRunInitSimulated(rootfs.getAbsolutePath())
                        : nativeRunInit(rootfs.getAbsolutePath());
                String report = inputReport + "\n\n" + (launchGuest
                        ? "啟動模式：GingerVM ARM user-mode interpreter 執行真實 AOSP init；不是 guest-kernel VM，也不會保持為背景執行中的 Android OS。\n\n"
                        : "執行模式：GingerVM ARM user-mode interpreter 的 init 測試。\n\n")
                        + (nativeReport == null ? "native runner 未回傳結果。" : nativeReport);
                runOnUiThread(() -> {
                    if (simulatePropertyEvent) {
                        statusText.setText(nativeReport != null && nativeReport.contains("Guest response: AOSP init")
                                ? "狀態：SIMULATED event 已由 init 處理；guest 回到等待點"
                                : "狀態：SIMULATED event 回應未確認，請查看結果");
                    } else if (launchGuest) {
                        statusText.setText(nativeReport != null && nativeReport.contains("WaitingForEvents")
                                ? "狀態：init 已到等待點；完整 Android OS 尚未開機"
                                : "狀態：受限 init 啟動未到預期等待點，請查看結果");
                    } else {
                        statusText.setText(nativeReport != null && nativeReport.contains("WaitingForEvents")
                                ? "狀態：已到達預期 init 等待點"
                                : "狀態：測試已停止，請查看結果");
                    }
                    reportText.setText(report);
                    launchButton.setEnabled(true);
                    runButton.setEnabled(true);
                    simulateButton.setEnabled(true);
                });
            } catch (Throwable error) {
                runOnUiThread(() -> {
                    statusText.setText(launchGuest ? "狀態：啟動檔案檢查或 init 啟動失敗" : "狀態：測試失敗");
                    reportText.setText(error.toString());
                    launchButton.setEnabled(true);
                    runButton.setEnabled(true);
                    simulateButton.setEnabled(true);
                });
            }
        });
    }

    private String startupInputReport(File rootfs) throws IOException {
        StringBuilder report = new StringBuilder("本次 init/user-mode 必要檔案：\n");
        for (String relativePath : INIT_STARTUP_FILES) {
            File input = new File(rootfs, relativePath);
            if (!input.isFile() || input.length() == 0) {
                throw new IOException("必要 guest 啟動檔案缺失或為空：/" + relativePath);
            }
            report.append("  存在：/").append(relativePath).append('\n');
        }
        return report.toString();
    }

    private File prepareRootfs() throws IOException {
        verifyPackagedStartupAssets();
        File appData = new File(getFilesDir(), "gingervm");
        File rootfs = new File(appData, "rootfs");
        File stamp = new File(appData, "rootfs-version.txt");
        String existing = stamp.isFile() ? readFile(stamp) : "";
        boolean cached = ROOTFS_VERSION.equals(existing.trim())
                && hasFiles(rootfs, INIT_STARTUP_FILES);

        if (!cached) {
            deleteRecursively(appData);
            if (!rootfs.mkdirs() && !rootfs.isDirectory()) {
                throw new IOException("Cannot create private guest rootfs: " + rootfs);
            }
            copyAssetNode("rootfs", rootfs);
        } else {
            for (String name : new String[] {"cache", "data", "dev", "mnt", "proc", "sdcard", "sys", "tmp", "vendor", "sbin"}) {
                File path = new File(rootfs, name);
                deleteRecursively(path);
                if (!path.mkdirs() && !path.isDirectory()) {
                    throw new IOException("Cannot reset guest directory: " + path);
                }
            }
        }

        for (String name : new String[] {"cache", "data", "dev", "etc", "mnt", "proc", "sdcard", "sys", "tmp", "vendor", "sbin"}) {
            File path = new File(rootfs, name);
            if (!path.mkdirs() && !path.isDirectory()) {
                throw new IOException("Cannot create guest directory: " + path);
            }
        }
        File ueventd = new File(rootfs, "sbin/ueventd");
        if (!ueventd.exists()) {
            try {
                Os.symlink("../init", ueventd.getAbsolutePath());
            } catch (ErrnoException error) {
                throw new IOException("Cannot create guest ueventd symlink", error);
            }
        }
        if (!hasFiles(rootfs, INIT_STARTUP_FILES)) {
            throw new IOException("Guest rootfs is incomplete after asset extraction; required init inputs are missing.");
        }
        writeFile(stamp, ROOTFS_VERSION);
        return rootfs;
    }

    private void verifyPackagedStartupAssets() throws IOException {
        StringBuilder missing = new StringBuilder();
        for (String relativePath : INIT_STARTUP_FILES) {
            try (InputStream ignored = getAssets().open("rootfs/" + relativePath)) {
                // Opening the asset verifies that the APK actually contains the required startup input.
            } catch (IOException error) {
                if (missing.length() > 0) {
                    missing.append(", ");
                }
                missing.append('/').append(relativePath);
            }
        }
        if (missing.length() > 0) {
            throw new IOException("APK guest startup preflight failed; missing required file(s): " + missing);
        }
    }

    private static boolean hasFiles(File root, String[] relativePaths) {
        for (String relativePath : relativePaths) {
            File file = new File(root, relativePath);
            if (!file.isFile() || file.length() == 0) {
                return false;
            }
        }
        return true;
    }

    private void copyAssetNode(String assetPath, File destination) throws IOException {
        String[] children = getAssets().list(assetPath);
        if (children != null && children.length > 0) {
            if (!destination.mkdirs() && !destination.isDirectory()) {
                throw new IOException("Cannot create directory: " + destination);
            }
            for (String child : children) {
                copyAssetNode(assetPath + "/" + child, new File(destination, child));
            }
            return;
        }
        File parent = destination.getParentFile();
        if (parent != null && !parent.mkdirs() && !parent.isDirectory()) {
            throw new IOException("Cannot create directory: " + parent);
        }
        try (InputStream input = getAssets().open(assetPath)) {
            try (FileOutputStream output = new FileOutputStream(destination)) {
                copyStream(input, output);
            }
        } catch (FileNotFoundException error) {
            if (children == null) {
                throw error;
            }
            if (!destination.mkdirs() && !destination.isDirectory()) {
                throw new IOException("Cannot create empty asset directory: " + destination, error);
            }
        }
    }

    private void showNotices() {
        executor.execute(() -> {
            try {
                String html = readSystemNotice();
                runOnUiThread(() -> {
                    TextView content = text("", 14, TEXT, false);
                    content.setText(Html.fromHtml(html));
                    content.setMovementMethod(LinkMovementMethod.getInstance());
                    content.setPadding(dp(16), dp(8), dp(16), dp(8));
                    ScrollView view = new ScrollView(this);
                    view.addView(content);
                    new AlertDialog.Builder(this)
                            .setTitle("Android system image NOTICE")
                            .setView(view)
                            .setPositiveButton("關閉", null)
                            .show();
                });
            } catch (IOException error) {
                runOnUiThread(() -> new AlertDialog.Builder(this)
                        .setTitle("無法讀取 NOTICE")
                        .setMessage(error.toString())
                        .setPositiveButton("關閉", null)
                        .show());
            }
        });
    }

    private String readSystemNotice() throws IOException {
        try (InputStream input = getAssets().open("rootfs/system/etc/NOTICE.html");
             ByteArrayOutputStream output = new ByteArrayOutputStream()) {
            copyStream(input, output);
            return new String(output.toByteArray(), StandardCharsets.UTF_8);
        } catch (FileNotFoundException noExpandedHtml) {
            try (InputStream raw = getAssets().open("rootfs/system/etc/NOTICE.html.gz");
                 GZIPInputStream gzip = new GZIPInputStream(raw);
                 ByteArrayOutputStream output = new ByteArrayOutputStream()) {
                copyStream(gzip, output);
                return new String(output.toByteArray(), StandardCharsets.UTF_8);
            }
        }
    }

    private static void copyStream(InputStream input, java.io.OutputStream output) throws IOException {
        byte[] buffer = new byte[32 * 1024];
        int count;
        while ((count = input.read(buffer)) != -1) {
            output.write(buffer, 0, count);
        }
    }

    private static void writeFile(File file, String value) throws IOException {
        File parent = file.getParentFile();
        if (parent != null && !parent.mkdirs() && !parent.isDirectory()) {
            throw new IOException("Cannot create directory: " + parent);
        }
        try (FileOutputStream output = new FileOutputStream(file, false)) {
            output.write(value.getBytes(StandardCharsets.UTF_8));
        }
    }

    private static String readFile(File file) throws IOException {
        try (FileInputStream input = new FileInputStream(file);
             ByteArrayOutputStream output = new ByteArrayOutputStream()) {
            copyStream(input, output);
            return new String(output.toByteArray(), StandardCharsets.UTF_8);
        }
    }

    private static void deleteRecursively(File file) throws IOException {
        if (!file.exists()) {
            return;
        }
        if (file.isDirectory()) {
            File[] children = file.listFiles();
            if (children != null) {
                for (File child : children) {
                    deleteRecursively(child);
                }
            }
        }
        if (!file.delete()) {
            throw new IOException("Cannot remove: " + file);
        }
    }

    private LinearLayout card(LinearLayout parent) {
        LinearLayout card = new LinearLayout(this);
        card.setOrientation(LinearLayout.VERTICAL);
        card.setPadding(dp(16), dp(16), dp(16), dp(16));
        GradientDrawable background = new GradientDrawable();
        background.setColor(CARD);
        background.setCornerRadius(dp(18));
        card.setBackground(background);
        LinearLayout.LayoutParams layout = params(-1, -2);
        layout.topMargin = dp(18);
        parent.addView(card, layout);
        return card;
    }

    private TextView text(String value, int size, int color, boolean bold) {
        TextView view = new TextView(this);
        view.setText(value);
        view.setTextSize(size);
        view.setTextColor(color);
        if (bold) {
            view.setTypeface(Typeface.DEFAULT, Typeface.BOLD);
        }
        view.setLineSpacing(dp(3), 1.0f);
        return view;
    }

    private LinearLayout.LayoutParams params(int width, int height) {
        return new LinearLayout.LayoutParams(width, height);
    }

    private int dp(int value) {
        return Math.round(value * getResources().getDisplayMetrics().density);
    }

    @Override
    protected void onDestroy() {
        executor.shutdownNow();
        super.onDestroy();
    }
}
