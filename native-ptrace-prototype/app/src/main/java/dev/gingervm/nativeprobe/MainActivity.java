package dev.gingervm.nativeprobe;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.ClipData;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.res.AssetManager;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Process;
import android.os.StatFs;
import android.system.ErrnoException;
import android.system.Os;
import android.system.OsConstants;
import android.system.StructStat;
import android.view.Gravity;
import android.view.View;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileDescriptor;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.RandomAccessFile;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.HashSet;
import java.util.Locale;
import java.util.Set;
import java.text.SimpleDateFormat;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

public final class MainActivity extends Activity {
    private static final String GUEST_ROOT_NAME = "google-api10-full-root";
    private static final int REQUEST_SAVE_LOG = 2301;
    private static final String LOG_FILE_NAME = "gingervm-guest-trace.txt";
    private static final String INIT_SHA256 = "2d9cbb198d8367f434c5fd7bada245c9e7618dc910253190f5d4dd3d0f6d1a00";
    private static final String MANIFEST_SHA_ASSET = "api10-system-manifest.sha256";
    private static final long STORAGE_MARGIN_BYTES = 12L * 1024L * 1024L;
    private static final int MAX_REPORT_CHARS = 48 * 1024;
    private static final int MAX_LOG_VIEW_BYTES = 256 * 1024;
    private static final int STOP_CLEANUP_GRACE_SECONDS = 15;

    private final Set<String> knownSystemAssetDirectories = new HashSet<>();
    private TextView report;
    private ScrollView reportScrollView;
    private AlertDialog liveLogDialog;
    private ScrollView liveLogScroll;
    private TextView liveLogBody;
    private Button guestButton;
    private Button exportButton;
    private Button viewLogButton;
    private Button stopButton;
    private File latestLogFile;
    private volatile boolean stopRequested;
    private volatile boolean explicitStopRequested;
    private volatile boolean runActive;
    private volatile boolean runCancellable;
    private volatile Thread activeRunThread;
    private volatile java.lang.Process activeSupervisorProcess;
    private final StringBuilder runProgressLog = new StringBuilder();

    @Override
    public void onCreate(Bundle state) {
        super.onCreate(state);
        setTitle("GingerVM");
        buildUi();
        latestLogFile = new File(getCacheDir(), LOG_FILE_NAME);
        exportButton.setEnabled(hasExportableLog());
        viewLogButton.setEnabled(hasExportableLog());
        report.setText("GingerVM Android guest: continuous init process-tree trace\n\n"
                + "Stages the original Google SDK API 10 / Android 2.3.7 ARMv7 ramdisk and complete matching /system tree. Starts the original static /init once and follows its fork/clone/exec descendants in the same bounded ptrace session. Dynamic ELF copies change only PT_INTERP to the original guest linker inherited as fd 198; the host Android linker is not substituted.\n"
                + "This is not a claim of a complete boot or desktop. Guest mount/device/identity operations are software-only; no host root or host mount is used.\n\n"
                + "Host ABI: " + Arrays.toString(Build.SUPPORTED_ABIS) + "\n"
                + "64-bit app process: " + Process.is64Bit() + "\n"
                + "Android API: " + Build.VERSION.SDK_INT + "\n"
                + "Latest user-provided Android 12 screen (v0.6.7): staging failed before guest execution while deleting the previous app-private tree at /mnt/sdcard. Official API10 init.rc sets `mkdir /mnt/sdcard 0000 system system`; the old cleanup then got null from File.listFiles(). v0.6.8 repairs cleanup but is not yet device-tested. Earlier v0.6.6 trace: PID 1 passed coldboot wait and property-area ftruncate, then AF_UNIX socket(1,1,0) received -97 (EAFNOSUPPORT). The v0.6.7 software socket model has not yet been exercised on-device; no guest linker, Zygote, framework, or desktop boot has been reached.\n\n"
                + "Log retention: one latest complete session, overwritten by the next run (not circular). The viewer shows a bounded tail; share/save exports the full latest file.\n"
                + "No v0.6.8 trace has been recorded yet; the earlier device evidence above is historical context.");
    }

    private void buildUi() {
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(24, 24, 24, 24);
        root.setGravity(Gravity.CENTER_HORIZONTAL);

        guestButton = new Button(this);
        guestButton.setText("Stage guest + trace continuous Android startup");
        root.addView(guestButton, new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT));

        LinearLayout runControls = new LinearLayout(this);
        runControls.setOrientation(LinearLayout.HORIZONTAL);
        viewLogButton = new Button(this);
        viewLogButton.setText("查看日誌");
        stopButton = new Button(this);
        stopButton.setText("停止");
        stopButton.setEnabled(false);
        runControls.addView(viewLogButton, new LinearLayout.LayoutParams(
                0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f));
        runControls.addView(stopButton, new LinearLayout.LayoutParams(
                0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f));
        root.addView(runControls, new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT));

        exportButton = new Button(this);
        exportButton.setText("分享／儲存完整追蹤日誌");
        exportButton.setEnabled(false);
        root.addView(exportButton, new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT));

        reportScrollView = new ScrollView(this);
        report = new TextView(this);
        report.setTextSize(14);
        report.setTextIsSelectable(true);
        report.setPadding(0, 20, 0, 0);
        reportScrollView.addView(report);
        root.addView(reportScrollView, new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, 0, 1f));
        setContentView(root);

        guestButton.setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View view) { startRun(); }
        });
        exportButton.setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View view) { showLogExportOptions(); }
        });
        viewLogButton.setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View view) { showLogViewer(); }
        });
        stopButton.setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View view) { requestStop(); }
        });
    }

    private void startRun() {
        if (runActive) return;
        stopRequested = false;
        explicitStopRequested = false;
        runActive = true;
        runCancellable = true;
        activeSupervisorProcess = null;
        synchronized (runProgressLog) { runProgressLog.setLength(0); }
        guestButton.setEnabled(false);
        exportButton.setEnabled(false);
        viewLogButton.setEnabled(true);
        stopButton.setEnabled(true);
        setReportText("Preparing the complete Google API10 guest image; about 106 MiB of userland and linker aliases are staged across app-private storage and extracted ARM32 libraries…\n"
                + "HISTORICAL DEVICE BASELINE (user-provided v0.6.7 Android 12 screenshot; not this run): staging failed before guest execution while deleting the previous app-private tree at /mnt/sdcard. Official API10 init.rc requests mkdir /mnt/sdcard 0000 system system; the old cleanup lstat'ed the directory then File.listFiles() returned null. v0.6.8 restores app-owner rwx only for lstat-confirmed real directories, uses O_NOFOLLOW before listing, unlinks symlinks without traversing targets, and treats missing paths as no-op. This cleanup fix and the v0.6.7 software AF_UNIX model are not yet confirmed on-device; no guest linker/Zygote/Framework has been reached. This run's Stop button requests a separate user cancellation.\n");
        postProgress("RUN STARTED: one continuous original /init process-tree session; this app-private latest-log file will be replaced when the run ends.\n");
        Thread worker = new Thread(new Runnable() {
            @Override public void run() {
                String result;
                try {
                    result = executeGuestEnvironmentTest();
                } catch (RunCancelledException e) {
                    result = "USER CANCELLED: " + e.getMessage() + "\nNo guest program was executed. Partial staging will be safely rechecked or removed on the next run.\n";
                } catch (Exception e) {
                    result = "TRACE FAILED: " + e + "\n";
                }
                runCancellable = false;
                final String completeLog;
                synchronized (runProgressLog) { completeLog = runProgressLog.toString() + result; }
                IOException writeFailure = null;
                try {
                    writeLatestLog(completeLog);
                } catch (IOException e) {
                    writeFailure = e;
                }
                runActive = false;
                activeSupervisorProcess = null;
                activeRunThread = null;
                final IOException finalWriteFailure = writeFailure;
                final String finalResult = writeFailure == null ? completeLog : completeLog
                        + "\nLOG EXPORT PREPARATION FAILED: " + writeFailure + "\n";
                runOnUiThread(new Runnable() {
                    @Override public void run() {
                        setReportText(finalResult);
                        guestButton.setEnabled(true);
                        exportButton.setEnabled(finalWriteFailure == null && hasExportableLog());
                        viewLogButton.setEnabled(hasExportableLog());
                        stopButton.setEnabled(false);
                    }
                });
            }
        }, "guest-init-process-tree");
        activeRunThread = worker;
        worker.start();
    }

    private boolean hasExportableLog() {
        return latestLogFile != null && latestLogFile.isFile() && latestLogFile.length() > 0;
    }

    private void requestStop() {
        if (!runActive || !runCancellable) return;
        stopRequested = true;
        explicitStopRequested = true;
        stopButton.setEnabled(false);
        postProgress("\nUSER STOP REQUESTED: stopping the current staging/trace run; this is distinct from the supervisor time limit.\n");
        java.lang.Process supervisor = activeSupervisorProcess;
        if (supervisor != null) {
            try {
                supervisor.destroy();
                postProgress("Sent SIGTERM to the supervisor; waiting for traced children to be terminated and reaped.\n");
            } catch (Exception e) {
                postProgress("Could not send graceful stop to supervisor: " + e + "\n");
            }
        } else {
            postProgress("No supervisor is running yet; staging will stop at its next safe cancellation checkpoint.\n");
        }
    }

    private void showLogViewer() {
        String text;
        String title;
        final boolean live = runActive;
        if (live) {
            text = report.getText().toString();
            title = "即時日誌（畫面最近內容）";
        } else if (hasExportableLog()) {
            try {
                text = readLatestLogTail();
                title = "完整追蹤日誌（最近 256 KiB）";
            } catch (IOException e) {
                Toast.makeText(this, "讀取日誌失敗：" + e, Toast.LENGTH_LONG).show();
                return;
            }
        } else {
            Toast.makeText(this, "目前沒有可查看的追蹤日誌", Toast.LENGTH_LONG).show();
            return;
        }
        TextView body = new TextView(this);
        body.setTextSize(13);
        body.setTextIsSelectable(true);
        body.setPadding(24, 20, 24, 20);
        body.setText(text);
        ScrollView viewer = new ScrollView(this);
        viewer.addView(body);
        final AlertDialog dialog = new AlertDialog.Builder(this)
                .setTitle(title)
                .setView(viewer)
                .setPositiveButton("關閉", null)
                .create();
        if (live) {
            liveLogDialog = dialog;
            liveLogScroll = viewer;
            liveLogBody = body;
            dialog.setOnDismissListener(new DialogInterface.OnDismissListener() {
                @Override public void onDismiss(DialogInterface dismissed) {
                    if (liveLogDialog == dialog) {
                        liveLogDialog = null;
                        liveLogScroll = null;
                        liveLogBody = null;
                    }
                }
            });
        }
        dialog.show();
        scrollToLatest(viewer);
    }

    private String readLatestLogTail() throws IOException {
        try (RandomAccessFile in = new RandomAccessFile(latestLogFile, "r")) {
            long length = in.length();
            boolean truncated = length > MAX_LOG_VIEW_BYTES;
            long start = Math.max(0, length - MAX_LOG_VIEW_BYTES);
            in.seek(start);
            if (truncated) {
                while (in.getFilePointer() < length && in.read() != '\n') { }
            }
            ByteArrayOutputStream bytes = new ByteArrayOutputStream();
            byte[] buffer = new byte[8192];
            int n;
            while ((n = in.read(buffer)) >= 0) bytes.write(buffer, 0, n);
            String tail = new String(bytes.toByteArray(), StandardCharsets.UTF_8);
            if (truncated) return "［畫面僅顯示日誌尾端；完整單次執行記錄仍可分享／儲存］\n" + tail;
            return tail;
        }
    }

    private String boundedReport(String text) {
        if (text.length() <= MAX_REPORT_CHARS) return text;
        int start = Math.max(0, text.length() - (MAX_REPORT_CHARS - 64));
        int newline = text.indexOf('\n', start);
        if (newline >= 0 && newline + 1 < text.length()) start = newline + 1;
        return "［畫面只保留最近約 48 Ki 字元；完整日誌可分享／儲存］\n" + text.substring(start);
    }

    private void setReportText(String text) {
        String displayText = boundedReport(text);
        report.setText(displayText);
        scrollToLatest(reportScrollView);
        if (liveLogDialog != null && liveLogDialog.isShowing() &&
            liveLogBody != null && liveLogScroll != null) {
            liveLogBody.setText(displayText);
            scrollToLatest(liveLogScroll);
        }
    }

    private void scrollToLatest(final ScrollView scrollView) {
        if (scrollView == null) return;
        scrollView.post(new Runnable() {
            @Override public void run() {
                scrollView.fullScroll(View.FOCUS_DOWN);
            }
        });
    }

    private void appendReportText(final String text) {
        runOnUiThread(new Runnable() {
            @Override public void run() {
                setReportText(report.getText().toString() + text);
            }
        });
    }

    private void throwIfStopRequested() throws RunCancelledException {
        if (stopRequested) throw new RunCancelledException("user requested Stop; cancellation checkpoint reached");
    }

    private static final class RunCancelledException extends IOException {
        RunCancelledException(String message) { super(message); }
    }

    private void writeLatestLog(String text) throws IOException {
        File parent = latestLogFile.getParentFile();
        if (parent != null && !parent.isDirectory() && !parent.mkdirs())
            throw new IOException("cannot create trace-log cache directory");
        try (FileOutputStream out = new FileOutputStream(latestLogFile, false)) {
            out.write(text.getBytes(StandardCharsets.UTF_8));
            out.flush();
            out.getFD().sync();
        }
    }

    private void showLogExportOptions() {
        if (!hasExportableLog()) {
            exportButton.setEnabled(false);
            Toast.makeText(this, "目前沒有可匯出的完整日誌", Toast.LENGTH_LONG).show();
            return;
        }
        new AlertDialog.Builder(this)
                .setTitle("匯出完整追蹤日誌")
                .setItems(new CharSequence[]{"分享日誌…", "儲存為文字檔…"},
                        new DialogInterface.OnClickListener() {
                            @Override public void onClick(DialogInterface dialog, int which) {
                                if (which == 0) shareLatestLog();
                                else if (which == 1) saveLatestLog();
                            }
                        })
                .show();
    }

    private void shareLatestLog() {
        Uri uri = Uri.parse("content://" + getPackageName() + ".trace-logs/latest.txt");
        Intent send = new Intent(Intent.ACTION_SEND);
        send.setType("text/plain");
        send.putExtra(Intent.EXTRA_SUBJECT, "GingerVM 完整 guest trace");
        send.putExtra(Intent.EXTRA_TEXT, "完整追蹤日誌以文字檔附件提供。");
        send.putExtra(Intent.EXTRA_STREAM, uri);
        send.setClipData(ClipData.newUri(getContentResolver(), "GingerVM trace log", uri));
        send.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
        try {
            startActivity(Intent.createChooser(send, "分享完整追蹤日誌"));
        } catch (Exception e) {
            Toast.makeText(this, "無法開啟分享選單：" + e, Toast.LENGTH_LONG).show();
        }
    }

    private void saveLatestLog() {
        Intent save = new Intent(Intent.ACTION_CREATE_DOCUMENT);
        save.addCategory(Intent.CATEGORY_OPENABLE);
        save.setType("text/plain");
        save.putExtra(Intent.EXTRA_TITLE, exportLogFileName());
        try {
            startActivityForResult(save, REQUEST_SAVE_LOG);
        } catch (Exception e) {
            Toast.makeText(this, "無法開啟檔案儲存器：" + e, Toast.LENGTH_LONG).show();
        }
    }

    private String exportLogFileName() {
        String stamp = new SimpleDateFormat("yyyyMMdd-HHmmss", Locale.US).format(new Date());
        return "GingerVM-guest-trace-" + stamp + ".txt";
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode != REQUEST_SAVE_LOG || resultCode != RESULT_OK || data == null || data.getData() == null)
            return;
        try (InputStream in = new FileInputStream(latestLogFile)) {
            java.io.OutputStream target = getContentResolver().openOutputStream(data.getData(), "w");
            if (target == null) throw new IOException("document provider returned no output stream");
            try (java.io.OutputStream out = target) {
                byte[] buffer = new byte[16384];
                int n;
                while ((n = in.read(buffer)) >= 0) out.write(buffer, 0, n);
                out.flush();
            }
            Toast.makeText(this, "完整日誌已儲存", Toast.LENGTH_LONG).show();
        } catch (Exception e) {
            Toast.makeText(this, "儲存日誌失敗：" + e, Toast.LENGTH_LONG).show();
        }
    }

    private String executeGuestEnvironmentTest() throws RunCancelledException {
        throwIfStopRequested();
        StringBuilder out = new StringBuilder();
        out.append("GingerVM continuous Android 2.3.7/API 10 init process-tree trace\n");
        out.append("HISTORICAL DEVICE BASELINE (user-provided v0.6.7 Android 12 screenshot; not this run): staging failed before guest execution while deleting the previous app-private tree at /mnt/sdcard. Official API10 init.rc requests mkdir /mnt/sdcard 0000 system system; old cleanup lstat'ed it as a directory then File.listFiles() returned null. v0.6.8 restores app-owner rwx only on lstat-confirmed real directories, opens without following symlinks, and treats missing paths as no-op; this fix has not yet been confirmed on-device. Earlier v0.6.6 trace reached AF_UNIX socket(1,1,0), got -97 (EAFNOSUPPORT), and exited; thus the v0.6.7 software socket model remains unverified. No guest linker/Zygote/framework has been reached.\n\n");
        out.append("Host ABI: ").append(Arrays.toString(Build.SUPPORTED_ABIS)).append('\n');
        out.append("64-bit app process: ").append(Process.is64Bit()).append('\n');
        out.append("Android API: ").append(Build.VERSION.SDK_INT).append('\n');
        if (!Process.is64Bit() || !Arrays.asList(Build.SUPPORTED_ABIS).contains("arm64-v8a")
                || !Arrays.asList(Build.SUPPORTED_ABIS).contains("armeabi-v7a")) {
            return out.append("NOT RUN: this smoke suite requires a 64-bit arm64-v8a app process and installed ARM32 compatibility libraries.\n").toString();
        }

        File nativeLibraryDir = new File(getApplicationInfo().nativeLibraryDir);
        File supervisor = new File(nativeLibraryDir, "libgingervm_init_supervisor.so");
        File guestLibraryDir = findExtractedAbiLibraryDir(nativeLibraryDir, "libgingervm_guest_init.so");
        if (guestLibraryDir == null) {
            return out.append("SETUP FAILED: no installed app library directory contains the executable ELF32 ARM guest payload.\n").toString();
        }
        out.append("Resolved ARM32 guest native-library directory: ").append(guestLibraryDir.getAbsolutePath()).append('\n');
        File guestInit = new File(guestLibraryDir, "libgingervm_guest_init.so");
        if (!supervisor.isFile() || !supervisor.canExecute() || !guestInit.isFile() || !guestInit.canExecute()) {
            return out.append("SETUP FAILED: extracted supervisor or official static ARM32 init is missing/not executable.\n").toString();
        }

        final String manifestHash;
        final long requiredBytes;
        final JSONObject manifest;
        try {
            manifestHash = readAssetText(MANIFEST_SHA_ASSET).trim();
            String manifestText = readAssetText("api10-system-manifest.json");
            manifest = new JSONObject(manifestText);
            requiredBytes = manifest.getLong("app_private_asset_bytes");
            if (!manifestHash.equals(sha256(manifestText.getBytes(StandardCharsets.UTF_8))))
                throw new IOException("manifest SHA-256 does not match the packaged digest");
            loadSystemAssetDirectories(manifest);
        } catch (Exception e) {
            return out.append("SETUP FAILED: full-system asset manifest is invalid: ").append(e).append('\n').toString();
        }
        if (manifestHash.length() != 64 || !manifestHash.matches("[0-9a-f]{64}")) {
            return out.append("SETUP FAILED: system manifest digest is missing or malformed.\n").toString();
        }

        File guestRoot = new File(getFilesDir(), GUEST_ROOT_NAME);
        File systemRoot = new File(new File(guestRoot, ".images"), "system");
        String readyMarker = "GINGERVM-API10-CONTINUOUS-v0.4.0\n" + manifestHash + "\n"
                + guestLibraryDir.getAbsolutePath() + "\n" + INIT_SHA256 + "\n";
        boolean reuse = isDeploymentReady(guestRoot, systemRoot, readyMarker, manifest, guestLibraryDir);
        throwIfStopRequested();
        long available = new StatFs(getFilesDir().getAbsolutePath()).getAvailableBytes();
        if (!reuse && available < requiredBytes + STORAGE_MARGIN_BYTES) {
            return out.append("NOT ENOUGH PRIVATE STORAGE: need at least ")
                    .append((requiredBytes + STORAGE_MARGIN_BYTES) / (1024 * 1024)).append(" MiB free to stage the full /system tree; available ")
                    .append(available / (1024 * 1024)).append(" MiB. No guest files were removed.\n").toString();
        }

        try {
            if (reuse) {
                out.append("DEPLOYMENT: reusing verified app-private full guest tree\n");
                postProgress("Reusing verified full API10 guest tree; preparing the continuous init trace…\n");
            } else {
                postProgress("Removing any previous/partial guest tree without following symlinks…\n");
                deleteRecursively(guestRoot);
                if (!guestRoot.mkdirs() && !guestRoot.isDirectory()) throw new IOException("cannot create app-private guest root");
                postProgress("Copying original ramdisk and complete /system tree (about 106 MiB including linker aliases)…\n");
                copyAssetTree("api10-init-root", guestRoot);
                File images = new File(guestRoot, ".images");
                if (!images.mkdirs() && !images.isDirectory()) throw new IOException("cannot create guest image directory");
                copyAssetTree("api10-system", systemRoot);
                if (!systemRoot.isDirectory()) throw new IOException("full /system image tree was not staged");
                restoreSystemAssetNames(systemRoot, manifest);
                restoreSystemSymlinks(systemRoot);
                installNativeSystemPayloads(systemRoot, guestLibraryDir);
                verifyGuestSystemTree(systemRoot, manifest, guestLibraryDir);

                ensureDirectory(new File(guestRoot, "dev/socket"));
                ensureDirectory(new File(guestRoot, "proc"));
                ensureDirectory(new File(guestRoot, "sys"));
                ensureDirectory(new File(guestRoot, "sbin"));
                Os.symlink("../init", new File(guestRoot, "sbin/ueventd").getAbsolutePath());
                try (FileOutputStream marker = new FileOutputStream(new File(guestRoot, ".gingervm-deployment"))) {
                    marker.write(readyMarker.getBytes(StandardCharsets.UTF_8));
                    marker.getFD().sync();
                }
                out.append("DEPLOYMENT: staged original ramdisk + full ").append(manifest.optInt("regular_file_count"))
                        .append("-file /system tree (uncompressed ").append(manifest.optLong("regular_file_bytes") / (1024 * 1024)).append(" MiB)\n");
                out.append("SYSTEM LINKS: ").append(manifest.optInt("symlink_count")).append(" confined symlinks restored\n");
                out.append("NATIVE PAYLOADS: ").append(manifest.optInt("native_library_count"))
                        .append(" guest system libraries + ").append(manifest.optInt("native_executable_count"))
                        .append(" original guest executable ELFs + ").append(manifest.optInt("dynamic_executable_count"))
                        .append(" PT_INTERP-only linker aliases in APK-extracted armeabi-v7a\n");
                postProgress("Full API10 system tree staged. Starting one /init process-tree trace…\n");
            }
        } catch (RunCancelledException e) {
            return out.append("USER CANCELLED DURING STAGING: ").append(e.getMessage()).append('\n')
                    .append("No guest program was executed. Partial app-private staging is incomplete and will be safely rechecked or removed on the next run.\n").toString();
        } catch (Exception e) {
            return out.append("STAGING FAILED: ").append(e).append('\n')
                    .append("No guest program was executed. You can retry; partial app-private guest data will be safely removed first.\n").toString();
        }

        out.append("Guest root: app-private files/").append(GUEST_ROOT_NAME).append('\n');
        out.append("System image backing: app-private /.images/system; guest /system is exposed by the software mount broker\n");
        out.append("Supervisor: ").append(supervisor.getAbsolutePath()).append('\n');
        out.append("ARM32 executable directory: ").append(guestLibraryDir.getAbsolutePath()).append('\n');
        out.append("Source image hashes: original Google API10 ramdisk/system; no Samsung payloads\n");
        out.append("Host root/mount calls: none\n\n");

        out.append("Continuous trace: one original /init with its traced child tree; maximum 32 tracees, bounded by the supervisor timeout.\n");
        out.append("Dynamic ELF policy: preserve each original executable and create a separate copy changing only PT_INTERP to /proc/self/fd/198; fd 198 is the original Google API10 linker inherited by the guest tree. Host Android linker substitution is not accepted.\n\n");
        throwIfStopRequested();
        appendProgress(out, "Start original /init and follow its child processes in the same session");
        out.append(runNative("continuous /init process tree", supervisor, guestInit, guestRoot, 120,
                guestLibraryDir, "/init"));
        out.append("\nBOOT BOUNDARY: a dynamic-linker entry event is not proof that the guest target reached main, nor proof of Zygote, framework, system-server, or desktop boot. The first unsupported stage is reported explicitly.\n");
        return out.toString();
    }

    private String runNative(String label, File supervisor, File guestExecutable, File guestRoot,
                             int timeoutSeconds, File allowedGuestLibraryDir, String... guestArgv) {
        return runNative(new StringBuilder("--- ").append(label).append(" ---\n"), supervisor,
                guestExecutable, guestRoot, timeoutSeconds, allowedGuestLibraryDir, guestArgv);
    }

    private String runNative(StringBuilder header, File supervisor, File guestExecutable, File guestRoot,
                             int timeoutSeconds, File allowedGuestLibraryDir, String... guestArgv) {
        java.lang.Process process;
        try {
            int traceMillis = Math.max(500, Math.min(120000, (timeoutSeconds - 3) * 1000));
            String[] command = new String[5 + guestArgv.length];
            command[0] = supervisor.getAbsolutePath();
            command[1] = guestExecutable.getAbsolutePath();
            command[2] = guestRoot.getAbsolutePath();
            command[3] = allowedGuestLibraryDir.getAbsolutePath();
            command[4] = Integer.toString(traceMillis);
            System.arraycopy(guestArgv, 0, command, 5, guestArgv.length);
            process = new ProcessBuilder(command).redirectErrorStream(true).start();
        } catch (Exception e) {
            if (stopRequested) return header.append("USER CANCELLED BEFORE SUPERVISOR START: ").append(e).append('\n').toString();
            return header.append("START FAILED: ").append(e).append('\n').toString();
        }
        final java.lang.Process child = process;
        activeSupervisorProcess = process;
        if (stopRequested) process.destroy();
        final InputStream outputStream = child.getInputStream();
        final TraceOutputCapture.CaptureSession captureSession = new TraceOutputCapture.CaptureSession();
        final AtomicReference<TraceOutputCapture.Result> captureResult = new AtomicReference<>();
        Thread reader = new Thread(new Runnable() {
            @Override public void run() {
                TraceOutputCapture.Result result;
                try {
                    result = captureSession.readToEof(outputStream, new TraceOutputCapture.ChunkListener() {
                        @Override public void onText(String chunk) { appendReportText(chunk); }
                    });
                } catch (RuntimeException e) {
                    result = captureSession.failAndSeal("output reader failed: " + e);
                }
                try {
                    outputStream.close();
                } catch (IOException e) {
                    result = result.withFailure("output stream close failed: " + e);
                }
                captureResult.set(result);
            }
        }, "guest-output-reader");
        reader.setDaemon(true);
        reader.start();
        int exit = -1;
        boolean timedOut = false;
        boolean interrupted = false;
        boolean forcedAfterGrace = false;
        long processDeadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(timeoutSeconds);
        while (process.isAlive()) {
            if (!stopRequested && !timedOut && System.nanoTime() >= processDeadline) {
                timedOut = true;
                process.destroy();
            }
            if (stopRequested || timedOut) {
                process.destroy();
                long graceDeadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(STOP_CLEANUP_GRACE_SECONDS);
                while (process.isAlive() && System.nanoTime() < graceDeadline) {
                    long remaining = graceDeadline - System.nanoTime();
                    long waitNanos = Math.min(remaining, TimeUnit.MILLISECONDS.toNanos(100));
                    try {
                        process.waitFor(Math.max(1L, waitNanos), TimeUnit.NANOSECONDS);
                    } catch (InterruptedException e) {
                        interrupted = true;
                        stopRequested = true;
                        process.destroy();
                    }
                }
                if (process.isAlive()) {
                    forcedAfterGrace = true;
                    process.destroyForcibly();
                    interrupted |= waitForProcessUninterruptibly(process);
                }
                break;
            }
            long remaining = processDeadline - System.nanoTime();
            long waitNanos = Math.min(remaining, TimeUnit.MILLISECONDS.toNanos(200));
            try {
                process.waitFor(Math.max(1L, waitNanos), TimeUnit.NANOSECONDS);
            } catch (InterruptedException e) {
                interrupted = true;
                stopRequested = true;
                process.destroy();
            }
        }
        if (!process.isAlive()) exit = process.exitValue();

        long drainDeadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(STOP_CLEANUP_GRACE_SECONDS);
        while (reader.isAlive() && System.nanoTime() < drainDeadline) {
            try { reader.join(100L); }
            catch (InterruptedException e) { interrupted = true; }
        }
        boolean outputDrainTimedOut = reader.isAlive();
        if (outputDrainTimedOut) {
            captureSession.failAndSeal("output pipe did not reach EOF within the post-stop drain grace");
            try { outputStream.close(); } catch (IOException ignored) {}
            long closeDeadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(2);
            while (reader.isAlive() && System.nanoTime() < closeDeadline) {
                try { reader.join(100L); }
                catch (InterruptedException e) { interrupted = true; }
            }
            if (reader.isAlive()) captureSession.failAndSeal("output reader remained blocked after stream close");
        }
        activeSupervisorProcess = null;
        TraceOutputCapture.Result captured = captureResult.get();
        if (captured == null) captured = captureSession.snapshot();
        String trace = captured.text();
        if (captured.recoveredInterruptedReads > 0)
            trace += "\nOUTPUT CAPTURE RECOVERED: InterruptedIOException reads="
                    + captured.recoveredInterruptedReads + "; resumed draining the supervisor pipe.\n";
        if (captured.failure != null)
            trace += "\nOUTPUT CAPTURE ERROR: " + captured.failure + "; exported log may be incomplete.\n";
        else if (outputDrainTimedOut)
            trace += "\nOUTPUT CAPTURE ERROR: the reader did not finish draining and closing the supervisor pipe; exported log may be incomplete.\n";
        if (forcedAfterGrace)
            trace += "\nAPP STOP FALLBACK: supervisor did not exit during the graceful cleanup window and was force-terminated; native tracee cleanup is unconfirmed.\n";
        boolean guestLinkerEntered = trace.contains("GUEST DYNAMIC EXEC EVENT:");
        header.append(trace);
        if (interrupted) header.append("\nRUN INTERRUPTED: the app thread was interrupted; a graceful stop was requested before fallback cleanup.\n");
        if (stopRequested) {
            header.append(explicitStopRequested
                    ? "\nUSER CANCEL REQUESTED: explicit app Stop action; not a supervisor timeout.\n"
                    : "\nRUN CANCEL REQUESTED: app worker interruption requested graceful supervisor shutdown.\n");
            boolean cleanupConfirmed = trace.contains("STOP: user cancellation cleanup confirmed;")
                    && trace.matches("(?s).*TRACE CLEANUP: tracked=[0-9]+ reaped=[0-9]+ already-gone=[0-9]+ unresolved=0.*");
            if (cleanupConfirmed && !forcedAfterGrace)
                header.append("USER CANCEL RESULT: supervisor confirmed all tracked tracees reaped (unresolved=0).\n");
            else if (forcedAfterGrace)
                header.append("USER CANCEL RESULT: Java force-stop fallback ran; tracee cleanup cannot be confirmed from this capture.\n");
            else if (trace.contains("STOP: user-requested cancellation before guest exec; no supervisor timeout occurred")
                    || trace.contains("USER CANCELLED BEFORE SUPERVISOR START"))
                header.append("USER CANCEL RESULT: cancellation happened before guest execution; no tracees existed to reap.\n");
            else if (trace.contains("STOP: root /init exited") || trace.contains("STOP: root /init terminated"))
                header.append("USER CANCEL RESULT: the guest had already reached a root-process stop; see the native STOP line for its outcome.\n");
            else
                header.append("USER CANCEL RESULT: native cleanup confirmation is absent; inspect the supervisor STOP/CLEANUP lines above.\n");
        }
        if (timedOut) {
            header.append("\nAPP TIMEOUT: the Java wall-time guard expired after ").append(timeoutSeconds).append(" seconds; this is not the normal supervisor event-wait timeout.\n");
            header.append("Supervisor exit code after graceful wait: ").append(exit).append('\n');
            if (guestLinkerEntered) header.append("RESULT: the continuous tree entered the original API10 linker, but the dynamic target main/zygote/framework entry remains unproven.\n");
        } else {
            header.append("\nSupervisor exit code: ").append(exit).append('\n');
            if (exit == 3) {
                header.append("RESULT: one continuous /init child tree hit an unsupported or unverified dynamic interpreter and stopped fail-closed.\n");
            } else if (exit == 4) {
                header.append("RESULT: the continuous trace stopped at the bounded child-process cap.\n");
            } else if (trace.contains("STOP: root /init terminated by signal")) {
                header.append("RESULT: guest /init terminated by signal; this is not a successful startup.\n");
            } else if (guestLinkerEntered) {
                header.append("RESULT: the continuous tree entered the original API10 linker for a dynamic guest ELF; its target main entry and Android boot stages remain unproven.\n");
            } else {
                header.append(exit == 0
                        ? "RESULT: one continuous /init process-tree trace completed or timed out; inspect each stage and stop reason. This is not a full Android boot.\n"
                        : "RESULT: the continuous /init process-tree trace failed before a conclusive stage; inspect the first failure above.\n");
            }
        }
        if (interrupted) Thread.currentThread().interrupt();
        return header.toString();
    }

    private static boolean waitForProcessUninterruptibly(java.lang.Process process) {
        boolean interrupted = false;
        while (process.isAlive()) {
            try { process.waitFor(); }
            catch (InterruptedException e) { interrupted = true; }
        }
        return interrupted;
    }

    private void appendProgress(StringBuilder output, String message) {
        output.append("\n=== ").append(message).append(" ===\n");
        appendReportText(message + "…\n");
    }

    private void postProgress(final String message) {
        synchronized (runProgressLog) { runProgressLog.append(message); }
        appendReportText(message);
    }

    private void loadSystemAssetDirectories(JSONObject manifest) throws IOException, JSONException {
        knownSystemAssetDirectories.clear();
        JSONArray directories = manifest.getJSONArray("directories");
        for (int i = 0; i < directories.length(); ++i) {
            String relative = directories.getString(i);
            validateRelativePath(relative);
            knownSystemAssetDirectories.add("api10-system/" + relative);
        }
    }

    private boolean isDeploymentReady(File guestRoot, File systemRoot, String expectedMarker,
                                      JSONObject manifest, File guestLibraryDir) {
        File marker = new File(guestRoot, ".gingervm-deployment");
        File init = new File(guestRoot, "init");
        File ueventd = new File(guestRoot, "sbin/ueventd");
        try {
            if (!marker.isFile() || !init.isFile() || !expectedMarker.equals(readFileText(marker))
                    || !INIT_SHA256.equals(sha256(init))
                    || !OsConstants.S_ISLNK(Os.lstat(ueventd.getAbsolutePath()).st_mode)
                    || !"../init".equals(Os.readlink(ueventd.getAbsolutePath()))) return false;
            verifyGuestSystemTree(systemRoot, manifest, guestLibraryDir);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    private void verifyGuestSystemTree(File systemRoot, JSONObject manifest, File guestLibraryDir)
            throws IOException, JSONException {
        if (!systemRoot.isDirectory()) throw new IOException("guest system root is missing");
        Set<String> expectedDirectories = new HashSet<>();
        Set<String> expectedFiles = new HashSet<>();
        Set<String> expectedLinks = new HashSet<>();
        JSONArray directories = manifest.getJSONArray("directories");
        for (int i = 0; i < directories.length(); ++i) {
            throwIfStopRequested();
            String relative = directories.getString(i);
            validateRelativePath(relative);
            expectedDirectories.add(relative);
            File directory = new File(systemRoot, relative);
            if (!OsConstants.S_ISDIR(lstatMode(directory)))
                throw new IOException("guest system directory missing: " + relative);
        }

        JSONArray files = manifest.getJSONArray("files");
        long sourceBytes = 0;
        int sourceFileCount = 0;
        for (int i = 0; i < files.length(); ++i) {
            throwIfStopRequested();
            JSONObject item = files.getJSONObject(i);
            String relative = item.getString("path");
            String kind = item.getString("kind");
            validateRelativePath(relative);
            long size = item.getLong("size");
            String digest = item.getString("sha256");
            sourceBytes += size;
            sourceFileCount++;
            if ("asset".equals(kind)) {
                expectedFiles.add(relative);
                verifyRegularFile(new File(systemRoot, relative), size, digest, false);
            } else {
                expectedLinks.add(relative);
                String nativeName = item.getString("native");
                validateRelativePath(nativeName);
                File nativeFile = new File(guestLibraryDir, nativeName);
                verifyRegularFile(nativeFile, size, digest, true);
                if (item.has("dynamic_native")) {
                    String dynamicNative = item.getString("dynamic_native");
                    validateRelativePath(dynamicNative);
                    File dynamicFile = new File(guestLibraryDir, dynamicNative);
                    verifyRegularFile(dynamicFile, item.getLong("dynamic_size"),
                            item.getString("dynamic_sha256"), true);
                    if (!isArm32Executable(dynamicFile) ||
                            !"/system/bin/linker".equals(item.getString("dynamic_interpreter_original")) ||
                            !"/proc/self/fd/198".equals(item.getString("dynamic_interpreter_patched")))
                        throw new IOException("invalid guest-linker executable alias: " + dynamicNative);
                }
                verifySymlink(new File(systemRoot, relative), nativeFile.getAbsolutePath());
            }
        }
        if (sourceBytes != manifest.getLong("regular_file_bytes") ||
            sourceFileCount != manifest.getInt("regular_file_count"))
            throw new IOException("guest source file count/size does not match manifest");
        if (manifest.getLong("app_private_asset_bytes") !=
            sumAssetBytes(files)) throw new IOException("app-private asset bytes do not match manifest");

        JSONArray symlinks = manifest.getJSONArray("symlinks");
        if (symlinks.length() != manifest.getInt("symlink_count"))
            throw new IOException("guest symlink count does not match manifest");
        for (int i = 0; i < symlinks.length(); ++i) {
            throwIfStopRequested();
            JSONArray item = symlinks.getJSONArray(i);
            String relative = item.getString(0);
            validateRelativePath(relative);
            expectedLinks.add(relative);
            verifySymlink(new File(systemRoot, relative),
                    resolveGuestSymlinkTarget(systemRoot, relative, item.getString(1)));
        }

        Set<String> actualDirectories = new HashSet<>();
        Set<String> actualFiles = new HashSet<>();
        Set<String> actualLinks = new HashSet<>();
        collectGuestSystemTree(systemRoot, systemRoot, actualDirectories, actualFiles, actualLinks);
        if (!expectedDirectories.equals(actualDirectories) || !expectedFiles.equals(actualFiles) ||
            !expectedLinks.equals(actualLinks))
            throw new IOException("guest /system tree paths differ from the verified source manifest");
    }

    private long sumAssetBytes(JSONArray files) throws IOException, JSONException {
        long total = 0;
        for (int i = 0; i < files.length(); ++i) {
            throwIfStopRequested();
            JSONObject item = files.getJSONObject(i);
            if ("asset".equals(item.getString("kind"))) total += item.getLong("size");
        }
        return total;
    }

    private void collectGuestSystemTree(File root, File directory, Set<String> directories,
                                        Set<String> files, Set<String> links)
            throws IOException {
        throwIfStopRequested();
        File[] children = directory.listFiles();
        if (children == null) throw new IOException("cannot list staged system directory " + directory);
        String prefix = root.getAbsolutePath() + File.separator;
        for (File child : children) {
            throwIfStopRequested();
            String absolute = child.getAbsolutePath();
            if (!absolute.startsWith(prefix)) throw new IOException("system path escaped staged root");
            String relative = absolute.substring(prefix.length()).replace(File.separatorChar, '/');
            int mode = lstatMode(child);
            if (OsConstants.S_ISDIR(mode)) {
                directories.add(relative);
                collectGuestSystemTree(root, child, directories, files, links);
            } else if (OsConstants.S_ISREG(mode)) {
                files.add(relative);
            } else if (OsConstants.S_ISLNK(mode)) {
                links.add(relative);
            } else {
                throw new IOException("unexpected special file in guest system: " + relative);
            }
        }
    }

    private void verifyRegularFile(File file, long size, String expectedSha256, boolean executable)
            throws IOException {
        if (!OsConstants.S_ISREG(lstatMode(file)) || file.length() != size ||
            (executable && !file.canExecute()) || !expectedSha256.equals(sha256(file)))
            throw new IOException("guest payload mismatch: " + file.getName());
    }

    private void verifySymlink(File link, String expectedTarget) throws IOException {
        if (!OsConstants.S_ISLNK(lstatMode(link)) || !expectedTarget.equals(readLink(link)))
            throw new IOException("guest symlink mismatch: " + link.getAbsolutePath());
    }

    private int lstatMode(File file) throws IOException {
        try {
            return Os.lstat(file.getAbsolutePath()).st_mode;
        } catch (ErrnoException e) {
            throw new IOException("cannot inspect guest path " + file, e);
        }
    }

    private String readLink(File link) throws IOException {
        try {
            return Os.readlink(link.getAbsolutePath());
        } catch (ErrnoException e) {
            throw new IOException("cannot read guest symlink " + link, e);
        }
    }

    private String sha256(File file) throws IOException {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            try (InputStream in = new FileInputStream(file)) {
                byte[] buffer = new byte[32768];
                int n;
                while ((n = in.read(buffer)) >= 0) {
                    throwIfStopRequested();
                    digest.update(buffer, 0, n);
                }
            }
            return toHex(digest.digest());
        } catch (NoSuchAlgorithmException e) {
            throw new IOException("SHA-256 is unavailable", e);
        }
    }

    private String sha256(byte[] bytes) throws IOException {
        try {
            return toHex(MessageDigest.getInstance("SHA-256").digest(bytes));
        } catch (NoSuchAlgorithmException e) {
            throw new IOException("SHA-256 is unavailable", e);
        }
    }

    private String toHex(byte[] bytes) {
        StringBuilder result = new StringBuilder(bytes.length * 2);
        for (byte value : bytes) result.append(String.format(java.util.Locale.US, "%02x", value & 0xff));
        return result.toString();
    }

    private void restoreSystemSymlinks(File systemRoot) throws IOException, JSONException {
        JSONArray links = new JSONArray(readAssetText("api10-system-symlinks.json"));
        for (int i = 0; i < links.length(); ++i) {
            throwIfStopRequested();
            JSONArray item = links.getJSONArray(i);
            String relative = item.getString(0);
            String target = item.getString(1);
            validateRelativePath(relative);
            File link = new File(systemRoot, relative);
            ensureDirectory(link.getParentFile());
            if (link.exists()) deleteRecursively(link);
            String hostTarget = resolveGuestSymlinkTarget(systemRoot, relative, target);
            try {
                Os.symlink(hostTarget, link.getAbsolutePath());
            } catch (ErrnoException e) {
                throw new IOException("cannot restore confined system symlink " + relative + " -> " + target, e);
            }
        }
    }

    private void restoreSystemAssetNames(File systemRoot, JSONObject manifest) throws IOException, JSONException {
        JSONArray files = manifest.getJSONArray("files");
        for (int i = 0; i < files.length(); ++i) {
            throwIfStopRequested();
            JSONObject item = files.getJSONObject(i);
            if (!"asset".equals(item.getString("kind"))) continue;
            String original = item.getString("path");
            String assetPath = item.optString("asset_path", original);
            if (assetPath.equals(original)) continue;
            validateRelativePath(original);
            validateRelativePath(assetPath);
            File staged = new File(systemRoot, assetPath);
            File restored = new File(systemRoot, original);
            if (!staged.isFile()) throw new IOException("staged APK asset missing: " + assetPath);
            ensureDirectory(restored.getParentFile());
            if (restored.exists()) deleteRecursively(restored);
            if (!staged.renameTo(restored)) throw new IOException("cannot restore original system filename: " + original);
        }
    }

    private void installNativeSystemPayloads(File systemRoot, File guestLibraryDir)
            throws IOException, JSONException {
        File nativeLinker = new File(guestLibraryDir, "libgingervm_guest_linker.so");
        if (!nativeLinker.isFile() || !nativeLinker.canExecute()) throw new IOException("extracted guest linker is not executable");
        replaceWithNativeSymlink(systemRoot, "bin/linker", nativeLinker);

        JSONArray libraries = new JSONArray(readAssetText("api10-system-native-libraries.json"));
        for (int i = 0; i < libraries.length(); ++i) {
            throwIfStopRequested();
            JSONObject item = libraries.getJSONObject(i);
            replaceWithNativeSymlink(systemRoot, item.getString("path"),
                    new File(guestLibraryDir, item.getString("native")));
        }

        JSONArray executables = new JSONArray(readAssetText("api10-system-native-executables.json"));
        for (int i = 0; i < executables.length(); ++i) {
            throwIfStopRequested();
            JSONObject item = executables.getJSONObject(i);
            replaceWithNativeSymlink(systemRoot, item.getString("path"),
                    new File(guestLibraryDir, item.getString("native")));
        }
    }

    private void replaceWithNativeSymlink(File systemRoot, String relative, File nativeFile) throws IOException {
        validateRelativePath(relative);
        if (!nativeFile.isFile() || !nativeFile.canExecute())
            throw new IOException("APK-extracted guest payload is missing/not executable: " + nativeFile.getName());
        File destination = new File(systemRoot, relative);
        ensureDirectory(destination.getParentFile());
        deleteRecursively(destination);
        try {
            Os.symlink(nativeFile.getAbsolutePath(), destination.getAbsolutePath());
        } catch (ErrnoException e) {
            throw new IOException("cannot create APK-native guest payload link for " + relative, e);
        }
    }

    private String resolveGuestSymlinkTarget(File systemRoot, String relative, String target) throws IOException {
        if (target.length() == 0 || target.indexOf('\u0000') >= 0) throw new IOException("invalid symlink target");
        ArrayList<String> parts = new ArrayList<>();
        if (target.startsWith("/")) {
            if (target.equals("/system")) {
                parts.add(".images");
                parts.add("system");
            } else if (target.startsWith("/system/")) {
                parts.add(".images");
                parts.add("system");
                addNormalizedParts(parts, target.substring("/system/".length()), true);
            } else {
                addNormalizedParts(parts, target.substring(1), true);
            }
        } else {
            parts.add(".images");
            parts.add("system");
            String parent = relative.contains("/") ? relative.substring(0, relative.lastIndexOf('/')) : "";
            addNormalizedParts(parts, parent, false);
            addNormalizedParts(parts, target, false);
        }
        String root = systemRoot.getAbsoluteFile().getParentFile().getParentFile().getCanonicalPath();
        StringBuilder output = new StringBuilder(root);
        for (String part : parts) output.append('/').append(part);
        String host = output.toString();
        String canonicalRoot = new File(root).getCanonicalPath();
        if (!host.equals(canonicalRoot) && !host.startsWith(canonicalRoot + File.separator))
            throw new IOException("system symlink escapes app-private guest root");
        return host;
    }

    private void addNormalizedParts(ArrayList<String> parts, String path, boolean absolute) throws IOException {
        for (String part : path.split("/")) {
            if (part.length() == 0 || part.equals(".")) continue;
            if (part.equals("..")) {
                if (parts.isEmpty()) {
                    if (absolute) continue;
                    throw new IOException("relative symlink escapes guest root");
                }
                parts.remove(parts.size() - 1);
            } else {
                parts.add(part);
            }
        }
    }

    private void validateRelativePath(String path) throws IOException {
        if (path == null || path.length() == 0 || path.startsWith("/") || path.indexOf('\u0000') >= 0)
            throw new IOException("invalid guest-relative path");
        for (String part : path.split("/")) {
            if (part.length() == 0 || part.equals(".") || part.equals(".."))
                throw new IOException("unsafe guest-relative path: " + path);
        }
    }

    private void ensureDirectory(File directory) throws IOException {
        if (directory == null || (!directory.mkdirs() && !directory.isDirectory()))
            throw new IOException("cannot create app-private directory " + directory);
    }

    private File findExtractedAbiLibraryDir(File primaryNativeLibraryDir, String libraryName) {
        ArrayList<File> candidates = new ArrayList<>();
        addLibrarySearchDirectories(primaryNativeLibraryDir, 1, candidates);
        addLibrarySearchDirectories(primaryNativeLibraryDir == null ? null : primaryNativeLibraryDir.getParentFile(), 3, candidates);
        File source = new File(getApplicationInfo().sourceDir);
        addLibrarySearchDirectories(source.getParentFile(), 4, candidates);
        String[] splits = getApplicationInfo().splitSourceDirs;
        if (splits != null) {
            for (String split : splits) addLibrarySearchDirectories(new File(split).getParentFile(), 4, candidates);
        }
        for (File candidate : candidates) {
            if (isArm32Executable(new File(candidate, libraryName))) return candidate;
        }
        return null;
    }

    private void addLibrarySearchDirectories(File directory, int depth, ArrayList<File> candidates) {
        if (directory == null || depth < 0) return;
        try {
            if (!OsConstants.S_ISDIR(Os.lstat(directory.getAbsolutePath()).st_mode)) return;
            String canonical = directory.getCanonicalPath();
            for (File existing : candidates)
                if (existing.getCanonicalPath().equals(canonical)) return;
            candidates.add(directory);
            if (depth == 0) return;
            File[] children = directory.listFiles();
            if (children == null) return;
            for (File child : children) {
                try {
                    if (OsConstants.S_ISDIR(Os.lstat(child.getAbsolutePath()).st_mode))
                        addLibrarySearchDirectories(child, depth - 1, candidates);
                } catch (ErrnoException ignored) { }
            }
        } catch (IOException | ErrnoException ignored) { }
    }

    private boolean isArm32Executable(File file) {
        if (!file.isFile() || !file.canExecute()) return false;
        try (InputStream in = new FileInputStream(file)) {
            byte[] header = new byte[20];
            int offset = 0;
            while (offset < header.length) {
                int n = in.read(header, offset, header.length - offset);
                if (n < 0) return false;
                offset += n;
            }
            return header[0] == 0x7f && header[1] == 'E' && header[2] == 'L' && header[3] == 'F'
                    && header[4] == 1 && header[5] == 1
                    && (header[18] & 0xff) == 40 && (header[19] & 0xff) == 0;
        } catch (IOException e) {
            return false;
        }
    }

    private void copyAssetTree(String assetPath, File destination) throws IOException {
        throwIfStopRequested();
        String[] children = getAssets().list(assetPath);
        if (children == null) children = new String[0];
        boolean directory = "api10-system".equals(assetPath) || knownSystemAssetDirectories.contains(assetPath)
                || (children != null && children.length > 0);
        if (directory) {
            ensureDirectory(destination);
            for (String child : children) {
                throwIfStopRequested();
                if (assetPath.equals("api10-init-root")
                        && (child.equals("STAGING-NOTE.txt") || child.equals("ASSET-FILES.txt"))) continue;
                copyAssetTree(assetPath + "/" + child, new File(destination, child));
            }
            return;
        }
        try (InputStream in = getAssets().open(assetPath)) {
            File parent = destination.getParentFile();
            if (parent != null && !parent.mkdirs() && !parent.isDirectory()) throw new IOException("cannot create " + parent);
            try (FileOutputStream stream = new FileOutputStream(destination)) {
                byte[] buffer = new byte[16384];
                int n;
                while ((n = in.read(buffer)) >= 0) {
                    throwIfStopRequested();
                    stream.write(buffer, 0, n);
                }
            }
        }
    }

    private void copyAssetFile(String assetPath, File destination) throws IOException {
        File parent = destination.getParentFile();
        if (parent != null && !parent.mkdirs() && !parent.isDirectory()) throw new IOException("cannot create " + parent);
        try (InputStream in = getAssets().open(assetPath); FileOutputStream stream = new FileOutputStream(destination)) {
            byte[] buffer = new byte[16384];
            int n;
            while ((n = in.read(buffer)) >= 0) {
                throwIfStopRequested();
                stream.write(buffer, 0, n);
            }
        }
    }

    private String readAssetText(String assetPath) throws IOException {
        try (InputStream in = getAssets().open(assetPath); ByteArrayOutputStream out = new ByteArrayOutputStream()) {
            byte[] buffer = new byte[16384];
            int n;
            while ((n = in.read(buffer)) >= 0) out.write(buffer, 0, n);
            return new String(out.toByteArray(), StandardCharsets.UTF_8);
        }
    }

    private String readFileText(File file) throws IOException {
        try (InputStream in = new FileInputStream(file); ByteArrayOutputStream out = new ByteArrayOutputStream()) {
            byte[] buffer = new byte[4096];
            int n;
            while ((n = in.read(buffer)) >= 0) out.write(buffer, 0, n);
            return new String(out.toByteArray(), StandardCharsets.UTF_8);
        }
    }

    private void deleteRecursively(File file) throws IOException {
        AppPrivateTreeCleanup.deleteRecursively(file, new AppPrivateTreeCleanup.Operations() {
            @Override
            public AppPrivateTreeCleanup.Node lstat(File path) throws IOException {
                return lstatForCleanup(path);
            }

            @Override
            public void makeDirectoryListable(File directory, AppPrivateTreeCleanup.Node expected)
                    throws IOException {
                AppPrivateTreeCleanup.Node current = lstatForCleanup(directory);
                if (current == null) return;
                requireSameCleanupDirectory(directory, expected, current);
                try {
                    int ownerAccess = OsConstants.S_IRUSR | OsConstants.S_IWUSR | OsConstants.S_IXUSR;
                    Os.chmod(directory.getAbsolutePath(), (current.mode & 07777) | ownerAccess);
                } catch (ErrnoException e) {
                    throw new IOException("cannot restore app access to app-private directory " + directory, e);
                }
            }

            @Override
            public String[] list(File directory, AppPrivateTreeCleanup.Node expected) throws IOException {
                FileDescriptor descriptor = null;
                try {
                    descriptor = Os.open(directory.getAbsolutePath(), OsConstants.O_RDONLY
                            | OsConstants.O_NOFOLLOW | OsConstants.O_CLOEXEC, 0);
                    requireSameCleanupDirectory(directory, expected, cleanupNode(Os.fstat(descriptor)));
                    String[] children = directory.list();
                    requireSameCleanupDirectory(directory, expected, lstatForCleanup(directory));
                    return children;
                } catch (ErrnoException e) {
                    if (e.errno == OsConstants.ENOENT) return new String[0];
                    throw new IOException("cannot open app-private directory without following symlinks "
                            + directory, e);
                } finally {
                    if (descriptor != null) {
                        try {
                            Os.close(descriptor);
                        } catch (ErrnoException ignored) { }
                    }
                }
            }

            @Override
            public void remove(File path) throws IOException {
                try {
                    Os.remove(path.getAbsolutePath());
                } catch (ErrnoException e) {
                    if (e.errno != OsConstants.ENOENT)
                        throw new IOException("cannot remove app-private path " + path, e);
                }
            }
        }, new AppPrivateTreeCleanup.CancellationCheck() {
            @Override
            public void check() throws IOException {
                throwIfStopRequested();
            }
        });
    }

    private AppPrivateTreeCleanup.Node lstatForCleanup(File path) throws IOException {
        try {
            return cleanupNode(Os.lstat(path.getAbsolutePath()));
        } catch (ErrnoException e) {
            if (e.errno == OsConstants.ENOENT) return null;
            throw new IOException("cannot lstat app-private path " + path, e);
        }
    }

    private AppPrivateTreeCleanup.Node cleanupNode(StructStat stat) {
        return new AppPrivateTreeCleanup.Node(OsConstants.S_ISDIR(stat.st_mode),
                OsConstants.S_ISLNK(stat.st_mode), stat.st_mode,
                stat.st_dev + ":" + stat.st_ino);
    }

    private static void requireSameCleanupDirectory(File path, AppPrivateTreeCleanup.Node expected,
                                                     AppPrivateTreeCleanup.Node actual) throws IOException {
        if (actual == null || actual.symbolicLink || !actual.directory || !expected.sameObject(actual))
            throw new IOException("app-private directory changed during cleanup; refusing to follow " + path);
    }
}
