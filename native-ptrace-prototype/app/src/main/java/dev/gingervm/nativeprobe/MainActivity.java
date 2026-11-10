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
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
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

    private final Set<String> knownSystemAssetDirectories = new HashSet<>();
    private TextView report;
    private Button guestButton;
    private Button exportButton;
    private File latestLogFile;

    @Override
    public void onCreate(Bundle state) {
        super.onCreate(state);
        buildUi();
        latestLogFile = new File(getCacheDir(), LOG_FILE_NAME);
        exportButton.setEnabled(hasExportableLog());
        report.setText("GingerVM Android guest: continuous init process-tree trace\n\n"
                + "Stages the original Google SDK API 10 / Android 2.3.7 ARMv7 ramdisk and complete matching /system tree. Starts the original static /init once and follows its fork/clone/exec descendants in the same bounded ptrace session. Dynamic ELF copies change only PT_INTERP to the original guest linker inherited as fd 198; the host Android linker is not substituted.\n"
                + "This is not a claim of a complete boot or desktop. Guest mount/device/identity operations are software-only; no host root or host mount is used.\n\n"
                + "Host ABI: " + Arrays.toString(Build.SUPPORTED_ABIS) + "\n"
                + "64-bit app process: " + Process.is64Bit() + "\n"
                + "Android API: " + Build.VERSION.SDK_INT + "\n"
                + "No guest smoke trace has been recorded yet.");
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

        exportButton = new Button(this);
        exportButton.setText("分享／儲存完整追蹤日誌");
        exportButton.setEnabled(false);
        root.addView(exportButton, new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT));

        ScrollView scroll = new ScrollView(this);
        report = new TextView(this);
        report.setTextSize(14);
        report.setTextIsSelectable(true);
        report.setPadding(0, 20, 0, 0);
        scroll.addView(report);
        root.addView(scroll, new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, 0, 1f));
        setContentView(root);

        guestButton.setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View view) { startRun(); }
        });
        exportButton.setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View view) { showLogExportOptions(); }
        });
    }

    private void startRun() {
        guestButton.setEnabled(false);
        exportButton.setEnabled(false);
        report.setText("Preparing the complete Google API10 guest image; about 106 MiB of userland and linker aliases are staged across app-private storage and extracted ARM32 libraries…\n");
        new Thread(new Runnable() {
            @Override public void run() {
                String result;
                try {
                    result = executeGuestEnvironmentTest();
                } catch (Exception e) {
                    result = "TRACE FAILED: " + e + "\n";
                }
                IOException writeFailure = null;
                try {
                    writeLatestLog(result);
                } catch (IOException e) {
                    writeFailure = e;
                }
                final IOException finalWriteFailure = writeFailure;
                final String finalResult = writeFailure == null ? result : result
                        + "\nLOG EXPORT PREPARATION FAILED: " + writeFailure + "\n";
                runOnUiThread(new Runnable() {
                    @Override public void run() {
                        report.setText(finalResult);
                        guestButton.setEnabled(true);
                        exportButton.setEnabled(finalWriteFailure == null && hasExportableLog());
                    }
                });
            }
        }, "guest-init-process-tree").start();
    }

    private boolean hasExportableLog() {
        return latestLogFile != null && latestLogFile.isFile() && latestLogFile.length() > 0;
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

    private String executeGuestEnvironmentTest() {
        StringBuilder out = new StringBuilder();
        out.append("GingerVM continuous Android 2.3.7/API 10 init process-tree trace\n");
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
            return header.append("START FAILED: ").append(e).append('\n').toString();
        }
        final java.lang.Process child = process;
        final ByteArrayOutputStream captured = new ByteArrayOutputStream();
        final AtomicReference<String> readerFailure = new AtomicReference<>();
        Thread reader = new Thread(new Runnable() {
            @Override public void run() {
                try (InputStream in = child.getInputStream()) {
                    byte[] buffer = new byte[4096];
                    int n;
                    while ((n = in.read(buffer)) >= 0) {
                        captured.write(buffer, 0, n);
                    }
                } catch (Exception e) { readerFailure.set(e.toString()); }
            }
        }, "guest-output-reader");
        reader.start();
        int exit = -1;
        boolean timedOut = false;
        try {
            if (!process.waitFor(timeoutSeconds, TimeUnit.SECONDS)) {
                timedOut = true;
                process.destroyForcibly();
                process.waitFor();
            }
            if (!timedOut) exit = process.exitValue();
            reader.join();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            process.destroyForcibly();
            return header.append("RUN INTERRUPTED: ").append(e).append('\n').toString();
        }
        String trace = new String(captured.toByteArray(), StandardCharsets.UTF_8);
        if (readerFailure.get() != null)
            trace += "\nOUTPUT CAPTURE ERROR: " + readerFailure.get() + "; exported log may be incomplete.\n";
        boolean guestLinkerEntered = trace.contains("GUEST DYNAMIC EXEC EVENT:");
        header.append(trace);
        if (timedOut) {
            header.append("\nAPP TIMEOUT: supervisor was stopped after ").append(timeoutSeconds).append(" seconds.\n");
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
        return header.toString();
    }

    private void appendProgress(StringBuilder output, String message) {
        output.append("\n=== ").append(message).append(" ===\n");
        postProgress(message + "…\n");
    }

    private void postProgress(final String message) {
        runOnUiThread(new Runnable() {
            @Override public void run() { report.append(message); }
        });
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

    private long sumAssetBytes(JSONArray files) throws JSONException {
        long total = 0;
        for (int i = 0; i < files.length(); ++i) {
            JSONObject item = files.getJSONObject(i);
            if ("asset".equals(item.getString("kind"))) total += item.getLong("size");
        }
        return total;
    }

    private void collectGuestSystemTree(File root, File directory, Set<String> directories,
                                        Set<String> files, Set<String> links)
            throws IOException {
        File[] children = directory.listFiles();
        if (children == null) throw new IOException("cannot list staged system directory " + directory);
        String prefix = root.getAbsolutePath() + File.separator;
        for (File child : children) {
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
                while ((n = in.read(buffer)) >= 0) digest.update(buffer, 0, n);
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
            JSONObject item = libraries.getJSONObject(i);
            replaceWithNativeSymlink(systemRoot, item.getString("path"),
                    new File(guestLibraryDir, item.getString("native")));
        }

        JSONArray executables = new JSONArray(readAssetText("api10-system-native-executables.json"));
        for (int i = 0; i < executables.length(); ++i) {
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
        String[] children = getAssets().list(assetPath);
        if (children == null) children = new String[0];
        boolean directory = "api10-system".equals(assetPath) || knownSystemAssetDirectories.contains(assetPath)
                || (children != null && children.length > 0);
        if (directory) {
            ensureDirectory(destination);
            for (String child : children) {
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
                while ((n = in.read(buffer)) >= 0) stream.write(buffer, 0, n);
            }
        }
    }

    private void copyAssetFile(String assetPath, File destination) throws IOException {
        File parent = destination.getParentFile();
        if (parent != null && !parent.mkdirs() && !parent.isDirectory()) throw new IOException("cannot create " + parent);
        try (InputStream in = getAssets().open(assetPath); FileOutputStream stream = new FileOutputStream(destination)) {
            byte[] buffer = new byte[16384];
            int n;
            while ((n = in.read(buffer)) >= 0) stream.write(buffer, 0, n);
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
        StructStat stat;
        try {
            stat = Os.lstat(file.getAbsolutePath());
        } catch (ErrnoException e) {
            if (e.errno == OsConstants.ENOENT) return;
            throw new IOException("cannot lstat app-private path " + file, e);
        }
        if (OsConstants.S_ISDIR(stat.st_mode)) {
            File[] children = file.listFiles();
            if (children == null) throw new IOException("cannot list app-private directory " + file);
            for (File child : children) deleteRecursively(child);
            try {
                Os.remove(file.getAbsolutePath());
            } catch (ErrnoException e) {
                throw new IOException("cannot remove app-private directory " + file, e);
            }
        } else {
            try {
                Os.remove(file.getAbsolutePath());
            } catch (ErrnoException e) {
                throw new IOException("cannot remove app-private path " + file, e);
            }
        }
    }
}
