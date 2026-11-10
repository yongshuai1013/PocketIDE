package dev.gingervm.nativeprobe;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.content.Context;
import android.database.Cursor;
import android.database.MatrixCursor;
import android.net.Uri;
import android.os.ParcelFileDescriptor;
import android.provider.OpenableColumns;

import java.io.File;
import java.io.FileNotFoundException;

public final class TraceLogProvider extends ContentProvider {
    private static final String FILE_NAME = "gingervm-guest-trace.txt";

    @Override public boolean onCreate() { return true; }

    private boolean isLatestLogUri(Uri uri) {
        Context context = getContext();
        return context != null
                && (context.getPackageName() + ".trace-logs").equals(uri.getAuthority())
                && uri.getPathSegments().size() == 1
                && "latest.txt".equals(uri.getPathSegments().get(0));
    }

    private File getLatestLog() {
        return new File(getContext().getCacheDir(), FILE_NAME);
    }

    @Override public String getType(Uri uri) {
        return isLatestLogUri(uri) ? "text/plain" : null;
    }

    @Override public Cursor query(Uri uri, String[] projection, String selection,
                                  String[] selectionArgs, String sortOrder) {
        if (!isLatestLogUri(uri)) return null;
        String[] columns = projection == null
                ? new String[]{OpenableColumns.DISPLAY_NAME, OpenableColumns.SIZE}
                : projection;
        MatrixCursor cursor = new MatrixCursor(columns, 1);
        File file = getLatestLog();
        Object[] row = new Object[columns.length];
        for (int i = 0; i < columns.length; ++i) {
            if (OpenableColumns.DISPLAY_NAME.equals(columns[i])) row[i] = FILE_NAME;
            else if (OpenableColumns.SIZE.equals(columns[i])) row[i] = file.isFile() ? file.length() : 0L;
        }
        cursor.addRow(row);
        return cursor;
    }

    @Override public ParcelFileDescriptor openFile(Uri uri, String mode) throws FileNotFoundException {
        if (!isLatestLogUri(uri) || !("r".equals(mode) || "rt".equals(mode)))
            throw new FileNotFoundException("only read access to the latest trace log is allowed");
        File file = getLatestLog();
        if (!file.isFile()) throw new FileNotFoundException("no completed trace log is available");
        return ParcelFileDescriptor.open(file, ParcelFileDescriptor.MODE_READ_ONLY);
    }

    @Override public Uri insert(Uri uri, ContentValues values) { return null; }
    @Override public int delete(Uri uri, String selection, String[] selectionArgs) { return 0; }
    @Override public int update(Uri uri, ContentValues values, String selection, String[] selectionArgs) { return 0; }
}
