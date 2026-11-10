package dev.gingervm.nativeprobe;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InterruptedIOException;
import java.nio.charset.StandardCharsets;

/** Captures merged supervisor output without losing bytes when a pipe read is interrupted. */
public final class TraceOutputCapture {
    public static final int MAX_CONSECUTIVE_INTERRUPTED_READS = 32;
    private static final int BUFFER_BYTES = 8192;

    public interface ChunkListener {
        void onText(String text);
    }

    public static final class Result {
        private final byte[] bytes;
        public final int recoveredInterruptedReads;
        public final String failure;

        private Result(byte[] bytes, int recoveredInterruptedReads, String failure) {
            this.bytes = bytes;
            this.recoveredInterruptedReads = recoveredInterruptedReads;
            this.failure = failure;
        }

        public String text() {
            return new String(bytes, StandardCharsets.UTF_8);
        }

        public Result withFailure(String extra) {
            if (extra == null || extra.isEmpty()) return this;
            String combined = failure == null ? extra : failure + "; " + extra;
            return new Result(bytes, recoveredInterruptedReads, combined);
        }

        public static Result failure(String message) {
            return new Result(new byte[0], 0, message);
        }
    }

    public static final class CaptureSession {
        private final ByteArrayOutputStream captured = new ByteArrayOutputStream();
        private int recoveredInterruptedReads;
        private String failure;
        private boolean sealed;

        public Result readToEof(InputStream input, ChunkListener listener) {
            byte[] buffer = new byte[BUFFER_BYTES];
            int consecutiveInterrupted = 0;
            for (;;) {
                final int count;
                try {
                    count = input.read(buffer, 0, buffer.length);
                } catch (InterruptedIOException e) {
                    int transferred = Math.max(0, Math.min(e.bytesTransferred, buffer.length));
                    if (transferred > 0) append(buffer, transferred, listener);
                    Thread.interrupted();
                    synchronized (this) { ++recoveredInterruptedReads; }
                    if (++consecutiveInterrupted > MAX_CONSECUTIVE_INTERRUPTED_READS) {
                        return finish("too many consecutive interrupted pipe reads");
                    }
                    try {
                        Thread.sleep(5L);
                    } catch (InterruptedException ignored) {
                        Thread.interrupted();
                    }
                    continue;
                } catch (IOException e) {
                    return finish(e.getClass().getSimpleName() + ": " + e.getMessage());
                }
                if (count < 0) return finish(null);
                if (count == 0) {
                    Thread.yield();
                    continue;
                }
                append(buffer, count, listener);
                consecutiveInterrupted = 0;
            }
        }

        private void append(byte[] buffer, int count, ChunkListener listener) {
            synchronized (this) {
                if (sealed) return;
                captured.write(buffer, 0, count);
            }
            if (listener != null) {
                try {
                    listener.onText(new String(buffer, 0, count, StandardCharsets.UTF_8));
                } catch (RuntimeException ignored) {
                    // A live UI update must never interrupt the full byte capture.
                }
            }
        }

        private synchronized Result finish(String error) {
            if (!sealed) {
                failure = error;
                sealed = true;
            }
            return snapshotLocked();
        }

        public synchronized Result failAndSeal(String error) {
            if (!sealed) {
                failure = error;
                sealed = true;
            }
            return snapshotLocked();
        }

        public synchronized Result snapshot() {
            return snapshotLocked();
        }

        private Result snapshotLocked() {
            return new Result(captured.toByteArray(), recoveredInterruptedReads, failure);
        }
    }

    private TraceOutputCapture() {}

    public static Result readToEof(InputStream input, ChunkListener listener) {
        return new CaptureSession().readToEof(input, listener);
    }
}
