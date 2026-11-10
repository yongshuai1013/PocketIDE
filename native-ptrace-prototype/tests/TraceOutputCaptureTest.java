package dev.gingervm.nativeprobe;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InterruptedIOException;
import java.nio.charset.StandardCharsets;

public final class TraceOutputCaptureTest {
    private static final class Step {
        final byte[] bytes;
        final boolean interrupted;
        Step(String text, boolean interrupted) {
            this.bytes = text.getBytes(StandardCharsets.UTF_8);
            this.interrupted = interrupted;
        }
    }

    private static final class ScriptedInput extends InputStream {
        private final Step[] steps;
        private int index;
        private final boolean interruptForever;

        ScriptedInput(boolean interruptForever, Step... steps) {
            this.interruptForever = interruptForever;
            this.steps = steps;
        }

        @Override public int read() throws IOException {
            byte[] one = new byte[1];
            int count = read(one, 0, 1);
            return count < 0 ? -1 : one[0] & 0xff;
        }

        @Override public int read(byte[] out, int offset, int length) throws IOException {
            if (interruptForever) throw new InterruptedIOException("read interrupted");
            if (index >= steps.length) return -1;
            Step step = steps[index++];
            int count = Math.min(step.bytes.length, length);
            System.arraycopy(step.bytes, 0, out, offset, count);
            if (step.interrupted) {
                InterruptedIOException e = new InterruptedIOException("read interrupted");
                e.bytesTransferred = count;
                throw e;
            }
            return count == 0 ? -1 : count;
        }
    }

    private static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }

    public static void main(String[] args) {
        StringBuilder live = new StringBuilder();
        Thread.currentThread().interrupt();
        TraceOutputCapture.Result result = TraceOutputCapture.readToEof(
                new ScriptedInput(false,
                        new Step("head\n", false),
                        new Step("part", true),
                        new Step("tail\n", false)), live::append);
        check(!Thread.currentThread().isInterrupted(), "interrupted read should be cleared before retry");
        check(result.failure == null, "transient interruption should recover to EOF: " + result.failure);
        check(result.recoveredInterruptedReads == 1, "expected exactly one recovered read");
        check("head\nparttail\n".equals(result.text()), "full bytes including partial transfer were not preserved");
        check(result.text().equals(live.toString()), "live output chunks differ from captured output");

        TraceOutputCapture.Result bounded = TraceOutputCapture.readToEof(
                new ScriptedInput(true), null);
        check(bounded.failure != null && bounded.failure.contains("too many consecutive"),
                "repeated interrupted reads must terminate with an explicit incomplete-capture error");
        check(bounded.recoveredInterruptedReads == TraceOutputCapture.MAX_CONSECUTIVE_INTERRUPTED_READS + 1,
                "interruption retry bound was not enforced");

        TraceOutputCapture.Result ordinaryError = TraceOutputCapture.readToEof(
                new ByteArrayInputStream("ok".getBytes(StandardCharsets.UTF_8)), null);
        check(ordinaryError.failure == null && "ok".equals(ordinaryError.text()), "ordinary EOF capture failed");
        System.out.println("TraceOutputCapture regression: PASS (InterruptedIOException retried, partial bytes preserved, bounded failure explicit)");
    }
}
