package dev.gingervm.nativeprobe;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.IOException;

public final class GuestFramePacketTest {
    private GuestFramePacketTest() { }

    public static void main(String[] args) throws Exception {
        require(args.length == 1, "expected native frame packet path");
        byte[] packet = readAll(args[0]);
        GuestFramePacket.Frame frame = GuestFramePacket.decodeGuestFramebuffer(packet);
        require(frame.width == 2 && frame.height == 2 && frame.sequence == 7,
                "native packet dimensions/sequence did not round-trip");
        require(frame.argb.length == 4, "wrong decoded pixel count");
        require(frame.argb[0] == 0xffff0000, "red RGB565 conversion failed");
        require(frame.argb[1] == 0xff00ff00, "green RGB565 conversion failed");
        require(frame.argb[2] == 0xff0000ff, "blue RGB565 conversion failed");
        require(frame.argb[3] == 0xffffffff, "white RGB565 conversion failed");

        byte[] changed = packet.clone();
        changed[64] ^= 1;
        rejects(changed, "payload checksum mismatch must fail closed");
        changed = packet.clone();
        changed[8] = (byte) GuestFramePacket.SOURCE_TEST_ONLY;
        rejects(changed, "test-only frame source must never be accepted by the renderer");
        changed = packet.clone();
        changed[12] = 0;
        changed[13] = 0;
        changed[14] = 0;
        changed[15] = 0;
        rejects(changed, "zero width must be rejected");
        changed = packet.clone();
        changed[20] = 2;
        changed[21] = 0;
        changed[22] = 0;
        changed[23] = 0;
        rejects(changed, "stride smaller than a row must be rejected");
        changed = packet.clone();
        changed[24] = 24;
        rejects(changed, "unsupported pixel format must be rejected");
        changed = packet.clone();
        changed[30] = 2;
        rejects(changed, "invalid msb_right must be rejected");
        changed = new byte[GuestFramePacket.HEADER_BYTES + GuestFramePacket.MAX_PAYLOAD_BYTES + 1];
        rejects(changed, "oversized packets must be rejected before rendering");
        System.out.println("GuestFramePacketTest: PASS");
    }

    private static byte[] readAll(String path) throws IOException {
        try (FileInputStream in = new FileInputStream(path);
             ByteArrayOutputStream out = new ByteArrayOutputStream()) {
            byte[] buffer = new byte[8192];
            int count;
            while ((count = in.read(buffer)) >= 0) out.write(buffer, 0, count);
            return out.toByteArray();
        }
    }

    private static void rejects(byte[] packet, String message) throws Exception {
        try {
            GuestFramePacket.decodeGuestFramebuffer(packet);
        } catch (IOException expected) {
            return;
        }
        throw new AssertionError(message);
    }

    private static void require(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }
}
