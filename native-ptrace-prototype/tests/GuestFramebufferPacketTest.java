package dev.gingervm.nativeprobe;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.IOException;

public final class GuestFramebufferPacketTest {
    private GuestFramebufferPacketTest() { }

    public static void main(String[] args) throws Exception {
        require(args.length == 1, "expected native fb0 GVMF packet path");
        byte[] packet = readAll(args[0]);
        GuestFramePacket.Frame frame = GuestFramePacket.decodeGuestFramebuffer(packet);
        require(frame.width == 480 && frame.height == 800, "wrong guest fb0 resolution");
        require(frame.sequence == 1, "wrong guest page-flip sequence");
        require(frame.argb.length == 480 * 800, "wrong guest pixel count");
        require(frame.argb[0] == 0xffff0000, "guest RGB565 red pixel did not survive transport");
        require(frame.argb[1] == 0xff00ff00, "guest RGB565 green pixel did not survive transport");
        require(frame.argb[2] == 0xff0000ff, "guest RGB565 blue pixel did not survive transport");
        require(frame.argb[3] == 0xffffffff, "guest RGB565 white pixel did not survive transport");
        require(frame.argb[4] == 0xff000000, "untouched guest backing bytes were changed");
        System.out.println("GuestFramebufferPacketTest: PASS (native guest backing -> GVMF/1 -> Android Java RGB565 decoder)");
    }

    private static byte[] readAll(String path) throws IOException {
        try (FileInputStream in = new FileInputStream(path);
             ByteArrayOutputStream out = new ByteArrayOutputStream()) {
            byte[] buffer = new byte[32768];
            int count;
            while ((count = in.read(buffer)) >= 0) out.write(buffer, 0, count);
            return out.toByteArray();
        }
    }

    private static void require(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }
}
