package dev.gingervm.nativeprobe;

import java.io.IOException;
import java.util.zip.CRC32;

/** Decoder for bounded, atomically published guest framebuffer packets. */
public final class GuestFramePacket {
    public static final int HEADER_BYTES = 64;
    public static final String CHANNEL_DIRECTORY = "gingervm-display";
    public static final String CHANNEL_FILE = "latest.gvmf";
    public static final String CHANNEL_TEMP_FILE = "latest.gvmf.tmp";
    public static final String CHANNEL_ENVIRONMENT = "GINGERVM_GUEST_FRAME_DIR";
    public static final int MAX_WIDTH = 4096;
    public static final int MAX_HEIGHT = 4096;
    public static final long MAX_PIXELS = 2097152L;
    public static final int MAX_PAYLOAD_BYTES = 8388608;
    public static final int SOURCE_GUEST_FRAMEBUFFER = 1;
    public static final int SOURCE_TEST_ONLY = 2;

    private GuestFramePacket() { }

    public static final class Frame {
        public final int width;
        public final int height;
        public final long sequence;
        public final int[] argb;

        private Frame(int width, int height, long sequence, int[] argb) {
            this.width = width;
            this.height = height;
            this.sequence = sequence;
            this.argb = argb;
        }
    }

    public static Frame decodeGuestFramebuffer(byte[] packet) throws IOException {
        if (packet == null || packet.length < HEADER_BYTES)
            throw new IOException("guest frame packet is shorter than its header");
        if (packet[0] != 'G' || packet[1] != 'V' || packet[2] != 'M' || packet[3] != 'F')
            throw new IOException("guest frame magic mismatch");
        if (u16(packet, 4) != 1 || u16(packet, 6) != HEADER_BYTES)
            throw new IOException("unsupported guest frame protocol version/header");
        if (u32(packet, 8) != SOURCE_GUEST_FRAMEBUFFER)
            throw new IOException("frame source is not a guest framebuffer");

        long widthLong = u32(packet, 12);
        long heightLong = u32(packet, 16);
        long strideLong = u32(packet, 20);
        int bpp = u8(packet[24]);
        if (u8(packet[25]) != 1 || u16(packet, 26) != 0 || u32(packet, 60) != 0)
            throw new IOException("unsupported guest pixel byte order or reserved bits");
        if (widthLong == 0 || heightLong == 0 || widthLong > MAX_WIDTH || heightLong > MAX_HEIGHT ||
                widthLong * heightLong > MAX_PIXELS)
            throw new IOException("guest frame dimensions exceed the bounded viewport limits");
        if (bpp != 16 && bpp != 32)
            throw new IOException("unsupported guest framebuffer bits-per-pixel");
        int width = (int) widthLong;
        int height = (int) heightLong;
        int bytesPerPixel = bpp / 8;
        if (strideLong < widthLong * bytesPerPixel || strideLong > 65536)
            throw new IOException("invalid guest framebuffer row stride");
        int stride = (int) strideLong;

        int[] red = channel(packet, 28, bpp, true);
        int[] green = channel(packet, 32, bpp, true);
        int[] blue = channel(packet, 36, bpp, true);
        int[] alpha = channel(packet, 40, bpp, false);
        long used = mask(red) | mask(green) | mask(blue) | mask(alpha);
        if ((mask(red) & mask(green)) != 0 || (mask(red) & mask(blue)) != 0 ||
                (mask(green) & mask(blue)) != 0 || (mask(alpha) & (mask(red) | mask(green) | mask(blue))) != 0 ||
                (alpha[1] == 0 && alpha[0] != 0) || used == 0)
            throw new IOException("overlapping or invalid guest framebuffer color channels");

        long payloadLong = u32(packet, 44);
        long expectedPayload = strideLong * heightLong;
        if (payloadLong != expectedPayload || payloadLong > MAX_PAYLOAD_BYTES ||
                packet.length != HEADER_BYTES + (int) payloadLong)
            throw new IOException("guest frame payload length is invalid or exceeds bounds");
        long sequence = u64(packet, 48);
        if (sequence <= 0) throw new IOException("guest frame sequence must be positive");
        CRC32 crc = new CRC32();
        crc.update(packet, HEADER_BYTES, (int) payloadLong);
        if (crc.getValue() != u32(packet, 56))
            throw new IOException("guest frame payload checksum mismatch");

        int[] pixels = new int[(int) (widthLong * heightLong)];
        int out = 0;
        for (int y = 0; y < height; ++y) {
            int row = HEADER_BYTES + y * stride;
            for (int x = 0; x < width; ++x) {
                int at = row + x * bytesPerPixel;
                long value = u8(packet[at]) | ((long) u8(packet[at + 1]) << 8);
                if (bytesPerPixel == 4) {
                    value |= ((long) u8(packet[at + 2]) << 16) | ((long) u8(packet[at + 3]) << 24);
                }
                int r = expand(value, red);
                int g = expand(value, green);
                int b = expand(value, blue);
                int a = alpha[1] == 0 ? 255 : expand(value, alpha);
                pixels[out++] = (a << 24) | (r << 16) | (g << 8) | b;
            }
        }
        return new Frame(width, height, sequence, pixels);
    }

    private static int[] channel(byte[] packet, int offset, int bpp, boolean required) throws IOException {
        int bitOffset = u8(packet[offset]);
        int length = u8(packet[offset + 1]);
        int msbRight = u8(packet[offset + 2]);
        if (packet[offset + 3] != 0 || msbRight > 1)
            throw new IOException("invalid guest color bitfield flags");
        if (length == 0) {
            if (required || bitOffset != 0 || msbRight != 0)
                throw new IOException("required guest color channel is absent");
        } else if (length < 5 || length > 8 || bitOffset + length > bpp) {
            throw new IOException("guest color bitfield is outside pixel bounds");
        }
        return new int[]{bitOffset, length, msbRight};
    }

    private static long mask(int[] channel) {
        if (channel[1] == 0) return 0;
        return ((1L << channel[1]) - 1L) << channel[0];
    }

    private static int expand(long value, int[] channel) {
        int length = channel[1];
        long raw = (value >>> channel[0]) & ((1L << length) - 1L);
        if (channel[2] != 0) raw = reverseBits(raw, length);
        long max = (1L << length) - 1L;
        return (int) ((raw * 255L + max / 2L) / max);
    }

    private static long reverseBits(long value, int length) {
        long reversed = 0;
        for (int i = 0; i < length; ++i) {
            reversed = (reversed << 1) | (value & 1L);
            value >>>= 1;
        }
        return reversed;
    }

    private static int u8(byte value) { return value & 0xff; }

    private static int u16(byte[] data, int offset) {
        return u8(data[offset]) | (u8(data[offset + 1]) << 8);
    }

    private static long u32(byte[] data, int offset) {
        return (long) u8(data[offset]) |
                ((long) u8(data[offset + 1]) << 8) |
                ((long) u8(data[offset + 2]) << 16) |
                ((long) u8(data[offset + 3]) << 24);
    }

    private static long u64(byte[] data, int offset) {
        long value = 0;
        for (int i = 0; i < 8; ++i) value |= (long) u8(data[offset + i]) << (i * 8);
        return value;
    }
}
