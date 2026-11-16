package dev.gingervm.nativeprobe;

import java.io.IOException;
import java.nio.channels.FileChannel;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.OpenOption;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.PosixFilePermission;
import java.util.EnumSet;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public final class AppPrivateFileModeRestorerTest {
    private static final class OpenFile {
        final Path path;
        final FileChannel channel;

        OpenFile(Path path, FileChannel channel) {
            this.path = path;
            this.channel = channel;
        }
    }

    private static final class HostOps implements AppPrivateFileModeRestorer.Operations {
        @Override
        public AppPrivateFileModeRestorer.Node lstat(java.io.File file) throws IOException {
            Path path = file.toPath();
            Map<String, Object> attributes = Files.readAttributes(path, "unix:mode,dev,ino",
                    LinkOption.NOFOLLOW_LINKS);
            return node(attributes);
        }

        @Override
        public Object openReadOnlyNoFollow(java.io.File file) throws IOException {
            Path path = file.toPath();
            Set<OpenOption> options = new HashSet<>();
            options.add(StandardOpenOption.READ);
            options.add(LinkOption.NOFOLLOW_LINKS);
            return new OpenFile(path, FileChannel.open(path, options));
        }

        @Override
        public AppPrivateFileModeRestorer.Node fstat(Object descriptor) throws IOException {
            OpenFile file = (OpenFile) descriptor;
            return lstat(file.path.toFile());
        }

        @Override
        public void fchmod(Object descriptor, int safeMode) throws IOException {
            OpenFile file = (OpenFile) descriptor;
            Files.setPosixFilePermissions(file.path, permissions(safeMode));
        }

        @Override
        public void close(Object descriptor) throws IOException {
            ((OpenFile) descriptor).channel.close();
        }

        private static AppPrivateFileModeRestorer.Node node(Map<String, Object> attrs) {
            return new AppPrivateFileModeRestorer.Node(
                    ((Number) attrs.get("mode")).intValue(),
                    ((Number) attrs.get("dev")).longValue(),
                    ((Number) attrs.get("ino")).longValue());
        }
    }

    public static void main(String[] args) throws Exception {
        Path base = Files.createTempDirectory("gingervm-file-modes-");
        try {
            verifyRestorationAndSafety(base);
            System.out.println("app-private guest file mode regression: PASS (manifest mode 0550 restored, traversal and symlink paths rejected, special bits stripped)");
        } finally {
            deleteTree(base);
        }
    }

    private static void verifyRestorationAndSafety(Path base) throws Exception {
        Path root = Files.createDirectory(base.resolve("guest-root"));
        Path system = Files.createDirectory(root.resolve("system"));
        Path etc = Files.createDirectory(system.resolve("etc"));
        Path script = etc.resolve("init.goldfish.sh");
        Files.write(script, "#!/system/bin/sh\nexit 0\n".getBytes(java.nio.charset.StandardCharsets.UTF_8));
        Files.setPosixFilePermissions(script, permissions(0644));

        Path outsideDirectory = Files.createDirectory(base.resolve("outside"));
        Path outside = outsideDirectory.resolve("outside.sh");
        Files.write(outside, "do not chmod outside\n".getBytes(java.nio.charset.StandardCharsets.UTF_8));
        Files.setPosixFilePermissions(outside, permissions(0644));

        HostOps ops = new HostOps();
        AppPrivateFileModeRestorer.restore(root.toFile(), "system/etc/init.goldfish.sh", 0550, ops);
        assertMode(script, 0550);
        AppPrivateFileModeRestorer.verify(root.toFile(), "system/etc/init.goldfish.sh", 0550, ops);
        assert AppPrivateFileModeRestorer.safeHostMode(04755) == 0755;

        Files.setPosixFilePermissions(script, permissions(0644));
        expectRejected(() -> AppPrivateFileModeRestorer.verify(
                root.toFile(), "system/etc/init.goldfish.sh", 0550, ops));

        Path finalLink = etc.resolve("final-link.sh");
        Files.createSymbolicLink(finalLink, outside);
        expectRejected(() -> AppPrivateFileModeRestorer.restore(
                root.toFile(), "system/etc/final-link.sh", 0550, ops));
        assertMode(outside, 0644);
        Files.delete(finalLink);

        Path parentLink = root.resolve("outside-parent");
        Files.createSymbolicLink(parentLink, outsideDirectory);
        expectRejected(() -> AppPrivateFileModeRestorer.restore(
                root.toFile(), "outside-parent/outside.sh", 0550, ops));
        assertMode(outside, 0644);

        expectRejected(() -> AppPrivateFileModeRestorer.restore(root.toFile(), "../outside.sh", 0550, ops));
        expectRejected(() -> AppPrivateFileModeRestorer.restore(root.toFile(), "system/etc/../../outside.sh", 0550, ops));
        expectRejected(() -> AppPrivateFileModeRestorer.restore(root.toFile(), "/tmp/outside.sh", 0550, ops));
        expectRejected(() -> AppPrivateFileModeRestorer.restore(root.toFile(), "system//etc/script", 0550, ops));
        expectRejected(() -> AppPrivateFileModeRestorer.restore(root.toFile(), "system\\etc\\script", 0550, ops));
    }

    private interface CheckedAction {
        void run() throws Exception;
    }

    private static void expectRejected(CheckedAction action) throws Exception {
        boolean rejected = false;
        try {
            action.run();
        } catch (IOException expected) {
            rejected = true;
        }
        assert rejected : "unsafe or mismatched guest mode path was accepted";
    }

    private static Set<PosixFilePermission> permissions(int mode) {
        EnumSet<PosixFilePermission> result = EnumSet.noneOf(PosixFilePermission.class);
        if ((mode & 0400) != 0) result.add(PosixFilePermission.OWNER_READ);
        if ((mode & 0200) != 0) result.add(PosixFilePermission.OWNER_WRITE);
        if ((mode & 0100) != 0) result.add(PosixFilePermission.OWNER_EXECUTE);
        if ((mode & 0040) != 0) result.add(PosixFilePermission.GROUP_READ);
        if ((mode & 0020) != 0) result.add(PosixFilePermission.GROUP_WRITE);
        if ((mode & 0010) != 0) result.add(PosixFilePermission.GROUP_EXECUTE);
        if ((mode & 0004) != 0) result.add(PosixFilePermission.OTHERS_READ);
        if ((mode & 0002) != 0) result.add(PosixFilePermission.OTHERS_WRITE);
        if ((mode & 0001) != 0) result.add(PosixFilePermission.OTHERS_EXECUTE);
        return result;
    }

    private static void assertMode(Path path, int expected) throws IOException {
        int mode = ((Number) Files.getAttribute(path, "unix:mode", LinkOption.NOFOLLOW_LINKS)).intValue();
        assert (mode & 07777) == expected : "unexpected mode " + Integer.toOctalString(mode & 07777);
    }

    private static void deleteTree(Path root) throws IOException {
        Files.walkFileTree(root, new SimpleFileVisitor<Path>() {
            @Override
            public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) throws IOException {
                Files.delete(file);
                return FileVisitResult.CONTINUE;
            }

            @Override
            public FileVisitResult postVisitDirectory(Path dir, IOException error) throws IOException {
                if (error != null) throw error;
                Files.delete(dir);
                return FileVisitResult.CONTINUE;
            }
        });
    }
}
