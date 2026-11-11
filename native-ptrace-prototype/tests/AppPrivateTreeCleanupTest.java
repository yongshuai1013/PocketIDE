package dev.gingervm.nativeprobe;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.PosixFilePermission;
import java.util.HashSet;
import java.util.Set;

public final class AppPrivateTreeCleanupTest {
    private static final class HostOperations implements AppPrivateTreeCleanup.Operations {
        @Override
        public AppPrivateTreeCleanup.Node lstat(File file) throws IOException {
            try {
                BasicFileAttributes attributes = Files.readAttributes(file.toPath(),
                        BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
                Object key = attributes.fileKey();
                return new AppPrivateTreeCleanup.Node(attributes.isDirectory(),
                        attributes.isSymbolicLink(), 0,
                        key == null ? file.getAbsolutePath() : key.toString());
            } catch (NoSuchFileException missing) {
                return null;
            }
        }

        @Override
        public void makeDirectoryListable(File directory, AppPrivateTreeCleanup.Node expected)
                throws IOException {
            AppPrivateTreeCleanup.Node current = lstat(directory);
            requireSameDirectory(directory, expected, current);
            Set<PosixFilePermission> permissions = new HashSet<>(
                    Files.getPosixFilePermissions(directory.toPath(), LinkOption.NOFOLLOW_LINKS));
            permissions.add(PosixFilePermission.OWNER_READ);
            permissions.add(PosixFilePermission.OWNER_WRITE);
            permissions.add(PosixFilePermission.OWNER_EXECUTE);
            Files.setPosixFilePermissions(directory.toPath(), permissions);
        }

        @Override
        public String[] list(File directory, AppPrivateTreeCleanup.Node expected) throws IOException {
            requireSameDirectory(directory, expected, lstat(directory));
            String[] children = directory.list();
            requireSameDirectory(directory, expected, lstat(directory));
            return children;
        }

        @Override
        public void remove(File path) throws IOException {
            Files.deleteIfExists(path.toPath());
        }

        private static void requireSameDirectory(File path,
                AppPrivateTreeCleanup.Node expected, AppPrivateTreeCleanup.Node actual) throws IOException {
            if (actual == null || !actual.directory || actual.symbolicLink
                    || !expected.sameObject(actual)) {
                throw new IOException("test refused to traverse changed or linked directory: " + path);
            }
        }
    }

    public static void main(String[] args) throws Exception {
        Path temp = Files.createTempDirectory("gingervm-cleanup-test-");
        Path guest = temp.resolve("google-api10-full-root");
        Path sdcard = guest.resolve("mnt/sdcard");
        Path locked = guest.resolve("data/locked");
        Path outside = temp.resolve("outside");
        Path outsideMarker = outside.resolve("preserve.txt");
        HostOperations operations = new HostOperations();

        try {
            Files.createDirectories(sdcard);
            Files.write(sdcard.resolve("stale-entry"), new byte[]{1, 2, 3});
            Files.createDirectories(locked);
            Files.write(locked.resolve("stale-entry"), new byte[]{4, 5, 6});
            Files.createDirectories(outside);
            Files.write(outsideMarker, "outside must survive".getBytes(StandardCharsets.UTF_8));
            Files.createSymbolicLink(guest.resolve("outside-directory-link"), outside);
            Files.createSymbolicLink(sdcard.resolve("outside-file-link"), outsideMarker);
            setNoPermissions(sdcard);
            setNoPermissions(locked);

            // This matches init.rc's `mkdir /mnt/sdcard 0000 system system`.
            AppPrivateTreeCleanup.deleteRecursively(guest.toFile(), operations, () -> { });
            check(!Files.exists(guest, LinkOption.NOFOLLOW_LINKS), "guest tree should be removed");
            check(Files.exists(outsideMarker, LinkOption.NOFOLLOW_LINKS),
                    "recursive cleanup must not follow a guest symlink to outside data");
            check("outside must survive".equals(new String(Files.readAllBytes(outsideMarker),
                    StandardCharsets.UTF_8)), "outside marker contents must remain unchanged");

            // ENOENT at the requested root is an idempotent no-op.
            AppPrivateTreeCleanup.deleteRecursively(guest.toFile(), operations, () -> { });

            // A symlink supplied as the cleanup root itself is unlinked, not entered.
            Path rootLink = temp.resolve("guest-root-link");
            Files.createSymbolicLink(rootLink, outside);
            AppPrivateTreeCleanup.deleteRecursively(rootLink.toFile(), operations, () -> { });
            check(!Files.exists(rootLink, LinkOption.NOFOLLOW_LINKS), "root symlink should be unlinked");
            check(Files.exists(outsideMarker, LinkOption.NOFOLLOW_LINKS),
                    "root symlink target must remain untouched");
            System.out.println("app-private staging cleanup regression: PASS (mode-0000 guest dirs are removable; missing roots are no-op; guest symlinks are unlinked without following targets)");
        } finally {
            makeOwnerAccessibleIfPresent(sdcard);
            makeOwnerAccessibleIfPresent(locked);
            Files.walkFileTree(temp, new SimpleFileVisitor<Path>() {
                @Override
                public FileVisitResult visitFile(Path file, BasicFileAttributes attributes) throws IOException {
                    Files.deleteIfExists(file);
                    return FileVisitResult.CONTINUE;
                }

                @Override
                public FileVisitResult postVisitDirectory(Path directory, IOException error) throws IOException {
                    if (error != null) throw error;
                    Files.deleteIfExists(directory);
                    return FileVisitResult.CONTINUE;
                }
            });
        }
    }

    private static void setNoPermissions(Path path) throws IOException {
        Set<PosixFilePermission> none = new HashSet<>();
        Files.setPosixFilePermissions(path, none);
    }

    private static void makeOwnerAccessibleIfPresent(Path path) throws IOException {
        if (!Files.exists(path, LinkOption.NOFOLLOW_LINKS)) return;
        Set<PosixFilePermission> permissions = new HashSet<>();
        permissions.add(PosixFilePermission.OWNER_READ);
        permissions.add(PosixFilePermission.OWNER_WRITE);
        permissions.add(PosixFilePermission.OWNER_EXECUTE);
        Files.setPosixFilePermissions(path, permissions);
    }

    private static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }
}
