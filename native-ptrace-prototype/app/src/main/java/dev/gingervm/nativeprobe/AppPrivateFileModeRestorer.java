package dev.gingervm.nativeprobe;

import java.io.File;
import java.io.IOException;

/** Restores authenticated guest rwx bits on regular files inside an app-private tree. */
public final class AppPrivateFileModeRestorer {
    private static final int S_IFMT = 0170000;
    private static final int S_IFREG = 0100000;
    private static final int S_IFDIR = 0040000;
    private static final int S_IFLNK = 0120000;

    public static final class Node {
        public final int mode;
        public final long device;
        public final long inode;

        public Node(int mode, long device, long inode) {
            this.mode = mode;
            this.device = device;
            this.inode = inode;
        }
    }

    /** Platform operations are descriptor-based for the final chmod target. */
    public interface Operations {
        Node lstat(File path) throws IOException;
        Object openReadOnlyNoFollow(File path) throws IOException;
        Node fstat(Object descriptor) throws IOException;
        void fchmod(Object descriptor, int safeMode) throws IOException;
        void close(Object descriptor) throws IOException;
    }

    private static final class Target {
        final File file;
        final Node node;

        Target(File file, Node node) {
            this.file = file;
            this.node = node;
        }
    }

    private AppPrivateFileModeRestorer() {}

    /** Strip setuid, setgid and sticky bits; only ordinary rwx permissions reach the host. */
    public static int safeHostMode(int sourceMode) throws IOException {
        if (sourceMode < 0 || (sourceMode & ~07777) != 0)
            throw new IOException("invalid source guest mode");
        return sourceMode & 0777;
    }

    public static void restore(File root, String relativePath, int sourceMode, Operations ops)
            throws IOException {
        int safeMode = safeHostMode(sourceMode);
        Target target = inspect(root, relativePath, ops);
        Object descriptor = ops.openReadOnlyNoFollow(target.file);
        if (descriptor == null) throw new IOException("no-follow guest file open returned null");
        try {
            Node opened = ops.fstat(descriptor);
            requireSameRegularFile(target.node, opened);
            ops.fchmod(descriptor, safeMode);
            Node restored = ops.fstat(descriptor);
            requireSameRegularFile(target.node, restored);
            if ((restored.mode & 07777) != safeMode)
                throw new IOException("guest file mode restoration did not persist");
        } finally {
            ops.close(descriptor);
        }
    }

    public static void verify(File root, String relativePath, int sourceMode, Operations ops)
            throws IOException {
        int safeMode = safeHostMode(sourceMode);
        Target target = inspect(root, relativePath, ops);
        Object descriptor = ops.openReadOnlyNoFollow(target.file);
        if (descriptor == null) throw new IOException("no-follow guest file open returned null");
        try {
            Node opened = ops.fstat(descriptor);
            requireSameRegularFile(target.node, opened);
            if ((opened.mode & 07777) != safeMode)
                throw new IOException("staged guest file mode differs from source manifest");
        } finally {
            ops.close(descriptor);
        }
    }

    private static Target inspect(File root, String relativePath, Operations ops)
            throws IOException {
        if (root == null || ops == null) throw new IOException("guest mode root or operations missing");
        String[] components = validateRelativePath(relativePath);

        File absoluteRoot = root.getAbsoluteFile();
        Node rootNode = ops.lstat(absoluteRoot);
        if (!isDirectory(rootNode.mode)) throw new IOException("guest mode root is not a real directory");
        File canonicalRoot = absoluteRoot.getCanonicalFile();
        Node canonicalRootNode = ops.lstat(canonicalRoot);
        if (!isDirectory(canonicalRootNode.mode)) throw new IOException("canonical guest mode root is not a directory");

        File current = canonicalRoot;
        Node node = canonicalRootNode;
        for (int i = 0; i < components.length; ++i) {
            current = new File(current, components[i]);
            node = ops.lstat(current);
            if (i + 1 == components.length) {
                if (!isRegularFile(node.mode))
                    throw new IOException(isSymlink(node.mode)
                            ? "refusing guest mode change through a symlink"
                            : "guest mode target is not a regular file");
            } else if (!isDirectory(node.mode)) {
                throw new IOException(isSymlink(node.mode)
                        ? "refusing guest mode traversal through a symlink"
                        : "guest mode path parent is not a directory");
            }
        }
        return new Target(current, node);
    }

    private static String[] validateRelativePath(String path) throws IOException {
        if (path == null || path.isEmpty() || path.startsWith("/") || path.indexOf('\\') >= 0 ||
                path.indexOf('\0') >= 0)
            throw new IOException("invalid relative guest mode path");
        String[] components = path.split("/", -1);
        for (String component : components) {
            if (component.isEmpty() || ".".equals(component) || "..".equals(component))
                throw new IOException("guest mode path traversal rejected");
        }
        return components;
    }

    private static void requireSameRegularFile(Node expected, Node actual) throws IOException {
        if (expected == null || actual == null || !isRegularFile(actual.mode) ||
                expected.device != actual.device || expected.inode != actual.inode)
            throw new IOException("guest mode target changed during validation");
    }

    private static boolean isRegularFile(int mode) {
        return (mode & S_IFMT) == S_IFREG;
    }

    private static boolean isDirectory(int mode) {
        return (mode & S_IFMT) == S_IFDIR;
    }

    private static boolean isSymlink(int mode) {
        return (mode & S_IFMT) == S_IFLNK;
    }
}
