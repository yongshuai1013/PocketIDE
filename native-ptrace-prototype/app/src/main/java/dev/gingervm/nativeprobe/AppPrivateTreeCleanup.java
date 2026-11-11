package dev.gingervm.nativeprobe;

import java.io.File;
import java.io.IOException;

/** Safe recursive cleanup for a stopped, app-private guest tree. */
final class AppPrivateTreeCleanup {
    interface Operations {
        Node lstat(File path) throws IOException;
        void makeDirectoryListable(File directory, Node expected) throws IOException;
        String[] list(File directory, Node expected) throws IOException;
        void remove(File path) throws IOException;
    }

    interface CancellationCheck {
        void check() throws IOException;
    }

    static final class Node {
        final boolean directory;
        final boolean symbolicLink;
        final int mode;
        final String identity;

        Node(boolean directory, boolean symbolicLink, int mode, String identity) {
            this.directory = directory;
            this.symbolicLink = symbolicLink;
            this.mode = mode;
            this.identity = identity;
        }

        boolean sameObject(Node other) {
            return other != null && directory == other.directory
                    && symbolicLink == other.symbolicLink
                    && identity != null && identity.equals(other.identity);
        }
    }

    private AppPrivateTreeCleanup() { }

    static void deleteRecursively(File path, Operations operations,
                                  CancellationCheck cancellation) throws IOException {
        cancellation.check();
        Node initial = operations.lstat(path);
        if (initial == null) return;

        // lstat marks symlinks as non-directories. Remove the link itself; never list its target.
        if (initial.symbolicLink || !initial.directory) {
            operations.remove(path);
            return;
        }

        operations.makeDirectoryListable(path, initial);
        Node accessible = operations.lstat(path);
        if (accessible == null) return;
        requireSameDirectory(path, initial, accessible);

        String[] children = operations.list(path, accessible);
        if (children == null)
            throw new IOException("cannot list app-private directory " + path);
        for (String childName : children) {
            cancellation.check();
            if (childName == null || childName.length() == 0
                    || ".".equals(childName) || "..".equals(childName)
                    || childName.indexOf('/') >= 0) {
                throw new IOException("invalid app-private directory entry under " + path);
            }
            deleteRecursively(new File(path, childName), operations, cancellation);
        }

        Node beforeRemove = operations.lstat(path);
        if (beforeRemove == null) return;
        requireSameDirectory(path, accessible, beforeRemove);
        cancellation.check();
        operations.remove(path);
    }

    private static void requireSameDirectory(File path, Node expected, Node actual) throws IOException {
        if (actual.symbolicLink || !actual.directory || !expected.sameObject(actual)) {
            throw new IOException("app-private directory changed during cleanup; refusing to follow " + path);
        }
    }
}
