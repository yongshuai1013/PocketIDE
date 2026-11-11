#ifndef GINGERVM_INIT_BROKER_H
#define GINGERVM_INIT_BROKER_H

#include <errno.h>
#include <limits.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

enum guest_syscall_class {
    GUEST_SYSCALL_DENY = 0,
    GUEST_SYSCALL_ALLOW_SAFE = 1,
    GUEST_SYSCALL_PATH_REWRITE = 2,
    GUEST_SYSCALL_VIRTUALIZE = 3,
    GUEST_SYSCALL_VIRTUAL_MOUNT = 4,
    GUEST_SYSCALL_VIRTUAL_DEVICE = 5,
    GUEST_SYSCALL_BLOCK_PROCESS = 6,
    GUEST_SYSCALL_TRACE_PROCESS = 7,
    GUEST_SYSCALL_FILE_OPERATION = 8,
};

/* Narrow ARM EABI syscall policy for the original static Gingerbread init.
 * Every number not explicitly listed here is canceled before host dispatch. */
static inline enum guest_syscall_class guest_syscall_policy(int nr) {
    switch (nr) {
        /* Guest-local ordinary file operations on already-brokered descriptors. */
        case 1: case 3: case 4: case 6: case 19: case 41: case 42: case 63:
        case 45: case 55: case 91: case 108: case 114: case 118:
        case 119: case 125: case 126: case 140: case 141: case 145: case 146:
        case 148: case 162: case 163:
        case 173: case 174: case 175: case 176: case 177: case 179:
        case 180: case 181: case 192: case 197: case 240: case 248: case 257:
        case 217: case 220: case 221: case 263: case 264: case 265: case 266:
        case 338: case 0x0f0002: case 0x0f0005:
            return GUEST_SYSCALL_ALLOW_SAFE;

        /* Absolute guest paths are translated and checked before host execution. */
        case 5: case 8: case 9: case 10: case 12: case 15: case 16: case 33:
        case 38: case 39: case 40: case 85: case 92: case 182: case 193:
        case 195: case 196: case 198: case 212: case 226: case 227: case 228:
        case 229: case 230:
        case 231: case 232: case 233: case 234: case 235: case 236: case 237:
        case 270: case 322: case 323: case 324: case 325: case 326: case 327:
        case 328: case 329: case 330: case 332: case 333: case 334:
            return GUEST_SYSCALL_PATH_REWRITE;

        /* Simulated IDs/permissions; never change the Android app's credentials. */
        case 20: case 23: case 24: case 46: case 47: case 49: case 50: case 60:
        case 64: case 80: case 81: case 138: case 139: case 164: case 165:
        case 170: case 171: case 172: case 184: case 185: case 199:
        case 102: case 168: case 200: case 201: case 202: case 203: case 204:
        case 205: case 206:
        case 207: case 208: case 209: case 210: case 211: case 213: case 214:
        case 215: case 216: case 224:
            return GUEST_SYSCALL_VIRTUALIZE;

        /* Symlinks and ftruncate are brokered only against app-private guest VFS objects. */
        case 83: case 93: case 331:
            return GUEST_SYSCALL_FILE_OPERATION;

        /* Guest mount table only: no host mount(2), umount(2), or pivot_root(2). */
        case 21: case 52:
            return GUEST_SYSCALL_VIRTUAL_MOUNT;

        /* Only ordinary files may represent devices; ioctl/socket/device actions
         * are not forwarded to the host kernel in this first slice. */
        case 14: case 54: case 94: case 95: case 133:
            return GUEST_SYSCALL_VIRTUAL_DEVICE;

        /* Only the ptrace supervisor's bounded, explicitly attached guest tree
         * may use these process-creation syscalls. */
        case 2: case 120: case 190:
            return GUEST_SYSCALL_TRACE_PROCESS;

        /* execve, ptrace, chroot, pivot_root, reboot, namespaces, sockets, and
         * every unknown syscall remain denied by default. */
        default:
            return GUEST_SYSCALL_DENY;
    }
}

static inline int guest_path_has_parent(const char *path) {
    const char *p = path;
    while (*p) {
        while (*p == '/') ++p;
        const char *start = p;
        while (*p && *p != '/') ++p;
        if ((size_t)(p - start) == 2 && start[0] == '.' && start[1] == '.') return 1;
    }
    return 0;
}

/* Resolve the existing path, or its nearest existing parent, and reject symlinks
 * escaping the app-private guest root. The tracee is stopped while this runs;
 * hostile multi-process guests still need descriptor-relative mediation to
 * eliminate TOCTOU races. */
static inline int guest_path_to_host(const char *root, const char *guest,
                                     char *host, size_t capacity) {
    if (!root || !guest || guest[0] != '/' || guest_path_has_parent(guest) || capacity == 0)
        return -EINVAL;
    char canonical_root[PATH_MAX];
    if (!realpath(root, canonical_root)) return -errno;
    int n = snprintf(host, capacity, "%s%s", canonical_root, guest);
    if (n <= 0 || (size_t)n >= capacity) return -ENAMETOOLONG;

    char candidate[PATH_MAX];
    if (strlen(host) >= sizeof(candidate)) return -ENAMETOOLONG;
    strcpy(candidate, host);
    char suffix[PATH_MAX] = "";
    for (;;) {
        char resolved[PATH_MAX];
        if (realpath(candidate, resolved)) {
            size_t root_len = strlen(canonical_root);
            if (strncmp(resolved, canonical_root, root_len) != 0 ||
                (resolved[root_len] != '\0' && resolved[root_len] != '/')) return -EACCES;
            n = suffix[0] == '\0'
                ? snprintf(host, capacity, "%s", resolved)
                : snprintf(host, capacity, "%s/%s", resolved, suffix);
            return n > 0 && (size_t)n < capacity ? 0 : -ENAMETOOLONG;
        }
        if (errno != ENOENT && errno != ENOTDIR) return -errno;
        char *slash = strrchr(candidate, '/');
        if (!slash) return -EACCES;
        if (slash == candidate) {
            candidate[1] = '\0';
            if (suffix[0] != '\0') return -EACCES;
        } else {
            const char *tail = slash + 1;
            if (*tail == '\0') return -EACCES;
            if (suffix[0] == '\0') {
                n = snprintf(suffix, sizeof(suffix), "%s", tail);
            } else {
                char combined[PATH_MAX];
                n = snprintf(combined, sizeof(combined), "%s/%s", tail, suffix);
                if (n > 0 && (size_t)n < sizeof(combined)) strcpy(suffix, combined);
            }
            if (n <= 0 || n >= (int)sizeof(suffix)) return -ENAMETOOLONG;
            *slash = '\0';
        }
        size_t root_len = strlen(canonical_root);
        if (strncmp(candidate, canonical_root, root_len) != 0 ||
            (candidate[root_len] != '\0' && candidate[root_len] != '/')) return -EACCES;
    }
}

#endif
