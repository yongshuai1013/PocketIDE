#ifndef GINGERVM_GUEST_DIAGNOSTICS_H
#define GINGERVM_GUEST_DIAGNOSTICS_H

#include <errno.h>
#include <stddef.h>
#include <string.h>

/* Escape untrusted guest path bytes before writing them to a line-oriented log.
 * Returns 1 when output was truncated, 0 when the whole input was copied. */
static inline int guest_diag_escape(const char *input, char *output, size_t capacity) {
    static const char hex[] = "0123456789abcdef";
    size_t used = 0;
    int truncated = 0;
    if (!output || capacity == 0) return 1;
    output[0] = '\0';
    if (!input) input = "";

    for (size_t i = 0; input[i] != '\0'; ++i) {
        unsigned char c = (unsigned char)input[i];
        char piece[4];
        size_t length;
        if (c >= 0x20 && c <= 0x7e && c != '\\' && c != '"') {
            piece[0] = (char)c;
            length = 1;
        } else if (c == '\\' || c == '"') {
            piece[0] = '\\';
            piece[1] = (char)c;
            length = 2;
        } else {
            piece[0] = '\\';
            piece[1] = 'x';
            piece[2] = hex[c >> 4];
            piece[3] = hex[c & 0x0f];
            length = 4;
        }
        if (length > capacity - 1 - used) {
            truncated = 1;
            break;
        }
        memcpy(output + used, piece, length);
        used += length;
    }

    if (truncated) {
        if (capacity >= 4) {
            if (used > capacity - 4) used = capacity - 4;
            memcpy(output + used, "...", 3);
            used += 3;
        } else {
            used = 0;
        }
    }
    output[used] = '\0';
    return truncated;
}

static inline const char *guest_diag_syscall_name(int number) {
    switch (number) {
        case 2: return "fork";
        case 3: return "read";
        case 4: return "write";
        case 5: return "open";
        case 6: return "close";
        case 11: return "execve";
        case 21: return "mount";
        case 26: return "ptrace";
        case 37: return "kill";
        case 52: return "umount2";
        case 83: return "symlink";
        case 93: return "ftruncate";
        case 102: return "socketcall";
        case 114: return "wait4";
        case 120: return "clone";
        case 168: return "poll";
        case 281: return "socket";
        case 282: return "bind";
        case 283: return "connect";
        case 284: return "listen";
        case 285: return "accept";
        case 288: return "socketpair";
        default: return "unknown";
    }
}

static inline const char *guest_diag_errno_name(int error_number) {
    switch (error_number) {
        case EACCES: return "EACCES";
        case EFAULT: return "EFAULT";
        case ENOENT: return "ENOENT";
        case ENOEXEC: return "ENOEXEC";
        case EPERM: return "EPERM";
        case ENOSYS: return "ENOSYS";
        case EAGAIN: return "EAGAIN";
        case ENAMETOOLONG: return "ENAMETOOLONG";
        case ELOOP: return "ELOOP";
        case ENOTDIR: return "ENOTDIR";
        case EINVAL: return "EINVAL";
        case EBADF: return "EBADF";
        case EEXIST: return "EEXIST";
        default: return "ERRNO";
    }
}

#endif
