#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

#include "../app/src/main/cpp/guest_diagnostics.h"

int main(void) {
    char output[64];
    assert(guest_diag_escape("/system/bin/app_process", output, sizeof(output)) == 0);
    assert(strcmp(output, "/system/bin/app_process") == 0);

    assert(guest_diag_escape("bad\n\033\"path", output, sizeof(output)) == 0);
    assert(strcmp(output, "bad\\x0a\\x1b\\\"path") == 0);

    char long_path[128];
    memset(long_path, 'x', sizeof(long_path) - 1);
    long_path[sizeof(long_path) - 1] = '\0';
    char short_output[16];
    assert(guest_diag_escape(long_path, short_output, sizeof(short_output)) == 1);
    assert(strlen(short_output) == sizeof(short_output) - 1);
    assert(strcmp(short_output + sizeof(short_output) - 4, "...") == 0);

    assert(strcmp(guest_diag_syscall_name(11), "execve") == 0);
    assert(strcmp(guest_diag_syscall_name(281), "socket") == 0);
    assert(strcmp(guest_diag_syscall_name(999), "unknown") == 0);
    assert(strcmp(guest_diag_errno_name(EACCES), "EACCES") == 0);
    assert(strcmp(guest_diag_errno_name(12345), "ERRNO") == 0);
    puts("guest diagnostics regression: PASS (escaped path bytes, bounded logs, syscall/errno labels)");
    return 0;
}
