#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "../app/src/main/cpp/guest_diagnostics.h"
#include "../app/src/main/cpp/guest_sigsys_context.h"

static int map_probe;

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
    assert(strcmp(guest_diag_syscall_name(126), "sigprocmask") == 0);
    assert(strcmp(guest_diag_syscall_name(175), "rt_sigprocmask") == 0);
    assert(strcmp(guest_diag_syscall_name(202), "getegid32") == 0);
    assert(strcmp(guest_diag_syscall_name(281), "socket") == 0);
    assert(strcmp(guest_diag_syscall_name(290), "sendto") == 0);
    assert(strcmp(guest_diag_syscall_name(292), "recvfrom") == 0);
    assert(strcmp(guest_diag_syscall_name(999), "unknown") == 0);
    assert(strcmp(guest_diag_errno_name(EACCES), "EACCES") == 0);
    assert(strcmp(guest_diag_errno_name(ENOTSOCK), "ENOTSOCK") == 0);
    assert(strcmp(guest_diag_errno_name(EOPNOTSUPP), "EOPNOTSUPP") == 0);
    assert(strcmp(guest_diag_errno_name(12345), "ERRNO") == 0);

    struct guest_diag_proc_map mapping;
    const char synthetic_map[] =
        "afd00000-afd40000 r-xp 00000000 103:02 12345 "
        "/data/app/com.example/lib/arm/libgingervm_system_lib_libc.so\n";
    assert(guest_diag_parse_proc_maps_line(synthetic_map, &mapping) == 0);
    assert(mapping.start == UINT64_C(0xafd00000));
    assert(mapping.end == UINT64_C(0xafd40000));
    assert(strcmp(mapping.permissions, "r-xp") == 0);
    assert(guest_diag_proc_map_contains(&mapping, UINT64_C(0xafd0bf6c)));
    assert(guest_diag_proc_map_file_offset(&mapping, UINT64_C(0xafd0bf6c)) ==
           UINT64_C(0xbf6c));
    assert(!guest_diag_proc_map_contains(&mapping, mapping.end));
    assert(strstr(mapping.path, "libgingervm_system_lib_libc.so") != NULL);
    assert(guest_diag_parse_proc_maps_line("not a proc maps record", &mapping) == -EINVAL);

    assert(guest_diag_find_proc_map(getpid(), (uint64_t)(uintptr_t)&map_probe,
                                    &mapping) == 0);
    assert(guest_diag_proc_map_contains(&mapping, (uint64_t)(uintptr_t)&map_probe));
    int seccomp_mode = guest_diag_read_proc_seccomp_mode(getpid());
    assert(seccomp_mode == 0 || seccomp_mode == 1 || seccomp_mode == 2 ||
           seccomp_mode == -ENOENT);

    puts("guest diagnostics regression: PASS (escaped paths, ARM syscall labels/errno names, bounded proc maps, module offsets, Seccomp status)");
    return 0;
}
