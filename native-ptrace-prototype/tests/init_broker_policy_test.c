#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "../app/src/main/cpp/init_broker.h"

static void make_dir(const char *path) {
    assert(mkdir(path, 0700) == 0 || errno == EEXIST);
}

int main(void) {
    assert(guest_syscall_policy(21) == GUEST_SYSCALL_VIRTUAL_MOUNT);
    assert(guest_syscall_policy(52) == GUEST_SYSCALL_VIRTUAL_MOUNT);
    assert(guest_syscall_policy(322) == GUEST_SYSCALL_PATH_REWRITE);
    assert(guest_syscall_policy(195) == GUEST_SYSCALL_PATH_REWRITE);
    assert(guest_syscall_policy(15) == GUEST_SYSCALL_PATH_REWRITE);
    assert(guest_syscall_policy(24) == GUEST_SYSCALL_VIRTUALIZE);
    assert(guest_syscall_policy(14) == GUEST_SYSCALL_VIRTUAL_DEVICE);
    assert(guest_syscall_policy(120) == GUEST_SYSCALL_TRACE_PROCESS);
    assert(guest_syscall_policy(2) == GUEST_SYSCALL_TRACE_PROCESS);
    assert(guest_syscall_policy(190) == GUEST_SYSCALL_TRACE_PROCESS);
    assert(guest_syscall_policy(11) == GUEST_SYSCALL_DENY); /* execve uses explicit ELF mediation */
    assert(guest_syscall_policy(102) == GUEST_SYSCALL_VIRTUALIZE); /* software socketcall */
    assert(guest_syscall_policy(168) == GUEST_SYSCALL_VIRTUALIZE); /* software poll */
    assert(guest_syscall_policy(26) == GUEST_SYSCALL_DENY);  /* ptrace */
    assert(guest_syscall_policy(218) == GUEST_SYSCALL_DENY); /* pivot_root */
    assert(guest_syscall_policy(88) == GUEST_SYSCALL_DENY);  /* reboot */
    assert(guest_syscall_policy(0x0f0005) == GUEST_SYSCALL_ALLOW_SAFE); /* ARM set_tls */
    assert(guest_syscall_policy(9999) == GUEST_SYSCALL_DENY);

    char base[80] = "/tmp/gingervm-init-policy-XXXXXX";
    char *tmp = mkdtemp(base);
    assert(tmp != NULL);
    char root[256], outside[256], inside_file[512], link_path[512], escape_path[512];
    assert(snprintf(root, sizeof(root), "%s/guest", tmp) > 0);
    assert(snprintf(outside, sizeof(outside), "%s/outside", tmp) > 0);
    assert(snprintf(inside_file, sizeof(inside_file), "%s/init.rc", root) > 0);
    assert(snprintf(link_path, sizeof(link_path), "%s/etc-link", root) > 0);
    assert(snprintf(escape_path, sizeof(escape_path), "%s/escape", root) > 0);
    make_dir(root);
    make_dir(outside);
    FILE *file = fopen(inside_file, "w");
    assert(file != NULL);
    fputs("on init\n", file);
    fclose(file);
    assert(symlink("init.rc", link_path) == 0);
    assert(symlink(outside, escape_path) == 0);

    char host[PATH_MAX];
    assert(guest_path_to_host(root, "/init.rc", host, sizeof(host)) == 0);
    assert(strcmp(host, inside_file) == 0);
    assert(guest_path_to_host(root, "/future/new.conf", host, sizeof(host)) == 0);
    assert(strncmp(host, root, strlen(root)) == 0);
    assert(guest_path_to_host(root, "relative", host, sizeof(host)) == -EINVAL);
    assert(guest_path_to_host(root, "/../outside/file", host, sizeof(host)) == -EINVAL);
    assert(guest_path_to_host(root, "/escape/secret", host, sizeof(host)) == -EACCES);
    assert(guest_path_to_host(root, "/etc-link", host, sizeof(host)) == 0);
    assert(strcmp(host, inside_file) == 0);

    unlink(link_path);
    unlink(escape_path);
    unlink(inside_file);
    rmdir(root);
    rmdir(outside);
    rmdir(tmp);
    puts("init broker policy/path regression: PASS (mount/identity/device virtualized; only supervised fork/exec chain admitted; traversal and symlink escapes rejected)");
    return 0;
}
