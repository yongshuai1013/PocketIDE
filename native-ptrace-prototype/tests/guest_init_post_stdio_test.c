#include "../app/src/main/cpp/guest_null_stdio.h"
#include "../app/src/main/cpp/guest_kmsg_virtual.h"

#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static char *read_text(const char *path) {
    FILE *file = fopen(path, "rb");
    assert(file != NULL);
    assert(fseek(file, 0, SEEK_END) == 0);
    long length = ftell(file);
    assert(length >= 0 && length <= 1024 * 1024);
    assert(fseek(file, 0, SEEK_SET) == 0);
    char *text = (char *)malloc((size_t)length + 1u);
    assert(text != NULL);
    assert(fread(text, 1u, (size_t)length, file) == (size_t)length);
    assert(fclose(file) == 0);
    text[length] = '\0';
    return text;
}

static void test_continuous_post_stdio_path(const char *init_rc_path,
                                            const char *goldfish_rc_path) {
    struct guest_null_stdio_runtime null_runtime;
    guest_null_stdio_runtime_init(&null_runtime);
    uint8_t stdio_mask = 0;
    int result = 0;

    assert(guest_null_stdio_mknod(&null_runtime, 1, "/init", 0,
        GUEST_NULL_STDIO_PATH, GUEST_NULL_STDIO_MODE,
        GUEST_NULL_STDIO_DEVICE) == 0);
    assert(guest_null_stdio_open_validate(&null_runtime, 1, "/init", 0,
        GUEST_NULL_STDIO_PATH,
        GUEST_ARM32_O_RDWR | GUEST_ARM32_O_LARGEFILE) == 0);
    const int null_fd = 5000;
    assert(guest_null_stdio_open_complete(&null_runtime, null_fd) == null_fd);
    assert(guest_null_stdio_unlink(&null_runtime, 1, "/init", 0,
        GUEST_NULL_STDIO_PATH) == 0);
    for (int target = 0; target <= 2; ++target) {
        assert(guest_null_stdio_dup2(&null_runtime, &stdio_mask, null_fd,
            target, 1, &result) == 1);
        assert(result == target);
    }
    guest_null_stdio_source_fd_closed(&null_runtime, null_fd);
    assert(stdio_mask == GUEST_NULL_STDIO_FD_MASK);

    struct guest_kmsg_runtime kmsg;
    guest_kmsg_runtime_init(&kmsg);
    assert(guest_kmsg_mknod(&kmsg, 1, "/init", 0, GUEST_KMSG_PATH,
        GUEST_KMSG_MODE, GUEST_KMSG_DEVICE) == 0);
    assert(kmsg.node_present && !kmsg.unlinked);
    const uint32_t open_flags = GUEST_KMSG_O_WRONLY | GUEST_KMSG_O_LARGEFILE;
    assert(guest_kmsg_open_validate(&kmsg, 1, "/init", 0,
        GUEST_KMSG_PATH, 0u) == -EINVAL);
    assert(guest_kmsg_open_validate(&kmsg, 1, "/init", 0,
        GUEST_KMSG_PATH, open_flags) == 0);
    const int kmsg_fd = 5001;
    assert(guest_kmsg_open_complete(&kmsg, kmsg_fd) == kmsg_fd);
    guest_kmsg_note_fcntl(&kmsg, kmsg_fd, GUEST_KMSG_F_SETFD,
        GUEST_KMSG_FD_CLOEXEC, 0);
    assert(kmsg.fd_cloexec && kmsg.fcntl_setfd_succeeded == 1);
    assert(guest_kmsg_unlink(&kmsg, 1, "/init", 0, GUEST_KMSG_PATH) == 0);
    assert(!kmsg.node_present && kmsg.unlinked && kmsg.fd_open);
    assert(guest_kmsg_open_validate(&kmsg, 1, "/init", 0,
        GUEST_KMSG_PATH, open_flags) == -ENOENT);
    guest_kmsg_note_write(&kmsg, kmsg_fd, 64);
    assert(kmsg.write_calls == 1 && kmsg.write_bytes == 64);
    guest_kmsg_note_fd_closed(&kmsg, kmsg_fd, 0, 1, 1);
    assert(kmsg.fd_open && kmsg.close_on_exec_calls == 0);
    guest_kmsg_note_fd_closed(&kmsg, kmsg_fd, 0, 0, 0);
    assert(!kmsg.fd_open && kmsg.close_calls == 1);

    struct guest_kmsg_runtime exec_runtime;
    guest_kmsg_runtime_init(&exec_runtime);
    assert(guest_kmsg_mknod(&exec_runtime, 1, "/init", 0, GUEST_KMSG_PATH,
        GUEST_KMSG_MODE, GUEST_KMSG_DEVICE) == 0);
    assert(guest_kmsg_open_validate(&exec_runtime, 1, "/init", 0,
        GUEST_KMSG_PATH, GUEST_KMSG_O_WRONLY) == 0);
    assert(guest_kmsg_open_complete(&exec_runtime, 5002) == 5002);
    guest_kmsg_note_fcntl(&exec_runtime, 5002, GUEST_KMSG_F_SETFD,
        GUEST_KMSG_FD_CLOEXEC, 0);
    guest_kmsg_note_fd_closed(&exec_runtime, 5002, 0, 0, 1);
    assert(!exec_runtime.fd_open && exec_runtime.close_on_exec_calls == 1);

    char *init_rc = read_text(init_rc_path);
    char *goldfish_rc = read_text(goldfish_rc_path);
    assert(strstr(init_rc, "on early-init") != NULL);
    assert(strstr(init_rc, "start ueventd") != NULL);
    assert(strstr(goldfish_rc, "on boot") != NULL);
    assert(strstr(goldfish_rc,
        "service goldfish-setup /system/etc/init.goldfish.sh") != NULL);
    free(init_rc);
    free(goldfish_rc);

    /* API10 log_init is optional. A failed node creation/open does not stop the
     * later init.rc read; API10 source-order checks enforce that boundary. */
    struct guest_kmsg_runtime optional_failure;
    guest_kmsg_runtime_init(&optional_failure);
    assert(guest_kmsg_mknod(&optional_failure, 1, "/init", 0,
        GUEST_KMSG_PATH, GUEST_KMSG_MODE, GUEST_KMSG_DEVICE + 1u) == -EINVAL);
    assert(!optional_failure.node_present);
    init_rc = read_text(init_rc_path);
    assert(strstr(init_rc, "on early-init") != NULL);
    free(init_rc);
}

static void test_kmsg_fail_closed(void) {
    struct guest_kmsg_runtime runtime;
    guest_kmsg_runtime_init(&runtime);
    assert(guest_kmsg_mknod(&runtime, 1, "/init", 0, "/dev/__kmsg__/x",
        GUEST_KMSG_MODE, GUEST_KMSG_DEVICE) == -EOPNOTSUPP);
    assert(guest_kmsg_mknod(&runtime, 2, "/init", 0, GUEST_KMSG_PATH,
        GUEST_KMSG_MODE, GUEST_KMSG_DEVICE) == -EPERM);
    assert(guest_kmsg_mknod(&runtime, 1, "/sbin/ueventd", 0, GUEST_KMSG_PATH,
        GUEST_KMSG_MODE, GUEST_KMSG_DEVICE) == -EPERM);
    assert(guest_kmsg_mknod(&runtime, 1, "/init", 1000, GUEST_KMSG_PATH,
        GUEST_KMSG_MODE, GUEST_KMSG_DEVICE) == -EPERM);
    assert(guest_kmsg_mknod(&runtime, 1, "/init", 0, GUEST_KMSG_PATH,
        0100600u, GUEST_KMSG_DEVICE) == -EINVAL);
    assert(guest_kmsg_mknod(&runtime, 1, "/init", 0, GUEST_KMSG_PATH,
        GUEST_KMSG_MODE, 0x00000103u) == -EINVAL);
    assert(!runtime.node_present && runtime.mknod_accepted == 0);

    assert(guest_kmsg_mknod(&runtime, 1, "/init", 0, GUEST_KMSG_PATH,
        GUEST_KMSG_MODE, GUEST_KMSG_DEVICE) == 0);
    assert(guest_kmsg_open_validate(&runtime, 1, "/init", 0,
        GUEST_KMSG_PATH, GUEST_KMSG_O_WRONLY) == 0);
    assert(guest_kmsg_open_complete(&runtime, -EMFILE) == -EMFILE);
    assert(runtime.open_failed == 1 && runtime.node_present);
    assert(guest_kmsg_unlink(&runtime, 1, "/init", 0, GUEST_KMSG_PATH) == 0);
    assert(!runtime.node_present && !runtime.fd_open);
}

int main(int argc, char **argv) {
    assert(argc == 3);
    test_continuous_post_stdio_path(argv[1], argv[2]);
    test_kmsg_fail_closed();
    puts("API10 post-stdio host state-machine/source-content regression: PASS (null stdio -> exact /dev/__kmsg__ 1:11/0600 mknod -> O_WRONLY virtual FD -> CLOEXEC -> unlink while open -> discard-write -> /init.rc early-init/ueventd content; denied variants fail closed; no guest binary or host device executed)");
    return 0;
}
