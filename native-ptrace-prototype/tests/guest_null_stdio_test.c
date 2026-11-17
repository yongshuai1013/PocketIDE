#include "../app/src/main/cpp/guest_null_stdio.h"

#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>

static void test_exact_init_sequence(void) {
    struct guest_null_stdio_runtime runtime;
    guest_null_stdio_runtime_init(&runtime);
    uint8_t stdio_mask = 0;

    assert(guest_null_stdio_mknod(&runtime, 1, "/init", 0,
        GUEST_NULL_STDIO_PATH, GUEST_NULL_STDIO_MODE,
        GUEST_NULL_STDIO_DEVICE) == 0);
    assert(runtime.node_present && !runtime.unlinked && runtime.mknod_accepted == 1);

    assert(guest_null_stdio_open_validate(&runtime, 1, "/init", 0,
        GUEST_NULL_STDIO_PATH, GUEST_ARM32_O_RDWR | GUEST_ARM32_O_LARGEFILE) == 0);
    const int virtual_fd = 5000;
    assert(guest_null_stdio_open_complete(&runtime, virtual_fd) == virtual_fd);
    assert(runtime.source_fd_open && runtime.open_succeeded == 1);

    assert(guest_null_stdio_unlink(&runtime, 1, "/init", 0,
        GUEST_NULL_STDIO_PATH) == 0);
    assert(!runtime.node_present && runtime.unlinked);
    assert(runtime.source_fd_open); /* unlink removes only the name, not the open file description */

    int result = -1;
    for (int target_fd = 0; target_fd <= 2; ++target_fd) {
        assert(guest_null_stdio_dup2(&runtime, &stdio_mask, virtual_fd,
            target_fd, 1, &result) == 1);
        assert(result == target_fd);
    }
    assert(stdio_mask == GUEST_NULL_STDIO_FD_MASK);
    guest_null_stdio_source_fd_closed(&runtime, virtual_fd);
    assert(!runtime.source_fd_open && runtime.source_fd_closes == 1);
    assert(stdio_mask == GUEST_NULL_STDIO_FD_MASK); /* dup2 aliases outlive source close */

    assert(guest_null_stdio_io(&runtime, stdio_mask, 0, 0, 4096, &result) == 1);
    assert(result == 0); /* null-device reads are EOF */
    assert(guest_null_stdio_io(&runtime, stdio_mask, 1, 1, 37, &result) == 1);
    assert(result == 37); /* null-device writes discard bytes and report count */
    assert(guest_null_stdio_io(&runtime, stdio_mask, 2, 1, 0, &result) == 1);
    assert(result == 0);
    assert(runtime.stdio_reads == 1 && runtime.stdio_writes == 2);

    assert(guest_null_stdio_close(&runtime, &stdio_mask, 2, &result) == 1);
    assert(result == 0 && stdio_mask == 0x03u);
    assert(guest_null_stdio_io(&runtime, stdio_mask, 2, 0, 1, &result) == 0);
    assert(runtime.unlink_succeeded == 1 && runtime.dup2_succeeded == 3);
}

static void test_open_failure_still_unlinks(void) {
    struct guest_null_stdio_runtime runtime;
    guest_null_stdio_runtime_init(&runtime);
    assert(guest_null_stdio_mknod(&runtime, 1, "/init", 0,
        GUEST_NULL_STDIO_PATH, GUEST_NULL_STDIO_MODE,
        GUEST_NULL_STDIO_DEVICE) == 0);
    assert(guest_null_stdio_open_validate(&runtime, 1, "/init", 0,
        GUEST_NULL_STDIO_PATH, GUEST_ARM32_O_RDWR | GUEST_ARM32_O_LARGEFILE) == 0);
    assert(guest_null_stdio_open_complete(&runtime, -EMFILE) == -EMFILE);
    assert(runtime.open_failed == 1 && runtime.node_present);
    assert(guest_null_stdio_unlink(&runtime, 1, "/init", 0,
        GUEST_NULL_STDIO_PATH) == 0);
    assert(!runtime.node_present && runtime.unlinked && runtime.source_fd == -1);
}

static void test_mknod_open_unlink_and_dup_fail_closed(void) {
    struct guest_null_stdio_runtime runtime;
    guest_null_stdio_runtime_init(&runtime);
    uint8_t stdio_mask = 0;
    int result = 0;

    assert(guest_null_stdio_mknod(&runtime, 1, "/init", 0,
        "/dev/__kmsg__", GUEST_NULL_STDIO_MODE, GUEST_NULL_STDIO_DEVICE) == -EOPNOTSUPP);
    assert(guest_null_stdio_mknod(&runtime, 1, "/init", 0,
        "/dev/__null__/../null", GUEST_NULL_STDIO_MODE, GUEST_NULL_STDIO_DEVICE) == -EOPNOTSUPP);
    assert(guest_null_stdio_mknod(&runtime, 1, "/sbin/ueventd", 0,
        GUEST_NULL_STDIO_PATH, GUEST_NULL_STDIO_MODE, GUEST_NULL_STDIO_DEVICE) == -EPERM);
    assert(guest_null_stdio_mknod(&runtime, 2, "/init", 0,
        GUEST_NULL_STDIO_PATH, GUEST_NULL_STDIO_MODE, GUEST_NULL_STDIO_DEVICE) == -EPERM);
    assert(guest_null_stdio_mknod(&runtime, 1, "/init", 1000,
        GUEST_NULL_STDIO_PATH, GUEST_NULL_STDIO_MODE, GUEST_NULL_STDIO_DEVICE) == -EPERM);
    assert(guest_null_stdio_mknod(&runtime, 1, "/init", 0,
        GUEST_NULL_STDIO_PATH, 0100600u, GUEST_NULL_STDIO_DEVICE) == -EINVAL);
    assert(guest_null_stdio_mknod(&runtime, 1, "/init", 0,
        GUEST_NULL_STDIO_PATH, 020666u, GUEST_NULL_STDIO_DEVICE) == -EINVAL);
    assert(guest_null_stdio_mknod(&runtime, 1, "/init", 0,
        GUEST_NULL_STDIO_PATH, GUEST_NULL_STDIO_MODE, 0x00000105u) == -EINVAL);
    assert(!runtime.node_present && runtime.mknod_accepted == 0);

    assert(guest_null_stdio_mknod(&runtime, 1, "/init", 0,
        GUEST_NULL_STDIO_PATH, GUEST_NULL_STDIO_MODE, GUEST_NULL_STDIO_DEVICE) == 0);
    assert(guest_null_stdio_open_validate(&runtime, 1, "/init", 0,
        GUEST_NULL_STDIO_PATH, 0u) == -EINVAL); /* O_RDONLY is not API10 O_RDWR */
    assert(guest_null_stdio_open_validate(&runtime, 1, "/init", 0,
        GUEST_NULL_STDIO_PATH, GUEST_ARM32_O_RDWR | 0100u) == -EINVAL);
    assert(guest_null_stdio_open_validate(&runtime, 2, "/init", 0,
        GUEST_NULL_STDIO_PATH, GUEST_ARM32_O_RDWR) == -EPERM);
    assert(runtime.open_failed == 3 && runtime.node_present);

    assert(guest_null_stdio_unlink(&runtime, 1, "/init", 0,
        GUEST_NULL_STDIO_PATH) == 0); /* API10 unlinks even if open failed */
    assert(!runtime.node_present);

    assert(guest_null_stdio_dup2(&runtime, &stdio_mask, 5000, 1, 1, &result) == 1);
    assert(result == 1 && stdio_mask == 0x02u);
    assert(guest_null_stdio_dup2(&runtime, &stdio_mask, 5000, 3, 1, &result) == 1);
    assert(result == -EOPNOTSUPP && stdio_mask == 0x02u);
    assert(guest_null_stdio_dup2(&runtime, &stdio_mask, 99, 2, 0, &result) == 0);
}

int main(void) {
    test_exact_init_sequence();
    test_open_failure_still_unlinks();
    test_mknod_open_unlink_and_dup_fail_closed();
    puts("guest null-device init stdio state-machine regression: PASS (API10 mknod 1:3/0600 -> O_RDWR virtual FD -> unlink -> dup2 0/1/2 -> EOF/discard; denied variants fail closed; no host device operation; original guest binaries are not executed)");
    return 0;
}
