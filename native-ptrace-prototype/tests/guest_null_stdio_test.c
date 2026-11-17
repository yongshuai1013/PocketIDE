#include "../app/src/main/cpp/guest_null_stdio.h"

#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>

static struct guest_null_stdio_identity init_identity(void) {
    return (struct guest_null_stdio_identity) {
        .guest_pid = 1, .guest_parent_pid = 0, .guest_euid = 0,
        .executable = "/init", .exec_image_committed = 1,
        .arm32_elf_valid = 1, .backing_path_approved = 1
    };
}

static struct guest_null_stdio_identity ueventd_identity(void) {
    return (struct guest_null_stdio_identity) {
        .guest_pid = 2, .guest_parent_pid = 1, .guest_euid = 0,
        .executable = "/sbin/ueventd", .exec_image_committed = 1,
        .arm32_elf_valid = 1, .backing_path_approved = 1
    };
}

static void test_exact_init_sequence(void) {
    struct guest_null_stdio_runtime runtime;
    guest_null_stdio_runtime_init(&runtime);
    struct guest_null_stdio_identity init = init_identity();
    uint8_t stdio_mask = 0;

    assert(guest_null_stdio_actor_for_identity(&init) == GUEST_NULL_STDIO_ACTOR_INIT);
    assert(guest_null_stdio_mknod(&runtime, &init, GUEST_NULL_STDIO_PATH,
        GUEST_NULL_STDIO_MODE, GUEST_NULL_STDIO_DEVICE) == 0);
    assert(runtime.node_present && !runtime.unlinked && runtime.mknod_accepted == 1);

    assert(guest_null_stdio_open_validate(&runtime, &init, GUEST_NULL_STDIO_PATH,
        GUEST_ARM32_O_RDWR | GUEST_ARM32_O_LARGEFILE) == 0);
    const int virtual_fd = 5000;
    assert(guest_null_stdio_open_complete(&runtime, virtual_fd) == virtual_fd);
    assert(runtime.source_fd_open && runtime.open_succeeded == 1);
    assert(guest_null_stdio_open_validate(&runtime, &init, GUEST_NULL_STDIO_PATH,
        GUEST_ARM32_O_RDWR) == -EBUSY); /* unsupported second open cannot alias global state */

    assert(guest_null_stdio_unlink(&runtime, &init, GUEST_NULL_STDIO_PATH) == 0);
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

static void test_ueventd_identity_and_stdio_sequence(void) {
    struct guest_null_stdio_runtime runtime;
    guest_null_stdio_runtime_init(&runtime);
    struct guest_null_stdio_identity init = init_identity();
    struct guest_null_stdio_identity ueventd = ueventd_identity();
    uint8_t init_mask = 0, ueventd_mask = 0;
    int result = 0;

    /* PID/executable text alone is insufficient: every image and ancestry
     * predicate must be present before ueventd may recreate /dev/__null__. */
    assert(guest_null_stdio_actor_for_identity(&ueventd) == GUEST_NULL_STDIO_ACTOR_UEVENTD);
    struct guest_null_stdio_identity bad = ueventd;
    bad.backing_path_approved = 0;
    assert(guest_null_stdio_actor_for_identity(&bad) == GUEST_NULL_STDIO_ACTOR_DENIED);
    bad = ueventd; bad.arm32_elf_valid = 0;
    assert(guest_null_stdio_actor_for_identity(&bad) == GUEST_NULL_STDIO_ACTOR_DENIED);
    bad = ueventd; bad.exec_image_committed = 0;
    assert(guest_null_stdio_actor_for_identity(&bad) == GUEST_NULL_STDIO_ACTOR_DENIED);
    bad = ueventd; bad.guest_parent_pid = 9;
    assert(guest_null_stdio_actor_for_identity(&bad) == GUEST_NULL_STDIO_ACTOR_DENIED);
    bad = ueventd; bad.guest_euid = 1000;
    assert(guest_null_stdio_actor_for_identity(&bad) == GUEST_NULL_STDIO_ACTOR_DENIED);
    bad = ueventd; bad.executable = "/system/bin/ueventd";
    assert(guest_null_stdio_actor_for_identity(&bad) == GUEST_NULL_STDIO_ACTOR_DENIED);
    bad = ueventd; bad.guest_pid = 1;
    assert(guest_null_stdio_actor_for_identity(&bad) == GUEST_NULL_STDIO_ACTOR_DENIED);

    assert(guest_null_stdio_mknod(&runtime, &init, GUEST_NULL_STDIO_PATH,
        GUEST_NULL_STDIO_MODE, GUEST_NULL_STDIO_DEVICE) == 0);
    assert(guest_null_stdio_open_validate(&runtime, &init, GUEST_NULL_STDIO_PATH,
        GUEST_ARM32_O_RDWR) == 0);
    assert(guest_null_stdio_open_complete(&runtime, 5000) == 5000);
    assert(guest_null_stdio_unlink(&runtime, &init, GUEST_NULL_STDIO_PATH) == 0);
    for (int fd = 0; fd <= 2; ++fd)
        assert(guest_null_stdio_dup2(&runtime, &init_mask, 5000, fd, 1, &result) == 1);
    guest_null_stdio_source_fd_closed(&runtime, 5000);

    /* ueventd is PID1's verified direct child and must perform the same
     * source-shaped sequence with its own app-private guest FD table. */
    assert(guest_null_stdio_mknod(&runtime, &ueventd, GUEST_NULL_STDIO_PATH,
        GUEST_NULL_STDIO_MODE, GUEST_NULL_STDIO_DEVICE) == 0);
    assert(guest_null_stdio_open_validate(&runtime, &ueventd, GUEST_NULL_STDIO_PATH,
        GUEST_ARM32_O_RDWR | GUEST_ARM32_O_LARGEFILE) == 0);
    assert(guest_null_stdio_open_complete(&runtime, 5001) == 5001);
    assert(guest_null_stdio_unlink(&runtime, &ueventd, GUEST_NULL_STDIO_PATH) == 0);
    ueventd_mask = init_mask;
    for (int fd = 0; fd <= 2; ++fd)
        assert(guest_null_stdio_dup2(&runtime, &ueventd_mask, 5001, fd, 1, &result) == 1);
    guest_null_stdio_source_fd_closed(&runtime, 5001);
    assert(ueventd_mask == GUEST_NULL_STDIO_FD_MASK);
    assert(runtime.mknod_accepted == 2 && runtime.open_succeeded == 2 &&
           runtime.unlink_succeeded == 2 && runtime.source_fd_closes == 2);
}

static void test_open_failure_still_unlinks(void) {
    struct guest_null_stdio_runtime runtime;
    guest_null_stdio_runtime_init(&runtime);
    struct guest_null_stdio_identity init = init_identity();
    assert(guest_null_stdio_mknod(&runtime, &init, GUEST_NULL_STDIO_PATH,
        GUEST_NULL_STDIO_MODE, GUEST_NULL_STDIO_DEVICE) == 0);
    assert(guest_null_stdio_open_validate(&runtime, &init, GUEST_NULL_STDIO_PATH,
        GUEST_ARM32_O_RDWR | GUEST_ARM32_O_LARGEFILE) == 0);
    assert(guest_null_stdio_open_complete(&runtime, -EMFILE) == -EMFILE);
    assert(runtime.open_failed == 1 && runtime.node_present);
    assert(guest_null_stdio_unlink(&runtime, &init, GUEST_NULL_STDIO_PATH) == 0);
    assert(!runtime.node_present && runtime.unlinked && runtime.source_fd == -1);
}

static void test_fail_closed_and_dup2_replacement(void) {
    struct guest_null_stdio_runtime runtime;
    guest_null_stdio_runtime_init(&runtime);
    struct guest_null_stdio_identity init = init_identity();
    struct guest_null_stdio_identity ueventd = ueventd_identity();
    struct guest_null_stdio_identity denied = ueventd;
    uint8_t stdio_mask = 0;
    int result = 0;

    denied.backing_path_approved = 0;
    assert(guest_null_stdio_mknod(&runtime, &denied, GUEST_NULL_STDIO_PATH,
        GUEST_NULL_STDIO_MODE, GUEST_NULL_STDIO_DEVICE) == -EPERM);
    assert(guest_null_stdio_mknod(&runtime, &ueventd, "/dev/__kmsg__",
        GUEST_NULL_STDIO_MODE, GUEST_NULL_STDIO_DEVICE) == -EOPNOTSUPP);
    assert(guest_null_stdio_mknod(&runtime, &ueventd, "/dev/__null__/../null",
        GUEST_NULL_STDIO_MODE, GUEST_NULL_STDIO_DEVICE) == -EOPNOTSUPP);
    assert(guest_null_stdio_mknod(&runtime, &init, GUEST_NULL_STDIO_PATH,
        0100600u, GUEST_NULL_STDIO_DEVICE) == -EINVAL);
    assert(guest_null_stdio_mknod(&runtime, &init, GUEST_NULL_STDIO_PATH,
        020666u, GUEST_NULL_STDIO_DEVICE) == -EINVAL);
    assert(guest_null_stdio_mknod(&runtime, &init, GUEST_NULL_STDIO_PATH,
        GUEST_NULL_STDIO_MODE, 0x00000105u) == -EINVAL);
    assert(!runtime.node_present && runtime.mknod_accepted == 0);

    assert(guest_null_stdio_mknod(&runtime, &init, GUEST_NULL_STDIO_PATH,
        GUEST_NULL_STDIO_MODE, GUEST_NULL_STDIO_DEVICE) == 0);
    assert(guest_null_stdio_open_validate(&runtime, &init, GUEST_NULL_STDIO_PATH, 0u) == -EINVAL);
    assert(guest_null_stdio_open_validate(&runtime, &init, GUEST_NULL_STDIO_PATH,
        GUEST_ARM32_O_RDWR | 0100u) == -EINVAL);
    assert(guest_null_stdio_open_validate(&runtime, &ueventd, GUEST_NULL_STDIO_PATH,
        GUEST_ARM32_O_RDWR) == 0);
    assert(guest_null_stdio_open_complete(&runtime, 5000) == 5000);
    assert(guest_null_stdio_open_validate(&runtime, &init, GUEST_NULL_STDIO_PATH,
        GUEST_ARM32_O_RDWR) == -EBUSY);
    assert(runtime.open_failed == 3 && runtime.node_present);

    assert(guest_null_stdio_unlink(&runtime, &init, GUEST_NULL_STDIO_PATH) == 0);
    assert(!runtime.node_present);
    assert(guest_null_stdio_dup2(&runtime, &stdio_mask, 5000, 1, 1, &result) == 1);
    assert(result == 1 && stdio_mask == 0x02u);
    assert(guest_null_stdio_dup2(&runtime, &stdio_mask, 5000, 3, 1, &result) == 1);
    assert(result == -EOPNOTSUPP && stdio_mask == 0x02u);
    assert(guest_null_stdio_dup2(&runtime, &stdio_mask, 99, 2, 0, &result) == 0);

    uint8_t replaced_mask = GUEST_NULL_STDIO_FD_MASK;
    assert(guest_null_stdio_note_dup2_result(&replaced_mask, 1, 0, 1) == 1);
    assert(replaced_mask == 0x05u); /* ordinary file replaced the null alias */
    assert(guest_null_stdio_note_dup2_result(&replaced_mask, 0, 0, -EBADF) == 0);
    assert(replaced_mask == 0x05u); /* failed dup2 does not alter guest state */
    assert(guest_null_stdio_note_dup2_result(&replaced_mask, 2, 1, 2) == 0);
    assert(replaced_mask == 0x05u); /* null-backed source keeps null semantics */
}

int main(void) {
    test_exact_init_sequence();
    test_ueventd_identity_and_stdio_sequence();
    test_open_failure_still_unlinks();
    test_fail_closed_and_dup2_replacement();
    puts("guest null-device init/ueventd stdio state-machine regression: PASS (verified PID1 and direct-child ueventd identities; exact 1:3/0600 mknod -> O_RDWR -> unlink -> dup2 0/1/2; duplicate opens and outside identities fail closed; null FD replacement tracked only after successful dup2; no host device operation; guest binaries are not executed)");
    return 0;
}
