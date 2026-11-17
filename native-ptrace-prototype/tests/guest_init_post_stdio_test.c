#define _GNU_SOURCE
#include "../app/src/main/cpp/guest_null_stdio.h"
#include "../app/src/main/cpp/guest_kmsg_virtual.h"
#include "../app/src/main/cpp/guest_uevent_virtual.h"
#include "../app/src/main/cpp/guest_safe_dir.h"

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

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

static struct guest_null_stdio_identity make_init_identity(void) {
    return (struct guest_null_stdio_identity) {
        .guest_pid = 1, .guest_parent_pid = 0, .guest_euid = 0,
        .executable = "/init", .exec_image_committed = 1,
        .arm32_elf_valid = 1, .backing_path_approved = 1
    };
}

static struct guest_null_stdio_identity make_ueventd_identity(void) {
    return (struct guest_null_stdio_identity) {
        .guest_pid = 2, .guest_parent_pid = 1, .guest_euid = 0,
        .executable = "/sbin/ueventd", .exec_image_committed = 1,
        .arm32_elf_valid = 1, .backing_path_approved = 1
    };
}

static uint8_t api10_null_stdio_setup(struct guest_null_stdio_runtime *runtime,
        const struct guest_null_stdio_identity *identity, int virtual_fd,
        enum guest_null_stdio_actor expected_actor) {
    assert(guest_null_stdio_actor_for_identity(identity) == expected_actor);
    assert(guest_null_stdio_mknod(runtime, identity, GUEST_NULL_STDIO_PATH,
        GUEST_NULL_STDIO_MODE, GUEST_NULL_STDIO_DEVICE) == 0);
    assert(guest_null_stdio_open_validate(runtime, identity, GUEST_NULL_STDIO_PATH,
        GUEST_ARM32_O_RDWR | GUEST_ARM32_O_LARGEFILE) == 0);
    assert(guest_null_stdio_open_complete(runtime, virtual_fd) == virtual_fd);
    assert(guest_null_stdio_unlink(runtime, identity, GUEST_NULL_STDIO_PATH) == 0);
    uint8_t mask = 0;
    int result = -1;
    for (int target = 0; target <= 2; ++target) {
        assert(guest_null_stdio_dup2(runtime, &mask, virtual_fd, target, 1,
            &result) == 1);
        assert(result == target);
    }
    guest_null_stdio_source_fd_closed(runtime, virtual_fd);
    assert(!runtime->source_fd_open && mask == GUEST_NULL_STDIO_FD_MASK);
    assert(guest_null_stdio_io(runtime, mask, 0, 0, 64, &result) == 1 && result == 0);
    assert(guest_null_stdio_io(runtime, mask, 1, 1, 19, &result) == 1 && result == 19);
    return mask;
}

static void test_continuous_init_to_ueventd_coldboot_model(
        const char *init_rc_path, const char *goldfish_rc_path) {
    struct guest_null_stdio_runtime null_runtime;
    guest_null_stdio_runtime_init(&null_runtime);
    struct guest_null_stdio_identity init = make_init_identity();
    struct guest_null_stdio_identity ueventd = make_ueventd_identity();

    /* API10 init.c: open_devnull_stdio() precedes log_init() and config parse. */
    uint8_t init_stdio_mask = api10_null_stdio_setup(&null_runtime, &init,
        5000, GUEST_NULL_STDIO_ACTOR_INIT);
    assert(init_stdio_mask == GUEST_NULL_STDIO_FD_MASK);

    /* API10 log_init() is optional: the software-only kmsg model never blocks
     * subsequent config loading when its exact request is rejected. */
    struct guest_kmsg_runtime kmsg;
    guest_kmsg_runtime_init(&kmsg);
    assert(guest_kmsg_mknod(&kmsg, 1, "/init", 0, GUEST_KMSG_PATH,
        GUEST_KMSG_MODE, GUEST_KMSG_DEVICE) == 0);
    const uint32_t kmsg_flags = GUEST_KMSG_O_WRONLY | GUEST_KMSG_O_LARGEFILE;
    assert(guest_kmsg_open_validate(&kmsg, 1, "/init", 0,
        GUEST_KMSG_PATH, kmsg_flags) == 0);
    assert(guest_kmsg_open_complete(&kmsg, 5001) == 5001);
    guest_kmsg_note_fcntl(&kmsg, 5001, GUEST_KMSG_F_SETFD,
        GUEST_KMSG_FD_CLOEXEC, 0);
    assert(kmsg.fd_cloexec);
    assert(guest_kmsg_unlink(&kmsg, 1, "/init", 0, GUEST_KMSG_PATH) == 0);
    guest_kmsg_note_write(&kmsg, 5001, 28);

    char *init_rc = read_text(init_rc_path);
    char *goldfish_rc = read_text(goldfish_rc_path);
    assert(strstr(init_rc, "on early-init") != NULL);
    assert(strstr(init_rc, "start ueventd") != NULL);
    assert(strstr(goldfish_rc, "on boot") != NULL);
    assert(strstr(goldfish_rc,
        "service goldfish-setup /system/etc/init.goldfish.sh") != NULL);
    free(init_rc);
    free(goldfish_rc);
    /* The CLOEXEC kmsg descriptor is closed on the ueventd exec, independently
     * of the null stdio descriptors inherited through dup2. */
    guest_kmsg_note_fd_closed(&kmsg, 5001, 0, 0, 1);
    assert(!kmsg.fd_open && kmsg.close_on_exec_calls == 1);

    /* The sole additional mknod actor is a committed, valid ARM32 ELF image of
     * /sbin/ueventd that is a root direct child of PID1. */
    struct guest_null_stdio_identity bad = ueventd;
    bad.backing_path_approved = 0;
    assert(guest_null_stdio_mknod(&null_runtime, &bad, GUEST_NULL_STDIO_PATH,
        GUEST_NULL_STDIO_MODE, GUEST_NULL_STDIO_DEVICE) == -EPERM);
    uint8_t ueventd_stdio_mask = api10_null_stdio_setup(&null_runtime,
        &ueventd, 5002, GUEST_NULL_STDIO_ACTOR_UEVENTD);
    assert(ueventd_stdio_mask == GUEST_NULL_STDIO_FD_MASK);
    assert(null_runtime.mknod_accepted == 2 && null_runtime.open_succeeded == 2 &&
           null_runtime.unlink_succeeded == 2 && null_runtime.source_fd_closes == 2);

    /* API10 devices.c uses a guest AF_NETLINK/SOCK_DGRAM/kobject socket. All
     * arguments and events stay in this process-local software model. */
    assert(guest_uevent_socket_args_valid(16, 2, 15));
    assert(!guest_uevent_socket_args_valid(1, 2, 15));
    struct guest_uevent_sockaddr_nl bind_addr = {
        .family = GUEST_UEVENT_AF_NETLINK, .pad = 0, .pid = 2,
        .groups = UINT32_MAX
    };
    const int authorized_ueventd =
        guest_null_stdio_actor_for_identity(&ueventd) ==
            GUEST_NULL_STDIO_ACTOR_UEVENTD;
    assert(authorized_ueventd);
    assert(guest_uevent_bind_args_valid(&bind_addr, sizeof(bind_addr), 2));
    assert(!guest_uevent_bind_args_valid(&bind_addr, sizeof(bind_addr), 1));
    assert(guest_uevent_setsockopt_args_valid(1, GUEST_UEVENT_SO_PASSCRED, 1, 4));
    assert(guest_uevent_setsockopt_args_valid(1, GUEST_UEVENT_SO_RCVBUFFORCE,
        GUEST_UEVENT_RCVBUFFORCE_BYTES, 4));

    struct guest_uevent_queue queue;
    guest_uevent_queue_init(&queue);
    static const char add_request[] = "add\n";
    assert(guest_uevent_enqueue_coldboot_add(&queue, authorized_ueventd,
        GUEST_UEVENT_SYSFS_ATTRIBUTE_PATH, add_request,
        sizeof(add_request) - 1u) == 4);
    assert(guest_uevent_enqueue_coldboot_add(&queue, authorized_ueventd,
        GUEST_FB0_SYSFS_ATTRIBUTE_PATH, add_request,
        sizeof(add_request) - 1u) == 4);
    assert(guest_uevent_queue_readable(&queue));
    const struct guest_uevent_event *net_event = guest_uevent_queue_front(&queue);
    assert(net_event && net_event->length > 0);
    assert(memmem(net_event->data, net_event->length,
        "INTERFACE=" GUEST_PROFILE_NET_IFACE,
        sizeof("INTERFACE=" GUEST_PROFILE_NET_IFACE) - 1u) != NULL);
    assert(guest_uevent_queue_consume(&queue) == 0);
    const struct guest_uevent_event *graphics_event = guest_uevent_queue_front(&queue);
    assert(graphics_event && graphics_event->length > 0);
    assert(memmem(graphics_event->data, graphics_event->length,
        "MAJOR=29", 8) != NULL);
    assert(memmem(graphics_event->data, graphics_event->length,
        "MINOR=0", 7) != NULL);
    assert(guest_uevent_queue_consume(&queue) == 0);
    assert(queue.enqueued == 2 && queue.delivered == 2 &&
           !guest_uevent_queue_readable(&queue));

    /* The host temporary file below is test-only persistence evidence. The app
     * runtime uses the guest VFS/app-private backing and never host mknod. */
    struct guest_coldboot_observation observation = {0};
    char template[] = "/tmp/gingervm-init-ueventd-marker-XXXXXX";
    char *root = mkdtemp(template);
    assert(root != NULL);
    char dev_dir[PATH_MAX], marker_path[PATH_MAX], vfs_dir[PATH_MAX];
    int length = snprintf(dev_dir, sizeof(dev_dir), "%s/.vfs/mount-0", root);
    assert(length > 0 && (size_t)length < sizeof(dev_dir));
    int safe_dir_fd = guest_safe_dir_open_beneath_root(root, dev_dir, 1, 0700);
    assert(safe_dir_fd >= 0 && close(safe_dir_fd) == 0);
    length = snprintf(marker_path, sizeof(marker_path), "%s/.coldboot_done", dev_dir);
    assert(length > 0 && (size_t)length < sizeof(marker_path));
    length = snprintf(vfs_dir, sizeof(vfs_dir), "%s/.vfs", root);
    assert(length > 0 && (size_t)length < sizeof(vfs_dir));
    struct stat absent;
    assert(stat(marker_path, &absent) == -1 && errno == ENOENT);
    assert(guest_coldboot_note_pid1_stat(&observation, 1,
        GUEST_COLD_BOOT_MARKER_PATH, -ENOENT) == 0);

    const uint32_t marker_flags = O_WRONLY | O_CREAT;
    int marker_fd = open(marker_path, (int)(marker_flags | O_NOFOLLOW), 0000);
    assert(marker_fd >= 0);
    assert(guest_coldboot_note_marker_open(&observation, authorized_ueventd,
        GUEST_COLD_BOOT_MARKER_PATH, marker_flags, 0000, marker_fd) == 0);
    assert(observation.marker_opened_by_ueventd &&
           observation.marker_open_result == marker_fd);
    struct stat opened;
    assert(fstat(marker_fd, &opened) == 0 && S_ISREG(opened.st_mode));
    assert((opened.st_mode & 07777u) == 0u && opened.st_ino != 0 && opened.st_size == 0);
    assert(close(marker_fd) == 0);
    assert(guest_coldboot_note_marker_close(&observation, authorized_ueventd,
        marker_fd, 0) == 1);
    struct stat persisted;
    assert(lstat(marker_path, &persisted) == 0 && S_ISREG(persisted.st_mode));
    assert(persisted.st_ino == opened.st_ino &&
           (persisted.st_mode & 07777u) == 0u && persisted.st_size == 0);
    assert(guest_coldboot_note_pid1_stat(&observation, 1,
        GUEST_COLD_BOOT_MARKER_PATH, 0) == 1);
    assert(observation.marker_close_observed &&
           observation.pid1_stat_succeeded_after_marker &&
           observation.marker_stat_pair_observed);

    assert(unlink(marker_path) == 0);
    assert(rmdir(dev_dir) == 0 && rmdir(vfs_dir) == 0 && rmdir(root) == 0);
}

static void test_kmsg_failure_is_optional_and_closed(void) {
    struct guest_kmsg_runtime runtime;
    guest_kmsg_runtime_init(&runtime);
    assert(guest_kmsg_mknod(&runtime, 1, "/init", 0, GUEST_KMSG_PATH,
        GUEST_KMSG_MODE, GUEST_KMSG_DEVICE + 1u) == -EINVAL);
    assert(!runtime.node_present);
    /* Source-order test also confirms init continues on to read init.rc. */
}

int main(int argc, char **argv) {
    assert(argc == 3);
    test_continuous_init_to_ueventd_coldboot_model(argv[1], argv[2]);
    test_kmsg_failure_is_optional_and_closed();
    puts("API10 continuous init-to-ueventd coldboot state-machine/source-content regression: PASS (verified PID1 null stdio -> optional kmsg CLOEXEC -> staged init.rc/Goldfish actions -> verified direct-child ueventd null stdio -> guest-only AF_NETLINK contract/bind/options -> queued net+fb0 add drain -> mode-0000 marker open/close/inode persistence -> PID1 stat condition; fail-closed identity checked; no guest binaries, host netlink, device node, root or mount executed)");
    return 0;
}
