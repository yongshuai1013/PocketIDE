#define _GNU_SOURCE
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

#include "../app/src/main/cpp/guest_uevent_virtual.h"
#include "../app/src/main/cpp/guest_safe_dir.h"

static void test_socket_contract(void) {
    assert(guest_uevent_socket_args_valid(16, 2, 15));
    assert(!guest_uevent_socket_args_valid(1, 2, 15));
    assert(!guest_uevent_socket_args_valid(16, 1, 15));
    assert(!guest_uevent_socket_args_valid(16, 2, 0));

    struct guest_uevent_sockaddr_nl addr = {
        .family = 16, .pad = 0, .pid = 2, .groups = UINT32_MAX,
    };
    assert(guest_uevent_bind_args_valid(&addr, sizeof(addr), 2));
    assert(!guest_uevent_bind_args_valid(&addr, sizeof(addr) - 1, 2));
    assert(!guest_uevent_bind_args_valid(&addr, sizeof(addr), 3));
    addr.pad = 1;
    assert(!guest_uevent_bind_args_valid(&addr, sizeof(addr), 2));
    addr.pad = 0; addr.groups = 0;
    assert(!guest_uevent_bind_args_valid(&addr, sizeof(addr), 2));
    addr.groups = UINT32_MAX; addr.family = 1;
    assert(!guest_uevent_bind_args_valid(&addr, sizeof(addr), 2));

    assert(guest_uevent_setsockopt_args_valid(1, 33, 65536, 4));
    assert(guest_uevent_setsockopt_args_valid(1, 16, 1, 4));
    assert(!guest_uevent_setsockopt_args_valid(1, 33, 65535, 4));
    assert(!guest_uevent_setsockopt_args_valid(1, 16, 0, 4));
    assert(!guest_uevent_setsockopt_args_valid(0, 16, 1, 4));
    assert(!guest_uevent_setsockopt_args_valid(1, 999, 1, 4));
    assert(!guest_uevent_setsockopt_args_valid(1, 16, 1, 3));
}

static void test_coldboot_event_drain_marker_and_pid1_stat(void) {
    struct guest_uevent_queue queue;
    guest_uevent_queue_init(&queue);
    assert(!guest_uevent_queue_readable(&queue));

    static const char request[] = "add\n";
    assert(guest_uevent_enqueue_coldboot_add(&queue, 0,
        GUEST_UEVENT_SYSFS_ATTRIBUTE_PATH, request, sizeof(request) - 1) == -EPERM);
    assert(guest_uevent_enqueue_coldboot_add(&queue, 1,
        "/sys/devices/virtual/other/uevent", request, sizeof(request) - 1) == -ENOENT);
    assert(guest_uevent_enqueue_coldboot_add(&queue, 1,
        GUEST_UEVENT_SYSFS_ATTRIBUTE_PATH, "remove\n", 7) == -EINVAL);
    assert(!guest_uevent_queue_readable(&queue));

    struct guest_uevent_sockaddr_nl bind_addr = {
        .family = GUEST_UEVENT_AF_NETLINK, .pad = 0, .pid = 2,
        .groups = UINT32_MAX,
    };
    assert(guest_uevent_bind_args_valid(&bind_addr, sizeof(bind_addr), 2));
    assert(guest_uevent_setsockopt_args_valid(1, GUEST_UEVENT_SO_PASSCRED, 1, 4));
    assert(guest_uevent_setsockopt_args_valid(1, GUEST_UEVENT_SO_RCVBUFFORCE,
                                               GUEST_UEVENT_RCVBUFFORCE_BYTES, 4));

    assert(guest_uevent_enqueue_coldboot_add(&queue, 1,
        GUEST_UEVENT_SYSFS_ATTRIBUTE_PATH, request, sizeof(request) - 1) == 4);
    assert(guest_uevent_queue_readable(&queue)); /* API10 do_coldboot immediately recvmsg-drains this */
    const struct guest_uevent_event *event = guest_uevent_queue_front(&queue);
    assert(event && event->length > 0);
    static const char expected[] =
        "add@" GUEST_UEVENT_SYSFS_DEVICE_PATH "\0"
        "ACTION=add\0"
        "DEVPATH=" GUEST_UEVENT_SYSFS_DEVICE_PATH "\0"
        "SUBSYSTEM=net\0"
        "INTERFACE=" GUEST_PROFILE_NET_IFACE "\0";
    assert(event->length == sizeof(expected) - 1);
    assert(memcmp(event->data, expected, sizeof(expected) - 1) == 0);
    assert(memmem(event->data, event->length, "DEVNAME=", 8) == NULL);
    assert(memmem(event->data, event->length, "MAJOR=", 6) == NULL);
    assert(guest_uevent_queue_consume(&queue) == 0); /* guest recvmsg + SCM_CREDENTIALS */
    assert(!guest_uevent_queue_readable(&queue)); /* later ueventd_main poll remains asleep */
    assert(guest_uevent_queue_consume(&queue) == -EAGAIN);
    assert(queue.enqueued == 1 && queue.delivered == 1 && queue.rejected == 3);

    struct guest_coldboot_observation observation = {0};
    /* A pre-marker stat cannot prove the wait condition was released. */
    assert(guest_coldboot_note_pid1_stat(&observation, 1,
        GUEST_COLD_BOOT_MARKER_PATH, -ENOENT) == 0);
    assert(guest_coldboot_note_pid1_stat(&observation, 1,
        GUEST_COLD_BOOT_MARKER_PATH, 0) == 0);
    assert(!observation.pid1_stat_succeeded_after_marker &&
           !observation.marker_stat_pair_observed);
    const uint32_t marker_flags = O_WRONLY | O_CREAT;
    assert(!guest_coldboot_marker_open_args_valid(O_RDONLY | O_CREAT, 0));
    assert(!guest_coldboot_marker_open_args_valid(O_WRONLY, 0));
    assert(!guest_coldboot_marker_open_args_valid(O_WRONLY | O_CREAT | O_TRUNC, 0));
    assert(!guest_coldboot_marker_open_args_valid(marker_flags, 0600));
#ifdef O_CLOEXEC
    assert(!guest_coldboot_marker_open_args_valid(marker_flags | O_CLOEXEC, 0));
#endif
#ifdef O_LARGEFILE
    assert(guest_coldboot_marker_open_args_valid(marker_flags | O_LARGEFILE, 0));
#endif
    assert(guest_coldboot_note_marker_open(&observation, 0,
        GUEST_COLD_BOOT_MARKER_PATH, marker_flags, 0, 4) == 0);
    assert(guest_coldboot_note_marker_open(&observation, 1,
        "/dev/not-coldboot", marker_flags, 0, 4) == 0);
    assert(guest_coldboot_note_marker_open(&observation, 1,
        GUEST_COLD_BOOT_MARKER_PATH, marker_flags, 0, -EACCES) == 0);
    assert(guest_coldboot_note_marker_open(&observation, 1,
        GUEST_COLD_BOOT_MARKER_PATH, marker_flags, 0, 4) == 0);
    assert(!observation.marker_stat_pair_observed);
    assert(guest_coldboot_note_marker_close(&observation, 1, 5, 0) == 0);
    assert(!observation.marker_close_observed);
    assert(guest_coldboot_note_marker_close(&observation, 1, 4, 0) == 1);
    assert(observation.marker_close_observed && observation.marker_close_result == 0);
    assert(guest_coldboot_note_pid1_stat(&observation, 1,
        GUEST_COLD_BOOT_MARKER_PATH, 0) == 1);
    assert(observation.pid1_stat_succeeded_after_marker);
    assert(observation.marker_stat_pair_observed);
    assert(guest_coldboot_note_marker_open(&observation, 1,
        GUEST_COLD_BOOT_MARKER_PATH, marker_flags, 0, 5) == 0); /* first fd retained */
    assert(observation.marker_open_fd == 4);

    struct guest_coldboot_observation source_order = {0};
    assert(guest_coldboot_note_marker_open(&source_order, 1,
        GUEST_COLD_BOOT_MARKER_PATH, marker_flags, 0, 4) == 0);
    assert(guest_coldboot_note_pid1_stat(&source_order, 2,
        GUEST_COLD_BOOT_MARKER_PATH, 0) == 0); /* not guest PID 1 */
    assert(guest_coldboot_note_pid1_stat(&source_order, 1,
        GUEST_COLD_BOOT_MARKER_PATH, 0) == 1);
    assert(source_order.marker_stat_pair_observed);
}

static void test_api10_coldboot_sequence_model_and_marker_persistence(void) {
    struct guest_uevent_queue queue;
    guest_uevent_queue_init(&queue);
    struct guest_coldboot_observation observation = {0};
    char template[] = "/tmp/gingervm-coldboot-marker-XXXXXX";
    char *root = mkdtemp(template);
    assert(root != NULL);
    char dev_backing[PATH_MAX], marker_path[PATH_MAX], vfs_path[PATH_MAX];
    int n = snprintf(dev_backing, sizeof(dev_backing), "%s/.vfs/mount-0", root);
    assert(n > 0 && (size_t)n < sizeof(dev_backing));
    int dirfd = guest_safe_dir_open_beneath_root(root, dev_backing, 1, 0700);
    assert(dirfd >= 0);
    assert(close(dirfd) == 0);
    n = snprintf(marker_path, sizeof(marker_path), "%s/.coldboot_done", dev_backing);
    assert(n > 0 && (size_t)n < sizeof(marker_path));
    n = snprintf(vfs_path, sizeof(vfs_path), "%s/.vfs", root);
    assert(n > 0 && (size_t)n < sizeof(vfs_path));

    struct stat before;
    for (unsigned i = 0; i < 8; ++i) {
        errno = 0;
        assert(stat(marker_path, &before) == -1 && errno == ENOENT);
        assert(guest_coldboot_note_pid1_stat(&observation, 1,
            GUEST_COLD_BOOT_MARKER_PATH, -ENOENT) == 0);
    }
    assert(observation.pid1_stat_checks == 8);
    assert(!observation.marker_opened_by_ueventd);

    /* API10 do_coldboot triggers an add, drains its socket, then device_init
     * creates the marker after the coldboot directory walks complete. */
    static const char request[] = "add\n";
    assert(guest_uevent_enqueue_coldboot_add(&queue, 1,
        GUEST_UEVENT_SYSFS_ATTRIBUTE_PATH, request, sizeof(request) - 1) == 4);
    assert(guest_uevent_queue_readable(&queue));
    const struct guest_uevent_event *event = guest_uevent_queue_front(&queue);
    assert(event != NULL);
    static const char expected_event[] =
        "add@" GUEST_UEVENT_SYSFS_DEVICE_PATH "\0"
        "ACTION=add\0"
        "DEVPATH=" GUEST_UEVENT_SYSFS_DEVICE_PATH "\0"
        "SUBSYSTEM=net\0"
        "INTERFACE=" GUEST_PROFILE_NET_IFACE "\0";
    assert(event->length == sizeof(expected_event) - 1);
    assert(memcmp(event->data, expected_event, sizeof(expected_event) - 1) == 0);
    assert(guest_uevent_queue_consume(&queue) == 0); /* API10 handle_device_fd() */
    assert(!guest_uevent_queue_readable(&queue));
    assert(queue.enqueued == 1 && queue.delivered == 1 && queue.count == 0);

    /* API10 devices.c: open(coldboot_done, O_WRONLY|O_CREAT, 0000); close(fd). */
    const uint32_t flags = O_WRONLY | O_CREAT;
    int fd = open(marker_path, (int)flags, 0000);
    assert(fd >= 0);
    assert(guest_coldboot_note_marker_open(&observation, 1,
        GUEST_COLD_BOOT_MARKER_PATH, flags, 0000, fd) == 0);
    assert(observation.marker_opened_by_ueventd);
    assert(observation.marker_open_flags == flags && observation.marker_open_mode == 0);
    assert(observation.marker_open_result == fd && observation.marker_open_fd == fd);

    struct stat opened;
    assert(fstat(fd, &opened) == 0);
    assert(S_ISREG(opened.st_mode));
    assert((opened.st_mode & 07777) == 0);
    assert(opened.st_ino != 0 && opened.st_size == 0);
    assert(close(fd) == 0);
    assert(guest_coldboot_note_marker_close(&observation, 1, fd, 0) == 1);

    struct stat after;
    assert(stat(marker_path, &after) == 0);
    assert(S_ISREG(after.st_mode) && (after.st_mode & 07777) == 0);
    assert(after.st_ino == opened.st_ino && after.st_size == 0);
    assert(guest_coldboot_note_pid1_stat(&observation, 1,
        GUEST_COLD_BOOT_MARKER_PATH, 0) == 1);
    assert(observation.pid1_stat_succeeded_after_marker);
    assert(observation.marker_stat_pair_observed);
    assert(observation.pid1_stat_checks == 9);

    assert(unlink(marker_path) == 0);
    assert(rmdir(dev_backing) == 0);
    assert(rmdir(vfs_path) == 0);
    assert(rmdir(root) == 0);
}

static void test_graphics_fb0_add_event(void) {
    struct guest_uevent_queue queue;
    guest_uevent_queue_init(&queue);
    static const char request[] = "add\n";
    assert(guest_uevent_enqueue_coldboot_add(&queue, 0,
        GUEST_FB0_SYSFS_ATTRIBUTE_PATH, request, sizeof(request) - 1) == -EPERM);
    assert(guest_uevent_enqueue_coldboot_add(&queue, 1,
        "/sys/devices/virtual/graphics/fb1/uevent", request,
        sizeof(request) - 1) == -ENOENT);
    assert(guest_uevent_enqueue_coldboot_add(&queue, 1,
        GUEST_FB0_SYSFS_ATTRIBUTE_PATH, "remove\n", 7) == -EINVAL);
    assert(guest_uevent_enqueue_coldboot_add(&queue, 1,
        GUEST_FB0_SYSFS_ATTRIBUTE_PATH, request, sizeof(request) - 1) == 4);
    assert(queue.count == 1);
    const struct guest_uevent_event *event = guest_uevent_queue_front(&queue);
    assert(event != NULL);
    static const char expected[] =
        "add@" GUEST_FB0_SYSFS_DEVICE_PATH "\0"
        "ACTION=add\0"
        "DEVPATH=" GUEST_FB0_SYSFS_DEVICE_PATH "\0"
        "SUBSYSTEM=graphics\0"
        "MAJOR=29\0"
        "MINOR=0\0";
    assert(event->length == sizeof(expected) - 1);
    assert(memcmp(event->data, expected, sizeof(expected) - 1) == 0);
    assert(memmem(event->data, event->length, "DEVNAME=", 8) == NULL);
    assert(guest_uevent_queue_consume(&queue) == 0);
    assert(!guest_uevent_queue_readable(&queue));
    assert(queue.enqueued == 1 && queue.delivered == 1 && queue.rejected == 3);
}

int main(void) {
    test_socket_contract();
    test_coldboot_event_drain_marker_and_pid1_stat();
    test_api10_coldboot_sequence_model_and_marker_persistence();
    test_graphics_fb0_add_event();
    puts("API10 guest-only uevent/coldboot sequence-model regression: PASS (one source-ordered guest add event drained before modeled mode-0000 marker creation; file persists with inode/type/mode/size intact; PID1 stat condition observed; test does not execute guest init/ueventd binaries; graphics add carries MAJOR=29/MINOR=0; no host netlink/device nodes)");
    return 0;
}
