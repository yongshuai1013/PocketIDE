#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "../app/src/main/cpp/guest_goldfish_tty_fs.h"
#include "../app/src/main/cpp/guest_uevent_virtual.h"

static void make_dir(const char *path) {
    assert(mkdir(path, 0700) == 0 || errno == EEXIST);
}

static void format_path(char *out, size_t capacity, const char *root,
                        const char *suffix) {
    int n = snprintf(out, capacity, "%s%s", root, suffix);
    assert(n > 0 && (size_t)n < capacity);
}

static void create_tty_directories(const char *root, uint32_t minor) {
    char path[PATH_MAX];
    make_dir(root);
    format_path(path, sizeof(path), root, "/dev"); make_dir(path);
    format_path(path, sizeof(path), root, "/sys"); make_dir(path);
    format_path(path, sizeof(path), root, "/sys/devices"); make_dir(path);
    format_path(path, sizeof(path), root, "/sys/devices/virtual"); make_dir(path);
    format_path(path, sizeof(path), root, "/sys/devices/virtual/tty"); make_dir(path);
    int n = snprintf(path, sizeof(path), "%s/sys/devices/virtual/tty/ttyS%u",
                     root, minor);
    assert(n > 0 && (size_t)n < sizeof(path));
    make_dir(path);
}

static void enqueue_and_deliver_tty_add(struct guest_uevent_queue *queue,
                                        struct guest_goldfish_tty_runtime *runtime,
                                        uint32_t minor) {
    char attribute[128];
    int n = snprintf(attribute, sizeof(attribute), "%s%u/uevent",
                     GUEST_GOLDFISH_TTY_SYSFS_ATTRIBUTE_PREFIX, minor);
    assert(n > 0 && (size_t)n < sizeof(attribute));
    assert(guest_uevent_enqueue_coldboot_add(queue, 1, attribute,
                                             "add\n", 4u) == 4);
    const struct guest_uevent_event *event = guest_uevent_queue_front(queue);
    assert(event != NULL);
    uint32_t parsed_minor = UINT32_MAX;
    assert(guest_goldfish_tty_event_matches(event->data, event->length,
                                             &parsed_minor));
    assert(parsed_minor == minor);
    assert(guest_goldfish_tty_note_event(runtime, event->data, event->length,
                                         &parsed_minor) == 1);
    assert(parsed_minor == minor);
    assert(guest_uevent_queue_consume(queue) == 0);
}

static void test_event_mknod_open_termios_epoll_lifecycle(const char *base) {
    char root[PATH_MAX], outside[PATH_MAX], backing[PATH_MAX];
    format_path(root, sizeof(root), base, "/guest");
    format_path(outside, sizeof(outside), base, "/outside");
    create_tty_directories(root, 1);
    make_dir(outside);

    struct guest_goldfish_tty_runtime runtime;
    struct guest_goldfish_tty_epoll_table epolls;
    struct guest_uevent_queue queue;
    struct guest_vsocket_table sockets;
    guest_goldfish_tty_runtime_init(&runtime);
    guest_goldfish_tty_epoll_table_init(&epolls);
    guest_uevent_queue_init(&queue);
    guest_vsocket_table_init(&sockets);

    uint32_t device = guest_goldfish_tty_makedev(
        GUEST_GOLDFISH_TTY_SYNTHETIC_MAJOR, GUEST_GOLDFISH_TTY_QEMUD_MINOR);
    uint32_t minor = UINT32_MAX;
    assert(guest_goldfish_tty_mknod_validate(&runtime, 1,
        "/dev/ttyS1", GUEST_GOLDFISH_TTY_MODE, device, &minor) == -ENOENT);
    assert(guest_uevent_enqueue_coldboot_add(&queue, 0,
        "/sys/devices/virtual/tty/ttyS1/uevent", "add\n", 4u) == -EPERM);
    assert(queue.rejected == 1u && queue.count == 0u);
    enqueue_and_deliver_tty_add(&queue, &runtime, 1);
    assert(runtime.events_received == 1u && runtime.uevent_mask == 0x02u);
    assert(queue.enqueued == 1u && queue.delivered == 1u && queue.count == 0u);

    assert(guest_goldfish_tty_mknod_validate(&runtime, 0,
        "/dev/ttyS1", GUEST_GOLDFISH_TTY_MODE, device, &minor) == -EPERM);
    assert(guest_goldfish_tty_mknod_validate(&runtime, 1,
        "/dev/ttyS1", GUEST_GOLDFISH_TTY_MODE, device + 1u, &minor) == -EINVAL);
    assert(guest_goldfish_tty_mknod_validate(&runtime, 1,
        "/dev/ttyS1", 0020666u, device, &minor) == -EINVAL);
    assert(guest_goldfish_tty_mknod_validate(&runtime, 1,
        "/dev/ttyS8", GUEST_GOLDFISH_TTY_MODE, device, &minor) == -EOPNOTSUPP);
    assert(guest_goldfish_tty_mknod_validate(&runtime, 1,
        "/dev/../outside/ttyS1", GUEST_GOLDFISH_TTY_MODE, device,
        &minor) == -EOPNOTSUPP);

    format_path(backing, sizeof(backing), root, "/dev/ttyS1");
    assert(guest_goldfish_tty_create_app_private_placeholder(root,
        "/dev/ttyS1", backing, &runtime, 1, GUEST_GOLDFISH_TTY_MODE,
        device, &minor) == 0);
    assert(minor == 1u && runtime.nodes_created == 1u && runtime.node_mask == 0x02u);
    struct stat node_stat;
    assert(lstat(backing, &node_stat) == 0);
    assert(S_ISREG(node_stat.st_mode) && !S_ISLNK(node_stat.st_mode));
    assert((node_stat.st_mode & 0777u) == 0600u && node_stat.st_size == 0);
    assert(guest_goldfish_tty_mknod_validate(&runtime, 1,
        "/dev/ttyS1", GUEST_GOLDFISH_TTY_MODE, device, &minor) == 0);
    assert(guest_goldfish_tty_create_app_private_placeholder(root,
        "/dev/ttyS1", backing, &runtime, 1, GUEST_GOLDFISH_TTY_MODE,
        device, &minor) == -EEXIST);
    assert(guest_goldfish_tty_create_app_private_placeholder(root,
        "/dev/ttyS1", outside, &runtime, 1, GUEST_GOLDFISH_TTY_MODE,
        device, &minor) == -EACCES);

    uint32_t qemud_flags = 2u | GUEST_GOLDFISH_TTY_O_LARGEFILE;
    assert(guest_goldfish_tty_open_validate(&runtime, 0, "/dev/ttyS1",
        qemud_flags, &minor) == -EPERM);
    assert(guest_goldfish_tty_open_validate(&runtime, 1, "/dev/ttyS0",
        qemud_flags, &minor) == -EOPNOTSUPP);
    assert(guest_goldfish_tty_open_validate(&runtime, 1, "/dev/ttyS1",
        2u, &minor) == -EACCES);
    assert(guest_goldfish_tty_open_validate(&runtime, 1, "/dev/ttyS1",
        qemud_flags, &minor) == 0 && minor == 1u);

    int tty_fd = guest_vsocket_alloc_fd(&sockets, VIRTUAL_FD_DEV_TTY);
    assert(tty_fd >= 0);
    struct guest_vsocket_fd *tty_entry = guest_vsocket_fd_get(&sockets, tty_fd);
    assert(tty_entry != NULL);
    tty_entry->device_mode = GUEST_GOLDFISH_TTY_MODE;
    tty_entry->device_major = GUEST_GOLDFISH_TTY_SYNTHETIC_MAJOR;
    tty_entry->device_minor = 1u;
    tty_entry->open_flags = qemud_flags;
    assert(guest_goldfish_tty_note_open(&runtime, 1u, tty_fd) == 0);
    assert(guest_goldfish_tty_open_validate(&runtime, 1, "/dev/ttyS1",
        qemud_flags, &minor) == -EBUSY);

    struct guest_arm32_termios got, set;
    memset(&got, 0, sizeof(got));
    assert(guest_goldfish_tty_ioctl(&runtime, 0, tty_fd,
        GUEST_GOLDFISH_TTY_TCGETS, &got, sizeof(got)) == -EPERM);
    assert(guest_goldfish_tty_ioctl(&runtime, 1, tty_fd + 1,
        GUEST_GOLDFISH_TTY_TCGETS, &got, sizeof(got)) == -EBADF);
    assert(guest_goldfish_tty_ioctl(&runtime, 1, tty_fd,
        GUEST_GOLDFISH_TTY_TCGETS, &got, sizeof(got)) == 0);
    assert(got.c_iflag == (0000400u | 0002000u));
    assert(got.c_oflag == (0000001u | 0000004u));
    assert(got.c_cflag == (0000017u | 0000060u | 0000200u | 0002000u));
    assert(got.c_line == 0u && got.c_cc[0] == 0x03u && got.c_cc[2] == 0x7fu);
    set = got;
    set.c_iflag ^= 0000200u;
    set.c_cc[5] = 0x1bu;
    assert(guest_goldfish_tty_ioctl(&runtime, 1, tty_fd,
        GUEST_GOLDFISH_TTY_TCSETS, &set, sizeof(set)) == 0);
    memset(&got, 0, sizeof(got));
    assert(guest_goldfish_tty_ioctl(&runtime, 1, tty_fd,
        GUEST_GOLDFISH_TTY_TCGETS, &got, sizeof(got)) == 0);
    assert(memcmp(&got, &set, sizeof(got)) == 0);
    assert(guest_goldfish_tty_ioctl(&runtime, 1, tty_fd, 0xdeadbeefu,
        &got, sizeof(got)) == -ENOTTY);
    assert(guest_goldfish_tty_ioctl(&runtime, 1, tty_fd,
        GUEST_GOLDFISH_TTY_TCGETS, &got, sizeof(got) - 1u) == -EFAULT);
    assert(runtime.ioctl_gets == 2u && runtime.ioctl_sets == 1u);

    assert(guest_goldfish_tty_read_result(&runtime, tty_fd, 0) ==
           GUEST_GOLDFISH_TTY_READ_PARK);
    assert(guest_goldfish_tty_read_result(&runtime, tty_fd, 1) == -EAGAIN);
    assert(guest_goldfish_tty_write_result(&runtime, tty_fd, 9u) == -EOPNOTSUPP);
    assert(guest_goldfish_tty_write_result(&runtime, tty_fd, 0u) == 0);
    assert(runtime.empty_reads == 2u && runtime.writes_without_peer == 1u);

    int listener_fd = guest_vsocket_alloc_fd(&sockets, VIRTUAL_FD_QEMUD_LISTENER);
    assert(listener_fd >= 0);
    sockets.qemud_listener_fd = listener_fd;
    struct guest_vsocket_fd *listener = guest_vsocket_fd_get(&sockets, listener_fd);
    assert(listener != NULL);
    listener->bound = 1;
    listener->listening = 1;
    int unrelated_fd = guest_vsocket_alloc_fd(&sockets, VIRTUAL_FD_GENERIC);
    assert(unrelated_fd >= 0);

    assert(guest_goldfish_tty_epoll_create(&epolls, &sockets, 0, 7u) == -EINVAL);
    assert(guest_goldfish_tty_epoll_create(&epolls, &sockets, 4, 0u) == -EINVAL);
    int epfd = guest_goldfish_tty_epoll_create(&epolls, &sockets, 4, 7u);
    assert(epfd >= 0);
    assert(guest_vsocket_fd_get(&sockets, epfd)->kind == VIRTUAL_FD_EPOLL);
    uint32_t watch_events = GUEST_GOLDFISH_TTY_EPOLLIN |
                            GUEST_GOLDFISH_TTY_EPOLLET;
    uint64_t watch_data = UINT64_C(0x1122334455667788);
    assert(guest_goldfish_tty_epoll_ctl(&epolls, &sockets, 0, 7u,
        epfd, GUEST_GOLDFISH_TTY_EPOLL_CTL_ADD, tty_fd,
        watch_events, watch_data, tty_fd, listener_fd) == -EPERM);
    assert(guest_goldfish_tty_epoll_ctl(&epolls, &sockets, 1, 8u,
        epfd, GUEST_GOLDFISH_TTY_EPOLL_CTL_ADD, tty_fd,
        watch_events, watch_data, tty_fd, listener_fd) == -EBADF);
    assert(guest_goldfish_tty_epoll_ctl(&epolls, &sockets, 1, 7u,
        epfd, GUEST_GOLDFISH_TTY_EPOLL_CTL_ADD, tty_fd,
        watch_events, watch_data, tty_fd, listener_fd) == 0);
    assert(guest_goldfish_tty_epoll_ctl(&epolls, &sockets, 1, 7u,
        epfd, GUEST_GOLDFISH_TTY_EPOLL_CTL_ADD, unrelated_fd,
        GUEST_GOLDFISH_TTY_EPOLLIN, 0x1234u, tty_fd, listener_fd) == -EPERM);
    struct guest_goldfish_tty_epoll_instance *instance =
        guest_goldfish_tty_epoll_find(&epolls, epfd);
    assert(instance != NULL);
    int found_watch = 0;
    for (size_t i = 0; i < GUEST_GOLDFISH_TTY_EPOLL_MAX_WATCHES; ++i) {
        if (instance->watches[i].registered && instance->watches[i].fd == tty_fd) {
            found_watch = 1;
            assert(instance->watches[i].events == watch_events);
            assert(instance->watches[i].data == watch_data);
        }
    }
    assert(found_watch);
    assert(guest_goldfish_tty_epoll_ctl(&epolls, &sockets, 1, 7u,
        epfd, GUEST_GOLDFISH_TTY_EPOLL_CTL_ADD, tty_fd,
        watch_events, watch_data, tty_fd, listener_fd) == -EEXIST);
    assert(guest_goldfish_tty_epoll_ctl(&epolls, &sockets, 1, 7u,
        epfd, GUEST_GOLDFISH_TTY_EPOLL_CTL_ADD, listener_fd,
        GUEST_GOLDFISH_TTY_EPOLLIN, 0xfeedu, tty_fd, listener_fd) == 0);
    assert(guest_goldfish_tty_epoll_watch_count(&epolls, epfd) == 2u);
    assert(guest_goldfish_tty_epoll_ctl(&epolls, &sockets, 1, 7u,
        epfd, GUEST_GOLDFISH_TTY_EPOLL_CTL_MOD, tty_fd,
        GUEST_GOLDFISH_TTY_EPOLLIN, 0x99u, tty_fd, listener_fd) == 0);
    assert(guest_goldfish_tty_epoll_ctl(&epolls, &sockets, 1, 7u,
        epfd, GUEST_GOLDFISH_TTY_EPOLL_CTL_DEL, listener_fd,
        0, 0, tty_fd, listener_fd) == 0);
    assert(guest_goldfish_tty_epoll_watch_count(&epolls, epfd) == 1u);
    assert(guest_goldfish_tty_epoll_wait_result(&epolls, 7u, epfd, 4, -1) ==
           GUEST_GOLDFISH_TTY_EPOLL_WAIT_PARK);
    assert(guest_goldfish_tty_epoll_wait_result(&epolls, 7u, epfd, 4, 0) == 0);
    assert(guest_goldfish_tty_epoll_wait_result(&epolls, 7u, epfd, 4, 25) ==
           -EOPNOTSUPP);
    assert(guest_goldfish_tty_epoll_wait_result(&epolls, 7u, epfd, 0, 0) ==
           -EINVAL);
    assert(guest_goldfish_tty_epoll_wait_result(&epolls, 8u, epfd, 4, -1) ==
           -EBADF);

    guest_goldfish_tty_epoll_remove_watched_fd(&epolls, tty_fd);
    assert(guest_goldfish_tty_epoll_watch_count(&epolls, epfd) == 0u);
    assert(guest_goldfish_tty_epoll_close(&epolls, epfd) == 0);
    assert(guest_goldfish_tty_epoll_find(&epolls, epfd) == NULL);
    assert(guest_goldfish_tty_note_close(&runtime, tty_fd) == 0);
    assert(runtime.tty_fd == -1);
    assert(guest_goldfish_tty_note_close(&runtime, tty_fd) == -EBADF);
}

static void test_symlinked_node_and_outside_containment(const char *base) {
    char root[PATH_MAX], outside[PATH_MAX], guest_node[PATH_MAX], backing[PATH_MAX];
    format_path(root, sizeof(root), base, "/attack-root");
    format_path(outside, sizeof(outside), base, "/outside/ttyS2");
    create_tty_directories(root, 2);
    char outside_dir[PATH_MAX];
    format_path(outside_dir, sizeof(outside_dir), base, "/outside");
    make_dir(outside_dir);
    int fd = open(outside, O_CREAT | O_WRONLY | O_EXCL | O_CLOEXEC, 0600);
    assert(fd >= 0);
    assert(write(fd, "keep", 4u) == 4);
    assert(close(fd) == 0);
    format_path(guest_node, sizeof(guest_node), root, "/dev/ttyS2");
    assert(symlink(outside, guest_node) == 0);
    format_path(backing, sizeof(backing), root, "/dev/ttyS2");

    struct guest_goldfish_tty_runtime runtime;
    guest_goldfish_tty_runtime_init(&runtime);
    struct guest_uevent_queue queue;
    guest_uevent_queue_init(&queue);
    enqueue_and_deliver_tty_add(&queue, &runtime, 2u);
    uint32_t device = guest_goldfish_tty_makedev(
        GUEST_GOLDFISH_TTY_SYNTHETIC_MAJOR, 2u);
    uint32_t minor = UINT32_MAX;
    assert(guest_goldfish_tty_create_app_private_placeholder(root,
        "/dev/ttyS2", backing, &runtime, 1, GUEST_GOLDFISH_TTY_MODE,
        device, &minor) == -ELOOP);
    assert(lstat(guest_node, &(struct stat){0}) == 0);
    struct stat st;
    assert(stat(outside, &st) == 0 && S_ISREG(st.st_mode) && st.st_size == 4);

    char outside_backing[PATH_MAX];
    format_path(outside_backing, sizeof(outside_backing), base,
                "/outside/ttyS2");
    assert(guest_goldfish_tty_create_app_private_placeholder(root,
        "/dev/ttyS2", outside_backing, &runtime, 1, GUEST_GOLDFISH_TTY_MODE,
        device, &minor) == -EACCES);
    assert(stat(outside, &st) == 0 && st.st_size == 4);
}

int main(int argc, char **argv) {
    assert(argc == 2 && argv[1][0] == '/');
    const char *base = argv[1];
    make_dir(base);
    test_event_mknod_open_termios_epoll_lifecycle(base);
    test_symlinked_node_and_outside_containment(base);
    puts("Goldfish ttyS1 uevent/mknod/open/termios/epoll regression: PASS (synthetic 240:1 explicitly guest-only; no host tty, epoll or device node used; no peer bytes/replies fabricated)");
    return 0;
}
