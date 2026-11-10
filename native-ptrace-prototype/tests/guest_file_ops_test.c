#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "../app/src/main/cpp/guest_file_ops.h"

struct child_fds { int writable; int readonly; int outside; int directory; };

static void write_file(const char *path, const char *text) {
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    assert(fd >= 0);
    size_t length = strlen(text);
    assert(write(fd, text, length) == (ssize_t)length);
    assert(close(fd) == 0);
}

int main(void) {
    char temp_template[] = "/tmp/gingervm-file-ops-XXXXXX";
    char *temp = mkdtemp(temp_template);
    assert(temp != NULL);
    char root[PATH_MAX], dev[PATH_MAX], property_file[PATH_MAX], outside_file[PATH_MAX];
    assert(snprintf(root, sizeof(root), "%s/guest", temp) > 0);
    assert(snprintf(dev, sizeof(dev), "%s/dev", root) > 0);
    assert(snprintf(property_file, sizeof(property_file), "%s/__properties__", dev) > 0);
    assert(snprintf(outside_file, sizeof(outside_file), "%s/outside", temp) > 0);
    assert(mkdir(root, 0700) == 0);
    assert(mkdir(dev, 0700) == 0);
    write_file(property_file, "old");
    write_file(outside_file, "host");

    int ready[2];
    assert(pipe(ready) == 0);
    pid_t child = fork();
    assert(child >= 0);
    if (child == 0) {
        close(ready[0]);
        struct child_fds fds;
        fds.writable = open(property_file, O_RDWR);
        fds.readonly = open(property_file, O_RDONLY);
        fds.outside = open(outside_file, O_RDWR);
        fds.directory = open(dev, O_RDONLY | O_DIRECTORY);
        if (fds.writable < 0 || fds.readonly < 0 || fds.outside < 0 || fds.directory < 0)
            _exit(80);
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) != 0) _exit(81);
        if (write(ready[1], &fds, sizeof(fds)) != (ssize_t)sizeof(fds)) _exit(82);
        close(ready[1]);
        raise(SIGSTOP);
        _exit(0);
    }
    close(ready[1]);
    struct child_fds fds;
    assert(read(ready[0], &fds, sizeof(fds)) == (ssize_t)sizeof(fds));
    close(ready[0]);
    int status = 0;
    assert(waitpid(child, &status, __WALL) == child);
    assert(WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP);

    char relative[PATH_MAX];
    assert(guest_ftruncate_app_private(child, fds.writable, 4096, root,
                                       relative, sizeof(relative)) == 0);
    assert(strcmp(relative, "/dev/__properties__") == 0);
    struct stat st;
    assert(stat(property_file, &st) == 0 && st.st_size == 4096);

    assert(guest_ftruncate_app_private(child, fds.writable, -1, root,
                                       relative, sizeof(relative)) == -EINVAL);
    assert(guest_ftruncate_app_private(child, fds.readonly, 1, root,
                                       relative, sizeof(relative)) == -EBADF);
    assert(guest_ftruncate_app_private(child, fds.outside, 1, root,
                                       relative, sizeof(relative)) == -EPERM);
    assert(guest_ftruncate_app_private(child, fds.directory, 1, root,
                                       relative, sizeof(relative)) == -EINVAL);
    assert(guest_ftruncate_app_private(child, 9999, 1, root,
                                       relative, sizeof(relative)) == -EBADF);
    assert(stat(property_file, &st) == 0 && st.st_size == 4096);
    assert(stat(outside_file, &st) == 0 && st.st_size == 4);

    (void)ptrace(PTRACE_KILL, child, NULL, NULL);
    (void)kill(child, SIGKILL);
    while (waitpid(child, &status, __WALL) < 0 && errno == EINTR) {}
    unlink(property_file);
    unlink(outside_file);
    rmdir(dev);
    rmdir(root);
    rmdir(temp);
    puts("app-private guest ftruncate regression: PASS (regular guest file resized; read-only, outside-root, directory and invalid fds fail closed)");
    return 0;
}
