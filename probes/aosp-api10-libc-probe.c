#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>

static int check_signal_registration(void) {
    struct sigaction action;
    struct sigaction previous;

    memset(&action, 0, sizeof(action));
    memset(&previous, 0, sizeof(previous));
    action.sa_handler = SIG_IGN;
    action.sa_flags = SA_RESTART;

    if (sigaction(SIGUSR1, &action, &previous) != 0) {
        return 13;
    }
    if (previous.sa_handler != SIG_DFL || previous.sa_flags != 0 ||
        previous.sa_mask != 0) {
        return 14;
    }
    if (sigaction(SIGUSR1, NULL, &previous) != 0 ||
        previous.sa_handler != SIG_IGN ||
        (previous.sa_flags & SA_RESTART) == 0) {
        return 15;
    }
    if (sigaction(SIGKILL, &action, NULL) == 0) {
        return 16;
    }
    if (sigaction(SIGUSR2, &action, &action) != 0 || action.sa_handler != SIG_DFL) {
        return 17;
    }
    if (sigaction(SIGUSR2, NULL, &previous) != 0 ||
        previous.sa_handler != SIG_IGN) {
        return 18;
    }
    errno = 0;
    if (sigaction(SIGUSR1, (const struct sigaction *)1, NULL) != -1 || errno != EFAULT) {
        return 27;
    }
    errno = 0;
    if (sigaction(SIGUSR1, NULL, (struct sigaction *)1) != -1 || errno != EFAULT) {
        return 28;
    }
    if (sigaction(SIGUSR1, NULL, &previous) != 0 ||
        previous.sa_handler != SIG_IGN) {
        return 29;
    }
    return 0;
}

static int check_virtual_devices(void) {
    unsigned char bytes[16];
    const char *random_paths[] = {"/dev/random", "/dev/urandom"};
    unsigned int index;
    int fd;
    ssize_t count;

    fd = open("/dev/null", O_RDWR);
    if (fd < 0) {
        return 20;
    }
    if (read(fd, bytes, 1) != 0 || write(fd, "discard", 7) != 7 || close(fd) != 0) {
        return 21;
    }

    fd = open("/dev/zero", O_RDONLY);
    if (fd < 0) {
        return 22;
    }
    count = read(fd, bytes, sizeof(bytes));
    if (count != (ssize_t)sizeof(bytes) || close(fd) != 0) {
        return 23;
    }
    for (index = 0; index < sizeof(bytes); ++index) {
        if (bytes[index] != 0) {
            return 24;
        }
    }

    for (index = 0; index < sizeof(random_paths) / sizeof(random_paths[0]); ++index) {
        fd = open(random_paths[index], O_RDONLY);
        if (fd < 0) {
            return 25;
        }
        if (read(fd, bytes, sizeof(bytes)) != (ssize_t)sizeof(bytes) || close(fd) != 0) {
            return 26;
        }
    }
    return 0;
}

int main(int argc, char **argv) {
    static const char message[] = "AOSP Android 2.3.7 Bionic libc app reached main\n";
    static const char marker[] = "/tmp/gingervm-aosp-libc.txt";
    int fd;
    ssize_t written;
    int result;

    (void)argc;
    (void)argv;
    if (getpid() <= 0) {
        return 10;
    }
    result = check_signal_registration();
    if (result != 0) {
        return result;
    }
    result = check_virtual_devices();
    if (result != 0) {
        return result;
    }
    fd = open(marker, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        return 11;
    }
    written = write(fd, message, sizeof(message) - 1);
    if (close(fd) != 0 || written != (ssize_t)(sizeof(message) - 1)) {
        return 12;
    }
    return 0;
}
