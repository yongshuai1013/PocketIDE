#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc == 2 && strcmp(argv[1], "leaf") == 0) return 0;
    if (argc != 1) return 90;

    pid_t child = fork();
    if (child < 0) return 91;
    if (child == 0) {
        execl(argv[0], argv[0], "leaf", (char *)NULL);
        _exit(92);
    }

    int status = 0;
    pid_t waited;
    do { waited = waitpid(child, &status, 0); } while (waited < 0 && errno == EINTR);
    if (waited != child || !WIFEXITED(status) || WEXITSTATUS(status) != 0) return 93;
    return 0;
}
