#include <sys/syscall.h>
#include <unistd.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char *argv[]) {
    int pid, target_fd;
    int pidfd, sock_fd;

    if (argc != 3) {
        perror("Usage: get_fd <target_pid> <target_fd>\n");
        exit(-1);
    }

    pid = atoi(argv[1]);
    target_fd = atoi(argv[2]);

    printf("pid: %d, target_fd: %d\n", pid, target_fd);

    pidfd = syscall(SYS_pidfd_open, pid, 0);
    sock_fd = syscall(SYS_pidfd_getfd, pidfd, target_fd, 0);

    printf("pidfd: %d, sock_fd: %d\n", pidfd, sock_fd);

    while (1);

    return 0;
}
