#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <linux/vm_sockets.h>

#include <stdio.h>
#include <stdlib.h>

#include <bpf/bpf.h>
#include "bpf-verdict.skel.h"

int steal_fd(int target_pid, int target_fd) {
    int pidfd, sock_fd;

    if ((pidfd = syscall(SYS_pidfd_open, target_pid, 0)) < 0) {
        perror("pipfd_open fail");
        exit(1);
    }
    if ((sock_fd = syscall(SYS_pidfd_getfd, pidfd, target_fd, 0)) < 0) {
        perror("pipfd_getfd fail");
        exit(1);
    }

    close(pidfd);
    return sock_fd;
}

int main(int argc, char *argv[]) {
    int tcp_pid, tcp_fd, stolen_tcp_fd;
    int vsock_pid, vsock_fd, stolen_vsock_fd;
    __u32 key;
    __u64 value;
    int sock_map_fd;
    struct bpf_verdict *skel;
    struct bpf_map *sock_map;

    if (argc != 5) {
        perror("Usage: sock_map <tcp_pid> <tcp_fd> <vsock_pid> <vsock_fd>\n");
        exit(-1);
    }

    tcp_pid = atoi(argv[1]);
    tcp_fd = atoi(argv[2]);
    stolen_tcp_fd = steal_fd(tcp_pid, tcp_fd);

    tcp_pid = atoi(argv[3]);
    tcp_fd = atoi(argv[4]);
    stolen_tcp_fd = steal_fd(tcp_pid, tcp_fd);

    if (!(skel = bpf_verdict__open_and_load())) {
        perror("bpf open and load fail");
        exit(errno);
    }

    sock_map = skel->maps.sock_map;
    sock_map_fd = bpf_map__fd(sock_map);
    bpf_prog_attach(bpf_program__fd(skel->progs.bpf_prog_verdict), sock_map_fd, BPF_SK_SKB_VERDICT, 0);

    key = 0;
    value = stolen_tcp_fd;
    printf("%d\n", stolen_tcp_fd);
    printf("Add stolen sockfd into the bpf map\n");
    if (bpf_map_update_elem(sock_map_fd, &key, &value, BPF_NOEXIST)) {
        perror("bpf map update fail");
        exit(errno);
    }
    key = 1;
    value = stolen_vsock_fd;
    printf("Add vsock into the bpf map\n");
    if (bpf_map_update_elem(sock_map_fd, &key, &value, BPF_NOEXIST)) {
        perror("bpf map update fail");
        exit(errno);
    }

    bpf_verdict__detach(skel);
    bpf_verdict__destroy(skel);

    return 0;
}
