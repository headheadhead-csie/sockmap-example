#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <linux/vm_sockets.h>

#include <stdio.h>
#include <stdlib.h>

#include <bpf/bpf.h>
#include "bpf-verdict.skel.h"

int build_vsock_server(int *vsock_server) {
    int vsock_client;
    struct sockaddr_vm sockaddr = {
        .svm_cid = VMADDR_CID_HOST,
        .svm_family = AF_VSOCK,
        .svm_port = 8787,
    };

    if ((*vsock_server = socket(AF_VSOCK, SOCK_STREAM, 0)) < 0) {
        perror("socketpair error");
        exit(errno);
    }
    if (bind(*vsock_server, (const struct sockaddr *)&sockaddr, sizeof(sockaddr))) {
        perror("vsock bind error");
        exit(errno);
    }
    if (listen(*vsock_server, 64)) {
        perror("vsock listen error");
        exit(errno);
    }
    if ((vsock_client = accept(*vsock_server, NULL, NULL)) < 0) {
        perror("vsock accept error");
        exit(errno);
    }

    return vsock_client;
}

int get_sock_fd(int target_pid, int target_fd) {
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
    int target_pid, target_fd, sock_fd;
    int ret;
    __u32 key;
    __u64 value;
    int vsock_server, vsock_client;
    int sock_map_fd;
    struct bpf_verdict *skel;
    struct bpf_map *sock_map;
    const char *s = "Hello";
    char buf[64];

    if (argc != 3) {
        perror("Usage: sock_map <target_pid> <target_fd>\n");
        exit(-1);
    }

    target_pid = atoi(argv[1]);
    target_fd = atoi(argv[2]);
    sock_fd = get_sock_fd(target_pid, target_fd);

    vsock_client = build_vsock_server(&vsock_server);

    if (!(skel = bpf_verdict__open_and_load())) {
        perror("bpf open and load fail");
        exit(errno);
    }

    sock_map = skel->maps.sock_map;
    sock_map_fd = bpf_map__fd(sock_map);
    bpf_prog_attach(bpf_program__fd(skel->progs.bpf_prog_verdict), sock_map_fd, BPF_SK_SKB_VERDICT, 0);

    key = 0;
    value = sock_fd;
    printf("%d\n", sock_fd);
    printf("Add stolen sockfd into the bpf map\n");
    if ((ret = bpf_map_update_elem(sock_map_fd, &key, &value, BPF_NOEXIST))) {
        perror("bpf map update fail");
        exit(errno);
    }
    key = 1;
    value = vsock_client;
    printf("Add vsock into the bpf map\n");
    if ((ret = bpf_map_update_elem(sock_map_fd, &key, &value, BPF_NOEXIST))) {
        perror("bpf map update fail");
        exit(errno);
    }

    bpf_verdict__detach(skel);
    bpf_verdict__destroy(skel);

    return 0;
}
