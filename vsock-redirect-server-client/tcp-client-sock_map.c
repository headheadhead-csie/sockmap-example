#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/syscall.h>
#include <linux/vm_sockets.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <stdio.h>
#include <stdlib.h>

#include <bpf/bpf.h>
#include "bpf-verdict.skel.h"

struct sockmap_key {
    __u32 family;
    __u16 local_port;
    __u16 remote_port;
};

int main(int argc, char *argv[]) {
    int tcp_server_port, tcp_fd;
    in_addr_t tcp_s_addr;
    int vsk_server_cid, vsk_server_port, vsk_server_fd;
    __u64 value;
    int sock_map_fd;
    struct bpf_verdict *skel;
    struct bpf_map *sock_map;
    struct sockaddr_in tcp_server_addr, tcp_local_addr;
    unsigned int tcp_local_addr_len = sizeof(tcp_local_addr);
    struct sockaddr_vm vsk_server_addr, vsk_peer_addr;
    unsigned int vsk_peer_addr_len = sizeof(vsk_peer_addr);
    struct sockmap_key key;

    if (argc != 4) {
        perror("Usage: sock_map <tcp_server_addr> <tcp_server_port> <vsock_server_port>\n");
        exit(-1);
    }
    tcp_s_addr = inet_addr(argv[1]);
    tcp_server_port = atoi(argv[2]);
    vsk_server_port = atoi(argv[3]);

    vsk_server_fd = socket(AF_VSOCK, SOCK_STREAM, 0);
    memset(&vsk_server_addr, 0, sizeof(vsk_server_addr));
    vsk_server_addr.svm_family = AF_VSOCK;
    vsk_server_addr.svm_cid = VMADDR_CID_ANY;
    vsk_server_addr.svm_port = vsk_server_port;
    if (bind(vsk_server_fd, (const struct sockaddr *)&vsk_server_addr, sizeof(vsk_server_addr))) {
        perror("bind fail");
        exit(errno);
    }
    listen(vsk_server_fd, 32);

    memset(&tcp_server_addr, 0, sizeof(tcp_server_addr));
    tcp_server_addr.sin_addr.s_addr = tcp_s_addr;
    tcp_server_addr.sin_family = AF_INET;
    tcp_server_addr.sin_port = ntohs(tcp_server_port);

    if (!(skel = bpf_verdict__open_and_load())) {
        perror("bpf open and load fail");
        exit(errno);
    }
    sock_map = skel->maps.sock_map;
    sock_map_fd = bpf_map__fd(sock_map);
    bpf_prog_attach(bpf_program__fd(skel->progs.bpf_prog_verdict), sock_map_fd, BPF_SK_SKB_VERDICT, 0);

    while (true) {
        int new_conn;

        if ((new_conn = accept(vsk_server_fd, (struct sockaddr *)&vsk_peer_addr, &vsk_peer_addr_len)) < 0) {
            perror("accept fail");
            exit(errno);
        }
        printf("vsock local port: %d, remote port: %d\n", vsk_server_port, vsk_peer_addr.svm_port);

        tcp_fd = socket(AF_INET, SOCK_STREAM, 0);
        if (connect(tcp_fd, (const struct sockaddr *)&tcp_server_addr, sizeof(tcp_server_addr)) < 0) {
            perror("connect fail");
            exit(errno);
        }
        if (getsockname(tcp_fd, (struct sockaddr *)&tcp_local_addr, &tcp_local_addr_len)) {
            perror("getsockname fail");
            exit(errno);
        }
        printf("tcp local port: %d, remote port: %d\n", tcp_local_addr.sin_port, tcp_server_port);

        key.family = AF_VSOCK;
        key.local_port = vsk_server_port;
        key.remote_port = vsk_peer_addr.svm_port;
        value = tcp_fd;
        if (bpf_map_update_elem(sock_map_fd, &key, &value, BPF_NOEXIST)) {
            perror("bpf map update fail");
            exit(errno);
        }

        key.family = AF_INET;
        key.local_port = tcp_local_addr.sin_port;
        key.remote_port = tcp_server_port;
        value = new_conn;
        if (bpf_map_update_elem(sock_map_fd, &key, &value, BPF_NOEXIST)) {
            perror("bpf map update fail");
            exit(errno);
        }
    }

    bpf_verdict__detach(skel);
    bpf_verdict__destroy(skel);

    return 0;
}
