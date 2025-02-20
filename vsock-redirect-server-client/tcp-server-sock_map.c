#include "sock_map.h"

int set_tcp_server(struct sockaddr_in *tcp_server_addr, int tcp_server_port) {
    int tcp_server_fd = socket(AF_INET, SOCK_STREAM, 0);

    memset(tcp_server_addr, 0, sizeof(*tcp_server_addr));
    tcp_server_addr->sin_family = AF_INET;
    tcp_server_addr->sin_addr.s_addr = INADDR_ANY;
    tcp_server_addr->sin_port = htons(tcp_server_port);
    if (bind(tcp_server_fd, (const struct sockaddr *)tcp_server_addr, sizeof(*tcp_server_addr))) {
        perror("bind fail");
        exit(errno);
    }
    listen(tcp_server_fd, 32);

    return tcp_server_fd;
}

int main(int argc, char *argv[]) {
    int tcp_server_port, tcp_server_fd;
    int vsk_server_cid, vsk_server_port, vsk_fd;
    struct sockaddr_in tcp_server_addr, tcp_peer_addr;
    unsigned int tcp_peer_addr_len = sizeof(tcp_peer_addr);
    struct sockaddr_vm vsk_server_addr, vsk_local_addr;
    unsigned int vsk_local_addr_len = sizeof(vsk_local_addr);

    if (argc != 4) {
        perror("Usage: sock_map <tcp_server_port> <vsock_server_cid> <vsock_server_port>\n");
        exit(-1);
    }
    tcp_server_port = atoi(argv[1]);
    vsk_server_cid = atoi(argv[2]);
    vsk_server_port = atoi(argv[3]);

    set_sigint_handler();

    tcp_server_fd = set_tcp_server(&tcp_server_addr, tcp_server_port);

    memset(&vsk_server_addr, 0, sizeof(tcp_server_addr));
    vsk_server_addr.svm_family = AF_VSOCK;
    vsk_server_addr.svm_cid = vsk_server_cid;
    vsk_server_addr.svm_port = vsk_server_port;

    set_bpf_map();

    while (true) {
        int new_conn;

        if ((new_conn = accept(tcp_server_fd, (struct sockaddr *)&tcp_peer_addr, &tcp_peer_addr_len)) < 0) {
            perror("accept fail");
            exit(errno);
        }
        printf("tcp local port: %d, remote port: %d\n", tcp_server_port, tcp_peer_addr.sin_port);

        vsk_fd = socket(AF_VSOCK, SOCK_STREAM, 0);
        if (connect(vsk_fd, (const struct sockaddr *)&vsk_server_addr, sizeof(vsk_server_addr)) < 0) {
            perror("connect fail");
            exit(errno);
        }
        if (getsockname(vsk_fd, (struct sockaddr *)&vsk_local_addr, &vsk_local_addr_len)) {
            perror("getsockname fail");
            exit(errno);
        }
        printf("vsock local port: %d, remote port: %d\n", vsk_local_addr.svm_port, vsk_server_port);

        update_bpf_map(AF_INET, tcp_server_port, tcp_peer_addr.sin_port, vsk_fd);
        update_bpf_map(AF_VSOCK, vsk_local_addr.svm_port, vsk_server_port, new_conn);
    }

    bpf_verdict__detach(skel);
    bpf_verdict__destroy(skel);

    return 0;
}
