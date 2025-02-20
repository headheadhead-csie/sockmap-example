#include "sock_map.h"

int set_vsock_server(struct sockaddr_vm *vsk_server_addr, int vsk_server_port) {
    int vsk_server_fd = socket(AF_VSOCK, SOCK_STREAM, 0);

    memset(vsk_server_addr, 0, sizeof(*vsk_server_addr));
    vsk_server_addr->svm_family = AF_VSOCK;
    vsk_server_addr->svm_cid = VMADDR_CID_ANY;
    vsk_server_addr->svm_port = vsk_server_port;
    if (bind(vsk_server_fd, (const struct sockaddr *)vsk_server_addr, sizeof(*vsk_server_addr))) {
        perror("bind fail");
        exit(errno);
    }
    listen(vsk_server_fd, 32);

    return vsk_server_fd;
}

int main(int argc, char *argv[]) {
    int tcp_server_port, tcp_fd;
    in_addr_t tcp_s_addr;
    int vsk_server_port, vsk_server_fd;
    struct sockaddr_in tcp_server_addr, tcp_local_addr;
    unsigned int tcp_local_addr_len = sizeof(tcp_local_addr);
    struct sockaddr_vm vsk_server_addr, vsk_peer_addr;
    unsigned int vsk_peer_addr_len = sizeof(vsk_peer_addr);

    if (argc != 4) {
        perror("Usage: sock_map <tcp_server_addr> <tcp_server_port> <vsock_server_port>\n");
        exit(-1);
    }
    tcp_s_addr = inet_addr(argv[1]);
    tcp_server_port = atoi(argv[2]);
    vsk_server_port = atoi(argv[3]);

    set_sigint_handler();

    vsk_server_fd = set_vsock_server(&vsk_server_addr, vsk_server_port);

    memset(&tcp_server_addr, 0, sizeof(tcp_server_addr));
    tcp_server_addr.sin_addr.s_addr = tcp_s_addr;
    tcp_server_addr.sin_family = AF_INET;
    tcp_server_addr.sin_port = ntohs(tcp_server_port);

    set_bpf_map();

    while (true) {
        int new_conn;

        if ((new_conn = accept(vsk_server_fd, (struct sockaddr *)&vsk_peer_addr, &vsk_peer_addr_len)) < 0) {
            perror("accept fail");
            exit(errno);
        }
        printf("vsock local port: %hu, remote port: %hu\n", vsk_server_port, vsk_peer_addr.svm_port);

        tcp_fd = socket(AF_INET, SOCK_STREAM, 0);
        if (connect(tcp_fd, (const struct sockaddr *)&tcp_server_addr, sizeof(tcp_server_addr)) < 0) {
            perror("connect fail");
            exit(errno);
        }
        if (getsockname(tcp_fd, (struct sockaddr *)&tcp_local_addr, &tcp_local_addr_len)) {
            perror("getsockname fail");
            exit(errno);
        }
        printf("tcp local port: %hu, remote port: %hu\n", tcp_local_addr.sin_port, tcp_server_port);

        update_bpf_map(AF_VSOCK, vsk_server_port, vsk_peer_addr.svm_port, tcp_fd);
        update_bpf_map(AF_INET, ntohs(tcp_local_addr.sin_port), htons(tcp_server_port), new_conn);
    }

    bpf_verdict__detach(skel);
    bpf_verdict__destroy(skel);

    return 0;
}
