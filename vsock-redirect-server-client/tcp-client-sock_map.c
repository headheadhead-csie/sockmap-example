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
    bool use_nodelay = false;
    int tcp_server_port, tcp_fd;
    in_addr_t tcp_s_addr;
    int vsk_server_port, vsk_server_fd;
    struct sockaddr_in tcp_server_addr, tcp_local_addr;
    unsigned int tcp_local_addr_len = sizeof(tcp_local_addr);
    struct sockaddr_vm vsk_server_addr, vsk_peer_addr;
    unsigned int vsk_peer_addr_len = sizeof(vsk_peer_addr);

    if (argc != 5) {
        perror("Usage: sock_map <tcp_server_addr> <tcp_server_port> <vsock_server_port> <use_nodelay>\n");
        exit(-1);
    }
    tcp_s_addr = inet_addr(argv[1]);
    tcp_server_port = atoi(argv[2]);
    vsk_server_port = atoi(argv[3]);
    use_nodelay = atoi(argv[4]);

    set_sigint_handler();

    vsk_server_fd = set_vsock_server(&vsk_server_addr, vsk_server_port);

    memset(&tcp_server_addr, 0, sizeof(tcp_server_addr));
    tcp_server_addr.sin_addr.s_addr = tcp_s_addr;
    tcp_server_addr.sin_family = AF_INET;
    tcp_server_addr.sin_port = ntohs(tcp_server_port);

    set_bpf_map();

    while (true) {
        int new_conn, flag = 1;

        if ((new_conn = accept4(vsk_server_fd, (struct sockaddr *)&vsk_peer_addr,
                                &vsk_peer_addr_len, SOCK_NONBLOCK)) < 0) {
            perror("accept fail");
            exit(errno);
        }
        if (setsockopt(new_conn, SOL_SOCKET, SO_ZEROCOPY, &flag, sizeof(flag))) {
            perror("setsockopt fail");
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
        if (fcntl(tcp_fd, F_SETFL, fcntl(tcp_fd, F_GETFL) | O_NONBLOCK) < 0) {
            perror("fcntl fail");
            exit(errno);
        }
        if (use_nodelay) {
            if (setsockopt(tcp_fd, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag))) {
                perror("setsockopt fail");
                exit(errno);
            }
        }
        printf("tcp local port: %hu, remote port: %hu\n", tcp_local_addr.sin_port, tcp_server_port);

        update_bpf_map(AF_VSOCK, vsk_server_port, vsk_peer_addr.svm_port, tcp_fd);
        update_bpf_map(AF_INET, ntohs(tcp_local_addr.sin_port), htons(tcp_server_port), new_conn);
        printf("start clear sock\n");
        clear_sock(tcp_fd, new_conn);
        clear_sock(new_conn, tcp_fd);
        printf("finish clear sock\n");
    }

    bpf_verdict__detach(skel);
    bpf_verdict__destroy(skel);

    return 0;
}
