#include "sock_map.h"

int set_tcp_server(struct sockaddr_in *tcp_server_addr, int tcp_server_port) {
    int tcp_server_fd = socket(AF_INET, SOCK_STREAM, 0);

    if (tcp_server_fd < 0) {
        perror("socket fail");
        exit(errno);
    }

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
    int epoll_fd;
    struct epoll_event event, events[MAX_EVENTS];
    bool use_nodelay = false, use_zc = false;
    int tcp_server_port, tcp_server_fd, tcp_stub_fd;
    in_addr_t guest_s_addr;
    int vsk_server_cid, vsk_server_port, vsk_fd;
    struct sockaddr_in tcp_server_addr, tcp_peer_addr, guest_server_addr;
    unsigned int tcp_peer_addr_len = sizeof(tcp_peer_addr);
    struct sockaddr_vm vsk_server_addr, vsk_local_addr;
    unsigned int vsk_local_addr_len = sizeof(vsk_local_addr);
    struct sock_key_pair tcp_server_skp;

    if (argc != 7) {
        perror("Usage: sock_map <guest_addr> <tcp_server_port> <vsock_server_cid> <vsock_server_port> <use_nodelay> <use_zc>\n");
        exit(-1);
    }
    guest_s_addr = inet_addr(argv[1]);
    tcp_server_port = atoi(argv[2]);
    vsk_server_cid = atoi(argv[3]);
    vsk_server_port = atoi(argv[4]);
    use_nodelay = atoi(argv[5]);
    use_zc = atoi(argv[6]);

    set_sigint_handler();

    if ((epoll_fd = epoll_create1(0)) < 0) {
        perror("epoll_create fail");
        exit(errno);
    }

    tcp_server_fd = set_tcp_server(&tcp_server_addr, tcp_server_port);
    tcp_server_skp.sock_fd = tcp_server_fd;
    event.events = EPOLLIN;
    event.data.ptr = &tcp_server_skp;
    add_event(epoll_fd, tcp_server_fd, &event);

    memset(&vsk_server_addr, 0, sizeof(tcp_server_addr));
    vsk_server_addr.svm_family = AF_VSOCK;
    vsk_server_addr.svm_cid = vsk_server_cid;
    vsk_server_addr.svm_port = vsk_server_port;

    memset(&guest_server_addr, 0, sizeof(guest_server_addr));
    guest_server_addr.sin_family = AF_INET;
    guest_server_addr.sin_port = htons(vsk_server_port);
    guest_server_addr.sin_addr.s_addr = guest_s_addr;

    set_bpf_map();

    while (true) {
        struct sock_key_pair *skp, *tcp_skp, *vsk_skp;
        int new_conn, flag, event_cnt;

        event_cnt = epoll_wait(epoll_fd, events, MAX_EVENTS, -1);
        for (int i = 0; i < event_cnt; i++) {
            skp = events[i].data.ptr;

            if (skp->sock_fd == tcp_server_fd) {
                if ((new_conn = accept4(tcp_server_fd, (struct sockaddr *)&tcp_peer_addr,
                                        &tcp_peer_addr_len, SOCK_NONBLOCK)) < 0) {
                    perror("accept fail");
                    exit(errno);
                }
                flag = use_nodelay;
                if (setsockopt(new_conn, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag))) {
                    perror("setsockopt fail");
                    exit(errno);
                }
                DPRINTF("tcp local port: %hu, remote port: %hu\n", tcp_server_port, tcp_peer_addr.sin_port);

                tcp_stub_fd = socket(AF_INET, SOCK_STREAM, 0);
                if (connect(tcp_stub_fd, (const struct sockaddr *)&guest_server_addr, sizeof(guest_server_addr)) < 0) {
                    perror("connect guest fail");
                    exit(errno);
                }

                vsk_fd = socket(AF_VSOCK, SOCK_STREAM, 0);
                if (connect(vsk_fd, (const struct sockaddr *)&vsk_server_addr, sizeof(vsk_server_addr)) < 0) {
                    perror("connect fail");
                    exit(errno);
                }
                if (getsockname(vsk_fd, (struct sockaddr *)&vsk_local_addr, &vsk_local_addr_len)) {
                    perror("getsockname fail");
                    exit(errno);
                }
                if (fcntl(vsk_fd, F_SETFL, fcntl(vsk_fd, F_GETFL) | O_NONBLOCK) < 0) {
                    perror("fcntl fail");
                    exit(errno);
                }
                flag = use_zc;
                if (setsockopt(vsk_fd, SOL_SOCKET, SO_ZEROCOPY, &flag, sizeof(flag))) {
                    perror("setsockopt fail");
                    exit(errno);
                }
                DPRINTF("vsock local port: %hu, remote port: %hu\n", vsk_local_addr.svm_port, vsk_server_port);

                event.events = EPOLLHUP | EPOLLRDHUP;
                tcp_skp = malloc(sizeof(*tcp_skp));
                vsk_skp = malloc(sizeof(*vsk_skp));

                event.data.ptr = tcp_skp;
                tcp_skp->sock_fd = new_conn;
                tcp_skp->stub_fd = -1;
                add_event(epoll_fd, new_conn, &event);
                tcp_skp->pair = vsk_skp;

                event.data.ptr = vsk_skp;
                vsk_skp->sock_fd = vsk_fd;
                vsk_skp->stub_fd = tcp_stub_fd;
                add_event(epoll_fd, vsk_fd, &event);
                vsk_skp->pair = tcp_skp;

                set_key(&vsk_skp->key, AF_INET, tcp_server_port, tcp_peer_addr.sin_port);
                update_bpf_map(&vsk_skp->key, vsk_fd);
                set_key(&tcp_skp->key, AF_VSOCK, vsk_local_addr.svm_port, vsk_server_port);
                update_bpf_map(&tcp_skp->key, new_conn);

                DPRINTF("start clear sock\n");
                clear_sock(new_conn, vsk_fd);
                clear_sock(vsk_fd, new_conn);
                DPRINTF("finish clear sock\n");
            } else {
                struct sock_key_pair *pair = skp->pair;
                DPRINTF("cleaning socket %d\n", skp->sock_fd);

                if (!(event.events & (EPOLLHUP | EPOLLRDHUP)))
                    continue;
                if (pair->pair) {
                    shutdown(skp->sock_fd, SHUT_RDWR);
                    shutdown(pair->sock_fd, SHUT_RDWR);
                    skp->pair = NULL;
                    del_event(epoll_fd, skp->sock_fd);
                } else {
                    close(skp->sock_fd);
                    close(pair->sock_fd);
                    if (skp->stub_fd >= 0)
                        close(skp->stub_fd);
                    if (pair->stub_fd >= 0)
                        close(pair->stub_fd);
                    free(pair);
                    free(skp);
                }

                skp = NULL;
                DPRINTF("socket are closed\n");
            }
        }
    }

    bpf_verdict__detach(skel);
    bpf_verdict__destroy(skel);

    return 0;
}
