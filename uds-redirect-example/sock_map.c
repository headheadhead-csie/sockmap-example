#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>

#include <stdio.h>
#include <stdlib.h>

#include <bpf/bpf.h>
#include "bpf-verdict.skel.h"

int main(int argc, char *argv[]) {
    int ret;
    __u32 key;
    __u64 value;
    int uds[2], tcp[2];
    int sock_map_fd;
    struct bpf_verdict *skel;
    struct bpf_map *sock_map;
    const char *s = "Hello";
    char buf[64];

    if ((ret = socketpair(AF_UNIX, SOCK_STREAM, 0, uds))) {
        perror("socketpair error");
        exit(errno);
    }

    if ((ret = socketpair(AF_UNIX, SOCK_STREAM, 0, tcp))) {
        perror("socketpair error");
        exit(errno);
    }

    if (!(skel = bpf_verdict__open_and_load())) {
        perror("bpf open and load fail");
        exit(errno);
    }

    sock_map = skel->maps.sock_map;
    sock_map_fd = bpf_map__fd(sock_map);
    bpf_prog_attach(bpf_program__fd(skel->progs.bpf_prog_verdict), sock_map_fd, BPF_SK_SKB_VERDICT, 0);

    key = 0;
    value = uds[0];
    if ((ret = bpf_map_update_elem(sock_map_fd, &key, &value, BPF_NOEXIST))) {
        perror("bpf map update fail");
        exit(errno);
    }
    key = 1;
    value = tcp[1];
    if ((ret = bpf_map_update_elem(sock_map_fd, &key, &value, BPF_NOEXIST))) {
        perror("bpf map update fail");
        exit(errno);
    }

    printf("test ingress redirection\n");
    skel->bss->test_ingress = true;
    write(tcp[0], s, strlen(s)+1);
    printf("finish write\n");
    read(uds[0], buf, strlen(s)+1);
    printf("finish read\n");
    printf("ingress buf: %s\n", buf);
    memset(buf, 0, sizeof(buf));

    printf("test egress redirection\n");
    skel->bss->test_ingress = false;
    write(tcp[0], s, strlen(s)+1);
    printf("finish write\n");
    read(uds[1], buf, strlen(s)+1);
    printf("finish read\n");
    printf("egress buf: %s\n", buf);
    memset(buf, 0, sizeof(buf));

    bpf_verdict__detach(skel);
    bpf_verdict__destroy(skel);

    return 0;
}
