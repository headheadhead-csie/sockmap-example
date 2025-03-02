#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
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

static struct bpf_verdict *skel;
static int sock_map_fd;

static void handler(int signum) {
    struct sockmap_key key, next_key = {0, 0};
    if (skel) {
        while (bpf_map_get_next_key(sock_map_fd, &key, &next_key) == 0) {
            if (bpf_map_delete_elem(sock_map_fd, &next_key)) {
                perror("bpf map update fail");
                exit(errno);
            }
            key = next_key;
        }
        bpf_verdict__detach(skel);
        bpf_verdict__destroy(skel);
        skel = NULL;
    }
    exit(0);
}

static void set_sigint_handler() {
    struct sigaction sigact = {
        .sa_handler = handler,
    };

    sigaction(SIGINT, &sigact, NULL);
    return;
}

static void set_bpf_map() {
    struct bpf_map *sock_map;

    if (!(skel = bpf_verdict__open_and_load())) {
        perror("bpf open and load fail");
        exit(errno);
    }
    sock_map = skel->maps.sock_map;
    sock_map_fd = bpf_map__fd(sock_map);
    bpf_prog_attach(bpf_program__fd(skel->progs.bpf_prog_verdict), sock_map_fd, BPF_SK_SKB_VERDICT, 0);
}

static void update_bpf_map(__u32 family, __u16 local_port, __u16 remote_port, __u64 value) {
    struct sockmap_key key;
    key.family = family;
    key.local_port = local_port;
    key.remote_port = remote_port;
    if (bpf_map_update_elem(sock_map_fd, &key, &value, BPF_NOEXIST)) {
        perror("bpf map update fail");
        exit(errno);
    }
}

static void clear_sock(int src_sock, int dst_sock) {
    char buf[4096];
    unsigned int read_cnt, write_cnt;

    while ((read_cnt = read(src_sock, buf, sizeof(buf))) > 0)
        while ((write_cnt = write(dst_sock, buf+write_cnt, read_cnt))
               != read_cnt)
            read_cnt -= write_cnt;

    if (read_cnt < 0) {
        perror("read socket fail");
        exit(errno);
    }

    if (write_cnt < 0) {
        perror("write socket fail");
        exit(errno);
    }
}

