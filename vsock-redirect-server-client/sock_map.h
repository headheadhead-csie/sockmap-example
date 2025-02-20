#include <errno.h>
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

static void handler(int signum) {
    if (skel) {
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
static int set_bpf_map() {
    struct bpf_map *sock_map;
    int sock_map_fd;

    if (!(skel = bpf_verdict__open_and_load())) {
        perror("bpf open and load fail");
        exit(errno);
    }
    sock_map = skel->maps.sock_map;
    sock_map_fd = bpf_map__fd(sock_map);
    bpf_prog_attach(bpf_program__fd(skel->progs.bpf_prog_verdict), sock_map_fd, BPF_SK_SKB_VERDICT, 0);

    return sock_map_fd;
}

static void update_bpf_map(int sock_map_fd, __u32 family,
                    __u16 local_port, __u16 remote_port,
                    __u64 value) {
    struct sockmap_key key;
    key.family = AF_INET;
    key.local_port = local_port;
    key.remote_port = remote_port;
    if (bpf_map_update_elem(sock_map_fd, &key, &value, BPF_NOEXIST)) {
        perror("bpf map update fail");
        exit(errno);
    }
}
