#include <linux/bpf.h>
#include <stdbool.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define AF_VSOCK 40

struct sockmap_key {
    __u32 family;
    __u16 local_port;
    __u16 remote_port;
};

struct {
    __uint(type, BPF_MAP_TYPE_SOCKHASH);
    __type(key, struct sockmap_key);
    __type(value, __u64);
    __uint(max_entries, 256);
} sock_map SEC(".maps");

SEC("sk_skb")
int bpf_prog_verdict(struct __sk_buff *skb) {
    struct sockmap_key skm_key = {
        .family = skb->family,
        .local_port = skb->local_port,
        .remote_port = skb->remote_port >> 16, /* see net/core/filter.c */
    };
    return bpf_sk_redirect_hash(skb, &sock_map, &skm_key, 0);
}

char _license[] SEC("license") = "GPL";
