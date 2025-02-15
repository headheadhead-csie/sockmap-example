#include <linux/bpf.h>
#include <stdbool.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct {
    __uint(type, BPF_MAP_TYPE_SOCKMAP);
    __uint(max_entries, 4);
    __type(key, __u32);
    __type(value, __u64);
} sock_map SEC(".maps");

bool test_ingress = false;

// A simple test program that redirect packet from port 8787 to port 8788.
SEC("sk_skb")
int bpf_prog_verdict(struct __sk_buff *skb) {
    return bpf_sk_redirect_map(skb, &sock_map, 0, test_ingress ? BPF_F_INGRESS: 0);
}

char _license[] SEC("license") = "GPL";
