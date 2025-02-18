#include <linux/bpf.h>
#include <stdbool.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define AF_VSOCK 40

struct {
    __uint(type, BPF_MAP_TYPE_SOCKMAP);
    __uint(max_entries, 4);
    __type(key, __u32);
    __type(value, __u64);
} sock_map SEC(".maps");

// A simple test program that redirects VSOCK message to another socket
// VSOCK should be placed at index 1
SEC("sk_skb")
int bpf_prog_verdict(struct __sk_buff *skb) {
    if (skb->family == AF_VSOCK)
        return bpf_sk_redirect_map(skb, &sock_map, 0, 0);
    else
        return bpf_sk_redirect_map(skb, &sock_map, 1, 0);
}

char _license[] SEC("license") = "GPL";
