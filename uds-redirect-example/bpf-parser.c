#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

SEC("sk_skb/stream_parser")
int bpf_prog_parser(struct __sk_buff *skb) {
    return skb->len;
}
