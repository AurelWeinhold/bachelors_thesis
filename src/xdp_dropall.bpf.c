#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "GPL";

SEC("xdp")
int drop_all(struct xdp_md *ctx)
{
	return XDP_DROP;
}
