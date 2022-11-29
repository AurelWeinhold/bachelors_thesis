#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "GPL";

const volatile __u32 port = 0;

SEC("xdp")
int drop_all(struct xdp_md *ctx)
{
	// invalid or no port given
	if (port == 0)
		return XDP_PASS;

	// declare where data starts and ends
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

	// parse ethernet packet
	// ethernet packet must not go over `data_end` edge
	struct ethhdr *eth = data;
	if ((void*)eth + sizeof(*eth) > data_end)
		return XDP_PASS;

	// IPv4 packet must not be go over `data_end` edge
	struct iphdr *ipv4 = (void*)eth + sizeof(*eth);
	if ((void*)ipv4 + sizeof(*ipv4) > data_end)
		return XDP_PASS;
	
	// protocol must be TCP
	if (ipv4->protocol == IPPROTO_TCP) {

		// TCP packet must not go over `data_end` edge
		struct tcphdr *tcp = (void*)ipv4 + sizeof(*ipv4);
		if ((void*)tcp + sizeof(*tcp) > data_end)
			return XDP_PASS;

		// drop only if packet arrived on port `port`
		// change from network to host byte order
		if (bpf_ntohs(tcp->dest) == port)
			return XDP_DROP;

		bpf_printk("TCP packet destination: %i", bpf_ntohs(tcp->dest));
	}

	// TODO(Aurel): parse IPv6 packets

	return XDP_PASS;
}
