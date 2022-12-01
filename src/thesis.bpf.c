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
	if (ipv4->protocol != IPPROTO_TCP)
		return XDP_PASS;

	// TODO(Aurel): parse IPv6 packets

	// TCP packet must not go over `data_end` edge
	struct tcphdr *tcp = (void*)ipv4 + sizeof(*ipv4);
	if ((void*)tcp + sizeof(*tcp) > data_end)
		return XDP_PASS;

	// destination must be `port` (take care of network and host byte order!)
	if (bpf_ntohs(tcp->dest) != port)
		return XDP_PASS;

	// reverse source and destination ip
	__u32 dest_ip = ipv4->daddr;
	ipv4->daddr = ipv4->saddr;
	ipv4->saddr = dest_ip;

	// reverse source and destination port
	__u32 dest_port = tcp->dest;
	tcp->dest = tcp->source;
	tcp->source = dest_port;

	bpf_printk("Rerouting packet to %lu:%lu", ipv4->daddr, bpf_ntohs(tcp->dest));

	return XDP_TX;
}
