#include <vmlinux.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "thesis.h"

//#define DEBUG

char LICENSE[] SEC("license") = "GPL";

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 2);
	__type(key, char[MAX_KEY_LEN]);
	__type(value, __u32);
} state SEC(".maps");

SEC("xdp")
int
drop_all(struct xdp_md *ctx)
{
#ifdef DEBUG
	// some spacing helps differentiate between the individual packets
	bpf_printk("\n\n");
#endif

	__u32 port = 0;

	void *port_lookup = bpf_map_lookup_elem(&state, &state_keys.port);
	if (port_lookup) {
		port = *(u32 *)port_lookup;
	}

	// invalid or no port given
	if (port == 0) {
#ifdef DEBUG
		bpf_printk("Invalid port: %p", port);
#endif
		return XDP_PASS;
	}

	// declare where data starts and ends
	void *data     = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

	// parse ethernet packet
	// ethernet packet must not go over `data_end` edge
	struct ethhdr *eth = data;
	if ((void *)eth + sizeof(*eth) > data_end) {
#ifdef DEBUG
		bpf_printk("not an ethernet packet");
#endif
		return XDP_PASS;
	}

	// IPv4 packet must not be go over `data_end` edge
	struct iphdr *ipv4 = (void *)eth + sizeof(*eth);
	if ((void *)ipv4 + sizeof(*ipv4) > data_end) {
#ifdef DEBUG
		bpf_printk("Not an ipv4 packet");
#endif
		return XDP_PASS;
	}

#ifdef DEBUG
	// source and destination ip helps identify packets
	bpf_printk("source ip: %d", ipv4->saddr);
	bpf_printk("  dest ip: %d", ipv4->daddr);
#endif

	// protocol must be TCP
	if (ipv4->protocol != IPPROTO_TCP) {
#ifdef DEBUG
		bpf_printk("Wrong protocol: %i", ipv4->protocol);
#endif
		return XDP_PASS;
	}

	// TODO(Aurel): parse IPv6 packets

	// TCP packet must not go over `data_end` edge
	struct tcphdr *tcp = (void *)ipv4 + sizeof(*ipv4);
	if ((void *)tcp + sizeof(*tcp) > data_end) {
#ifdef DEBUG
		bpf_printk("Not a tcp packet");
#endif
		return XDP_PASS;
	}

	if (tcp->syn || tcp->fin || tcp->rst)
		return XDP_PASS;

#ifdef DEBUG
	// source and destination port helps identify packets
	bpf_printk("source port: %d", bpf_ntohs(tcp->source));
	bpf_printk("  dest port: %d", bpf_ntohs(tcp->dest));
#endif

	// destination must be `port` (take care of network and host byte order!)
	if (bpf_ntohs(tcp->dest) != port) {
#ifdef DEBUG
		bpf_printk("Different port");
#endif
		return XDP_PASS;
	}

	void *base = (void *)tcp + sizeof(*tcp);

	// TODO(Aurel): What is in the `data_offset`s bytes? Another header?
	int data_offset = 12;
	char *data_base = base + data_offset;
	if ((void *)(data_base + PROT_PACKET_SIZE) > data_end) {
#ifdef DEBUG
		bpf_printk("Not the defined protocol");
#endif
		return XDP_PASS;
	}

	struct prot *request = (struct prot *)data_base;
#ifdef DEBUG
	// printing op-code helps identify packets
	// TODO(Aurel): Print not only numerical
	bpf_printk("op: %d", request->op);
#endif

	// only handle read requests
	if (request->op != PROT_OP_READ) {
#ifdef DEBUG
		bpf_printk("Not a read request");
#endif
		return XDP_PASS;
	}

	// get the state
	int *state_lookup = bpf_map_lookup_elem(&state, &state_keys.state);
	if (!state_lookup) {
#ifdef DEBUG
		bpf_printk("Failed to look up state");
#endif
		return XDP_PASS;
	}

	/*
	 * **Only change packet after here!**
	 * All checks and the lookup were successful.
	 */

	u32 tmp_seq  = tcp->seq;
	tcp->seq     = tcp->ack_seq;
	tcp->ack_seq = tmp_seq;

	// set the current state in the value field
	request->value = *state_lookup;

	// reverse source and destination ip
	__u32 dest_ip = ipv4->daddr;
	ipv4->daddr   = ipv4->saddr;
	ipv4->saddr   = dest_ip;

	// reverse source and destination port
	__u32 dest_port = tcp->dest;
	tcp->dest       = tcp->source;
	tcp->source     = dest_port;

#ifdef DEBUG
	bpf_printk("Successfully read value");
	bpf_printk("Rerouting packet to %lu:%lu", ipv4->daddr,
	           bpf_ntohs(tcp->dest));
#endif

	return XDP_TX;
}
