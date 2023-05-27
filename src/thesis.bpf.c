#include <vmlinux.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "thesis.h"

#define memcpy __builtin_memcpy
#define ETH_ALEN 6

#define DEBUG 0

char LICENSE[] SEC("license") = "GPL";

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 3); // port, speed_limit, cars
	__type(key, char[MAX_KEY_LEN]);
	__type(value, __u32);
} state SEC(".maps");

SEC("xdp")
int
drop_all(struct xdp_md *ctx)
{
#if DEBUG > 1
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
#if DEBUG > 1
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
#if DEBUG > 1
		bpf_printk("not an ethernet packet");
#endif
		return XDP_PASS;
	}

	// IPv4 packet must not be go over `data_end` edge
	struct iphdr *ipv4 = (void *)eth + sizeof(*eth);
	if ((void *)ipv4 + sizeof(*ipv4) > data_end) {
#if DEBUG > 1
		bpf_printk("Not an ipv4 packet");
#endif
		return XDP_PASS;
	}

#if DEBUG > 1
	// source and destination ip helps identify packets
	bpf_printk("source ip: %d", ipv4->saddr);
	bpf_printk("  dest ip: %d", ipv4->daddr);
#endif

	// protocol must be TCP
	if (ipv4->protocol != IPPROTO_TCP) {
#if DEBUG > 1
		bpf_printk("Wrong protocol: %i", ipv4->protocol);
#endif
		return XDP_PASS;
	}

	// TODO(Aurel): parse IPv6 packets

	// TCP packet must not go over `data_end` edge
	struct tcphdr *tcp = (void *)ipv4 + sizeof(*ipv4);
	if ((void *)tcp + sizeof(*tcp) > data_end) {
#if DEBUG > 1
		bpf_printk("Not a tcp packet");
#endif
		return XDP_PASS;
	}

	if (tcp->syn || tcp->fin || tcp->rst)
		return XDP_PASS;

#if DEBUG > 1
	// source and destination port helps identify packets
	bpf_printk("source port: %d", bpf_ntohs(tcp->source));
	bpf_printk("  dest port: %d", bpf_ntohs(tcp->dest));
#endif

	// destination must be `port` (take care of network and host byte order!)
	if (bpf_ntohs(tcp->dest) != port) {
#if DEBUG > 1
		bpf_printk("Different port");
#endif
		return XDP_PASS;
	}

	void *base = (void *)tcp + sizeof(*tcp);

	// TODO(Aurel): What is in the `data_offset`s bytes? Another header?
	int data_offset = 12;
	char *data_base = base + data_offset;
	if ((void *)(data_base + PROT_PACKET_SIZE) > data_end) {
#if DEBUG > 1
		bpf_printk("Not the defined protocol");
#endif
		return XDP_PASS;
	}

	struct prot *request = (struct prot *)data_base;
#if DEBUG > 1
	// printing op-code helps identify packets
	// TODO(Aurel): Print not only numerical
	bpf_printk("op: %d", request->op);
#endif

	// only handle PROT_OP_GET_SPEED_LIMIT requests
	if (request->op != PROT_OP_GET_SPEED_LIMIT) {
#if DEBUG > 1
		bpf_printk("Not a read request");
#endif
		return XDP_PASS;
	}

	// get the speed limit
	int *speed_limit_lookup =
			bpf_map_lookup_elem(&state, &state_keys.speed_limit);
	if (!speed_limit_lookup) {
#if DEBUG > 1
		bpf_printk("Failed to look up map (speed_limit)");
#endif
		return XDP_PASS;
	}

	// atomic increment of the value at a memory location
	__sync_fetch_and_add(cars_lookup, 1);
	/* Same as, but atomic:
	 *
	 * int cars = *cars_lookup;
	 * cars++;
	 * if (bpf_map_update_elem(&state, &state_keys.cars, &cars, 0) != 0)
	 *		return XDP_PASS;
	*/

	/*
	 * **Only change packet after here!**
	 * All checks and the lookup were successful.
	 */

	u8 tmp_mac[ETH_ALEN];
	memcpy(tmp_mac, eth->h_dest, ETH_ALEN);
	memcpy(eth->h_dest, eth->h_source, ETH_ALEN);
	memcpy(eth->h_source, tmp_mac, ETH_ALEN);

	u32 tmp_seq  = tcp->seq;
	tcp->seq     = tcp->ack_seq;
	tcp->ack_seq = tmp_seq;

	// set the current state in the value field
	request->op    = PROT_OP_REPLY;
	request->value = *speed_limit_lookup;

	// reverse source and destination ip
	__u32 dest_ip = ipv4->daddr;
	ipv4->daddr   = ipv4->saddr;
	ipv4->saddr   = dest_ip;

	// reverse source and destination port
	__u32 dest_port = tcp->dest;
	tcp->dest       = tcp->source;
	tcp->source     = dest_port;

#if DEBUG > 0
	bpf_printk("Successfully read value");
	bpf_printk("Rerouting packet to %lu:%lu", ipv4->daddr,
	           bpf_ntohs(tcp->dest));
#endif
	return XDP_TX;
}
