#include <vmlinux.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "config.h"
#include "prot.h"
#include "speed_limit.h"
#include "thesis.h"

#define memcpy   __builtin_memcpy
#define ETH_ALEN 6

char LICENSE[] SEC("license") = "GPL";

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 3); // port, speed_limit, cars
	__type(key, char[MAX_KEY_LEN]);
	__type(value, __u32);
} state SEC(".maps");
// TODO(Aurel): move port into read-only bpf configuration variable!

// Taken from:
// https://gist.github.com/sbernard31/d4fee7518a1ff130452211c0d355b3f7
__attribute__((__always_inline__)) static inline __u16
csum_fold_helper(__u64 csum)
{
	int i;
#pragma unroll
	for (i = 0; i < 4; i++) {
		if (csum >> 16)
			csum = (csum & 0xffff) + (csum >> 16);
	}
	return ~csum;
}

__attribute__((__always_inline__)) static inline void
ipv4_csum_inline(void *iph, __u64 *csum)
{
	__u16 *next_iph_u16 = (__u16 *)iph;
#pragma clang loop unroll(full)
	for (int i = 0; i < sizeof(struct iphdr) >> 1; i++) {
		*csum += *next_iph_u16++;
	}
	*csum = csum_fold_helper(*csum);
}

__attribute__((__always_inline__)) static inline void
ipv4_csum(void *data_start, int data_size, __u64 *csum)
{
	*csum = bpf_csum_diff(0, 0, data_start, data_size, *csum);
	*csum = csum_fold_helper(*csum);
}

__attribute__((__always_inline__)) static inline void
ipv4_l4_csum(void *data_start, __u32 data_size, __u64 *csum, struct iphdr *iph)
{
	__u32 tmp = 0;
	*csum     = bpf_csum_diff(0, 0, &iph->saddr, sizeof(__be32), *csum);
	*csum     = bpf_csum_diff(0, 0, &iph->daddr, sizeof(__be32), *csum);
	tmp       = __builtin_bswap32((__u32)(iph->protocol));
	*csum     = bpf_csum_diff(0, 0, &tmp, sizeof(__u32), *csum);
	tmp       = __builtin_bswap32((__u32)(data_size));
	*csum     = bpf_csum_diff(0, 0, &tmp, sizeof(__u32), *csum);
	*csum     = bpf_csum_diff(0, 0, data_start, data_size, *csum);
	*csum     = csum_fold_helper(*csum);
}

SEC("xdp")
int
quick_reply(struct xdp_md *ctx)
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

	// actually check, that is an IPv4 packet
	if (eth->h_proto != bpf_ntohs(IPv4_H_PROTO)) {
#if DEBUG > 1
		bpf_printk("Not an ipv4 packet");
#endif
		return XDP_PASS;
	}

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

	// protocol must be UDP
	if (ipv4->protocol != IPPROTO_UDP) {
#if DEBUG > 1
		bpf_printk("Wrong protocol: %i", ipv4->protocol);
#endif
		return XDP_PASS;
	}

	// udp packet must not go over `data_end` edge
	struct udphdr *udp = (void *)ipv4 + sizeof(*ipv4);
	if ((void *)udp + sizeof(*udp) > data_end) {
#if DEBUG > 1
		bpf_printk("Not a udp packet");
#endif
		return XDP_PASS;
	}

#if DEBUG > 1
	// source and destination port helps identify packets
	bpf_printk("source port: %d", bpf_ntohs(udp->source));
	bpf_printk("  dest port: %d", bpf_ntohs(udp->dest));
#endif

	// destination must be `port` (take care of network and host byte order!)
	if (bpf_ntohs(udp->dest) != port) {
#if DEBUG > 1
		bpf_printk("Different port");
#endif
		return XDP_PASS;
	}

	void *prot = (void *)udp + sizeof(*udp);
	if ((void *)(prot + PROT_PACKET_SIZE) > data_end) {
#if DEBUG > 1
		bpf_printk("Not the defined protocol");
#endif
		return XDP_PASS;
	}

	struct prot *request = (struct prot *)prot;
#if DEBUG > 1
	// printing op-code helps identify packets
	// TODO(Aurel): Print not only numerical
	bpf_printk("op: %d", request->op);
#endif

	// only handle PROT_OP_GET_SPEED_LIMIT and PROT_OP_OUT_OF_RANGE requests
	if (request->op != PROT_OP_GET_SPEED_LIMIT &&
	    request->op != PROT_OP_OUT_OF_RANGE) {
#if DEBUG > 1
		bpf_printk(
				"Neither a PROT_OP_GET_SPEED_LIMIT nor PROT_OP_OUT_OF_RANGE request");
#endif
		return XDP_PASS;
	}

	int *cars_lookup = bpf_map_lookup_elem(&state, &state_keys.cars);
	if (!cars_lookup) {
#if DEBUG > 1
		bpf_printk("Failed to look up map (cars)");
#endif
		return XDP_PASS;
	}

	if (request->op == PROT_OP_OUT_OF_RANGE) {
		// NOTE(Aurel): For PROT_OP_OUT_OF_RANGE need only the car counter to be
		// decremented and the packet discarded.
#if DEBUG > 0
		bpf_printk("PROT_OP_OUT_OF_RANGE");
#endif
		__sync_fetch_and_add(cars_lookup, -1);
		return XDP_DROP;
	}

	// PROT_OP_GET_SPEED_LIMIT
#if DEBUG > 0
	bpf_printk("PROT_OP_GET_SPEED_LIMIT");
#endif

	// atomic increment of the value at a memory location
	__sync_fetch_and_add(cars_lookup, 1);
	/* Same as, but atomic:
	 *
	 * int cars = *cars_lookup;
	 * cars++;
	 * if (bpf_map_update_elem(&state, &state_keys.cars, &cars, 0) != 0)
	 *		return XDP_PASS;
	*/

	// get the speed limit
	int *speed_limit_lookup =
			bpf_map_lookup_elem(&state, &state_keys.speed_limit);
	if (!speed_limit_lookup) {
#if DEBUG > 1
		bpf_printk("Failed to look up map (speed_limit)");
#endif
		return XDP_PASS;
	}

#ifdef DEBUG_EBPF_ONLY
	if (*cars_lookup < SPEED_LIMIT_DROP_START)
		*speed_limit_lookup = SPEED_LIMIT_MAX;
	else if (*cars_lookup < SPEED_LIMIT_DROP_STOP)
		*speed_limit_lookup = SPEED_LIMIT_DROP_FUNC(*cars_lookup);
	else
		*speed_limit_lookup = SPEED_LIMIT_MIN;
#endif

	/*
	 * **Only change packet after here!**
	 * All checks and the lookup were successful.
	 */

	// set the current state in the value field
	request->op    = PROT_OP_REPLY;
	request->value = *speed_limit_lookup;

	// reverse mac address
	u8 tmp_mac[ETH_ALEN];
	memcpy(tmp_mac, eth->h_dest, ETH_ALEN);
	memcpy(eth->h_dest, eth->h_source, ETH_ALEN);
	memcpy(eth->h_source, tmp_mac, ETH_ALEN);

	// reverse source and destination ip
	__u32 dest_ip = ipv4->daddr;
	ipv4->daddr   = ipv4->saddr;
	ipv4->saddr   = dest_ip;

	// reverse source and destination port
	__u32 dest_port = udp->dest;
	udp->dest       = udp->source;
	udp->source     = dest_port;

#if DEBUG > 0
	bpf_printk("Successfully read value");
	bpf_printk("Rerouting packet to %lu:%lu", ipv4->daddr,
	           bpf_ntohs(udp->dest));
#endif


	// Updating the checksums is taken from:
	// https://gist.github.com/sbernard31/d4fee7518a1ff130452211c0d355b3f7
	// Update IP checksum
	ipv4->check = 0;
	__u64 cs   = 0;
	ipv4_csum(ipv4, sizeof(*ipv4), &cs);
	ipv4->check = cs;

	// Update UDP checksum
	__u16 udp_len = sizeof(*udp) + PROT_PACKET_SIZE;
	udp->check = 0;
	cs         = 0;
	ipv4_l4_csum(udp, udp_len, &cs, ipv4);
	udp->check = cs;


	// outgoing XDP interface
	return XDP_TX;
}
