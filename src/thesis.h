#ifndef THESIS_H

// TODO(Aurel): Update accordingly if needed!
#define MAX_KEY_LEN 5
struct state_keys {
	char port[MAX_KEY_LEN];
	char state[MAX_KEY_LEN];
};

// keys for the state map between userspace and eBPF application
const struct state_keys state_keys = {
	.port  = "port",
	.state = "state",
};

/*
 * TODO(Aurel): Maybe don't stop adding padding. This is done so the network
 * packet (at an offset) can be casted to `struct prot`.
 */
#pragma pack(push, 1)
struct prot {
	int op;
	int value;
};
#pragma pack(pop)

/**
 * Protocol offsets
 * 0 |----|----|----|----|
 *   |        op         |
 * 4 |----|----|----|----|
 *   |       value       |
 * 8 |----|----|----|----|
 */
#define PROT_PACKET_SIZE 8
/**
 * Offsets to the individual fields
 */
enum prot_offset {
	PROT_OP_OFFSET    = 0,
	PROT_VALUE_OFFSET = 4,
};
/**
 * OP codes
 */
enum protocol_op {
	PROT_OP_NOOP  = 0,
	PROT_OP_READ  = 1,
	PROT_OP_WRITE = 2,
};

#define THESIS_H
#endif /* ifndef THESIS_H */
