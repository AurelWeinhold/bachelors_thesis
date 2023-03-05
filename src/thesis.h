#ifndef THESIS_H

// TODO(Aurel): Update accordingly if needed!
#define MAX_KEY_LEN 5
struct state_keys {
	char port[MAX_KEY_LEN];
	char state[MAX_KEY_LEN];
};

const struct state_keys state_keys = {
	.port = "port",
	.state = "state",
};

struct prot {
	int op;
	int value;
};

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
