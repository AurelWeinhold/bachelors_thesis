#ifndef PROT_H

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
	PROT_OP_REPLY = 3,

	PROT_OP_GET_SPEED_LIMIT = 4,
	PROT_OP_OUT_OF_RANGE    = 5,
};

#define PROT_H
#endif /* ifndef PROT_H */
