#ifndef THESIS_H

// TODO(Aurel): Update accordingly if needed!
// TODO(Aurel): Maybe pass the port as a constant as it can't really change.
#define MAX_KEY_LEN 12
struct state_keys {
	char port[MAX_KEY_LEN];
	char speed_limit[MAX_KEY_LEN];
	char cars[MAX_KEY_LEN];
};

// keys for the state map between userspace and eBPF application
const struct state_keys state_keys = {
	.port        = "port",
	.speed_limit = "speed_limit",
	.cars        = "cars",
};

#define THESIS_H
#endif /* ifndef THESIS_H */
