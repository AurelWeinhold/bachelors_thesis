#ifndef THESIS_H

// TODO(Aurel): Update accordingly if needed!
#define MAX_KEY_LEN 5
struct state_keys {
	char port[MAX_KEY_LEN];
};

const struct state_keys state_keys = {
	.port = "port",
};

#define THESIS_H
#endif /* ifndef THESIS_H */
