// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2020 Facebook */

// shared
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

// eBPF
#include <bpf/libbpf.h>
#include <signal.h>

// userspace server
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "thesis.h"
#include "thesis.skel.h"

#define PORT_LEN 5

struct state {
	char port[PORT_LEN + 1];
	int state;
};

static int
libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	/*
	 * TODO(Aurel): Figure out how to handle verbose setting.
	 * if (level == LIBBPF_DEBUG && !env.verbose)
	 * 	return 0;
	 */
	return vfprintf(stderr, format, args);
}

static volatile bool exiting = false;

static void
sig_handler(int sig)
{
	exiting = true;
}

int
init_socket(int *sockfd, char *port)
{
	struct addrinfo hints, *server_info, *p;

	// hints needs to be filled with all 0 except for ai_family, ai_socktype
	// and ai_flags in order to be automatically filled by getaddrinfo()
	memset(&hints, 0, sizeof(hints));
	hints.ai_family   = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags    = AI_PASSIVE;

	int rv;
	if ((rv = getaddrinfo(NULL, port, &hints, &server_info)) != 0) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
		return -1;
	}

	// loop through all the results and bind to the first possible
	int status = 0;
	for (p = server_info; p != NULL; p = p->ai_next) {
		// trying to get a socket
		if ((*sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) ==
		    -1) {
			perror("server: socket");
			continue;
		}
		// SO_REUSEADDR: Port may be reused after program stops running
		int optval = 1;
		setsockopt(*sockfd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(int));

		// trying to bind to that socket
		if ((status = bind(*sockfd, p->ai_addr, p->ai_addrlen)) == -1) {
			close(*sockfd);
			perror("server: bind");
			continue;
		}
		// socket bound
		break;
	}
	freeaddrinfo(server_info);
	if (p == NULL) {
		fprintf(stderr, "server: failed to connect to socket.\n");
		return -1;
	}
	if (status == -1) {
		fprintf(stderr, "server: failed to bind to socket.\n");
		return -1;
	}

	// preparing for incoming connections
	if (listen(*sockfd, 1) == -1) {
		perror("listen");
		return -1;
	}
	return 0;
}

static struct state *shared_state;

int
main(int argc, char **argv)
{
	struct thesis_bpf *obj;

	// Parse command line arguments
	if (argc < 3) {
		fprintf(stderr, "Usage: %s ifindex port\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	int ifindex = atoi(argv[1]);
	if (ifindex <= 0) {
		fprintf(stderr, "ifindex must be at least 1\n");
		exit(EXIT_FAILURE);
	}

	int port = atoi(argv[2]);
	if (port < 0) {
		fprintf(stderr, "port needs to be at least 0\n");
		exit(EXIT_FAILURE);
	}

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* Cleaner handling of Ctrl-C */
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	/* Load and verify BPF application */
	obj = thesis_bpf__open();
	if (!obj) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		exit(EXIT_FAILURE);
	}

	// Shared memory for accessing the state in both threads
	// TODO(Aurel): What does MAP_ANONYMOUS mean?
	shared_state = mmap(NULL, sizeof(*shared_state), PROT_READ | PROT_WRITE,
	                    MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (shared_state == MAP_FAILED) {
		fprintf(stderr, "Failed to create shared memory\n");
		exit(EXIT_FAILURE);
	}

	strncpy(shared_state->port, port_str, PORT_LEN);
	shared_state->port[PORT_LEN] = '\0';
	shared_state->state          = 0;

	int pid;
	if ((pid = fork()) == 0) {
		// child: eBPF

		struct bpf_map *state_map = NULL;

		/* Load & verify BPF programs */
		int err = thesis_bpf__load(obj);
		if (err) {
			fprintf(stderr, "Failed to load and verify BPF skeleton\n");
			goto cleanup;
		}

		/* Attach to XDP stage */
		// struct bpf_link bpf_program__attach_xdp(const struct bpf_program, int ifindex)
		/*
		 * struct bpf_link {
		 *		atomic64_t refcnt;
		 * 		u32 id;
		 * 		enum bpf_link_type type;
		 * 		const struct bpf_link_ops *ops;
		 * 		struct bpf_prog *prog;
		 * 		struct work_struct work;
		 * };
		 */
		struct bpf_link *link =
				bpf_program__attach_xdp(obj->progs.drop_all, ifindex);
		if (!link) {
			fprintf(stderr, "Failed to attach eBPF to XDP.\n");
			goto cleanup;
		}
		// NOTE(Aurel): filter needs to be loaded to access appropriate memory
		state_map = obj->maps.state;
		// NOTE(Aurel): See header for state map keys:
		bpf_map__update_elem(state_map, &state_keys.port,
		                     sizeof(state_keys.port), &shared_state->port,
		                     sizeof(__u32), 0);
		bpf_map__update_elem(state_map, &state_keys.state,
		                     sizeof(state_keys.state), &shared_state->state,
		                     sizeof(__u32), 0);

		char port_str[5];
		errno = 0; // actually errno
		int n = 0;
		while (!exiting) {
			if (err < 0) {
				printf("Error scanning for user input: %d\n", err);
				break;
			}
		};

	cleanup:
		/* Clean up */
		thesis_bpf__destroy(obj);

		return err < 0 ? -err : 0;

	} else {
		// parent: userspace
		// fallback port: port
	}
}
