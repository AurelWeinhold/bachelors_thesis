// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2020 Facebook */

// shared
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include <sys/wait.h>

// eBPF
#include <bpf/libbpf.h>
#include <signal.h>

// networking
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "thesis.h"
#include "thesis.skel.h"

//#define DEBUG_USERSPACE_ONLY
//#define DEBUG_EBPF_ONLY

#define MAX_CONNECTIONS 10
// TODO(Aurel): Make BUF_SIZE == PROT_PACKET_SIZE
#define BUF_SIZE 256
#define PORT_LEN 5

struct state {
	uint32_t state;
};

static volatile bool exiting = false;
static struct state *shared_state;

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

static void
sig_handler(int sig)
{
	exiting = true;
}

void
print_prot(struct prot prot)
{
	printf("op: %d\n", prot.op);
	printf("value: %d\n", prot.value);
}

/**
 * Receives data on the given `socket_fd` and parses it into the given `packet`.
 *
 * @param int socket_fd The socket file descriptor to receive data on.
 * @param struct prot *packet The packet struct to parse the received data into.
 *
 * @return -1 if something failed or an invalid packet was sent.
 * @return 0 for success. `prot` has then been overwritten with the newly
 *			 received data.
 */
int
receive_prot_packet(int socket_fd, struct prot *packet)
{
	printf("receiving\n");
	uint8_t buf[BUF_SIZE];
	size_t nr_bytes_recv = 0;
	uint8_t *wr_ptr      = buf;
	int cur_recv;
	while (nr_bytes_recv < PROT_PACKET_SIZE) {
		//         recv(socket_fd, buf,    remaining buf_size,       flags)
		cur_recv = recv(socket_fd, wr_ptr, BUF_SIZE - nr_bytes_recv, 0);
		if (cur_recv < 0) {
			perror("recv");
			return -1;
		}
		if (cur_recv == 0)
			// All data received
			return -1;
		nr_bytes_recv += cur_recv;
		wr_ptr += cur_recv;
	}

	if (nr_bytes_recv != PROT_PACKET_SIZE) {
		printf("error receiving: received %zu bytes\n", nr_bytes_recv);
		return -1;
	}

	// parse packet
	packet->op = buf[PROT_OP_OFFSET];
	memcpy(&packet->value, buf + PROT_VALUE_OFFSET, sizeof(packet->value));

	return 0;
}

int
send_prot(int socket_fd, struct prot prot)
{
	int size = sizeof(prot);

	char buf[size + 1];
	memcpy(buf + PROT_OP_OFFSET, &prot.op, 4);
	memcpy(buf + PROT_VALUE_OFFSET, &prot.value, 4);

	// loop while not all `size` bytes have been sent
	long nsent = 0;
	while (nsent != size) {
		int bytes;
		if ((bytes = send(socket_fd, buf + nsent, size - nsent, 0)) < -1) {
			perror("send");
			return -1;
		}
		nsent += bytes;
	}
	return 0;
}

int
send_state(int socket_fd)
{
	struct prot reply = { .op = PROT_OP_READ, .value = shared_state->state };
	return send_prot(socket_fd, reply);
}

int
handle_request(int fd, fd_set *primary_fds)
{
	struct prot request;
	receive_prot_packet(fd, &request);
	print_prot(request);

	switch (request.op) {
	case PROT_OP_READ:
		send_state(fd);
		break;
	case PROT_OP_WRITE:
		// TODO(Aurel): Implement writing the state.
		shared_state->state = request.value;
		printf("Updated state: %d\n", shared_state->state);
		send_state(fd);
		break;
	default:;
	}

	close(fd);
	FD_CLR(fd, primary_fds);
	return 1;
}

int
init_socket(int *socket_fd, char *port)
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
		if ((*socket_fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) ==
		    -1) {
			perror("server: socket");
			continue;
		}
		// SO_REUSEADDR: Port may be reused after program stops running
		int optval = 1;
		setsockopt(*socket_fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(int));

		// trying to bind to that socket
		if ((status = bind(*socket_fd, p->ai_addr, p->ai_addrlen)) == -1) {
			close(*socket_fd);
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
	if (listen(*socket_fd, 1) == -1) {
		perror("listen");
		return -1;
	}
	return 0;
}

int
userspace(char *port_str)
{
	// fallback port: port

	/*
	 * NOTE(Aurel): Inspired by [beej's guide to networking in
	 * C](https://beej.us/guide/bgnet/)
	 */

	int sockfd = -1, new_fd;

	if (init_socket(&sockfd, port_str) < 0) {
		fprintf(stderr, "initializing socket failed.\n");
		if (sockfd >= 0)
			close(sockfd);
		exit(EXIT_FAILURE);
	}

	fd_set primary_fds;
	fd_set read_fds; // temporary fd set for select
	int fd_max;      // maximum fd

	// clear both fd_sets
	FD_ZERO(&read_fds);
	FD_ZERO(&primary_fds);

	struct sockaddr_storage remoteaddr;
	socklen_t socklen;

	if (listen(sockfd, MAX_CONNECTIONS) == -1) {
		perror("listen");
		exit(3);
	}

	// add the listener to the master set
	FD_SET(sockfd, &primary_fds);
	fd_max = sockfd;

	while (!exiting) {
		// every connection we accept is in primary which we copy to
		// read_fds to read from
		read_fds = primary_fds;

		if (select(fd_max + 1, &read_fds, NULL, NULL, NULL) == -1) {
			perror("select");
			exit(4);
		}

		// check each fd for data to read
		int read = 0;
		for (int fd = 0; fd <= fd_max; fd++) {
			if (FD_ISSET(fd, &read_fds)) {
				// connection found

				if (fd == sockfd) {
					// new connection found
					int new_fd;
					socklen = sizeof remoteaddr;
					new_fd  = accept(sockfd, (struct sockaddr *)&remoteaddr,
					                 &socklen);
					if (new_fd == -1) {
						perror("accept");
					} else {
						// adding new connection to list
						FD_SET(new_fd, &primary_fds);
						if (new_fd > fd_max) {
							// update max fd
							fd_max = new_fd;
						}
						printf("New connection established @ fd-%d.\n", new_fd);
					}
				} else {
					// already established connection is sending data
#ifndef DEBUG_EBPF_ONLY
					read = handle_request(fd, &primary_fds);
#endif
				}
			}
		}
		/* TODO(Aurel): When to break out of loop?
		if (read)
			break;
		*/
	}

	close(sockfd);
	return 0;
}

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

	char *port_str = argv[2];
	int port       = atoi(port_str);
	if (port < 0) {
		fprintf(stderr, "port needs to be at least 0\n");
		exit(EXIT_FAILURE);
	}

#ifndef DEBUG_USERSPACE_ONLY
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
#endif

	// Shared memory for accessing the state in both threads
	// TODO(Aurel): What does MAP_ANONYMOUS mean?
	shared_state = mmap(NULL, sizeof(*shared_state), PROT_READ | PROT_WRITE,
	                    MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (shared_state == MAP_FAILED) {
		fprintf(stderr, "Failed to create shared memory\n");
		exit(EXIT_FAILURE);
	}
	shared_state->state = 3012;

#ifndef DEBUG_USERSPACE_ONLY
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
		err = bpf_map__update_elem(state_map, &state_keys.port,
		                           sizeof(state_keys.port), &port,
		                           sizeof(__u32), 0);
		bpf_map__update_elem(state_map, &state_keys.state,
		                     sizeof(state_keys.state), &shared_state->state,
		                     sizeof(__u32), 0);

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
#endif
		// parent: userspace
		userspace(port_str);
#ifndef DEBUG_USERSPACE_ONLY
		wait(NULL);
	}
#endif
}
