// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2020 Facebook */

#include "config.h"

// shared
#include <errno.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

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

#include "speed_limit.h"

#define MAX_CONNECTIONS 100
// TODO(Aurel): Make BUF_SIZE == PROT_PACKET_SIZE
#define BUF_SIZE 256
#define PORT_LEN 5

double
calc_speed_limit(int x)
{
	if (x < SPEED_LIMIT_DROP_START)
		return SPEED_LIMIT_MAX;
	else if (x < SPEED_LIMIT_DROP_STOP)
		return SPEED_LIMIT_DROP_FUNC(x);
	else
		return SPEED_LIMIT_MIN;
}

struct state {
	uint32_t speed_limit;
	uint32_t cars;
};

static volatile bool exiting = false;

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

enum poll_fds { RECEIVED_MSG };

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

int
update_speed_limit(struct state *state, struct bpf_map *state_map)
{
	int err = 0;
#ifndef DEBUG_USERSPACE_ONLY
	// read cars from map
	// NOTE(Aurel): this is not the actual location of the
	// data, but rather the value copied over
	err = bpf_map__lookup_elem(state_map, &state_keys.cars,
	                           sizeof(state_keys.cars), &state->cars,
	                           sizeof(__u32), 0);
	if (err) {
		fprintf(stderr, "Failed reading map (cars). errno: %s\n",
		        strerror(errno));
		return -1;
	}
#endif

	// set speed limit according to function
	printf("Speed limit: %d\n", state->speed_limit);
	state->speed_limit = calc_speed_limit(state->cars);

#ifndef DEBUG_USERSPACE_ONLY
	// update map
	err = bpf_map__update_elem(state_map, &state_keys.speed_limit,
	                           sizeof(state_keys.speed_limit),
	                           &state->speed_limit, sizeof(__u32), 0);
	if (err) {
		fprintf(stderr, "Failed updating map (speed_limit). errno: %s\n",
		        strerror(errno));
		return -1;
	}
#endif
	return 0;
}

// get sockaddr, IPv4 or IPv6:
void *
get_in_addr(struct sockaddr *sa)
{
	if (sa->sa_family == AF_INET) {
		return &(((struct sockaddr_in *)sa)->sin_addr);
	}

	return &(((struct sockaddr_in6 *)sa)->sin6_addr);
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
wait_and_receive_prot_packet(int socket_fd, struct prot *packet,
                             struct sockaddr_storage *from)
{
	printf("waiting and receiving...\n");

	size_t nr_bytes_recv = 0;
	uint8_t buf[BUF_SIZE];
	socklen_t addr_len = sizeof(*from);
	if ((nr_bytes_recv = recvfrom(socket_fd, buf, 100 - 1, 0,
	                              (struct sockaddr *)from, &addr_len)) == -1) {
		perror("recvfrom");
		exit(1);
	}

	char s[INET_ADDRSTRLEN];
	inet_ntop(from->ss_family, get_in_addr((struct sockaddr *)from), s,
	          sizeof(s));

	printf("listener: got packet from %s\n", s);
	printf("listener: packet is %zu bytes long\n", nr_bytes_recv);

	if (nr_bytes_recv != PROT_PACKET_SIZE) {
		printf("error receiving: received %zu bytes\n", nr_bytes_recv);
		return -1;
	}

	// parse packet
	memcpy(&packet->op, buf + PROT_OP_OFFSET, sizeof(packet->op));
	memcpy(&packet->value, buf + PROT_VALUE_OFFSET, sizeof(packet->value));

	return 0;
}

int
send_speed_limit(int socket_fd, struct state *state, struct sockaddr_storage to)
{
	struct prot reply = { .op = PROT_OP_REPLY, .value = state->speed_limit };

	// marshalling
	char buf[PROT_PACKET_SIZE + 1];
	memcpy(buf + PROT_OP_OFFSET, &reply.op, 4);
	memcpy(buf + PROT_VALUE_OFFSET, &reply.value, 4);

	// sending
	sendto(socket_fd, buf, PROT_PACKET_SIZE, 0, (struct sockaddr *)&to,
	       sizeof(to));
	// TODO(Aurel): Error handling!
	return 0;
}

int
handle_request(int socket_fd, struct state *state, struct bpf_map *state_map)
{
	// TODO(Aurel): When to update speed limit for connections handled by eBPF?
	struct prot request;
	struct sockaddr_storage from;
	int err = wait_and_receive_prot_packet(socket_fd, &request, &from);
	if (err < 0) {
		printf("Error receiving packet\n");
		return -1;
	}
	print_prot(request);

	switch (request.op) {
	case PROT_OP_READ:
		send_speed_limit(socket_fd, state, from);
		break;
	case PROT_OP_WRITE:
		// TODO(Aurel): Implement writing the state.
		state->speed_limit = request.value;
#ifndef DEBUG_USERSPACE_ONLY
		// pass state to eBPF program
		int err = bpf_map__update_elem(state_map, &state_keys.speed_limit,
		                               sizeof(state_keys.speed_limit),
		                               &state->speed_limit, sizeof(__u32), 0);
		if (err) {
			fprintf(stderr, "Failed updating map (speed_limit). errno: %s\n",
			        strerror(errno));
			return -1;
		}
#endif

		printf("Updated state: %d\n", state->speed_limit);
		send_speed_limit(socket_fd, state, from);
		break;
	case PROT_OP_GET_SPEED_LIMIT:
		state->cars++;
		update_speed_limit(state, state_map);
		send_speed_limit(socket_fd, state, from);
		printf("New car arrived: %d\n", state->cars);
		break;
	case PROT_OP_OUT_OF_RANGE:
		state->cars--;
#ifndef DEBUG_USERSPACE_ONLY
		// pass state to eBPF program
		err = bpf_map__update_elem(state_map, &state_keys.cars,
		                           sizeof(state_keys.cars), &state->cars,
		                           sizeof(__u32), 0);
		if (err) {
			fprintf(stderr, "Failed updating map (cars). errno: %s\n",
			        strerror(errno));
			return -1;
		}
#endif
		update_speed_limit(state, state_map);
		printf("Car left range: %d\n", state->cars);
		break;
	default:;
	}
	return 0;
}

int
init_socket(int *socket_fd, char *port)
{
	struct addrinfo hints, *servinfo, *p;
	int rv;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family   = AF_INET;    // IPv4
	hints.ai_socktype = SOCK_DGRAM; // UDP
	hints.ai_flags    = AI_PASSIVE; // use my IP

	if ((rv = getaddrinfo(NULL, port, &hints, &servinfo)) != 0) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
		return 1;
	}

	// loop through all the results and bind to the first we can
	for (p = servinfo; p != NULL; p = p->ai_next) {
		if ((*socket_fd = socket(p->ai_family, p->ai_socktype,
		                         p->ai_protocol)) == -1) {
			perror("listener: socket");
			continue;
		}

		if (bind(*socket_fd, p->ai_addr, p->ai_addrlen) == -1) {
			close(*socket_fd);
			perror("listener: bind");
			continue;
		}

		break;
	}

	if (p == NULL) {
		fprintf(stderr, "listener: failed to bind socket\n");
		return 2;
	}

	freeaddrinfo(servinfo);
	return 0;
}

int
parse_args(int *port, int *ifindex, char **port_str, int argc, char **argv)
{
	// Parse command line arguments
	if (argc < 3) {
		fprintf(stderr, "Usage: %s ifindex port\n", argv[0]);
		return 1;
	}

	*ifindex = atoi(argv[1]);
	if (ifindex <= 0) {
		fprintf(stderr, "ifindex must be at least 1\n");
		return 1;
	}

	*port_str = argv[2];
	*port     = atoi(*port_str);
	if (port < 0) {
		fprintf(stderr, "port needs to be at least 0\n");
		return 1;
	}
	return 0;
}

int
main(int argc, char **argv)
{
	int port, ifindex;
	char *port_str;
	if (parse_args(&port, &ifindex, &port_str, argc, argv)) {
		exit(EXIT_FAILURE);
	}

	/* Cleaner handling of Ctrl-C */
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

#ifndef DEBUG_USERSPACE_ONLY
	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* Load and verify BPF application */
	struct thesis_bpf *obj = thesis_bpf__open();
	if (!obj) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		exit(EXIT_FAILURE);
	}
#endif

	struct state state = { .speed_limit = calc_speed_limit(0), .cars = 0 };

	// setup fds to be polled
	struct pollfd pollfds[1];
	pollfds[RECEIVED_MSG] = (struct pollfd){
		.events = POLLIN,
	};

	/********************
	 * Setup the server *
	 ********************
	 *
	 * NOTE(Aurel): Inspired by [beej's guide to networking in
	 * C](https://beej.us/guide/bgnet/)
	 */
	int socket_fd = -1, new_fd;

	if (init_socket(&socket_fd, port_str) < 0) {
		fprintf(stderr, "initializing socket failed.\n");
		if (socket_fd >= 0)
			close(socket_fd);
		exit(EXIT_FAILURE);
	}
	// add socket_fd to fd list for polling
	pollfds[RECEIVED_MSG].fd = socket_fd;

	int err                   = 0;
	struct bpf_map *state_map = NULL;
#ifndef DEBUG_USERSPACE_ONLY
	/**************************
	 * setup the eBPF program *
	 **************************/

	/* Load & verify BPF programs */
	err = thesis_bpf__load(obj);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	/* Attach to XDP stage */
	struct bpf_link *link =
			bpf_program__attach_xdp(obj->progs.quick_reply, ifindex);
	if (!link) {
		fprintf(stderr, "Failed to attach eBPF to XDP.\n");
		goto cleanup;
	}
	fprintf(stderr, "Attached eBPF to XDP stage...\n");

	// NOTE(Aurel): filter needs to be loaded to access appropriate memory
	state_map = obj->maps.state;
	/*
	 * NOTE(Aurel): Does not work as the fd is only written to by the user
	 * space. Kernel space directly accesses the memory behind it.
	 * int map_fd = bpf_map__fd(state_map); // get state map fd
	 * pollfds[MAP_UPDATE].fd = socket_fd;  // add to pollfds
	 */

	// NOTE(Aurel): See header for state map keys
	// pass port to eBPF program
	err = bpf_map__update_elem(state_map, &state_keys.port,
	                           sizeof(state_keys.port), &port, sizeof(__u32),
	                           0);
	if (err) {
		fprintf(stderr, "Failed updating map (port). errno: %s\n",
		        strerror(errno));
		goto cleanup;
	}

	// pass speed_limit to eBPF program
	err = bpf_map__update_elem(state_map, &state_keys.speed_limit,
	                           sizeof(state_keys.speed_limit),
	                           &state.speed_limit, sizeof(__u32), 0);
	if (err) {
		fprintf(stderr, "Failed updating map (speed_limit). errno: %s\n",
		        strerror(errno));
		goto cleanup;
	}

	// initialize cars
	err = bpf_map__update_elem(state_map, &state_keys.cars,
	                           sizeof(state_keys.cars), &state.cars,
	                           sizeof(__u32), 0);
	if (err) {
		fprintf(stderr, "Failed updating map (cars). errno: %s\n",
		        strerror(errno));
		goto cleanup;
	}
#endif

	/*******************************************
	 * start listening to incoming connections *
	 *******************************************/
	printf("Server ready for connections:\n");
	char buf[100];
	int rc;
	int pollfds_size = sizeof(pollfds) / sizeof(*pollfds);
	while (!exiting) {
#ifndef DEBUG_EBPF_ONLY
		rc = poll(pollfds, pollfds_size,
		          /* timeout = */ POLL_WAIT_S * 1000);
		if (rc == -1 && errno != EINTR) {
			perror("poll failed");
			continue;
		}

		if (!rc) {
			// timeout

			// recalculate speed limit
			update_speed_limit(&state, state_map);
			continue;
		}

		for (int i = 0; i < pollfds_size; ++i) {
			if (!(pollfds[i].revents & POLLIN)) {
				// fd not ready
				continue;
			}
			switch (i) {
			case RECEIVED_MSG:
				err = handle_request(socket_fd, &state, state_map);
				if (err < 0) {
					printf("Error handling request\n");
					goto cleanup;
				}
				break;
			default:
				printf("Unknown poll: %d\n", i);
				continue;
			}
		}
#else
		pause(); // pause until delivery of a signal
#endif
	}

cleanup:
#ifndef DEBUG_USERSPACE_ONLY
	/* Clean up eBPF program */
	thesis_bpf__destroy(obj);
	fprintf(stderr, "Detached eBPF program.\n");
	return err < 0 ? -err : 0;
#endif

	close(socket_fd);
	return 0;
}
