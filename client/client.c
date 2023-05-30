/*
 * NOTE(Aurel): Inspired by [beej's guide to networking in
 * C](https://beej.us/guide/bgnet/)
 */

#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

// timing
#include <time.h>

#include "prot.h"

#define MAX_HOSTNAME_LEN 30
#define MAX_PORT_LEN     5
#define MAX_DATA_SIZE    100

#define MEASURE_CLOCK_TIME
#define MEASURE_WALL_TIME

// get sockaddr, IPv4 or IPv6:
void *
get_in_addr(struct sockaddr *sa)
{
	if (sa->sa_family == AF_INET) {
		return &(((struct sockaddr_in *)sa)->sin_addr);
	}
	return &(((struct sockaddr_in6 *)sa)->sin6_addr);
}

struct prot
create_prot(enum protocol_op op, int value)
{
	struct prot prot = {
		.op    = op,
		.value = value,
	};
	return prot;
}

void
print_prot(struct prot prot)
{
	printf("op: %d\n", prot.op);
	printf("value: %d\n", prot.value);
}

int
send_prot(int socket_fd, struct prot prot, struct addrinfo *p)
{
	char buf[PROT_PACKET_SIZE];
	memcpy(buf + PROT_OP_OFFSET, &prot.op, 4);
	memcpy(buf + PROT_VALUE_OFFSET, &prot.value, 4);

	int numbytes = 0;
	if ((numbytes = sendto(socket_fd, buf, PROT_PACKET_SIZE, 0, p->ai_addr,
	                       p->ai_addrlen)) == -1) {
		perror("sendto");
		return -1;
	}

	return 0;
}

struct prot
receive_prot(int socket_fd, struct addrinfo *p)
{
	char buf[MAX_DATA_SIZE];
	size_t nr_bytes_recv = 0;

	if ((nr_bytes_recv = recvfrom(socket_fd, buf, 100 - 1, 0, p->ai_addr,
	                              &p->ai_addrlen)) == -1) {
		perror("recvfrom");
		exit(1);
	}

	if (nr_bytes_recv != PROT_PACKET_SIZE) {
		printf("error receiving: received %zu bytes\n", nr_bytes_recv);
		return (struct prot){ .op = -1, .value = -1 };
	}

	// parse packet
	struct prot packet;
	memcpy(&packet.op, buf + PROT_OP_OFFSET, sizeof(packet.op));
	memcpy(&packet.value, buf + PROT_VALUE_OFFSET, sizeof(packet.value));

	return packet;
}

int
main(int argc, char *argv[])
{
	int car_nr = 0;
	if (argc == 2)
		car_nr = atoi(argv[1]);

	int sockfd;
	struct addrinfo hints, *servinfo, *p;
	int rv;
	char *hostname = "localhost", *port = "8080";

	memset(&hints, 0, sizeof hints);
	hints.ai_family   = AF_INET; // IPv4
	hints.ai_socktype = SOCK_DGRAM;

	if ((rv = getaddrinfo(hostname, port, &hints, &servinfo)) != 0) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
		return 1;
	}

	// loop through all the results and make a socket
	for (p = servinfo; p != NULL; p = p->ai_next) {
		if ((sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) ==
		    -1) {
			perror("socket");
			continue;
		}
		break;
	}

	if (p == NULL) {
		fprintf(stderr, "failed to create socket\n");
		return 2;
	}
	freeaddrinfo(servinfo);

	// operation

	printf("%d: in range\n", car_nr);
	struct prot request = create_prot(PROT_OP_GET_SPEED_LIMIT, 0);
#ifdef MEASURE_CLOCK_TIME
	clock_t c_start = clock();
#endif
#ifdef MEASURE_WALL_TIME
	time_t t_start = time(NULL);
#endif

	int err = send_prot(sockfd, request, p);
	if (err < 0) {
		return 1;
		printf("Error sending packet\n");
	}
	struct prot reply = receive_prot(sockfd, p);
#ifdef MEASURE_CLOCK_TIME
	clock_t c_end = clock();
	double c_d    = (double)(c_end - c_start) / CLOCKS_PER_SEC;
	printf("%f\n", c_d);
#endif
#ifdef MEASURE_WALL_TIME
	time_t t_end = time(NULL);
	double t_d   = t_end - t_start;
	printf("%f\n", t_d);
#endif
#if defined(MEASURE_CLOCK_TIME) || defined(MEASURE_WALL_TIME)
	exit(0);
#endif
	printf("%d: speed limit: %d\n", car_nr, reply.value);
	int w = 2.0 * 60 * 60 / reply.value;
	printf("%d: sleeping %ds\n", car_nr, w);
	sleep(10);

	request = create_prot(PROT_OP_OUT_OF_RANGE, 0);
	err     = send_prot(sockfd, request, p);
	if (err < 0) {
		return 1;
		printf("Error sending packet\n");
	}

	// done
	printf("%d: out of range\n", car_nr);

	close(sockfd);
	return 0;
}
