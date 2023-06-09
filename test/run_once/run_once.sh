#!/usr/bin/env bash

IP="192.168.178.66"
PORT="8080"
NR_THREADS=1
NR_PACKETS=1000
ARGS="$IP $PORT $NR_THREADS $NR_PACKETS"

mkdir -p build
cd build
cmake ../../..
make || exit 1

for server in "thesis" "thesis_ebpf" "thesis_userspace"; do
	printf "clock\n" > ../"${server}_clock.csv"
	printf "wall\n" > ../"${server}_wall.csv"
	printf "clock;wall\n" > ../"${server}_both.csv"
	sudo ./server/$server 1 8080 &
	sleep 3
	./client/client_clock $ARGS >> ../"${server}_clock.csv"
	./client/client_wall  $ARGS >> ../"${server}_wall.csv"
	./client/client_both  $ARGS >> ../"${server}_both.csv"
	sudo pkill thesis
done
