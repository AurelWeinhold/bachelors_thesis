#!/usr/bin/env bash

# script config
NR_RUNS=100

# client config
IP="192.168.122.43"
PORT="8080"
NR_THREADS=120
NR_PACKETS=10000


ARGS="$IP $PORT $NR_THREADS $NR_PACKETS"

run=$(<run)

workspace_dir="/home/aurel/workspace"
src_dir="${workspace_dir}/bachelor_thesis_source"

mkdir -p "runs/$run"
echo $ARGS > "runs/$run/config.txt"

# TODO(Aurel): Stress
for server in "" "_ebpf" "_userspace"; do
	echo "nvcsw start;nvcsw end;nivcsw start;nivcsw end;nvcsw diff; nivcsw diff" > "runs/${run}/${c}/log${server}.txt"
done

for (( c=1; c<=$NR_RUNS; c++ ))
do
	mkdir -p "runs/$run/$c"
	for server in "" "_ebpf" "_userspace"
	do
		ssh aurel@ba-server sudo "${src_dir}/build/server/thesis${server}" 2 8080 \
			| tee -a "runs/${run}/log${server}.txt" &

		# wait for server to be started up
		sleep 2


		echo "thread id;clock" > "runs/${run}/${c}/log${server}.txt"
		ssh aurel@ba-client "${src_dir}/build/client/client_clock" $ARGS \
			| tee -a "runs/${run}/${c}/log${server}.txt"

		ssh aurel@ba-server sudo kill $(ssh aurel@ba-server pgrep "thesis")
	done
	sleep 2
done

echo $((run + 1)) > nr
