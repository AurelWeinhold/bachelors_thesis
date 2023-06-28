#!/usr/bin/env bash

NR_RUNS=10000

# client config
IP="192.168.122.43"
PORT="8080"
NR_THREADS_START=100
NR_THREADS=100000
NR_PACKETS=1000


ARGS="$IP $PORT"

run=$(<nr)

mkdir -p build
cd build
cmake ../../..
make || exit 1
cd ..

mkdir "run_$run"
echo $ARGS > "run_$run/config.txt"

server="thesis"
if [[ $# -gt 0 ]]; then
        server="thesis_$1"
	if [[ "$1" == "ebpf" ]]; then
		NR_THREADS_START=240
	elif [[ "$1" == "userspace" ]]; then
		NR_THREADS_START=120
	fi

fi
client="clock"

i=0
for (( r=0; r<=$NR_RUNS; r++ ))
do
	time for (( c=NR_THREADS_START; c<=$NR_THREADS; c++ ))
	do
		timeout 15s \
			./build/client/client_$client "run_${run}/${server}_${client}" $ARGS $c $NR_PACKETS $i > /dev/null

		if [[ "${PIPESTATUS[0]}" -eq "0" ]];
		then
			i=$((i+NR_THREADS))
			sleep 1
			continue
		fi
		echo $((c -1)) | tee -a "run_${run}/${server}_threads.txt"
		break 1
	done
done
echo "done"
