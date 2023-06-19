#!/usr/bin/env bash

# script config
NR_RUNS=1

# client config
IP="192.168.178.30"
PORT="8080"
NR_THREADS=64
NR_PACKETS=100


ARGS="$IP $PORT $NR_THREADS $NR_PACKETS"

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
fi
#echo "$server"

#printf "clock\n" > "${server}_clock.csv"
#printf "wall\n" > "${server}_wall.csv"
#printf "clock;wall\n" > ../"${server}_both.csv"
i=0
for (( c=1; c<=$NR_RUNS; c++ ))
do
	for client in "clock"; do #"wall" "both"; do
		./build/client/client_$client "run_${run}/${server}_${client}" $ARGS $i | \
			tee run_$run/$server.txt
		#echo "done $client"
		i=$((i+NR_THREADS))
	done
	#echo $c
done
