#!/usr/bin/env bash

NR_RUNS=10000

# client config
IP="192.168.122.43"
PORT="8080"
NR_THREADS=10000
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
fi

i=0
for (( r=0; r<=$NR_RUNS; r++ ))
do
        for (( c=120; c<=$NR_THREADS; c++ ))
        do
                for client in "clock"; do #"wall" "both"; do
                        timeout 30s \
                                ./build/client/client_$client "run_${run}/${server}_${client}" $ARGS $c $NR_PACKETS $i > /dev/null
                        if [[ "${PIPESTATUS[0]}" -eq "0" ]]; then
                                i=$((i+NR_THREADS))
                                sleep 5
                                continue
                        fi
                        echo $((c -1)) | tee -a "run_${run}/${server}_threads.txt"
                        break 2
                done
        done
done
echo "done"
