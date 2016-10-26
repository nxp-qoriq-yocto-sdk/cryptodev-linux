#!/bin/bash
#
#    Copyright 2016 NXP Semiconductors
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 2 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.



# no user-configurable options below this line

NUM_CORES=`nproc`
OUT_BASENAME="async_speed"
S_TIME_FORMAT=ISO
MPSTAT_OUT="mpstat_out"

function usage
{
cat << EOF
Usage: `basename $0` [OPTIONS] <alg_name>

  -m <threads>    number of threads to run with (defaults to number of cores)
  -t <secs>       time to run each test (default 10 secs)
  -n <bytes>      size of the test buffer (default 256 bytes)
  -h              show this help

alg_name: null, aes-128-cbc, aes-256-xts, sha1, sha256, crc32c
EOF
}

function SUM {
	paste -sd+ - | bc -l
}

function get_cpu_idle
{
    header_line=`grep %idle ${MPSTAT_OUT} | head -n 1 | sed 's/\s\+/ /g'`
    idle_column=`echo $header_line | wc -w`
    average_idle=`grep Average ${MPSTAT_OUT} | sed 's/\s\+/ /g' | cut -d' ' -f ${idle_column} | tail -n 1`

    echo $average_idle
}

function run_parallel
{
    trap control_c SIGINT

    OPTIONS="-t $tvalue -n $nvalue -m"
    CMD="async_speed $OPTIONS $alg_name"

    echo
    echo "Running $tvalue seconds $mvalue threads in parallel:"
    echo "    $CMD"

    (sleep 1; mpstat 1 $(($tvalue-2))) &> $MPSTAT_OUT &
    MPSTAT_PID=$!

    PIDS=""
    start=`date +%s.%N`

    for i in `seq 0 $(($mvalue-1))`
    do
	CMD_OUT="${OUT_BASENAME}_${i}"

	$CMD &> $CMD_OUT &
	PID=$!
	AFFINITY=$(($i % $NUM_CORES))
	taskset -pc $AFFINITY $PID > /dev/null

	PIDS="$PID $PIDS"
    done

    wait $PIDS
    end=`date +%s.%N`

    wait $MPSTAT_PID

    runtime=$(echo "scale=2; $end - $start" | bc -l )
    total_data=`cat ${OUT_BASENAME}_* | cut -f 1 | SUM`
    avg_speed=$(echo "scale=2; $total_data / $runtime / 1000000000" | bc -l)
    cpu_idle=`get_cpu_idle`

    echo
    echo "buffer size  :   $nvalue"
    echo "running time :   $runtime"
    echo "avg_speed    :   $avg_speed GiB/s"
    echo "all_cpu idle :   $cpu_idle %"
    echo
}

function control_c
{
    killall async_speed > /dev/null
    killall mpstat > /dev/null
}

function main
{
	[ ! -e "/dev/crypto" ] && sudo modprobe cryptodev || modprobe cryptodev || exit 1

	while getopts hm:t:n: option
	do
		case "$option" in
			m) mvalue="$OPTARG";;
			t) tvalue="$OPTARG";;
			n) nvalue="$OPTARG";;
			*) usage $0; exit 1;;
		esac
	done

	shift $((OPTIND-1))
	alg_name=$1

	[ -z "$tvalue" ] && tvalue=10      # 10 seconds per test by default
	[ -z "$mvalue" ] && mvalue=`nproc` # thread count defaults to nproc
	[ -z "$nvalue" ] && nvalue=256     # 256 bytes default buffer size

	[ "$tvalue" -lt 5 ] && tvalue=5

	case "$alg_name" in
	    "null"    |\
	    "aes-128-cbc" |\
	    "aes-256-xts" |\
	    "sha1"    |\
	    "sha256"  |\
	    "crc32c"  ) run_parallel;;
	    * ) usage && exit 1;;
	esac
}

main "$@"

