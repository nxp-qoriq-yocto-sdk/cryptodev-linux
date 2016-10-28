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

NUM_CORES=$(nproc)
CMD_BIN="async_speed"
OUT_BASENAME="async_speed"
MPSTAT_OUT="mpstat_out"

# A bigger hammer for mpstat to use ISO8601 time format (fixed in 11.2.2)
export LC_TIME=en_GB.UTF-8 &> /dev/null


function usage
{
cat << EOF
Usage: `basename $0` [OPTIONS] <alg_name>

  -m <threads>    number of threads to run with (defaults to number of cores)
  -t <secs>       time to run each test (default 10 secs)
  -n <bytes>      size of the test buffer (default 256 bytes)
  -v              make output more verbose (default tabular)
  -h              show this help

alg_name: null, aes-128-cbc, aes-256-xts, sha1, sha256, crc32c
EOF
}

function SUM {
	paste -sd+ - | bc -l
}

function get_cpu_idle
{
    header_line=$(grep %idle ${MPSTAT_OUT} | head -n 1 | sed 's/\s\+/ /g')
    idle_column=$(echo $header_line | wc -w)
    average_idle=$(grep Average ${MPSTAT_OUT} | sed 's/\s\+/ /g' | cut -d' ' -f ${idle_column} | tail -n 1)

    echo $average_idle
}

function run_parallel
{
    trap control_c SIGINT

    OPTIONS="-t $tvalue -n $nvalue -m"
    CMD="$CMD_BIN $OPTIONS $alg_name"

    (sleep 1; S_TIME_FORMAT=ISO mpstat 1 $(($tvalue-2))) &> $MPSTAT_OUT &
    MPSTAT_PID=$!

    PIDS=""
    start=$(date +%s.%N)

    for i in $(seq 0 $(($mvalue-1)))
    do
	CMD_OUT="${OUT_BASENAME}_${i}"

	$CMD &> $CMD_OUT &
	PID=$!
	AFFINITY=$(($i % $NUM_CORES))
	taskset -pc $AFFINITY $PID > /dev/null

	PIDS="$PID $PIDS"
    done

    wait $PIDS
    end=$(date +%s.%N)

    wait $MPSTAT_PID

    grep "ioctl" ${OUT_BASENAME}_* &> /dev/null
    if (($? == 0))
    then
	echo "cryptodev is not built with -DENABLE_ASYNC flag"
	exit 1
    fi

    runtime=$(echo "scale=2; ($end - $start) / 1" | bc -l )
    total_data=$(cat ${OUT_BASENAME}_* | cut -f 1 | SUM)
    avg_speed=$(echo "scale=2; $total_data / $runtime / 1000000000" | bc -l)
    cpu_idle=$(get_cpu_idle)

    if [ ! -z "$vvalue" ]
    then
	echo
	echo "buffer size  :   $nvalue"
	echo "running time :   $runtime"
	echo "avg_speed    :   $avg_speed GB/s"
	echo "all_cpu idle :   $cpu_idle %"
	echo
    else
	echo -e "algorithm\t""threads\t""run time\t"\
	     "buffer size\t""GB/s\t""%cpu idle"
	echo -e "${alg_name}\t${mvalue}\t${runtime}\t"\
	     "${nvalue}\t${avg_speed}\t${cpu_idle}"
    fi
}

function control_c
{
    killall async_speed > /dev/null
    killall mpstat > /dev/null
}

function main
{
	[ ! -e "/dev/crypto" ] &&
		(sudo modprobe cryptodev || modprobe cryptodev || exit 1)

	$(which ${CMD_BIN} &> /dev/null)
	if (($? != 0))
	then
		echo "${CMD_BIN} test is not installed"
		exit 1
	fi

	rm -f ${OUT_BASENAME}_*
	rm -f ${MPSTAT_OUT}

	while getopts vhm:t:n: option
	do
		case "$option" in
			m) mvalue="$OPTARG";;
			t) tvalue="$OPTARG";;
			n) nvalue="$OPTARG";;
			v) vvalue="verbose";;
			*) usage $0; exit 1;;
		esac
	done

	shift $((OPTIND-1))
	alg_name=$1

	[ -z "$tvalue" ] && tvalue=10         # 10 seconds per test by default
	[ -z "$mvalue" ] && mvalue=$NUM_CORES # thread count defaults to nproc
	[ -z "$nvalue" ] && nvalue=256        # 256 bytes default buffer size

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

