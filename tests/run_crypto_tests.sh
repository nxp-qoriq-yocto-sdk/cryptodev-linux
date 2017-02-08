#!/bin/bash


BUF_SIZE="8192 16384 65536 131072 262144"
THREAD_CNT="1 8 12"
ALG_NAMES="aes-128-cbc aes-256-xts sha1 sha256 crc32c"
TIME=10

############################

function usage
{
cat << EOF
Usage: `basename $0` [OPTIONS]

  -a              run async version of the benchmark (default sync)
  -h              show this help

Run in sequence benchmarks for several crypto algorithms:
$ALG_NAMES
EOF
}

while getopts ah option
do
    case "$option" in
	a) aflag="-a";;
	*) usage $0; exit 1;;
    esac
done


#restool dpseci create --num-queues=8 --priorities=1,2,3,4,5,6,7,8
#restool dprc assign dprc.1 --object=dpseci.0 --plugged=1


#grep DPIO /proc/interrupts
for alg_name in ${ALG_NAMES}
do
	for multi in ${THREAD_CNT}
	do
		for bsize in ${BUF_SIZE}
		do
			speed_multi.sh -t ${TIME}\
				-n ${bsize}\
				-m ${multi}\
				${aflag}\
				${alg_name} |
			tail -n 1
		done
	done
done

#grep DPIO /proc/interrupts