#!/bin/bash


DEV=$1
BPFOBJ=$2
SEC=$3
tc qdisc del dev $DEV clsact
tc qdisc add dev $DEV clsact
tc filter add dev $DEV ingress prio 1 handle 1 bpf da obj $BPFOBJ sec $SEC
tc filter show dev $DEV ingress
