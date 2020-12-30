#!/bin/bash

ip netns del bpf_ns1
ip link del dev bpf_veth0
ip link del dev bpf_veth1
ip link add bpf_veth0 type veth peer name bpf_veth1
ip netns add bpf_ns1
ip link set bpf_veth1 netns bpf_ns1
ip netns exec bpf_ns1 ip addr add 172.18.1.10/24 dev bpf_veth1
ip addr add 172.18.1.11/24 dev bpf_veth0
ip netns exec bpf_ns1 ip link set bpf_veth1 up
ip link set bpf_veth0 up
ip netns exec bpf_ns1 ip route add 0.0.0.0/0 via 172.18.1.11 dev bpf_veth1
ping -c 5 172.18.1.10