#!/bin/bash

LOCAL_RT_NAME="vm1"
LOCAL_RT_ADDRESS="192.168.42.253/24"
LOCAL_RT_LLADDRESS="52:54:00:01:00:01"
LOCAL_RT_NETWORK="192.168.42.0/24"
MEC_NAME="vm2"
MEC_ADDRESS="192.168.1.50/24"
MEC_LLADDRESS="52:54:00:02:00:01"
MEC_NETWORK="192.168.1.0/24"
CDC_NAME="vm3"
CDC_ADDRESS="192.168.3.50/24"
CDC_LLADDRESS="52:54:00:03:00:01"
CDC_NETWORK="192.168.3.0/24"
RT_NAME="vm4"
RT_ADDRESS1="172.16.1.254/24"
RT_LLADDRESS1="52:54:00:00:01:01"
RT_ADDRESS2="172.16.2.254/24"
RT_LLADDRESS2="52:54:00:00:01:02"
RT_ADDRESS3="172.16.3.254/24"
RT_LLADDRESS3="52:54:00:00:01:03"

SLG1_DL_ADDRESS="192.168.42.254"
SLG1_DL_LLADDRESS="52:54:00:01:01:01"
SLG1_UL_ADDRESS="172.16.1.1"
SLG1_UL_LLADDRESS="52:54:00:00:00:01"
SLG2_DL_ADDRESS="192.168.1.254"
SLG2_DL_LLADDRESS="52:54:00:02:01:01"
SLG2_UL_ADDRESS="172.16.2.1"
SLG2_UL_LLADDRESS="52:54:00:00:00:02"
SLG3_DL_ADDRESS="192.168.3.254"
SLG3_DL_LLADDRESS="52:54:00:03:01:01"
SLG3_UL_ADDRESS="172.16.3.1"
SLG3_UL_LLADDRESS="52:54:00:00:00:03"

echo "=========== ${RT_NAME} ============"
uvt-kvm ssh ${RT_NAME} "sudo ip addr flush dev ens4"
uvt-kvm ssh ${RT_NAME} "sudo ip addr flush dev ens5"
uvt-kvm ssh ${RT_NAME} "sudo ip addr flush dev ens6"
uvt-kvm ssh ${RT_NAME} "sudo ip addr add ${RT_ADDRESS1} dev ens4"
uvt-kvm ssh ${RT_NAME} "sudo ip neigh add ${SLG1_UL_ADDRESS} dev ens4 lladdr ${SLG1_UL_LLADDRESS}"
uvt-kvm ssh ${RT_NAME} "sudo ip link set up  dev ens4"
uvt-kvm ssh ${RT_NAME} "sudo ip addr add ${RT_ADDRESS2} dev ens5"
uvt-kvm ssh ${RT_NAME} "sudo ip neigh add ${SLG2_UL_ADDRESS} dev ens5 lladdr ${SLG2_UL_LLADDRESS}"
uvt-kvm ssh ${RT_NAME} "sudo ip link set up  dev ens5"
uvt-kvm ssh ${RT_NAME} "sudo ip addr add ${RT_ADDRESS3} dev ens6"
uvt-kvm ssh ${RT_NAME} "sudo ip neigh add ${SLG3_UL_ADDRESS} dev ens6 lladdr ${SLG3_UL_LLADDRESS}"
uvt-kvm ssh ${RT_NAME} "sudo ip link set up  dev ens6"
uvt-kvm ssh ${RT_NAME} "sudo ip addr"
uvt-kvm ssh ${RT_NAME} "sudo ip route"
uvt-kvm ssh ${RT_NAME} "sudo tc qdisc add dev ens6 root netem delay 100ms"
uvt-kvm ssh ${RT_NAME} "echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward"
echo ""

echo "=========== ${LOCAL_RT_NAME} ============"
uvt-kvm ssh ${LOCAL_RT_NAME} "sudo ip addr flush dev ens4"
uvt-kvm ssh ${LOCAL_RT_NAME} "sudo ip addr add ${LOCAL_RT_ADDRESS} dev ens4"
uvt-kvm ssh ${LOCAL_RT_NAME} "sudo ip link set up dev ens4"
uvt-kvm ssh ${LOCAL_RT_NAME} "sudo ip route add ${MEC_NETWORK} via ${SLG1_DL_ADDRESS} dev ens4"
uvt-kvm ssh ${LOCAL_RT_NAME} "sudo ip route add ${CDC_NETWORK} via ${SLG1_DL_ADDRESS} dev ens4"
uvt-kvm ssh ${LOCAL_RT_NAME} "sudo ip neigh flush dev ens4"
uvt-kvm ssh ${LOCAL_RT_NAME} "sudo ip neigh add ${SLG1_DL_ADDRESS} dev ens4 lladdr ${SLG1_DL_LLADDRESS}"
uvt-kvm ssh ${LOCAL_RT_NAME} "sudo ip addr"
uvt-kvm ssh ${LOCAL_RT_NAME} "sudo ip route"
echo ""


echo "=========== ${MEC_NAME} ============"
uvt-kvm ssh ${MEC_NAME} "sudo ip addr flush dev ens4"
uvt-kvm ssh ${MEC_NAME} "sudo ip addr add ${MEC_ADDRESS} dev ens4"
uvt-kvm ssh ${MEC_NAME} "sudo ip addr add ${CDC_ADDRESS} dev ens4"
uvt-kvm ssh ${MEC_NAME} "sudo ip link set up dev ens4"
uvt-kvm ssh ${MEC_NAME} "sudo ip route add ${LOCAL_RT_NETWORK} via ${SLG2_DL_ADDRESS} dev ens4"
# uvt-kvm ssh ${MEC_NAME} "sudo ip route add ${CDC_NETWORK} via ${SLG2_DL_ADDRESS} dev ens4"
uvt-kvm ssh ${MEC_NAME} "sudo ip neigh flush dev ens4"
uvt-kvm ssh ${MEC_NAME} "sudo ip neigh add ${SLG2_DL_ADDRESS} dev ens4 lladdr ${SLG2_DL_LLADDRESS}"
uvt-kvm ssh ${MEC_NAME} "sudo ip addr"
uvt-kvm ssh ${MEC_NAME} "sudo ip route"
echo ""

echo "=========== ${CDC_NAME} ============"
uvt-kvm ssh ${CDC_NAME} "sudo ip addr flush dev ens4"
uvt-kvm ssh ${CDC_NAME} "sudo ip addr add ${MEC_ADDRESS} dev ens4"
uvt-kvm ssh ${CDC_NAME} "sudo ip addr add ${CDC_ADDRESS} dev ens4"
uvt-kvm ssh ${CDC_NAME} "sudo ip link set up dev ens4"
uvt-kvm ssh ${CDC_NAME} "sudo ip route add ${LOCAL_RT_NETWORK} via ${SLG3_DL_ADDRESS} dev ens4"
# uvt-kvm ssh ${CDC_NAME} "sudo ip route add ${MEC_NETWORK} via ${SLG3_DL_ADDRESS} dev ens4"
uvt-kvm ssh ${CDC_NAME} "sudo ip neigh flush dev ens4"
uvt-kvm ssh ${CDC_NAME} "sudo ip neigh add ${SLG3_DL_ADDRESS} dev ens4 lladdr ${SLG3_DL_LLADDRESS}"
uvt-kvm ssh ${CDC_NAME} "sudo ip addr"
uvt-kvm ssh ${CDC_NAME} "sudo ip route"
echo ""

