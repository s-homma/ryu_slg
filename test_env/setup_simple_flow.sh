#!/bin/bash

FLOW_FILE="/tmp/flow"

echo "====== SLG1 ======"

cat << EOF > ${FLOW_FILE}
table 0
{"table_id":0,"priority":10,"packet_count":0,"cookie":0,"actions":["ENCAP: {packet_type:VxLAN}","SET_FIELD: {vxlan_vni:4}","ENCAP: {packet_type:UDP}","SET_FIELD: {udp_src:5432}","SET_FIELD: {udp_dst:4789}","ENCAP: {packet_type:IPv4}","SET_FIELD: {ipv4_src:172.16.1.1}","SET_FIELD: {ipv4_dst:172.16.2.1}","SET_NW_TTL:64","ENCAP: {packet_type:ETHER}","SET_FIELD: {eth_src:52:54:00:00:00:01}","SET_FIELD: {eth_dst:52:54:00:00:01:01}","OUTPUT:2"],"match":{"in_port":1,"dl_type":2048, "ipv4_dst":"192.168.1.0/255.255.255.0"}}
{"table_id":0,"priority":10,"packet_count":0,"cookie":0,"actions":["ENCAP: {packet_type:VxLAN}","SET_FIELD: {vxlan_vni:4}","ENCAP: {packet_type:UDP}","SET_FIELD: {udp_src:5432}","SET_FIELD: {udp_dst:4789}","ENCAP: {packet_type:IPv4}","SET_FIELD: {ipv4_src:172.16.1.1}","SET_FIELD: {ipv4_dst:172.16.3.1}","SET_NW_TTL:64","ENCAP: {packet_type:ETHER}","SET_FIELD: {eth_src:52:54:00:00:00:01}","SET_FIELD: {eth_dst:52:54:00:00:01:01}","OUTPUT:2"],"match":{"in_port":1,"dl_type":2048, "ipv4_dst":"192.168.3.0/255.255.255.0"}}
{"table_id":0,"priority":10,"packet_count":0,"cookie":0,"actions":["DECAP: {cur_pkt_type:ETHER, new_pkt_type:IPv4}","DECAP: {cur_pkt_type:IPv4, new_pkt_type:UDP}","DECAP: {cur_pkt_type:UDP, new_pkt_type:VxLAN}","DECAP: {cur_pkt_type:VxLAN, new_pkt_type:NEXT}","SET_FIELD: {eth_dst:52:54:00:01:00:01}","OUTPUT:1"],"match":{"in_port":2,"dl_type":2048,"nw_proto":17,"tp_dst":4789}}
EOF

no_proxy=* ../ofctl_script/add_flow -d 1 < ${FLOW_FILE}
no_proxy=* ../ofctl_script/show_flow -d 1

echo "====== SLG2 ======"

cat << EOF > ${FLOW_FILE}
table 0
{"table_id":0,"priority":10,"packet_count":0,"cookie":0,"actions":["ENCAP: {packet_type:VxLAN}","SET_FIELD: {vxlan_vni:4}","ENCAP: {packet_type:UDP}","SET_FIELD: {udp_src:5432}","SET_FIELD: {udp_dst:4789}","ENCAP: {packet_type:IPv4}","SET_FIELD: {ipv4_src:172.16.2.1}","SET_FIELD: {ipv4_dst:172.16.1.1}","SET_NW_TTL:64","ENCAP: {packet_type:ETHER}","SET_FIELD: {eth_src:52:54:00:00:00:02}","SET_FIELD: {eth_dst:52:54:00:00:01:02}","OUTPUT:2"],"match":{"in_port":1,"dl_type":2048, "ipv4_dst":"192.168.42.0/255.255.255.0"}}
{"table_id":0,"priority":10,"packet_count":0,"cookie":0,"actions":["ENCAP: {packet_type:VxLAN}","SET_FIELD: {vxlan_vni:4}","ENCAP: {packet_type:UDP}","SET_FIELD: {udp_src:5432}","SET_FIELD: {udp_dst:4789}","ENCAP: {packet_type:IPv4}","SET_FIELD: {ipv4_src:172.16.2.1}","SET_FIELD: {ipv4_dst:172.16.3.1}","SET_NW_TTL:64","ENCAP: {packet_type:ETHER}","SET_FIELD: {eth_src:52:54:00:00:00:02}","SET_FIELD: {eth_dst:52:54:00:00:01:02}","OUTPUT:2"],"match":{"in_port":1,"dl_type":2048, "ipv4_dst":"192.168.3.0/255.255.255.0"}}
{"table_id":0,"priority":10,"packet_count":0,"cookie":0,"actions":["DECAP: {cur_pkt_type:ETHER, new_pkt_type:IPv4}","DECAP: {cur_pkt_type:IPv4, new_pkt_type:UDP}","DECAP: {cur_pkt_type:UDP, new_pkt_type:VxLAN}","DECAP: {cur_pkt_type:VxLAN, new_pkt_type:NEXT}","SET_FIELD: {eth_dst:52:54:00:02:00:01}","OUTPUT:1"],"match":{"in_port":2,"dl_type":2048,"nw_proto":17,"tp_dst":4789}}
EOF

no_proxy=* ../ofctl_script/add_flow -d 2 < ${FLOW_FILE}
no_proxy=* ../ofctl_script/show_flow -d 2


echo "====== SLG3 ======"

cat << EOF > ${FLOW_FILE}
table 0
{"table_id":0,"priority":10,"packet_count":0,"cookie":0,"actions":["ENCAP: {packet_type:VxLAN}","SET_FIELD: {vxlan_vni:4}","ENCAP: {packet_type:UDP}","SET_FIELD: {udp_src:5432}","SET_FIELD: {udp_dst:4789}","ENCAP: {packet_type:IPv4}","SET_FIELD: {ipv4_src:172.16.3.1}","SET_FIELD: {ipv4_dst:172.16.1.1}","SET_NW_TTL:64","ENCAP: {packet_type:ETHER}","SET_FIELD: {eth_src:52:54:00:00:00:03}","SET_FIELD: {eth_dst:52:54:00:00:01:03}","OUTPUT:2"],"match":{"in_port":1,"dl_type":2048, "ipv4_dst":"192.168.42.0/255.255.255.0"}}
{"table_id":0,"priority":10,"packet_count":0,"cookie":0,"actions":["ENCAP: {packet_type:VxLAN}","SET_FIELD: {vxlan_vni:4}","ENCAP: {packet_type:UDP}","SET_FIELD: {udp_src:5432}","SET_FIELD: {udp_dst:4789}","ENCAP: {packet_type:IPv4}","SET_FIELD: {ipv4_src:172.16.3.1}","SET_FIELD: {ipv4_dst:172.16.2.1}","SET_NW_TTL:64","ENCAP: {packet_type:ETHER}","SET_FIELD: {eth_src:52:54:00:00:00:03}","SET_FIELD: {eth_dst:52:54:00:00:01:03}","OUTPUT:2"],"match":{"in_port":1,"dl_type":2048, "ipv4_dst":"192.168.1.0/255.255.255.0"}}
{"table_id":0,"priority":10,"packet_count":0,"cookie":0,"actions":["DECAP: {cur_pkt_type:ETHER, new_pkt_type:IPv4}","DECAP: {cur_pkt_type:IPv4, new_pkt_type:UDP}","DECAP: {cur_pkt_type:UDP, new_pkt_type:VxLAN}","DECAP: {cur_pkt_type:VxLAN, new_pkt_type:NEXT}","SET_FIELD: {eth_dst:52:54:00:03:00:01}","OUTPUT:1"],"match":{"in_port":2,"dl_type":2048,"nw_proto":17,"tp_dst":4789}}
EOF

no_proxy=* ../ofctl_script/add_flow -d 3 < ${FLOW_FILE}
no_proxy=* ../ofctl_script/show_flow -d 3

