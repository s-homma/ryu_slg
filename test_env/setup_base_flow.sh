#!/bin/bash

FLOW_FILE="/tmp/flow"

cat << EOF > ${FLOW_FILE}
table 0
{"table_id":0,"priority":1,"packet_count":0,"cookie":0,"actions":["OUTPUT:2"],"match":{"in_port":1}}
{"table_id":0,"priority":1,"packet_count":0,"cookie":0,"actions":["OUTPUT:1"],"match":{"in_port":2}}
EOF

no_proxy=* ../ofctl_script/add_flow -d 1 < ${FLOW_FILE}
no_proxy=* ../ofctl_script/add_flow -d 2 < ${FLOW_FILE}
no_proxy=* ../ofctl_script/add_flow -d 3 < ${FLOW_FILE}

echo "======== SLG1 ========="
no_proxy=* ../ofctl_script/show_flow -d 1
echo "======== SLG2 ========="
no_proxy=* ../ofctl_script/show_flow -d 2
echo "======== SLG3 ========="
no_proxy=* ../ofctl_script/show_flow -d 3

