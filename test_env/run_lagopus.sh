#!/bin/bash

set -x

LAGO_DIR=${HOME}/lagopus/
LAGO_CMD=${LAGO_DIR}/src/cmds/lagopus

COREMASK=1-7
# COREMASK=20-31
# MEMORY=16384,16384
CONF_FILE=/tmp/lagopus.dsl
LOG_FILE=/dev/stderr

#
# +---------+---------+-----------------+--------+------------------+-------+----------+
# |         |         |                 |        |                  |       |          |
# | +-------+---------+------+  +-------+--------+-------+  +-------+-------+--------+ |
# | |                        |  |                        |  |                        | |
# | | of-bridge01            |  | of-bridge02            |  | of-bridge03            | |
# | | Role: SLG1             |  | Role: SLG2             |  | Role: SLG3             | |
# | | dpid: 0x01             |  | dpid: 0x02             |  | dpid: 0x03             | |
# | | port:                  |  | port:                  |  | port:                  | |
# | |   1: vhost,/tmp/sock11 |  |   1: vhost,/tmp/sock21 |  |   1: vhost,/tmp/sock31 | |
# | |   2: vhost,/tmp/sock12 |  |   2: vhost,/tmp/sock22 |  |   2: vhost,/tmp/sock32 | |
# | |                        |  |                        |  |                        | |
# | +------------------------+  +------------------------+  +------------------------+ |
# |                                                                                    |
# +------------------------------------------------------------------------------------+
#   Lagopus Switch
#
  
# create lagopus.dsl

cat << EOF > ${CONF_FILE}
channel channel01 create -dst-addr 127.0.0.1 -protocol tcp
controller controller01 create -channel channel01 -role equal -connection-type main
channel channel02 create -dst-addr 127.0.0.1 -protocol tcp
controller controller02 create -channel channel02 -role equal -connection-type main
channel channel03 create -dst-addr 127.0.0.1 -protocol tcp
controller controller03 create -channel channel03 -role equal -connection-type main

interface interface11 create -type ethernet-dpdk-phy -device eth_vhost11,iface=/tmp/sock11
interface interface12 create -type ethernet-dpdk-phy -device eth_vhost12,iface=/tmp/sock12
interface interface21 create -type ethernet-dpdk-phy -device eth_vhost21,iface=/tmp/sock21
interface interface22 create -type ethernet-dpdk-phy -device eth_vhost22,iface=/tmp/sock22
interface interface31 create -type ethernet-dpdk-phy -device eth_vhost31,iface=/tmp/sock31
interface interface32 create -type ethernet-dpdk-phy -device eth_vhost32,iface=/tmp/sock32

port port11 create -interface interface11
port port12 create -interface interface12
port port21 create -interface interface21
port port22 create -interface interface22
port port31 create -interface interface31
port port32 create -interface interface32

bridge of-bridge01 create -controller controller01 -port port11 1 -port port12 2 -dpid 0x1
bridge of-bridge01 enable
bridge of-bridge02 create -controller controller02 -port port21 1 -port port22 2 -dpid 0x2
bridge of-bridge02 enable
bridge of-bridge03 create -controller controller03 -port port31 1 -port port32 2 -dpid 0x3
bridge of-bridge03 enable

EOF

sudo rm /tmp/sock*
# sudo ${LAGO_CMD} -d -C ${CONF_FILE} -l ${LOG_FILE} -- -l ${COREMASK} --socket-mem ${MEMORY}  -n 4 --
sudo ${LAGO_CMD} -d -C ${CONF_FILE} -l ${LOG_FILE} -- -l ${COREMASK} -n 4 --
