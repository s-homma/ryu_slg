# Copyright (C) 2019 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import logging
import json

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto.ether import ETH_TYPE_IP
from ryu.lib.ofctl_v1_3 import mod_flow_entry



#####################################################################################################################
#
#  +------------------------+  +------------------------+  +------------------------+    +---------------------+
#  |                        |  |                        |  |                        |    |                     |
#  | VM1                    |  | VM2                    |  | VM3                    |    | VM4                 |
#  | Role: Local Router     |  | Role: MEC              |  | Role: Central DC       |    | Role: Router        |
#  | MAC: 52:54:00:01:00:01 |  | MAC: 52:54:00:02:00:01 |  | MAC: 52:54:00:03:00:01 |    | SLG01-if:           |
#  | IP:  192.168.42.253    |  | IP:  192.168.1.50      |  | IP:  192.168.3.50      |    |   172.16.1.254      |
#  |                        |  |                        |  |                        |    |   52:54:00:00:01:01 |
#  +-------+----------------+  +-------+----------------+  +-------+----------------+    | SLG02-if:           |
#          |                           |                           |                     |   172.16.2.254      |
#          |         +-------------------------------------------------------------------+   52:54:00:00:01:02 |
#          |         |                 |                           |                     | SLG03-if:           |
#          |         |                 |        +----------------------------------------+   172.16.3.254      |
#          |         |                 |        |                  |                     |   52:54:00:00:01:03 |
#          |         |                 |        |                  |       +-------------+                     |
#          |         |                 |        |                  |       |             +---------------------+
#          |         |                 |        |                  |       |
#+------------------------------------------------------------------------------------+
#|         |         |                 |        |                  |       |          |
#| +-------+---------+------+  +-------+--------+-------+  +-------+-------+--------+ |
#| |                        |  |                        |  |                        | |
#| | OF-Bridge01            |  | OF-Bridge02            |  | OF-Bridge03            | |
#| | Role: SLG1             |  | Role: SLG2             |  | Role: SLG3             | |
#| | Downlink:              |  | Downlink:              |  | Downlink:              | |
#| |   192.168.42.254       |  |   192.168.1.254        |  |   192.168.3.254        | |
#| |   52:54:00:01:01:01    |  |   52:54:00:02:01:01    |  |   52:54:00:03:01:01    | |
#| | Uplink:                |  | Uplink:                |  | Uplink:                | |
#| |   172.16.1.1           |  |   172.16.2.1           |  |   172.16.3.1           | |
#| |   52:54:00:00:00:01    |  |   52:54:00:00:00:02    |  |   52:54:00:00:00:03    | |
#| |                        |  |                        |  |                        | |
#| +------------------------+  +------------------------+  +------------------------+ |
#|                                                                                    |
#+------------------------------------------------------------------------------------+
#
# * Table Design:
#
# table 0: ARP, icmp, decap
# table 1: Routing
# table 11: rewrite mac address and output to downlink
# table 12: output to uplink
# table 100: encap vni 5000, output to uplink
# table 101: encap vni 5010, output to uplink
# table 102: encap vni 5020, output to uplink
# table 103: encap vni 5030, output to uplink
# table 104: encap vni 5040, output to uplink
#
####################################################################################################################

class interface(dict):

    def __init__(self, index, ip_address, mac_address):
        self.index = index
        self.ip_address = ip_address
        self.mac_address = mac_address
        self.gateway = None
        return

    def __repl__(self):
        return str({"index": self.index, "ip_address": self.ip_address, "mac_address": self.mac_address})

class SliceGateway(dict):

    def __init__(self):
        self.interface = {}
        return

    def __repl__(self):
        return self.interface
    
    def add_interface(self, index, ip_address, mac_address):
        self.interface[index] = interface(index, ip_address, mac_address)
        return

    def add_gw(self, index, ip_address, mac_address):
        self.interface[index].gateway = interface(0, ip_address, mac_address)

    
slg = [
    SliceGateway(),
    SliceGateway(),
    SliceGateway()
]

slg[0].add_interface(1, "192.168.42.254", "52:54:00:01:01:01")
slg[0].add_gw(1, "192.168.42.253", "52:54:00:01:00:01")
slg[0].add_interface(2, "172.16.1.1", "52:54:00:00:00:01")
slg[0].add_gw(2, "172.16.1.254", "52:54:00:00:01:01")

slg[1].add_interface(1, "192.168.1.254", "52:54:00:02:01:01")
slg[1].add_gw(1, "192.168.1.50", "52:54:00:02:00:01")
slg[1].add_interface(2, "172.16.2.1", "52:54:00:00:00:02")
slg[1].add_gw(2, "172.16.2.254", "52:54:00:00:01:02")

slg[2].add_interface(1, "192.168.3.254", "52:54:00:03:01:01")
slg[2].add_gw(1, "192.168.3.50", "52:54:00:03:00:01")
slg[2].add_interface(2, "172.16.3.1", "52:54:00:00:00:03")
slg[2].add_gw(2, "172.16.3.254", "52:54:00:00:01:03")

PACKET_TYPE_ETHER=0
PACKET_TYPE_IPv4=67584
PACKET_TYPE_UDP=131089
PACKET_TYPE_VxLAN=201397
PACKET_TYPE_NEXT=65534

class RyuSlgInit(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, ** kwargs):
        super(RyuSlgInit, self).__init__(*args, **kwargs)

    def make_vxlan_encap_action(self, eth_src, eth_dst, ipv4_src, ipv4_dst, udp_src, vni):
        return [
                {"type": "ENCAP", "packet_type": PACKET_TYPE_VxLAN},
                {"type": "SET_FIELD", "field": "vxlan_vni", "value": vni},
                {"type": "ENCAP", "packet_type": PACKET_TYPE_UDP},
                {"type": "SET_FIELD", "field": "udp_src", "value": udp_src},
                {"type": "SET_FIELD", "field": "udp_dst", "value":4789},
                {"type": "ENCAP", "packet_type": PACKET_TYPE_IPv4},
                {"type": "SET_FIELD", "field": "ipv4_src", "value": ipv4_src},
                {"type": "SET_FIELD", "field": "ipv4_dst", "value": ipv4_dst},
                {"type": "SET_NW_TTL", "nw_ttl": 64},
                {"type": "ENCAP",  "packet_type": PACKET_TYPE_ETHER},
                {"type": "SET_FIELD", "field": "eth_src", "value": eth_src},
                {"type": "SET_FIELD", "field": "eth_dst", "value": eth_dst}
        ]
    def make_vxlan_decap_action(self):
        return [
            {"type": "DECAP", "cur_pkt_type": PACKET_TYPE_ETHER, "new_pkt_type": PACKET_TYPE_IPv4},
            {"type": "DECAP", "cur_pkt_type": PACKET_TYPE_IPv4, "new_pkt_type": PACKET_TYPE_UDP},
            {"type": "DECAP", "cur_pkt_type": PACKET_TYPE_UDP, "new_pkt_type": PACKET_TYPE_VxLAN},
            {"type": "DECAP", "cur_pkt_type": PACKET_TYPE_VxLAN, "new_pkt_type": PACKET_TYPE_NEXT},
        ]
        
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        self.logger.info('switch joind: datapath: %061x' % datapath.id)

        slg_id = datapath.id - 1
        
        # base flow
        flow = {'priority': 1, 'table_id': 0}
        flow['match'] = {'in_port': 1}
        flow['actions'] = [{'type':'OUTPUT','port': 2}]
        print flow
        mod_flow_entry(datapath, flow, ofproto.OFPFC_ADD)
        flow['match'] = {'in_port': 2}
        flow['actions'] = [{'type':'OUTPUT','port': 1}]
        print flow
        mod_flow_entry(datapath, flow, ofproto.OFPFC_ADD)
        
        if slg_id != 1 :
            # in_port: 1 ENCAP
            flow = {'priority': 10, 'table_id':0}
            flow['match'] = {'in_port': 1, "dl_type":2048}
            flow['actions'] = self.make_vxlan_encap_action(
                eth_src = slg[slg_id].interface[2].mac_address,
                eth_dst = slg[slg_id].interface[2].gateway.mac_address,
                ipv4_src = slg[slg_id].interface[2].ip_address,
                ipv4_dst = slg[2 if slg_id != 2 else 0].interface[2].ip_address,
                udp_src = 12345,
                vni = 5000 + 4 * 10
            )
            flow['actions'].append({"type":"OUTPUT", "port": 2})
            print flow
            mod_flow_entry(datapath, flow, ofproto.OFPFC_ADD)
        
            # in_port: 2 DECAP
            flow = {'priority': 10, 'table_id':0}
            flow['match'] = {'in_port':2, 'dl_type': 2048, "nw_proto":17, "tp_dst": 4789}
            flow['actions'] = self.make_vxlan_decap_action()
            flow['actions'].append({"type": "SET_FIELD", "field": "eth_dst", "value": slg[0 if slg_id != 2 else 2].interface[1].gateway.mac_address})
            flow['actions'].append({"type":"OUTPUT", "port": 1})
            print flow
            mod_flow_entry(datapath, flow, ofproto.OFPFC_ADD)
        
