# Copyright (C) 2012 Nippon Telegraph and Telephone Corporation.
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



####################################
#
# * Port assignment of SliceGateway:
#
# port 1: Downlink interface
# port 2: Uplink/VxLAN interface
# port 3: Copy of downlink interface to reply icmp and arp
# port 4: Copy of uplink interface to reply icmp and arp
#
#
#  Copy of   +        + Copy of
#  Downlink  |        | Uplink
#  Interface |        | Interface
#            |        |
# +----------+--------+----------+
# |          3        4          |
# |                              |
# |       Lagopus OF Switch      |
# |                              |
# |          1        2          |
# +----------+--------+----------+
#            |        |
#  Downlink  |        | Uplink(VxLAN)
#  Interface |        | Interface
#            |        |
#            +        +
#
#
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
#######################################

class interface(dict):

    def __init__(self, index, ip_address, mac_address):
        self.index = index
        self.ip_address = ip_address
        self.mac_address = mac_address
        self.neigh = {}
        self.gw = {}
        return

    def __repl__(self):
        return str({"index": self.index, "ip_address": self.ip_address, "mac_address": self.mac_address})

    def add_neigh(self, ip_address, mac_address):
        self.neigh[ip_address] = mac_address
        return
    def add_gw(self, ip_address, mac_address):
        self.gw = {"ip_address": ip_address, "mac_address": mac_address}
        return

class SliceGateway(dict):

    def __init__(self):
        self.interface = {}
        return

    def __repl__(self):
        return self.interface
    
    def add_interface(self, index, ip_address, mac_address):
        self.interface[index] = interface(index, ip_address, mac_address)
        return

    def add_neigh(self, index, ip_address, mac_address):
        self.interface[index].add_neigh(ip_address, mac_address)
        return

    def add_gw(self, index, ip_address, mac_address):
        self.interface[index].add_gw(ip_address, mac_address)

    
slg = [
    SliceGateway(),
    SliceGateway(),
    SliceGateway()
]

slg[0].add_interface(0, "172.16.0.254", "12:34:56:78:9a:bc")
slg[0].add_gw(0, "172.16.0.253", "12:34:56:78:9a:bc")
slg[0].add_interface(1, "172.16.1.1", "12:34:56:78:9a:bc")
slg[0].add_gw(1, "172.16.1.254", "12:34:56:78:9a:bc")

slg[1].add_interface(0, "192.168.1.254", "12:34:56:78:9a:bc")
slg[1].add_gw(0, "192.168.1.50", "12:34:56:78:9a:bc")
slg[1].add_interface(1, "172.16.2.1", "12:34:56:78:9a:bc")
slg[1].add_gw(1, "172.16.2.254", "12:34:56:78:9a:bc")

slg[2].add_interface(0, "192.168.3.254", "12:34:56:78:9a:bc")
slg[2].add_gw(0, "192.168.3.50", "12:34:56:78:9a:bc")
slg[2].add_interface(1, "172.16.3.1", "12:34:56:78:9a:bc")
slg[2].add_gw(1, "172.16.3.254", "12:34:56:78:9a:bc")


PACKET_TYPE_ETHER=0
PACKET_TYPE_IPv4=67584
PACKET_TYPE_UDP=131089
PACKET_TYPE_VxLAN=201397
PACKET_TYPE_NEXT=65534

class RyuSlgInit(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, ** kwargs):
        super(RyuSlgInit, self).__init__(*args, **kwargs)


    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        self.logger.info('switch joind: datapath: %061x' % datapath.id)

        # base flow
        flow = {'priority': 1, 'table_id': 0}
        flow['match'] = {'in_port': 1}
        flow['actions'] = [{'type':'OUTPUT','port': 3}]
        print flow
        mod_flow_entry(datapath, flow, ofproto.OFPFC_ADD)
        flow['match'] = {'in_port': 3}
        flow['actions'] = [{'type':'OUTPUT','port': 1}]
        print flow
        mod_flow_entry(datapath, flow, ofproto.OFPFC_ADD)
        flow['match'] = {'in_port': 2}
        flow['actions'] = [{'type':'OUTPUT','port': 4}]
        print flow
        mod_flow_entry(datapath, flow, ofproto.OFPFC_ADD)
        flow['match'] = {'in_port': 4}
        flow['actions'] = [{'type':'OUTPUT','port': 2}]
        print flow
        mod_flow_entry(datapath, flow, ofproto.OFPFC_ADD)
        
        # ICMP
        flow = {'priority': 10, 'table_id': 0}
        flow['match'] = {'in_port': 1, 'dl_type': 2048,
                         'ipv4_dst': slg[datapath.id - 1].interface[0].ip_address}
        flow['actions'] = [{'type': 'OUTPUT', 'port': 3}]
        print flow
        flow['match'] = {'in_port': 3, 'dl_type': 2048}
        flow['actions'] = [{'type': 'OUTPUT', 'port': 1}]
        print flow
        mod_flow_entry(datapath, flow, ofproto.OFPFC_ADD)
        flow['match'] = {'in_port': 2, 'dl_type': 2048,
                         'ipv4_dst': slg[datapath.id - 1].interface[1].ip_address}
        flow['actions'] = [{'type': 'OUTPUT', 'port': 4}]
        print flow
        mod_flow_entry(datapath, flow, ofproto.OFPFC_ADD)
        flow['match'] = {'in_port': 2, 'dl_type': 2048}
        flow['actions'] = [{'type': 'OUTPUT', 'port': 4}]
        print flow
        mod_flow_entry(datapath, flow, ofproto.OFPFC_ADD)
        
        # ARP
        flow = {'priority': 10, 'table_id': 0}
        flow['match'] = {'in_port': 1, 'dl_type': 2054}
        flow['actions'] = [{'type': 'OUTPUT', 'port': 3}]
        print flow
        mod_flow_entry(datapath, flow, ofproto.OFPFC_ADD)
        flow = {'priority': 10, 'table_id': 0}
        flow['match'] = {'in_port': 3, 'dl_type': 2054}
        flow['actions'] = [{'type': 'OUTPUT', 'port': 1}]
        print flow
        mod_flow_entry(datapath, flow, ofproto.OFPFC_ADD)
        flow['match'] = {'in_port': 2, 'dl_type': 2054}
        flow['actions'] = [{'type': 'OUTPUT', 'port': 4}]
        print flow
        mod_flow_entry(datapath, flow, ofproto.OFPFC_ADD)
        flow['match'] = {'in_port': 4, 'dl_type': 2054}
        flow['actions'] = [{'type': 'OUTPUT', 'port': 2}]
        print flow
        mod_flow_entry(datapath, flow, ofproto.OFPFC_ADD)




        
        # in_port: 1
        flow = {'priority': 5, 'table_id':0}
        flow['match'] = {'in_port': 1}
        flow['actions'] = [{'type':}]
        print flow
        mod_flow_entry(datapath, flow, ofproto.OFPFC_ADD)
        
        # in_port: 2 DECAP
        flow = {'priority': 5, 'table_id':0}
        flow['match'] = {'in_port'}
        print flow
        mod_flow_entry(datapath, flow, ofproto.OFPFC_ADD)

        # Routing
        

        # OUTPUT port 1
        flow = {'priority': 10, 'table_id': 11}
        flow['match'] = {}
        flow['actions'] = [{"type":"OUTPUT", "port": 1}]
        print flow
        mod_flow_entry(datapath, flow, ofproto.OFPFC_ADD)
        
        # OUTPUT port 2
        flow = {'priority': 10, 'table_id': 12}
        flow["match"] = {}
        flow["actions"] = [{"type": "OUTPUT", "port": 2}]
        print flow
        mod_flow_entry(datapath, flow, ofproto.OFPFC_ADD)
        
        # encap vni 5000, OUTPUT port 2
        for i in range(5):
            flow = {'priority': 10, 'table_id': (100 + i)}
            flow["match"] = {}
            flow["actions"] = [
                {"type": "ENCAP", "packet_type": PACKET_TYPE_VxLAN},
                {"type": "SET_FIELD", "field": "vxlan_vni", "value": (5000 + i * 10)},
                {"type": "ENCAP", "packet_type": PACKET_TYPE_UDP},
                {"type": "SET_FIELD", "field": "udp_src", "value":5432},
                {"type": "SET_FIELD", "field": "udp_dst", "value":4789},
                {"type": "ENCAP", "packet_type": PACKET_TYPE_IPv4},
                {"type": "SET_FIELD", "field": "ipv4_src", "value": slg[datapath.id - 1].interface[1].ip_address},
                {"type": "SET_FIELD", "field": "ipv4_dst", "value": "172.21.0.2"},
                {"type": "SET_FILED", "field": "SET_NW_TTL", "value": 64},
                {"type": "ENCAP",  "packet_type": PACKET_TYPE_ETHER},
                {"type": "SET_FIELD", "field": "eth_src", "value": slg[datapath.id - 1].interface[1].mac_address},
                {"type": "SET_FIELD", "field": "eth_dst", "value": slg[datapath.id - 1].interface[1].gw["mac_address"]},
                {"type": "OUTPUT", "port": 2}
            ]
            print flow
            mod_flow_entry(datapath, flow, ofproto.OFPFC_ADD)

        
