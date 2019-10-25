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
# table 12: encap, output to uplink
#
#######################################

class interface(dict):
    index = 0
    ip_address = "0.0.0.0"
    mac_address = "12:34:56:78:8a:bc"
    neigh = {}
    
    def __init__(self, index, ip_address, mac_address):
        self.index = index
        self.ip_address = ip_address
        self.mac_address = mac_address
        return

    def __repl__(self):
        return str({"index": self.index, "ip_address": self.ip_address, "mac_address": self.mac_address})

    def add_neigh(self, ip_address, mac_address):
        self.neigh[ip_address] = mac_address
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

    
slg = [
    SliceGateway(),
    SliceGateway(),
    SliceGateway()
]

slg[0].add_interface(0, "172.16.0.254", "12:34:56:78:9a:bc")
slg[0].add_neigh(0, "172.16.0.253", "12:34:56:78:9a:bc")
slg[0].add_interface(1, "172.16.1.1", "12:34:56:78:9a:bc")
slg[0].add_neigh(1, "172.16.1.254", "12:34:56:78:9a:bc")

slg[1].add_interface(0, "192.168.1.254", "12:34:56:78:9a:bc")
slg[1].add_neigh(0, "192.168.1.50", "12:34:56:78:9a:bc")
slg[1].add_interface(1, "172.16.2.1", "12:34:56:78:9a:bc")
slg[1].add_neigh(1, "172.16.2.254", "12:34:56:78:9a:bc")

slg[2].add_interface(0, "192.168.3.254", "12:34:56:78:9a:bc")
slg[2].add_neigh(0, "192.168.3.50", "12:34:56:78:9a:bc")
slg[2].add_interface(1, "172.16.3.1", "12:34:56:78:9a:bc")
slg[2].add_neigh(1, "172.16.3.254", "12:34:56:78:9a:bc")

initial_flows = [
    # DPID 1
    [
        # ARP
        
        # ICMP
        {'priority':10,
         'table_id':0,
         'match':{'in_port': 1,
                  'dl_type' : 2048,
                  'ipv4_dst' : slg[0].interface[0].ip_address},
         'actions' :[
             {"type":"OUTPUT","port":3}
         ]},
        {'priority':1,
         'table_id':0,
         'match':{'in_port': 3},
         'actions' :[
             {"type":"OUTPUT","port":1}
         ]},
        {'priority':10,
         'table_id':0,
         'match':{'in_port': 2,
                  'dl_type' : 2048,
                  'ipv4_dst' : slg[0].interface[1].ip_address},
         'actions' :[
             {"type":"OUTPUT","port":4}
         ]},
        {'priority':1,
         'table_id':0,
         'match':{'in_port': 4},
         'actions' :[
             {"type":"OUTPUT","port":2}
         ]},
        
        {'priority':1,
         'table_id':1,
         'match':{'dl_type' : 2048,
                  'ip_proto' : 6},
         'actions' :[]},
        {'priority':1,
         'table_id':2,
         'match':{'dl_type' : 2048,
                  'ip_proto' : 6},
         'actions' :[]}
        
    ],
    # DPID 2
    [
        {'priority':2,
         'table_id':0,
         'match':{'dl_type' : 2048,
                  'ip_proto' : 6},
        'actions' :[]},
        {'priority':2,
         'table_id':1,
         'match':{'dl_type' : 2048,
                  'ip_proto' : 6},
         'actions' :[]},
        {'priority':2,
         'table_id':2,
         'match':{'dl_type' : 2048,
                  'ip_proto' : 6},
         'actions' :[]}
    ],
    # DPID 3
    [
        {'priority':3,
         'table_id':0,
         'match':{'dl_type' : 2048,
                  'ip_proto' : 6},
         'actions' :[]},
        {'priority':3,
         'table_id':1,
         'match':{'dl_type' : 2048,
                  'ip_proto' : 6},
         'actions' :[]},
        {'priority':3,
         'table_id':2,
         'match':{'dl_type' : 2048,
                  'ip_proto' : 6},
         'actions' :[]}
    ]
]

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
                         'ipv4_dst': slg[0].interface[0].ip_address}
        flow['actions'] = [{'type': 'OUTPUT', 'port': 3}]
        print flow
        mod_flow_entry(datapath, flow, ofproto.OFPFC_ADD)
        flow['match'] = {'in_port': 2, 'dl_type': 2048,
                         'ipv4_dst': slg[0].interface[1].ip_address}
        flow['actions'] = [{'type': 'OUTPUT', 'port': 4}]
        print flow
        mod_flow_entry(datapath, flow, ofproto.OFPFC_ADD)
        
        # ARP
        flow = {'priority': 10, 'table_id': 0}
        flow['match'] = {'in_port': 1, 'dl_type': 2054}
        flow['actions'] = [{'type': 'OUTPUT', 'port': 3}]
        print flow
        mod_flow_entry(datapath, flow, ofproto.OFPFC_ADD)
        flow['match'] = {'in_port': 2, 'dl_type': 2054}
        flow['actions'] = [{'type': 'OUTPUT', 'port': 4}]
        print flow
        mod_flow_entry(datapath, flow, ofproto.OFPFC_ADD)

        
        # print slg
        
        # for flow in initial_flows[datapath.id - 1] :
        #     print flow
        #     mod_flow_entry(datapath,
        #                    flow,
        #                    ofproto.OFPFC_ADD)
        
        # if datapath.id == 1 :
        #     for ip_proto in [6,17]:
        #         mod_flow_entry(datapath,
        #                        ofproto.OFPFC_ADD)
