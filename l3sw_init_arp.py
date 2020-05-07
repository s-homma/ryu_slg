import logging
import json

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto.ether import ETH_TYPE_IP
from ryu.lib.ofctl_v1_3 import mod_flow_entry

# Added for SimpleArp
from operator import attrgetter
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import arp
from ryu.lib.packet.packet import Packet
from ryu.lib.packet.ethernet import ethernet
from ryu.lib.packet.arp import arp
from ryu.ofproto import ether
from ryu.ofproto import inet


####################################################################
#
#  +---------------------------------+ 
#  |                                 |
#  |    VM2                          |
#  |    Name: testserv               |
#  |    MAC: 52:54:00:01:00:01       |
#  |    IP:  192.168.42.253          |
#  |                                 |
#  +-------+-------------------------+
#          | 
#          |        
#          | intnet1: 172.16.10.0/24
#          |
#          |        
#  +-------+-------------------------+
#  |                                 |
#  |     VM1                         |
#  |     OF-Bridge01                 |
#  |     Name:slg[0]                 |
#  |     Dpid: 1                     |
#  |     Downlink:                   |
#  |       172.16.10.100             |
#  |       08:00:27:3a:a1:22         |
#  |     Uplink:                     |
#  |       192.168.57.100            |
#  |       08:00:27:e0:5a:14         |  
#  |                                 |
#  +-------+-------------------------+
#          |
#          | 
#          | vboxnet1: 192.168.57.0/24
#          |
#          |
#  +-------+-------------------------+
#  |                                 |
#  |     Host OS: OSX 10.15.4        |
#  |     VM Env: VirtualBox6.1.6     |
#  |     IP(hostonly adopter):       |
#  |       192.168.57.1              |
#  |     MAC: 0a:00:27:00:00:01      |
#  |                                 |
#  +---------------------------------+
#
# * Flow Entries:
# Table 0
# Priority 100: ARP
# Priority  10: rewrite mac address and output to downlink/uplink
# 
###################################################################

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
        self.interface[index].gateway = interface(index, ip_address, mac_address)

#    def make_vxlan_encap_action(eth_src, eth_dst, ipv4_src, ipv4_dst, udp_src, vni):
#	    return [
# 	        {"type": "ENCAP", "packet_type": PACKET_TYPE_VxLAN},
#	        {"type": "SET_FIELD", "field": "vxlan_vni", "value": vni},
#	        {"type": "ENCAP", "packet_type": PACKET_TYPE_UDP},
#	        {"type": "SET_FIELD", "field": "udp_src", "value": udp_src},
#	        {"type": "SET_FIELD", "field": "udp_dst", "value":4789},
#	        {"type": "ENCAP", "packet_type": PACKET_TYPE_IPv4},
#			{"type": "SET_FIELD", "field": "ipv4_src", "value": ipv4_src},
#	        {"type": "SET_FIELD", "field": "ipv4_dst", "value": ipv4_dst},
#    	    {"type": "SET_NW_TTL", "nw_ttl": 64},
#       		{"type": "ENCAP",  "packet_type": PACKET_TYPE_ETHER},
#        	{"type": "SET_FIELD", "field": "eth_src", "value": eth_src},
#        	{"type": "SET_FIELD", "field": "eth_dst", "value": eth_dst}
#        ]
#	def make_vxlan_decap_action():
#    	return [
#        	{"type": "DECAP", "cur_pkt_type": PACKET_TYPE_ETHER, "new_pkt_type": PACKET_TYPE_IPv4},
#        	{"type": "DECAP", "cur_pkt_type": PACKET_TYPE_IPv4, "new_pkt_type": PACKET_TYPE_UDP},
#        	{"type": "DECAP", "cur_pkt_type": PACKET_TYPE_UDP, "new_pkt_type": PACKET_TYPE_VxLAN},
#        	{"type": "DECAP", "cur_pkt_type": PACKET_TYPE_VxLAN, "new_pkt_type": PACKET_TYPE_NEXT},
#		]

# Define network interfaces

#slg = [
#    SliceGateway(),
#    SliceGateway(),
#   SliceGateway()
#]

slg = [SliceGateway()]

slg[0].add_interface(1, "192.168.57.100", "08:00:27:e0:5a:14")
#slg[0].add_gw(1, "192.168.57.1", "0a:00:27:00:00:01")
slg[0].add_gw(1, "192.168.57.1", None)
slg[0].add_interface(2, "172.16.10.100", "08:00:27:08:0a:ce")
#slg[0].add_gw(2, "172.16.10.2", "08:00:27:3a:a1:22")
slg[0].add_gw(2, "172.16.10.2", None)

#slg[1].add_interface(1, "192.168.1.254", "52:54:00:02:01:01")
#slg[1].add_gw(1, "192.168.1.50", "52:54:00:02:00:01")
#slg[1].add_interface(2, "172.16.2.1", "52:54:00:00:00:02")
#slg[1].add_gw(2, "172.16.2.254", "52:54:00:00:01:02")

#slg[2].add_interface(1, "192.168.3.254", "52:54:00:03:01:01")
#slg[2].add_gw(1, "192.168.3.50", "52:54:00:03:00:01")
#slg[2].add_interface(2, "172.16.3.1", "52:54:00:00:00:03")
#slg[2].add_gw(2, "172.16.3.254", "52:54:00:00:01:03")

PACKET_TYPE_ETHER=0
PACKET_TYPE_IPv4=67584
PACKET_TYPE_UDP=131089
PACKET_TYPE_VxLAN=201397
PACKET_TYPE_NEXT=65534

LOG = logging.getLogger('RyuSlgInit')
LOG.setLevel(logging.DEBUG)
logging.basicConfig()

SLG_PORT1 = 1
SLG_PORT2 = 2

class RyuSlgInit(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, ** kwargs):
        super(RyuSlgInit, self).__init__(*args, **kwargs)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        datapath.id = msg.datapath_id
        ofproto_parser = datapath.ofproto_parser
        self.logger.info('switch joind: datapath: %061x' % datapath.id)

        slg_id = datapath.id - 1

        set_config = ofproto_parser.OFPSetConfig(
            datapath,
            datapath.ofproto.OFPC_FRAG_NORMAL,
            datapath.ofproto.OFPCML_MAX
        )
        datapath.send_msg(set_config)
        self.install_table_miss(datapath, datapath.id)

        # base flow
#        flow = {'priority': 1, 'table_id': 0}
#        flow['match'] = {'in_port': 1}
#        flow['actions'] = [{'type':'OUTPUT','port': 2}]
#        print(flow)
#        mod_flow_entry(datapath, flow, ofproto.OFPFC_ADD)
#        flow['match'] = {'in_port': 2}
#        flow['actions'] = [{'type':'OUTPUT','port': 1}]
#        print(flow)
#        mod_flow_entry(datapath, flow, ofproto.OFPFC_ADD)

        # L3 forwarding
        flow = {'priority': 10, 'table_id': 0}
        flow['match'] = {'in_port': 1, 'dl_type': 2048, 'eth_dst': slg[slg_id].interface[1].mac_address, 'ipv4_dst': slg[slg_id].interface[2].gateway.ip_address}
        flow['actions'] = [{"type": "SET_FIELD", "field": "eth_dst", "value": "08:00:27:3a:a1:22"}, {"type": "OUTPUT", "port": 2}]
        print(flow)
        mod_flow_entry(datapath, flow, ofproto.OFPFC_ADD)
        flow['match'] = {'in_port': 2, 'dl_type': 2048, 'eth_dst': slg[slg_id].interface[2].mac_address, 'ipv4_dst': slg[slg_id].interface[1].gateway.ip_address}
        flow['actions'] = [{"type": "SET_FIELD", "field": "eth_dst", "value": "0a:00:27:00:00:01"}, {"type": "OUTPUT", "port": 1}]
        print(flow)
        mod_flow_entry(datapath, flow, ofproto.OFPFC_ADD)

        # Packet-in for ARP
        flow = {'priority': 100, 'table_id': 0}
#        flow['match'] = {'in_port': 1, 'dl_type': 2054, 'eth_dst': "ff:ff:ff:ff:ff:ff", 'ipv4_dst': slg[slg_id].interface[1].ip_address}
        flow['match'] = {'in_port': 1, 'dl_type': 2054}
        flow['actions'] = [{"type": "OUTPUT", "port": 4294967293}]
        print(flow)
        mod_flow_entry(datapath, flow, ofproto.OFPFC_ADD)
#        flow['match'] = {'in_port': 2, 'dl_type': 2054, 'eth_dst': "ff:ff:ff:ff:ff:ff", 'ipv4_dst': slg[slg_id].interface[2].ip_address}
        flow['match'] = {'in_port': 2, 'dl_type': 2054}
        flow['actions'] = [{"type": "OUTPUT", "port": 4294967293}]
        print(flow)
        mod_flow_entry(datapath, flow, ofproto.OFPFC_ADD)

    def install_table_miss(self, datapath, dpid):
        datapath.id = dpid

        match = datapath.ofproto_parser.OFPMatch()

        actions = [datapath.ofproto_parser.OFPActionOutput(
                datapath.ofproto.OFPP_CONTROLLER,
                datapath.ofproto.OFPCML_NO_BUFFER)]
        inst = [datapath.ofproto_parser.OFPInstructionActions(
                datapath.ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = datapath.ofproto_parser.OFPFlowMod(
                datapath=datapath,
                priority=0,
                buffer_id=0xffffffff,
                match=match,
                instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        inPort = msg.match['in_port']

        packet = Packet(msg.data)
        etherFrame = packet.get_protocol(ethernet)
        if etherFrame.ethertype == ether.ETH_TYPE_ARP:
            self.receive_arp(datapath, packet, etherFrame, inPort)
            return 0
        else:
            LOG.debug("Drop packet")
            return 1

    def receive_arp(self, datapath, packet, etherFrame, inPort):
        arpPacket = packet.get_protocol(arp)

        if arpPacket.opcode == 1:
            arp_dstIp = arpPacket.dst_ip
            LOG.debug("receive ARP request %s => %s (port%d)"
                       %(etherFrame.src, etherFrame.dst, inPort))
            self.reply_arp(datapath, etherFrame, arpPacket, arp_dstIp, inPort)
        elif arpPacket.opcode == 2:
            pass

    def reply_arp(self, datapath, etherFrame, arpPacket, arp_dstIp, inPort):
        dstIp = arpPacket.src_ip
        srcIp = arpPacket.dst_ip
        dstMac = etherFrame.src
        if arp_dstIp == "192.168.57.100":
            srcMac = "08:00:27:e0:5a:14"
            outPort = SLG_PORT1
        elif arp_dstIp == "172.16.10.100":
            srcMac = "08:00:27:08:0a:ce"
            outPort = SLG_PORT2
        else:
            LOG.debug("unknown arp request received !")

        self.send_arp(datapath, 2, srcMac, srcIp, dstMac, dstIp, outPort)
        LOG.debug("send ARP reply %s => %s (port%d)" %(srcMac, dstMac, outPort))

    def send_arp(self, datapath, opcode, srcMac, srcIp, dstMac, dstIp, outPort):
        if opcode == 1:
            targetMac = "00:00:00:00:00:00"
            targetIp = dstIp
        elif opcode == 2:
            targetMac = dstMac
            targetIp = dstIp

        e = ethernet(dstMac, srcMac, ether.ETH_TYPE_ARP)
        a = arp(1, 0x0800, 6, 4, opcode, srcMac, srcIp, targetMac, targetIp)
        p = Packet()
        p.add_protocol(e)
        p.add_protocol(a)
        p.serialize()

        actions = [datapath.ofproto_parser.OFPActionOutput(outPort, 0)]
        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=0xffffffff,
            in_port=datapath.ofproto.OFPP_CONTROLLER,
            actions=actions,
            data=p.data)
        datapath.send_msg(out)

#       if slg_id != 1 :
#           # in_port: 1 ENCAP
#           flow = {'priority': 10, 'table_id':0}
#           flow['match'] = {'in_port': 1, "dl_type":2048}
#           flow['actions'] = make_vxlan_encap_action(
#               eth_src = slg[slg_id].interface[2].mac_address,
#               eth_dst = slg[slg_id].interface[2].gateway.mac_address,
#               ipv4_src = slg[slg_id].interface[2].ip_address,
#               ipv4_dst = slg[2 if slg_id != 2 else 0].interface[2].ip_address,
#               udp_src = 12345,
#               vni = 5000 + 4 * 10
#           )
#           flow['actions'].append({"type":"OUTPUT", "port": 2})
#           print(flow)
#           mod_flow_entry(datapath, flow, ofproto.OFPFC_ADD)

#       # in_port: 2 DECAP
#       flow = {'priority': 10, 'table_id':0}
#       flow['match'] = {'in_port':2, 'dl_type': 2048, "nw_proto":17, "tp_dst": 4789}
#       flow['actions'] = make_vxlan_decap_action()
#       flow['actions'].append({"type": "SET_FIELD", "field": "eth_dst", "value": slg[slg_id].interface[1].gateway.mac_address})
#       flow['actions'].append({"type":"OUTPUT", "port": 1})
#       print(flow)
#       mod_flow_entry(datapath, flow, ofproto.OFPFC_ADD)
