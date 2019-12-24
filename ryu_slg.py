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
import ast
from webob import Response

import pprint

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller import dpset
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_0
from ryu.ofproto import ofproto_v1_2
from ryu.ofproto import ofproto_v1_3
from ryu.lib import ofctl_v1_0
from ryu.lib import ofctl_v1_2
from ryu.lib import ofctl_v1_3
from ryu.app.wsgi import ControllerBase, WSGIApplication


LOG = logging.getLogger('ryu.app.ofctl_rest')

# supported ofctl versions in this restful app
supported_ofctl = {
    ofproto_v1_0.OFP_VERSION: ofctl_v1_0,
    ofproto_v1_2.OFP_VERSION: ofctl_v1_2,
    ofproto_v1_3.OFP_VERSION: ofctl_v1_3,
}

# REST API
#

# Retrieve the switch stats
#
# get the list of all switches
# GET /stats/switches
#
# get the desc stats of the switch
# GET /stats/desc/<dpid>
#
# get flows stats of the switch
# GET /stats/flow/<dpid>
#
# get flows stats of the switch filtered by the fields
# POST /stats/flow/<dpid>
#
# get aggregate flows stats of the switch
# GET /stats/aggregateflow/<dpid>
#
# get aggregate flows stats of the switch filtered by the fields
# POST /stats/aggregateflow/<dpid>
#
# get table stats of the switch
# GET /stats/table/<dpid>
#
# get table features stats of the switch
# GET /stats/tablefeatures/<dpid>
#
# get ports stats of the switch
# GET /stats/port/<dpid>
#
# get queues stats of the switch
# GET /stats/queue/<dpid>
#
# get queues config stats of the switch
# GET /stats/queueconfig/<dpid>/<port>
#
# get meter features stats of the switch
# GET /stats/meterfeatures/<dpid>
#
# get meter config stats of the switch
# GET /stats/meterconfig/<dpid>
#
# get meters stats of the switch
# GET /stats/meter/<dpid>
#
# get group features stats of the switch
# GET /stats/groupfeatures/<dpid>
#
# get groups desc stats of the switch
# GET /stats/groupdesc/<dpid>
#
# get groups stats of the switch
# GET /stats/group/<dpid>
#
# get ports description of the switch
# GET /stats/portdesc/<dpid>

# Update the switch stats
#
# add a flow entry
# POST /stats/flowentry/add
#
# modify all matching flow entries
# POST /stats/flowentry/modify
#
# modify flow entry strictly matching wildcards and priority
# POST /stats/flowentry/modify_strict
#
# delete all matching flow entries
# POST /stats/flowentry/delete
#
# delete flow entry strictly matching wildcards and priority
# POST /stats/flowentry/delete_strict
#
# delete all flow entries of the switch
# DELETE /stats/flowentry/clear/<dpid>
#
# add a meter entry
# POST /stats/meterentry/add
#
# modify a meter entry
# POST /stats/meterentry/modify
#
# delete a meter entry
# POST /stats/meterentry/delete
#
# add a group entry
# POST /stats/groupentry/add
#
# modify a group entry
# POST /stats/groupentry/modify
#
# delete a group entry
# POST /stats/groupentry/delete
#
# modify behavior of the physical port
# POST /stats/portdesc/modify
#
#
# send a experimeter message
# POST /stats/experimenter/<dpid>

#
# add slice
# POST /slice/add
#
# delete slice
# POST /slice/delete
#
# reset slices
# POST /slice/reset
#

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

def make_vxlan_encap_action(eth_src, eth_dst, ipv4_src, ipv4_dst, udp_src, vni):
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
def make_vxlan_decap_action():
    return [
        {"type": "DECAP", "cur_pkt_type": PACKET_TYPE_ETHER, "new_pkt_type": PACKET_TYPE_IPv4},
        {"type": "DECAP", "cur_pkt_type": PACKET_TYPE_IPv4, "new_pkt_type": PACKET_TYPE_UDP},
        {"type": "DECAP", "cur_pkt_type": PACKET_TYPE_UDP, "new_pkt_type": PACKET_TYPE_VxLAN},
        {"type": "DECAP", "cur_pkt_type": PACKET_TYPE_VxLAN, "new_pkt_type": PACKET_TYPE_NEXT},
    ]


class StatsController(ControllerBase):
    def __init__(self, req, link, data, **config):
        super(StatsController, self).__init__(req, link, data, **config)
        self.dpset = data['dpset']
        self.waiters = data['waiters']

    def get_dpids(self, req, **_kwargs):
        dps = list(self.dpset.dps.keys())
        body = json.dumps(dps)
        return Response(content_type='application/json', body=body)

    def get_desc_stats(self, req, dpid, **_kwargs):

        if type(dpid) == str and not dpid.isdigit():
            LOG.debug('invalid dpid %s', dpid)
            return Response(status=400)

        dp = self.dpset.get(int(dpid))

        if dp is None:
            return Response(status=404)
        _ofp_version = dp.ofproto.OFP_VERSION

        _ofctl = supported_ofctl.get(_ofp_version, None)
        if _ofctl is not None:
            desc = _ofctl.get_desc_stats(dp, self.waiters)

        else:
            LOG.debug('Unsupported OF protocol')
            return Response(status=501)

        body = json.dumps(desc)
        return Response(content_type='application/json', body=body)

    def get_flow_stats(self, req, dpid, **_kwargs):

        if req.body == '':
            flow = {}

        else:

            try:
                flow = ast.literal_eval(req.body)

            except SyntaxError:
                LOG.debug('invalid syntax %s', req.body)
                return Response(status=400)

        if type(dpid) == str and not dpid.isdigit():
            LOG.debug('invalid dpid %s', dpid)
            return Response(status=400)

        dp = self.dpset.get(int(dpid))

        if dp is None:
            return Response(status=404)

        _ofp_version = dp.ofproto.OFP_VERSION

        _ofctl = supported_ofctl.get(_ofp_version, None)
        if _ofctl is not None:
            flows = _ofctl.get_flow_stats(dp, self.waiters, flow)

        else:
            LOG.debug('Unsupported OF protocol')
            return Response(status=501)

        body = json.dumps(flows)
        return Response(content_type='application/json', body=body)

    def get_aggregate_flow_stats(self, req, dpid, **_kwargs):

        if req.body == '':
            flow = {}

        else:
            try:
                flow = ast.literal_eval(req.body)

            except SyntaxError:
                LOG.debug('invalid syntax %s', req.body)
                return Response(status=400)

        if type(dpid) == str and not dpid.isdigit():
            LOG.debug('invalid dpid %s', dpid)
            return Response(status=400)

        dp = self.dpset.get(int(dpid))

        if dp is None:
            return Response(status=404)

        _ofp_version = dp.ofproto.OFP_VERSION

        _ofctl = supported_ofctl.get(_ofp_version, None)
        if _ofctl is not None:
            flows = _ofctl.get_aggregate_flow_stats(dp, self.waiters, flow)

        else:
            LOG.debug('Unsupported OF protocol')
            return Response(status=501)

        body = json.dumps(flows)
        return Response(content_type='application/json', body=body)

    def get_table_stats(self, req, dpid, **_kwargs):

        if type(dpid) == str and not dpid.isdigit():
            LOG.debug('invalid dpid %s', dpid)
            return Response(status=400)

        dp = self.dpset.get(int(dpid))

        if dp is None:
            return Response(status=404)

        _ofp_version = dp.ofproto.OFP_VERSION

        _ofctl = supported_ofctl.get(_ofp_version, None)
        if _ofctl is not None:
            ports = _ofctl.get_table_stats(dp, self.waiters)

        else:
            LOG.debug('Unsupported OF protocol')
            return Response(status=501)

        body = json.dumps(ports)
        return Response(content_type='application/json', body=body)

    def get_table_features(self, req, dpid, **_kwargs):

        if type(dpid) == str and not dpid.isdigit():
            LOG.debug('invalid dpid %s', dpid)
            return Response(status=400)

        dp = self.dpset.get(int(dpid))

        if dp is None:
            return Response(status=404)

        _ofp_version = dp.ofproto.OFP_VERSION

        _ofctl = supported_ofctl.get(_ofp_version, None)
        if _ofctl is not None:
            ports = _ofctl.get_table_features(dp, self.waiters)

        else:
            LOG.debug('Unsupported OF protocol')
            return Response(status=501)

        body = json.dumps(ports)
        return Response(content_type='application/json', body=body)

    def get_port_stats(self, req, dpid, **_kwargs):

        if type(dpid) == str and not dpid.isdigit():
            LOG.debug('invalid dpid %s', dpid)
            return Response(status=400)

        dp = self.dpset.get(int(dpid))

        if dp is None:
            return Response(status=404)

        _ofp_version = dp.ofproto.OFP_VERSION

        _ofctl = supported_ofctl.get(_ofp_version, None)
        if _ofctl is not None:
            ports = _ofctl.get_port_stats(dp, self.waiters)

        else:
            LOG.debug('Unsupported OF protocol')
            return Response(status=501)

        body = json.dumps(ports)
        return Response(content_type='application/json', body=body)

    def get_queue_stats(self, req, dpid, **_kwargs):

        if type(dpid) == str and not dpid.isdigit():
            LOG.debug('invalid dpid %s', dpid)
            return Response(status=400)

        dp = self.dpset.get(int(dpid))

        if dp is None:
            return Response(status=404)

        _ofp_version = dp.ofproto.OFP_VERSION

        _ofctl = supported_ofctl.get(_ofp_version, None)
        if _ofctl is not None:
            queues = _ofctl.get_queue_stats(dp, self.waiters)

        else:
            LOG.debug('Unsupported OF protocol')
            return Response(status=501)

        body = json.dumps(queues)
        return Response(content_type='application/json', body=body)

    def get_queue_config(self, req, dpid, port, **_kwargs):

        if type(dpid) == str and not dpid.isdigit():
            LOG.debug('invalid dpid %s', dpid)
            return Response(status=400)

        if type(port) == str and not port.isdigit():
            LOG.debug('invalid port %s', port)
            return Response(status=400)

        dp = self.dpset.get(int(dpid))
        port = int(port)

        if dp is None:
            return Response(status=404)

        _ofp_version = dp.ofproto.OFP_VERSION

        _ofctl = supported_ofctl.get(_ofp_version, None)
        if _ofctl is not None:
            queues = _ofctl.get_queue_config(dp, port, self.waiters)

        else:
            LOG.debug('Unsupported OF protocol')
            return Response(status=501)

        body = json.dumps(queues)
        return Response(content_type='application/json', body=body)

    def get_meter_features(self, req, dpid, **_kwargs):

        if type(dpid) == str and not dpid.isdigit():
            LOG.debug('invalid dpid %s', dpid)
            return Response(status=400)

        dp = self.dpset.get(int(dpid))

        if dp is None:
            return Response(status=404)

        _ofp_version = dp.ofproto.OFP_VERSION
        _ofctl = supported_ofctl.get(_ofp_version, None)

        if _ofctl is not None and hasattr(_ofctl, 'get_meter_features'):
            meters = _ofctl.get_meter_features(dp, self.waiters)

        else:
            LOG.debug('Unsupported OF protocol or \
                request not supported in this OF protocol version')
            return Response(status=501)

        body = json.dumps(meters)
        return Response(content_type='application/json', body=body)

    def get_meter_config(self, req, dpid, **_kwargs):

        if type(dpid) == str and not dpid.isdigit():
            LOG.debug('invalid dpid %s', dpid)
            return Response(status=400)

        dp = self.dpset.get(int(dpid))

        if dp is None:
            return Response(status=404)

        _ofp_version = dp.ofproto.OFP_VERSION
        _ofctl = supported_ofctl.get(_ofp_version, None)

        if _ofctl is not None and hasattr(_ofctl, 'get_meter_config'):
            meters = _ofctl.get_meter_config(dp, self.waiters)

        else:
            LOG.debug('Unsupported OF protocol or \
                request not supported in this OF protocol version')
            return Response(status=501)

        body = json.dumps(meters)
        return Response(content_type='application/json', body=body)

    def get_meter_stats(self, req, dpid, **_kwargs):

        if type(dpid) == str and not dpid.isdigit():
            LOG.debug('invalid dpid %s', dpid)
            return Response(status=400)

        dp = self.dpset.get(int(dpid))

        if dp is None:
            return Response(status=404)

        _ofp_version = dp.ofproto.OFP_VERSION
        _ofctl = supported_ofctl.get(_ofp_version, None)

        if _ofctl is not None and hasattr(_ofctl, 'get_meter_stats'):
            meters = _ofctl.get_meter_stats(dp, self.waiters)

        else:
            LOG.debug('Unsupported OF protocol or \
                request not supported in this OF protocol version')
            return Response(status=501)

        body = json.dumps(meters)
        return Response(content_type='application/json', body=body)

    def get_group_features(self, req, dpid, **_kwargs):

        if type(dpid) == str and not dpid.isdigit():
            LOG.debug('invalid dpid %s', dpid)
            return Response(status=400)

        dp = self.dpset.get(int(dpid))

        if dp is None:
            return Response(status=404)

        _ofp_version = dp.ofproto.OFP_VERSION
        _ofctl = supported_ofctl.get(_ofp_version, None)

        if _ofctl is not None and hasattr(_ofctl, 'get_group_features'):
            groups = _ofctl.get_group_features(dp, self.waiters)

        else:
            LOG.debug('Unsupported OF protocol or \
                request not supported in this OF protocol version')
            return Response(status=501)

        body = json.dumps(groups)
        return Response(content_type='application/json', body=body)

    def get_group_desc(self, req, dpid, **_kwargs):

        if type(dpid) == str and not dpid.isdigit():
            LOG.debug('invalid dpid %s', dpid)
            return Response(status=400)

        dp = self.dpset.get(int(dpid))

        if dp is None:
            return Response(status=404)

        _ofp_version = dp.ofproto.OFP_VERSION
        _ofctl = supported_ofctl.get(_ofp_version, None)

        if _ofctl is not None and hasattr(_ofctl, 'get_group_desc'):
            groups = _ofctl.get_group_desc(dp, self.waiters)

        else:
            LOG.debug('Unsupported OF protocol or \
                request not supported in this OF protocol version')
            return Response(status=501)

        body = json.dumps(groups)
        return Response(content_type='application/json', body=body)

    def get_group_stats(self, req, dpid, **_kwargs):

        if type(dpid) == str and not dpid.isdigit():
            LOG.debug('invalid dpid %s', dpid)
            return Response(status=400)

        dp = self.dpset.get(int(dpid))

        if dp is None:
            return Response(status=404)

        _ofp_version = dp.ofproto.OFP_VERSION
        _ofctl = supported_ofctl.get(_ofp_version, None)

        if _ofctl is not None and hasattr(_ofctl, 'get_group_stats'):
            groups = _ofctl.get_group_stats(dp, self.waiters)

        else:
            LOG.debug('Unsupported OF protocol or \
                request not supported in this OF protocol version')
            return Response(status=501)

        body = json.dumps(groups)
        return Response(content_type='application/json', body=body)

    def get_port_desc(self, req, dpid, **_kwargs):

        if type(dpid) == str and not dpid.isdigit():
            LOG.debug('invalid dpid %s', dpid)
            return Response(status=400)

        dp = self.dpset.get(int(dpid))

        if dp is None:
            return Response(status=404)

        _ofp_version = dp.ofproto.OFP_VERSION

        _ofctl = supported_ofctl.get(_ofp_version, None)
        if _ofctl is not None:
            groups = _ofctl.get_port_desc(dp, self.waiters)

        else:
            LOG.debug('Unsupported OF protocol')
            return Response(status=501)

        body = json.dumps(groups)
        return Response(content_type='application/json', body=body)

    def mod_flow_entry(self, req, cmd, **_kwargs):

        try:
            flow = ast.literal_eval(req.body)

        except SyntaxError:
            LOG.debug('invalid syntax %s', req.body)
            return Response(status=400)

        dpid = flow.get('dpid')

        if type(dpid) == str and not dpid.isdigit():
            LOG.debug('invalid dpid %s', dpid)
            return Response(status=400)

        dp = self.dpset.get(int(dpid))

        if dp is None:
            return Response(status=404)

        if cmd == 'add':
            cmd = dp.ofproto.OFPFC_ADD
        elif cmd == 'modify':
            cmd = dp.ofproto.OFPFC_MODIFY
        elif cmd == 'modify_strict':
            cmd = dp.ofproto.OFPFC_MODIFY_STRICT
        elif cmd == 'delete':
            cmd = dp.ofproto.OFPFC_DELETE
        elif cmd == 'delete_strict':
            cmd = dp.ofproto.OFPFC_DELETE_STRICT
        else:
            return Response(status=404)

        _ofp_version = dp.ofproto.OFP_VERSION
        _ofctl = supported_ofctl.get(_ofp_version, None)
        if _ofctl is not None:
            _ofctl.mod_flow_entry(dp, flow, cmd)
        else:
            LOG.debug('Unsupported OF protocol')
            return Response(status=501)

        return Response(status=200)

    def delete_flow_entry(self, req, dpid, **_kwargs):

        if type(dpid) == str and not dpid.isdigit():
            LOG.debug('invalid dpid %s', dpid)
            return Response(status=400)

        dp = self.dpset.get(int(dpid))

        if dp is None:
            return Response(status=404)

        _ofp_version = dp.ofproto.OFP_VERSION

        if ofproto_v1_0.OFP_VERSION == _ofp_version:
            flow = {}
        else:
            flow = {'table_id': dp.ofproto.OFPTT_ALL}

        _ofctl = supported_ofctl.get(_ofp_version, None)
        if _ofctl is not None:
            _ofctl.mod_flow_entry(dp, flow, dp.ofproto.OFPFC_DELETE)

        else:
            LOG.debug('Unsupported OF protocol')
            return Response(status=501)

        return Response(status=200)


    def mod_slice(self, req, cmd, **_kwargs):

        print "mod_slice"
        
        try:
            slice = ast.literal_eval(req.body)

        except SyntaxError:
            LOG.debug('invalid syntax %s', req.body)
            return Response(status=400)

        print slice

        slice_id = slice.get('slice_id')
        print "slice_id: " + str(slice_id)
        src_ip = slice.get('src_ip')
        print "src_ip: " + str(src_ip)
        dst_ip = slice.get('dst_ip')
        print "dst_ip: " + str(dst_ip)
        dst_port = slice.get('dst_port')
        print "dst_port: " + str(dst_port)
        vni = 5000 + slice_id * 10
        print "vni: " + str(vni)

        for i in range(3):
            dpid = i + 1
            dp = self.dpset.get(int(dpid))
            if dp is None:
                return Response(status=404)


        ## SLG1: Edge Router Gateway
        dpid = 1
        dp = self.dpset.get(int(dpid))
        _ofp_version = dp.ofproto.OFP_VERSION
        _ofctl = supported_ofctl.get(_ofp_version, None)
        if _ofctl is None:
            LOG.debug('Unsupported OF protocol')
            return Response(status=501)
        
        if cmd == 'add':
            of_cmd = dp.ofproto.OFPFC_ADD
        elif cmd == 'delete':
            of_cmd = dp.ofproto.ofpfc_delete
        elif cmd == 'reset':
            print 'reset slice: Not implemented'
            return Response(status=404)
        else:
            return Response(status=404)

        flow = {'priority': 100, 'table_id':0}
        flow['actions'] = make_vxlan_encap_action(
            eth_src = slg[0].interface[2].mac_address,
            eth_dst = slg[0].interface[2].gateway.mac_address,
            ipv4_src = slg[0].interface[2].ip_address,
            ipv4_dst = slg[1 if slice_id == 1 or slice_id == 2 else 2].interface[2].ip_address,
            udp_src = 12345,
            vni = 5000 + slice_id * 10
        )
        flow['actions'].append({"type":"OUTPUT", "port": 2})
        flow['match'] = {'in_port': 1, "dl_type": 2048, "ip_proto": 6, "ipv4_src": src_ip, "ipv4_dst": dst_ip, "tcp_dst": dst_port}
        print flow
        _ofctl.mod_flow_entry(dp, flow, of_cmd)
        flow['match'] = {'in_port': 1, "dl_type": 2048, "ip_proto": 17, "ipv4_src": src_ip, "ipv4_dst": dst_ip, "udp_dst": dst_port}
        print flow
        _ofctl.mod_flow_entry(dp, flow, of_cmd)
        flow['match'] = {'in_port': 1, "dl_type": 2048, "ip_proto": 1, "ipv4_src": src_ip, "ipv4_dst": dst_ip}
        print flow
        _ofctl.mod_flow_entry(dp, flow, of_cmd)


        
        ## SLG2: MEC gateway
        if slice_id == 1 or slice_id == 2:
            dpid = 2
            dp = self.dpset.get(int(dpid))
            _ofp_version = dp.ofproto.OFP_VERSION
            _ofctl = supported_ofctl.get(_ofp_version, None)
            if _ofctl is None:
                LOG.debug('Unsupported OF protocol')
                return Response(status=501)
            
            if cmd == 'add':
                of_cmd = dp.ofproto.OFPFC_ADD
            elif cmd == 'delete':
                of_cmd = dp.ofproto.ofpfc_delete
            elif cmd == 'reset':
                print 'reset slice: Not implemented'
                return Response(status=404)
            else:
                return Response(status=404)
            
            flow = {'priority': 100, 'table_id':0}
            flow['actions'] = make_vxlan_encap_action(
                eth_src = slg[1].interface[2].mac_address,
                eth_dst = slg[1].interface[2].gateway.mac_address,
                ipv4_src = slg[1].interface[2].ip_address,
                ipv4_dst = slg[0].interface[2].ip_address,
                udp_src = 12345,
                vni = 5000 + slice_id * 10
            )
            flow['actions'].append({"type":"OUTPUT", "port": 2})
            flow['match'] = {'in_port': 1, "dl_type": 2048, "ip_proto": 6, "ipv4_src": dst_ip, "ipv4_dst": src_ip, "udp_src": dst_port}
            print flow
            _ofctl.mod_flow_entry(dp, flow, of_cmd)
            flow['match'] = {'in_port': 1, "dl_type": 2048, "ip_proto": 17, "ipv4_src": dst_ip, "ipv4_dst": src_ip, "udp_src": dst_port}
            print flow
            _ofctl.mod_flow_entry(dp, flow, of_cmd)
            flow['match'] = {'in_port': 1, "dl_type": 2048, "ip_proto": 1, "ipv4_src": dst_ip, "ipv4_dst": src_ip}
            print flow
            _ofctl.mod_flow_entry(dp, flow, of_cmd)

        else:
            dpid = 3
            dp = self.dpset.get(int(dpid))
            _ofp_version = dp.ofproto.OFP_VERSION
            _ofctl = supported_ofctl.get(_ofp_version, None)
            if _ofctl is None:
                LOG.debug('Unsupported OF protocol')
                return Response(status=501)
            
            if cmd == 'add':
                of_cmd = dp.ofproto.OFPFC_ADD
            elif cmd == 'delete':
                of_cmd = dp.ofproto.ofpfc_delete
            elif cmd == 'reset':
                print 'reset slice: Not implemented'
                return Response(status=404)
            else:
                return Response(status=404)
            
            flow = {'priority': 100, 'table_id':0}
            flow['actions'] = make_vxlan_encap_action(
                eth_src = slg[2].interface[2].mac_address,
                eth_dst = slg[2].interface[2].gateway.mac_address,
                ipv4_src = slg[2].interface[2].ip_address,
                ipv4_dst = slg[0].interface[2].ip_address,
                udp_src = 12345,
                vni = 5000 + slice_id * 10
            )
            flow['actions'].append({"type":"OUTPUT", "port": 2})
            flow['match'] = {'in_port': 1, "dl_type": 2048, "ip_proto": 6, "ipv4_src": dst_ip, "ipv4_dst": src_ip, "tcp_src": dst_port}
            print flow
            _ofctl.mod_flow_entry(dp, flow, of_cmd)
            flow['match'] = {'in_port': 1, "dl_type": 2048, "ip_proto": 17, "ipv4_src": dst_ip, "ipv4_dst": src_ip, "udp_src": dst_port}
            print flow
            _ofctl.mod_flow_entry(dp, flow, of_cmd)
            flow['match'] = {'in_port': 1, "dl_type": 2048, "ip_proto": 1, "ipv4_src": dst_ip, "ipv4_dst": src_ip}
            print flow
            _ofctl.mod_flow_entry(dp, flow, of_cmd)

        return Response(status=200)
    
    def mod_meter_entry(self, req, cmd, **_kwargs):

        try:
            flow = ast.literal_eval(req.body)

        except SyntaxError:
            LOG.debug('invalid syntax %s', req.body)
            return Response(status=400)

        dpid = flow.get('dpid')

        if type(dpid) == str and not dpid.isdigit():
            LOG.debug('invalid dpid %s', dpid)
            return Response(status=400)

        dp = self.dpset.get(int(dpid))

        if dp is None:
            return Response(status=404)

        if cmd == 'add':
            cmd = dp.ofproto.OFPMC_ADD
        elif cmd == 'modify':
            cmd = dp.ofproto.OFPMC_MODIFY
        elif cmd == 'delete':
            cmd = dp.ofproto.OFPMC_DELETE
        else:
            return Response(status=404)

        _ofp_version = dp.ofproto.OFP_VERSION
        _ofctl = supported_ofctl.get(_ofp_version, None)

        if _ofctl is not None and hasattr(_ofctl, 'mod_meter_entry'):
            _ofctl.mod_meter_entry(dp, flow, cmd)

        else:
            LOG.debug('Unsupported OF protocol or \
                request not supported in this OF protocol version')
            return Response(status=501)

        return Response(status=200)

    def mod_group_entry(self, req, cmd, **_kwargs):

        try:
            group = ast.literal_eval(req.body)

        except SyntaxError:
            LOG.debug('invalid syntax %s', req.body)
            return Response(status=400)

        dpid = group.get('dpid')

        if type(dpid) == str and not dpid.isdigit():
            LOG.debug('invalid dpid %s', dpid)
            return Response(status=400)

        dp = self.dpset.get(int(dpid))

        if dp is None:
            return Response(status=404)

        if cmd == 'add':
            cmd = dp.ofproto.OFPGC_ADD
        elif cmd == 'modify':
            cmd = dp.ofproto.OFPGC_MODIFY
        elif cmd == 'delete':
            cmd = dp.ofproto.OFPGC_DELETE
        else:
            return Response(status=404)

        _ofp_version = dp.ofproto.OFP_VERSION
        _ofctl = supported_ofctl.get(_ofp_version, None)

        if _ofctl is not None and hasattr(_ofctl, 'mod_group_entry'):
            _ofctl.mod_group_entry(dp, group, cmd)

        else:
            LOG.debug('Unsupported OF protocol or \
                request not supported in this OF protocol version')
            return Response(status=501)

        return Response(status=200)

    def mod_port_behavior(self, req, cmd, **_kwargs):

        try:
            port_config = ast.literal_eval(req.body)

        except SyntaxError:
            LOG.debug('invalid syntax %s', req.body)
            return Response(status=400)

        dpid = port_config.get('dpid')

        if type(dpid) == str and not dpid.isdigit():
            LOG.debug('invalid dpid %s', dpid)
            return Response(status=400)

        port_no = port_config.get('port_no', 0)
        if type(port_no) == str and not port_no.isdigit():
            LOG.debug('invalid port_no %s', port_no)
            return Response(status=400)

        port_info = self.dpset.port_state[int(dpid)].get(port_no)

        if port_info:
            port_config.setdefault('hw_addr', port_info.hw_addr)
            port_config.setdefault('advertise', port_info.advertised)
        else:
            return Response(status=404)

        dp = self.dpset.get(int(dpid))

        if dp is None:
            return Response(status=404)

        if cmd != 'modify':
            return Response(status=404)

        _ofp_version = dp.ofproto.OFP_VERSION

        _ofctl = supported_ofctl.get(_ofp_version, None)
        if _ofctl is not None:
            _ofctl.mod_port_behavior(dp, port_config)

        else:
            LOG.debug('Unsupported OF protocol')
            return Response(status=501)

        return Response(status=200)

    def send_experimenter(self, req, dpid, **_kwargs):

        if type(dpid) == str and not dpid.isdigit():
            LOG.debug('invalid dpid %s', dpid)
            return Response(status=400)

        dp = self.dpset.get(int(dpid))

        if dp is None:
            return Response(status=404)

        try:
            exp = ast.literal_eval(req.body)

        except SyntaxError:
            LOG.debug('invalid syntax %s', req.body)
            return Response(status=400)

        _ofp_version = dp.ofproto.OFP_VERSION
        _ofctl = supported_ofctl.get(_ofp_version, None)

        if _ofctl is not None and hasattr(_ofctl, 'send_experimenter'):
            _ofctl.send_experimenter(dp, exp)

        else:
            LOG.debug('Unsupported OF protocol')
            return Response(status=501)

        return Response(status=200)


class RestStatsApi(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION,
                    ofproto_v1_2.OFP_VERSION,
                    ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {
        'dpset': dpset.DPSet,
        'wsgi': WSGIApplication
    }

    def __init__(self, *args, **kwargs):
        super(RestStatsApi, self).__init__(*args, **kwargs)
        self.dpset = kwargs['dpset']
        wsgi = kwargs['wsgi']
        self.waiters = {}
        self.data = {}
        self.data['dpset'] = self.dpset
        self.data['waiters'] = self.waiters
        mapper = wsgi.mapper

        wsgi.registory['StatsController'] = self.data
        path = '/stats'
        uri = path + '/switches'
        mapper.connect('stats', uri,
                       controller=StatsController, action='get_dpids',
                       conditions=dict(method=['GET']))

        uri = path + '/desc/{dpid}'
        mapper.connect('stats', uri,
                       controller=StatsController, action='get_desc_stats',
                       conditions=dict(method=['GET']))

        uri = path + '/flow/{dpid}'
        mapper.connect('stats', uri,
                       controller=StatsController, action='get_flow_stats',
                       conditions=dict(method=['GET', 'POST']))

        uri = path + '/aggregateflow/{dpid}'
        mapper.connect('stats', uri,
                       controller=StatsController,
                       action='get_aggregate_flow_stats',
                       conditions=dict(method=['GET', 'POST']))

        uri = path + '/table/{dpid}'
        mapper.connect('stats', uri,
                       controller=StatsController, action='get_table_stats',
                       conditions=dict(method=['GET']))

        uri = path + '/tablefeatures/{dpid}'
        mapper.connect('stats', uri,
                       controller=StatsController, action='get_table_features',
                       conditions=dict(method=['GET']))

        uri = path + '/port/{dpid}'
        mapper.connect('stats', uri,
                       controller=StatsController, action='get_port_stats',
                       conditions=dict(method=['GET']))

        uri = path + '/queue/{dpid}'
        mapper.connect('stats', uri,
                       controller=StatsController, action='get_queue_stats',
                       conditions=dict(method=['GET']))

        uri = path + '/queueconfig/{dpid}/{port}'
        mapper.connect('stats', uri,
                       controller=StatsController, action='get_queue_config',
                       conditions=dict(method=['GET']))

        uri = path + '/meterfeatures/{dpid}'
        mapper.connect('stats', uri,
                       controller=StatsController, action='get_meter_features',
                       conditions=dict(method=['GET']))

        uri = path + '/meterconfig/{dpid}'
        mapper.connect('stats', uri,
                       controller=StatsController, action='get_meter_config',
                       conditions=dict(method=['GET']))

        uri = path + '/meter/{dpid}'
        mapper.connect('stats', uri,
                       controller=StatsController, action='get_meter_stats',
                       conditions=dict(method=['GET']))

        uri = path + '/groupfeatures/{dpid}'
        mapper.connect('stats', uri,
                       controller=StatsController, action='get_group_features',
                       conditions=dict(method=['GET']))

        uri = path + '/groupdesc/{dpid}'
        mapper.connect('stats', uri,
                       controller=StatsController, action='get_group_desc',
                       conditions=dict(method=['GET']))

        uri = path + '/group/{dpid}'
        mapper.connect('stats', uri,
                       controller=StatsController, action='get_group_stats',
                       conditions=dict(method=['GET']))

        uri = path + '/portdesc/{dpid}'
        mapper.connect('stats', uri,
                       controller=StatsController, action='get_port_desc',
                       conditions=dict(method=['GET']))

        uri = path + '/flowentry/{cmd}'
        mapper.connect('stats', uri,
                       controller=StatsController, action='mod_flow_entry',
                       conditions=dict(method=['POST']))

        uri = path + '/flowentry/clear/{dpid}'
        mapper.connect('stats', uri,
                       controller=StatsController, action='delete_flow_entry',
                       conditions=dict(method=['DELETE']))

        uri = path + '/meterentry/{cmd}'
        mapper.connect('stats', uri,
                       controller=StatsController, action='mod_meter_entry',
                       conditions=dict(method=['POST']))

        uri = path + '/groupentry/{cmd}'
        mapper.connect('stats', uri,
                       controller=StatsController, action='mod_group_entry',
                       conditions=dict(method=['POST']))

        uri = path + '/portdesc/{cmd}'
        mapper.connect('stats', uri,
                       controller=StatsController, action='mod_port_behavior',
                       conditions=dict(method=['POST']))

        uri = path + '/experimenter/{dpid}'
        mapper.connect('stats', uri,
                       controller=StatsController, action='send_experimenter',
                       conditions=dict(method=['POST']))

        uri = path + '/slice/{cmd}'
        mapper.connect('stats', uri,
                       controller=StatsController, action='mod_slice',
                       conditions=dict(method=['POST']))


    @set_ev_cls([ofp_event.EventOFPStatsReply,
                 ofp_event.EventOFPDescStatsReply,
                 ofp_event.EventOFPFlowStatsReply,
                 ofp_event.EventOFPAggregateStatsReply,
                 ofp_event.EventOFPTableStatsReply,
                 ofp_event.EventOFPTableFeaturesStatsReply,
                 ofp_event.EventOFPPortStatsReply,
                 ofp_event.EventOFPQueueStatsReply,
                 ofp_event.EventOFPMeterStatsReply,
                 ofp_event.EventOFPMeterFeaturesStatsReply,
                 ofp_event.EventOFPMeterConfigStatsReply,
                 ofp_event.EventOFPGroupStatsReply,
                 ofp_event.EventOFPGroupFeaturesStatsReply,
                 ofp_event.EventOFPGroupDescStatsReply,
                 ofp_event.EventOFPPortDescStatsReply
                 ], MAIN_DISPATCHER)
    def stats_reply_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath

        if dp.id not in self.waiters:
            return
        if msg.xid not in self.waiters[dp.id]:
            return
        lock, msgs = self.waiters[dp.id][msg.xid]
        msgs.append(msg)

        flags = 0
        if dp.ofproto.OFP_VERSION == ofproto_v1_0.OFP_VERSION:
            flags = dp.ofproto.OFPSF_REPLY_MORE
        elif dp.ofproto.OFP_VERSION == ofproto_v1_2.OFP_VERSION:
            flags = dp.ofproto.OFPSF_REPLY_MORE
        elif dp.ofproto.OFP_VERSION == ofproto_v1_3.OFP_VERSION:
            flags = dp.ofproto.OFPMPF_REPLY_MORE

        if msg.flags & flags:
            return
        del self.waiters[dp.id][msg.xid]
        lock.set()

    @set_ev_cls([ofp_event.EventOFPSwitchFeatures,
                 ofp_event.EventOFPQueueGetConfigReply], MAIN_DISPATCHER)
    def features_reply_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath

        if dp.id not in self.waiters:
            return
        if msg.xid not in self.waiters[dp.id]:
            return
        lock, msgs = self.waiters[dp.id][msg.xid]
        msgs.append(msg)

        del self.waiters[dp.id][msg.xid]
        lock.set()
