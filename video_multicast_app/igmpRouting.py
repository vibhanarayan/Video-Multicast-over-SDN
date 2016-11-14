# Copyright (C) 2016 Nippon Telegraph and Telephone Corporation.
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

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib import igmplib
from ryu.lib.dpid import str_to_dpid
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet, arp, ipv4, igmp, udp
from ryu.lib.packet import ether_types
from ryu.lib import ip
import shortestRouting
import networkx as nx

ETHERNET = ethernet.ethernet.__name__
ARP = arp.arp.__name__
IPV4 = ipv4.ipv4.__name__

class Entry (object):
    def __init__ (self, port, mac):
        self.port = port
        self.mac = mac

class IgmpRouting(shortestRouting.ShortestRouting):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {'igmplib': igmplib.IgmpLib}

    def __init__(self, *args, **kwargs):
        super(IgmpRouting, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.ip_to_mac = {}
        self._snoop = kwargs['igmplib']
        self._snoop.set_querier_mode(
            dpid=str_to_dpid('0000000000000001'), server_port=2)

    @set_ev_cls(igmplib.EventPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return

        dst = eth.dst
        src = eth.src
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        #header_list =dict((p.protocol_name, p) for p in pkt)
        header_list = []
        arpPkt = pkt.get_protocol(arp.arp)
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        if arpPkt is not None:
            header_list.append(ARP)
            ip_src = arpPkt.src_ip
            ip_dst = arpPkt.dst_ip
        elif ip_pkt is not None:
            header_list.append(IPV4)
            ip_src = ip_pkt.src
            ip_dst = ip_pkt.dst

        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)
        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        self.ip_to_mac.setdefault(dpid, {})
        if ip_src not in self.ip_to_mac[dpid]:
            self.ip_to_mac[dpid][ip_src] = Entry(in_port, src)

        if ip_src not in self.net:
            self.net.add_node(ip_src)
            self.net.add_edge(dpid, ip_src, {'port':in_port})
            self.net.add_edge(ip_src, dpid)

        if ip_dst in self.net:
            #find the unweighted shortest path i.e. minimum hop path
            path = nx.shortest_path(self.net,ip_src,ip_dst)
            next = path[path.index(dpid) + 1]
            out_port = self.net[dpid][next]['port']
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        if out_port != ofproto.OFPP_FLOOD:
            #add flow basd on the IP address
            if ARP in header_list:
                match = parser.OFPMatch(in_port=in_port, eth_dst=dst, arp_spa=ip_src, arp_tpa=ip_dst, eth_type=0x0800)
            elif IPV4 in header_list:
                match = parser.OFPMatch(in_port=in_port, eth_dst=dst, ipv4_src=ip_src, ipv4_dst=ip_dst, eth_type=0x0800)
            self.add_flow(datapath, 1, match, actions)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)


    @set_ev_cls(igmplib.EventMulticastGroupStateChanged,
                MAIN_DISPATCHER)
    def _status_changed(self, ev):
        msg = {
            igmplib.MG_GROUP_ADDED: 'Multicast Group Added',
            igmplib.MG_MEMBER_CHANGED: 'Multicast Group Member Changed',
            igmplib.MG_GROUP_REMOVED: 'Multicast Group Removed',
        }
        self.logger.info("%s: [%s] querier:[%s] hosts:%s",
                         msg.get(ev.reason), ev.address, ev.src,
                         ev.dsts)
