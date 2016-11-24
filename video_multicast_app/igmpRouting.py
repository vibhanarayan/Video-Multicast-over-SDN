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
from ryu.lib.packet import ether_types, in_proto
from ryu.lib import ip
from ryu.topology import event, switches
from ryu.topology.api import get_link, get_switch, get_host
from ryu.lib.mac import haddr_to_bin
import shortestRouting
import networkx as nx
from MCIP_mapping import MCIPMap


ETHERNET = ethernet.ethernet.__name__
ARP = arp.arp.__name__
IPV4 = ipv4.ipv4.__name__
CONTROLLER_MAC = '08:00:27:a0:d2:9f'
CONTROLLER_IP = '10.0.2.15'

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
        data = None

        #header_list =dict((p.protocol_name, p) for p in pkt)
        header_list = []
        arpPkt = pkt.get_protocol(arp.arp)
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        udp_pkt = pkt.get_protocol(udp.udp)

        if arpPkt is not None:
            header_list.append(ARP)
            ip_src = arpPkt.src_ip
            ip_dst = arpPkt.dst_ip
        elif ip_pkt is not None:
            header_list.append(IPV4)
            ip_src = ip_pkt.src
            ip_dst = ip_pkt.dst

        #self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)
        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        self.ip_to_mac.setdefault(dpid, {})
        if ip_src not in self.ip_to_mac[dpid]:
            self.ip_to_mac[dpid][ip_src] = Entry(in_port, src)

        if ip_src not in self.net:
            self.net.add_node(ip_src)
            self.net.add_edge(dpid, ip_src, {'port':in_port})
            self.net.add_edge(ip_src, dpid)

        #########################################
        """
        If the destination ip of the arp packet received is controller IP,
        then add a rule to forward all packets to controller, also send an arp reply to host.
        """
        if arpPkt is not None and arpPkt.dst_ip == CONTROLLER_IP:
            out_port = ofproto.OFPP_CONTROLLER
            actions = [parser.OFPActionOutput(out_port)]
            #match = parser.OFPMatch(in_port=in_port, eth_dst=dst, arp_spa=ip_src, arp_tpa=ip_dst, eth_type=0x0800)
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, ipv4_src=ip_src, ipv4_dst=ip_dst, eth_type=0x0800)
            self.add_flow(datapath, 1, match, actions)

            arpreply = packet.Packet()
            e = ethernet.ethernet(dst=eth.src, src=CONTROLLER_MAC, ethertype=eth.ethertype)
            a = arp.arp(opcode=arp.ARP_REPLY, src_mac=CONTROLLER_MAC,
                        src_ip=CONTROLLER_IP, dst_mac=arpPkt.src_mac,
                        dst_ip=arpPkt.src_ip)
            arpreply.add_protocol(e)
            arpreply.add_protocol(a)
            arpreply.buffer_id = 0xffffffff
            arpreply.serialize()
            data = arpreply.data

            #print "ARP reply", arpreply
            out_port = in_port
            actions = [parser.OFPActionOutput(out_port)]
            match = parser.OFPMatch(in_port=ofproto.OFPP_CONTROLLER, eth_dst=eth.src, ipv4_src=CONTROLLER_IP, ipv4_dst=arpPkt.src_ip, eth_type=0x0800)
            self.add_flow(datapath, 1, match, actions)

            out = parser.OFPPacketOut(datapath=datapath, buffer_id=arpreply.buffer_id,
                                      in_port=ofproto.OFPP_CONTROLLER, actions=actions, data=data)
            datapath.send_msg(out)

        elif udp_pkt and ip_pkt.dst == CONTROLLER_IP:
            #print "UDP ", udp_pkt
            if udp_pkt.dst_port == 8000:
                video_id = pkt.protocols[-1]
                mcip = self.mcip_obj.assign_mcip(video_id, ip_pkt.src)
                #print "MCIP", self.mcip_obj.mapping, self.mcip_obj.mapping[video_id][0][0]

                reply = packet.Packet()
                reply.add_protocol(ethernet.ethernet(dst=eth.src,
                                   src=eth.dst,
                                   ethertype=eth.ethertype))
                reply.add_protocol(ipv4.ipv4(version=4,
                                   proto=in_proto.IPPROTO_UDP,
                                   src=ip_pkt.dst,
                                   dst=ip_pkt.src))
                reply.add_protocol(udp.udp(dst_port=8000, src_port=8000))
                reply.add_protocol(str(mcip))
                reply.serialize()
                #print "Reply", reply
                reply.buffer_id = ofproto.OFP_NO_BUFFER
                data = reply.data

                actions = [parser.OFPActionOutput(in_port)]
                out = parser.OFPPacketOut(datapath=datapath, buffer_id=reply.buffer_id,
                                          in_port=ofproto.OFPP_CONTROLLER, actions=actions, data=data)
                datapath.send_msg(out)

            elif udp_pkt.dst_port == 8001:
                video_id = pkt.protocols[-1]
                #print "MCIP", video_id, self.mcip_obj.mapping, self.mcip_obj.mapping[video_id][0][0]
                mcip = self.mcip_obj.get_mcip(video_id)
                #print mcip, type(mcip)

                hop_num = 100
                best_mcip = ''
                out_ip = ''
                #print "nodes in set ", self.net.nodes()
                for p in mcip:
                    if p[1] in self.net:
                        path = nx.shortest_path(self.net, ip_pkt.src, p[1])
                        #print "Path ", path
                        if (len(path)-1) < hop_num:
                             hop_num = len(path)-1
                             next = path[path.index(dpid) + 1]
                             out_port = self.net[dpid][next]['port']
                             best_mcip = str(p[0])
                             out_ip = ip_pkt.src

                #print best_mcip
                #reply = packet.Packet(data=str(best_mcip))
                reply = packet.Packet()
                reply.add_protocol(ethernet.ethernet(dst=eth.src,
                                   src=eth.dst,
                                   ethertype=eth.ethertype))
                reply.add_protocol(ipv4.ipv4(version=4,
                                   proto=in_proto.IPPROTO_UDP,
                                   src=ip_pkt.dst,
                                   dst=out_ip))
                reply.add_protocol(udp.udp(src_port=8001, dst_port=8001))
                reply.add_protocol(str(best_mcip))
                reply.serialize()
                #print reply
                reply.buffer_id = ofproto.OFP_NO_BUFFER
                data = reply.data

                actions = [parser.OFPActionOutput(in_port)]
                out = parser.OFPPacketOut(datapath=datapath, buffer_id=reply.buffer_id,
                                          in_port=ofproto.OFPP_CONTROLLER, actions=actions, data=data)
                datapath.send_msg(out)

        ###########################################

        else:
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
