# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
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
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet, ipv4, arp
from ryu.lib.packet import ether_types


class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.ip_to_mac = {}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    def l3_resolve(self, did, ip):
        if ip in self.ip_to_mac:
            if self.ip_to_mac[ip] in self.mac_to_port[did]:
                return self.mac_to_port[did][self.ip_to_mac[ip]]
            else:
                self.logger.info("[L2] Unknown mac {}".format(self.ip_to_mac[ip]))
                return None
        else:
            self.logger.info("[L3] Unknown ip {}".format(ip))
        return None

    def add_l3_flow(self, datapath, host1, host2, proto):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        port1 = self.l3_resolve(datapath.id, host1)
        port2 = self.l3_resolve(datapath.id, host2)
        if port1 == None or port2 == None:
            return
        self.logger.info('[L3] flow between {} and {}'.format(host1, host2))
        # host1 -> host2
        actions = [parser.OFPActionOutput(port2)]
        match = parser.OFPMatch(dl_type = 0x800,
                                nw_src = struct.unpack('!I', ipv4_to_bin(host1))[0],
                                nw_dst = struct.unpack('!I', ipv4_to_bin(host2))[0],
                                nw_proto = proto)
        mod = parser.OFPFlowMod(datapath=datapath,
                                match=match,
                                cookie=0,
                                command=ofproto.OFPFC_ADD,
                                idle_timeout=20,
                                hard_timeout=0,
                                priority=1000,
                                flags=ofproto.OFPFF_SEND_FLOW_REM,
                                actions=actions)
        datapath.send_msg(mod)
        # host2 -> host1
        actions = [parser.OFPActionOutput(port1)]
        match = parser.OFPMatch(dl_type = 0x800,
                                nw_src = struct.unpack('!I', ipv4_to_bin(host2))[0],
                                nw_dst = struct.unpack('!I', ipv4_to_bin(host1))[0],
                                nw_proto = proto)
        mod = parser.OFPFlowMod(datapath=datapath,
                                match=match,
                                cookie=0,
                                command=ofproto.OFPFC_ADD,
                                idle_timeout=20,
                                hard_timeout=0,
                                priority=1000,
                                flags=ofproto.OFPFF_SEND_FLOW_REM,
                                actions=actions)
        datapath.send_msg(mod)

    def learn_host(self, datapath, pkt, in_port):
        eth_pkt = pkt.get_protocol(ethernet.ethernet)
        if eth_pkt != None:
            mac = eth_pkt.src
            if datapath.id not in self.mac_to_port:
                self.mac_to_port[datapath.id] = {}
            self.mac_to_port[datapath.id][mac] = in_port
            ip_pkt = pkt.get_protocol(ipv4.ipv4)
            if ip_pkt != None:
                host1 = []
                host2 = []
                host1.append(ip_pkt.src)
                host2.append(ip_pkt.dst)
                self.ip_to_mac[host1[0]] = mac
                proto = ip_pkt.proto
                """
                if proto == 6:
                    tcp_pkt = pkt.get_protocol(tcp.tcp)
                    host1.append(tcp_pkt.src_port)
                    host2.append(tcp_pkt.dst_port)
                    if host1[1] == self.PRIORITY_PORT or host2[1] == self.PRIORITY_PORT:
                        # add prioritary flow
                        self.add_qos_l4_flow(datapath, host1, host2, proto, 7)
                    else:
                        # add non prioritary flow
                        self.add_qos_l4_flow(datapath, host1, host2, proto, 1)
                elif proto == 0x11:
                    udp_pkt = pkt.get_protocol(udp.udp)
                    host1.append(udp_pkt.src_port)
                    host2.append(udp_pkt.dst_port)
                    if host1[1] == self.PRIORITY_PORT or host2[1] == self.PRIORITY_PORT:
                        # add prioritary flow
                        self.add_qos_l4_flow(datapath, host1, host2, proto, 7)
                    else:
                        # add non prioritary flow
                        self.add_qos_l4_flow(datapath, host1, host2, proto, 1)
                else:
                """
                self.add_l3_flow(datapath, host1[0], host2[0], proto)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
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

        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        # learn a mac address to avoid FLOOD next time.
        self.learn_host(datapath, pkt, in_port)
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
            # verify if we have a valid buffer_id, if yes avoid to send both
            # flow_mod & packet_out
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 1, match, actions)
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
