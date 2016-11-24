from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3, ofproto_v1_0
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet, arp, ipv4, udp
from ryu.lib.packet import ether_types, in_proto
from ryu.lib import ip
from ryu.topology import event, switches
from ryu.topology.api import get_link, get_switch, get_host
from ryu.app.wsgi import ControllerBase
from ryu.lib.mac import haddr_to_bin
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


class ShortestRouting(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(ShortestRouting, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.topology_api_app = self
        self.net = nx.DiGraph()
        self.ip_to_mac = {}
        self.mcip_obj = MCIPMap()

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)


    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]

        mod = datapath.ofproto_parser.OFPFlowMod(datapath=datapath, match=match, cookie=0,
                            command=ofproto.OFPFC_ADD,idle_timeout=0, hard_timeout=0,
                            priority=priority,flags=ofproto.OFPFF_SEND_FLOW_REM,
                            instructions=inst)
        datapath.send_msg(mod)


    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
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
                    #match = parser.OFPMatch(in_port=in_port, eth_dst=dst, arp_spa=ip_src, arp_tpa=ip_dst, eth_type=0x0800)
                    match = parser.OFPMatch(in_port=in_port, eth_dst=dst, ipv4_src=ip_src, ipv4_dst=ip_dst, eth_type=0x0800)
                    self.add_flow(datapath, 1, match, actions)
                #elif IPV4 in header_list:
                    #match = parser.OFPMatch(in_port=in_port, eth_dst=dst, ipv4_src=ip_src, ipv4_dst=ip_dst, eth_type=0x0800)
                #self.add_flow(datapath, 1, match, actions)

            data = None
            if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                data = msg.data

            out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                      in_port=in_port, actions=actions, data=data)
            datapath.send_msg(out)


    @set_ev_cls(event.EventSwitchEnter)
    def get_topology(self, ev):
        switch_list = get_switch(self.topology_api_app, None)
        switches = []
        for switch in switch_list:
            switches.extend([switch.dp.id])
        self.net.add_nodes_from(switches)

        links_list = get_link(self.topology_api_app, None)
        links = []
        for link in links_list:
            links.extend([(link.src.dpid,link.dst.dpid,{'port':link.src.port_no})])
        self.net.add_edges_from(links)

        links = []
        for link in links_list:
            links.extend([(link.dst.dpid,link.src.dpid,{'port':link.dst.port_no})])
        self.net.add_edges_from(links)
        print "nodes ", self.net.nodes()
        print "edges ", self.net.edges()

