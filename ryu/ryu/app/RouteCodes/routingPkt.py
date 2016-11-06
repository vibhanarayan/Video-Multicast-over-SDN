from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.topology import event, switches
from ryu.topology.api import get_link, get_switch, get_host
from ryu.app.wsgi import ControllerBase
from ryu.lib.mac import haddr_to_bin
import networkx as nx


class RoutingPkt(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(RoutingPkt, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.topology_api_app = self
        self.net = nx.DiGraph()

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

        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        #self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        if src not in self.net:
            self.net.add_node(src)
            self.net.add_edge(dpid, src, {'port':in_port})
            self.net.add_edge(src, dpid)

        if dst in self.net:
            #print "dst present", src, dst
            path = nx.shortest_path(self.net,src,dst)
            #print "path "
            next = path[path.index(dpid) + 1]
            out_port = self.net[dpid][next]['port']
            #print "in port ", in_port
            #print "out port ", out_port
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
            self.add_flow(datapath, 1, match, actions)

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

