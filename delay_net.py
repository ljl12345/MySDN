from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.topology import event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER, HANDSHAKE_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import arp
from ryu.lib.packet import ipv4
from ryu.lib.packet import tcp
from ryu.topology.api import get_link
from ryu.lib.packet import ether_types
from ryu.app.wsgi import  WSGIApplication
from collections import defaultdict
import network_monitor
from ryu.base.app_manager import lookup_service_brick
from ryu.topology.api import get_switch
from ryu.topology.switches import LLDPPacket
from struct import pack, unpack
from time import time

class delay_net(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {
        "Network_Monitor": network_monitor.Network_Monitor,
        "wsgi": WSGIApplication
    }
    def __init__(self, *args, **kwargs):
        super(delay_net, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.ip_to_mac = {}
        self.mac_to_dpid = {}  # {mac:(dpid,port)}

        self.datapaths = defaultdict(lambda: None)
        self.topology_api_app = self
        self.src_links = defaultdict(lambda: defaultdict(lambda: None))

        self.check_ip_dpid = defaultdict(list)

        self.qos_ip_bw_list = []
        
        self.network_monitor = kwargs["Network_Monitor"]

        self.ip_to_switch = {}
        self.port_name_to_num = {}

        self.ip_to_port = {}  #{ip:(dpid,port)}
        #promise me, use it well :)
        self.pathmod = 0
        self.donum = 0
        self.path = None

        self.echo_delay = defaultdict(lambda:float("-inf"))
        self.lldp_delay = defaultdict(lambda:float("inf"))
        self.switches = None

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None, idle_timeout=0, hard_timeout=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    idle_timeout=idle_timeout,
                                    hard_timeout=hard_timeout,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    idle_timeout=idle_timeout,
                                    hard_timeout=hard_timeout,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):

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
        pkt_arp = pkt.get_protocol(arp.arp)
        pkt_ipv4 = pkt.get_protocol(ipv4.ipv4)
        pkt_tcp = pkt.get_protocol(tcp.tcp)

        dst = eth.dst
        src = eth.src
        dpid = datapath.id

        # self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        # in rest_topology, self.mac_to_port is for the find for host
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src] = in_port
        #get delay
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            try:
                src_dpid, src_port_no = LLDPPacket.lldp_parse(msg.data)
                self.send_echo_request(self.datapaths[src_dpid])
                if self.switches is None:
                    self.switches = lookup_service_brick('switches')
                for port, port_data in self.switches.ports.items():
                    if src_dpid == port.dpid and src_port_no == port.port_no:
                        self.lldp_delay[(src_dpid,dpid)] = port_data.delay
            except:
                return
        # arp handle
        if pkt_arp and pkt_arp.opcode == arp.ARP_REQUEST:
            if pkt_arp.src_ip not in self.ip_to_mac:
                self.ip_to_mac[pkt_arp.src_ip] = src
                self.mac_to_dpid[src] = (dpid, in_port)
                self.ip_to_port[pkt_arp.src_ip] = (dpid, in_port)

            if pkt_arp.dst_ip in self.ip_to_mac:
                #self.logger.info("[PACKET] ARP packet_in.")
                self.handle_arpre(datapath=datapath, port=in_port,
                                  src_mac=self.ip_to_mac[pkt_arp.dst_ip],
                                  dst_mac=src, src_ip=pkt_arp.dst_ip, dst_ip=pkt_arp.src_ip)
            else:
                # to avoid flood when the dst ip not in the network
                if datapath.id not in self.check_ip_dpid[pkt_arp.dst_ip]:
                    self.check_ip_dpid[pkt_arp.dst_ip].append(datapath.id)
                    out_port = ofproto.OFPP_FLOOD
                    actions = [parser.OFPActionOutput(out_port)]
                    data = None
                    if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                        data = msg.data
                    out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                              in_port=in_port, actions=actions, data=data)
                    datapath.send_msg(out)
            return

        elif pkt_arp and pkt_arp.opcode == arp.ARP_REPLY:
            if pkt_arp.src_ip not in self.ip_to_mac:
                self.ip_to_mac[pkt_arp.src_ip] = src
                self.mac_to_dpid[src] = (dpid, in_port)
                self.ip_to_port[pkt_arp.src_ip] = (dpid, in_port)
            dst_mac = self.ip_to_mac[pkt_arp.dst_ip]
            (dst_dpid, dst_port) = self.mac_to_dpid[dst_mac]
            self.handle_arpre(datapath=self.datapaths[dst_dpid], port=dst_port, src_mac=src, dst_mac=dst_mac,
                              src_ip=pkt_arp.src_ip, dst_ip=pkt_arp.dst_ip)
            return

        if pkt_ipv4 and (self.ip_to_port.get(pkt_ipv4.dst)) and (self.ip_to_port.get(pkt_ipv4.src)):
            (src_dpid, src_port) = self.ip_to_port[pkt_ipv4.src]  # src dpid and port
            (dst_dpid, dst_port) = self.ip_to_port[pkt_ipv4.dst]  # dst dpid and port
            self.install_path(src_dpid=src_dpid, dst_dpid=dst_dpid, src_port=src_port, dst_port=dst_port,ev=ev, src=src, dst=dst, pkt_ipv4=pkt_ipv4, pkt_tcp=pkt_tcp)
            #out_port = None
            #if dst in self.mac_to_port[dpid]:
            #    out_port = self.mac_to_port[dpid][dst]
            #else:
             #   out_port = ofproto.OFPP_FLOOD
            #actions = [parser.OFPActionOutput(out_port)]
            #out = parser.OFPPacketOut(datapath = datapath,buffer_id=msg.buffer_id,in_port=msg.match['in_port'],actions=actions, data=None)
            #datapath.send_msg(out)
    def send_pkt(self, datapath, port, pkt):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        pkt.serialize()
        data = pkt.data
        actions = [parser.OFPActionOutput(port=port)]
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER, in_port=ofproto.OFPP_CONTROLLER,actions=actions, data=data)
        datapath.send_msg(out)

    def handle_arpre(self, datapath, port, src_mac, dst_mac, src_ip, dst_ip):
        pkt = packet.Packet()
        pkt.add_protocol(ethernet.ethernet(ethertype=0x0806, dst=dst_mac, src=src_mac))
        pkt.add_protocol(arp.arp(opcode=arp.ARP_REPLY, src_mac=src_mac, src_ip=src_ip, dst_mac=dst_mac, dst_ip=dst_ip))
        self.send_pkt(datapath, port, pkt)
    def install_path(self, src_dpid, dst_dpid, src_port, dst_port, ev, src, dst, pkt_ipv4, pkt_tcp):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        mid_path = None
        mid_path = self.short_path(src=src_dpid, dst=dst_dpid)
        if mid_path is None:
            return
        self.path = None
        t_path = str("path:")
        t_path += str(pkt_ipv4.src) + "-->>"+str(pkt_ipv4.dst)
        self.path = [(src_dpid, src_port)] + mid_path + [(dst_dpid, dst_port)]
        #self.logger.info("path : %s", str(self.path))
        total = 0
        src_de = src_dpid
        path_1 = str(pkt_ipv4.src)+"->"
        t_num = 0
        for node_num in range(1,26):
            for lldp_dst in range(1,26) :
                result_delay = (self.lldp_delay[(node_num,lldp_dst)]+self.lldp_delay[(lldp_dst,node_num)]-self.echo_delay[lldp_dst]-self.echo_delay[node_num])/2
                if result_delay != float('inf') and node_num < lldp_dst:
                    self.logger.info("src_node:%d, dst_node:%d,delay:%f",node_num,lldp_dst,result_delay*1000)
        for (temp_src, temp_dst) in self.path:
                if t_num == 1:
                    path_1 += "s"+str(temp_src) + "->"
                    t_num = 0
                    if src_de == temp_src:
                        total += 0;
                    else:
                        total += self.lldp_delay[(src_de, temp_src)] + self.lldp_delay[(temp_src, src_de)] - self.echo_delay[temp_src]- self.echo_delay[src_de]
                    src_de = temp_src
                    continue
                t_num += 1
        path_1 += str(pkt_ipv4.dst)
        #self.logger.info("%s", t_path)
        self.logger.info("total delay:%f", total*1000/2)
        print(path_1)
        for i in xrange(len(self.path) - 2, -1, -2):
            datapath_path = self.datapaths[self.path[i][0]]
            match = parser.OFPMatch(in_port=self.path[i][1], eth_src=src, eth_dst=dst, eth_type=0x0800,ipv4_src=pkt_ipv4.src, ipv4_dst=pkt_ipv4.dst)

            if i < (len(self.path) - 2):
                actions = [parser.OFPActionOutput(self.path[i + 1][1])]
            else:
                actions = [parser.OFPActionSetField(eth_dst=self.ip_to_mac.get(pkt_ipv4.dst)),
                            parser.OFPActionOutput(self.path[i + 1][1])]

            self.add_flow(datapath_path, 100, match, actions, idle_timeout=5, hard_timeout=0)
        # time_install = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')
        # self.logger.info("time_install: %s", time_install)
    @set_ev_cls(ofp_event.EventOFPEchoReply, [HANDSHAKE_DISPATCHER, CONFIG_DISPATCHER, MAIN_DISPATCHER])
    def echo_reply_handler(self, ev):
        #self.echo_delay[ev.msg.datapath.id] = time.time() - eval(ev.msg.data)
        self.echo_delay[ev.msg.datapath.id] = ev.timestamp - unpack('!d', ev.msg.data)[0]

    def send_echo_request(self, datapath):
       # datapath.send_msg(datapath.ofproto_parser.OFPEchoRequest(datapath, data="%.6f"%time.time()))

        datapath.send_msg(datapath.ofproto_parser.OFPEchoRequest(datapath, pack('!d',time())))

    def short_path(self, src, dst, bw=0):
        if src == dst:
            return []
        result = defaultdict(lambda: defaultdict(lambda:None))
        total_delay = defaultdict(lambda: None)
        def delay(src, dst):
            return self.lldp_delay[src,dst] + self.lldp_delay[dst,src]- self.echo_delay[src]-self.echo_delay[dst]
        # the node is checked
        seen = [src]

        # the total_delay to src
        total_delay[src] = 0

        while len(seen) < len(self.src_links):
            node = seen[-1]
            if node == dst:
                break
            for (temp_src, temp_dst) in self.src_links[node]:
                if temp_dst not in seen:
                    temp_src_port = self.src_links[node][(temp_src, temp_dst)][0]
                    temp_dst_port = self.src_links[node][(temp_src, temp_dst)][1]
                    if (total_delay[temp_dst] is None) or (total_delay[temp_dst] > total_delay[temp_src] + delay(src=temp_src, dst=temp_dst)):
                        total_delay[temp_dst] = total_delay[temp_src] + delay(src=temp_src,dst=temp_dst)
                        # result = {"dpid":(link_src, src_port, link_dst, dst_port)}
                        result[temp_dst] = (temp_src, temp_src_port, temp_dst, temp_dst_port)
            min_node = None
            min_path = 999
            # get the min_path node
            for temp_node in total_delay:
                if (temp_node not in seen) and (total_delay[temp_node] is not None):
                    if total_delay[temp_node] < min_path:
                        min_node = temp_node
                        min_path = total_delay[temp_node]
            if min_node is None:
                break
            seen.append(min_node)

        path = []

        if dst not in result:
            return None

        while (dst in result) and (result[dst] is not None):
            path = [result[dst][2:4]] + path
            path = [result[dst][0:2]] + path
            dst = result[dst][0]
        #self.logger.info("path : %s", str(path))
        return path

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                del self.datapaths[datapath.id]
        #self.logger.info("datapaths : %s", self.datapaths)

    @set_ev_cls([event.EventSwitchEnter, event.EventSwitchLeave, event.EventPortAdd, event.EventPortDelete,
        event.EventPortModify, event.EventLinkAdd, event.EventLinkDelete])
    def get_topology(self, ev):
        links_list = get_link(self.topology_api_app, None)
        self.src_links.clear()
        for link in links_list:
            sw_src = link.src.dpid
            sw_dst = link.dst.dpid
            src_port = link.src.port_no
            dst_port = link.dst.port_no
            src_port_name = link.src.name
            dst_port_name = link.dst.name
            self.port_name_to_num[src_port_name] = src_port
            self.port_name_to_num[dst_port_name] = dst_port
            self.src_links[sw_src][(sw_src, sw_dst)] = (src_port, dst_port)
            self.src_links[sw_dst][(sw_dst, sw_src)] = (dst_port, src_port)
            # self.logger.info("****src_port_name : %s", str(src_port_name))
            # self.logger.info("src_links : %s", str(self.src_links))
            # self.logger.info("port_name_to_num : %s", str(self.port_name_to_num))

