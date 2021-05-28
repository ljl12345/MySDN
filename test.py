from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet

from ryu.lib.packet import ether_types
class LearningSwitch(app_manager.RyuApp):
	OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
 	def __init__(self, *args, **kwargs):
 		super(LearningSwitch, self).__init__(*args, **kwargs)
		self.mac_to_port = {}

 	def add_flow(self, datapath, priority, match, actions, buffer_id = None):
 		dp = datapath
 		ofp = dp.ofproto
 		parser = dp.ofproto_parser
 		
		inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
 		mod = parser.OFPFlowMod(datapath=dp, priority=priority, match=match,instructions=inst)
 		dp.send_msg(mod)

	@set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
	def switch_features_handler(self, ev):
		msg = ev.msg
		dp = msg.datapath
		ofp = dp.ofproto
		parser = dp.ofproto_parser

		match = parser.OFPMatch()
 		actions = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER,ofp.OFPCML_NO_BUFFER)]
		self.add_flow(dp, 0, match, actions)

	# handle packet_in message
	@set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
	def packet_in_handler(self, ev):
		msg = ev.msg
		dp = msg.datapath
		ofp = dp.ofproto
		parser = dp.ofproto_parser

		#the identity of switch
		dpid = dp.id
		self.mac_to_port.setdefault(dpid, {})
		
		#the port that receive the packet
		in_port = msg.match['in_port']
		
		pkt = packet.Packet(msg.data)
 		eth_pkt = pkt.get_protocol(ethernet.ethernet)
 		
		if eth_pkt.ethertype == ether_types.ETH_TYPE_LLDP:
			return
		# get the mac
 		dst = eth_pkt.dst
 		src = eth_pkt.src

 		# we can use the logger to print some useful information
 		self.logger.info('packet: %s %s %s %s', dpid, src, dst, in_port)
		
		self.mac_to_port[dpid][src] = in_port
		if dst in self.mac_to_port[dpid]:
			out_port = self.mac_to_port[dpid][dst]
		else:
			out_port = ofp.OFPP_FLOOD
		
		actions = [parser.OFPActionOutput(out_port)]
		
		if out_port != ofp.OFPP_FLOOD:
			match = parser.OFPMatch(in_port = in_port, eth_dst = dst, eth_src = src)
			self.add_flow(dp,1, match,actions)
			self.logger.info("send packet to switch port: %s",out_port)
		out = parser.OFPPacketOut(datapath=dp, buffer_id=msg.buffer_id,in_port=in_port,actions=actions)
		dp.send_msg(out)
