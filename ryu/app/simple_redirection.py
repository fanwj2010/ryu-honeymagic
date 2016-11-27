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
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto import ofproto_v1_3_parser
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import tcp
from ryu.lib.packet import ipv4
from ryu.honeyapp.session import Session
from ryu.honeyapp.exceptions import CustomException, badStateException
import ryu.controller.dpset
from ryu.controller.dpset import EventDP
import array
import pprint
from ryu.lib.packet import ether_types

from ryu.ofproto.ofproto_v1_2 import OFPG_ANY
from ryu.ofproto.ofproto_v1_3 import OFP_VERSION
from ryu.lib.mac import haddr_to_bin

class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.sessions = {}

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
            mod = parser.OFPFlowMod(datapath=datapath, idle_timeout=130, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, idle_timeout=130, priority=priority,
                                    match=match, instructions=inst)

        #print "installing flow mod with priority " + str(priority) + " match fields " + str(match) + " actions " + str(actions)
        self.logger.info("installing flow mod with priority %s match fields %s actions %s",str(priority), str(match), str(actions))
        datapath.send_msg(mod)


    def prepare_backward_match_action(self, pkt, parser, ofproto):
        ipd = pkt.get_protocol(ipv4.ipv4)
        tcpd = pkt.get_protocol(tcp.tcp)

        match = parser.OFPMatch(eth_type=0x800, ipv4_dst=ipd.src, ip_proto=6, tcp_src=tcpd.dst_port, tcp_dst=tcpd.src_port)

        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]

        return match, actions


    def manage_comm(self, pkt, ev):
	msg = ev.msg
 	datapath = msg.datapath
	dpid = datapath.id
	ofproto = datapath.ofproto
	parser = datapath.ofproto_parser
	in_port = msg.match['in_port']
	
	pkt_ethernet = pkt.get_protocol(ethernet.ethernet)
	pkt_ipv4 = pkt.get_protocol(ipv4.ipv4)
	pkt_tcp = pkt.get_protocol(tcp.tcp)	
	
	src_ip = pkt_ipv4.src
	dst_ip = pkt_ipv4.dst

	# Parsing of packet and getting payload
        for p in pkt:
           if isinstance(p, array.ArrayType):
                payload = str(bytearray(p))
        # Make sure variable payload is set
        try:
           payload
	   self.logger.info("The payload is set.")		
        except NameError:
           payload = None	
	   self.logger.info("The payload is none.")	

        if src_ip in self.sessions:
           if pkt_tcp.src_port in self.sessions[src_ip]:
              sess = self.sessions[src_ip][pkt_tcp.src_port]
              self.logger.info("ipv4 src is in sessions, packet_in from switch=%s",dpid)
           else:
              sess = Session(src_ip, pkt_tcp.src_port, pkt, dst_ip, pkt_ethernet.dst)
              self.sessions[src_ip] = {}
              self.sessions[src_ip][pkt_tcp.src_port] = sess
              self.logger.info("ipv4 src not in sessions, packet_in from switch=%s",dpid)
        else:
           sess = Session(src_ip, pkt_tcp.src_port, pkt, dst_ip, pkt_ethernet.dst)
           self.sessions[src_ip] = {}
           self.sessions[src_ip][pkt_tcp.src_port] = sess
           self.logger.info("ipv4 src not in sessions, packet_in from switch=%s",dpid)

        
        if sess.getState() == Session.SESSIONTERMINATED:
	   dst = pkt_ethernet.dst 
           if dst in self.mac_to_port[dpid]:
              out_port = self.mac_to_port[dpid][dst]	
           else:
              out_port = ofproto.OFPP_FLOOD
           data = msg.data
           actions = [parser.OFPActionOutput(out_port)]
           out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port, actions=actions, data=data)
           datapath.send_msg(out)
           self.logger.info("ACK_FIN Pkt from attacker is forwarded.") 	


        if sess.getState() == Session.SESSIONSJOINED:           
           dst = pkt_ethernet.dst 
           if dst in self.mac_to_port[dpid]:
              out_port = self.mac_to_port[dpid][dst]	
           else:
              out_port = ofproto.OFPP_FLOOD
           data = msg.data
           actions = [parser.OFPActionOutput(out_port)]
           out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port, actions=actions, data=data)
           datapath.send_msg(out)
           self.logger.info("Pkt from attacker is forwarded.")
           
           if pkt_tcp.bits == 1 | 1 << 4:
              #if src_ip in self.sessions:
              #del self.sessions[src_ip]
              sess.setState(Session.SESSIONTERMINATED)
              self.logger.info("ACK_FIN Pkt is sent, Session is terminated by the attacker!!!!!!!!!!!!!!!!!!") 
           return
                        

        #SYN IS SET, MEANS WE ARE DECLARING A NEW SESSION AND STORE THE ORIGINAL PACKET. SENDING A SYN ACK RESPONSE
        if pkt_tcp.bits & 0x2 and sess.getState() == Session.INITIALSESSION: 
           self.logger.info("session state = %s", sess.getState())
	   sess.setState(Session.SYNRECV)
           self.logger.info("SYN is received.") 

           #Generating SYN_ACK response to the TCP SYN
           syn_ack_pkt = sess.generateSYNACKtoSYN()
           data = syn_ack_pkt.data

           actions = [parser.OFPActionOutput(in_port)]
           out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER, in_port=ofproto.OFPP_CONTROLLER, actions=actions, data=data)
           datapath.send_msg(out) 
           sess.setState(Session.SYNACKSENT)
           self.logger.info("SYN_ACK is sent.")
           return 
        #else:
        #   raise badStateException('SYN_ACK failed ')
        #   return

        if pkt_tcp.bits & 0x2 and sess.getState() == Session.SYNSENT:
           self.logger.info("session state = %s", sess.getState())
           hp_mac = pkt_ethernet.dst
           if hp_mac in self.mac_to_port[dpid]:
              out_port = self.mac_to_port[dpid][hp_mac]	
           else:
              out_port = ofproto.OFPP_FLOOD
           syn_pkt = sess.generateSYNpkt()
           data = syn_pkt.data
           actions = [parser.OFPActionOutput(out_port)]
           out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,in_port=ofproto.OFPP_CONTROLLER, actions=actions, data=data)
           datapath.send_msg(out)
           sess.setState(Session.SYNSENT)
	   self.logger.info("SYN is forwarded.")
           return

        #else:
        #   raise badStateException('SYN forward is failed ')
        #   return


        #ACK is SET
        if pkt_tcp.bits & 1 << 4 :
           try:
               #sess = self.sessions[src_ip][pkt_tcp.src_port]
               if sess.getState() == Session.SYNACKSENT:
                  # this is probably a ACK to SYN_ACK
		  if payload is None:
                      sess.saveACKpkt(pkt)
                      sess.setState(Session.ACKRECV)
                      self.logger.info("ACK is recieved, Waiting for the first payload packet")
                      return
                  else:
                      raise badStateException('Received ACK with payload in state ')
                      return


	       if sess.getState() == Session.ACKRECV:
                  # We should catch the first payload now
                  if payload is not None and pkt_tcp.bits & 1 << 3:
                      #request = payload.split('\n', 1)[0]
                      #print 'Request is ', request
                      #print 'Payload is', payload
                      #sess.setRequestURI(request)
                      sess.savePAYLOADpkt(pkt)
                      sess.setPayload(payload)
                      sess.setState(Session.PAYLOADRECV)
                      self.logger.info("Payload is received: %s", payload)
                      
                      hp_mac = pkt_ethernet.dst                   
             
                      syn_pkt = sess.generateSYNpkt()
		      
                      match, actions = self.prepare_backward_match_action(syn_pkt, parser, ofproto)
                      self.add_flow(datapath, 2, match, actions)
                      data = syn_pkt.data


                      #TODO make sure mac address is in this table else create a ARP request ?!
                      if hp_mac in self.mac_to_port[dpid]:
                          out_port = self.mac_to_port[dpid][hp_mac]
                          #check if the traffic is malicious
                          if hp_mac == '02:fd:00:00:02:01' and dpid == 1:
	                     self.mac_to_port[dpid][hp_mac] = 4
	                     out_port = 4
			     sess.setOutport(out_port)		
                      else:
                          out_port = ofproto.OFPP_FLOOD
		     
                      actions = [parser.OFPActionOutput(out_port)]
                      out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,
                                                  in_port=ofproto.OFPP_CONTROLLER, actions=actions, data=data)
                      datapath.send_msg(out)
                      sess.setState(Session.SYNSENT)
	              self.logger.info("SYN is sent.")
                      return
                  else:
                      raise badStateException('We did not received ACK with payload in state ' )

           except Exception:
               print Exception.message
               #TODO update state

    def manage_backward_comm(self, pkt, ev):
        msg = ev.msg
        in_port = msg.match['in_port']
        datapath = msg.datapath
        dpid = datapath.id
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        pkt_ipv4 = pkt.get_protocol(ipv4.ipv4)
        pkt_tcp = pkt.get_protocol(tcp.tcp)
	pkt_ethernet = pkt.get_protocol(ethernet.ethernet)

        sess = self.sessions[pkt_ipv4.dst][pkt_tcp.dst_port]
        
        self.logger.info("packet_in  from switch=%s src=%s dst=%s inport=%s", dpid, pkt_ethernet.src, pkt_ethernet.dst, in_port)
        

        if sess.getState() == Session.SESSIONTERMINATED:
	   dst = pkt_ethernet.dst 
           if dst in self.mac_to_port[dpid]:
              out_port = self.mac_to_port[dpid][dst]	
           else:
              out_port = ofproto.OFPP_FLOOD
           data = msg.data
           actions = [parser.OFPActionOutput(out_port)]
           out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port, actions=actions, data=data)
           datapath.send_msg(out)
           self.logger.info("ACK_FIN Pkt from honeypot is forwarded.") 	


        if sess.getState() == Session.SESSIONSJOINED:
           #if pkt_tcp.bits == 1 << 4 | 1 << 1:
           dst = pkt_ethernet.dst 
           if dst in self.mac_to_port[dpid]:
              out_port = self.mac_to_port[dpid][dst]	
           else:
              out_port = ofproto.OFPP_FLOOD
           data = msg.data
           actions = [parser.OFPActionOutput(out_port)]
           out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port, actions=actions, data=data)
           datapath.send_msg(out)
           self.logger.info("Pkt from honeypot is forwarded.")

           if pkt_tcp.bits == 1 | 1 << 4:
                 #if pkt_ipv4.dst in self.sessions:
                 #del self.sessions[pkt_ipv4.dst]
              sess.setState(Session.SESSIONTERMINATED)
              self.logger.info("ACK_FIN Pkt is sent, Session is terminated by the honeypot!!!!!!!!!!!!!!!!") 

           return
       

        if sess.getState() == Session.PAYLOADSENT:
           self.logger.info("The payload from honeypot is comming.")
           dst = pkt_ethernet.dst 
           if dst in self.mac_to_port[dpid]:
              out_port = self.mac_to_port[dpid][dst]	
           else:
              out_port = ofproto.OFPP_FLOOD
           data = msg.data
           actions = [parser.OFPActionOutput(out_port)]
           out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port, actions=actions, data=data)
           datapath.send_msg(out)
           sess.setState(Session.SESSIONSJOINED)
           self.logger.info("Session is joined.")
           return

        if sess.getState() == Session.SYNSENT:
            # SYN and ACK is set
            if pkt_tcp.bits == 1 << 4 | 1 << 1:
                sess.setState(Session.SYNACKRECV)
                self.logger.info("SYN_ACK is received.")
                sess.saveHPsynseq(pkt_tcp.seq)
                sess.saveSYNACKpkt(pkt)

                #GENERATE ACK TO SYN ACK
                ack_pkt = sess.generateACKtoSYNACK()

                data = ack_pkt.data

                actions = [parser.OFPActionOutput(in_port)]
                out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER, in_port=ofproto.OFPP_CONTROLLER, actions=actions, data=data)
                datapath.send_msg(out)
		sess.setState(Session.ACKSENT)
		self.logger.info("ACK is sent.")              
                 
                self.logger.info("dpid=%s for set the ofsoftswitch13", dpid)
                   
                #SRCmatch, direction to Honeypot
                match = parser.OFPMatch(eth_type=0x800, eth_dst=pkt_ethernet.src, ip_proto=6, ipv4_src=sess.src_ip, ipv4_dst=pkt_ipv4.src, tcp_src=sess.src_port, tcp_dst=pkt_tcp.src_port)
		hp_mac = pkt_ethernet.src
                self.logger.info("hp_mac=%s", hp_mac)

                out_port_tohp = None
                if hp_mac in self.mac_to_port[dpid]:
                    out_port_tohp = self.mac_to_port[dpid][hp_mac]		
                else:
                    out_port_tohp = ofproto.OFPP_FLOOD
                self.logger.info("out_port_tohp=%s", out_port_tohp)
                ack_diff = sess.getACKDiff()
                actions = [parser.OFPActionSetField(tcp_ack_diff=ack_diff), parser.OFPActionOutput(out_port_tohp)]
                self.add_flow(datapath, 3, match, actions)
                self.logger.info("set flow mod in dpid %s, outport %s, direct to hp", dpid, out_port_tohp)
		   
                #DSTmatch, direction from Honeypot
                match = parser.OFPMatch(eth_type=0x800, eth_dst=pkt_ethernet.dst, ip_proto=6, ipv4_src=pkt_ipv4.src, ipv4_dst=sess.src_ip, tcp_src=pkt_tcp.src_port, tcp_dst=sess.src_port)
                atk_mac = pkt_ethernet.dst
                self.logger.info("atk_mac=%s", atk_mac)
                out_port_fromhp = None
                if atk_mac in self.mac_to_port[dpid]:
                    out_port_fromhp = self.mac_to_port[dpid][atk_mac]		
                else:
                    out_port_fromhp = ofproto.OFPP_FLOOD
                self.logger.info("out_port_fromhp=%s", out_port_fromhp)
                seq_diff = sess.getSEQDiff()
                actions = [parser.OFPActionSetField(tcp_seq_diff=seq_diff), parser.OFPActionOutput(out_port_fromhp)]
                self.add_flow(datapath, 3, match, actions)
                self.logger.info("set flow mod in dpid %s, outport %s, direct from hp", dpid, out_port_fromhp)

                #TODO send the payload pkt 
                payload_pkt = sess.generatePAYLOADpkt()
                out_port = sess.getOutport()
                actions = [parser.OFPActionOutput(out_port)]
                data = payload_pkt.data
                out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER, in_port=ofproto.OFPP_CONTROLLER, actions=actions, data=data)
                datapath.send_msg(out)
      	        sess.setState(Session.PAYLOADSENT)
                self.logger.info("Payload is sent.")
                return

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes", ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        # pkt = packet.Packet(msg.data)
        pkt = packet.Packet(array.array('B', ev.msg.data))
	pkt_ipv4 = pkt.get_protocol(ipv4.ipv4)
        pkt_tcp = pkt.get_protocol(tcp.tcp)
        pkt_ethernet = pkt.get_protocol(ethernet.ethernet)
	
	if pkt_ethernet.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return

        # If TCP communication, check if it has been an establisehd session 
        if pkt_ipv4 is not None:
              if pkt_tcp is not None:
		   if pkt_ipv4.dst not in self.sessions:
                      self.logger.info("\nipv4 dst not in sessions, packet_in from switch=%s ", datapath.id) 
                      self.logger.info("then ipv4 dst =%s, tcp dst =%s ", pkt_ipv4.dst, pkt_tcp.dst_port) 
                      self.manage_comm(pkt, ev) 
                      return
                   elif pkt_ipv4.dst in self.sessions:
                      self.logger.info("\nipv4 dst in sessions, packet_in from switch=%s ", datapath.id) 
                      if pkt_tcp.dst_port in self.sessions[pkt_ipv4.dst]: 
                           self.logger.info("then ipv4 dst =%s, tcp dst =%s ", pkt_ipv4.dst, pkt_tcp.dst_port) 
                           self.manage_backward_comm(pkt, ev) 
                           return


        dst = pkt_ethernet.dst
        src = pkt_ethernet.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})


        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port
        
	#set the specific out port 	
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
	    if dst == '02:fd:00:00:02:01' and dpid == 1:
	       self.mac_to_port[dpid][dst] = 4
	       out_port = 4		
        else:
            out_port = ofproto.OFPP_FLOOD
	    
	
	#if out_port < 10 :
	#	self.logger.info("packet_in from switch=%s src=%s dst=%s inport=%s outport=%s", dpid, src, dst, in_port, out_port)
        	
		       
	actions = [parser.OFPActionOutput(out_port)]
        
	# install a flow to avoid packet_in next time
	if pkt_tcp and pkt_ipv4 and pkt_ethernet:	   	
           if out_port != ofproto.OFPP_FLOOD:
               src_port = pkt_tcp.src_port
               dst_port = pkt_tcp.dst_port
               src_ipv4 = pkt_ipv4.src
	       if src_port == None:
	       	  return
               else:
	       	  self.logger.info("src_port = %s ipv4_src = %s, in_port=%s", src_port, src_ipv4, in_port)	
               match = parser.OFPMatch(eth_type=0x800, in_port=in_port, eth_dst=dst, ip_proto=6, tcp_src=src_port, tcp_dst=dst_port)
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


    #@set_ev_cls(EventDP, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    #def _state_change_handler(self, ev):
    #    print ev.enter

