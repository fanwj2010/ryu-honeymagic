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

import array
import pprint
import subprocess
import os
import Queue 
import thread
import threading
import configparser
import ast
import time

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
from ryu.lib.packet import icmp
from ryu.lib import snortlib
from ryu.lib.packet import ether_types
from ryu.lib import pcaplib
from ryu.lib.packet import packet

from ryu.honeyapp.session import Session
from ryu.honeyapp.snort_rules_parser import SnortRuleParser
from ryu.honeyapp.exceptions import CustomException, badStateException
import ryu.controller.dpset
from ryu.controller.dpset import EventDP

from ryu.ofproto.ofproto_v1_2 import OFPG_ANY
from ryu.ofproto.ofproto_v1_3 import OFP_VERSION
from ryu.lib.mac import haddr_to_bin

CONFIG_FILE = "/opt/honeymagic/ryu-hp/ryu/app/honeymagic.conf"

class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {'snortlib': snortlib.SnortLib}
    
    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        
        self.snort = kwargs['snortlib']
        #self.snort_port = 7
        socket_config = {'unixsock': True}
        self.snort.set_config(socket_config)
        self.snort.start_socket_server()
        self.alert_msg = {}

	self.mac_to_port = {}
        self.sessions = {}
        self.alert = Queue.Queue() 
        self.lookup = Queue.Queue() 

        self.config = configparser.ConfigParser()
        self.config.read(CONFIG_FILE)
        self.log_dir = self.config['main']['log_dir']
        self.alert_file = self.config['main']['alert_file']
        self.pcap_file = self.config['main']['pcap_file']
        self.snort_conf = self.config['main']['snort_conf']     
        self.snort_rules = self.config['main']['snort_rules']     
        self.main_ovs =  int(self.config['main']['mainflow-dpid'])
        self.snort_port = int(self.config['main']['mainflow-dpid-snort-port'])
        self.front_end = self.config['main']['front-end']
       
        self.rulefile_handle = open(self.snort_rules, 'rb')
        
        self.datapath_for_DumpAlert = None
        self.pkt_for_DumpAlert = None
        self.in_port_for_DumpAlert = 0
        self.dpid_for_DumpAlert = 0
        

    
    @set_ev_cls(snortlib.EventAlert, MAIN_DISPATCHER)
    def _dump_alert(self, ev):
        print('\n\nSnort_Alert event !!!!!!!!')
        msg = ev.msg
        datapath = self.datapath_for_DumpAlert
        dpid = self.dpid_for_DumpAlert
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        #in_port = msg.match['in_port']

        print('alertmsg: %s' % ''.join(msg.alertmsg))
        #self.packet_print(msg.pkt)
        #pkt = packet.Packet(array.array('B', msg.pkt))
        pkt = self.pkt_for_DumpAlert
        pkt_ethernet = pkt.get_protocol(ethernet.ethernet)
        pkt_ipv4 = pkt.get_protocol(ipv4.ipv4)
        pkt_tcp = pkt.get_protocol(tcp.tcp)
        
        self.mac_to_port.setdefault(dpid, {})
        #try:
        sess = self.sessions[pkt_ipv4.src][pkt_tcp.src_port]  
        #except:
        #   sess = Session(pkt_ipv4.src, pkt_tcp.src_port, pkt_ipv4.dst, self.in_port_for_DumpAlert)
        #   self.sessions[pkt_ipv4.src] = {}
        #   self.sessions[pkt_ipv4.src][pkt_tcp.src_port] = sess

        self.alert_msg[pkt_ipv4.dst][pkt_tcp.dst_port] = "".join(msg.alertmsg)
        alert_rt = self.alert_msg[pkt_ipv4.dst][pkt_tcp.dst_port]

        if "DROP" not in alert_rt:
           #Redirection: TCP handshake replay initial
           self.logger.info("Need to redirect the pkt to backend, so initial TCP handover...\n")
           self.logger.info("Before lookup [dst mac = %s, self.mac_to_port[dpid=%s] = %s]", pkt_ethernet.dst, dpid, self.mac_to_port[dpid]) 
           dpid_ovs = int(self.config[pkt_ipv4.dst]['ovs-dpid'])   
           hp_mac = str(self.config[pkt_ipv4.dst]['MAC'])
           if dpid == dpid_ovs:
                   honeypot_name = alert_rt[:3]
                   out_port_number = int(self.config[pkt_ipv4.dst][honeypot_name])
	           self.mac_to_port[dpid][hp_mac] = out_port_number
	           out_port = out_port_number
	           sess.setOutport(out_port)
           else:
                   if pkt_ethernet.dst in self.mac_to_port[dpid]:
                      out_port = self.mac_to_port[dpid][pkt_ethernet.dst]                     
                   else:
                      out_port = ofproto.OFPP_FLOOD

           self.logger.info("After lookup [dst mac = %s, self.mac_to_port[dpid=%s] = %s]", pkt_ethernet.dst, dpid, self.mac_to_port[dpid])
           
           self.add_backward_flow(datapath, sess.syn_pkt, out_port)
                   
           actions = [parser.OFPActionOutput(out_port)]
                   
           data = sess.syn_pkt_data        
           out = parser.OFPPacketOut(datapath=datapath,buffer_id=ofproto.OFP_NO_BUFFER,
                                      in_port=ofproto.OFPP_CONTROLLER, actions=actions,data=data)                      
           datapath.send_msg(out)
           
           syn_tcp = sess.syn_pkt.get_protocol(tcp.tcp)
           self.logger.info("SYN sent [seq = %s , ack = %s] to initial TCP handshake replay...", syn_tcp.seq, syn_tcp.ack)  
           sess.setState(Session.A_TCP_HS_REPLAY)                
                  
          

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
        self.logger.info("\nConfigure SDN switches...")
        if datapath.id == self.main_ovs:
           self.logger.info("install flow entrires in [main ovs, dpid = %d]", datapath.id)
           p = SnortRuleParser()     
           with self.rulefile_handle as f:
                for rule in p.nonblank_lines(f):
                    ruleline = p.parse([rule])
                    flow_entry = {}
                    flow_entry['eth_type']= 0x800
                    try:
                       if ruleline['protocol'] == "icmp":
                           ip_proto = 1
                       elif ruleline['protocol'] == "tcp":
                           ip_proto = 6
                       elif ruleline['protocol'] == "udp":
                           ip_proto = 17
                       flow_entry['ip_proto'] = int(ip_proto)
                    except Exception:
                         print "no protocal"

                    try:
                       if ruleline['srcaddr'] != "any":
                           flow_entry['ipv4_src'] = ruleline['srcaddr']
                    except Exception:
                       print "no src ip addr"
                    
                    try:  
                       if ruleline['srcport'] != "any":
                           flow_entry['tcp_src'] = int(ruleline['srcport'])
                    except Exception:
                       print "no src port"
                    
                    try:
                       if ruleline['dstaddr'] != "any":
                           flow_entry['ipv4_dst'] = ruleline['dstaddr']
                    except Exception:
                       print "no dst ip addr"
                    
                    try:
                       if ruleline['dstport'] != "any":
                           flow_entry['tcp_dst'] = int(ruleline['dstport'])
                    except Exception:
                       print "no dst port"                    
                    
                    actions = []
                    try:
                       if ruleline['options']['msg'] == "DROP":
                          try:
                             #ruleline['options']['content']
                             if ruleline['options']['content'] is None:
                                 actions = []
                             else:
                                 actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,ofproto.OFPCML_NO_BUFFER)]
                          except:
                             print "no content"
                       else:
                          actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,ofproto.OFPCML_NO_BUFFER)] 
                    except Exception:
                        print "no msg"  
                    
                    try: 
                        if ruleline['options']['priority'] is not None:
                           priority = int(ruleline['options']['priority'])
                        else: 
                           priority = 0
                    except Exception:
                        print "no priority"

	            match = parser.OFPMatch(**flow_entry)
                 
                    self.add_flow_to_ctl(datapath, priority, match, actions)
        else:
            self.logger.info("install flow entrires in [ofsoftswitch, dpid = %d]", datapath.id)           
            match = parser.OFPMatch()
            actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,ofproto.OFPCML_NO_BUFFER)]
            self.add_flow_to_ctl(datapath, 0, match, actions)
   
    def add_flow_to_ctl(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id, priority=priority, match=match, instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match, instructions=inst)

        #print "installing flow mod with priority " + str(priority) + " match fields " + str(match) + " actions " + str(actions)
        self.logger.info("Installing CTL flow mod to in dpid %s with priority %s match fields %s actions %s",str(datapath.id), str(priority), str(match), str(actions))
        datapath.send_msg(mod)



    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions)]

        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, idle_timeout=30, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, idle_timeout=30, priority=priority,
                                    match=match, instructions=inst)

        #print "installing flow mod with priority " + str(priority) + " match fields " + str(match) + " actions " + str(actions)
        self.logger.info("Installing DATA flow mod in dpid %s with priority %s match fields %s actions %s",str(datapath.id), str(priority), str(match), str(actions))
        datapath.send_msg(mod)
       

    def add_backward_flow(self, datapath, pkt, out_port):
        ofproto = datapath.ofproto
	parser = datapath.ofproto_parser
        ipd = pkt.get_protocol(ipv4.ipv4)
        #tcpd = pkt.get_protocol(tcp.tcp)    
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]        
        #match = parser.OFPMatch(eth_type=0x800, ip_proto=6, ipv4_dst=ipd.src, tcp_dst=tcpd.src_port, ipv4_src=ipd.dst, tcp_src=tcpd.dst_port)
        match = parser.OFPMatch(eth_type=0x800, in_port = out_port, ip_proto=6, ipv4_dst=ipd.src, ipv4_src=ipd.dst)

        self.add_flow(datapath, 1, match, actions)
        #self.logger.info("The backward flow entry from honeypot to controller is set.")
 

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
	
        
        #self.logger.info("MAC dst is %s ,", pkt_ethernet.dst)
	src_ip = pkt_ipv4.src
	dst_ip = pkt_ipv4.dst

        #self.logger.info("Control bits = %s, seq = %s, ack = %s", bin(pkt_tcp.bits), pkt_tcp.seq, pkt_tcp.ack)
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
        
        self.sessions.setdefault(src_ip, {})
        #print self.sessions   
	#Get the session that the pkt belong to, Regist a new session if the session was not registed
        if src_ip in self.sessions:
           #self.logger.info("\nsrc IP (%s) is in sessions, packet_in from switch dpid= %s", src_ip, dpid)
           if pkt_tcp.src_port in self.sessions[src_ip]:             
              sess = self.sessions[src_ip][pkt_tcp.src_port]
              self.logger.info("Packet belongs to session [%s:%s], state = %s",src_ip, pkt_tcp.src_port, sess.getState())
           else:
              #self.logger.info("src Port (%s) is NOT in sessions, packet_in from switch dpid= %s",pkt_tcp.src_port, dpid)
              sess = Session(src_ip, pkt_tcp.src_port, dst_ip, in_port)
              #self.sessions[src_ip] = {}
              self.sessions[src_ip][pkt_tcp.src_port] = sess
              self.logger.info("Packet belongs to session [%s:%s] (new port), state = %s",src_ip, pkt_tcp.src_port, sess.getState())
        else:
           #self.logger.info("\nsrc IP (%s) is NOT in sessions, packet_in from switch dpid= %s", src_ip, dpid)
           sess = Session(src_ip, pkt_tcp.src_port, dst_ip, in_port)
           #self.sessions[src_ip] = {}
           self.sessions[src_ip][pkt_tcp.src_port] = sess
           self.logger.info("Packet belongs to session [%s:%s] (new IP : new port), state = %s",src_ip, pkt_tcp.src_port, sess.getState())
        

###     ## Attacker launches Session: Attacker --> Honeypot
    
        #SYN
        if pkt_tcp.bits == 0x2 and sess.getState() == Session.SESSION_INITIAL:
           self.logger.info("Attacker launches Session state = %s", sess.getState())
           self.logger.info("SYN recv [seq = %s , ack = %s]", pkt_tcp.seq, pkt_tcp.ack)
           sess.saveSYNpkt(pkt)
           sess.saveSYNpktdata(msg.data)            
           serv_port_dict = ast.literal_eval(self.config[pkt_ipv4.dst]['LIH-services'])
           for serv, port in serv_port_dict.iteritems():
               if port == pkt_tcp.dst_port:
                  self.logger.info("Target [%s:%s, %s]", dst_ip, pkt_tcp.dst_port, serv)  
                  #Generating SYN_ACK response to the TCP SYN
                  syn_ack_pkt = sess.generateSYNACKtoSYN()
                  data = syn_ack_pkt.data
                  actions = [parser.OFPActionOutput(in_port)]
                  out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER, in_port=ofproto.OFPP_CONTROLLER, actions=actions, data=data)

                  #time.sleep(0.1)
                  datapath.send_msg(out) 

                  syn_ack_tcp = syn_ack_pkt.get_protocol(tcp.tcp)
                  self.logger.info("SYN_ACK resp [seq = %s , ack = %s]", syn_ack_tcp.seq, syn_ack_tcp.ack)
           sess.setState(Session.A_TCP_HS_PLAY)
           return     

        #ACK
        elif pkt_tcp.bits == 1 << 4 and sess.getState() == Session.A_TCP_HS_PLAY:
             self.logger.info("Attacker launched Session state = %s", sess.getState()) 
             #print "ACK option=", pkt_tcp.option  
             self.logger.info("ACK recv [seq = %s , ack = %s]", pkt_tcp.seq, pkt_tcp.ack)
             sess.saveACKpkt(pkt)
             sess.saveACKpktdata(msg.data)
             self.logger.info("TCP established, save the ACK pkt and wait for the ACK_PSH payload pkt...")  
             sess.setState(Session.A_TCP_ESTABLISHED)  
             return

        
        #ACK_PSH
        elif pkt_tcp.bits == 1 << 3 | 1 << 4 and sess.getState() == Session.A_TCP_ESTABLISHED:
           # We should catch the first payload pkt now        
             self.logger.info("Attacker launched Session state = %s", sess.getState())
             #print "ACK_PSH option=", pkt_tcp.option   
             #request = payload.split('\n', 1)[0]                    
             sess.savePAYLOADpkt(pkt)
             sess.savePAYLOADpktdata(msg.data)
             #sess.setPayload(payload)
             self.logger.info("PSH_ACK recv [seq = %s , ack = %s] payload: %s", pkt_tcp.seq, pkt_tcp.ack, payload)
             pkt_data=msg.data
	     
             try:
                alert_rt = self.alert_msg[pkt_ipv4.dst][pkt_tcp.dst_port]
                self.logger.info("Alert msg = %s", alert_rt)
                if "DROP" in alert_rt:
                   self.logger.info("DROP !!! RST The Connection!")                                          
                   rst_pkt = sess.generateRSTpkt()  
                  
                   data = rst_pkt.data
                   actions = [parser.OFPActionOutput(in_port)]
                           
	           out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,
                                            in_port=ofproto.OFPP_CONTROLLER, actions=actions, data=data)                          
                   datapath.send_msg(out)                                                   
                   rst_pkt_tcp = rst_pkt.get_protocol(tcp.tcp) 
                   self.logger.info("RST resp [seq = %s , ack = %s]", rst_pkt_tcp.seq, rst_pkt_tcp.ack)
                   sess.setState(Session.SESSION_TERMINATED)
                   del self.sessions[pkt_ipv4.src][pkt_tcp.src_port]
                   self.logger.info("Attacker launched Session [%s:%s] in dictionary is deleted.\n", pkt_ipv4.src, pkt_tcp.src_port)
                   
                else:
                    #Redirection: TCP hand shake replay initial
                    self.logger.info("Need to redirect the pkt to backend, so initial TCP handover...\n")
                    self.logger.info("Before lookup [dst mac = %s, self.mac_to_port[dpid=%s] = %s]", pkt_ethernet.dst, dpid, self.mac_to_port[dpid]) 
                    dpid_ovs = int(self.config[pkt_ipv4.dst]['ovs-dpid'])
                    hp_mac = str(self.config[pkt_ipv4.dst]['MAC'])
                    if dpid == dpid_ovs:
                       honeypot_name = alert_rt[:3]
                       out_port_number = int(self.config[pkt_ipv4.dst][honeypot_name])
	               self.mac_to_port[dpid][hp_mac] = out_port_number
	               out_port = out_port_number
	               sess.setOutport(out_port)
                    else:
                       if pkt_ethernet.dst in self.mac_to_port[dpid]:
                           out_port = self.mac_to_port[dpid][pkt_ethernet.dst]                     
                       else:
                           out_port = ofproto.OFPP_FLOOD

                    self.logger.info("After lookup [dst mac = %s, self.mac_to_port[dpid=%s] = %s]", pkt_ethernet.dst, dpid, self.mac_to_port[dpid])
                       
                    self.logger.info("Prepare backward flow entry from honeypot to controller.")
                    self.add_backward_flow(datapath, sess.syn_pkt, out_port)
                   
                    actions = [parser.OFPActionOutput(out_port)]
                   
                    data = sess.syn_pkt_data        
                    out = parser.OFPPacketOut(datapath=datapath,buffer_id=ofproto.OFP_NO_BUFFER,in_port=ofproto.OFPP_CONTROLLER, actions=actions,data=data)                      
                    datapath.send_msg(out)
           
                    syn_tcp = sess.syn_pkt.get_protocol(tcp.tcp)
                    self.logger.info("SYN sent [seq = %s , ack = %s] to initail TCP handshake Replay...", syn_tcp.seq, syn_tcp.ack)  
                    sess.setState(Session.A_TCP_HS_REPLAY)                
                       
                   
             except: 
                 self.logger.info("No alert msg for this session")
                 self.datapath_for_DumpAlert = datapath
                 self.pkt_for_DumpAlert = pkt
                 self.in_port_for_DumpAlert = in_port
                 self.dpid_for_DumpAlert = dpid    
                 actions = [parser.OFPActionOutput(self.snort_port)]
                 out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,
                                  in_port=ofproto.OFPP_CONTROLLER, actions=actions, data=msg.data)
                 datapath.send_msg(out)
                 self.logger.info("Send ACK_PSH pkt out to Snort")
             
             return


###     ## Attacked launched Session Replay: Controller --> Honeypot
        #SYN        
        elif pkt_tcp.bits == 0x2 and sess.getState() == Session.A_TCP_HS_REPLAY:
           self.logger.info("Attacker launched Replay Session state = %s", sess.getState())
           self.logger.info("SYN recv [seq = %s , ack = %s]", pkt_tcp.seq, pkt_tcp.ack)
           
           if pkt_ethernet.dst in self.mac_to_port[dpid]:
        	out_port = self.mac_to_port[dpid][pkt_ethernet.dst]
           else:
        	out_port = ofproto.OFPP_FLOOD
           actions = [parser.OFPActionOutput(out_port)]        
           data = msg.data

           out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,
        	                          in_port=in_port, actions=actions, data=data)
           datapath.send_msg(out)          
                
           self.logger.info("SYN sent [seq = %s , ack = %s]", pkt_tcp.seq, pkt_tcp.ack)
           self.logger.info("Attacker launched Relay Session state = %s", sess.getState())
           return

        
        
###     ## Honeypot launched Session: Attacker --> Honeypot
        #SYN_ACK
        elif pkt_tcp.bits == 1 << 1 | 1 << 4 and sess.getState() == Session.H_TCP_HS_PLAY:
           self.logger.info("Honeypot launched Session state = %s", sess.getState())
           self.logger.info("SYN_ACK recv [seq = %s , ack = %s]", pkt_tcp.seq, pkt_tcp.ack)
           
           self.logger.info("Before lookup [dst mac = %s, self.mac_to_port[dpid=%s] = %s]", pkt_ethernet.dst, dpid, self.mac_to_port[dpid]) 
                  
           dpid_ovs = int(self.config[pkt_ipv4.dst]['ovs-dpid'])
           hp_mac = str(self.config[pkt_ipv4.dst]['MAC'])
           if dpid == dpid_ovs: 
	      self.mac_to_port[dpid][hp_mac] = int(sess.in_port)
	      out_port = int(sess.in_port)
	      sess.setOutport(out_port)              
           else:
              if pkt_ethernet.dst in self.mac_to_port[dpid]:
                   out_port = self.mac_to_port[dpid][pkt_ethernet.dst]
              else:
                   out_port = ofproto.OFPP_FLOOD
           self.logger.info("After lookup [dst mac = %s, self.mac_to_port[dpid=%s] = %s]", pkt_ethernet.dst, dpid, self.mac_to_port[dpid])
           actions = [parser.OFPActionOutput(out_port)]

           if dpid != dpid_ovs: 
              match = parser.OFPMatch(eth_type=0x800, eth_dst=pkt_ethernet.dst, ip_proto=6, ipv4_src=pkt_ipv4.src, ipv4_dst=pkt_ipv4.dst, tcp_src=pkt_tcp.src_port, tcp_dst=pkt_tcp.dst_port)
              if msg.buffer_id != ofproto.OFP_NO_BUFFER:
           	 self.add_flow(datapath, 3, match, actions, msg.buffer_id)	     
              else:
           	 self.add_flow(datapath, 3, match, actions)
                   
           data = msg.data        
           out = parser.OFPPacketOut(datapath=datapath,buffer_id=ofproto.OFP_NO_BUFFER,
                                      in_port=in_port, actions=actions,data=data)                      
           datapath.send_msg(out)       
           self.logger.info("SYN_ACK sent [seq = %s , ack = %s]", pkt_tcp.seq, pkt_tcp.ack)
           self.logger.info("Honeypot launched Session state = %s", sess.getState())
           return
             
        #ACK
        elif pkt_tcp.bits & 1 << 4 and sess.getState() == Session.H_TCP_FORWARD:
           self.logger.info("Honeypot launched Session state = %s", sess.getState())
           self.logger.info("ACK recv [seq = %s , ack = %s]", pkt_tcp.seq, pkt_tcp.ack)
           #if pkt_ethernet.dst in self.mac_to_port[dpid]:
           #    out_port = self.mac_to_port[dpid][pkt_ethernet.dst]
           #else:
           #    out_port = ofproto.OFPP_FLOOD
           out_port = sess.getOutport()

           match = parser.OFPMatch(eth_type=0x800, eth_dst=pkt_ethernet.dst, ip_proto=6, ipv4_src=pkt_ipv4.src, ipv4_dst=pkt_ipv4.dst, tcp_src=pkt_tcp.src_port, tcp_dst=pkt_tcp.dst_port)
           if msg.buffer_id != ofproto.OFP_NO_BUFFER:
               self.add_flow(datapath, 3, match, actions, msg.buffer_id)	     
           else:
               self.add_flow(datapath, 3, match, actions)

           actions = [parser.OFPActionOutput(out_port)]        
           data = msg.data
           out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,
        	                          in_port=in_port, actions=actions, data=data)
           datapath.send_msg(out)          
                
           self.logger.info("ACK sent [seq = %s , ack = %s]", pkt_tcp.seq, pkt_tcp.ack)
           self.logger.info("Honeypot launched Session state = %s", sess.getState())
           return

           
       
###     ##For all the Joined Sessions, process the subsequence inbound pkt.
        elif sess.getState() == Session.A_TCP_FORWARD or sess.getState() == Session.A_SESSION_JOINED or sess.getState() == Session.H_TCP_FORWARD or sess.getState() == Session.H_TCP_ESTABLISHED:
           self.logger.info("Session state = %s", sess.getState())
           self.logger.info("Inbound pkt recv [seq = %s , ack = %s]", pkt_tcp.seq, pkt_tcp.ack)
           if pkt_ethernet.dst in self.mac_to_port[dpid]:
               out_port = self.mac_to_port[dpid][pkt_ethernet.dst]
           else:
               out_port = ofproto.OFPP_FLOOD
           actions = [parser.OFPActionOutput(out_port)]        
           data = msg.data
           out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,
        	                          in_port=in_port, actions=actions, data=data)
           datapath.send_msg(out)          
                    
           #match = parser.OFPMatch(in_port=in_port, eth_type=0x800, ip_proto=6, ipv4_src=pkt_ipv4.src, ipv4_dst=pkt_ipv4.dst, tcp_src=pkt_tcp.src_port, tcp_dst=pkt_tcp.dst_port)
           #if msg.buffer_id != ofproto.OFP_NO_BUFFER:
           #    self.add_flow(datapath, 3, match, actions, msg.buffer_id)
           #else:
           #    self.add_flow(datapath, 3, match, actions)
           self.logger.info("Inbound pkt forward [seq = %s , ack = %s]", pkt_tcp.seq, pkt_tcp.ack)
          
           self.logger.info("Session state = %s", sess.getState())
           		
           #ACK_FIN   
           if pkt_tcp.bits == 1 | 1 << 4:
              sess.setState(Session.SESSION_TERMINATED)
           return
        
        #ACK_FIN
        elif sess.getState() == Session.SESSION_TERMINATED:
	   self.logger.info("Session state = %s", sess.getState())
           self.logger.info("ACK_FIN recv [seq = %s , ack = %s]", pkt_tcp.seq, pkt_tcp.ack)
           if pkt_ethernet.dst in self.mac_to_port[dpid]:
               out_port = self.mac_to_port[dpid][pkt_ethernet.dst]
           else:
               out_port = ofproto.OFPP_FLOOD
           actions = [parser.OFPActionOutput(out_port)]        
           data = msg.data
           out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,
        	                          in_port=in_port, actions=actions, data=data)
           datapath.send_msg(out)
           self.logger.info("ACK_FIN forward [seq = %s , ack = %s]", pkt_tcp.seq, pkt_tcp.ack)
           self.logger.info("Session state = %s", sess.getState())
           return	            

        
###     ## Drop any other pkt
        else:
             dst = pkt_ethernet.dst
             src = pkt_ethernet.src
	
             #learn a mac address to avoid FLOOD next time.
             self.mac_to_port[dpid][src] = in_port

             if dst in self.mac_to_port[dpid]:
        	  out_port = self.mac_to_port[dpid][dst]
             else:
        	  out_port = ofproto.OFPP_FLOOD

             actions = []

             data = None
             if msg.buffer_id == ofproto.OFP_NO_BUFFER:
        	  data = msg.data

             out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
        	                          in_port=in_port, actions=actions, data=data)
             datapath.send_msg(out)
             return

                      	
         
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
        
        
        #self.logger.info("MAC dst is %s ,", pkt_ethernet.dst)
	src_ip = pkt_ipv4.src
	dst_ip = pkt_ipv4.dst
        
        #self.logger.info("Control bits = %s, seq = %s, ack = %s", bin(pkt_tcp.bits), pkt_tcp.seq, pkt_tcp.ack)
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
         

        self.sessions.setdefault(dst_ip, {})
        #print self.sessions        
	#Get the session that the pkt belong to, Regist a new session if the session was not registed
        if dst_ip in self.sessions:
           #self.logger.info("\nsrc IP (%s) is in sessions, packet_in from switch dpid= %s", src_ip, dpid)
           if pkt_tcp.dst_port in self.sessions[dst_ip]:
              sess = self.sessions[dst_ip][pkt_tcp.dst_port]
              self.logger.info("Packet belongs to session [%s:%s], state = %s",dst_ip, pkt_tcp.dst_port, sess.getState())
           else:
              #self.logger.info("src Port (%s) is NOT in sessions, packet_in from switch dpid= %s",pkt_tcp.src_port, dpid)
              sess = Session(dst_ip, pkt_tcp.dst_port, src_ip, in_port)
              #self.sessions[dst_ip] = {}
              self.sessions[dst_ip][pkt_tcp.dst_port] = sess
              self.logger.info("Packet belongs to session [%s:%s] (new port), state = %s",dst_ip, pkt_tcp.dst_port, sess.getState())
        else:
           #self.logger.info("\nsrc IP (%s) is NOT in sessions, packet_in from switch dpid= %s", src_ip, dpid)
           sess = Session(dst_ip, pkt_tcp.dst_port, src_ip, in_port)
           #self.sessions[dst_ip] = {}
           self.sessions[dst_ip][pkt_tcp.dst_port] = sess
           self.logger.info("Packet belongs to session [%s:%s] (new IP : new port), state = %s",dst_ip, pkt_tcp.dst_port, sess.getState())      
        

###     ## Attacker launched Session Replay: Controller <-- Honeypot
        #SYN_ACK               
        if pkt_tcp.bits == 1 << 1 | 1 << 4 and sess.getState() == Session.A_TCP_HS_REPLAY:
           self.logger.info("Attacker launched Replay Session state = %s", sess.getState())
           self.logger.info("SYN_ACK recv [seq = %s , ack = %s]", pkt_tcp.seq, pkt_tcp.ack)
           #print "SYN_ACK option=", pkt_tcp.option 
           sess.saveHPsynseq(pkt_tcp.seq)
           sess.saveSYNACKpkt(pkt)
           dpid_ovs = int(self.config[pkt_ipv4.src]['ovs-dpid'])
           
           #if ofsoftswitch13, Forward the pkt to OVS, and install flow entries for SEQ synchronization
           if dpid !=  dpid_ovs:              
              if pkt_ethernet.dst in self.mac_to_port[dpid]:
        	 out_port = self.mac_to_port[dpid][pkt_ethernet.dst]
              else:
        	 out_port = ofproto.OFPP_FLOOD
              actions = [parser.OFPActionOutput(out_port)]        
              data = msg.data
              out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,
        	                          in_port=in_port, actions=actions, data=data)
              datapath.send_msg(out)                          
              self.logger.info("SYN_ACK sent [seq = %s , ack = %s]", pkt_tcp.seq, pkt_tcp.ack)
              self.logger.info("Attacker launched Replay Session state = %s", sess.getState())
              
              self.logger.info("Configure ofsoftswitch13 [honeynet dpid= %s] for SEQ sychronization...", dpid)          
              #SRCmatch, direction to Honeypot
              match = parser.OFPMatch(eth_type=0x800, eth_dst=pkt_ethernet.src, ip_proto=6, ipv4_src=pkt_ipv4.dst, ipv4_dst=pkt_ipv4.src, tcp_src=pkt_tcp.dst_port, tcp_dst=pkt_tcp.src_port)
              hp_mac = pkt_ethernet.src
              #self.logger.info("hp_mac=%s", hp_mac)
              if hp_mac in self.mac_to_port[dpid]:
                  out_port = self.mac_to_port[dpid][hp_mac]		
              else:
                  out_port = ofproto.OFPP_FLOOD
              #self.logger.info("[dpid =  %s, out_port_to_honeypot = %s]", dpid, out_port)
              ack_diff = sess.getACKDiff(sess.honeypot_syn_seq, sess.controller_syn_seq)
              actions = [parser.OFPActionSetField(tcp_ack_diff=ack_diff), parser.OFPActionOutput(out_port)]
              if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                   self.add_flow(datapath, 3, match, actions, msg.buffer_id)
              else:
                   self.add_flow(datapath, 3, match, actions)
		   
              #DSTmatch, direction to attacker
              match = parser.OFPMatch(eth_type=0x800, eth_dst=pkt_ethernet.dst, ip_proto=6, ipv4_src=pkt_ipv4.src, ipv4_dst=pkt_ipv4.dst, tcp_src=pkt_tcp.src_port, tcp_dst=pkt_tcp.dst_port)
              atk_mac = pkt_ethernet.dst
              #self.logger.info("atk_mac=%s", atk_mac)
              if atk_mac in self.mac_to_port[dpid]:
                   out_port = self.mac_to_port[dpid][atk_mac]		
              else:
                   out_port = ofproto.OFPP_FLOOD
              #self.logger.info("[dpid = %s, out_port_to_attacker = %s]", dpid, out_port)
              seq_diff = sess.getSEQDiff(sess.controller_syn_seq, sess.honeypot_syn_seq)
              actions = [parser.OFPActionSetField(tcp_seq_diff=seq_diff), parser.OFPActionOutput(out_port)]
              if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                   self.add_flow(datapath, 3, match, actions, msg.buffer_id)
              else:
                   self.add_flow(datapath, 3, match, actions)

           #respond with ACK, and then ACK_PSH
           else:              
              #GENERATE ACK TO SYN ACK
              #ack_pkt = sess.generateACKtoSYNACK()                           
              actions = [parser.OFPActionOutput(in_port)]

              ack_pkt_data = sess.ack_pkt_data
              out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER, in_port=ofproto.OFPP_CONTROLLER, actions=actions, data=ack_pkt_data)
              datapath.send_msg(out)
              ack_pkt = sess.ack_pkt
              ack_tcp = ack_pkt.get_protocol(tcp.tcp)
              self.logger.info("ACK resp [seq = %s , ack = %s], replayed TCP connection established", ack_tcp.seq, ack_tcp.ack)
              sess.setState(Session.A_TCP_REPLAY_ESTABLISHED)

              ack_psh_pkt_data = sess.payload_pkt_data
              out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER, in_port=ofproto.OFPP_CONTROLLER, actions=actions, data=ack_psh_pkt_data)
              datapath.send_msg(out)
              ack_psh_pkt = sess.payload_pkt
              ack_psh_tcp = ack_psh_pkt.get_protocol(tcp.tcp)
              self.logger.info("ACK_PSH sent [seq = %s , ack = %s]", ack_psh_tcp.seq, ack_psh_tcp.ack)
              self.logger.info("Attack launched Replay Session state = %s", sess.getState())
           
           return
                 
           
        #ACK or ACK_PSH
        elif pkt_tcp.bits & 1 << 4  and sess.getState() == Session.A_TCP_REPLAY_ESTABLISHED:
           self.logger.info("Attacker launched Replay Session state = %s", sess.getState())
           self.logger.info("ACK recv [seq = %s , ack = %s]", pkt_tcp.seq, pkt_tcp.ack)
           #print "ACK option=", pkt_tcp.option
           dpid_ovs = int(self.config[pkt_ipv4.src]['ovs-dpid'])
           if dpid == dpid_ovs:
              self.logger.info("Configure main OVS [honeynet dpid= %s] to avoid packet_in of this session next time...", dpid)
              #install flow entry direct to honeypot
              match = parser.OFPMatch(eth_type=0x800, eth_dst=pkt_ethernet.src, ip_proto=6, ipv4_src=sess.src_ip, ipv4_dst=pkt_ipv4.src, tcp_src=sess.src_port, tcp_dst=pkt_tcp.src_port)
              out_port = in_port   
              self.logger.info("[dpid =  %s, out_port_to_honeypot = %s]", dpid, out_port)
              actions = [parser.OFPActionOutput(out_port)]
              if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                  self.add_flow(datapath, 3, match, actions, msg.buffer_id)
              else:
                  self.add_flow(datapath, 3, match, actions)	   
              #install flow entry to attacker
              match = parser.OFPMatch(in_port=in_port, eth_type=0x800, eth_dst=pkt_ethernet.dst, ip_proto=6, ipv4_src=pkt_ipv4.src, ipv4_dst=sess.src_ip, tcp_src=pkt_tcp.src_port, tcp_dst=sess.src_port)
              atk_mac = pkt_ethernet.dst
              if atk_mac in self.mac_to_port[dpid]:
                 out_port = self.mac_to_port[dpid][atk_mac]		
              else:
                 out_port = ofproto.OFPP_FLOOD
              self.logger.info("[dpid = %s, out_port_to_attacker = %s]", dpid, out_port)          
              actions = [parser.OFPActionOutput(out_port)]
              if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                 self.add_flow(datapath, 3, match, actions, msg.buffer_id)
              else:
                 self.add_flow(datapath, 3, match, actions)

           dst = pkt_ethernet.dst 
           if dst in self.mac_to_port[dpid]:
              out_port = self.mac_to_port[dpid][dst]	
           else:
              out_port = ofproto.OFPP_FLOOD
           data = msg.data
           actions = [parser.OFPActionOutput(out_port)]
           out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER, in_port=in_port, actions=actions, data=data)
           datapath.send_msg(out)
           self.logger.info("ACK resp [seq = %s , ack = %s] to join the two sessions to finish TCP handover", pkt_tcp.seq, pkt_tcp.ack)
           sess.setState(Session.A_SESSION_JOINED)
           return
        
       
        

###     ## Honeypot launches Session: Attacker <-- Honeypot

        #SYN
        elif pkt_tcp.bits == 0x2 and sess.getState() == Session.SESSION_INITIAL:
           self.logger.info("Honeypot launches Session state = %s", sess.getState())
           self.logger.info("SYN recv [seq = %s , ack = %s]", pkt_tcp.seq, pkt_tcp.ack)
                      
           dst = pkt_ethernet.dst
           src = pkt_ethernet.src       	  
        
           self.mac_to_port[dpid][src] = in_port

           dpid_ovs = int(self.config[pkt_ipv4.src]['ovs-dpid'])

           if dpid == dpid_ovs: 
              if dst in self.mac_to_port[dpid]:
                 out_port = self.mac_to_port[dpid][dst]
              else:
                out_port = ofproto.OFPP_FLOOD
	      
              self.logger.info("Prepare backward flow entry from attacker to controller.")
              self.add_backward_flow(datapath, pkt, out_port) 

              actions = [parser.OFPActionOutput(out_port)]
           
              data = msg.data
              out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,in_port=in_port, actions=actions, data=data)
              datapath.send_msg(out)

              self.logger.info("SYN sent [seq = %s , ack = %s]", pkt_tcp.seq, pkt_tcp.ack)
              sess.setState(Session.H_TCP_HS_PLAY)            
           else:
              if dst in self.mac_to_port[dpid]:
                 out_port = self.mac_to_port[dpid][dst]
              else:
                 out_port = ofproto.OFPP_FLOOD

              actions = [parser.OFPActionOutput(out_port)]          
           
              match = parser.OFPMatch(eth_type=0x800, eth_dst=pkt_ethernet.dst, ip_proto=6, ipv4_src=pkt_ipv4.src, ipv4_dst=pkt_ipv4.dst, tcp_src=pkt_tcp.src_port, tcp_dst=pkt_tcp.dst_port)
              if msg.buffer_id != ofproto.OFP_NO_BUFFER:
           	 self.add_flow(datapath, 3, match, actions, msg.buffer_id)	     
              else:
           	 self.add_flow(datapath, 3, match, actions)

              data = msg.data           
              out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER, in_port=in_port, actions=actions, data=data)
              datapath.send_msg(out)
              self.logger.info("SYN sent [seq = %s , ack = %s]", pkt_tcp.seq, pkt_tcp.ack)
              self.logger.info("Honeypot launched Session state = %s", sess.getState())
           return
        
        #ACK
        elif pkt_tcp.bits == 1 << 4 and sess.getState() == Session.H_TCP_HS_PLAY:
           self.logger.info("Honeypot launched Session state = %s", sess.getState())
           self.logger.info("ACK recv [seq = %s , ack = %s]", pkt_tcp.seq, pkt_tcp.ack)

           dst = pkt_ethernet.dst
           src = pkt_ethernet.src
                                                                                             
           if dst in self.mac_to_port[dpid]:
               out_port = self.mac_to_port[dpid][dst]
           else:
               out_port = ofproto.OFPP_FLOOD          

           actions = [parser.OFPActionOutput(out_port)]          
           
           #self.logger.info("Install flow entry in OVS")  
           #match = parser.OFPMatch(eth_type=0x800, in_port=in_port, eth_dst=pkt_ethernet.dst, ip_proto=6, ipv4_src=pkt_ipv4.src, ipv4_dst=pkt_ipv4.dst, tcp_src=pkt_tcp.src_port, tcp_dst=pkt_tcp.dst_port)
           #if msg.buffer_id != ofproto.OFP_NO_BUFFER:
           #	self.add_flow(datapath, 3, match, actions, msg.buffer_id)	     
           #else:
           #	self.add_flow(datapath, 3, match, actions)

           data = msg.data           
           out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER, in_port=in_port, actions=actions, data=data)
           datapath.send_msg(out)
           
           self.logger.info("ACK resp [seq = %s , ack = %s], Honeypot launched TCP connection is established", pkt_tcp.seq, pkt_tcp.ack)
           sess.setState(Session.H_TCP_ESTABLISHED)
           return

        #ACK_PSH
        elif pkt_tcp.bits == 1 << 3 | 1 << 4 and sess.getState() == Session.H_TCP_ESTABLISHED:
           self.logger.info("Honeypot launched Session state = %s", sess.getState())
           self.logger.info("ACK_PSH recv [seq = %s , ack = %s]", pkt_tcp.seq, pkt_tcp.ack)

           dst = pkt_ethernet.dst
           src = pkt_ethernet.src
                                                                                             
           if dst in self.mac_to_port[dpid]:
               out_port = self.mac_to_port[dpid][dst]
           else:
               out_port = ofproto.OFPP_FLOOD          

           actions = [parser.OFPActionOutput(out_port)]          
           
           #self.logger.info("Install flow entry in OVS")  
           #match = parser.OFPMatch(in_port=in_port, eth_type=0x800, eth_dst=pkt_ethernet.dst, ip_proto=6, ipv4_src=pkt_ipv4.src, ipv4_dst=pkt_ipv4.dst, tcp_src=pkt_tcp.src_port, tcp_dst=pkt_tcp.dst_port)
           #if msg.buffer_id != ofproto.OFP_NO_BUFFER:
           #	self.add_flow(datapath, 3, match, actions, msg.buffer_id)	     
           #else:
           #	self.add_flow(datapath, 3, match, actions)

           data = msg.data           
           out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER, in_port=in_port, actions=actions, data=data)
           datapath.send_msg(out)
           
           self.logger.info("ACK_PSH resp [seq = %s , ack = %s]", pkt_tcp.seq, pkt_tcp.ack)
           sess.setState(Session.H_TCP_FORWARD)
           return

                
###     ##For all the Joined Sessions, process the subsequence outbound pkt.
        elif sess.getState() == Session.A_TCP_FORWARD or sess.getState() == Session.A_SESSION_JOINED or sess.getState() == Session.H_TCP_FORWARD or sess.getState() == Session.H_TCP_ESTABLISHED:
           #if pkt_tcp.bits == 1 << 4 | 1 << 1:
           dst = pkt_ethernet.dst 
           if dst in self.mac_to_port[dpid]:
              out_port = self.mac_to_port[dpid][dst]	
           else:
              out_port = ofproto.OFPP_FLOOD
           actions = [parser.OFPActionOutput(out_port)]


           match = parser.OFPMatch(in_port=in_port, eth_type=0x800, ip_proto=6, ipv4_src=pkt_ipv4.src, ipv4_dst=pkt_ipv4.dst, tcp_src=pkt_tcp.src_port, tcp_dst=pkt_tcp.dst_port)
           if msg.buffer_id != ofproto.OFP_NO_BUFFER:
               self.add_flow(datapath, 3, match, actions, msg.buffer_id)
           else:
               self.add_flow(datapath, 3, match, actions)
  

           #data = None
           #if msg.buffer_id == ofproto.OFP_NO_BUFFER:
           #    data = msg.data
           data = msg.data
           out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER, in_port=in_port, actions=actions, data=data)
           datapath.send_msg(out)
           self.logger.info("Session joined (outbound), pkt is forwarded [dpid= %s : session state= %s]", dpid, sess.getState())


           if pkt_tcp.bits == 1 | 1 << 4:
                 #if pkt_ipv4.dst in self.sessions:
                 #del self.sessions[pkt_ipv4.dst]
              sess.setState(Session.SESSION_TERMINATED)
              self.logger.info("Session joined (outbound), ACK_FIN is forwarded [dpid= %s : session state= %s]", dpid, sess.getState())
              #delete the flow mod
              #code
           return       
        
        elif sess.getState() == Session.SESSION_TERMINATED:
           dst = pkt_ethernet.dst 
           if dst in self.mac_to_port[dpid]:
              out_port = self.mac_to_port[dpid][dst]	
           else:
              out_port = ofproto.OFPP_FLOOD
           actions = [parser.OFPActionOutput(out_port)]

           #data = None
           #if msg.buffer_id == ofproto.OFP_NO_BUFFER:
           #     data = msg.data
           data = msg.data
           out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER, in_port=in_port, actions=actions, data=data)
           datapath.send_msg(out)
           self.logger.info("Session terminated (outbound), ACK_FIN is forwarded [dpid= %s : session state= %s]", dpid, sess.getState())
           del self.sessions[pkt_ipv4.dst][pkt_tcp.dst_port]
           self.logger.info("session from IP %s Source Port %s in dictionary is deleted.\n", pkt_ipv4.dst, pkt_tcp.dst_port)
           return
           #delete the flow mod
           #code

        
       

###     ##Drop any other pkt 
        else:
             dst = pkt_ethernet.dst
             src = pkt_ethernet.src
	
             #self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

             #learn a mac address to avoid FLOOD next time.
             self.mac_to_port[dpid][src] = in_port

             if dst in self.mac_to_port[dpid]:
        	  out_port = self.mac_to_port[dpid][dst]
             else:
        	  out_port = ofproto.OFPP_FLOOD

             actions = []

             data = None
             if msg.buffer_id == ofproto.OFP_NO_BUFFER:
        	  data = msg.data

             out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
        	                          in_port=in_port, actions=actions, data=data)
             datapath.send_msg(out)
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
     
        #pkt = packet.Packet(msg.data)    
        pkt = packet.Packet(array.array('B', ev.msg.data))
	pkt_ipv4 = pkt.get_protocol(ipv4.ipv4)
        pkt_tcp = pkt.get_protocol(tcp.tcp)
        pkt_ethernet = pkt.get_protocol(ethernet.ethernet)
	
        
        # ignore lldp packet
	if pkt_ethernet.ethertype == ether_types.ETH_TYPE_LLDP:    
            return
        
        #self.logger.info("\nNew Packet_In event")        
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        # If TCP communication, check if it has been an establisehd session 
        #if dpid == dpid_ovs:
        if pkt_ipv4 is not None and pkt_tcp is not None:
              self.alert_msg.setdefault(pkt_ipv4.dst, {})
              self.logger.info("\nNew TCP Packet_In event, pkt id = %s", pkt_ipv4.identification)
              dst = pkt_ethernet.dst
              src = pkt_ethernet.src       	
              self.logger.info("INFO[ dpid=%s : in_port=%s ; src=%s <-> dst=%s; \n %s:%s <-> %s:%s; bits= %s, seq= %s, ack= %s]", dpid, in_port, src, dst, pkt_ipv4.src, pkt_tcp.src_port, pkt_ipv4.dst, pkt_tcp.dst_port, bin(pkt_tcp.bits), pkt_tcp.seq, pkt_tcp.ack )
              dst_mac_hp = None
              src_mac_hp = None
              #TODO when honeyd used
              if pkt_ipv4.dst in self.config:
              	   dst_mac_hp = self.config[pkt_ipv4.dst]['MAC']
              	   #self.logger.info("\n The dst HP MAC is %s", dst_mac_hp)                
              elif pkt_ipv4.src in self.config:
                   src_mac_hp = self.config[pkt_ipv4.src]['MAC']
		   #self.logger.info("\n The src HP MAC is %s", src_mac_hp)
                
	      #if pkt_ipv4.dst not in self.sessions and pkt_ethernet.dst == dst_mac_hp:
              if pkt_ethernet.dst == dst_mac_hp:
                   self.logger.info("packet_in (-->) from [honeynet dpid= %s : in_port= %s]", datapath.id, in_port) 
                   self.manage_comm(pkt, ev) 
                   return
              #elif pkt_ipv4.dst in self.sessions and pkt_ethernet.src == src_mac_hp:
              elif pkt_ethernet.src == src_mac_hp:
                   self.logger.info("packet_in (<--) from [honeynet dpid= %s : in_port= %s]", datapath.id, in_port)
                   #if pkt_tcp.dst_port in self.sessions[pkt_ipv4.dst]: 
                   self.manage_backward_comm(pkt, ev) 
                   return
              else:
                   self.logger.info("packet_in from [non-honeynet dpid= %s : in_port= %s]", datapath.id, in_port)
                                  
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
                   return

	else:
	     dst = pkt_ethernet.dst
             src = pkt_ethernet.src        
	
             #self.logger.info("Non-TCP packet in [dpid=%s : in_port=%s ; src=%s <-> dst=%s]", dpid, in_port, src, dst)

             #learn a mac address to avoid FLOOD next time.
             self.mac_to_port[dpid][src] = in_port

             if dst in self.mac_to_port[dpid]:
        	  out_port = self.mac_to_port[dpid][dst]
             else:
        	  out_port = ofproto.OFPP_FLOOD

             actions = [parser.OFPActionOutput(out_port)]

             data = None
             if msg.buffer_id == ofproto.OFP_NO_BUFFER:
        	  data = msg.data

             out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
        	                          in_port=in_port, actions=actions, data=data)
             #time.sleep(0.05)
             datapath.send_msg(out)
             return
