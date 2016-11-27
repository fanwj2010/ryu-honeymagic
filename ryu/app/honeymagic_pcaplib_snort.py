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

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
         
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

        self.alertfile_handle = open(self.alert_file, 'w+')
        self.pcapfile_handle = open(self.pcap_file, 'wb')
        self.rulefile_handle = open(self.snort_rules, 'rb')
      
        self.snort_command = "snort -A fast " +" -r " + self.pcap_file + " -l "+ self.log_dir + " -c " + self.snort_conf + " -D"
	#self.pcap_writer = pcaplib.Writer(open('test.pcap', 'wb'))    

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
        
        if datapath.id == self.main_ovs:
           self.logger.info("dpid = %d, main dpid = %d", datapath.id, self.main_ovs)
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

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
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
       

    def del_flow(self, datapath, priority, match, actions, out_port):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]

        mod = parser.OFPFlowMod(datapath=datapath, command=ofproto_v1_3.OFPFC_DELETE, out_port=out_port, priority=priority, match=match, instructions=inst)
        self.logger.info("deleting flow mod in dpid %s in out port %s , with priority %s match fields %s actions %s",str(datapath.id), str(out_port), str(priority), str(match), str(actions))
        datapath.send_msg(mod)
       

    def add_backward_flow(self, datapath, pkt):
        self.logger.info("Prepare backward flow mod that is from honeypot to controller.")
        ofproto = datapath.ofproto
	parser = datapath.ofproto_parser
        ipd = pkt.get_protocol(ipv4.ipv4)
        tcpd = pkt.get_protocol(tcp.tcp)    
        
        match = parser.OFPMatch(eth_type=0x800, ip_proto=6, ipv4_dst=ipd.src, tcp_dst=tcpd.src_port, ipv4_src=ipd.dst, tcp_src=tcpd.dst_port)
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 3, match, actions)
        self.logger.info("The backward flow mod from honeypot to controller is set.")
 

    def snort_detect(self, pkt_data): 
        self.alertfile_handle = open(self.alert_file, 'w+')
        self.pcapfile_handle = open(self.pcap_file, 'wb')  	
        #clean up the alert file
        self.alertfile_handle.seek(0)
        self.alertfile_handle.truncate()
        
        #save the pkt to pcap
        self.pcapfile_handle.seek(0)
        self.pcapfile_handle.truncate()         
        self.pcap_writer = pcaplib.Writer(self.pcapfile_handle)
           
        self.pcap_writer.write_pkt(pkt_data)
        self.pcapfile_handle.flush()
        self.pcapfile_handle.close()        
        
        #Execute Snort
        p = subprocess.Popen(self.snort_command, stdout=subprocess.PIPE, shell=True)
        (output, err) = p.communicate()
        p_statue = p.wait()
        
        #read the alert file and return result  
        self.alertfile_handle.flush()
        try:
           alertline = self.alertfile_handle.readlines()
        except:
           pass
        alert_rt = None
        try: 
           alertline[0]
           self.logger.info("alert is: %s", alertline[0])
           if "DROP" in alertline[0]:
               alert_rt = "DROP"
           elif  "HIH" in alertline[0]:
               alert_rt = "HIH"
           else:
               alert_rt = "MIH" 
        except:
           self.logger.info("alert is none") 
           alert_rt = "DROP"

        self.alertfile_handle.close() 
        
        self.logger.info("alert is %s", alert_rt)
        self.alert.put(alert_rt) 
        #return alert_rt        

    def lookupOutPort(self, port_name):
        interface = port_name
        command = "ovs-vsctl get Interface "+ interface + " ofport"
        p = subprocess.Popen(command, stdout=subprocess.PIPE, shell=True)
        (output, err) = p.communicate()
        p_statue = p.wait()
        self.logger.info("out port number = %s", output)
        #print "ofprot number is :", output
        self.lookup.put(output)


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
              
	#Get the session that the pkt belong to, Regist a new session if the session was not registed
        if src_ip in self.sessions:
           self.logger.info("\nsrc IP (%s) is in sessions, packet_in from switch dpid= %s", src_ip, dpid)
           if pkt_tcp.src_port in self.sessions[src_ip]:
              #self.logger.info("src Port (%s) is in sessions, packet_in from switch dpid= %s",pkt_tcp.src_port, dpid)
              sess = self.sessions[src_ip][pkt_tcp.src_port]
           else:
              #self.logger.info("src Port (%s) is NOT in sessions, packet_in from switch dpid= %s",pkt_tcp.src_port, dpid)
              sess = Session(src_ip, pkt_tcp.src_port, pkt, dst_ip, pkt_ethernet.dst)
              self.sessions[src_ip] = {}
              self.sessions[src_ip][pkt_tcp.src_port] = sess
              self.logger.info("\nsession from IP %s Source Port %s in dictionary is created.\n", src_ip, pkt_tcp.src_port)
        else:
           self.logger.info("\nsrc IP (%s) is NOT in sessions, packet_in from switch dpid= %s", src_ip, dpid)
           sess = Session(src_ip, pkt_tcp.src_port, pkt, dst_ip, pkt_ethernet.dst)
           self.sessions[src_ip] = {}
           self.sessions[src_ip][pkt_tcp.src_port] = sess
           self.logger.info("\nsession from IP %s Source Port %s in dictionary is created.\n", src_ip, pkt_tcp.src_port)

        #state_pkt = sess.getState()
        #self.logger.info("Session state = %s, BITS = %s", state_pkt, str(pkt_tcp.bits)) 	
        #if pkt_tcp.bits == 24 or pkt_tcp.bits == 25:
        #   if pkt_tcp.src_port in self.sessions[pkt_ipv4.src]:
        #      del self.sessions[pkt_ipv4.src][pkt_tcp.src_port]
        #      self.logger.info("\nRST: session from IP %s Source Port %s in dictionary is deleted.\n", pkt_ipv4.src, pkt_tcp.src_port)
              

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
           self.logger.info("Session terminated (inbound), ACK_FIN is forwarded [dpid= %s : session state= %s]", dpid, sess.getState()) 
           return	            


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
           self.logger.info("Session joined (inbound), Pkt is forwarded [dpid= %s : session state= %s]", dpid, sess.getState())
           
           if pkt_tcp.bits == 1 | 1 << 4:
              sess.setState(Session.SESSIONTERMINATED)
              self.logger.info("Session terminated (inbound), ACK_FIN is forwarded [dpid= %s : session state= %s]", dpid, sess.getState())
           return
                        

        #SYN IS SET, MEANS WE ARE DECLARING A NEW SESSION AND STORE THE ORIGINAL PACKET. SENDING A SYN ACK RESPONSE
        if pkt_tcp.bits & 0x2 and sess.getState() == Session.INITIALSESSION:
	   sess.setState(Session.SYNRECV)
           self.logger.info("Session initial (inbound), SYN is received [dpid= %s : session state= %s]", dpid, sess.getState()) 
           
           serv_port_dict = ast.literal_eval(self.config[pkt_ipv4.dst]['LIH-services'])
           for serv, port in serv_port_dict.iteritems():
               if port == pkt_tcp.dst_port:
                  self.logger.info("[%s : %s]", serv, pkt_tcp.dst_port)  
                  #Generating SYN_ACK response to the TCP SYN
                  syn_ack_pkt = sess.generateSYNACKtoSYN()
                  data = syn_ack_pkt.data
                  actions = [parser.OFPActionOutput(in_port)]
                  out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER, in_port=ofproto.OFPP_CONTROLLER, actions=actions, data=data)
                  datapath.send_msg(out) 
                  sess.setState(Session.SYNACKSENT)
                  self.logger.info("Session initial (outbound), SYN_ACK is forwarded [dpid= %s : session state= %s]", dpid, sess.getState()) 
           return 
        #else:
        #   raise badStateException('SYN_ACK failed ')
        #   return

        if pkt_tcp.bits & 0x2 and sess.getState() == Session.SYNSENT:
           self.logger.info("Session replaying (inbound), SYN is received [dpid= %s : session state= %s]", dpid, sess.getState()) 
           hp_mac = pkt_ethernet.dst         
           if hp_mac in self.mac_to_port[dpid]:
              out_port = self.mac_to_port[dpid][hp_mac]             	
              #self.logger.info("hp mac in mac_to_port, dpid is %s, hp_mac is %s, outport is %s", dpid, hp_mac, out_port)
           else:
              out_port = ofproto.OFPP_FLOOD
              #self.logger.info("OFPP_FLOOD dpid is %s, hp_mac is %s, outport is %s", dpid, hp_mac, out_port)
              out_port = 2
              self.mac_to_port[dpid][hp_mac] = out_port
           #self.logger.info("!!!!!!out_port %s", out_port)
           syn_pkt = sess.generateSYNpkt()
           data = syn_pkt.data
           actions = [parser.OFPActionOutput(out_port)]
           out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,in_port=ofproto.OFPP_CONTROLLER, actions=actions, data=data)
           datapath.send_msg(out)
           sess.setState(Session.SYNSENT)
	   self.logger.info("Session replaying (inbound), SYN is forwarded [dpid= %s : session state= %s]", dpid, sess.getState())
           return

        #else:
        #   raise badStateException('SYN forward is failed ')
        #   return


        #ACK is SET
        if pkt_tcp.bits & 1 << 4 and sess.getState() == Session.SYNACKSENT:
           # this is probably a ACK to SYN_ACK
           if payload is None:
               sess.saveACKpkt(pkt)
               sess.setState(Session.ACKRECV)
               self.logger.info("Session initial (inbound), ACK is received [dpid= %s : session state= %s]", dpid, sess.getState())
               return
           else:
               #raise badStateException('Received ACK with payload in state')
               pass
        
        
	if pkt_tcp.bits & 1 << 4 and sess.getState() == Session.ACKRECV:
           # We should catch the first payload pkt now
           if payload is not None and pkt_tcp.bits & 1 << 3:
              self.logger.info("Session initial (inbound), payload pkt is received [dpid= %s : session state= %s]", dpid, sess.getState())
              #request = payload.split('\n', 1)[0]                    
              sess.savePAYLOADpkt(pkt)
              sess.setPayload(payload)
              sess.setState(Session.PAYLOADRECV)
              self.logger.info("Payload is received: %s ", payload)
              pkt_data=msg.data
	      try:
	   	  self.logger.info("Snort Detection")
                  self.snort_detect(pkt_data)
	      except Exception:
                  print Exception.message
	   	      
              alert_rt = self.alert.get()
              self.logger.info("snort alert result is %s", alert_rt) 
              if alert_rt == "DROP":
                  self.logger.info("DROP !!! RST The Connection!")                                          
                  rst_pkt = sess.generateRSTpkt()                          
                  data = rst_pkt.data
                  actions = [parser.OFPActionOutput(in_port)]
                           
	          out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,
                                            in_port=ofproto.OFPP_CONTROLLER, actions=actions, data=data)                          
                  datapath.send_msg(out)                                                    
                  sess.setState(Session.SESSIONTERMINATED)
                  self.logger.info("Session reset, RST is sent back [dpid= %s : session state= %s : in_port= %s]", dpid, sess.getState(), in_port)
                  del self.sessions[pkt_ipv4.src][pkt_tcp.src_port]
                  self.logger.info("\nsession from IP %s Source Port %s in dictionary is deleted.\n", pkt_ipv4.src, pkt_tcp.src_port) 
                  return 
              else:		                             
                  redirect_dst = alert_rt
                  out_port_name = self.config[pkt_ipv4.dst][redirect_dst]                      
            
                  hp_mac = pkt_ethernet.dst                        
            
                  syn_pkt = sess.generateSYNpkt()		      
                  self.add_backward_flow(datapath, syn_pkt) 
                  if hp_mac in self.mac_to_port[dpid]:
                       out_port = self.mac_to_port[dpid][hp_mac]
                       dpid_ovs = int(self.config[pkt_ipv4.dst]['ovs-dpid'])
                       honeypot_mac = self.config[pkt_ipv4.dst]['MAC']                        
                       if hp_mac == honeypot_mac and dpid == dpid_ovs:
                             self.logger.info("Lookup out port")
                             self.lookupOutPort(out_port_name)                          
	     	             out_put_value = int(self.lookup.get())
	                     self.mac_to_port[dpid][hp_mac] = out_put_value
	                     out_port = out_put_value
	    	      	     sess.setOutport(out_port)		
                  else:
                       out_port = ofproto.OFPP_FLOOD
                  
                  actions = [parser.OFPActionOutput(out_port)]
                           
                  out = parser.OFPPacketOut(datapath=datapath,buffer_id=ofproto.OFP_NO_BUFFER,
                                      in_port=ofproto.OFPP_CONTROLLER, actions=actions,data=syn_pkt.data)
                      
                  datapath.send_msg(out)
                  
                  sess.setState(Session.SYNSENT)
                  self.logger.info("Session start replaying, SYN is forwarded [dpid= %s : session state= %s]", dpid, sess.getState())
                  return
           else:
                #raise badStateException('We did not received ACK with payload in state ' )
                pass
           

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
        
        #self.logger.info("packet_in from switch dpid=%s src=%s dst=%s inport=%s", dpid, pkt_ethernet.src, pkt_ethernet.dst, in_port)
        
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
           self.logger.info("Session terminated (outbound), ACK_FIN is forwarded [dpid= %s : session state= %s]", dpid, sess.getState())
           del self.sessions[pkt_ipv4.dst][pkt_tcp.dst_port]
           self.logger.info("session from IP %s Source Port %s in dictionary is deleted.\n", pkt_ipv4.dst, pkt_tcp.dst_port)
           return
           #delete the flow mod
           #code

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
           self.logger.info("Session joined (outbound), pkt is forwarded [dpid= %s : session state= %s]", dpid, sess.getState())


           if pkt_tcp.bits == 1 | 1 << 4:
                 #if pkt_ipv4.dst in self.sessions:
                 #del self.sessions[pkt_ipv4.dst]
              sess.setState(Session.SESSIONTERMINATED)
              self.logger.info("Session joined (outbound), ACK_FIN is forwarded [dpid= %s : session state= %s]", dpid, sess.getState())
              #delete the flow mod
              #code

           return
       

        if sess.getState() == Session.PAYLOADSENT:
           self.logger.info("Session replaying (outbound), payload pkt is received [dpid= %s : session state= %s]", dpid, sess.getState())
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
           self.logger.info("Session joined (outbound), payload pkt is forwarded [dpid= %s : session state= %s]", dpid, sess.getState())
           return

        if sess.getState() == Session.SYNSENT:
            # SYN and ACK is set
            if pkt_tcp.bits == 1 << 4 | 1 << 1:
                sess.setState(Session.SYNACKRECV)
                self.logger.info("Session replaying (outbound), SYN_ACK is received [dpid= %s : session state= %s]", dpid, sess.getState())
                sess.saveHPsynseq(pkt_tcp.seq)
                sess.saveSYNACKpkt(pkt)

                #GENERATE ACK TO SYN ACK
                ack_pkt = sess.generateACKtoSYNACK()

                data = ack_pkt.data

                actions = [parser.OFPActionOutput(in_port)]
                out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER, in_port=ofproto.OFPP_CONTROLLER, actions=actions, data=data)
                datapath.send_msg(out)
		sess.setState(Session.ACKSENT)
                self.logger.info("Session replaying (inbound), ACK is sent [dpid= %s : session state= %s]", dpid, sess.getState())
                 
                self.logger.info("Set the ofsoftswitch13 [dpid= %s] actions for SEQ sychronization", dpid)
                   
                #SRCmatch, direction to Honeypot
                match = parser.OFPMatch(eth_type=0x800, eth_dst=pkt_ethernet.src, ip_proto=6, ipv4_src=sess.src_ip, ipv4_dst=pkt_ipv4.src, tcp_src=sess.src_port, tcp_dst=pkt_tcp.src_port)
		hp_mac = pkt_ethernet.src
                #self.logger.info("hp_mac=%s", hp_mac)

                #out_port_tohp = 0
                if hp_mac in self.mac_to_port[dpid]:
                    out_port = self.mac_to_port[dpid][hp_mac]		
                else:
                    out_port = ofproto.OFPP_FLOOD
                #out_port = 2   
                self.logger.info("out_port_tohp=%s", out_port)
                ack_diff = sess.getACKDiff()
                actions = [parser.OFPActionSetField(tcp_ack_diff=ack_diff), parser.OFPActionOutput(out_port)]
                self.add_flow(datapath, 3, match, actions)
                self.logger.info("Set flow mod in [dpid= %s : outport= %s] direct to hp (inbound)", dpid, out_port)
		   
                #DSTmatch, direction from Honeypot
                match = parser.OFPMatch(eth_type=0x800, eth_dst=pkt_ethernet.dst, ip_proto=6, ipv4_src=pkt_ipv4.src, ipv4_dst=sess.src_ip, tcp_src=pkt_tcp.src_port, tcp_dst=sess.src_port)
                atk_mac = pkt_ethernet.dst
                self.logger.info("atk_mac=%s", atk_mac)
                #out_port_fromhp = None
                if atk_mac in self.mac_to_port[dpid]:
                    out_port = self.mac_to_port[dpid][atk_mac]		
                else:
                    out_port = ofproto.OFPP_FLOOD
                #out_port = 1
                self.logger.info("out_port_fromhp=%s", out_port)
                seq_diff = sess.getSEQDiff()
                actions = [parser.OFPActionSetField(tcp_seq_diff=seq_diff), parser.OFPActionOutput(out_port)]
                self.add_flow(datapath, 3, match, actions)
                self.logger.info("Set flow mod in [dpid= %s : outport= %s] direct from hp (outbound)", dpid, out_port)

                #TODO send the payload pkt 
                payload_pkt = sess.generatePAYLOADpkt()
                out_port = sess.getOutport()
                actions = [parser.OFPActionOutput(out_port)]
                data = payload_pkt.data
                out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER, in_port=ofproto.OFPP_CONTROLLER, actions=actions, data=data)
                datapath.send_msg(out)
      	        sess.setState(Session.PAYLOADSENT)
                self.logger.info("Session replaying (inbound), payload pkt is sent [dpid= %s : session state= %s]", dpid, sess.getState())
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


        # If TCP communication, check if it has been an establisehd session 
        #if dpid == dpid_ovs:
        if pkt_ipv4 is not None and pkt_tcp is not None:
              dst_mac_hp = None
              src_mac_hp = None
           
              if pkt_ipv4.dst in self.config:
              	   dst_mac_hp = self.config[pkt_ipv4.dst]['MAC']
              	   #self.logger.info("\n The dst HP MAC is %s", dst_mac_hp)                
              elif pkt_ipv4.src in self.config:
                   src_mac_hp = self.config[pkt_ipv4.src]['MAC']
		   #self.logger.info("\n The src HP MAC is %s", src_mac_hp)
                
	      if pkt_ipv4.dst not in self.sessions and pkt_ethernet.dst == dst_mac_hp:
                   self.logger.info("\npacket_in (inbound) from [switch= %s : in_port= %s]", datapath.id, in_port) 
                   self.manage_comm(pkt, ev) 
                   return
              elif pkt_ipv4.dst in self.sessions and pkt_ethernet.src == src_mac_hp:
                   self.logger.info("\npacket_in (outbound) from [switch= %s : in_port= %s]", datapath.id, in_port)
                   if pkt_tcp.dst_port in self.sessions[pkt_ipv4.dst]: 
                       #self.logger.info("then ipv4 dst =%s, tcp dst =%s ", pkt_ipv4.dst, pkt_tcp.dst_port)                    
                       self.manage_backward_comm(pkt, ev) 
                       return
              else:
                   self.logger.info("\npacket_in (outside switches) from [switch= %s : in_port= %s]", datapath.id, in_port)   
		   dst = pkt_ethernet.dst
                   src = pkt_ethernet.src

        	   dpid = datapath.id
        	   self.mac_to_port.setdefault(dpid, {})
        
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
        	   	#if msg.buffer_id != ofproto.OFP_NO_BUFFER:
        	   	#     self.add_flow(datapath, 1, match, actions, msg.buffer_id)
        	   	#     return
        	   	#else:
        	   	#     self.add_flow(datapath, 1, match, actions)
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

             dpid = datapath.id
             self.mac_to_port.setdefault(dpid, {})
	
             #self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

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
             datapath.send_msg(out)
             return
