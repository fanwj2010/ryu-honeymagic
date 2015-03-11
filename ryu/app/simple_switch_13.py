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
from ryu.cdnapp.session import Session
from ryu.cdnapp.cdnapp import Cdnapp
from ryu.cdnapp.exceptions import CustomException, badStateException
import ryu.controller.dpset
from ryu.controller.dpset import EventDP
import array
import pprint

class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.sessions = {}
        self.cdn = Cdnapp()
        self.RequestRouters = []

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

        routers = self.cdn.getRequestRouters()
        for rkeys in routers.keys():
            #Filling up the requestrouters array with ip addresses for later easier use.
            self.RequestRouters.append(routers[rkeys]['ip_address'])
            match = parser.OFPMatch(eth_type=0x800, ipv4_dst=routers[rkeys]['ip_address'], ip_proto=6, tcp_dst=80)
            actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
            self.add_flow(datapath, 2, match, actions)

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

        print "installing flow mod with priority " + str(priority) + " match fields " + str(match) + " actions " + str(actions)

        datapath.send_msg(mod)

    def prepare_backward_match_action(self, pkt, parser, ofproto):
        ipd = pkt.get_protocol(ipv4.ipv4)
        tcpd = pkt.get_protocol(tcp.tcp)

        match = parser.OFPMatch(eth_type=0x800, ipv4_dst=ipd.src, ip_proto=6, tcp_dst=tcpd.src_port)

        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]

        return match, actions

    def manage_cdncomm(self, pkt, ev):
        msg = ev.msg
        datapath = msg.datapath
        dpid = datapath.id
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        ethdat = pkt.get_protocol(ethernet.ethernet)
        ipv4dat = pkt.get_protocol(ipv4.ipv4)

        src_ip = ipv4dat.src
        dst_ip = ipv4dat.dst

        tcpdat = pkt.get_protocol(tcp.tcp)

        # Parsing of packet and getting payload
        for p in pkt:
            if isinstance(p, array.ArrayType):
                payload = str(bytearray(p))
        # Make sure variable payload is set

        try:
            payload
        except NameError:
            payload = None

        # SYN IS SET, MEANS WE ARE DECLARING A NEW SESSION AND STORE THE ORIGINAL PACKET. SENDING A SYN ACK RESPONSE
        if tcpdat.bits & 0x2:
            sess = Session(src_ip, tcpdat.src_port, pkt, dst_ip, ethdat.dst)
            if src_ip in self.sessions:
                self.sessions[src_ip][tcpdat.src_port] = sess
            else:
                self.sessions[src_ip] = {}
                self.sessions[src_ip][tcpdat.src_port] = sess

            #Generating ACK response to the TCP SYN
            ackpkt = sess.generateACKtoSYN()
            data = ackpkt.data

            actions = [parser.OFPActionOutput(in_port)]
            out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,
                                      in_port=ofproto.OFPP_CONTROLLER, actions=actions, data=data)
            datapath.send_msg(out)
            sess.setState(Session.SYNACKSENT)

            return

        # ACK IS SET
        if tcpdat.bits & 1 << 4:
            try:
                sess = self.sessions[src_ip][tcpdat.src_port]
                if sess.getState() == Session.SYNACKSENT:
                    # this is probably a ack to SYNACK
                    if payload is None:
                        sess.saveACKpkt(pkt)
                        sess.setState(Session.ACKRECV)
                        print 'ACK packet saved for our session. Waiting for HTTP GET'
                        return
                    else:
                        raise badStateException('Received ACK with payload in state ' + sess.getState())
                        return

                if sess.getState() == Session.ACKRECV:
                    # We should catch HTTP GET now
                    if payload is not None:
                        request = payload.split('\n', 1)[0]
                        print 'Request is ', request
                        sess.setState(Session.HTTPGETRECV)
                        sess.setRequestURI(request)
                        sess.saveHTTPGETpkt(pkt)
                        sess.setPayload(payload)

                        seip, semac = self.cdn.getSeForIP(sess.srcip)
                        sess.setServiceEngineIPandMAC(seip, semac)
                        synpkt = sess.generateSYNpkt()

                        match, actions = self.prepare_backward_match_action(synpkt, parser, ofproto)

                        self.add_flow(datapath, 2, match, actions)

                        data = synpkt.data

                        #TODO make sure mac address is in this table else create a ARP request ?!
                        if semac in self.mac_to_port[dpid]:
                            out_port = self.mac_to_port[dpid][semac]

                        actions = [parser.OFPActionOutput(out_port)]
                        out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,
                                                  in_port=ofproto.OFPP_CONTROLLER, actions=actions, data=data)
                        datapath.send_msg(out)
                        sess.setState(Session.SYNSENT)

                        return
                    else:
                        raise badStateException('We did not received ACK with payload in state ' + sess.getState())

            except Exception:
                print Exception.message
                #TODO update state

    def manage_backward_cdncomm(self, pkt, ev):
        msg = ev.msg
        in_port = msg.match['in_port']
        datapath = msg.datapath
        dpid = datapath.id
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        ipd = pkt.get_protocol(ipv4.ipv4)
        tcpdat = pkt.get_protocol(tcp.tcp)

        sess = self.sessions[ipd.dst][tcpdat.dst_port]

        if sess.getState() == Session.SYNSENT:
            if tcpdat.bits == 1 << 4 | 1 << 1:
                sess.setState(Session.SYNACKRECV)
                sess.saveSEseq(tcpdat.seq)
                sess.saveSYNACKpkt(pkt)

                #GENERATE ACK TO SYN ACK
                ackpkt = sess.generateACKtoSYNACK()

                data = ackpkt.data

                actions = [parser.OFPActionOutput(in_port)]
                out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,
                                          in_port=ofproto.OFPP_CONTROLLER, actions=actions, data=data)
                datapath.send_msg(out)

                rrip, rrmac = sess.getRequestRouterIPandMAC()
                print rrip, rrmac
                seip, semac = sess.getServiceEngineIPandMAC()
                print seip, semac

                #SRCmatch, direction to Service Engine
                match = parser.OFPMatch(eth_type=0x800, ipv4_src=sess.srcip, ip_proto=6, tcp_src=sess.srcport)
                actions = [parser.OFPActionSetField(tcp_ack=sess.getCounterDiff() - 1), parser.OFPActionSetField(ipv4_dst=seip),
                           parser.OFPActionSetField(eth_dst=semac),
                           parser.OFPActionOutput(self.mac_to_port[dpid][semac])]
                self.add_flow(datapath, 3, match, actions)

                #DSTmatch, directino from Service Engine
                match = parser.OFPMatch(eth_type=0x800, ipv4_dst=sess.srcip, ip_proto=6, tcp_dst=sess.srcport)
                tcpseq = 0xffffffff - sess.getCounterDiff() + 2
                actions = [parser.OFPActionSetField(tcp_seq=tcpseq), parser.OFPActionSetField(ipv4_src=rrip),
                           parser.OFPActionSetField(eth_src=rrmac),
                           parser.OFPActionOutput(self.mac_to_port[dpid][sess.getClientMac()])]
                self.add_flow(datapath, 3, match, actions)

                #TODO send HTTP GET
                #As soon as dsn server will be up we make this

                return


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

        # pkt = packet.Packet(msg.data)
        pkt = packet.Packet(array.array('B', ev.msg.data))
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        # IF TCP communication, check if it is related to the CDNAPP
        ipv4dat = pkt.get_protocol(ipv4.ipv4)
        tcpdat = pkt.get_protocol(tcp.tcp)
        if ipv4dat is not None:
            if ipv4dat.dst in self.RequestRouters:
                if tcpdat is not None:
                    if tcpdat.dst_port == 80:
                        self.manage_cdncomm(pkt, ev)
                        return
            else:
                if tcpdat is not None:
                    if ipv4dat.dst in self.sessions:
                        if tcpdat.dst_port in self.sessions[ipv4dat.dst]:
                            self.manage_backward_cdncomm(pkt, ev)
                            return

        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        print self.mac_to_port

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


    @set_ev_cls(EventDP, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        print ev.enter