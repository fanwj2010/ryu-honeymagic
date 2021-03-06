__author__ = 'efan'

from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import tcp
from ryu.lib.packet import ipv4
import datetime
import array
import random
import pprint

class Session:
     
    #Session states
    SESSION_INITIAL = 0

    #Attacker launches Session states
    A_TCP_HS_PLAY = 1
    A_TCP_ESTABLISHED = 2
    A_TCP_FORWARD = 3
    
    A_TCP_HS_REPLAY = 4
    A_TCP_REPLAY_ESTABLISHED = 5
    A_SESSION_JOINED = 6

    #Honeypot launches Session states
    H_TCP_HS_PLAY = 7
    H_TCP_ESTABLISHED = 8
    H_TCP_FORWARD = 9

    #End Session states
    SESSION_TERMINATED = 10
    SESSION_RESET = 11


    def __init__(self, src_ip, src_port, rqst_ip, in_port):
        self.src_ip = src_ip
        self.src_port = src_port
        self.syn_pkt = None
        self.syn_pkt_data = None
        self.seq = 0
        self.request_ip = rqst_ip
        self.reaction = None
        self.payload = None
        self.ack_pkt = None
        self.ack_pkt_data = None
        self.ack_fin_pkt = None
        self.request_uri = None
        self.host = None
        self.payload_pkt = None
        self.payload_pkt_data = None
        self.syn_ack_pkt = None
        self.client_src_mac = None
        self.in_port = in_port
        self.out_port = None
        self.controller_syn_seq = None
        self.honeypot_syn_seq = None
        self.frontend_syn_seq = None
        self.sesstime = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.state = self.SESSION_INITIAL
        self.main_dpid = 0


    #This function is used to generate a SYN_ACK response to a initial SYN request.
    def generateSYNACKtoSYN(self):
        ipv4_p = self.syn_pkt.get_protocol(ipv4.ipv4)
        tcp_P = self.syn_pkt.get_protocol(tcp.tcp)
        eth_p = self.syn_pkt.get_protocol(ethernet.ethernet)

        e = ethernet.ethernet(dst=eth_p.src, src=eth_p.dst)
        #The application allow to generate TCP/IP stack fingerprint by setting packet header information: IP ID, SYN seq number, etc.
        #In this version we simply use the inbound packet's header information
        ip = ipv4.ipv4(4, 5, ipv4_p.tos, ipv4_p.total_length, ipv4_p.identification, ipv4_p.flags, 0, ipv4_p.ttl, 6, 0, src=ipv4_p.dst, dst=ipv4_p.src, option=None)
        bits = 0 | 1 << 1 | 1 << 4  # SYN and ACK set
        #In this version we simply generate random SYN seq number
        random.seed(1)
        self.controller_syn_seq = random.randint(4000000000, 4100000000)
        seq = self.controller_syn_seq
        tcpd = tcp.tcp(tcp_P.dst_port, tcp_P.src_port, seq, tcp_P.seq+1, 0, bits, 65535, 0, 0, tcp_P.option)
        print  "SYN_ACK option=",  tcp_P.option
        #for p in self.syn_pkt:
        #    if p.protocol_name == 'ethernet':
        #        self.client_src_mac = p.src
        #        e = ethernet.ethernet(dst=p.src, src=p.dst)
        #    if p.protocol_name == 'ipv4':
        #        ip = ipv4.ipv4(4, 5, p.tos, 0, 0, 0, 0, 255, 6, 0, src=p.dst, dst=p.src, option=None)
        #    if p.protocol_name == 'tcp':
        #        bits = 0 | 1 << 1 | 1 << 4  # SYN and ACK set
        #        self.controller_syn_seq = 1 #random.randint(1, 100) # select random seq
                #TODO need a function to select it according to different OS
	#	seq = self.controller_syn_seq
                #print "src_port=", p.src_port, "dst_port=", p.dst_port, "seq=", p.seq, "ack=", p.ack, "bits=", p.bits, "win_size=", p.window_size, "urg=", p.urgent, "option=",  p.option
        #        tcpd = tcp.tcp(p.dst_port, p.src_port, seq, p.seq+1, 0, bits, 65535, 0, 0, None)

        p = packet.Packet()
        p.add_protocol(e)
        p.add_protocol(ip)
        p.add_protocol(tcpd)
        p.serialize()
        print "SYN_ACK is generated."
        return p


    def generateSYNpkt(self):
        #for p in self.syn_pkt:
        #    if p.protocol_name == 'ethernet':
        #        e = ethernet.ethernet(dst=p.dst, src=p.src)
        #    if p.protocol_name == 'ipv4':
        #        #ip_dst = self.serviceEngineIP
        #        ip = ipv4.ipv4(4, 5, p.tos, 0, p.identification, p.flags, 0, p.ttl, p.proto, 0, src=p.src, dst=p.dst, option=None)
        #    if p.protocol_name == 'tcp':
        #        #print "src_port=", p.src_port, "dst_port=", p.dst_port, "seq=", p.seq, "ack=", p.ack, "bits=", p.bits, "win_size=", p.window_size, "urg=", p.urgent, "option=",  p.option
        #        #str(bytearray(p.option))
        #        tcpd = tcp.tcp(p.src_port, p.dst_port, p.seq, p.ack, 0, p.bits, p.window_size, 0, p.urgent, p.option)
        ipv4_p = self.syn_pkt.get_protocol(ipv4.ipv4)
        tcp_P = self.syn_pkt.get_protocol(tcp.tcp)
        eth_p = self.syn_pkt.get_protocol(ethernet.ethernet)

        e = ethernet.ethernet(dst=eth_p.dst, src=eth_p.src)

        ip = ipv4.ipv4(4, 5, ipv4_p.tos, ipv4_p.total_length, ipv4_p.identification, ipv4_p.flags, 0, ipv4_p.ttl, 6, 0 , src=ipv4_p.src, dst=ipv4_p.dst, option=ipv4_p.option)

        tcpd = tcp.tcp(tcp_P.src_port, tcp_P.dst_port, tcp_P.seq, tcp_P.ack, 0, tcp_P.bits, tcp_P.window_size, 0, tcp_P.urgent, tcp_P.option)

        pkt = packet.Packet()
        pkt.add_protocol(e)
        pkt.add_protocol(ip)
        pkt.add_protocol(tcpd)
        pkt.serialize()
        print "SYN is generated."
        return pkt

    def generateACKtoSYNACK(self):
        ip_ack = self.ack_pkt.get_protocol(ipv4.ipv4)
        tcp_ack = self.ack_pkt.get_protocol(tcp.tcp)
        eth_ack = self.ack_pkt.get_protocol(ethernet.ethernet)

        ip_syn_ack = self.syn_ack_pkt.get_protocol(ipv4.ipv4)
        tcp_syn_ack = self.syn_ack_pkt.get_protocol(tcp.tcp)
        eth_syn_ack = self.syn_ack_pkt.get_protocol(ethernet.ethernet)

        e = ethernet.ethernet(dst=eth_syn_ack.src, src=eth_syn_ack.dst)

        ip = ipv4.ipv4(4, 5, ip_ack.tos, ip_ack.total_length, ip_ack.identification, ip_ack.flags, 0, ip_ack.ttl, ip_ack.proto, 0, src=ip_syn_ack.dst, dst=ip_syn_ack.src, option=ip_ack.option)

        tcpd = tcp.tcp(tcp_syn_ack.dst_port, tcp_syn_ack.src_port, tcp_syn_ack.ack, tcp_syn_ack.seq+1, 0, tcp_ack.bits, tcp_ack.window_size, 0, tcp_ack.urgent, tcp_ack.option)

        #for p in self.syn_ack_pkt:
        #    if p.protocol_name == 'ethernet':
        #        e = ethernet.ethernet(dst=p.src, src=p.dst)
        #    if p.protocol_name == 'ipv4':
                #ip = ipv4.ipv4(4, 5, p.tos, 0, ip_ack.identification, ip_ack.flags, 0, ip_ack.ttl, ip_ack.proto, 0, src=p.dst, dst=p.src, option=None)
        #        ip = ipv4.ipv4(4, 5, p.tos, 0, 0, 0, 0, 255, 6, 0, src=p.dst, dst=p.src, option=None)
        #    if p.protocol_name == 'tcp':
        #        tcpd = tcp.tcp(p.dst_port, p.src_port, p.ack, p.seq+1, 0, 1 << 4, tcp_ack.window_size, 0, 0)
        pkt = packet.Packet()
        pkt.add_protocol(e)
        pkt.add_protocol(ip)
        pkt.add_protocol(tcpd)
        pkt.serialize()
        print "ACK is generated."
        return pkt


    def generatePAYLOADpkt(self):
        ip_pl = self.payload_pkt.get_protocol(ipv4.ipv4)
        tcp_pl = self.payload_pkt.get_protocol(tcp.tcp)
        eth_pl = self.payload_pkt.get_protocol(ethernet.ethernet)

        ip_syn_ack = self.syn_ack_pkt.get_protocol(ipv4.ipv4)
        tcp_syn_ack = self.syn_ack_pkt.get_protocol(tcp.tcp)
        eth_syn_ack = self.syn_ack_pkt.get_protocol(ethernet.ethernet)

        e = ethernet.ethernet(dst=eth_syn_ack.src, src=eth_syn_ack.dst)
        ip = ipv4.ipv4(4, 5, ip_pl.tos, ip_pl.total_length, ip_pl.identification, ip_pl.flags, 0, ip_pl.ttl, ip_pl.proto, 0, ip_syn_ack.dst, ip_syn_ack.src, ip_pl.option)
        tcpd = tcp.tcp(tcp_syn_ack.dst_port, tcp_syn_ack.src_port, tcp_syn_ack.ack, tcp_syn_ack.seq+1, 0, tcp_pl.bits, tcp_pl.window_size, 0, tcp_pl.urgent, tcp_pl.option)

        #for p in self.syn_ack_pkt:
        #    if p.protocol_name == 'ethernet':
        #        e = ethernet.ethernet(p.src, p.dst)
        #    if p.protocol_name == 'ipv4':
        #        ip = ipv4.ipv4(4, 5, p.tos, 0, ipget.identification, ipget.flags, 0, ipget.ttl, ipget.proto, 0, p.dst, p.src, None)
        #    if p.protocol_name == 'tcp':
        #        tcpd = tcp.tcp(p.dst_port, p.src_port, p.ack, p.seq+1, 0, 1 << 4, tcpget.window_size, 0, 0)
        pkt = packet.Packet()
        pkt.add_protocol(e)
        pkt.add_protocol(ip)
        pkt.add_protocol(tcpd)
        #for p in self.payload_pkt:
        #    if isinstance(p, array.ArrayType):
        #        payload = str(bytearray(p))
        # Make sure variable payload is set
        #try:
        #    payload
        #except NameError:
        #    payload = None
        #pkt.add_protocol(payload)
        pkt.serialize()
        print "Payload is generated."
        return pkt

    def generateACKtoACKPSHpkt(self):
	ipv4_p = self.payload_pkt.get_protocol(ipv4.ipv4)
        tcp_P = self.payload_pkt.get_protocol(tcp.tcp)
        eth_p = self.payload_pkt.get_protocol(ethernet.ethernet)

        e = ethernet.ethernet(dst=eth_p.src, src=eth_p.dst)

        ip = ipv4.ipv4(4, 5, ipv4_p.tos, 0, ipv4_p.identification, ipv4_p.flags, 0, ipv4_p.ttl, ipv4_p.proto, 0, src=ipv4_p.dst, dst=ipv4_p.src, option=ipv4_p.option)

        bits = 1 << 4
        tcpd = tcp.tcp(tcp_P.dst_port, tcp_P.src_port, tcp_P.ack, tcp_P.seq+1, 0, bits , tcp_P.window_size, 0, tcp_P.urgent, option=tcp_P.option)

        ack_pkt = packet.Packet()
        ack_pkt.add_protocol(e)
        ack_pkt.add_protocol(ip)
        ack_pkt.add_protocol(tcpd)
        ack_pkt.serialize()
        print "ACK packet is generated."
        return ack_pkt

    def generateRSTpkt(self):
	ipv4_p = self.payload_pkt.get_protocol(ipv4.ipv4)
        tcp_P = self.payload_pkt.get_protocol(tcp.tcp)
        eth_p = self.payload_pkt.get_protocol(ethernet.ethernet)

        e = ethernet.ethernet(dst=eth_p.src, src=eth_p.dst)

        #ip = ipv4.ipv4(4, 5, ipv4_p.tos, 0, 0, 0, 0, 255, 6, 0, src=ipv4_p.dst, dst=ipv4_p.src, option=None)
        #ip = ipv4.ipv4(4, 5, ipv4_p.tos, 0, ipv4_p.identification, ipv4_p.flags, 0, ipv4_p.ttl, ipv4_p.proto, 0, src=ipv4_p.src, dst=ipv4_p.dst, option=None)
        ip = ipv4.ipv4(4, 5, ipv4_p.tos, 0, ipv4_p.identification, ipv4_p.flags, 0, ipv4_p.ttl, ipv4_p.proto, 0, src=ipv4_p.dst, dst=ipv4_p.src, option=ipv4_p.option)

        bits = 1 << 4 | 1 << 2
        tcpd = tcp.tcp(tcp_P.dst_port, tcp_P.src_port, tcp_P.ack, tcp_P.seq+1, 0, bits , tcp_P.window_size, 0, tcp_P.urgent, option=tcp_P.option)

        rst_pkt = packet.Packet()
        rst_pkt.add_protocol(e)
        rst_pkt.add_protocol(ip)
        rst_pkt.add_protocol(tcpd)
        rst_pkt.serialize()
        print "RST packet is generated."
        return rst_pkt

    def generateFINpkt(self):
	ipv4_p = self.payload_pkt.get_protocol(ipv4.ipv4)
        tcp_P = self.payload_pkt.get_protocol(tcp.tcp)
        eth_p = self.payload_pkt.get_protocol(ethernet.ethernet)

        e = ethernet.ethernet(dst=eth_p.dst, src=eth_p.src)

        #ip = ipv4.ipv4(4, 5, ipv4_p.tos, 0, 0, 0, 0, 255, 6, 0, src=ipv4_p.dst, dst=ipv4_p.src, option=None)
        #ip = ipv4.ipv4(4, 5, ipv4_p.tos, 0, ipv4_p.identification, ipv4_p.flags, 0, ipv4_p.ttl, ipv4_p.proto, 0, src=ipv4_p.src, dst=ipv4_p.dst, option=None)
        ip = ipv4.ipv4(4, 5, ipv4_p.tos, 0, ipv4_p.identification, ipv4_p.flags, 0, ipv4_p.ttl, ipv4_p.proto, 0, src=ipv4_p.dst, dst=ipv4_p.src, option=None)

        bits = 1 | 1 << 4
        #tcpd = tcp.tcp(tcp_P.src_port, tcp_P.dst_port, tcp_P.seq, tcp_P.ack, 0, bits, tcp_P.window_size, 0, tcp_P.urgent, tcp_P.option)
        tcpd = tcp.tcp(tcp_P.dst_port, tcp_P.src_port, tcp_P.seq, tcp_P.ack, 0, bits, tcp_P.window_size, 0, tcp_P.urgent, tcp_P.option)

        fin_pkt = packet.Packet()
        fin_pkt.add_protocol(e)
        fin_pkt.add_protocol(ip)
        fin_pkt.add_protocol(tcpd)
        fin_pkt.serialize()
        print "FIN packet is generated."
        return fin_pkt



    def setReaction(self, reaction):
        self.reaction = reaction
        print 'Session action is', self.reaction

    def getReaction(self):
        return self.reaction

    # This function is used to save the incoming ACK packet for our SYN_ACK for later use
    def saveACKpkt(self, pkt):
        self.ack_pkt = pkt

    def saveACKpktdata(self, pkt_data):
        self.ack_pkt_data = pkt_data

    def saveSYNpkt(self, pkt):
        self.syn_pkt = pkt

    def saveSYNpktdata(self, pkt_data):
        self.syn_pkt_data = pkt_data

    def getSYNpkt(self):
        return self.syn_pkt

    def setPayload(self, payload):
        self.payload = payload

    def savePAYLOADpkt(self, pkt):
        self.payload_pkt = pkt

    def savePAYLOADpktdata(self, pkt_data):
        self.payload_pkt_data = pkt_data

    def saveSYNACKpkt(self, pkt):
        self.syn_ack_pkt = pkt

    def saveACKFINpkt(self, pkt):
        self.ack_fin_pkt = pkt


    def setState(self, state):
        self.state = state
        #print 'Set [', self.src_ip, ':', self.src_port, '] session state =', self.state
        print 'Session state =', self.state

    def getState(self):
        return self.state

    def setOutport(self, port):
	self.out_port = port
        #print "out port number is: ", self.out_port


    def getOutport(self):
        return self.out_port

    def setRequestURI(self, uri):
        self.request_uri = uri

    def setHost(self, host):
        self.host = host

    def saveHPseq(self, seq):
        self.seq = seq
    def getCounterDiff(self):
        return self.seq

    def saveHPsynseq(self, seq):
        self.honeypot_syn_seq = seq
    def getHPsynseq(self):
	return self.honeypot_syn_seq

    def saveFRONTsynseq(self, seq):
        self.frontend_syn_seq = seq
    def getFRONTsynseq(self):
	return self.frontend_syn_seq

    def saveCTRLsynseq(self, seq):
        self.controller_syn_seq = seq
    def getCTRLsynseq(self, seq):
        return self.controller_syn_seq

    def getSEQDiff(self, f_seq, b_seq):
	#CounterDiff = self.controller_syn_seq - self.honeypot_syn_seq
        CounterDiff = f_seq - b_seq
        return CounterDiff
    def getACKDiff(self, b_seq, f_seq):
	#CounterDiff = self.honeypot_syn_seq - self.controller_syn_seq
        CounterDiff = b_seq - f_seq
        return CounterDiff

    def getRequestIP(self):
        return self.request_ip

    #def setServiceEngineIP(self, ipadd):
    #    self.serviceEngineIP = ipadd

    #def getServiceEngineIP(self):
    #    return self.serviceEngineIP

    def getClientMac(self):
        return self.client_src_Mac

    def getClientInPort(self):
        return self.inport

    def getsrcPort(self):
        return self.src_port

    def getsrcIP(self):
        return self.src_ip

    def getreqURI(self):
        return self.request_uri

    def getSessionTime(self):
        return self.sesstime

    def getHost(self):
        return self.host
