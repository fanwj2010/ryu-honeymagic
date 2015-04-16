__author__ = 'thomas'

from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import tcp
from ryu.lib.packet import ipv4


class Session:

    # FROM CLIENT STATES
    SYNRECV = 1
    SYNACKSENT = 2
    ACKRECV = 3
    HTTPGETRECV = 4

    # TO CDN ENGINE STATES
    SYNSENT = 5
    SYNACKRECV = 6
    ACKSENT = 7
    HTTPGETSENT = 8

    # FINAL STATES
    SESSIONSJOINED = 9
    CDNERROR = 10


    def __init__(self, srcip, srcport, pkt, rrip, inport):
        self.srcip = srcip
        self.srcport = srcport
        self.synpkt = pkt
        self.seq = 0
        self.requestRouterIP = rrip
        self.serviceEngineIP = None
        self.ackpkt = None
        self.requesturi = None
        self.httpgetpkt = None
        self.synackpkt = None
        self.clientsrcMac = None
        self.inport = inport
        self.state = self.SYNRECV

    #This function is used to generate a SYN, ACK response to a initial SYN request.
    def generateACKtoSYN(self):
        for p in self.synpkt:
            if p.protocol_name == 'ethernet':
                eth_src = p.dst
                eth_dst = p.src
                self.clientsrcMac = p.src
                e = ethernet.ethernet(eth_dst, eth_src)
            if p.protocol_name == 'ipv4':
                ip_src = p.dst
                ip_dst = p.src
                ip = ipv4.ipv4(4, 5, p.tos, 0, 0, 0, 0, 255, 6, 0, ip_src, ip_dst, None)
            if p.protocol_name == 'tcp':
                bits = 0 | 1 << 1 | 1 << 4  # ACK and SYN set
                src_port = p.dst_port
                dst_port = p.src_port
                ack = p.seq + 1
                seq = 1
                tcpd = tcp.tcp(src_port, dst_port, seq, ack, 0, bits, 65535, 0, 0, None)

        p = packet.Packet()
        p.add_protocol(e)
        p.add_protocol(ip)
        p.add_protocol(tcpd)
        p.serialize()

        return p

    def getSYNpkt(self):
        return self.synpkt

    def generateSYNpkt(self, dst_port=80):
        for p in self.synpkt:
            if p.protocol_name == 'ethernet':
                e = ethernet.ethernet(p.dst, p.src)
            if p.protocol_name == 'ipv4':
                ip_dst = self.serviceEngineIP
                ip = ipv4.ipv4(4, 5, p.tos, 0, p.identification, p.flags, 0, p.ttl, p.proto, 0, p.src, ip_dst, None)
            if p.protocol_name == 'tcp':
                tcpd = tcp.tcp(p.src_port, dst_port, p.seq, p.ack, 0, p.bits, p.window_size, 0, p.urgent, str(bytearray(p.option)))

        pkt = packet.Packet()
        pkt.add_protocol(e)
        pkt.add_protocol(ip)
        pkt.add_protocol(tcpd)
        pkt.serialize()

        return pkt

    def generateACKtoSYNACK(self):

        ipack = self.ackpkt.get_protocol(ipv4.ipv4)
        tcpack = self.ackpkt.get_protocol(tcp.tcp)

        for p in self.synackpkt:
            if p.protocol_name == 'ethernet':
                e = ethernet.ethernet(p.src, p.dst)
            if p.protocol_name == 'ipv4':
                ip = ipv4.ipv4(4, 5, p.tos, 0, ipack.identification, ipack.flags, 0, ipack.ttl, ipack.proto, 0, p.dst, p.src)
            if p.protocol_name == 'tcp':
                tcpd = tcp.tcp(p.dst_port, p.src_port, p.ack, p.seq+1, 0, 1 << 4, tcpack.window_size, 0, 0)

        pkt = packet.Packet()
        pkt.add_protocol(e)
        pkt.add_protocol(ip)
        pkt.add_protocol(tcpd)
        pkt.serialize()

        return pkt

    # This function is used to save the incoming ACK packet for our SYN, ACK for later use
    def saveACKpkt(self, pkt):
        self.ackpkt = pkt
        return

    def setState(self, state):
        self.state = state
        print 'Session state of ', self.srcip, ':', self.srcport, ': ', self.state
        return

    def getState(self):
        return self.state

    def setRequestURI(self, uri):
        self.requesturi = uri

    def setPayload(self, payload):
        self.payload = payload

    def saveHTTPGETpkt(self, pkt):
        self.httpgetpkt = pkt

    def saveSYNACKpkt(self, pkt):
        self.synackpkt = pkt

    def saveSEseq(self, seq):
        self.seq = seq

    def getCounterDiff(self):
        return self.seq

    def getRequestRouterIP(self):
        return self.requestRouterIP

    def setServiceEngineIP(self, ipadd):
        self.serviceEngineIP = ipadd

    def getServiceEngineIP(self):
        return self.serviceEngineIP

    def getClientMac(self):
        return self.clientsrcMac

    def getClientInPort(self):
        return self.inport

    def getsrcPort(self):
        return self.srcport

    def getsrcIP(self):
        return self.srcip

    def getreqURI(self):
        return self.requesturi