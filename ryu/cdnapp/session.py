__author__ = 'thomas'

from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import tcp
from ryu.lib.packet import ipv4

class Session:

    def __init__(self, srcip, srcport, pkt):
        self.srcip = srcip
        self.srcport = srcport
        self.pkt = pkt
        self.synpkt = pkt

    def generateACKtoSYN(self):
        for p in self.pkt:
            print p
            if p.protocol_name == 'ethernet':
                eth_src = p.dst
                eth_dst = p.src
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
                seq = 0
                tcpd = tcp.tcp(src_port, dst_port, seq, ack, 0, bits, 65535, 0, 0, None)

        p = packet.Packet()
        p.add_protocol(e)
        p.add_protocol(ip)
        p.add_protocol(tcpd)
        p.serialize()

        return p


