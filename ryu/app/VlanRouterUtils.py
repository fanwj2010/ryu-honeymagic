from ryu.app.rest_cdn_router import *
from netaddr import *

UINT16_MAX = 0xffff
UINT32_MAX = 0xffffffff
UINT64_MAX = 0xffffffffffffffff


ETHERNET = ethernet.ethernet.__name__
VLAN = vlan.vlan.__name__
IPV4 = ipv4.ipv4.__name__
ARP = arp.arp.__name__
ICMP = icmp.icmp.__name__
TCP = tcp.tcp.__name__
UDP = udp.udp.__name__

MAX_SUSPENDPACKETS = 50  # Threshold of the packet suspends thread count.

ARP_REPLY_TIMER = 5  # sec
OFP_REPLY_TIMER = 1.0  # sec
CHK_ROUTING_TBL_INTERVAL = 1800  # sec

SWITCHID_PATTERN = dpid_lib.DPID_PATTERN + r'|all'
VLANID_PATTERN = r'[0-9]{1,4}|all'

VLANID_NONE = 0
VLANID_MIN = 2
VLANID_MAX = 4094

COOKIE_DEFAULT_ID = 0
COOKIE_SHIFT_VLANID = 32
COOKIE_SHIFT_ROUTEID = 16

DEFAULT_ROUTE = '0.0.0.0/0'
IDLE_TIMEOUT = 1800  # sec
DEFAULT_TTL = 64

REST_COMMAND_RESULT = 'command_result'
REST_RESULT = 'result'
REST_DETAILS = 'details'
REST_OK = 'success'
REST_NG = 'failure'
REST_ALL = 'all'
REST_SWITCHID = 'switch_id'
REST_VLANID = 'vlan_id'
REST_NW = 'internal_network'
REST_ADDRESSID = 'address_id'
REST_ADDRESS = 'address'
REST_ROUTEID = 'route_id'
REST_ROUTE = 'route'
REST_DESTINATION = 'destination'
REST_GATEWAY = 'gateway'

#CUSTOM REST VARIABLES
REST_REQUEST_ROUTER = 'request_router'

PRIORITY_VLAN_SHIFT = 1000
PRIORITY_NETMASK_SHIFT = 32

PRIORITY_NORMAL = 0
PRIORITY_ARP_HANDLING = 1
PRIORITY_DEFAULT_ROUTING = 1
PRIORITY_MAC_LEARNING = 2
PRIORITY_STATIC_ROUTING = 2
PRIORITY_IMPLICIT_ROUTING = 3
PRIORITY_L2_SWITCHING = 4
PRIORITY_IP_HANDLING = 5
PRIORITY_CDN_HANDLING = 6

PRIORITY_TYPE_ROUTE = 'priority_route'

class PortData(dict):
    def __init__(self, ports):
        super(PortData, self).__init__()
        for port in ports.values():
            data = Port(port.port_no, port.hw_addr)
            self[port.port_no] = data


class Port(object):
    def __init__(self, port_no, hw_addr):
        super(Port, self).__init__()
        self.port_no = port_no
        self.mac = hw_addr


class AddressData(dict):
    def __init__(self):
        super(AddressData, self).__init__()
        self.address_id = 1

    def add(self, address):
        err_msg = 'Invalid [%s] value.' % REST_ADDRESS
        nw_addr, mask, default_gw = nw_addr_aton(address, err_msg=err_msg)

        # Check overlaps
        for other in self.values():
            other_mask = mask_ntob(other.netmask)
            add_mask = mask_ntob(mask, err_msg=err_msg)
            if (other.nw_addr == ipv4_apply_mask(default_gw, other.netmask) or
                    nw_addr == ipv4_apply_mask(other.default_gw, mask,
                                               err_msg)):
                msg = 'Address overlaps [address_id=%d]' % other.address_id
                raise CommandFailure(msg=msg)

        address = Address(self.address_id, nw_addr, mask, default_gw)
        ip_str = ip_addr_ntoa(nw_addr)
        key = '%s/%d' % (ip_str, mask)
        self[key] = address

        self.address_id += 1
        self.address_id &= UINT32_MAX
        if self.address_id == COOKIE_DEFAULT_ID:
            self.address_id = 1

        return address

    def delete(self, address_id):
        for key, value in self.items():
            if value.address_id == address_id:
                del self[key]
                return

    def get_default_gw(self):
        return [address.default_gw for address in self.values()]

    def get_data(self, addr_id=None, ip=None):
        for address in self.values():
            if addr_id is not None:
                if addr_id == address.address_id:
                    return address
            else:
                assert ip is not None
                if ipv4_apply_mask(ip, address.netmask) == address.nw_addr:
                    return address
        return None


class Address(object):
    def __init__(self, address_id, nw_addr, netmask, default_gw):
        super(Address, self).__init__()
        self.address_id = address_id
        self.nw_addr = nw_addr
        self.netmask = netmask
        self.default_gw = default_gw

    def __contains__(self, ip):
        return bool(ipv4_apply_mask(ip, self.netmask) == self.nw_addr)


class RoutingTable(dict):
    def __init__(self):
        super(RoutingTable, self).__init__()
        self.route_id = 1

    def add(self, dst_nw_addr, gateway_ip):
        err_msg = 'Invalid [%s] value.'

        if dst_nw_addr == DEFAULT_ROUTE:
            dst_ip = 0
            netmask = 0
        else:
            dst_ip, netmask, dummy = nw_addr_aton(
                dst_nw_addr, err_msg=err_msg % REST_DESTINATION)

        gateway_ip = ip_addr_aton(gateway_ip, err_msg=err_msg % REST_GATEWAY)

        # Check overlaps
        overlap_route = None
        if dst_nw_addr == DEFAULT_ROUTE:
            if DEFAULT_ROUTE in self:
                overlap_route = self[DEFAULT_ROUTE].route_id
        elif dst_nw_addr in self:
            overlap_route = self[dst_nw_addr].route_id

        if overlap_route is not None:
            msg = 'Destination overlaps [route_id=%d]' % overlap_route
            raise CommandFailure(msg=msg)

        routing_data = Route(self.route_id, dst_ip, netmask, gateway_ip)
        ip_str = ip_addr_ntoa(dst_ip)
        key = '%s/%d' % (ip_str, netmask)
        self[key] = routing_data

        self.route_id += 1
        self.route_id &= UINT32_MAX
        if self.route_id == COOKIE_DEFAULT_ID:
            self.route_id = 1

        return routing_data

    def delete(self, route_id):
        for key, value in self.items():
            if value.route_id == route_id:
                del self[key]
                return

    def get_gateways(self):
        return [routing_data.gateway_ip for routing_data in self.values()]

    def get_data(self, gw_mac=None, dst_ip=None):
        if gw_mac is not None:
            for route in self.values():
                if gw_mac == route.gateway_mac:
                    return route
            return None

        elif dst_ip is not None:
            get_route = None
            mask = 0
            for route in self.values():
                if ipv4_apply_mask(dst_ip, route.netmask) == route.dst_ip:
                    # For longest match
                    if mask < route.netmask:
                        get_route = route
                        mask = route.netmask

            if get_route is None:
                get_route = self.get(DEFAULT_ROUTE, None)
            return get_route
        else:
            return None


class Route(object):
    def __init__(self, route_id, dst_ip, netmask, gateway_ip):
        super(Route, self).__init__()
        self.route_id = route_id
        self.dst_ip = dst_ip
        self.netmask = netmask
        self.gateway_ip = gateway_ip
        self.gateway_mac = None


class SuspendPacketList(list):
    def __init__(self, timeout_function):
        super(SuspendPacketList, self).__init__()
        self.timeout_function = timeout_function

    def add(self, in_port, header_list, data, dst_ip):
        suspend_pkt = SuspendPacket(in_port, header_list, data, dst_ip,
                                    self.wait_arp_reply_timer)
        self.append(suspend_pkt)

    def delete(self, pkt=None, del_addr=None):
        if pkt is not None:
            del_list = [pkt]
        else:
            assert del_addr is not None
            del_list = [pkt for pkt in self if pkt.dst_ip in del_addr]

        for pkt in del_list:
            self.remove(pkt)
            hub.kill(pkt.wait_thread)
            pkt.wait_thread.wait()

    def get_data(self, dst_ip):
        return [pkt for pkt in self if pkt.dst_ip == dst_ip]

    def wait_arp_reply_timer(self, suspend_pkt):
        hub.sleep(ARP_REPLY_TIMER)
        if suspend_pkt in self:
            self.timeout_function(suspend_pkt)
            self.delete(pkt=suspend_pkt)


class SuspendPacket(object):
    def __init__(self, in_port, header_list, data, dst_ip, timer):
        super(SuspendPacket, self).__init__()
        self.in_port = in_port
        #self.dst_ip = header_list[IPV4].dst
        self.dst_ip = dst_ip
        self.header_list = header_list
        self.data = data
        # Start ARP reply wait timer.
        self.wait_thread = hub.spawn(timer, self)



class RequestRouterTable(dict):
    def __init__(self):
        super(RequestRouterTable, self).__init__()
        self.request_router_id = 0

    def add(self, ip_address):
        ip = IPAddress(ip_address)
        self.request_router_id +=1
        self[ip_address] = ip
        return self.request_router_id



def ip_addr_aton(ip_str, err_msg=None):
    try:
        return addrconv.ipv4.bin_to_text(socket.inet_aton(ip_str))
    except (struct.error, socket.error) as e:
        if err_msg is not None:
            e.message = '%s %s' % (err_msg, e.message)
        raise ValueError(e.message)


def ip_addr_ntoa(ip):
    return socket.inet_ntoa(addrconv.ipv4.text_to_bin(ip))


def mask_ntob(mask, err_msg=None):
    try:
        return (UINT32_MAX << (32 - mask)) & UINT32_MAX
    except ValueError:
        msg = 'illegal netmask'
        if err_msg is not None:
            msg = '%s %s' % (err_msg, msg)
        raise ValueError(msg)


def ipv4_apply_mask(address, prefix_len, err_msg=None):
    import itertools

    assert isinstance(address, str)
    address_int = ipv4_text_to_int(address)
    return ipv4_int_to_text(address_int & mask_ntob(prefix_len, err_msg))


def ipv4_int_to_text(ip_int):
    assert isinstance(ip_int, (int, long))
    return addrconv.ipv4.bin_to_text(struct.pack('!I', ip_int))


def ipv4_text_to_int(ip_text):
    if ip_text == 0:
        return ip_text
    assert isinstance(ip_text, str)
    return struct.unpack('!I', addrconv.ipv4.text_to_bin(ip_text))[0]


def nw_addr_aton(nw_addr, err_msg=None):
    ip_mask = nw_addr.split('/')
    default_route = ip_addr_aton(ip_mask[0], err_msg=err_msg)
    netmask = 32
    if len(ip_mask) == 2:
        try:
            netmask = int(ip_mask[1])
        except ValueError as e:
            if err_msg is not None:
                e.message = '%s %s' % (err_msg, e.message)
            raise ValueError(e.message)
    if netmask < 0:
        msg = 'illegal netmask'
        if err_msg is not None:
            msg = '%s %s' % (err_msg, msg)
        raise ValueError(msg)
    nw_addr = ipv4_apply_mask(default_route, netmask, err_msg)
    return nw_addr, netmask, default_route
