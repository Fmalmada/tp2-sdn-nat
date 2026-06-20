# Import some POX stuff
from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.addresses import EthAddr, IPAddr
from pox.lib.packet.ethernet import ethernet
from pox.lib.packet.arp import arp
from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.icmp import icmp

log = core.getLogger()
RED    = "\033[31m"
GREEN  = "\033[32m"
YELLOW = "\033[33m"
CYAN   = "\033[36m"
BLUE   = "\033[34m"
RESET  = "\033[0m"


def log_color(color, msg):
    log.info(f"{color}{msg}{RESET}")


# ── Configuración del NAT (ajustar junto con topo.py si cambian las IPs del NAT)
PRIVATE_SUBNET = IPAddr("192.168.1.0")
PRIVATE_MASK   = 24
PRIVATE_IP     = IPAddr("192.168.1.254")
PUBLIC_IP      = IPAddr("200.0.0.254")
PUBLIC_MAC     = EthAddr("00:00:00:aa:aa:aa")
PRIVATE_MAC    = EthAddr("00:00:00:bb:bb:bb")
PUBLIC_PORT    = 1

NAT_PORT_START = 10000
NAT_PORT_END   = 65535
FLOW_TIMEOUT   = 600


class ProtoRouter(object):

    def __init__(self, connection):
        self.connection = connection
        connection.addListeners(self)

        self.arp_table = {}
        self.nat_out = {}
        self.nat_in = {}
        self.nat_cookies = {}
        self.cookie_to_nat = {}
        self.next_port = NAT_PORT_START
        self.free_ports = set()
        self.next_cookie = 1
        self.pending = {}

        log_color(YELLOW, "ProtoRouter (NAT/PAT) iniciado.")

    def _alloc_port(self):
        if self.free_ports:
            port = min(self.free_ports)
            self.free_ports.remove(port)
            return port
        if self.next_port > NAT_PORT_END:
            return None
        port = self.next_port
        self.next_port += 1
        return port

    def _release_port(self, port):
        if NAT_PORT_START <= port <= NAT_PORT_END:
            self.free_ports.add(port)

    def _flow_mod(self, cookie):
        fm = of.ofp_flow_mod()
        fm.idle_timeout = FLOW_TIMEOUT
        fm.flags |= of.OFPFF_SEND_FLOW_REM
        fm.cookie = cookie
        return fm

    def _handle_PacketIn(self, event):
        if not event.parsed.parsed:
            log.warning("[DROP] Trama no reconocida.")
            return

        pkt = event.parsed
        if pkt.type == ethernet.ARP_TYPE:
            self.handle_arp(event)
        elif pkt.type == ethernet.IP_TYPE:
            self.handle_ip(event)

    def _handle_FlowRemoved(self, event):
        if event.dpid != self.connection.dpid or not event.timeout:
            return
        nat_key = self.cookie_to_nat.pop(event.ofp.cookie, None)
        if nat_key is None:
            return
        pub_port = self.nat_out.pop(nat_key, None)
        if pub_port is not None:
            self.nat_in.pop((nat_key[0], pub_port), None)
            self.nat_cookies.pop(nat_key, None)
            self._release_port(pub_port)
            log_color(BLUE, f"NAT expirado: {nat_key}, puerto {pub_port} liberado")

    def handle_arp(self, event):
        pkt = event.parsed
        arp_pkt = pkt.payload
        in_port = event.port

        self.arp_table[arp_pkt.protosrc] = (arp_pkt.hwsrc, in_port)

        if arp_pkt.opcode == arp.REQUEST:
            if arp_pkt.protodst == PUBLIC_IP:
                self._send_arp_reply(arp_pkt, PUBLIC_MAC, in_port)
            elif arp_pkt.protodst == PRIVATE_IP:
                self._send_arp_reply(arp_pkt, PRIVATE_MAC, in_port)

        elif arp_pkt.opcode == arp.REPLY:
            self._flush_pending(arp_pkt.protosrc)

    def _send_arp_reply(self, req, reply_mac, out_port):
        r = arp()
        r.opcode = arp.REPLY
        r.hwsrc = reply_mac
        r.hwdst = req.hwsrc
        r.protosrc = req.protodst
        r.protodst = req.protosrc

        e = ethernet()
        e.type = ethernet.ARP_TYPE
        e.src = reply_mac
        e.dst = req.hwsrc
        e.payload = r
        msg = of.ofp_packet_out(data=e.pack())
        msg.actions.append(of.ofp_action_output(port=out_port))
        self.connection.send(msg)

    def _send_arp_request(self, src_ip, src_mac, dst_ip, out_port):
        r = arp()
        r.opcode = arp.REQUEST
        r.hwsrc = src_mac
        r.hwdst = EthAddr("ff:ff:ff:ff:ff:ff")
        r.protosrc = src_ip
        r.protodst = dst_ip

        e = ethernet()
        e.type = ethernet.ARP_TYPE
        e.src = src_mac
        e.dst = EthAddr("ff:ff:ff:ff:ff:ff")
        e.payload = r
        msg = of.ofp_packet_out(data=e.pack())
        msg.actions.append(of.ofp_action_output(port=out_port))
        self.connection.send(msg)

    def _flush_pending(self, ip):
        if ip not in self.pending:
            return
        for pkt, in_port in self.pending.pop(ip):
            self._process_outbound(pkt, pkt.payload, in_port)

    def handle_ip(self, event):
        pkt = event.parsed
        ip_pkt = pkt.payload
        in_port = event.port

        if ip_pkt.srcip.inNetwork(PRIVATE_SUBNET, PRIVATE_MASK):
            self._handle_outbound(pkt, ip_pkt, in_port)
        elif ip_pkt.dstip == PUBLIC_IP:
            self._handle_inbound(pkt, ip_pkt, in_port)

    def _parse_ports(self, ip_pkt):
        proto = ip_pkt.protocol
        if proto == ipv4.ICMP_PROTOCOL:
            return proto, ip_pkt.payload.next.id, ip_pkt.dstip, 0
        if proto in (ipv4.TCP_PROTOCOL, ipv4.UDP_PROTOCOL):
            t = ip_pkt.payload
            return proto, t.srcport, ip_pkt.dstip, t.dstport
        return None, None, None, None

    def _handle_outbound(self, pkt, ip_pkt, in_port):
        proto, src_port, dst_ip, dst_port = self._parse_ports(ip_pkt)
        if proto is None:
            return

        nat_key = (proto, ip_pkt.srcip, src_port)
        if nat_key not in self.nat_out:
            pub_port = self._alloc_port()
            if pub_port is None:
                log_color(RED, "Sin puertos NAT disponibles")
                return
            cookie = self.next_cookie
            self.next_cookie += 1
            self.nat_out[nat_key] = pub_port
            self.nat_in[(proto, pub_port)] = (ip_pkt.srcip, src_port, in_port)
            self.nat_cookies[nat_key] = cookie
            self.cookie_to_nat[cookie] = nat_key
            log_color(GREEN, f"Nueva NAT: {ip_pkt.srcip}:{src_port} -> {PUBLIC_IP}:{pub_port}")

        if dst_ip not in self.arp_table:
            self.pending.setdefault(dst_ip, []).append((pkt, in_port))
            self._send_arp_request(PUBLIC_IP, PUBLIC_MAC, dst_ip, PUBLIC_PORT)
            return

        self._process_outbound(pkt, ip_pkt, in_port)

    def _process_outbound(self, pkt, ip_pkt, in_port):
        proto = ip_pkt.protocol
        dst_ip = ip_pkt.dstip
        if proto == ipv4.ICMP_PROTOCOL:
            src_port = ip_pkt.payload.next.id
            dst_port = 0
        else:
            src_port = ip_pkt.payload.srcport
            dst_port = ip_pkt.payload.dstport

        nat_key = (proto, ip_pkt.srcip, src_port)
        pub_port = self.nat_out[nat_key]
        cookie = self.nat_cookies[nat_key]
        dst_mac, _ = self.arp_table[dst_ip]
        priv_ip, priv_port, priv_switch_port = self.nat_in[(proto, pub_port)]

        if priv_ip not in self.arp_table:
            self.arp_table[priv_ip] = (pkt.src, in_port)
        priv_mac, _ = self.arp_table[priv_ip]

        fm = self._flow_mod(cookie)
        fm.match.dl_type = 0x0800
        fm.match.nw_proto = proto
        fm.match.nw_src = ip_pkt.srcip
        fm.match.nw_dst = dst_ip
        fm.match.in_port = in_port
        if proto != ipv4.ICMP_PROTOCOL:
            fm.match.tp_src = src_port
            fm.match.tp_dst = dst_port
        fm.actions.append(of.ofp_action_nw_addr.set_src(PUBLIC_IP))
        if proto != ipv4.ICMP_PROTOCOL:
            fm.actions.append(of.ofp_action_tp_port.set_src(pub_port))
        fm.actions.append(of.ofp_action_dl_addr.set_src(PUBLIC_MAC))
        fm.actions.append(of.ofp_action_dl_addr.set_dst(dst_mac))
        fm.actions.append(of.ofp_action_output(port=PUBLIC_PORT))
        self.connection.send(fm)

        fm_back = self._flow_mod(cookie)
        fm_back.match.dl_type = 0x0800
        fm_back.match.nw_proto = proto
        fm_back.match.nw_dst = PUBLIC_IP
        fm_back.match.in_port = PUBLIC_PORT
        if proto != ipv4.ICMP_PROTOCOL:
            fm_back.match.tp_dst = pub_port
        fm_back.actions.append(of.ofp_action_nw_addr.set_dst(priv_ip))
        if proto != ipv4.ICMP_PROTOCOL:
            fm_back.actions.append(of.ofp_action_tp_port.set_dst(priv_port))
        fm_back.actions.append(of.ofp_action_dl_addr.set_src(PRIVATE_MAC))
        fm_back.actions.append(of.ofp_action_dl_addr.set_dst(priv_mac))
        fm_back.actions.append(of.ofp_action_output(port=priv_switch_port))
        self.connection.send(fm_back)

        ip_pkt.srcip = PUBLIC_IP
        ip_pkt.csum = 0
        if proto == ipv4.ICMP_PROTOCOL:
            ip_pkt.payload.next.id = pub_port
            ip_pkt.payload.next.csum = 0
            ip_pkt.payload.csum = 0
        else:
            ip_pkt.payload.srcport = pub_port
            ip_pkt.payload.csum = 0

        pkt.src = PUBLIC_MAC
        pkt.dst = dst_mac
        msg = of.ofp_packet_out(data=pkt.pack())
        msg.actions.append(of.ofp_action_output(port=PUBLIC_PORT))
        self.connection.send(msg)

    def _handle_inbound(self, pkt, ip_pkt, in_port):
        proto = ip_pkt.protocol
        if proto == ipv4.ICMP_PROTOCOL:
            dst_port = ip_pkt.payload.next.id
            src_info = dst_port
        elif proto in (ipv4.TCP_PROTOCOL, ipv4.UDP_PROTOCOL):
            dst_port = ip_pkt.payload.dstport
            src_info = ip_pkt.payload.srcport
        else:
            return

        nat_in_key = (proto, dst_port)
        if nat_in_key not in self.nat_in:
            return

        priv_ip, priv_port, priv_switch_port = self.nat_in[nat_in_key]
        priv_mac, _ = self.arp_table[priv_ip]
        nat_key = (proto, priv_ip, priv_port)
        cookie = self.nat_cookies[nat_key]

        fm_back = self._flow_mod(cookie)
        fm_back.match.dl_type = 0x0800
        fm_back.match.nw_proto = proto
        fm_back.match.nw_src = ip_pkt.srcip
        fm_back.match.nw_dst = PUBLIC_IP
        fm_back.match.in_port = PUBLIC_PORT
        if proto != ipv4.ICMP_PROTOCOL:
            fm_back.match.tp_src = src_info
            fm_back.match.tp_dst = dst_port
        fm_back.actions.append(of.ofp_action_nw_addr.set_dst(priv_ip))
        if proto != ipv4.ICMP_PROTOCOL:
            fm_back.actions.append(of.ofp_action_tp_port.set_dst(priv_port))
        fm_back.actions.append(of.ofp_action_dl_addr.set_src(PRIVATE_MAC))
        fm_back.actions.append(of.ofp_action_dl_addr.set_dst(priv_mac))
        fm_back.actions.append(of.ofp_action_output(port=priv_switch_port))
        self.connection.send(fm_back)

        ip_pkt.dstip = priv_ip
        ip_pkt.csum = 0
        if proto == ipv4.ICMP_PROTOCOL:
            ip_pkt.payload.next.id = priv_port
            ip_pkt.payload.next.csum = 0
            ip_pkt.payload.csum = 0
        else:
            ip_pkt.payload.dstport = priv_port
            ip_pkt.payload.csum = 0

        pkt.src = PRIVATE_MAC
        pkt.dst = priv_mac
        msg = of.ofp_packet_out(data=pkt.pack())
        msg.actions.append(of.ofp_action_output(port=priv_switch_port))
        self.connection.send(msg)


def launch():
    def start_switch(event):
        ProtoRouter(event.connection)

    core.openflow.addListenerByName("ConnectionUp", start_switch)
