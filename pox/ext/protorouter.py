# Import some POX stuff
from pox.core import core                       # Main POX object
import pox.openflow.libopenflow_01 as of        # OpenFlow 1.0 library
from pox.lib.addresses import EthAddr, IPAddr   # Address types
from pox.lib.packet.ethernet import ethernet
from pox.lib.packet.arp import arp
from pox.lib.packet.ipv4 import ipv4            # Para detectar protocolos L4
from pox.lib.packet.tcp import tcp              # Para extraer puertos TCP
from pox.lib.packet.udp import udp              # Para extraer puertos UDP

log = core.getLogger()
RED    = "\033[31m"
GREEN  = "\033[32m"
YELLOW = "\033[33m"
CYAN   = "\033[36m"
BLUE   = "\033[34m"
RESET  = "\033[0m"


def log_color(color, msg):
    log.info(f"{color}{msg}{RESET}")

# ──────────────────────────────────────────────
#  Configuración de red
# ──────────────────────────────────────────────
PRIVATE_SUBNET = IPAddr("192.168.1.0")      
PRIVATE_MASK = 24                           
PRIVATE_IP = IPAddr("192.168.1.254")        
PUBLIC_IP = IPAddr("200.0.0.254")           
PUBLIC_MAC = EthAddr("00:00:00:aa:aa:aa")   
PRIVATE_MAC = EthAddr("00:00:00:bb:bb:bb")  
PUBLIC_PORT = 1                             

# ── Constantes PAT ──────────────────────────────────────────────
NAT_PORT_START = 10000                     # Primer puerto público a asignar
NAT_PORT_END   = 65535                     # Último puerto público a asignar
FLOW_TIMEOUT   = 60                        # Segundos de inactividad antes de expirar flujo

class ProtoRouter(object):
    def __init__(self, connection):
        self.connection = connection
        connection.addListeners(self)

        # ── Tabla ARP dinámica ──────────────────────────────────────────
        self.arp_table = {}  # ip -> (mac, in_port)
        self.pending = {}    # ip_destino -> [(packet_ethernet, in_port), ...]

        # ── Tablas NAT (PAT) ────────────────────────────────────────────
        # Saliente: (proto, ip_privada, puerto_privado) -> puerto_publico
        self.nat_out = {}
        # Entrante: (proto, puerto_publico) -> (ip_privada, puerto_privado, in_port)
        self.nat_in  = {}
        # Próximo puerto público disponible
        self.next_port = NAT_PORT_START

        log_color(YELLOW, "ProtoRouter (con ARP dinámico y PAT) iniciado.")

    # ══════════════════════════════════════════════════════════════════════
    #  Dispatcher principal
    # ══════════════════════════════════════════════════════════════════════

    def _handle_PacketIn(self, event):
        if not event.parsed.parsed:
            return

        pkt = event.parsed

        if pkt.type == ethernet.ARP_TYPE:
            self.handle_arp(event)
        elif pkt.type == ethernet.IP_TYPE:
            self.handle_ip(event)
        else:
            log_color(YELLOW, f"Paquete ignorado: protocolo 0x{pkt.type:04x}")

    # ══════════════════════════════════════════════════════════════════════
    #  Manejo de ARP
    # ══════════════════════════════════════════════════════════════════════
    
    def handle_arp(self, event):
        pkt     = event.parsed
        arp_pkt = pkt.payload
        in_port = event.port

        self.arp_table[arp_pkt.protosrc] = (arp_pkt.hwsrc, in_port)
        log_color(BLUE, f"ARP aprendido: {arp_pkt.protosrc} → {arp_pkt.hwsrc} (port {in_port})")

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

        e = ethernet(type=ethernet.ARP_TYPE, src=reply_mac, dst=req.hwsrc, payload=r)
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

        e = ethernet(type=ethernet.ARP_TYPE, src=src_mac, dst=EthAddr("ff:ff:ff:ff:ff:ff"), payload=r)
        msg = of.ofp_packet_out(data=e.pack())
        msg.actions.append(of.ofp_action_output(port=out_port))
        self.connection.send(msg)

    def _flush_pending(self, ip):
        if ip not in self.pending:
            return
        pkts = self.pending.pop(ip)
        for (pkt, in_port) in pkts:
            # Los paquetes en pending siempre son salientes
            self._handle_outbound(pkt, pkt.payload, in_port)

    # ══════════════════════════════════════════════════════════════════════
    #  Manejo de IP & PAT
    # ══════════════════════════════════════════════════════════════════════
    
    def handle_ip(self, event):
        pkt     = event.parsed
        ip_pkt  = pkt.payload
        in_port = event.port

        log_color(YELLOW, f"IP: {ip_pkt.srcip} → {ip_pkt.dstip} | in_port={in_port} | Proto: {ip_pkt.protocol}")

        if ip_pkt.srcip.inNetwork(PRIVATE_SUBNET, PRIVATE_MASK):
            # ── Paquete SALIENTE (de red privada hacia red pública) ──────
            self._handle_outbound(pkt, ip_pkt, in_port)

        elif ip_pkt.dstip == PUBLIC_IP:
            # ── Paquete ENTRANTE (respuesta del servidor al NAT) ─────────
            self._handle_inbound(pkt, ip_pkt, in_port)

        else:
            log_color(RED, f"Paquete descartado: {ip_pkt.srcip} → {ip_pkt.dstip} no aplica NAT")

    def _handle_outbound(self, packet, ip_pkt, in_port):
        dst_ip = ip_pkt.dstip

        # 1. Resolución ARP del destino
        if dst_ip in self.arp_table:
            dst_mac, _ = self.arp_table[dst_ip]
        else:
            log_color(CYAN, f"MAC desconocida para {dst_ip}. Guardando en pending.")
            if dst_ip not in self.pending:
                self.pending[dst_ip] = []
            self.pending[dst_ip].append((packet, in_port))
            self._send_arp_request(src_ip=PUBLIC_IP, src_mac=PUBLIC_MAC, dst_ip=dst_ip, out_port=PUBLIC_PORT)
            return

        # 2. Verificar si es TCP/UDP para aplicar PAT
        is_tcp_udp = False
        l4_pkt = None
        if ip_pkt.protocol == ipv4.TCP_PROTOCOL or ip_pkt.protocol == ipv4.UDP_PROTOCOL:
            l4_pkt = ip_pkt.payload
            is_tcp_udp = True

        # Preparar reglas de flujo
        fm = of.ofp_flow_mod()
        fm.idle_timeout = FLOW_TIMEOUT
        fm.match.dl_type = 0x800
        fm.match.nw_src = ip_pkt.srcip
        fm.match.nw_dst = ip_pkt.dstip
        fm.match.in_port = in_port

        fm_back = of.ofp_flow_mod()
        fm_back.idle_timeout = FLOW_TIMEOUT
        fm_back.match.dl_type = 0x800
        fm_back.match.nw_src = ip_pkt.dstip
        fm_back.match.nw_dst = PUBLIC_IP
        fm_back.match.in_port = PUBLIC_PORT

        orig_srcip = ip_pkt.srcip

        if is_tcp_udp:
            # Lógica PAT
            priv_port = l4_pkt.srcport
            key_out = (ip_pkt.protocol, ip_pkt.srcip, priv_port)

            if key_out in self.nat_out:
                pub_port = self.nat_out[key_out]
            else:
                pub_port = self.next_port
                self.next_port += 1
                if self.next_port > NAT_PORT_END:
                    self.next_port = NAT_PORT_START

                self.nat_out[key_out] = pub_port
                self.nat_in[(ip_pkt.protocol, pub_port)] = (ip_pkt.srcip, priv_port, in_port)
                log_color(GREEN, f"[PAT CREADO] {ip_pkt.srcip}:{priv_port} -> {PUBLIC_IP}:{pub_port}")

            # Filtrar L4 en los flujos
            fm.match.nw_proto = ip_pkt.protocol
            fm.match.tp_src = priv_port
            fm.match.tp_dst = l4_pkt.dstport
            
            fm_back.match.nw_proto = ip_pkt.protocol
            fm_back.match.tp_src = l4_pkt.dstport
            fm_back.match.tp_dst = pub_port

            # Acciones L4 (PAT) + IP (NAT) + MAC
            fm.actions.append(of.ofp_action_nw_addr.set_src(PUBLIC_IP))
            fm.actions.append(of.ofp_action_tp_port.set_src(pub_port))
            fm.actions.append(of.ofp_action_dl_addr.set_src(PUBLIC_MAC))
            fm.actions.append(of.ofp_action_dl_addr.set_dst(dst_mac))
            fm.actions.append(of.ofp_action_output(port=PUBLIC_PORT))

            fm_back.actions.append(of.ofp_action_nw_addr.set_dst(ip_pkt.srcip))
            fm_back.actions.append(of.ofp_action_tp_port.set_dst(priv_port))
            fm_back.actions.append(of.ofp_action_dl_addr.set_src(PRIVATE_MAC))
            fm_back.actions.append(of.ofp_action_dl_addr.set_dst(packet.src))
            fm_back.actions.append(of.ofp_action_output(port=in_port))

            # Modificar paquete actual
            l4_pkt.srcport = pub_port
            log_color(CYAN, f"OUTBOUND (PAT): {orig_srcip}:{priv_port} → {PUBLIC_IP}:{pub_port}")

        else:
            # Lógica NAT sin PAT (para ICMP)
            fm.actions.append(of.ofp_action_nw_addr.set_src(PUBLIC_IP))
            fm.actions.append(of.ofp_action_dl_addr.set_src(PUBLIC_MAC))
            fm.actions.append(of.ofp_action_dl_addr.set_dst(dst_mac))
            fm.actions.append(of.ofp_action_output(port=PUBLIC_PORT))

            fm_back.actions.append(of.ofp_action_nw_addr.set_dst(ip_pkt.srcip))
            fm_back.actions.append(of.ofp_action_dl_addr.set_src(PRIVATE_MAC))
            fm_back.actions.append(of.ofp_action_dl_addr.set_dst(packet.src))
            fm_back.actions.append(of.ofp_action_output(port=in_port))

            log_color(CYAN, f"OUTBOUND (NAT IP): {orig_srcip} → {PUBLIC_IP}")

        # Enviar flujos al switch
        self.connection.send(fm)
        self.connection.send(fm_back)

        # Modificar IP/MAC del paquete actual y enviarlo
        ip_pkt.srcip = PUBLIC_IP
        packet.src = PUBLIC_MAC
        packet.dst = dst_mac

        msg = of.ofp_packet_out()
        msg.data = packet.pack()
        msg.actions.append(of.ofp_action_output(port=PUBLIC_PORT))
        self.connection.send(msg)

    def _handle_inbound(self, packet, ip_pkt, in_port):
        """Maneja paquetes que llegan al switch y no hicieron match con un flujo de hw."""
        
        if ip_pkt.protocol == ipv4.TCP_PROTOCOL or ip_pkt.protocol == ipv4.UDP_PROTOCOL:
            l4_pkt = ip_pkt.payload
            pub_port = l4_pkt.dstport
            key_in = (ip_pkt.protocol, pub_port)

            if key_in in self.nat_in:
                priv_ip, priv_port, out_port = self.nat_in[key_in]
                
                # Rescatar MAC de destino de la tabla ARP
                if priv_ip in self.arp_table:
                    dst_mac, _ = self.arp_table[priv_ip]
                    
                    log_color(CYAN, f"INBOUND (PAT manual): {PUBLIC_IP}:{pub_port} → {priv_ip}:{priv_port}")
                    
                    # Modificar paquete
                    l4_pkt.dstport = priv_port
                    ip_pkt.dstip = priv_ip
                    packet.src = PRIVATE_MAC
                    packet.dst = dst_mac
                    
                    msg = of.ofp_packet_out()
                    msg.data = packet.pack()
                    msg.actions.append(of.ofp_action_output(port=out_port))
                    self.connection.send(msg)
                else:
                    log_color(YELLOW, f"No se conoce la MAC interna de {priv_ip}")
            else:
                log_color(RED, f"Paquete entrante a {PUBLIC_IP}:{pub_port} sin mapeo NAT activo.")
        else:
            log_color(YELLOW, "INBOUND: Paquete no es TCP/UDP (posible ICMP expensivo o sin mapeo). Ignorado.")


def launch():
    def start_switch(event):
        log_color(YELLOW, f"Iniciando ProtoRouter para Switch {event.connection.dpid}")
        ProtoRouter(event.connection)

    core.openflow.addListenerByName("ConnectionUp", start_switch)