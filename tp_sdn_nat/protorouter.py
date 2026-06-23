# Import some POX stuff
from pox.core import core                       
import pox.openflow.libopenflow_01 as of        
from pox.lib.addresses import EthAddr, IPAddr   
from pox.lib.packet.ethernet import ethernet
from pox.lib.packet.arp import arp
from pox.lib.packet.ipv4 import ipv4            
from pox.lib.packet.tcp import tcp              
from pox.lib.packet.udp import udp              
from pox.lib.recoco import Timer                # Para el Garbage Collector
import time                                     # Para los timestamps

ipv4.ipv4 = ipv4

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

# ── Constantes PAT y Tiempos ────────────────────────────────────
NAT_PORT_START = 10000                     
NAT_PORT_END   = 65535                     
FLOW_TIMEOUT   = 20                        # Reducido para que el controlador vea el tráfico más seguido
UDP_TIMEOUT    = 30                        # Segundos para expirar conexiones UDP inactivas
TCP_TIMEOUT    = 120                       # Segundos para expirar conexiones TCP inactivas

class ProtoRouter(object):
    def __init__(self, connection):
        self.connection = connection
        connection.addListeners(self)

        # ── Tabla ARP dinámica ──────────────────────────────────────────
        self.arp_table = {}  # ip -> (mac, in_port)
        self.pending = {}    # ip_destino -> [(packet_ethernet, in_port), ...]

        # ── Tablas NAT con Estado (Etapa 4) ─────────────────────────────
        # nat_out: (proto, ip_privada, puerto_privado) -> {'pub_port': int, 'state': str, 'last_active': float}
        self.nat_out = {}
        # nat_in: (proto, puerto_publico) -> {'ip_priv': IPAddr, 'port_priv': int, 'in_port': int}
        self.nat_in  = {}
        
        self.next_port = NAT_PORT_START

        # Iniciar el Garbage Collector cada 5 segundos
        Timer(5, self._clean_expired_connections, recurring=True)

        log_color(YELLOW, "ProtoRouter (con ARP, PAT y Connection Tracking) iniciado.")

    # ══════════════════════════════════════════════════════════════════════
    #  Garbage Collector (Limpieza de Estado)
    # ══════════════════════════════════════════════════════════════════════
    
    def _clean_expired_connections(self):
        """Revisa la tabla de conexiones y elimina las expiradas o cerradas."""
        now = time.time()
        # Usamos list() para no modificar el diccionario mientras lo iteramos
        keys_to_delete = []

        for key_out, data in self.nat_out.items():
            proto, priv_ip, priv_port = key_out
            time_idle = now - data['last_active']
            state = data['state']
            
            # Condición 1: TCP cerrado (RST) o detectado cierre por FIN (TP Criterio)
            if proto == ipv4.TCP_PROTOCOL and state in ['CLOSED', 'CLOSING']:
                keys_to_delete.append(key_out)
            # Condición 2: Timeout general TCP
            elif proto == ipv4.TCP_PROTOCOL and time_idle > TCP_TIMEOUT:
                keys_to_delete.append(key_out)
            # Condición 3: Timeout UDP
            elif proto == ipv4.UDP_PROTOCOL and time_idle > UDP_TIMEOUT:
                keys_to_delete.append(key_out)

        for key_out in keys_to_delete:
            proto = key_out[0]
            pub_port = self.nat_out[key_out]['pub_port']
            key_in = (proto, pub_port)
            
            # Limpiar ambas tablas
            del self.nat_out[key_out]
            if key_in in self.nat_in:
                del self.nat_in[key_in]
                
            log_color(RED, f"[GC] Conexión {key_out[1]}:{key_out[2]} expirada/cerrada. Puerto {pub_port} liberado.")

    def _update_tcp_state(self, data, tcp_pkt):
        """Actualiza el estado de una conexión TCP en base a sus flags."""
        if tcp_pkt.RST:
            data['state'] = 'CLOSED'
        elif tcp_pkt.FIN:
            # Simplificación: si vemos un FIN, marcamos en proceso de cierre.
            data['state'] = 'CLOSING'
        elif tcp_pkt.SYN and tcp_pkt.ACK:
            data['state'] = 'ESTABLISHED'
        elif tcp_pkt.SYN:
            data['state'] = 'SYN_SENT'

    # ══════════════════════════════════════════════════════════════════════
    #  Dispatcher y ARP 
    # ══════════════════════════════════════════════════════════════════════

    def _handle_PacketIn(self, event):
        if not event.parsed.parsed:
            return

        pkt = event.parsed

        if pkt.type == ethernet.ARP_TYPE:
            self.handle_arp(event)
        elif pkt.type == ethernet.IP_TYPE:
            self.handle_ip(event)

    def handle_arp(self, event):
        pkt     = event.parsed
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
        r = arp(opcode=arp.REPLY, hwsrc=reply_mac, hwdst=req.hwsrc, protosrc=req.protodst, protodst=req.protosrc)
        e = ethernet(type=ethernet.ARP_TYPE, src=reply_mac, dst=req.hwsrc, payload=r)
        msg = of.ofp_packet_out(data=e.pack())
        msg.actions.append(of.ofp_action_output(port=out_port))
        self.connection.send(msg)

    def _send_arp_request(self, src_ip, src_mac, dst_ip, out_port):
        r = arp(opcode=arp.REQUEST, hwsrc=src_mac, hwdst=EthAddr("ff:ff:ff:ff:ff:ff"), protosrc=src_ip, protodst=dst_ip)
        e = ethernet(type=ethernet.ARP_TYPE, src=src_mac, dst=EthAddr("ff:ff:ff:ff:ff:ff"), payload=r)
        msg = of.ofp_packet_out(data=e.pack())
        msg.actions.append(of.ofp_action_output(port=out_port))
        self.connection.send(msg)

    def _flush_pending(self, ip):
        if ip not in self.pending:
            return
        pkts = self.pending.pop(ip)
        for (pkt, in_port) in pkts:
            self._handle_outbound(pkt, pkt.payload, in_port)

    # ══════════════════════════════════════════════════════════════════════
    #  Manejo de IP & PAT con Tracking
    # ══════════════════════════════════════════════════════════════════════
    
    def handle_ip(self, event):
        pkt     = event.parsed
        ip_pkt  = pkt.payload
        in_port = event.port

        if ip_pkt.srcip.inNetwork(PRIVATE_SUBNET, PRIVATE_MASK):
            self._handle_outbound(pkt, ip_pkt, in_port)
        elif ip_pkt.dstip == PUBLIC_IP:
            self._handle_inbound(pkt, ip_pkt, in_port)

    def _handle_outbound(self, packet, ip_pkt, in_port):
        dst_ip = ip_pkt.dstip

        if dst_ip in self.arp_table:
            dst_mac, _ = self.arp_table[dst_ip]
        else:
            if dst_ip not in self.pending:
                self.pending[dst_ip] = []
            self.pending[dst_ip].append((packet, in_port))
            self._send_arp_request(src_ip=PUBLIC_IP, src_mac=PUBLIC_MAC, dst_ip=dst_ip, out_port=PUBLIC_PORT)
            return

        is_tcp = (ip_pkt.protocol == ipv4.TCP_PROTOCOL)
        is_udp = (ip_pkt.protocol == ipv4.UDP_PROTOCOL)

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

        if is_tcp or is_udp:
            l4_pkt = ip_pkt.payload
            priv_port = l4_pkt.srcport
            key_out = (ip_pkt.protocol, ip_pkt.srcip, priv_port)

            if key_out in self.nat_out:
                pub_port = self.nat_out[key_out]['pub_port']
                self.nat_out[key_out]['last_active'] = time.time()
                if is_tcp:
                    self._update_tcp_state(self.nat_out[key_out], l4_pkt)
            else:
                pub_port = self.next_port
                self.next_port += 1
                if self.next_port > NAT_PORT_END:
                    self.next_port = NAT_PORT_START

                self.nat_out[key_out] = {
                    'pub_port': pub_port,
                    'state': 'SYN_SENT' if is_tcp else 'ACTIVE',
                    'last_active': time.time()
                }
                
                self.nat_in[(ip_pkt.protocol, pub_port)] = {
                    'ip_priv': ip_pkt.srcip,
                    'port_priv': priv_port,
                    'in_port': in_port
                }
                log_color(GREEN, f"[NUEVA CONEXIÓN] {ip_pkt.srcip}:{priv_port} -> {PUBLIC_IP}:{pub_port} ({'TCP' if is_tcp else 'UDP'})")

            fm.match.nw_proto = ip_pkt.protocol
            fm.match.tp_src = priv_port
            fm.match.tp_dst = l4_pkt.dstport
            fm_back.match.nw_proto = ip_pkt.protocol
            fm_back.match.tp_src = l4_pkt.dstport
            fm_back.match.tp_dst = pub_port

            fm.actions.append(of.ofp_action_nw_addr.set_src(PUBLIC_IP))
            fm.actions.append(of.ofp_action_tp_port.set_src(pub_port))
            fm_back.actions.append(of.ofp_action_nw_addr.set_dst(ip_pkt.srcip))
            fm_back.actions.append(of.ofp_action_tp_port.set_dst(priv_port))

            l4_pkt.srcport = pub_port

        else:
            # Lógica ICMP (NAT IP simple)
            fm.match.nw_proto = ip_pkt.protocol
            fm_back.match.nw_proto = ip_pkt.protocol
            
            fm.actions.append(of.ofp_action_nw_addr.set_src(PUBLIC_IP))
            fm_back.actions.append(of.ofp_action_nw_addr.set_dst(ip_pkt.srcip))

        # Acciones generales MAC y Salida
        fm.actions.append(of.ofp_action_dl_addr.set_src(PUBLIC_MAC))
        fm.actions.append(of.ofp_action_dl_addr.set_dst(dst_mac))
        fm.actions.append(of.ofp_action_output(port=PUBLIC_PORT))
        
        fm_back.actions.append(of.ofp_action_dl_addr.set_src(PRIVATE_MAC))
        fm_back.actions.append(of.ofp_action_dl_addr.set_dst(packet.src))
        fm_back.actions.append(of.ofp_action_output(port=in_port))

        self.connection.send(fm)
        self.connection.send(fm_back)

        # Enviar paquete actual modificado
        ip_pkt.srcip = PUBLIC_IP
        packet.src = PUBLIC_MAC
        packet.dst = dst_mac
        msg = of.ofp_packet_out(data=packet.pack())
        msg.actions.append(of.ofp_action_output(port=PUBLIC_PORT))
        self.connection.send(msg)

    def _handle_inbound(self, packet, ip_pkt, in_port):
        is_tcp = (ip_pkt.protocol == ipv4.TCP_PROTOCOL)
        is_udp = (ip_pkt.protocol == ipv4.UDP_PROTOCOL)

        if is_tcp or is_udp:
            l4_pkt = ip_pkt.payload
            pub_port = l4_pkt.dstport
            key_in = (ip_pkt.protocol, pub_port)

            if key_in in self.nat_in:
                data_in = self.nat_in[key_in]
                priv_ip = data_in['ip_priv']
                priv_port = data_in['port_priv']
                out_port = data_in['in_port']
                
                key_out = (ip_pkt.protocol, priv_ip, priv_port)
                if key_out in self.nat_out:
                    self.nat_out[key_out]['last_active'] = time.time()
                    if is_tcp:
                        self._update_tcp_state(self.nat_out[key_out], l4_pkt)

                if priv_ip in self.arp_table:
                    dst_mac, _ = self.arp_table[priv_ip]
                    
                    l4_pkt.dstport = priv_port
                    ip_pkt.dstip = priv_ip
                    packet.src = PRIVATE_MAC
                    packet.dst = dst_mac
                    
                    msg = of.ofp_packet_out(data=packet.pack())
                    msg.actions.append(of.ofp_action_output(port=out_port))
                    self.connection.send(msg)
                else:
                    log_color(YELLOW, f"MAC interna desconocida para {priv_ip}")

def launch():
    def start_switch(event):
        ProtoRouter(event.connection)
    core.openflow.addListenerByName("ConnectionUp", start_switch)