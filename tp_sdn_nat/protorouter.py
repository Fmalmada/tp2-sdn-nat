# Import some POX stuff
from pox.core import core                       # Main POX object
import pox.openflow.libopenflow_01 as of        # OpenFlow 1.0 library
from pox.lib.addresses import EthAddr, IPAddr   # Address types
from pox.lib.packet.ethernet import ethernet
from pox.lib.packet.arp import arp
from pox.lib.packet.ipv4 import ipv4
# ── ICMP OPCIONAL ── quitar esta línea si no se quiere soporte ICMP
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


# ──────────────────────────────────────────────
#  Configuración de red (sin valores hardcodeados de hosts)
# ──────────────────────────────────────────────
PRIVATE_SUBNET = IPAddr("192.168.1.0")      # Red interna
PRIVATE_MASK   = 24                         # Máscara de la red interna
PRIVATE_IP     = IPAddr("192.168.1.254")    # IP del NAT en la red privada
PUBLIC_IP      = IPAddr("200.0.0.254")      # IP del NAT en la red pública
PUBLIC_MAC     = EthAddr("00:00:00:aa:aa:aa")  # MAC del NAT hacia la red pública
PRIVATE_MAC    = EthAddr("00:00:00:bb:bb:bb")  # MAC del NAT hacia la red privada
PUBLIC_PORT    = 1                          # Puerto del switch conectado a la red pública

NAT_PORT_START = 10000                      # Primer puerto público a asignar
NAT_PORT_END   = 65535                      # Último puerto público a asignar
FLOW_TIMEOUT   = 60                         # Segundos de inactividad antes de expirar flujo


class ProtoRouter(object):

    def __init__(self, connection):
        self.connection = connection
        connection.addListeners(self)

        # ── Tabla ARP dinámica ──────────────────────────────────────────
        # ip -> (mac, puerto_del_switch)
        self.arp_table = {}

        # ── Tablas NAT ──────────────────────────────────────────────────
        # Saliente: (proto, ip_privada, puerto_privado) -> puerto_publico
        self.nat_out = {}
        # Entrante: (proto, puerto_publico) -> (ip_privada, puerto_privado, in_port)
        self.nat_in  = {}
        # Próximo puerto público disponible
        self.next_port = NAT_PORT_START

        # ── Cola de paquetes pendientes de resolución ARP ───────────────
        # ip_destino -> [(packet_ethernet, in_port), ...]
        self.pending = {}

        log_color(YELLOW, "ProtoRouter (NAT/PAT) iniciado.")

    # ══════════════════════════════════════════════════════════════════════
    #  Dispatcher principal
    # ══════════════════════════════════════════════════════════════════════

    def _handle_PacketIn(self, event):
        if not event.parsed.parsed:
            log.warning("[DROP] Trama no reconocida.")
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

        # Aprender siempre la MAC del remitente
        self.arp_table[arp_pkt.protosrc] = (arp_pkt.hwsrc, in_port)
        log_color(BLUE, f"ARP aprendido: {arp_pkt.protosrc} → {arp_pkt.hwsrc} (port {in_port})")

        if arp_pkt.opcode == arp.REQUEST:
            # ¿Me preguntan a mí?
            if arp_pkt.protodst == PUBLIC_IP:
                log_color(BLUE, f"ARP REQUEST para IP pública ({PUBLIC_IP}), respondiendo con {PUBLIC_MAC}")
                self._send_arp_reply(arp_pkt, PUBLIC_MAC, in_port)

            elif arp_pkt.protodst == PRIVATE_IP:
                log_color(BLUE, f"ARP REQUEST para IP privada ({PRIVATE_IP}), respondiendo con {PRIVATE_MAC}")
                self._send_arp_reply(arp_pkt, PRIVATE_MAC, in_port)

            else:
                # No es para mí, ignorar
                log_color(YELLOW, f"ARP REQUEST para {arp_pkt.protodst}: no es mi IP, ignorando.")

        elif arp_pkt.opcode == arp.REPLY:
            # Recibí una respuesta: procesar paquetes que estaban esperando
            log_color(BLUE, f"ARP REPLY recibido: {arp_pkt.protosrc} tiene {arp_pkt.hwsrc}")
            self._flush_pending(arp_pkt.protosrc)

    def _send_arp_reply(self, req, reply_mac, out_port):
        """Construye y envía un ARP reply."""
        r            = arp()
        r.opcode     = arp.REPLY
        r.hwsrc      = reply_mac
        r.hwdst      = req.hwsrc
        r.protosrc   = req.protodst
        r.protodst   = req.protosrc

        e         = ethernet()
        e.type    = ethernet.ARP_TYPE
        e.src     = reply_mac
        e.dst     = req.hwsrc
        e.payload = r

        msg        = of.ofp_packet_out()
        msg.data   = e.pack()
        msg.actions.append(of.ofp_action_output(port=out_port))
        self.connection.send(msg)

    def _send_arp_request(self, src_ip, src_mac, dst_ip, out_port):
        """Envía un ARP request broadcast para resolver dst_ip."""
        r            = arp()
        r.opcode     = arp.REQUEST
        r.hwsrc      = src_mac
        r.hwdst      = EthAddr("ff:ff:ff:ff:ff:ff")
        r.protosrc   = src_ip
        r.protodst   = dst_ip

        e         = ethernet()
        e.type    = ethernet.ARP_TYPE
        e.src     = src_mac
        e.dst     = EthAddr("ff:ff:ff:ff:ff:ff")
        e.payload = r

        msg        = of.ofp_packet_out()
        msg.data   = e.pack()
        msg.actions.append(of.ofp_action_output(port=out_port))
        self.connection.send(msg)
        log_color(BLUE, f"ARP REQUEST enviado: ¿quién tiene {dst_ip}? (desde {src_ip})")

    def _flush_pending(self, ip):
        """Procesa paquetes que estaban esperando la MAC de 'ip'."""
        if ip not in self.pending:
            return
        pkts = self.pending.pop(ip)
        log_color(BLUE, f"Procesando {len(pkts)} paquete(s) pendiente(s) para {ip}")
        for (pkt, in_port) in pkts:
            self._process_outbound(pkt, pkt.payload, in_port)

    # ══════════════════════════════════════════════════════════════════════
    #  Manejo de IP
    # ══════════════════════════════════════════════════════════════════════

    def handle_ip(self, event):
        pkt     = event.parsed
        ip_pkt  = pkt.payload
        in_port = event.port

        log_color(YELLOW, f"IP: {ip_pkt.srcip} → {ip_pkt.dstip} | in_port={in_port}")

        if ip_pkt.srcip.inNetwork(PRIVATE_SUBNET, PRIVATE_MASK):
            # ── Paquete SALIENTE (de red privada hacia red pública) ──────
            self._handle_outbound(pkt, ip_pkt, in_port)

        elif ip_pkt.dstip == PUBLIC_IP:
            # ── Paquete ENTRANTE (respuesta del servidor al NAT) ─────────
            self._handle_inbound(pkt, ip_pkt, in_port)

        else:
            log_color(RED, f"Paquete descartado: {ip_pkt.srcip} → {ip_pkt.dstip} no aplica NAT")

    # ──────────────────────────────────────────────────────────────────────
    #  Saliente: red privada → red pública
    # ──────────────────────────────────────────────────────────────────────

    def _handle_outbound(self, pkt, ip_pkt, in_port):
        proto    = ip_pkt.protocol
        tcp_udp  = ip_pkt.payload

        # ── ICMP OPCIONAL ── quitar el bloque marcado si no se quiere soporte ICMP ──
        if proto == ipv4.ICMP_PROTOCOL:
            icmp_pkt = ip_pkt.payload        # objeto icmp (type, code, csum)
            echo_pkt = icmp_pkt.next         # objeto echo (id, seq)
            src_port = echo_pkt.id           # el id del echo es el "puerto"
            dst_ip   = ip_pkt.dstip
            dst_port = 0                     # ICMP no tiene puerto destino
        # ── FIN ICMP OPCIONAL ────────────────────────────────────────────────────
        elif proto in (ipv4.TCP_PROTOCOL, ipv4.UDP_PROTOCOL):
            src_port = tcp_udp.srcport
            dst_ip   = ip_pkt.dstip
            dst_port = tcp_udp.dstport
        else:
            log_color(RED, f"Protocolo {proto} no soportado por NAT (solo TCP/UDP)")
            return

        # ── Buscar o crear entrada NAT ────────────────────────────────────
        nat_key = (proto, ip_pkt.srcip, src_port)
        if nat_key not in self.nat_out:
            if self.next_port > NAT_PORT_END:
                log_color(RED, "Sin puertos NAT disponibles!")
                return
            pub_port = self.next_port
            self.next_port += 1
            self.nat_out[nat_key] = pub_port
            self.nat_in[(proto, pub_port)] = (ip_pkt.srcip, src_port, in_port)
            log_color(GREEN, f"Nueva entrada NAT: {ip_pkt.srcip}:{src_port} → {PUBLIC_IP}:{pub_port}")
        else:
            pub_port = self.nat_out[nat_key]

        # ── ¿Tenemos la MAC del destino público? ─────────────────────────
        if dst_ip not in self.arp_table:
            log_color(BLUE, f"MAC de {dst_ip} desconocida, encolando paquete y enviando ARP REQUEST")
            self.pending.setdefault(dst_ip, []).append((pkt, in_port))
            self._send_arp_request(PUBLIC_IP, PUBLIC_MAC, dst_ip, PUBLIC_PORT)
            return

        self._process_outbound(pkt, ip_pkt, in_port)

    def _process_outbound(self, pkt, ip_pkt, in_port):
        """Traduce y reenvía un paquete saliente. Instala flujos en el switch."""
        proto  = ip_pkt.protocol
        dst_ip = ip_pkt.dstip

        # ── ICMP OPCIONAL ── quitar el bloque marcado si no se quiere soporte ICMP ──
        if proto == ipv4.ICMP_PROTOCOL:
            src_port = ip_pkt.payload.next.id   # echo.id
            dst_port = 0
        # ── FIN ICMP OPCIONAL ────────────────────────────────────────────────────
        else:
            src_port = ip_pkt.payload.srcport
            dst_port = ip_pkt.payload.dstport

        nat_key  = (proto, ip_pkt.srcip, src_port)
        pub_port = self.nat_out[nat_key]

        dst_mac, dst_switch_port = self.arp_table[dst_ip]

        log_color(GREEN,
            f"SALIENTE: {ip_pkt.srcip}:{src_port} → {dst_ip}:{dst_port} "
            f"| NAT: {PUBLIC_IP}:{pub_port}")

        # ── Instalar flujo SALIENTE en el switch ──────────────────────────
        fm = of.ofp_flow_mod()
        fm.idle_timeout = FLOW_TIMEOUT
        fm.match.dl_type  = 0x0800
        fm.match.nw_proto = proto
        fm.match.nw_src   = ip_pkt.srcip
        fm.match.tp_src   = src_port
        fm.match.in_port  = in_port
        # Acciones: reescribir IP src, puerto src, MACs y enviar
        fm.actions.append(of.ofp_action_nw_addr.set_src(PUBLIC_IP))
        fm.actions.append(of.ofp_action_tp_port.set_src(pub_port))
        fm.actions.append(of.ofp_action_dl_addr.set_src(PUBLIC_MAC))
        fm.actions.append(of.ofp_action_dl_addr.set_dst(dst_mac))
        fm.actions.append(of.ofp_action_output(port=PUBLIC_PORT))
        self.connection.send(fm)

        # ── Instalar flujo ENTRANTE en el switch ──────────────────────────
        priv_ip, priv_port, priv_switch_port = self.nat_in[(proto, pub_port)]

        # Aprender la MAC del cliente privado del paquete que llegó
        # (puede que no haya hecho ARP si tenía la MAC en caché)
        if priv_ip not in self.arp_table:
            self.arp_table[priv_ip] = (pkt.src, in_port)
            log_color(BLUE, f"MAC de {priv_ip} aprendida del paquete: {pkt.src}")

        priv_mac, _ = self.arp_table.get(priv_ip, (None, None))

        if priv_mac is None:
            log_color(RED, f"MAC de {priv_ip} no encontrada en tabla ARP, no se instala flujo entrante")
            return

        fm_back = of.ofp_flow_mod()
        fm_back.idle_timeout = FLOW_TIMEOUT
        fm_back.match.dl_type  = 0x0800
        fm_back.match.nw_proto = proto
        fm_back.match.nw_dst   = PUBLIC_IP
        fm_back.match.tp_dst   = pub_port
        fm_back.match.in_port  = PUBLIC_PORT
        # Acciones: reescribir IP dst, puerto dst, MACs y enviar
        fm_back.actions.append(of.ofp_action_nw_addr.set_dst(priv_ip))
        fm_back.actions.append(of.ofp_action_tp_port.set_dst(priv_port))
        fm_back.actions.append(of.ofp_action_dl_addr.set_src(PRIVATE_MAC))
        fm_back.actions.append(of.ofp_action_dl_addr.set_dst(priv_mac))
        fm_back.actions.append(of.ofp_action_output(port=priv_switch_port))
        self.connection.send(fm_back)

        # ── Reenviar el paquete actual (primero del flujo) ────────────────
        ip_pkt.srcip = PUBLIC_IP
        ip_pkt.csum  = 0

        # ── ICMP OPCIONAL ── quitar el bloque marcado si no se quiere soporte ICMP ──
        if proto == ipv4.ICMP_PROTOCOL:
            ip_pkt.payload.next.id   = pub_port   # echo.id
            ip_pkt.payload.next.csum = 0
            ip_pkt.payload.csum      = 0
        # ── FIN ICMP OPCIONAL ────────────────────────────────────────────────────
        else:
            tcp_udp         = ip_pkt.payload
            tcp_udp.srcport = pub_port
            tcp_udp.csum    = 0

        pkt.src = PUBLIC_MAC
        pkt.dst = dst_mac

        msg = of.ofp_packet_out()
        msg.data = pkt.pack()
        msg.actions.append(of.ofp_action_output(port=PUBLIC_PORT))
        self.connection.send(msg)

        log_color(CYAN,
            f"ENVIADO: {PUBLIC_IP}:{pub_port} → {dst_ip}:{dst_port} | "
            f"MAC: {PUBLIC_MAC} → {dst_mac}")

    # ──────────────────────────────────────────────────────────────────────
    #  Entrante: red pública → NAT (respuesta del servidor)
    # ──────────────────────────────────────────────────────────────────────

    def _handle_inbound(self, pkt, ip_pkt, in_port):
        proto    = ip_pkt.protocol
        tcp_udp  = ip_pkt.payload

        # ── ICMP OPCIONAL ── quitar el bloque marcado si no se quiere soporte ICMP ──
        if proto == ipv4.ICMP_PROTOCOL:
            dst_port = ip_pkt.payload.next.id   # echo.id
        # ── FIN ICMP OPCIONAL ────────────────────────────────────────────────────
        elif proto in (ipv4.TCP_PROTOCOL, ipv4.UDP_PROTOCOL):
            dst_port = tcp_udp.dstport
        else:
            log_color(RED, f"Protocolo {proto} no soportado por NAT (solo TCP/UDP)")
            return
        nat_key  = (proto, dst_port)

        if nat_key not in self.nat_in:
            log_color(RED,
                f"ENTRANTE sin entrada NAT: {ip_pkt.srcip} → {PUBLIC_IP}:{dst_port}, descartando")
            return

        priv_ip, priv_port, priv_switch_port = self.nat_in[nat_key]
        priv_mac_entry = self.arp_table.get(priv_ip)

        if priv_mac_entry is None:
            log_color(RED, f"MAC de {priv_ip} no encontrada, descartando paquete entrante")
            return

        priv_mac, _ = priv_mac_entry

        src_info = ip_pkt.payload.next.id if proto == ipv4.ICMP_PROTOCOL else tcp_udp.srcport
        log_color(GREEN,
            f"ENTRANTE: {ip_pkt.srcip}:{src_info} → {PUBLIC_IP}:{dst_port} "
            f"| NAT inverso → {priv_ip}:{priv_port}")

        # Traducir y reenviar
        ip_pkt.dstip = priv_ip
        ip_pkt.csum  = 0

        # ── ICMP OPCIONAL ── quitar el bloque marcado si no se quiere soporte ICMP ──
        if proto == ipv4.ICMP_PROTOCOL:
            ip_pkt.payload.next.id   = priv_port   # echo.id
            ip_pkt.payload.next.csum = 0
            ip_pkt.payload.csum      = 0
        # ── FIN ICMP OPCIONAL ────────────────────────────────────────────────────
        else:
            tcp_udp         = ip_pkt.payload
            tcp_udp.dstport = priv_port
            tcp_udp.csum    = 0

        pkt.src = PRIVATE_MAC
        pkt.dst = priv_mac

        msg = of.ofp_packet_out()
        msg.data = pkt.pack()
        msg.actions.append(of.ofp_action_output(port=priv_switch_port))
        self.connection.send(msg)

        log_color(CYAN,
            f"ENVIADO: {priv_ip}:{priv_port} | MAC: {PRIVATE_MAC} → {priv_mac}")


# ══════════════════════════════════════════════════════════════════════════
#  Launch
# ══════════════════════════════════════════════════════════════════════════

def launch():
    def start_switch(event):
        log_color(YELLOW, f"Iniciando ProtoRouter (NAT/PAT) para Switch {event.connection.dpid}")
        ProtoRouter(event.connection)

    core.openflow.addListenerByName("ConnectionUp", start_switch)