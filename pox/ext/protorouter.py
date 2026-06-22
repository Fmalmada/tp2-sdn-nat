# Import some POX stuff
from pox.core import core                       # Main POX object
import pox.openflow.libopenflow_01 as of        # OpenFlow 1.0 library
from pox.lib.addresses import EthAddr, IPAddr   # Address types
from pox.lib.packet.ethernet import ethernet
from pox.lib.packet.arp import arp

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
PRIVATE_MASK = 24                           # Máscara de la red interna
PRIVATE_IP = IPAddr("192.168.1.254")        # IP del router en la red privada
PUBLIC_IP = IPAddr("200.0.0.254")           # IP del router en la red pública
PUBLIC_MAC = EthAddr("00:00:00:aa:aa:aa")   # MAC del router hacia la red pública
PRIVATE_MAC = EthAddr("00:00:00:bb:bb:bb")  # MAC del router hacia la red privada
PUBLIC_PORT = 1                             # Puerto del switch conectado a la red pública


class ProtoRouter(object):
    def __init__(self, connection):
        self.connection = connection
        connection.addListeners(self)

        # ── Tabla ARP dinámica ──────────────────────────────────────────
        # ip -> (mac, puerto_del_switch)
        self.arp_table = {}

        # ── Cola de paquetes pendientes de resolución ARP ───────────────
        # ip_destino -> [(packet_ethernet, in_port), ...]
        self.pending = {}

        log_color(YELLOW, "ProtoRouter (con ARP dinámico) iniciado.")

    # ══════════════════════════════════════════════════════════════════════
    #  Dispatcher principal
    # ══════════════════════════════════════════════════════════════════════

    def _handle_PacketIn(self, event):
        if not event.parsed.parsed:
            log.warning("[DROP] PacketIn con trama no reconocida. POX no pudo decodificar el paquete.")
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

        # Aprender siempre la MAC del remitente y su puerto asociado
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
            self._process_ip(pkt, in_port)

    # ══════════════════════════════════════════════════════════════════════
    #  Manejo de IP
    # ══════════════════════════════════════════════════════════════════════
    
    def handle_ip(self, event):
        """Punto de entrada para paquetes IP recibidos."""
        self._process_ip(event.parsed, event.port)

    def _process_ip(self, packet, in_port):
        """Efectúa la lógica de ruteo e instalación de flujos con ARP dinámico."""
        ip_pkt = packet.payload

        log_color(
            YELLOW, f"RECIBIDO: {ip_pkt.srcip} → {ip_pkt.dstip} | "
            f"MAC: {packet.src} → {packet.dst} | In Port: {in_port}")

        if ip_pkt.srcip.inNetwork(PRIVATE_SUBNET, PRIVATE_MASK):
            log_color(GREEN, f"MATCH: {ip_pkt.srcip} pertenece a la red privada {PRIVATE_SUBNET}/{PRIVATE_MASK}")

            # ── RESOLUCIÓN DINÁMICA DE LA MAC DESTINO ─────────────────────
            dst_ip = ip_pkt.dstip
            
            if dst_ip in self.arp_table:
                # Si conocemos la MAC, la extraemos de la tabla dinámica
                dst_mac, _ = self.arp_table[dst_ip]
            else:
                # MAC desconocida: Encolamos el paquete actual
                log_color(CYAN, f"MAC desconocida para {dst_ip}. Guardando paquete en cola de espera.")
                if dst_ip not in self.pending:
                    self.pending[dst_ip] = []
                self.pending[dst_ip].append((packet, in_port))
                
                # Despachamos un ARP Request por el puerto público para descubrir al vecino externo
                self._send_arp_request(src_ip=PUBLIC_IP, src_mac=PUBLIC_MAC, dst_ip=dst_ip, out_port=PUBLIC_PORT)
                return

            # Instalar Flujo Saliente
            fm = of.ofp_flow_mod()
            fm.idle_timeout = 10

            # Filtro (Saliente)
            fm.match.nw_src = ip_pkt.srcip
            fm.match.dl_type = 0x800  # IPv4
            fm.match.in_port = in_port

            # Acción (Saliente)
            fm.actions.append(of.ofp_action_dl_addr.set_src(PUBLIC_MAC))
            fm.actions.append(of.ofp_action_dl_addr.set_dst(dst_mac))  # MAC dinámica obtenida por ARP
            fm.actions.append(of.ofp_action_output(port=PUBLIC_PORT))
            self.connection.send(fm)

            # Instalar Flujo Entrante (para respuesta)
            fm_back = of.ofp_flow_mod()
            fm_back.idle_timeout = 10

            # Filtro (Entrante)
            fm_back.match.nw_src = ip_pkt.dstip
            fm_back.match.nw_dst = ip_pkt.srcip
            fm_back.match.dl_type = 0x800  # IPv4
            fm_back.match.in_port = PUBLIC_PORT

            # Acción (Entrante)
            fm_back.actions.append(of.ofp_action_dl_addr.set_src(PRIVATE_MAC))
            fm_back.actions.append(of.ofp_action_dl_addr.set_dst(packet.src))
            fm_back.actions.append(of.ofp_action_output(port=in_port))
            self.connection.send(fm_back)

            # Reenviar paquete actual con MACs actualizadas (Los posteriores pasan por flujo)
            packet.src = PUBLIC_MAC
            packet.dst = dst_mac
            msg = of.ofp_packet_out()
            msg.data = packet.pack()
            msg.actions.append(of.ofp_action_output(port=PUBLIC_PORT))
            log_color(CYAN, f"ENVIANDO: {ip_pkt.srcip} → {ip_pkt.dstip} | MAC: {PUBLIC_MAC} → {dst_mac} | Out Port: {PUBLIC_PORT}")
            self.connection.send(msg)

        else:
            log_color(RED, f"NO MATCH: {ip_pkt.srcip} no pertenece a {PRIVATE_SUBNET}/{PRIVATE_MASK}")


def launch():
    def start_switch(event):
        log_color(YELLOW, f"Iniciando ProtoRouter para Switch {event.connection.dpid}")
        ProtoRouter(event.connection)

    core.openflow.addListenerByName("ConnectionUp", start_switch)