from pox.core import core
import pox.openflow.libopenflow_01 as of
import pox.lib.packet as pkt
from pox.lib.addresses import EthAddr

from config import PUBLIC_IP, PUBLIC_MAC, PRIVATE_IP, PRIVATE_MAC, PUBLIC_PORT

log = core.getLogger()

RED    = "\033[31m"
GREEN  = "\033[32m"
YELLOW = "\033[33m"
CYAN   = "\033[36m"
BLUE   = "\033[34m"
RESET  = "\033[0m"

def log_color(color, msg):
    log.info(f"{color}{msg}{RESET}")



class ARPHandler:

    def __init__(self, connection, on_mac_resolved):
        """
        connection      -- conexión OpenFlow al switch
        on_mac_resolved -- callback que se llama cuando se resuelve una MAC pendiente.
                           Firma: on_mac_resolved(in_port, raw_packet)
        """
        self._connection    = connection
        self._on_mac_resolved = on_mac_resolved

        # ip → (mac, puerto_switch)
        self.arp_table = {}

        # ip_destino → [(in_port, raw_packet), ...]
        self._pending  = {}

    # ── Punto de entrada ───────────────────────────────────────────────────

    def handle(self, event, arp_pkt):
        """Procesa un paquete ARP recibido."""
        self._learn(arp_pkt, event.port)

        if arp_pkt.opcode == pkt.arp.REQUEST:
            self._handle_request(arp_pkt, event.port)
        elif arp_pkt.opcode == pkt.arp.REPLY:
            self._handle_reply(arp_pkt)
        else:
            log_color(RED, f"ARP opcode desconocido: {arp_pkt.opcode}")

    # ── Encolar paquetes pendientes de resolución ARP ──────────────────────

    def request_mac(self, dst_ip, in_port, raw_packet):
        """
        Encola raw_packet hasta que se resuelva la MAC de dst_ip.
        Si es la primera vez que se pide esta IP, emite un ARP Request.
        """
        first_request = dst_ip not in self._pending
        self._pending.setdefault(dst_ip, []).append((in_port, raw_packet))

        if first_request:
            out_port = PUBLIC_PORT
            self._send_request(PUBLIC_IP, PUBLIC_MAC, dst_ip, out_port)
            log_color(BLUE, f"ARP REQUEST enviado: ¿quién tiene {dst_ip}? (desde {PUBLIC_IP})")

    def has_mac(self, ip):
        """Devuelve True si la MAC de ip está en la tabla ARP."""
        return ip in self.arp_table

    def get_mac(self, ip):
        """Devuelve (mac, sw_port) para una IP conocida, o None."""
        return self.arp_table.get(ip)

    # ── Internos ───────────────────────────────────────────────────────────

    def _learn(self, arp_pkt, in_port):
        """Aprende la MAC del remitente de cualquier paquete ARP."""
        if arp_pkt.protosrc not in (None,):
            self.arp_table[arp_pkt.protosrc] = (arp_pkt.hwsrc, in_port)
            log_color(BLUE, f"ARP aprendido: {arp_pkt.protosrc} → {arp_pkt.hwsrc} (port {in_port})")

    def _handle_request(self, arp_pkt, in_port):
        """Responde ARP Requests dirigidos a las IPs del NAT."""
        if arp_pkt.protodst == PUBLIC_IP:
            log_color(BLUE, f"ARP REQUEST para IP pública ({PUBLIC_IP}), respondiendo con {PUBLIC_MAC}")
            self._send_reply(arp_pkt, PUBLIC_MAC, in_port)

        elif arp_pkt.protodst == PRIVATE_IP:
            log_color(BLUE, f"ARP REQUEST para IP privada ({PRIVATE_IP}), respondiendo con {PRIVATE_MAC}")
            self._send_reply(arp_pkt, PRIVATE_MAC, in_port)

        else:
            log_color(YELLOW, f"ARP REQUEST para {arp_pkt.protodst}: no es mi IP, ignorando")

    def _handle_reply(self, arp_pkt):
        """Cuando llega un Reply, procesa los paquetes que estaban esperando esa MAC."""
        log_color(BLUE, f"ARP REPLY recibido: {arp_pkt.protosrc} tiene {arp_pkt.hwsrc}")
        self._flush_pending(arp_pkt.protosrc)

    def _flush_pending(self, ip):
        """Procesa todos los paquetes encolados para una IP ahora que su MAC es conocida."""
        if ip not in self._pending:
            return
        pending = self._pending.pop(ip)
        log_color(BLUE, f"Procesando {len(pending)} paquete(s) pendiente(s) para {ip}")
        for (in_port, raw_packet) in pending:
            self._on_mac_resolved(in_port, raw_packet)

    def _send_reply(self, req, reply_mac, out_port):
        """Construye y envía un ARP Reply."""
        r          = pkt.arp()
        r.opcode   = pkt.arp.REPLY
        r.hwsrc    = reply_mac
        r.hwdst    = req.hwsrc
        r.protosrc = req.protodst
        r.protodst = req.protosrc

        e         = pkt.ethernet()
        e.type    = pkt.ethernet.ARP_TYPE
        e.src     = reply_mac
        e.dst     = req.hwsrc
        e.payload = r

        self._send_raw(e.pack(), out_port)

    def _send_request(self, src_ip, src_mac, dst_ip, out_port):
        """Construye y envía un ARP Request broadcast."""
        r          = pkt.arp()
        r.opcode   = pkt.arp.REQUEST
        r.hwsrc    = src_mac
        r.hwdst    = EthAddr("ff:ff:ff:ff:ff:ff")
        r.protosrc = src_ip
        r.protodst = dst_ip

        e         = pkt.ethernet()
        e.type    = pkt.ethernet.ARP_TYPE
        e.src     = src_mac
        e.dst     = EthAddr("ff:ff:ff:ff:ff:ff")
        e.payload = r

        self._send_raw(e.pack(), out_port)

    def _send_raw(self, data, out_port):
        """Envía bytes crudos por un puerto del switch."""
        msg = of.ofp_packet_out()
        msg.data = data
        msg.actions.append(of.ofp_action_output(port=out_port))
        self._connection.send(msg)