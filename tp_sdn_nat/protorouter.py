# nat_router.py
# Coordinador principal del NAT.
# Orquesta ARPHandler, NATTable y FlowManager.
# Es el único que escucha eventos OpenFlow directamente.

from pox.core import core
import pox.openflow.libopenflow_01 as of
import pox.lib.packet as pkt

from config import (PUBLIC_IP, PUBLIC_MAC, PRIVATE_MAC,
                    PUBLIC_PORT, PRIVATE_SUBNET, PRIVATE_MASK)
from arp_handler import ARPHandler
from nat_table   import NATTable
from flow_manager import FlowManager

log = core.getLogger()


class ProtoRouter:

    def __init__(self, connection):
        self._connection  = connection

        self._nat_table   = NATTable()
        self._flow_mgr    = FlowManager(connection)
        self._arp_handler = ARPHandler(connection, self._on_mac_resolved)

        connection.addListeners(self)
        log.info("NATRouter iniciado para switch %s", connection.dpid)

    # ── Eventos OpenFlow ───────────────────────────────────────────────────

    def _handle_PacketIn(self, event):
        eth = event.parsed
        if not eth or not eth.parsed:
            log.warning("Paquete no reconocido, descartando")
            return

        if eth.type == pkt.ethernet.ARP_TYPE:
            self._arp_handler.handle(event, eth.payload)

        elif eth.type == pkt.ethernet.IP_TYPE:
            ip = eth.payload
            if not isinstance(ip, pkt.ipv4):
                log.warning("Paquete IP no parseable, descartando")
                return
            self._handle_ip(event.port, eth, ip, event.data)

        else:
            log.debug("Protocolo 0x%04x ignorado", eth.type)

    def _handle_FlowRemoved(self, event):
        """Limpia la entrada NAT cuando un flujo expira en el switch."""
        match = event.ofp.match
        proto = match.nw_proto

        if proto not in (pkt.ipv4.TCP_PROTOCOL, pkt.ipv4.UDP_PROTOCOL):
            return

        # El flujo saliente tiene src=PUBLIC_IP
        if match.nw_src == PUBLIC_IP and match.tp_src is not None:
            self._nat_table.remove_entry(proto, match.tp_src)

    # ── Manejo de IP ───────────────────────────────────────────────────────

    def _handle_ip(self, in_port, eth, ip, raw_data):
        if ip.srcip.inNetwork(PRIVATE_SUBNET, PRIVATE_MASK):
            self._handle_outbound(in_port, eth, ip, raw_data)
        elif ip.dstip == PUBLIC_IP:
            self._handle_inbound(in_port, eth, ip)
        else:
            log.warning("Paquete descartado: %s → %s no aplica NAT",
                        ip.srcip, ip.dstip)

    # ── NAT saliente ───────────────────────────────────────────────────────

    def _handle_outbound(self, in_port, eth, ip, raw_data):
        proto = ip.protocol
        if proto == pkt.ipv4.ICMP_PROTOCOL:
            priv_port = ip.payload.next.id
            dst_port  = 0
        elif proto in (pkt.ipv4.TCP_PROTOCOL, pkt.ipv4.UDP_PROTOCOL):
            priv_port = ip.payload.srcport
            dst_port  = ip.payload.dstport
        else:
            log.warning("Protocolo %d no soportado por NAT, descartando", proto)
            return

        priv_ip = ip.srcip
        dst_ip  = ip.dstip

        # Buscar o crear entrada NAT
        pub_port = self._nat_table.get_public_port(proto, priv_ip, priv_port)
        if pub_port is None:
            pub_port = self._nat_table.add_entry(proto, priv_ip, priv_port, in_port)
            if pub_port is None:
                return  # sin puertos disponibles, error ya loggeado

        # Resolver MAC del destino público
        if not self._arp_handler.has_mac(dst_ip):
            self._arp_handler.request_mac(dst_ip, in_port, raw_data)
            return

        dst_mac, _ = self._arp_handler.get_mac(dst_ip)

        # Aprender MAC del host privado si no la tenemos
        if not self._arp_handler.has_mac(priv_ip):
            self._arp_handler.arp_table[priv_ip] = (eth.src, in_port)
            log.info("MAC de %s aprendida del paquete: %s", priv_ip, eth.src)

        priv_mac, priv_sw_port = self._arp_handler.get_mac(priv_ip)

        # Instalar flujos en el switch
        self._flow_mgr.install_outbound(proto,
                                         priv_ip, priv_port,
                                         dst_ip,  dst_port,
                                         pub_port, dst_mac)
        self._flow_mgr.install_inbound(proto,
                                        pub_port,
                                        dst_ip, dst_port,
                                        priv_ip, priv_port,
                                        priv_mac, priv_sw_port)

        # Traducir y reenviar el primer paquete manualmente
        self._forward_outbound(eth, ip, dst_ip, dst_port,
                                proto, pub_port, dst_mac)

    def _forward_outbound(self, eth, ip, dst_ip, dst_port,
                           proto, pub_port, dst_mac):
        """Traduce y reenvía el primer paquete saliente."""
        ip.srcip = PUBLIC_IP
        ip.csum  = 0

        if proto == pkt.ipv4.ICMP_PROTOCOL:
            ip.payload.next.id   = pub_port
            ip.payload.next.csum = 0
            ip.payload.csum      = 0
        else:
            ip.payload.srcport = pub_port
            ip.payload.csum    = 0

        eth.src = PUBLIC_MAC
        eth.dst = dst_mac

        self._send_packet(eth.pack(), PUBLIC_PORT)
        log.info("ENVIADO saliente: %s:%d → %s:%d",
                 PUBLIC_IP, pub_port, dst_ip, dst_port)

    # ── NAT entrante ───────────────────────────────────────────────────────

    def _handle_inbound(self, in_port, eth, ip):
        proto = ip.protocol
        if proto == pkt.ipv4.ICMP_PROTOCOL:
            pub_port = ip.payload.next.id
        elif proto in (pkt.ipv4.TCP_PROTOCOL, pkt.ipv4.UDP_PROTOCOL):
            pub_port = ip.payload.dstport
        else:
            log.warning("Protocolo %d no soportado, descartando", proto)
            return

        entry = self._nat_table.get_private_info(proto, pub_port)
        if entry is None:
            log.warning("Paquete entrante sin entrada NAT (pub_port=%d), descartando",
                        pub_port)
            return

        priv_ip, priv_port, priv_sw_port = entry
        mac_entry = self._arp_handler.get_mac(priv_ip)
        if mac_entry is None:
            log.warning("MAC de %s no encontrada, descartando paquete entrante", priv_ip)
            return

        priv_mac, _ = mac_entry
        self._forward_inbound(eth, ip, proto, priv_ip, priv_port,
                               priv_mac, priv_sw_port)

    def _forward_inbound(self, eth, ip, proto,
                          priv_ip, priv_port, priv_mac, priv_sw_port):
        """Traduce y reenvía el primer paquete entrante."""
        ip.dstip = priv_ip
        ip.csum  = 0

        if proto == pkt.ipv4.ICMP_PROTOCOL:
            ip.payload.next.id   = priv_port
            ip.payload.next.csum = 0
            ip.payload.csum      = 0
        else:
            ip.payload.dstport = priv_port
            ip.payload.csum    = 0

        eth.src = PRIVATE_MAC
        eth.dst = priv_mac

        self._send_packet(eth.pack(), priv_sw_port)
        log.info("ENVIADO entrante: → %s:%d (sw_port=%d)",
                 priv_ip, priv_port, priv_sw_port)

    # ── Callback de ARP resuelto ───────────────────────────────────────────

    def _on_mac_resolved(self, in_port, raw_data):
        """
        Llamado por ARPHandler cuando se resuelve una MAC pendiente.
        Reinyecta el paquete para que sea procesado ahora que la MAC está disponible.
        """
        eth = pkt.ethernet(raw=raw_data)
        if eth.type != pkt.ethernet.IP_TYPE:
            return
        ip = eth.payload
        if not isinstance(ip, pkt.ipv4):
            return
        self._handle_ip(in_port, eth, ip, raw_data)

    # ── Envío ──────────────────────────────────────────────────────────────

    def _send_packet(self, data, out_port):
        msg = of.ofp_packet_out()
        msg.data = data
        msg.actions.append(of.ofp_action_output(port=out_port))
        self._connection.send(msg)


# ── Launch ─────────────────────────────────────────────────────────────────

def launch():
    def start_switch(event):
        log.info("Iniciando ProtoRouter para switch %s", event.connection.dpid)
        ProtoRouter(event.connection)

    core.openflow.addListenerByName("ConnectionUp", start_switch)