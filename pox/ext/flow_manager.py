# flow_manager.py
# Instala y elimina reglas OpenFlow en el switch.
# No sabe nada de ARP ni del estado NAT — solo construye y envía flow_mods.

from pox.core import core
import pox.openflow.libopenflow_01 as of
import pox.lib.packet as pkt

from config import PUBLIC_IP, PUBLIC_MAC, PRIVATE_MAC, PUBLIC_PORT, FLOW_TIMEOUT

log = core.getLogger()


class FlowManager:

    def __init__(self, connection):
        self._connection = connection

    def install_outbound(self, proto,
                          priv_ip, priv_port,
                          dst_ip,  dst_port,
                          pub_port, dst_mac):
        """
        Instala flujo saliente: paquetes de priv_ip:priv_port → dst_ip:dst_port
        son traducidos y reenviados por PUBLIC_PORT.
        """
        fm = of.ofp_flow_mod()
        fm.idle_timeout  = FLOW_TIMEOUT
        fm.flags         = of.OFPFF_SEND_FLOW_REM  # notificar al expirar
        fm.match.dl_type = 0x0800
        fm.match.nw_proto = proto
        fm.match.nw_src   = priv_ip
        fm.match.nw_dst   = dst_ip

        if proto != pkt.ipv4.ICMP_PROTOCOL:
            fm.match.tp_src = priv_port
            fm.match.tp_dst = dst_port

        fm.actions.append(of.ofp_action_nw_addr.set_src(PUBLIC_IP))
        if proto != pkt.ipv4.ICMP_PROTOCOL:
            fm.actions.append(of.ofp_action_tp_port.set_src(pub_port))
        fm.actions.append(of.ofp_action_dl_addr.set_src(PUBLIC_MAC))
        fm.actions.append(of.ofp_action_dl_addr.set_dst(dst_mac))
        fm.actions.append(of.ofp_action_output(port=PUBLIC_PORT))

        self._connection.send(fm)
        log.info("Flujo SALIENTE instalado: %s:%d → %s:%d (pub_port=%d)",
                 priv_ip, priv_port, dst_ip, dst_port, pub_port)

    def install_inbound(self, proto,
                         pub_port,
                         dst_ip, dst_port,
                         priv_ip, priv_port,
                         priv_mac, priv_sw_port):
        """
        Instala flujo entrante: paquetes de dst_ip:dst_port → PUBLIC_IP:pub_port
        son traducidos y reenviados al host privado.
        """
        fm = of.ofp_flow_mod()
        fm.idle_timeout   = FLOW_TIMEOUT
        fm.flags          = of.OFPFF_SEND_FLOW_REM
        fm.match.dl_type  = 0x0800
        fm.match.nw_proto = proto
        fm.match.nw_dst   = PUBLIC_IP
        fm.match.in_port  = PUBLIC_PORT

        if proto != pkt.ipv4.ICMP_PROTOCOL:
            fm.match.tp_dst = pub_port

        fm.actions.append(of.ofp_action_nw_addr.set_dst(priv_ip))
        if proto != pkt.ipv4.ICMP_PROTOCOL:
            fm.actions.append(of.ofp_action_tp_port.set_dst(priv_port))
        fm.actions.append(of.ofp_action_dl_addr.set_src(PRIVATE_MAC))
        fm.actions.append(of.ofp_action_dl_addr.set_dst(priv_mac))
        fm.actions.append(of.ofp_action_output(port=priv_sw_port))

        self._connection.send(fm)
        log.info("Flujo ENTRANTE instalado: pub_port=%d → %s:%d (sw_port=%d)",
                 pub_port, priv_ip, priv_port, priv_sw_port)