# nat_table.py
# Maneja el estado de las traducciones NAT.
# No sabe nada de paquetes, OpenFlow ni ARP — solo administra la tabla.

from pox.core import core
from config import NAT_PORT_START, NAT_PORT_END

log = core.getLogger()


class NATTable:

    def __init__(self):
        # Saliente: (proto, ip_privada, puerto_privado) → puerto_público
        self._nat_out = {}

        # Entrante: (proto, puerto_público) → (ip_privada, puerto_privado, sw_port)
        self._nat_in  = {}

        # Conjunto de puertos públicos en uso
        self._used_ports = set()
        self._next_port  = NAT_PORT_START

    # ── Consulta ───────────────────────────────────────────────────────────

    def get_public_port(self, proto, priv_ip, priv_port):
        """Devuelve el puerto público asignado a esta conexión, o None si no existe."""
        return self._nat_out.get((proto, priv_ip, priv_port))

    def get_private_info(self, proto, pub_port):
        """Devuelve (ip_privada, puerto_privado, sw_port) para un puerto público, o None."""
        return self._nat_in.get((proto, pub_port))

    # ── Alta ───────────────────────────────────────────────────────────────

    def add_entry(self, proto, priv_ip, priv_port, sw_port):
        """
        Crea una nueva entrada NAT asignando un puerto público libre.
        Devuelve el puerto público asignado, o None si no hay puertos disponibles.
        """
        pub_port = self._alloc_port()
        if pub_port is None:
            log.error("Sin puertos NAT disponibles")
            return None

        self._nat_out[(proto, priv_ip, priv_port)] = pub_port
        self._nat_in[(proto, pub_port)]             = (priv_ip, priv_port, sw_port)

        log.info("NAT nueva entrada: %s:%d → puerto público %d", priv_ip, priv_port, pub_port)
        return pub_port

    # ── Baja ───────────────────────────────────────────────────────────────

    def remove_entry(self, proto, pub_port):
        """
        Elimina la entrada NAT correspondiente a un puerto público.
        Se llama cuando el flujo OpenFlow expira (FlowRemoved).
        """
        entry = self._nat_in.pop((proto, pub_port), None)
        if entry is None:
            log.warning("remove_entry: no existe entrada para pub_port=%d", pub_port)
            return

        priv_ip, priv_port, _ = entry
        self._nat_out.pop((proto, priv_ip, priv_port), None)
        self._free_port(pub_port)

        log.info("NAT entrada eliminada: pub_port=%d (%s:%d)", pub_port, priv_ip, priv_port)

    # ── Asignación de puertos ──────────────────────────────────────────────

    def _alloc_port(self):
        """Asigna el próximo puerto público libre. Devuelve None si no hay."""
        start = self._next_port
        while self._next_port in self._used_ports:
            self._next_port += 1
            if self._next_port > NAT_PORT_END:
                self._next_port = NAT_PORT_START
            if self._next_port == start:
                return None

        port = self._next_port
        self._used_ports.add(port)
        self._next_port += 1
        if self._next_port > NAT_PORT_END:
            self._next_port = NAT_PORT_START
        return port

    def _free_port(self, port):
        """Libera un puerto público para reutilización."""
        self._used_ports.discard(port)