# config.py
# Configuración central del NAT. Todos los parámetros modificables están acá.
# Para cambiar IPs/MACs en la demo, solo hay que tocar este archivo.

from pox.lib.addresses import EthAddr, IPAddr

# ── Interfaz pública del NAT ───────────────────────────────────────────────
PUBLIC_IP   = IPAddr("200.0.0.254")
PUBLIC_MAC  = EthAddr("00:00:00:aa:aa:aa")
PUBLIC_PORT = 1                         # Puerto del switch hacia la red pública

# ── Interfaz privada del NAT ───────────────────────────────────────────────
PRIVATE_IP     = IPAddr("192.168.1.254")
PRIVATE_MAC    = EthAddr("00:00:00:bb:bb:bb")
PRIVATE_SUBNET = IPAddr("192.168.1.0")
PRIVATE_MASK   = 24

# ── Rango de puertos públicos para NAT ────────────────────────────────────
NAT_PORT_START = 10000
NAT_PORT_END   = 65535

# ── Timeout de flujos OpenFlow ────────────────────────────────────────────
FLOW_TIMEOUT = 60                       # segundos de inactividad