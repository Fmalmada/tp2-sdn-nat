#!/usr/bin/python3
"""
Test automatizado para TP2 SDN NAT
Corre con: sudo python3 test_nat.py
IMPORTANTE: POX debe estar corriendo antes de ejecutar este script
            python3 pox/pox.py log.level --DEBUG protorouter
"""

import time
import sys
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import RemoteController, OVSController
from mininet.link import TCLink
from mininet.log import setLogLevel

# ── Colores ────────────────────────────────────────────────────────────────
GREEN  = "\033[32m"
RED    = "\033[31m"
YELLOW = "\033[33m"
CYAN   = "\033[36m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

resultados = []

def ok(nombre):
    print(f"  {GREEN}✓ {nombre}{RESET}")
    resultados.append((nombre, True))

def fail(nombre, motivo=""):
    print(f"  {RED}✗ {nombre}{RESET}" + (f"\n    → {motivo}" if motivo else ""))
    resultados.append((nombre, False))

def titulo(texto):
    print(f"\n{CYAN}{BOLD}{'─'*55}{RESET}")
    print(f"{CYAN}{BOLD}  {texto}{RESET}")
    print(f"{CYAN}{BOLD}{'─'*55}{RESET}")

# ── Topología ──────────────────────────────────────────────────────────────

class NATTopo(Topo):
    def build(self):
        s1 = self.addSwitch('s1')
        h1 = self.addHost('h1', ip='200.0.0.1/24',   mac='00:00:00:00:00:01',
                          defaultRoute='via 200.0.0.254')
        h2 = self.addHost('h2', ip='192.168.1.2/24', mac='00:00:00:00:00:02',
                          defaultRoute='via 192.168.1.254')
        h3 = self.addHost('h3', ip='192.168.1.3/24', mac='00:00:00:00:00:03',
                          defaultRoute='via 192.168.1.254')
        self.addLink(h1, s1)
        self.addLink(h2, s1)
        self.addLink(h3, s1)

# ── Helpers ────────────────────────────────────────────────────────────────

def deshabilitar_ipv6(net):
    for host in net.hosts:
        host.cmd("sysctl -w net.ipv6.conf.all.disable_ipv6=1 > /dev/null 2>&1")
        host.cmd("sysctl -w net.ipv6.conf.default.disable_ipv6=1 > /dev/null 2>&1")
    net.get('s1').cmd("sysctl -w net.ipv6.conf.all.disable_ipv6=1 > /dev/null 2>&1")

def limpiar_arp(net):
    """Limpia caché ARP de todos los hosts."""
    for h in net.hosts:
        h.cmd("ip neigh flush all 2>/dev/null")

def esperar_controlador(net, intentos=10):
    """Espera hasta que el switch esté conectado al controlador."""
    s1 = net.get('s1')
    for i in range(intentos):
        result = s1.cmd("ovs-ofctl show s1 2>/dev/null")
        if "dpid" in result:
            return True
        time.sleep(1)
    return False

def ping_ok(host, dst_ip, count=5, timeout=10):
    """Ping con suficiente tiempo para resolver ARP y establecer flujos."""
    result = host.cmd(f"ping -c {count} -W {timeout} -i 0.5 {dst_ip} 2>&1")
    perdida = "100% packet loss" in result or "100% pérdida" in result
    sin_ruta = "Network is unreachable" in result or "Destino de red inaccesible" in result
    return not perdida and not sin_ruta and ("bytes from" in result or "bytes desde" in result)

def tcp_ok(cliente, servidor, ip, puerto, timeout=15):
    """HTTP con curl."""
    servidor.cmd(f"python3 -m http.server {puerto} > /dev/null 2>&1 &")
    time.sleep(2)
    result = cliente.cmd(f"curl -s --max-time {timeout} -o /dev/null -w '%{{http_code}}' http://{ip}:{puerto}/ 2>&1")
    servidor.cmd("pkill -f 'http.server' 2>/dev/null")
    time.sleep(1)
    return "200" in result

def udp_ok(cliente, servidor, ip, puerto, duracion=4, timeout=10):
    """iperf UDP."""
    servidor.cmd(f"iperf -s -u -p {puerto} -D > /dev/null 2>&1")
    time.sleep(2)
    result = cliente.cmd(f"iperf -c {ip} -u -p {puerto} -t {duracion} 2>&1")
    servidor.cmd(f"pkill -f 'iperf' 2>/dev/null")
    time.sleep(1)
    return "bits/sec" in result

# ── Tests ──────────────────────────────────────────────────────────────────

def test_icmp_basico(net):
    titulo("1. Conectividad ICMP básica")
    h1, h2, h3 = net.get('h1', 'h2', 'h3')
    limpiar_arp(net)
    time.sleep(2)

    if ping_ok(h2, '200.0.0.1'):
        ok("h2 → h1 ping")
    else:
        fail("h2 → h1 ping", "no hubo respuesta ICMP")

    limpiar_arp(net)
    time.sleep(2)

    if ping_ok(h3, '200.0.0.1'):
        ok("h3 → h1 ping")
    else:
        fail("h3 → h1 ping", "no hubo respuesta ICMP")


def test_icmp_simultaneo(net):
    titulo("2. ICMP simultáneo")
    h1, h2, h3 = net.get('h1', 'h2', 'h3')
    limpiar_arp(net)
    time.sleep(2)

    # Warmup: resolver ARP primero para que el simultaneo no falle por eso
    h2.cmd("ping -c 1 -W 5 200.0.0.1 > /dev/null 2>&1")
    h3.cmd("ping -c 1 -W 5 200.0.0.1 > /dev/null 2>&1")
    time.sleep(2)

    # Lanzar en paralelo
    h2.cmd("ping -c 5 -W 8 -i 0.5 200.0.0.1 > /tmp/ping_h2.txt 2>&1 &")
    h3.cmd("ping -c 5 -W 8 -i 0.5 200.0.0.1 > /tmp/ping_h3.txt 2>&1 &")
    time.sleep(12)

    res_h2 = h2.cmd("cat /tmp/ping_h2.txt")
    res_h3 = h3.cmd("cat /tmp/ping_h3.txt")

    ok_h2 = "bytes from" in res_h2 or "bytes desde" in res_h2
    ok_h3 = "bytes from" in res_h3 or "bytes desde" in res_h3

    if ok_h2:
        ok("h2 → h1 ping simultáneo")
    else:
        fail("h2 → h1 ping simultáneo", res_h2.strip().split('\n')[-1] if res_h2 else "sin salida")

    if ok_h3:
        ok("h3 → h1 ping simultáneo")
    else:
        fail("h3 → h1 ping simultáneo", res_h3.strip().split('\n')[-1] if res_h3 else "sin salida")


def test_tcp_basico(net):
    titulo("3. TCP básico (HTTP)")
    h1, h2, h3 = net.get('h1', 'h2', 'h3')
    limpiar_arp(net)
    time.sleep(2)

    if tcp_ok(h2, h1, '200.0.0.1', 8080):
        ok("h2 → h1 TCP (HTTP)")
    else:
        fail("h2 → h1 TCP (HTTP)", "curl no recibió HTTP 200")

    limpiar_arp(net)
    time.sleep(2)

    if tcp_ok(h3, h1, '200.0.0.1', 8081):
        ok("h3 → h1 TCP (HTTP)")
    else:
        fail("h3 → h1 TCP (HTTP)", "curl no recibió HTTP 200")


def test_tcp_simultaneo(net):
    titulo("4. TCP simultáneo")
    h1, h2, h3 = net.get('h1', 'h2', 'h3')
    limpiar_arp(net)
    time.sleep(2)

    h1.cmd("python3 -m http.server 8082 > /dev/null 2>&1 &")
    time.sleep(2)

    h2.cmd("curl -s --max-time 15 -o /dev/null -w '%{http_code}' http://200.0.0.1:8082/ > /tmp/tcp_h2.txt 2>&1 &")
    h3.cmd("curl -s --max-time 15 -o /dev/null -w '%{http_code}' http://200.0.0.1:8082/ > /tmp/tcp_h3.txt 2>&1 &")
    time.sleep(10)

    res_h2 = h2.cmd("cat /tmp/tcp_h2.txt")
    res_h3 = h3.cmd("cat /tmp/tcp_h3.txt")
    h1.cmd("pkill -f 'http.server' 2>/dev/null")

    if "200" in res_h2:
        ok("h2 → h1 TCP simultáneo")
    else:
        fail("h2 → h1 TCP simultáneo", f"respuesta: '{res_h2.strip()}'")

    if "200" in res_h3:
        ok("h3 → h1 TCP simultáneo")
    else:
        fail("h3 → h1 TCP simultáneo", f"respuesta: '{res_h3.strip()}'")


def test_udp_basico(net):
    titulo("5. UDP básico (iperf)")
    h1, h2, h3 = net.get('h1', 'h2', 'h3')
    limpiar_arp(net)
    time.sleep(2)

    if udp_ok(h2, h1, '200.0.0.1', 5001):
        ok("h2 → h1 UDP (iperf)")
    else:
        fail("h2 → h1 UDP (iperf)", "iperf no reportó transferencia")

    limpiar_arp(net)
    time.sleep(2)

    if udp_ok(h3, h1, '200.0.0.1', 5002):
        ok("h3 → h1 UDP (iperf)")
    else:
        fail("h3 → h1 UDP (iperf)", "iperf no reportó transferencia")


def test_udp_simultaneo(net):
    titulo("6. UDP simultáneo")
    h1, h2, h3 = net.get('h1', 'h2', 'h3')
    limpiar_arp(net)
    time.sleep(2)

    h1.cmd("iperf -s -u -p 5003 -D > /dev/null 2>&1")
    time.sleep(2)

    h2.cmd("iperf -c 200.0.0.1 -u -p 5003 -t 4 > /tmp/udp_h2.txt 2>&1 &")
    h3.cmd("iperf -c 200.0.0.1 -u -p 5003 -t 4 > /tmp/udp_h3.txt 2>&1 &")
    time.sleep(8)

    res_h2 = h2.cmd("cat /tmp/udp_h2.txt")
    res_h3 = h3.cmd("cat /tmp/udp_h3.txt")
    h1.cmd("pkill -f iperf 2>/dev/null")

    if "bits/sec" in res_h2:
        ok("h2 → h1 UDP simultáneo")
    else:
        fail("h2 → h1 UDP simultáneo", "iperf no reportó transferencia")

    if "bits/sec" in res_h3:
        ok("h3 → h1 UDP simultáneo")
    else:
        fail("h3 → h1 UDP simultáneo", "iperf no reportó transferencia")


def test_nat_no_hardcodeado(net):
    titulo("7. NAT no hardcodeado (cambiar MAC de h2)")
    h1, h2 = net.get('h1', 'h2')

    # Cambiar MAC de h2
    h2.cmd("ip link set h2-eth0 down")
    h2.cmd("ip link set h2-eth0 address 00:00:00:00:ff:ff")
    h2.cmd("ip link set h2-eth0 up")
    # Esperar a que la interfaz esté realmente up
    for _ in range(10):
        estado = h2.cmd("ip link show h2-eth0 2>/dev/null")
        if "UP" in estado and "00:00:00:00:ff:ff" in estado:
            break
        time.sleep(1)
    limpiar_arp(net)
    time.sleep(3)

    if tcp_ok(h2, h1, '200.0.0.1', 8083):
        ok("h2 TCP con MAC cambiada (00:00:00:00:ff:ff)")
    else:
        fail("h2 TCP con MAC cambiada", "el NAT puede estar hardcodeando MACs")

    # Restaurar
    h2.cmd("ip link set h2-eth0 down")
    h2.cmd("ip link set h2-eth0 address 00:00:00:00:00:02")
    h2.cmd("ip link set h2-eth0 up")
    time.sleep(1)


def test_direccion_inversa(net):
    titulo("8. Dirección inversa bloqueada (h1 → h2)")
    h1, h2 = net.get('h1', 'h2')
    limpiar_arp(net)
    time.sleep(2)

    # h1 intenta TCP directo a h2 — debe fallar
    h2.cmd("python3 -m http.server 9090 > /dev/null 2>&1 &")
    time.sleep(1)
    result = h1.cmd("curl -s --max-time 5 -o /dev/null -w '%{http_code}' http://192.168.1.2:9090/ 2>&1")
    h2.cmd("pkill -f 'http.server' 2>/dev/null")

    if "200" in result:
        fail("h1 no puede conectarse directamente a h2", "el NAT debería bloquear esto")
    else:
        ok("h1 no puede conectarse directamente a h2 (correcto)")


def test_flujos_switch(net):
    titulo("9. Flujos instalados en el switch")
    h1, h2 = net.get('h1', 'h2')
    s1 = net.get('s1')
    limpiar_arp(net)
    time.sleep(2)

    # Generar tráfico TCP para instalar flujos
    tcp_ok(h2, h1, '200.0.0.1', 8084)
    time.sleep(1)

    flows = s1.cmd("ovs-ofctl dump-flows s1 2>/dev/null")

    if "nw_src=192.168.1.2" in flows or "nw_dst=192.168.1.2" in flows:
        ok("Flujos NAT instalados en el switch")
    else:
        fail("No se encontraron flujos NAT", "revisar instalación de flujos OpenFlow")


# ── Main ───────────────────────────────────────────────────────────────────

def main():
    print(f"\n{BOLD}{CYAN}{'═'*55}{RESET}")
    print(f"{BOLD}{CYAN}   TEST SUITE - TP2 SDN NAT{RESET}")
    print(f"{BOLD}{CYAN}{'═'*55}{RESET}")
    print(f"{YELLOW}  POX debe estar corriendo:{RESET}")
    print(f"{YELLOW}  python3 pox/pox.py log.level --DEBUG protorouter{RESET}\n")

    setLogLevel('warning')

    topo = NATTopo()
    net  = Mininet(topo=topo, controller=RemoteController, link=TCLink)
    net.start()
    deshabilitar_ipv6(net)

    print(f"\n{GREEN}Red iniciada. Esperando conexión con el controlador...{RESET}")
    if not esperar_controlador(net):
        print(f"{RED}No se pudo conectar al controlador. ¿Está corriendo POX?{RESET}")
        net.stop()
        sys.exit(1)

    print(f"{GREEN}Switch conectado. Iniciando tests...{RESET}")
    time.sleep(2)

    try:
        test_icmp_basico(net)
        test_icmp_simultaneo(net)
        test_tcp_basico(net)
        test_tcp_simultaneo(net)
        test_udp_basico(net)
        test_udp_simultaneo(net)
        test_nat_no_hardcodeado(net)
        test_direccion_inversa(net)
        test_flujos_switch(net)

    except KeyboardInterrupt:
        print(f"\n{YELLOW}Tests interrumpidos por el usuario{RESET}")

    except Exception as e:
        print(f"\n{RED}Error inesperado: {e}{RESET}")
        import traceback
        traceback.print_exc()

    finally:
        print(f"\n{BOLD}{CYAN}{'═'*55}{RESET}")
        print(f"{BOLD}{CYAN}   RESUMEN{RESET}")
        print(f"{BOLD}{CYAN}{'═'*55}{RESET}")

        aprobados = sum(1 for _, r in resultados if r)
        totales   = len(resultados)

        for nombre, resultado in resultados:
            simbolo = f"{GREEN}✓{RESET}" if resultado else f"{RED}✗{RESET}"
            print(f"  {simbolo} {nombre}")

        color = GREEN if aprobados == totales else RED
        print(f"\n{BOLD}  Resultado: {color}{aprobados}/{totales} tests pasaron{RESET}")

        if aprobados == totales:
            print(f"{GREEN}{BOLD}  ¡Todo OK!{RESET}\n")
        else:
            print(f"{RED}{BOLD}  Hay {totales - aprobados} test(s) fallando{RESET}\n")

        net.stop()


if __name__ == '__main__':
    main()