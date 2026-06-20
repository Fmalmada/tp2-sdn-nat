# Guía de demo — TP2 NAT (martes)

## Antes de la demo

```bash
sudo apt install mininet openvswitch-switch iperf wireshark
sudo systemctl start openvswitch-switch
```

Necesitás **X11** (escritorio) para `xterm` y Wireshark.

---

## 1. Arranque (2 terminales)

**Terminal A — POX** (desde la raíz del repo):

```bash
cd tp2-sdn-nat
./tp_sdn_nat/run_pox.sh log.level --DEBUG protorouter
```

Esperar: `Listening on 0.0.0.0:6633`

**Terminal B — Mininet:**

```bash
cd tp2-sdn-nat
sudo python3 tp_sdn_nat/topo.py
```

Esperar: `mininet>`

En Terminal A debería aparecer: `connected` y `ProtoRouter (NAT/PAT) iniciado`.

**Terminal C (opcional)** — para ver flujos durante la demo:

```bash
sudo ovs-ofctl dump-flows s1
```

---

## 2. Abrir ventanas de hosts

```bash
mininet> xterm h1 h2 h3
```

En cada xterm podés agrandar la fuente: `Ctrl + botón derecho` → font size.

---

## 3. Prueba rápida de que todo anda (ping)

```bash
mininet> h2 ping -c 3 h1
```

- El **primer** ping puede perder 1 paquete (ARP + primera entrada NAT). Es normal.
- Repetir: `h2 ping -c 3 h1` → debería dar **0% packet loss**.

---

## 4. Demo TCP con iperf + Wireshark (1 cliente)

En la CLI de Mininet:

```bash
mininet> h1 wireshark >/dev/null 2>&1 &
mininet> h2 wireshark >/dev/null 2>&1 &
```

**xterm h1** (servidor):

```bash
iperf -s
```

**xterm h2** (cliente):

```bash
iperf -c 200.0.0.1
```

### Qué verificar

| Dónde | Qué |
|-------|-----|
| Salida iperf en h1 | Conexión desde **200.0.0.254** (IP pública del NAT), no desde 192.168.1.2 |
| Wireshark h2 | ARP hacia 192.168.1.254; IP origen privada saliendo |
| Wireshark h1 | IP origen **200.0.0.254**, puerto traducido (ej. 10000) |
| Terminal C | `sudo ovs-ofctl dump-flows s1` → reglas con `nw_src=192.168.1.2`, `set_field=200.0.0.254` |

En Terminal A (POX): `Nueva NAT: 192.168.1.2:XXXX -> 200.0.0.254:10000`

---

## 5. Demo UDP

**xterm h1:**

```bash
iperf -s -u
```

**xterm h2:**

```bash
iperf -c 200.0.0.1 -u
```

Mismas verificaciones que TCP.

---

## 6. Múltiples clientes simultáneos

**xterm h1:**

```bash
iperf -s
```

**xterm h2** y **xterm h3** (al mismo tiempo, en ventanas separadas):

```bash
iperf -c 200.0.0.1
```

Verificar en POX dos líneas `Nueva NAT` con puertos distintos (10000, 10001, …).

Repetir con UDP (`-u` en servidor y cliente).

---

## 7. Cambio de IP/MAC (si lo piden los docentes)

Editar **`topo.py`** (hosts) y las constantes al inicio de **`protorouter.py`** (IPs/MACs del NAT y subred).

Ejemplo — cambiar MAC de h2 en `topo.py`:

```python
mac='00:00:00:00:00:99',
```

Reiniciar POX (`run_pox.sh`) y Mininet. Probar `h2 ping -c 3 h1`.

---

## 8. Qué explicar si preguntan

| Tema | Respuesta corta |
|------|-----------------|
| ARP | Tabla dinámica; el NAT responde ARP por sus IPs; envía ARP request si no conoce la MAC de h1 |
| Tabla NAT | `nat_out`: (proto, IP priv, puerto priv) → puerto público; `nat_in`: (proto, puerto público) → host privado |
| Puertos públicos | Desde 10000; pool `free_ports` al expirar flujo |
| Flujos OpenFlow | Se instalan al primer paquete; `idle_timeout=60`; el switch reenvía sin pasar por POX |
| MAC desconocida | Paquete en cola `pending`; al llegar ARP reply se reenvía |
| Expiración | `FlowRemoved` libera entrada NAT y devuelve el puerto |

---

## 9. Errores comunes

| Lo que ves | Significado |
|------------|-------------|
| `Unable to contact ... 6653` | Ya corregido en topo.py (usa 6633) |
| `connection aborted` / `closed` en POX | Normal al cerrar Mininet (`exit`) |
| Ping pierde 1er paquete | ARP + setup inicial; repetir ping |
| `ping ... &` con 100% loss | No usar ping en background en la demo; usar iperf en xterms |
| Warning Python 3.12 | Advertencia de POX; si conecta, ignorar |
