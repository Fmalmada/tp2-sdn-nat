# Trabajo Práctico N°2 — SDN / NAT
## Redes (TA-048) — FIUBA

---

## 1. Descripción General de la Solución

Se implementó un **NAT saliente con traducción por puertos (PAT)** sobre el controlador SDN POX, extendiendo el protorouter provisto por la cátedra. El sistema permite que múltiples hosts de la red privada (`192.168.1.0/24`) se comuniquen con la red pública (`200.0.0.0/24`) compartiendo una única IP pública, manteniendo múltiples conexiones simultáneas para TCP y UDP.

La arquitectura final se descompone en cuatro módulos:

| Módulo | Archivo | Responsabilidad |
|---|---|---|
| Coordinador principal | `protorouter.py` | Orquesta los demás módulos; único listener de eventos OpenFlow |
| Manejo de ARP | `arp_handler.py` | Resolución dinámica de MACs, tabla ARP, cola de paquetes pendientes |
| Tabla NAT | `nat_table.py` | Estado de las traducciones activas; asignación de puertos públicos |
| Gestión de flujos | `flow_manager.py` | Construcción e instalación de `flow_mod` en el switch |
| Configuración | `config.py` | Parámetros centralizados (IPs, MACs, puertos, timeouts) |

### Topología

```
              Red Pública                    Red Privada
              port 1                         port 2, 3, 4
 ┌───────┐   IP:  200.0.0.254          ┌──────┐  IP: 192.168.1.254   ┌───────┐
 │  h1   ├───────────────────────────/ s1  \──────────────────────── │  h2   │
 └───────┘                           └──────┘                         └───────┘
 200.0.0.1/24                     NAT Switch                     192.168.1.2/24
 DG: 200.0.0.254                                                      ┌───────┐
 MAC: 00:00:00:00:00:01                                               │  h3   │
                                                                      └───────┘
                                                                 192.168.1.3/24
```

El switch OpenFlow actúa como dispositivo de capa 3 con dos "interfaces virtuales" manejadas por el controlador:

- **Interfaz pública:** IP `200.0.0.254`, MAC `00:00:00:aa:aa:aa`, puerto 1
- **Interfaz privada:** IP `192.168.1.254`, MAC `00:00:00:bb:bb:bb`, puertos 2-4

---

## 2. Diseño de la Tabla NAT

La tabla NAT mantiene dos índices complementarios para traducción bidireccional:

### Tabla saliente (`_nat_out`)

Clave: `(protocolo, ip_privada, puerto_privado)`  
Valor: `puerto_público`

Permite determinar, dado un paquete saliente de un host privado, qué puerto público usar.

### Tabla entrante (`_nat_in`)

Clave: `(protocolo, puerto_público)`  
Valor: `(ip_privada, puerto_privado, puerto_switch)`

Permite traducir un paquete entrante al host privado correcto, incluyendo el puerto físico del switch al que enviar.

### Ejemplo conceptual

| Protocolo | IP privada | Puerto privado | IP pública | Puerto público |
|---|---|---|---|---|
| TCP | 192.168.1.2 | 54321 | 200.0.0.254 | 10000 |
| TCP | 192.168.1.3 | 54321 | 200.0.0.254 | 10001 |
| UDP | 192.168.1.2 | 5001 | 200.0.0.254 | 10002 |
| UDP | 192.168.1.3 | 5001 | 200.0.0.254 | 10003 |

### Asignación de puertos públicos

El rango de puertos públicos disponibles se configura en `config.py`:

```python
NAT_PORT_START = 10000
NAT_PORT_END   = 65535
```

El allocator recorre el rango de forma circular (`_next_port`), saltando los puertos ya en uso (`_used_ports`). Cuando un flujo expira (evento `FlowRemoved`), el puerto se libera y queda disponible para reutilización.

---

## 3. Manejo de ARP

El módulo `arp_handler.py` implementa resolución ARP completamente dinámica, sin entradas estáticas en ningún host.

### Tabla ARP interna

```python
arp_table: { ip → (mac, puerto_switch) }
```

Se actualiza con cada paquete ARP recibido (aprendizaje pasivo desde el campo `protosrc` del ARP).

### Flujo de resolución

1. Un host privado envía un ARP Request consultando la IP del gateway (`192.168.1.254`).
2. `ARPHandler._handle_request()` detecta que es para `PRIVATE_IP` y responde con `PRIVATE_MAC`.
3. El host privado aprende la MAC del gateway y envía el paquete IP.
4. El controlador recibe el paquete IP. Si no conoce la MAC del destino público, encola el paquete en `_pending[dst_ip]` y emite un ARP Request hacia la red pública.
5. `h1` responde con su MAC. El controlador aprende la MAC, procesa todos los paquetes encolados y llama al callback `_on_mac_resolved`.
6. El callback reinyecta cada paquete pendiente en `_handle_ip`, que ahora sí puede completar la traducción e instalar los flujos.

### Cola de paquetes pendientes

```python
_pending: { ip_destino → [(in_port, raw_packet), ...] }
```

Evita perder paquetes que llegaron antes de que la MAC del destino fuera conocida. Solo se emite un ARP Request por IP desconocida (el primero); los siguientes paquetes simplemente se encolan.

---

## 4. Estrategia de Instalación de Flujos

Una vez resueltas todas las MACs y asignado el puerto público NAT, el controlador instala **dos flujos OpenFlow** en el switch por cada nueva conexión:

### Flujo saliente

Coincide con paquetes cuyo origen es la IP/puerto privados y destino es la IP/puerto públicos.  
Acciones:
- Reescribir IP origen → `PUBLIC_IP`
- Reescribir puerto origen → `pub_port` (TCP/UDP)
- Reescribir MAC origen → `PUBLIC_MAC`
- Reescribir MAC destino → MAC del servidor
- Enviar por `PUBLIC_PORT` (puerto 1 del switch)

### Flujo entrante

Coincide con paquetes cuyo destino es `PUBLIC_IP:pub_port` entrando por `PUBLIC_PORT`.  
Acciones:
- Reescribir IP destino → IP privada
- Reescribir puerto destino → puerto privado (TCP/UDP)
- Reescribir MAC origen → `PRIVATE_MAC`
- Reescribir MAC destino → MAC del host privado
- Enviar por el puerto del switch correspondiente al host privado

### Timeout y limpieza

Los flujos se instalan con `idle_timeout = 60 s` y el flag `OFPFF_SEND_FLOW_REM`. Cuando el switch expira un flujo por inactividad, notifica al controlador con un evento `FlowRemoved`, que identifica el flujo saliente por `nw_src == PUBLIC_IP` y libera la entrada NAT correspondiente.

### Primer paquete

El primer paquete de cada conexión llega al controlador vía `PacketIn` (antes de que existan flujos). Luego de instalar los flujos, el controlador lo traduce y reenvía manualmente (`_forward_outbound`). A partir del segundo paquete, el switch lo procesa directamente sin intervención del controlador.

---

## 5. Decisiones de Diseño

**Separación en módulos:** se optó por dividir la lógica en `ARPHandler`, `NATTable` y `FlowManager`, cada uno con responsabilidad única. `ProtoRouter` actúa como coordinador y es el único que recibe eventos OpenFlow. Esto facilita la prueba y el mantenimiento de cada componente de forma independiente.

**Sin hardcodeo de MACs o IPs de hosts:** toda la información de los hosts se aprende dinámicamente mediante ARP. La única información fija es la de las interfaces del propio NAT (en `config.py`), lo que permite cambiar MACs o IPs de los hosts en tiempo de ejecución sin modificar el código.

**Dirección inversa bloqueada:** los paquetes que no provienen de la red privada ni están destinados a `PUBLIC_IP` son descartados silenciosamente. Esto impide que `h1` inicie conexiones directas a hosts privados.

**Reutilización de puertos:** el allocator libera puertos al recibir `FlowRemoved`, permitiendo su reutilización. El recorrido circular del rango evita agotar puertos en escenarios de alta rotación.

---

## 6. Pruebas Realizadas

Las pruebas pueden ejecutarse de forma automatizada con `test_nat.py`, o manualmente abriendo terminales xterm para cada host desde la CLI de Mininet:

```
mininet> xterm h1 h2 h3
```

A continuación se detallan los comandos exactos para cada prueba manual.

---

### 6.1 TCP básico (HTTP con curl)

Verifica traducción TCP completa y respuesta HTTP 200.

**xterm h1** — levantar servidor:
```bash
python3 -m http.server 8080
```

**xterm h2** — hacer request:
```bash
curl -v http://200.0.0.1:8080/
```

**xterm h3** — hacer request (puerto diferente para evitar colisión de flujos activos):
```bash
# En xterm h1, levantar otro servidor en otro puerto:
python3 -m http.server 8081

# En xterm h3:
curl -v http://200.0.0.1:8081/
```

**Resultado esperado:** `curl` reporta `HTTP/1.0 200 OK` y muestra el listado de directorio.

---

### 6.2 TCP simultáneo

Verifica múltiples conexiones TCP activas al mismo tiempo. Se usa `iperf` en modo TCP con duración larga para garantizar solapamiento real.

**xterm h1** — levantar servidor iperf TCP:
```bash
iperf -s -p 5010
```

**xterm h2** (lanzar en background):
```bash
iperf -c 200.0.0.1 -p 5010 -t 15 > /tmp/tcp_h2.txt &
```

**xterm h3** (lanzar inmediatamente después):
```bash
iperf -c 200.0.0.1 -p 5010 -t 15 > /tmp/tcp_h3.txt &
```

Mientras corren, verificar desde la **CLI de Mininet** que hay dos flujos TCP activos al mismo tiempo:
```bash
ovs-ofctl dump-flows s1
```

Deben aparecer entradas con `nw_src=192.168.1.2` y `nw_src=192.168.1.3` simultáneamente. Luego de ~20 segundos verificar:

**xterm h2:**
```bash
cat /tmp/tcp_h2.txt
```

**xterm h3:**
```bash
cat /tmp/tcp_h3.txt
```

**Resultado esperado:** ambos archivos muestran transferencia con `Mbits/sec`.

---

### 6.3 UDP básico (iperf)

Verifica traducción UDP y flujo de retorno (estadísticas iperf).

**xterm h1** — levantar servidor UDP:
```bash
iperf -s -u -p 5001
```

**xterm h2:**
```bash
iperf -c 200.0.0.1 -u -p 5001 -t 4
```

Luego repetir con h3 en puerto diferente:

**xterm h1** — segundo servidor:
```bash
iperf -s -u -p 5002
```

**xterm h3:**
```bash
iperf -c 200.0.0.1 -u -p 5002 -t 4
```

**Resultado esperado:** iperf reporta transferencia con `bits/sec` en ambos casos.

---

### 6.4 UDP simultáneo

Verifica múltiples flujos UDP activos al mismo tiempo. Se aumenta la duración para garantizar solapamiento real.

**xterm h1** — levantar servidor iperf UDP:
```bash
iperf -s -u -p 5003
```

**xterm h2** (lanzar en background):
```bash
iperf -c 200.0.0.1 -u -p 5003 -t 15 > /tmp/udp_h2.txt &
```

**xterm h3** (lanzar inmediatamente después):
```bash
iperf -c 200.0.0.1 -u -p 5003 -t 15 > /tmp/udp_h3.txt &
```

Mientras corren, verificar desde la **CLI de Mininet** que hay dos flujos UDP activos al mismo tiempo:
```bash
ovs-ofctl dump-flows s1
```

Deben aparecer entradas con `nw_src=192.168.1.2` y `nw_src=192.168.1.3` simultáneamente. Luego de ~20 segundos verificar:

**xterm h2:**
```bash
cat /tmp/udp_h2.txt
```

**xterm h3:**
```bash
cat /tmp/udp_h3.txt
```

**Resultado esperado:** ambos archivos muestran estadísticas de transferencia con `bits/sec`.

---

### 6.5 NAT no hardcodeado (cambio de MAC en caliente)

Verifica que el controlador aprende MACs dinámicamente y no depende de valores fijos.

> **Nota:** al bajar y subir la interfaz, Mininet pierde la ruta default (`via 192.168.1.254`) pero no la restaura automáticamente. Es necesario agregarla a mano después de subir la interfaz. Esto no es un bug del NAT sino un comportamiento de Mininet.

**xterm h1** — levantar servidor primero:
```bash
python3 -m http.server 8083
```

**xterm h2** — cambiar MAC, restaurar ruta y verificar:
```bash
# Bajar interfaz, cambiar MAC, subir
ip link set h2-eth0 down
ip link set h2-eth0 address 00:00:00:00:ff:ff
ip link set h2-eth0 up

# Restaurar ruta default (se pierde al bajar la interfaz en Mininet)
ip route add default via 192.168.1.254

# Verificar MAC y ruta
ip link show h2-eth0
ip route show

# Limpiar ARP cache
ip neigh flush all

# Probar conectividad
curl -v http://200.0.0.1:8083/
```

**Resultado esperado:** `ip route show` muestra `default via 192.168.1.254`. El `curl` retorna `HTTP/1.0 200 OK` — el controlador aprendió la nueva MAC `00:00:00:00:ff:ff` vía ARP sin ninguna configuración adicional. Al terminar, restaurar:

**xterm h2:**
```bash
ip link set h2-eth0 down
ip link set h2-eth0 address 00:00:00:00:00:02
ip link set h2-eth0 up
ip route add default via 192.168.1.254
```

---

### 6.6 Dirección inversa bloqueada (h1 → h2)

Verifica que el NAT **no** permite conexiones iniciadas desde la red pública.

**xterm h2** — levantar servidor:
```bash
python3 -m http.server 9090
```

**xterm h1** — intentar conectarse directamente a h2:
```bash
curl -v --max-time 5 http://192.168.1.2:9090/
```

**Resultado esperado:** `curl` agota el timeout sin respuesta (`Connection timed out` o `Network is unreachable`). **No** debe retornar HTTP 200.

---

### 6.7 Flujos instalados en el switch

Verifica que el switch tiene reglas OpenFlow instaladas y maneja el tráfico sin intervención constante del controlador.

Primero generar tráfico TCP para que se instalen los flujos:

**xterm h1:**
```bash
python3 -m http.server 8084
```

**xterm h2:**
```bash
curl -s http://200.0.0.1:8084/
```

Luego, desde la **CLI de Mininet** (o un xterm del host con acceso a ovs-ofctl):

```bash
ovs-ofctl dump-flows s1
```

**Resultado esperado:** la salida incluye entradas con `nw_src=192.168.1.2` (flujo saliente) y `nw_dst=192.168.1.2` (flujo entrante), con contadores de paquetes mayores a 0:

```
cookie=0x0, ... nw_src=192.168.1.2,nw_dst=200.0.0.1,nw_proto=6 actions=mod_nw_src:200.0.0.254,...
cookie=0x0, ... nw_dst=200.0.0.254,nw_proto=6,tp_dst=10000    actions=mod_nw_dst:192.168.1.2,...
```

También es posible capturar tráfico en tiempo real con tcpdump para verificar la traducción:

**xterm h1** — capturar en interfaz pública:
```bash
tcpdump -i h1-eth0 -n
```

Los paquetes deben mostrar IP origen `200.0.0.254` (nunca `192.168.1.x`), confirmando que el NAT está operando correctamente.

---

## 7. Problemas Encontrados y Soluciones

**ARP antes de IP:** el primer paquete IP de un host privado llega cuando el controlador aún no conoce la MAC del servidor público. Se implementó la cola `_pending` y el callback `_on_mac_resolved` para reinyectar los paquetes una vez resuelta la MAC, sin perderlos.

**Limpieza de entradas NAT:** si los flujos expiran de forma asimétrica (por ejemplo, solo el flujo saliente genera `FlowRemoved`), puede quedar una entrada huérfana en `_nat_in`. Se mitigó usando el mismo `idle_timeout` para ambos flujos de una misma conexión, de modo que expiren aproximadamente al mismo tiempo.

**IPv6:** la topología deshabilita IPv6 explícitamente en todos los hosts y el switch (`sysctl`), evitando que el controlador reciba tráfico IPv6 inesperado que podría confundirse con paquetes IP sin procesar.

---

## 8. Conclusión

Se implementó exitosamente un NAT por puertos (PAT) sobre SDN con POX y Mininet. La solución soporta múltiples hosts privados, protocolos TCP y UDP simultáneos, resolución ARP dinámica y limpieza automática de estado al expirar los flujos. El diseño modular facilita la extensión futura (por ejemplo, timeout diferenciado por protocolo).

El paradigma SDN permite implementar lógica de red compleja (como NAT/PAT) en software puro, sin modificar el hardware de forwarding, y minimizando la intervención del controlador una vez instalados los flujos en el switch.
