### Cómo correr

#### 1. En la primera terminal (parado en `tp2-sdn-nat/pox/`)
```bash
python3 pox.py log.level --DEBUG protorouter
```

#### 2. En la segunda terminal (parado en `tp_sdn_nat/`)
```bash
sudo python3 topo.py
```

---

1. Validación de ARP y Conectividad (Criterio 1) 

Ejecuta directamente en la consola de Mininet:

Al borrar las líneas estáticas, los hosts no deberían conocer a nadie en la capa 2.

```bash
h2 arp -n
```

```bash
h1 arp -n
```

```bash
h2 ping -c 2 200.0.0.1
```

* 
**Resultado esperado:** El ping debe responder exitosamente. Esto confirma que el router intercepta el ARP, responde con sus MACs y habilita el flujo de paquetes básico.



---

2. Validación de PAT, Tráfico Bidireccional y Multihost (Criterios 2, 3 y 5) 

Abre las terminales necesarias con `xterm h1 h1 h2 h3` y corre lo siguiente:

* 
**En h1 (Ventana 1 - Inspector):** Corre el sniffer para verificar el enmascaramiento:


```bash
tcpdump -i h1-eth0 -n tcp
```


* 
**En h1 (Ventana 2 - Servidor):** Levanta el puerto de escucha:


```bash
nc -lnvp 8080 -n
```


* 
**En h2 (Cliente 1):** Conéctate y escribe un mensaje:


```bash
nc 200.0.0.1 8080
```


* 
**En h3 (Cliente 2):** Abre una segunda conexión simultánea (cancela un segundo el `nc` de h1 y vuelve a ejecutar `nc -lnvp 8080 -n` para recibir a h3):


```bash
nc 200.0.0.1 8080
```


* 
**Resultados esperados:** 1.  Los mensajes llegan de ida y vuelta de forma aislada (Criterio 3).
2.  En el `tcpdump` de `h1` verás que ambos hosts (`h2` y `h3`) le hablan mostrando **únicamente la IP pública `200.0.0.254**` pero usando puertos públicos distintos (ej. `10000` y `10001`) (Criterios 2 y 5).



---

3. Validación de Limpieza y Fin de Conexión (Criterio 4) 

* 
**Acción:** Presiona `Ctrl + C` en la terminal de `h2` o `h3` para matar el cliente TCP.


* **Resultado esperado:** Mira de inmediato la terminal donde se está ejecutando POX. En menos de 5 segundos verás el log rojo del Garbage Collector: `[GC] Conexión ... liberada`. Esto demuestra que el router no acumula reglas muertas en memoria.

**Salir de Mininet**
```bash
exit
```
Aquí tienes la guía detallada paso a paso con todos los comandos estructurados para realizar la auditoría avanzada de tu router utilizando **Wireshark**, **iperf**, y **OpenFlow (`ovs-ofctl`)**.

---

# 🧪 Batería de Pruebas Avanzadas: Validación Estructural del TP2

## PARTE 1: Prueba con Servidor y un Cliente

### Paso 1: Iniciar Interfaces Gráficas de Wireshark

En la consola de Mininet, lanza las instancias independientes para el entorno público y privado en segundo plano:

```bash
h2 wireshark >/dev/null 2>&1 &
```

```bash
h1 wireshark >/dev/null 2>&1 &
```

*En las ventanas de Wireshark que se abran, selecciona la interfaz `h2-eth0` (en el Wireshark de h2) y `h1-eth0` (en el Wireshark de h1). Haz doble clic para iniciar la captura en vivo.*

### Paso 2: Preparar Servidor e Interfaces Interactivos

En la consola de Mininet, abre las terminales interactivas:

```bash
xterm h1 h2
```

* **En la xterm de h1 (Servidor Público):** Corre el demonio de iperf en modo pasivo TCP:
```bash
iperf -s
```



### Paso 3: Ejecutar la Carga de Tráfico (Cliente TCP)

* **En la xterm de h2 (Cliente Privado):** Inicia la prueba de rendimiento apuntando a la IP de `h1`:
```bash
iperf -c 200.0.0.1
```



---

### Paso 4: Validaciones y Verificaciones Críticas (TCP)

#### A. Verificación en las salidas de `iperf`:

* **En h1 (Servidor):** Observarás que la conexión aceptada no proviene de `192.168.1.2`, sino que dice algo como `connected with 200.0.0.254 port XXXXX`. Esto demuestra que el enmascaramiento IP funciona.
* **En h2 (Cliente):** Verás el puerto efímero local de origen asignado por Linux (ej. `43210`) hacia el puerto destino `5001` (defecto de iperf).

#### B. Análisis de Paquetes en Wireshark:

* **Fase ARP:** Detén las capturas y filtra por `arp`. Verás el intercambio inicial: `h2` preguntando quién es `192.168.1.254` (el router responde con su MAC privada) y el router preguntando en la red pública quién es `200.0.0.1` para poder entregarle el paquete a `h1`.
* **Fase de Datos (Filtro `tcp`):** * En **h2-eth0**, el paquete conserva: `Src IP: 192.168.1.2`, `Dst IP: 200.0.0.1`, `Src Port: 43210`.
* En **h1-eth0**, el paquete mutó a: `Src IP: 200.0.0.254`, `Dst IP: 200.0.0.1`, `Src Port: 10000` (el puerto PAT asignado por tu código).



#### C. Auditoría de Flujos en el Switch (OpenFlow):

Abre una **terminal nativa de Linux** (fuera de Mininet/POX) y ejecuta:

```bash
sudo ovs-ofctl dump-flows s1
```

**Interpretación de los Campos Principales de los Flujos Instalados:**
Verás dos reglas instaladas dinámicamente por `protorouter.py` que se interpretan de la siguiente manera:

1. **Flujo Saliente (Outbound):**
* `in_port=2`: Todo paquete que entre por el puerto físico 2 (donde está conectado `h2`).
* `dl_type=0x800`: Debe ser obligatoriamente tráfico IPv4.
* `nw_proto=6`: Protocolo de transporte TCP.
* `nw_src=192.168.1.2, nw_dst=200.0.0.1`: Match exacto de las direcciones IP.
* `tp_src=43210, tp_dst=5001`: Match de los puertos de capa de transporte.
* `actions=mod_nw_src:200.0.0.254, mod_tp_src:10000, mod_dl_src:00:00:00:aa:aa:aa, mod_dl_dst:00:00:00:00:00:01, output:1`: **Esta es la magia del PAT**. Reescribe la IP origen por la pública, cambia el puerto de origen por el `10000`, actualiza las direcciones MAC de la capa de enlace y eyecta el paquete por el puerto físico 1 (red pública).


2. **Flujo Entrante / Reverso (Inbound):**
* `in_port=1`: Todo paquete de respuesta que regrese desde el mundo exterior por el puerto físico 1.
* `nw_src=200.0.0.1, nw_dst=200.0.0.254`: Viene del servidor hacia la IP pública del router.
* `tp_src=5001, tp_dst=10000`: Viene del puerto de iperf hacia el puerto PAT asignado (`10000`).
* `actions=mod_nw_dst:192.168.1.2, mod_tp_dst:43210, mod_dl_src:00:00:00:bb:bb:bb, mod_dl_dst:00:00:00:00:00:02, output:2`: Traduce a la inversa la IP y el puerto para recuperar la identidad de `h2`, reescribe las MACs internas y lo envía de vuelta por el puerto 2 a la red privada.



---

### Paso 5: Repetir la Validación con UDP

1. En la xterm de **h1**, cancela el iperf anterior (`Ctrl+C`) y levántalo en modo UDP:
```bash
iperf -s -u
```


2. En la xterm de **h2**, ejecuta el cliente UDP especificando un ancho de banda (ej: 10 Megabits):
```bash
iperf -c 200.0.0.1 -u -b 10M
```


3. **Verificación:** Repite el `sudo ovs-ofctl dump-flows s1`. Verás que las reglas ahora se instalan con el campo `nw_proto=17` (UDP) y que al cabo de **30 segundos** de terminar la prueba, el Garbage Collector las remueve de los diccionarios por el timeout de inactividad de UDP.

---

## PARTE 2: Prueba con Múltiples Clientes Simultáneos

Esta prueba confirmará que tu PAT es capaz de multiplexar y gestionar sesiones concurrentes sin colisiones de datos.

### Paso 1: Levantar Escenarios Concurrentes

En la consola de Mininet, abre las terminales de todos los actores privados y el servidor:

```bash
xterm h1 h2 h3
```

1. **En h1 (Servidor):** Deja corriendo el iperf base en modo TCP:
```bash
iperf -s
```


2. **En h2 (Cliente Privado 1):** Ejecuta de forma simultánea:
```bash
iperf -c 200.0.0.1 -t 15
```


3. **En h3 (Cliente Privado 2):** Inmediatamente (en paralelo antes de que pasen los 15 segundos), ejecuta en su ventana:
```bash
iperf -c 200.0.0.1 -t 15
```



*(Nota: Si deseas probar UDP en paralelo, detén el iperf de h1, levántalo con `iperf -s -u` y corre en h2 y h3 el comando `iperf -c 200.0.0.1 -u -b 5M -t 15`).*

### Paso 2: Verificación de Aislamiento

Revisa la pantalla del servidor `h1`. Notarás que registra **dos conexiones activas al mismo tiempo**:

* Una conexión desde `200.0.0.254` usando el puerto público `10001`.
* Otra conexión en paralelo desde `200.0.0.254` usando el puerto público `10002`.
Ambas sesiones transmiten datos en ráfagas concurrentes sin corromperse ni mezclarse.

---

### ¿Cómo la implementación distingue y mantiene el estado de múltiples conexiones concurrentes?

El secreto de que esto funcione sin conflictos radica en la arquitectura de estructuras de datos que implementamos en `protorouter.py`:

```python
key_out = (ip_pkt.protocol, ip_pkt.srcip, priv_port)

```

1. **Unicidad por Tupla Expresa:** Aunque por azares del sistema operativo tanto `h2` (`192.168.1.2`) como `h3` (`192.168.1.3`) intentaran salir hacia el exterior usando exactamente el **mismo puerto de origen local** (por ejemplo, el puerto `5001`), el router los diferencia de inmediato. Las claves generadas en el diccionario `self.nat_out` serían:
* Para h2: `(6, IPAddr("192.168.1.2"), 5001)`
* Para h3: `(6, IPAddr("192.168.1.3"), 5001)`
Como las IPs origen son distintas, mapean a dos entradas de diccionario totalmente independientes.


2. **Asignación Monotónica de Puertos Públicos:** Al procesar cada clave única, el contador global `self.next_port` le entrega un identificador secuencial exclusivo a cada flujo (a h2 le da el puerto público `10001` y a h3 el `10002`).
3. **Mapeo Inverso Unívoco:** En la tabla de entrada (`self.nat_in`), la clave es únicamente `(protocolo, puerto_publico)`. Cuando el servidor `h1` responde enviando paquetes a los puertos `10001` y `10002`, el router busca estas claves individuales y sabe con precisión matemática que el tráfico del puerto `10001` pertenece a la IP privada de `h2` y el del `10002` a la de `h3`, logrando una conmutación de paquetes simultánea, transparente y escalable.