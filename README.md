### Cómo correr

#### 1. En la primera terminal (parado en `tp2-sdn-nat/pox/`)
```bash
python3 pox.py log.level --DEBUG protorouter
```

#### 2. En la segunda terminal (parado en `tp_sdn_nat/`)
```bash
sudo python3 topo.py
```


### 🧪 Pruebas de **Etapa 1 (ARP Dinámico)**, dentro de la CLI de Mininet (Terminal 2)

Ejecuta las siguientes instrucciones dentro de la terminal de Mininet para comprobar el comportamiento dinámico:

Ejecuta las siguientes instrucciones dentro de la terminal de Mininet para comprobar el comportamiento dinámico:

#### 1. Verificar que las tablas ARP estén vacías

Al borrar las líneas estáticas, los hosts no deberían conocer a nadie en la capa 2.

```bash
h2 arp -n
```

```bash
h1 arp -n
```

*Deberías ver que no hay entradas registradas para las IPs `192.168.1.254` ni `200.0.0.254`.*

#### 2. Lanzar el Ping de prueba

Manda **3 paquetes** desde el host privado hacia el externo. El primer paquete tardará un poco más (mientras se resuelve el ARP), y los siguientes irán rápido.

```bash
h2 ping -c 3 200.0.0.1
```

#### 3. Verificar que aprendieron las MACs autónomamente

Vuelve a revisar las tablas ARP de los hosts. Ahora el protocolo dinámico tuvo que haber hecho su trabajo.

```bash
h2 arp -n
```

*Debería aparecer: `192.168.1.254` asociado a `00:00:00:bb:bb:bb`.*

```bash
h1 arp -n
```

*Debería aparecer: `200.0.0.254` asociado a `00:00:00:aa:aa:aa`.*

---

### 🔍 Qué debes mirar en los logs de POX (Terminal 1)

Hay exactamente **3 pares** de ARP Request/Reply para que la comunicación se establezca por primera vez.

el flujo ultra conciso:

### Lado Privado

1. **Primer Par (`h2` ↔ Switch)**
* **REQ:** `h2` pregunta: *¿Quién tiene la IP privada del gateway (`192.168.1.254`)?*
* **REP:** El switch (POX) responde: *Yo la tengo, mi MAC privada es `00:00:00:bb:bb:bb`.*
* *Resultado:* `h2` ya puede enviar el paquete ICMP al switch.



### Lado Público

2. **Segundo Par (Switch ↔ `h1`)**
* **REQ:** El switch (POX) pregunta al mundo exterior: *¿Quién tiene la IP de `h1` (`200.0.0.1`)?*
* **REP:** `h1` responde: *Yo la tengo, mi MAC es `00:00:00:00:00:01`.*
* *Resultado:* El switch descongela el ICMP, instala las reglas OpenFlow y le envía el ping a `h1`.


3. **Tercer Par (`h1` ↔ Switch)**
* **REQ:** `h1` (al intentar responder el ping) pregunta: *¿Quién tiene la IP pública del gateway (`200.0.0.254`)?*
* **REP:** El switch (POX) responde: *Yo la tengo, mi MAC pública es `00:00:00:aa:aa:aa`.*
* *Resultado:* `h1` ya puede enviar el ICMP Reply de vuelta.



---

A partir de que terminan estos 3 intercambios, **las tablas ARP de todos están llenas y las reglas OpenFlow están instaladas**. Ya no se transmite ningún ARP más.

---
¿Cómo lograr que sea una sola?
Si quisieras obligar a h1 a aprender la MAC del switch desde el primer Request y ahorrarte ese tercer paquete, podrías entrar a la consola de Mininet y cambiar la configuración del kernel de h1 en caliente ejecutando:
```bash
h1 sysctl -w net.ipv4.conf.all.arp_accept=1
```

### 🧪 Pruebas de **Etapa 2 (NAT sin PAT)**, dentro de la CLI de Mininet (Terminal 2)

1. En la consola de Mininet, abre las terminales (shift+insert para pegar):
```bash
xterm h1 h2
```


2. Te aparecerán dos ventanas independientes de fondo negro (una para `h1` y otra para `h2`).
3. En la ventana de **`h1`** (el host público), pon a escuchar el tráfico de red:
```bash
tcpdump -i h1-eth0 -n icmp
```


4. En la ventana de **`h2`** (el host privado), lanza el ping:
```bash
ping -c 2 200.0.0.1
```

### 🧪 Pruebas de **Etapa 3 (PAT)**, dentro de la CLI de Mininet (Terminal 2)

Deberías ver algo así en la terminal del controlador:

```text
200.0.0.254 > 200.0.0.1: ICMP echo request, id 1234, seq 1 ...
200.0.0.1 > 200.0.0.254: ICMP echo reply, id 1234, seq 1 ...
```


### 📝 Los 3 comandos en orden (para el machete)

Para cuando tengas que defender el TP o repetir la prueba, este es el orden exacto de los factores:

#### 1. En la ventana de `h1` (Servidor) - Dejarlo escuchando:

```bash
nc -lnvp 8080 -n

```

*(Levanta el puerto TCP 8080 en modo pasivo/escucha sin resolver DNS).*

#### 2. En la otra ventana de `h1` (o desde Mininet) - Capturar el tráfico:

```bash
tcpdump -i h1-eth0 -n tcp

```

*(Muestra en tiempo real los paquetes TCP que entran y salen de h1, confirmando la IP pública y el puerto 10000).*

#### 3. En la ventana de `h2` (Cliente) - Conectarse al servidor:

```bash
nc 200.0.0.1 8080

```
---


# Comandos Rápidos - Etapa 4

## Prueba A: Inactividad UDP (Timeout de 30s)
1. **h1 (Servidor):** `nc -lnup 9000 -n`
2. **h2 (Cliente):** `nc -u 200.0.0.1 9000`
3. **Acción:** Enviar mensaje, dar `Enter` y cerrar `h2` con `Ctrl + C`. 
4. **Verificación:** Esperar 30 segundos a que POX muestre el log rojo `[GC]` de liberación.

---

## Prueba B: Cierre Rápido TCP (Flags / Máx 120s)
1. **h1 (Servidor):** `nc -lnvp 8080 -n`
2. **h2 (Cliente):** `nc 200.0.0.1 8080`
3. **Acción:** Cerrar inmediatamente `h2` con `Ctrl + C`.
4. **Verificación:** Revisar la consola de POX; en 120 segundos aparecerá el log rojo `[GC]` liberando el puerto.

**Salir de Mininet**
```bash
exit
```