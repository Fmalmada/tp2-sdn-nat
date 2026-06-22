### Cómo correr

#### 1. En la primera terminal (parado en `tp2-sdn-nat/pox/`)
```bash
python3 pox.py log.level --DEBUG protorouter
```

#### 2. En la segunda terminal (parado en `tp_sdn_nat/`)
```bash
sudo python3 topo.py
```

Para probar la **Etapa 1 (ARP Dinámico)**, ejecutar cómo siempre en 2 terminales separadas. 


### 🧪 Pruebas dentro de la CLI de Mininet (Terminal 2)

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

A continuación se detalla el flujo cronológico exacto de los eventos capturados en el controlador POX durante la resolución ARP dinámica, incluyendo la descripción del comportamiento del **switch**:

* **`INFO:protorouter:ARP aprendido: 192.168.1.2 → 00:00:00:00:00:02 (port 2)`**
> **Descripción:** El switch intercepta un paquete proveniente de `h2`. El controlador aprende de forma dinámica la dirección MAC del host privado y el puerto físico al que está conectado, guardándolo en la estructura `arp_table`.


* **`INFO:protorouter:ARP REQUEST para IP privada (192.168.1.254), respondiendo con 00:00:00:bb:bb:bb`**
> **Descripción:** `h2` envía una solicitud preguntando por la MAC de su gateway. El controlador identifica que la consulta corresponde a la IP asignada a la interfaz privada del switch y genera un *ARP Reply* con la dirección `PRIVATE_MAC`.


* **`INFO:protorouter:RECIBIDO: 192.168.1.2 → 200.0.0.1 | MAC: 00:00:00:00:00:02 → 00:00:00:bb:bb:bb | In Port: 2`**
> **Descripción:** Una vez resuelta la capa 2, `h2` transmite formalmente el primer paquete de datos IPv4 (Ping ICMP) hacia la IP pública externa `200.0.0.1`, ingresando al switch por el puerto 2.


* **`INFO:protorouter:MATCH: 192.168.1.2 pertenece a la red privada 192.168.1.0/24`**
> **Descripción:** El controlador procesa el encabezado de red y valida que la dirección IP de origen se encuentra dentro del rango de la subred privada permitida.


* **`INFO:protorouter:MAC desconocida para 200.0.0.1. Guardando paquete en cola de espera.`**
> **Descripción:** Como la simulación ya no cuenta con datos cableados estáticos, el controlador detecta que la MAC del destino (`h1`) no existe en su caché. El paquete IP actual se congela dentro del diccionario `pending`.


* **`INFO:protorouter:ARP REQUEST enviado: ¿quién tiene 200.0.0.1? (desde 200.0.0.254)`**
> **Descripción:** El controlador fabrica un paquete *ARP Request* tipo broadcast utilizando la IP pública del switch como origen, y lo despacha al exterior para descubrir la dirección física de `200.0.0.1`.


* **`INFO:protorouter:ARP aprendido: 200.0.0.1 → 00:00:00:00:00:01 (port 1)`**
> **Descripción:** Al recibir el broadcast, el host externo `h1` responde. El switch intercepta esa trama y el controlador registra inmediatamente la MAC de `h1` vinculada al puerto público (puerto 1).


* **`INFO:protorouter:ARP REPLY recibido: 200.0.0.1 tiene 00:00:00:00:00:01`**
> **Descripción:** Confirmación formal de la recepción del paquete de respuesta ARP enviado por el host de la red externa.


* **`INFO:protorouter:Procesando 1 paquete(s) pendiente(s) para 200.0.0.1`**
> **Descripción:** Al completarse la resolución de la dirección física, se activa el mecanismo de vaciado (`flush`) para recuperar el paquete IP de `h2` que había quedado retenido en la cola de espera.


* **`INFO:protorouter:RECIBIDO: 192.168.1.2 → 200.0.0.1 | MAC: 00:00:00:00:00:02 → 00:00:00:bb:bb:bb | In Port: 2`**
> **Descripción:** El paquete IP recuperado vuelve a ingresar al flujo de procesamiento estándar de ruteo dentro del controlador.


* **`INFO:protorouter:MATCH: 192.168.1.2 pertenece a la red privada 192.168.1.0/24`**
> **Descripción:** Segunda validación de seguridad de la subred para el paquete liberado de la cola.


* **`INFO:protorouter:ENVIANDO: 192.168.1.2 → 200.0.0.1 | MAC: 00:00:00:aa:aa:aa → 00:00:00:00:00:01 | Out Port: 1`**
> **Descripción:** El controlador ordena al switch modificar las direcciones de Capa 2 (reescribe la MAC de origen con la MAC pública del switch y la de destino con la MAC dinámica aprendida de `h1`), despacha el paquete por el puerto 1 e inyecta las correspondientes reglas OpenFlow de flujo en el switch.


* **`INFO:protorouter:ARP aprendido: 200.0.0.1 → 00:00:00:00:00:01 (port 1)`**
> **Descripción:** Log de respaldo que ratifica el puerto y la ubicación física del extremo público en el mapa de memoria del switch.


* **`INFO:protorouter:ARP REQUEST para IP pública (200.0.0.254), respondiendo con 00:00:00:aa:aa:aa`**
> **Descripción:** Al intentar contestar el ping, `h1` genera su propia solicitud ARP dirigida a la IP pública del gateway. El controlador la procesa y le ordena al switch responder con su identidad física pública, cerrando exitosamente el ciclo de comunicación bidireccional.


**Salir de Mininet**
```bash
exit
```