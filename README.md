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