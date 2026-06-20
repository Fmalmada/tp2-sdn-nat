# TA-048 Redes - Trabajo Práctico 2: SDN / NAT

## ¿Qué es la carpeta `pox/`?

Es el **controlador SDN POX** (dependencia externa, clonada del repo oficial).  
**No hay que modificar su código interno** (`pox/pox/`).

El enunciado pide ubicar **nuestro** controlador en `pox/ext/protorouter.py` para ejecutarlo.  
Ese directorio (`pox/ext/`) es donde POX carga aplicaciones propias; no es la librería.

**Todo el trabajo del TP está en `tp_sdn_nat/`**. Antes de correr POX se copia el controlador ahí.

## Requisitos

- Python 3
- Mininet
- POX (carpeta `pox/` del repo)

## Ejecución

**Terminal 1 — Controlador POX** (desde la raíz del repo):

```bash
./tp_sdn_nat/run_pox.sh log.level --DEBUG protorouter
```

O manualmente:

```bash
cp tp_sdn_nat/protorouter.py pox/ext/protorouter.py
python3 pox/pox.py log.level --DEBUG protorouter
```

**Terminal 2 — Topología Mininet:**

```bash
sudo python3 tp_sdn_nat/topo.py
```

**Orden:** primero POX, luego Mininet.

En POX deberías ver `Listening on 0.0.0.0:6633` y, al arrancar Mininet, `connected` + `ProtoRouter (NAT/PAT) iniciado`.

### Requisitos del sistema

```bash
sudo apt install mininet openvswitch-switch
sudo systemctl start openvswitch-switch
sudo ovs-vsctl show   # debe responder sin error
```

## Pruebas en Mininet

Con ambas terminales corriendo y el prompt `mininet>`:

```bash
# 1. Conectividad básica (ICMP / ping)
mininet> h2 ping -c 3 h1
mininet> h3 ping -c 3 h1

# 2. Dos clientes a la vez
mininet> h2 ping -c 5 h1 &
mininet> h3 ping -c 5 h1 &

# 3. TCP (servidor en h1)
mininet> h1 python3 -m http.server 8080 &
mininet> h2 curl -s --connect-timeout 5 http://200.0.0.1:8080/ | head

# 4. UDP
mininet> h1 nc -u -l 9999 &
mininet> h2 bash -c 'echo hola | nc -u -w1 200.0.0.1 9999'

# 5. Salir
mininet> exit
```

Guía paso a paso para la **demo del martes**: [`DEMO.md`](DEMO.md)

## Verificación básica

```bash
mininet> h2 ping -c 3 h1
mininet> h3 ping -c 3 h1
```

## Cambiar IP/MAC (demo)

- **Hosts (h1, h2, h3):** editar `topo.py`. El controlador aprende sus MACs por ARP.
- **IPs/MACs del NAT:** editar las constantes al inicio de `protorouter.py` **y** los `defaultRoute` / IPs en `topo.py`. Luego volver a copiar con `run_pox.sh`.

Guía completa de pruebas: [`INFORME.md`](../INFORME.md) sección 7.
