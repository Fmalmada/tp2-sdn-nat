### Cómo correr

#### 1. En la primera terminal (parado en `tp2-sdn-nat/pox/`)
```bash
python3 pox.py log.level --DEBUG protorouter
```

#### 2. En la segunda terminal (parado en `tp_sdn_nat/`)
```bash
sudo python3 topo.py
```

#### 3. En la CLI de Mininet (ejecutar desde la terminal donde quedó la topología)
```bash
h2 ping h1
```

**Detener el ping**
```bash
# presionar Ctrl+C en la CLI de Mininet
```

**Salir de Mininet**
```bash
exit
```