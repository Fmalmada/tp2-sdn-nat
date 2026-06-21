Cómo correr:

en 1ra terminal parado en tp2-sdn-nat/pox/

´´´
python3 pox.py log.level --DEBUG protorouter
´´´

en 2da terminal parado en tp_sdn_nat/

´´´
sudo python3 topo.py
´´´

después puse poner en mininet> 

´´´
h2 ping h1
´´´
//ctrl+c para parar el ping
//salir de Mininet: "exit" 
