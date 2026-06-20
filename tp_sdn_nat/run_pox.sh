#!/bin/bash
# Copia el controlador a pox/ext/ (requerido por el enunciado) y arranca POX.
# Uso: ./tp_sdn_nat/run_pox.sh [log.level --DEBUG] protorouter

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cp "$ROOT/tp_sdn_nat/protorouter.py" "$ROOT/pox/ext/protorouter.py"
cd "$ROOT"
exec python3 pox/pox.py "$@"
