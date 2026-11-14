#!/usr/bin/env bash
# One command: ./run.sh <bodies_dir>   (box-local; no network after pip install)
# Pins to one core at nice 10 (v10-like proxy). CONTENDED=1 adds a same-core
# busy loop so the bench gets ~50% of the core (busy 2-vCPU seat proxy).
set -euo pipefail
cd "$(dirname "$0")"
BODIES=${1:?usage: run.sh <dir of block body JSON files>}
CORE=${CORE:-1}
[ -d .venv ] || { python3 -m venv .venv; .venv/bin/pip -q install zstandard lz4 brotli python-snappy msgpack; }
hog=""
if [ "${CONTENDED:-0}" = 1 ]; then taskset -c "$CORE" nice -n 10 sh -c 'while :; do :; done' & hog=$!; fi
trap '[ -n "$hog" ] && kill $hog' EXIT
OUT=${OUT:-results/run.json} REPS=${REPS:-3} taskset -c "$CORE" nice -n 10 .venv/bin/python bench.py "$BODIES"
.venv/bin/python table.py "${OUT:-results/run.json}"
