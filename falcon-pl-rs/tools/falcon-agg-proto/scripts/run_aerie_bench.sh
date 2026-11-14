#!/usr/bin/env bash
# Prototype: run a16z Aerie's own Falcon-512 aggregation bench at FPL-relevant
# batch sizes. Aerie is NOT vendored; this clones the pinned research release.
# Needs Rust >= 1.95. Aerie only accepts FN-DSA (fn-dsa 0.3.0) key-prefixed
# framing, not the original Falcon r||m framing FPL signs with today.
set -euo pipefail
DIR=${1:-/tmp/aerie-scratch}
REV=49b6c212c209286c536196f53618823ffdf0e899
THREADS=${THREADS:-2}
[ -d "$DIR" ] || git clone -q https://github.com/a16z/aerie.git "$DIR"
cd "$DIR" && git checkout -q "$REV"
nice -n 19 cargo build --release --locked -p aerie-bench --features falcon-bench --benches -j"$THREADS"
BIN=$(ls -t target/release/deps/falcon-* | grep -v '\.d$' | head -1)
for n in 8 128 1024; do
  for mode in "" "--common-salt"; do
    RAYON_NUM_THREADS=$THREADS "$BIN" $n $mode | grep -E '^[0-9]+\s' |
      awk -F'\t' -v m="${mode:-per-record}" '{print "records="$1" salt="m" prove_ms="$3" verify_ms="$19" verify_1thread_ms="$25" aggregate_bytes="$33}'
  done
done
