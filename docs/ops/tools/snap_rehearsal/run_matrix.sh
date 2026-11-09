#!/usr/bin/env bash
# Snapshot transport rehearsal matrix (isolated host only; loopback 29401-29408,
# hmac-dev scratch keys, network 2200, FALCON_PL_TEST_HOOKS gated).
# Usage: BIN=... CTL=... SCEN="s1 s2 ..." bash run_matrix.sh
# Then: python3 evaluate.py /tmp/falcon-snap-art-<TAG> <scenario>
H="${H:-$(dirname "$0")/../snap_catchup_session_rehearsal.sh}"
C16="FALCON_PL_SNAPSHOT_CHUNK_BYTES=16384"
P16="$C16 FALCON_PL_TEST_INBOUND_CATCH_CAP=16 FALCON_PL_TEST_CATCH_DRAIN_MS=5"
run() { echo "$(date -u +%T) start $1"; env "${@:2}" TAG=$1 systemd-run --scope -q -p MemoryMax=48G bash "$H" > /tmp/falcon-snap-art-$1.run.log 2>&1; echo "$(date -u +%T) end $1 rc=$?"; sleep 3; }
for s in ${SCEN:-s1 s2 s3 s4 s5 s6 s7 s8 s9 s10}; do case $s in
 s1)  run s1-basic WALLETS=20000 "ARCH_ENV=$C16" ;;                                   # eval: basic
 s2)  run s2-pressure WALLETS=20000 "ARCH_ENV=$P16" ;;                                # eval: pressure
 s3)  run s3-reask WALLETS=20000 "ARCH_ENV=$P16" "JOIN_ENV=FALCON_PL_TEST_REASK_AFTER_OFFER=1" ;;  # eval: reask
 s4)  run s4-two WALLETS=20000 "ARCH_ENV=$P16" "JOINERS=j1 j2" ;;                     # eval: two
 s5)  run s5-stall WALLETS=20000 "ARCH_ENV=$C16 FALCON_PL_TEST_SNAP_STALL_FROM_CHUNK=20 FALCON_PL_TEST_SNAP_STALL_MS=25000" TIMEOUT=240 ;;  # eval: stall
 s6)  run s6-large16k WALLETS=64000 "ARCH_ENV=$C16" TIMEOUT=300 ;;                    # eval: large
 s7)  run s7-large256k-pressure WALLETS=64000 "ARCH_ENV=FALCON_PL_TEST_INBOUND_CATCH_CAP=64 FALCON_PL_TEST_CATCH_DRAIN_MS=5" TIMEOUT=300 ;;  # eval: large
 s8)  run s8-heavy-pressure WALLETS=20000 "ARCH_ENV=$C16 FALCON_PL_TEST_INBOUND_CATCH_CAP=16 FALCON_PL_TEST_CATCH_DRAIN_MS=40" "JOIN_ENV=FALCON_PL_TEST_REASK_AFTER_OFFER=1" TIMEOUT=240 ;;  # eval: reask
 s9)  run s9-40mb-256k-two WALLETS=300000 "ARCH_ENV=FALCON_PL_TEST_INBOUND_CATCH_CAP=64 FALCON_PL_TEST_CATCH_DRAIN_MS=5" "JOINERS=j1 j2" TIMEOUT=600 ;;  # eval: two
 s10) run s10-40mb-256k-two-heavy WALLETS=300000 "ARCH_ENV=FALCON_PL_TEST_INBOUND_CATCH_CAP=16 FALCON_PL_TEST_CATCH_DRAIN_MS=20" "JOINERS=j1 j2" "JOIN_ENV=FALCON_PL_TEST_REASK_AFTER_OFFER=1" TIMEOUT=600 ;;  # eval: reask
esac; done
