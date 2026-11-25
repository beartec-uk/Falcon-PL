#!/usr/bin/env bash
# Graph steps for one fronted withdrawal: PEG_OUT (pays the withdrawer from the operator-funded
# UTXO) -> PEG_OUT_CONFIRM -> KICK_OFF_1 -> START_TIME -> KICK_OFF_2 -> TAKE_1.
# Called by fpl-operatord after the peer cross-check passed. Env: FPL_OPERATOR_SECRET (never echoed),
# FPL_CLAIM_NOTE_ID, FPL_PAYOUT_OUTPOINT, FPL_DEPOSIT_DIR (presigned deposit graph chosen by the
# deposit lookup), FPL_FALCON_CLAIMS (claim taken from the Falcon ledger: the coordinator's
# FalconAdaptor turns it into the peg-out event; no mock), FPL_NETWORK, FPL_ESPLORA, FPL_OP_HOME.
set -euo pipefail
: "${FPL_OP_HOME:?}" "${FPL_CLAIM_NOTE_ID:?}" "${FPL_PAYOUT_OUTPOINT:?}" "${FPL_DEPOSIT_DIR:?}" "${FPL_FALCON_CLAIMS:?}"
[[ -f "$FPL_DEPOSIT_DIR/final.json" ]] || { echo "no presigned graph in $FPL_DEPOSIT_DIR" >&2; exit 3; }
# Honor the write-off marker placed on unrecoverable test graphs (19 Nov 2026).
# operatord calls this script for every fronted withdrawal against a deposit graph;
# without this check a written-off graph is --resumed and loops on spent kickoffs.
if [[ -f "$FPL_DEPOSIT_DIR/WRITTEN_OFF_TEST" ]]; then
  echo "refusing to --resume: $FPL_DEPOSIT_DIR is marked WRITTEN_OFF_TEST (operator repayment written off; do not retry)." >&2
  exit 4
fi
req_id=$(basename -- "$FPL_DEPOSIT_DIR")
req_id=${req_id#req-}
intake_json="${FPL_OP_HOME}/intake/${req_id}.json"
if [[ -f "$intake_json" ]] && python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); sys.exit(0 if d.get("repayment")=="written_off_test" else 1)' "$intake_json"; then
  echo "refusing to --resume: intake $req_id has repayment=written_off_test." >&2
  exit 4
fi
LOG="$FPL_OP_HOME/logs/graph-$FPL_CLAIM_NOTE_ID.log"
cd "$FPL_DEPOSIT_DIR"
setsid nohup "$FPL_OP_HOME/bin/fpl_ceremony_coordinator" --dir "$FPL_DEPOSIT_DIR" --network "${FPL_NETWORK:-testnet4}" \
  --esplora "${FPL_ESPLORA}" --resume --scenario take1 --falcon-claims "$FPL_FALCON_CLAIMS" \
  --payout-outpoint "$FPL_PAYOUT_OUTPOINT" >>"$LOG" 2>&1 </dev/null &
echo "started graph steps pid $! (log $LOG)"
