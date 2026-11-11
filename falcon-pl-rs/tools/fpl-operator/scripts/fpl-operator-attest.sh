#!/usr/bin/env bash
# M1 Bitvm2AttestV2 via the public snarkjs prover (no arkworks proving key).
# Env (set by fpl-operatord or the operator by hand):
#   FPL_ATTEST_NOTE, FPL_ATTEST_PEGOUT_TXID (display), FPL_ATTEST_CLAIM_TXID,
#   FPL_OP_FALCON_CTL / _RPC / _ACCOUNT / _KEYS_DIR / _SCHEME / _NETWORK_ID / _BIN_DIR,
#   FPL_OP_BITCOIN_CLI (+ FPL_OP_BITCOIN_ARGS as a space-separated string),
#   FPL_ZKEY (path to final_v1.zkey), FPL_VK_JSON (verification_key.json),
#   optional FPL_VK_HEX (BITVM2_WITHDRAW_VK_HEX; if set, body is pre-checked as the ledger will).
# Needs: falcon-pl-bitvm2-attest, falcon-pl-bitvm2-setup, snarkjs in PATH / npx.
set -euo pipefail
BIN=${FPL_OP_BIN_DIR:-$(dirname "$0")}
S=${FPL_SETUP:-$BIN/falcon-pl-bitvm2-setup}
A=${FPL_ATTEST:-$BIN/falcon-pl-bitvm2-attest}
X=${SNARKJS:-npx snarkjs}
W=$(mktemp -d); trap 'rm -rf "$W"' EXIT
cli=($FPL_OP_BITCOIN_CLI ${FPL_OP_BITCOIN_ARGS--testnet4})
"$FPL_OP_FALCON_CTL" --addr "$FPL_OP_FALCON_RPC" status > "$W/status.json"
$A input --status "$W/status.json" --note-id "$FPL_ATTEST_NOTE" --pegout-txid "$FPL_ATTEST_PEGOUT_TXID" --out "$W/attest.json"
$S attest-wtns --input "$W/attest.json" --out "$W/w.wtns" --public-out "$W/public_expected.json" >/dev/null
$X groth16 prove "$FPL_ZKEY" "$W/w.wtns" "$W/proof.json" "$W/public.json"
$S proof-import --vk "$FPL_VK_JSON" --proof "$W/proof.json" --public "$W/public.json" > "$W/import.json"
raw=$("${cli[@]}" getrawtransaction "$FPL_ATTEST_PEGOUT_TXID" true)
bh=$(python3 -c 'import json,sys; print(json.load(sys.stdin)["blockhash"])' <<<"$raw")
ht=$("${cli[@]}" getblockheader "$bh" | python3 -c 'import json,sys; print(json.load(sys.stdin)["height"])')
"${cli[@]}" getblock "$bh" true | python3 -c 'import json,sys; print(json.dumps(json.load(sys.stdin)["tx"]))' > "$W/txids.json"
rawhex=$(python3 -c 'import json,sys; print(json.load(sys.stdin)["hex"])' <<<"$raw")
# FPL_VK_HEX may be hex or a path (fpl-operatord passes FPL_OP_ATTEST_VK_HEX, usually attest/v1_vk.bin):
# a file is read as hex text, or hex-encoded when binary (the attest tool wants hex).
vkh=${FPL_VK_HEX:-}
if [[ -n "$vkh" && -f "$vkh" ]]; then
  if ! LC_ALL=C grep -aqvE '^[0-9a-fA-F[:space:]]*$' "$vkh"; then vkh=$(tr -d '[:space:]' < "$vkh"); else vkh=$(od -An -v -tx1 "$vkh" | tr -d ' \n'); fi
fi
vk=(); [[ -n "$vkh" ]] && vk=(--vk-hex "$vkh")
$A body --input "$W/attest.json" --import "$W/import.json" --raw-tx "$rawhex" --btc-height "$ht" \
  --block-txids "$W/txids.json" --claim-txid "$FPL_ATTEST_CLAIM_TXID" "${vk[@]}" --out "$W/body.json"
kd=(); [[ -n "${FPL_OP_FALCON_KEYS_DIR:-}" ]] && kd=(--keys-dir "$FPL_OP_FALCON_KEYS_DIR")
body=$(python3 -c 'import json; print(json.dumps(json.load(open("'"$W"'/body.json"))))')
exec "$FPL_OP_FALCON_CTL" --addr "$FPL_OP_FALCON_RPC" operator --account "$FPL_OP_FALCON_ACCOUNT" \
  --scheme "${FPL_OP_FALCON_SCHEME:-falcon}" --network-id "${FPL_OP_FALCON_NETWORK_ID:-2300}" "${kd[@]}" --body "$body"
