#!/usr/bin/env bash
# Isolated loopback snapshot-transport rehearsal (beartec-brain only).
# Scratch hmac-dev keys, network 2200, ports 29401-29408, test hooks gated by
# FALCON_PL_TEST_HOOKS=1 + hmac-dev + network!=2300. Never touches live seats.
# Env: TAG, JOINERS ("j1" or "j1 j2"), WALLETS, ARCH_ENV, JOIN_ENV ("K=V K=V"),
#      TIMEOUT (s), BIN, CTL.
set -uo pipefail
: "${TAG:?}" "${JOINERS:=j1}" "${WALLETS:=800}" "${ARCH_ENV:=}" "${JOIN_ENV:=}" "${TIMEOUT:=180}"
BIN="${BIN:-/tmp/falcon-snap-repair-cargo/release/falcon-pl-node}"
CTL="${CTL:-/tmp/falcon-snap-repair-cargo/release/falcon-pl-ctl}"
ART=/tmp/falcon-snap-art-$TAG
if ss -lnt | grep -qE '127\.0\.0\.1:2940[1-8]\b'; then echo PORTS_BUSY; exit 3; fi
rm -rf "$ART"; mkdir -p "$ART/logs"
SCRATCH=$(mktemp -d /tmp/falcon-snap-$TAG-XXXXXX)
{ echo "TAG=$TAG JOINERS=$JOINERS WALLETS=$WALLETS TIMEOUT=$TIMEOUT"; echo "ARCH_ENV=$ARCH_ENV"; echo "JOIN_ENV=$JOIN_ENV";
  echo "src=$(cd /tmp/falcon-snap-repair-src && git rev-parse HEAD) dirty=$(cd /tmp/falcon-snap-repair-src && git diff --quiet || echo yes)";
  echo "node_src_sha=$(sha256sum /tmp/falcon-snap-repair-src/falcon-pl-rs/crates/fd-pl/src/bin/falcon_pl_node.rs | cut -c1-16)";
  sha256sum "$BIN"; echo "scratch=$SCRATCH"; date -u +%FT%TZ; } | tee "$ART/meta.txt"
KEYS="$SCRATCH/keys"; mkdir -p "$KEYS/lc"; NET=2200; VALS="v1,v2,v3,v4,v5,v6"
"$BIN" --gen-keys-only --keys-dir "$KEYS" --scheme hmac --allow-dev-crypto --validators "$VALS,${JOINERS// /,}" --id v1 >/dev/null
printf '%s\n' '{"qc_header_version":4,"qc_start_height":1,"network_id":2200,"start_height":1}' >"$KEYS/lc/bridge.json"
PIDS=""; SAMPLER=""
PAYER=""
cleanup() {
  [[ -n "$SAMPLER" ]] && kill "$SAMPLER" 2>/dev/null
  [[ -n "$PAYER" ]] && kill "$PAYER" 2>/dev/null
  for p in $PIDS; do kill "$p" 2>/dev/null; done; sleep 1
  for p in $PIDS; do kill -9 "$p" 2>/dev/null; done
  sleep 0.5
  if ss -lnt | grep -qE '127\.0\.0\.1:2940[1-8]\b'; then echo PORTS_STILL_BUSY >> "$ART/meta.txt"; else echo ports_cleared >> "$ART/meta.txt"; fi
}
trap cleanup EXIT
declare -A PID_OF PORT_OF
start() {
  local id="$1" port="$2" mode="$3" peers="$4" envs="$5"
  local dat="$SCRATCH/$id"; mkdir -p "$dat"/{run,snapshots,logs}
  local extra=() mcl=64
  [[ "$mode" == archive ]] && { extra+=(--archive --hub); mcl=256; }
  [[ "$mode" == join ]] && extra+=(--join)
  env FPL_EMPTY_BLOCK_FROM_HEIGHT=1 RUST_LOG=falcon_pl_node=debug FALCON_PL_TEST_HOOKS=1 $envs \
    nice -n19 ionice -c3 "$BIN" --id "$id" --listen "127.0.0.1:$port" --peers "$peers" \
    --keys-dir "$KEYS" --scheme hmac --allow-dev-crypto --validators "$VALS" --bond 1000 \
    --network-id "$NET" --online-epoch-heights 0 --first-claim-epoch 1 --min-block-interval-ms 0 \
    --admin-sock "$dat/run/admin.sock" --snapshot "$dat/snapshots/snap.json" --snapshot-out "$dat/snapshots/snap.json" \
    --snapshot-interval-ms 4000 --seal-interval-ms 200 --pack-budget-ms 400 --progress-timeout-ms 4000 \
    --max-chain-ledgers "$mcl" --load-wallets "$WALLETS" --lock-public-wire "${extra[@]}" \
    >"$dat/logs/node.log" 2>&1 &
  PIDS="$PIDS $!"; PID_OF[$id]=$!; PORT_OF[$id]=$port
  echo "started $id :$port pid=$! mode=$mode env=[$envs]" | tee -a "$ART/meta.txt"
}
MP() { local i=$1 o=() j; for j in 0 1 2 3 4 5; do [[ $j -eq $i ]]||o+=("127.0.0.1:$((29401+j))"); done; local IFS=,; echo "${o[*]}"; }
start v1 29401 archive "$(MP 0)" "$ARCH_ENV"
for i in 1 2 3 4 5; do start v$((i+1)) $((29401+i)) mesh "$(MP $i)" ""; done
st() { "$CTL" --addr "127.0.0.1:$1" status 2>/dev/null; }
export CTL ART
BOOT_DEADLINE=$((SECONDS+240))
until st 29401 >/dev/null; do (( SECONDS > BOOT_DEADLINE )) && { echo FAIL_BOOT > "$ART/RESULT.txt"; tail -30 "$SCRATCH/v1/logs/node.log"; exit 2; }; sleep 2; done
echo "boot_s=$SECONDS" | tee -a "$ART/meta.txt"
export KEYS NET
python3 - <<'PY'
import subprocess,os,time
ctl=os.environ["CTL"]; keys=os.environ["KEYS"]; net=os.environ["NET"]
ok=0
for seq in range(1,25):
  try:
    subprocess.check_output([ctl,"--addr","127.0.0.1:29401","pay","--from","alice","--to","bob","--amount","1","--fee","1","--sequence",str(seq),"--scheme","hmac","--keys-dir",keys,"--network-id",net],text=True,timeout=20,stderr=subprocess.STDOUT); ok+=1
  except Exception as e: print("pay",seq,"err",e)
  time.sleep(0.05)
print("pays_ok",ok)
PY
python3 - <<'PY' || { echo FAIL_MESH > "$ART/RESULT.txt"; exit 2; }
import json,subprocess,os,time
from collections import Counter
ctl=os.environ["CTL"]; art=os.environ["ART"]; dl=time.time()+240
while time.time()<dl:
  rows=[]
  for i in range(6):
    try: b=json.loads(subprocess.check_output([ctl,"--addr",f"127.0.0.1:{29401+i}","status"],text=True,timeout=20)).get("body") or {}
    except Exception: b={}
    rows.append((b.get("tip_height") or 0, b.get("tip_hash") or ""))
  t,n=Counter(r[0] for r in rows).most_common(1)[0]
  hs={h for (tt,h) in rows if tt==t}
  print("mesh",[r[0] for r in rows],len(hs),flush=True)
  if t>=1 and n>=5 and len(hs)==1:
    open(art+"/mesh_ok.json","w").write(json.dumps(rows)); raise SystemExit(0)
  time.sleep(2)
raise SystemExit(1)
PY
"$CTL" --admin-sock "$SCRATCH/v1/run/admin.sock" snapshot-save --path "$SCRATCH/v1/snapshots/snap.json" >/dev/null 2>&1 || true
sleep 1; ls -la "$SCRATCH/v1/snapshots/" > "$ART/v1_pin_dir.txt"
st 29401 > "$ART/v1_pre_joiner.json"
# Live load during the transfer: 1 pay/s keeps the mesh sealing new blocks the
# joiner must follow after adopt (exact PID, killed in cleanup).
( seq=25; while :; do "$CTL" --addr 127.0.0.1:29402 pay --from alice --to bob --amount 1 --fee 1 --sequence $seq \
    --scheme hmac --keys-dir "$KEYS" --network-id "$NET" >/dev/null 2>&1; seq=$((seq+1)); sleep 1; done ) &
PAYER=$!
n=0; for j in $JOINERS; do start "$j" $((29407+n)) join "127.0.0.1:29401" "$JOIN_ENV"; n=$((n+1)); done
date -u +%FT%T.%NZ > "$ART/joiners_started.txt"
( while :; do for id in v1 $JOINERS; do p=${PID_OF[$id]}; [[ -r /proc/$p/status ]] && echo "$(date +%s.%N) $id $(awk '/^VmRSS|^VmHWM/{printf "%s%s ",$1,$2}' /proc/$p/status)"; done; sleep 0.25; done ) > "$ART/rss_samples.txt" 2>/dev/null &
SAMPLER=$!
JPORTS=""; n=0; for j in $JOINERS; do JPORTS="$JPORTS $j:$((29407+n))"; n=$((n+1)); done
export JPORTS TIMEOUT
python3 - <<'PY'
import json,subprocess,os,time
ctl=os.environ["CTL"]; art=os.environ["ART"]; jp=[x.split(":") for x in os.environ["JPORTS"].split()]
def st(port):
  try: return json.loads(subprocess.check_output([ctl,"--addr",f"127.0.0.1:{port}","status"],text=True,timeout=20)).get("body") or {}
  except Exception as e: return {"err":str(e)}
dl=time.time()+int(os.environ["TIMEOUT"]); rows=[]; done=set()
while time.time()<dl:
  r={"t":time.time(),"v1":st(29401)}
  for j,p in jp: r[j]=st(int(p))
  rows.append({k:(v if k=="t" else {"tip":v.get("tip_height"),"hash":v.get("tip_hash"),"err":v.get("err")}) for k,v in r.items()})
  print("poll",{k:(v.get("tip_height") if isinstance(v,dict) else None) for k,v in r.items() if k!="t"},flush=True)
  for j,_ in jp:
    if r[j].get("tip_height") and r[j].get("tip_height")==r["v1"].get("tip_height") and r[j].get("tip_hash")==r["v1"].get("tip_hash") and r[j]["tip_height"]>=1:
      done.add(j)
  if len(done)==len(jp): break
  time.sleep(2)
open(art+"/trace.jsonl","w").write("\n".join(json.dumps(x) for x in rows)+"\n")
open(art+"/joiners_synced.json","w").write(json.dumps(sorted(done)))
PY
# Mesh health after the transfer: tips + hash agreement among v1..v6
kill "$PAYER" 2>/dev/null; PAYER=""
sleep 6
for i in 0 1 2 3 4 5; do echo "v$((i+1)) $(st $((29401+i)) | python3 -c 'import json,sys;b=json.load(sys.stdin).get("body") or {};print(b.get("tip_height"),b.get("tip_hash"))' 2>/dev/null)"; done > "$ART/mesh_after.txt"
for id in v1 $JOINERS; do p=${PID_OF[$id]}; echo "$id $(grep -E '^VmHWM|^VmRSS' /proc/$p/status 2>/dev/null | tr -s ' \t\n' ' ')"; done > "$ART/rss_final.txt"
for id in v1 v2 v3 v4 v5 v6 $JOINERS; do cp -a "$SCRATCH/$id/logs/node.log" "$ART/logs/$id.log"; done
ls -la "$SCRATCH"/j*/snapshots > "$ART/joiner_snap_dirs.txt" 2>&1
echo DONE > "$ART/DONE"
