#!/bin/bash
# Wait until BTC4 rail is within RAIL_SYNC_MAX_LAG of Testnet4, then run TC-1 once.
# Low priority; does not start the batch loop; does not restart validators.
set -uo pipefail
HOME_DIR=/home/falcon/loadgen/bridge
LOG=$HOME_DIR/logs/wait-and-once.log
mkdir -p "$HOME_DIR/logs" "$HOME_DIR/work"
exec >>"$LOG" 2>&1
echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] wait-and-once starting pid=$$"
# do not source discord.env into the shell transcript
export LOADGEN_CONFIG=$HOME_DIR/bridge-loadgen.env
if [ -f "$HOME_DIR/discord.env" ]; then
  set -a
  # shellcheck disable=SC1091
  . "$HOME_DIR/discord.env"
  set +a
fi
MAX_LAG=${RAIL_SYNC_MAX_LAG:-2}
POLL=30
while true; do
  set +e
  python3 - <<'PY'
import json, os, subprocess, urllib.request, sys
from datetime import datetime, timezone
from pathlib import Path

def gmt():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S GMT")

ctl=["/var/lib/falcon-pl-2300/bin/falcon-pl-ctl","--addr","127.0.0.1:19301","status"]
r=subprocess.run(ctl,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=60)
d=json.loads(r.stdout); b=d.get("body",d)
rail=[x for x in (b.get("rails") or []) if x.get("asset")=="BTC4"][0]
rail_h=int(rail.get("tip_height") or 0)
rh=str(rail.get("tip_hash") or "")
fork=rail.get("btc_fork")
fpl=int(b.get("tip_height") or 0)
tn4=int(urllib.request.urlopen("https://mempool.space/testnet4/api/blocks/tip/height", timeout=20).read().decode().strip())
lag=tn4-rail_h
line=f"{gmt()}: waiting rail={rail_h} tn4={tn4} lag={lag} fpl={fpl} fork={fork} hash={rh[:16]}…"
print(line, flush=True)
rec=Path("/home/falcon/loadgen/bridge/record/TEST-RECORD.md")
# append snapshot at most once per 5 minutes to the formal record
stamp=Path("/home/falcon/loadgen/bridge/work/last-record-note")
now=datetime.now(timezone.utc).timestamp()
last=float(stamp.read_text()) if stamp.exists() else 0
if rec.exists() and now-last>=300:
    with rec.open("a") as f:
        f.write(f"\n- {line}\n")
    stamp.write_text(str(now))
max_lag=int(os.environ.get("RAIL_SYNC_MAX_LAG","2"))
sys.exit(0 if lag<=max_lag else 3)
PY
  rc=$?
  set -e
  if [ "$rc" -eq 0 ]; then
    echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] rail synced; starting TC-1 once"
    exec nice -n 15 ionice -c 2 -n 7 /usr/bin/python3 "$HOME_DIR/falcon_pl_bridge_loadgen.py" "$HOME_DIR/bridge-loadgen.env" once
  fi
  if [ "$rc" -ne 3 ]; then
    echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] poll failed rc=$rc; retrying"
  fi
  sleep "$POLL"
done
