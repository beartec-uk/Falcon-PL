#!/usr/bin/env bash
# Dry-run & unit tests for install-falcon-node.sh (Items #1, #8, #13).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALLER="$SCRIPT_DIR/install-falcon-node.sh"

bash -n "$INSTALLER"
bash -n "$SCRIPT_DIR/falcon-node-autoupgrade"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# Source functions from install-falcon-node.sh without executing main "$@"
FUNCS_FILE="$TMP/funcs.sh"
sed '/^main "\$@"/d' "$INSTALLER" >"$FUNCS_FILE"
# shellcheck disable=SC1090
source "$FUNCS_FILE"

# --- Test 1 (Item #1): install_minisign_binary fallback + SHA-256 verification ---
mkdir -p "$TMP/pkg/minisign-linux/x86_64" "$TMP/dest"
cat <<'MS' >"$TMP/pkg/minisign-linux/x86_64/minisign"
#!/usr/bin/env bash
echo "minisign 0.11"
MS
chmod 0755 "$TMP/pkg/minisign-linux/x86_64/minisign"
tar -czf "$TMP/minisign-0.11-linux.tar.gz" -C "$TMP/pkg" minisign-linux
TAR_SHA="$(sha256sum "$TMP/minisign-0.11-linux.tar.gz" | awk '{print $1}')"

FALCON_MINISIGN_DEST_DIR="$TMP/dest"
MINISIGN_TARBALL_URL="file://$TMP/minisign-0.11-linux.tar.gz"
MINISIGN_TARBALL_SHA256="0000000000000000000000000000000000000000000000000000000000000000"
if install_minisign_binary 2>/dev/null; then
  echo "FAIL: install_minisign_binary should reject mismatched SHA-256" >&2
  exit 1
fi

MINISIGN_TARBALL_SHA256="$TAR_SHA"
install_minisign_binary
[[ -x "$TMP/dest/minisign" ]] || { echo "FAIL: minisign binary not executable" >&2; exit 1; }
[[ "$(stat -c '%a' "$TMP/dest/minisign")" == "755" ]] || { echo "FAIL: minisign mode not 755" >&2; exit 1; }

# Verify default URL and pinned SHA-256 in install-falcon-node.sh match official 0.11 release
grep -q 'https://github.com/jedisct1/minisign/releases/download/0.11/minisign-0.11-linux.tar.gz' "$INSTALLER"
grep -q 'f0a0954413df8531befed169e447a66da6868d79052ed7e892e50a4291af7ae0' "$INSTALLER"

# --- Test 2 (Item #8): node.env permissions and NODE_ID preservation ---
FALCON_HOME="$TMP/home"
resolve_home
mkdir -p "$BIN" "$KEYS" "$DATA" "$LOGS" "$CONF" "$RUN" "$VALDIR"
cat <<'ENV' >"$NODE_ENV"
OBSERVER_ID=obs-test-123456
LISTEN=127.0.0.1:19400
SERVICE_MODE=none
VERSION=2.9.81
ENV
chmod 0600 "$NODE_ENV"

# Even when NODE_ID was missing and mode was 0600, load_installed / ensure_node_env_readable recovers NODE_ID and fixes mode to 644
load_installed
[[ "$(kv_get "$NODE_ENV" NODE_ID)" == "obs-test-123456" ]] || { echo "FAIL: NODE_ID not recovered" >&2; exit 1; }
[[ "$(stat -c '%a' "$NODE_ENV")" == "644" ]] || { echo "FAIL: node.env mode not 644 after load_installed" >&2; exit 1; }

chmod 0600 "$NODE_ENV"
kv_set "$NODE_ENV" VERSION "2.10.0"
[[ "$(stat -c '%a' "$NODE_ENV")" == "644" ]] || { echo "FAIL: node.env mode not 644 after kv_set" >&2; exit 1; }
[[ "$(kv_get "$NODE_ENV" NODE_ID)" == "obs-test-123456" ]] || { echo "FAIL: NODE_ID lost after kv_set" >&2; exit 1; }

# --- Test 3 (Item #13): autoupgrade on|off|status and rollback on failed health check ---
OUT_STATUS="$(AUTOUPGRADE_ACTION=status cmd_autoupgrade)"
[[ "$OUT_STATUS" == *"autoupgrade: off"* ]] || { echo "FAIL: default autoupgrade status should be off (got: $OUT_STATUS)" >&2; exit 1; }

AUTOUPGRADE_ACTION=on AUTOUPGRADE_JITTER_SECS=0 cmd_autoupgrade >/dev/null
[[ "$(kv_get "$NODE_ENV" AUTOUPGRADE)" == "on" ]] || { echo "FAIL: AUTOUPGRADE not set to on" >&2; exit 1; }
[[ -x "$BIN/falcon-node-autoupgrade" ]] || { echo "FAIL: falcon-node-autoupgrade not created" >&2; exit 1; }

AUTOUPGRADE_ACTION=off cmd_autoupgrade >/dev/null
[[ "$(kv_get "$NODE_ENV" AUTOUPGRADE)" == "off" ]] || { echo "FAIL: AUTOUPGRADE not set to off" >&2; exit 1; }

# Verify rollback_autoupgrade restores .prev binary and VERSION
echo "v2.9.81-binary" >"$BIN/falcon-pl-node.prev"
echo "v2.9.81-ctl" >"$BIN/falcon-pl-ctl.prev"
echo "v2.10.0-broken" >"$BIN/falcon-pl-node"
echo "v2.10.0-broken" >"$BIN/falcon-pl-ctl"
kv_set "$NODE_ENV" VERSION "2.10.0"
svc_restart() { :; }
rollback_autoupgrade "2.9.81" >/dev/null 2>&1
[[ "$(cat "$BIN/falcon-pl-node")" == "v2.9.81-binary" ]] || { echo "FAIL: falcon-pl-node not rolled back" >&2; exit 1; }
[[ "$(cat "$BIN/falcon-pl-ctl")" == "v2.9.81-ctl" ]] || { echo "FAIL: falcon-pl-ctl not rolled back" >&2; exit 1; }
[[ "$(kv_get "$NODE_ENV" VERSION)" == "2.9.81" ]] || { echo "FAIL: VERSION not rolled back" >&2; exit 1; }

# --- Test 4 (2.10.1): auto-upgrade ON by default, opt-out remembered ---
SCTL_LOG="$TMP/sctl.log"; : >"$SCTL_LOG"
sctl() { echo "$*" >>"$SCTL_LOG"; }
SERVICE_MODE=system NO_AUTOUPGRADE=0
sed -i '/^AUTOUPGRADE/d' "$NODE_ENV"
autoupgrade_apply_default >/dev/null
[[ "$(kv_get "$NODE_ENV" AUTOUPGRADE)" == "on" ]] || { echo "FAIL: default should enable autoupgrade" >&2; exit 1; }
grep -q "enable --now $AUTOU_UNIT.timer" "$SCTL_LOG" || { echo "FAIL: timer not enabled by default" >&2; exit 1; }
kv_set "$NODE_ENV" AUTOUPGRADE off   # old installers wrote off by default: upgrade turns it on
autoupgrade_apply_default >/dev/null
[[ "$(kv_get "$NODE_ENV" AUTOUPGRADE)" == "on" ]] || { echo "FAIL: upgrade should turn old default-off on" >&2; exit 1; }
NO_AUTOUPGRADE=1 autoupgrade_apply_default >/dev/null
[[ "$(kv_get "$NODE_ENV" AUTOUPGRADE_OPTOUT)" == "1" && "$(kv_get "$NODE_ENV" AUTOUPGRADE)" == "off" ]] || { echo "FAIL: --no-autoupgrade not recorded" >&2; exit 1; }
NO_AUTOUPGRADE=0; autoupgrade_apply_default >/dev/null
[[ "$(kv_get "$NODE_ENV" AUTOUPGRADE)" == "off" ]] || { echo "FAIL: opt-out must survive a later upgrade" >&2; exit 1; }
grep -q '^OnActiveSec=15min' "$INSTALLER" || { echo "FAIL: timer should start 15 min after enable" >&2; exit 1; }
SERVICE_MODE=none

# --- Test 5 (2.10.1): adopted seat runner keeps the original args + working dir ---
W="$TMP/seat"; mkdir -p "$W/keys"
kv_set "$NODE_ENV" WORKDIR "$W"
printf '%s\n' "--id v99 --join --listen 0.0.0.0:19399 --keys-dir keys --snapshot snapshots/v99.json" >"$CONF/node.args"
write_adopt_runner
printf '#!/usr/bin/env bash\necho "$PWD|$*"\n' >"$BIN/falcon-pl-node"; chmod 0755 "$BIN/falcon-pl-node"
OUT="$("$BIN/run-node.sh")"
[[ "$OUT" == "$W|--id v99 --join --listen 0.0.0.0:19399 --keys-dir keys --snapshot snapshots/v99.json" ]] || { echo "FAIL: adopt runner args/dir wrong: $OUT" >&2; exit 1; }
ADOPTED=1; ( cmd_uninstall ) >/dev/null 2>&1 && { echo "FAIL: uninstall must refuse an adopted seat" >&2; exit 1; }
ADOPTED=0

# --- Test 6 (2.10.1 regression): resolve_home on a pre-2.10.1 node.env (no UNIT/ADOPTED/SVC_USER) under set -e ---
OLDH="$TMP/oldhome"; mkdir -p "$OLDH/config"
printf 'NODE_ID=old1\nVERSION=2.10.0\nAUTOUPGRADE=off\n' >"$OLDH/config/node.env"
OUT6="$(bash -c 'set -euo pipefail; source "$1"; FALCON_HOME="$2"; resolve_home; echo ok' _ "$FUNCS_FILE" "$OLDH" 2>&1 || true)"; [[ "$OUT6" == *ok ]] || { echo "FAIL: resolve_home aborts on a pre-2.10.1 node.env" >&2; exit 1; }
printf 'ADOPTED=1\nUNIT=falcon-pl-v99\nSVC_USER=falcon\n' >>"$OLDH/config/node.env"; OUT6="$(bash -c 'set -euo pipefail; source "$1"; FALCON_HOME="$2"; resolve_home; echo "$ADOPTED $UNIT $AUTOU_UNIT $SVC_USER"' _ "$FUNCS_FILE" "$OLDH" 2>&1 || true)"; [[ "$OUT6" == *"1 falcon-pl-v99 falcon-pl-v99-autoupgrade falcon" ]] || { echo "FAIL: resolve_home adopted fields" >&2; exit 1; }

# --- Test 7 (2.11.4): autoupgrade never rolls back / restarts a running node on a flat tip ---
# 12 Nov 2026 h=869559: an hourly run with no new release waited 120s for the tip, saw it flat
# (chain stall), "rolled back" to the same 2.11.3 and restarted v3/v12 mid-stall.
# Service / RPC state live in files: cmd_upgrade runs in a subshell, like the real unit state.
AU_SVC_F="$TMP/au_svc"; AU_RPC_F="$TMP/au_rpc"   # contents 1 = service active / RPC answers
AU_TIPS=()          # successive tip_height values returned by local_status
AU_PEERS=()         # successive best_peer_tip values
AU_RPCSEQ=()        # optional per-call RPC answers (1/0); overrides the RPC file
AU_WORK=true        # liveness.has_work reported by status
AU_I=0
RESTARTS="$TMP/restarts.log"; : >"$RESTARTS"
svc_active() { [[ "$(cat "$AU_SVC_F")" == 1 ]]; }
svc_restart() { echo restart >>"$RESTARTS"; echo 1 >"$AU_SVC_F"; }
local_status() {
  local i=$AU_I t p
  if (( ${#AU_RPCSEQ[@]} > 0 )); then
    local j=$i; (( j < ${#AU_RPCSEQ[@]} )) || j=$(( ${#AU_RPCSEQ[@]} - 1 ))
    AU_I=$(( AU_I + 1 ))
    [[ "${AU_RPCSEQ[$j]}" == 1 ]] || return 1
    i=$(( AU_I - 1 ))
  else
    [[ "$(cat "$AU_RPC_F")" == 1 ]] || return 1
    AU_I=$(( AU_I + 1 ))
  fi
  (( i < ${#AU_TIPS[@]} )) || i=$(( ${#AU_TIPS[@]} - 1 ))
  t="${AU_TIPS[$i]}"; p="${AU_PEERS[$i]:-$t}"
  printf '{"tip_height": %s, "best_peer_tip": %s, "liveness": {"tip_height": %s, "has_work": %s}}\n' "$t" "$p" "$t" "$AU_WORK" >"$1"
}
au_reset() { # svc rpc "tips" "peers"
  echo "$1" >"$AU_SVC_F"; echo "$2" >"$AU_RPC_F"; read -r -a AU_TIPS <<<"$3"; read -r -a AU_PEERS <<<"${4:-}"; AU_I=0; AU_RPCSEQ=(); AU_WORK=true; : >"$RESTARTS"
  echo "node-2.11.3" >"$BIN/falcon-pl-node"; echo "ctl-2.11.3" >"$BIN/falcon-pl-ctl"
  rm -f "$BIN/falcon-pl-node.prev" "$BIN/falcon-pl-ctl.prev"
  kv_set "$NODE_ENV" VERSION "2.11.3"
}
UPGRADE_CALLS="$TMP/upgrade.log"
upgrade_noop() { echo noop >>"$UPGRADE_CALLS"; }                                   # no new release
upgrade_new() { echo new >>"$UPGRADE_CALLS"; echo "node-2.11.4" >"$BIN/falcon-pl-node"; echo "ctl-2.11.4" >"$BIN/falcon-pl-ctl"; kv_set "$NODE_ENV" VERSION "2.11.4"; }
upgrade_fail() { echo fail >>"$UPGRADE_CALLS"; return 1; }                           # e.g. download failed
export FALCON_AUTOUPGRADE_HEALTH_TIMEOUT=2 FALCON_AUTOUPGRADE_POLL_SECS=1 FALCON_AUTOUPGRADE_STALL_PROBE_SECS=0
AUTOUPGRADE_JITTER_SECS=0
au_run() { # upgrade-fn ; prints rc
  : >"$UPGRADE_CALLS"
  cmd_upgrade() { "$AU_UPGRADE"; }
  local rc=0
  AUTOUPGRADE_ACTION=run cmd_autoupgrade >/dev/null 2>&1 || rc=$?
  echo "$rc"
}
nrestarts() { wc -l <"$RESTARTS" | tr -d ' '; }

# 7a health check return codes
au_reset 1 1 "869559 869559 869559 869559 869559"
rc=0; autoupgrade_health_check 869559 >/dev/null 2>&1 || rc=$?
[[ $rc -eq 2 ]] || { echo "FAIL 7a: active + RPC + flat tip must be 2 (stall), got $rc" >&2; exit 1; }
au_reset 0 1 "869559"
rc=0; autoupgrade_health_check 869559 >/dev/null 2>&1 || rc=$?
[[ $rc -eq 1 ]] || { echo "FAIL 7a: service down must be 1, got $rc" >&2; exit 1; }
au_reset 1 0 "869559"
rc=0; autoupgrade_health_check 869559 >/dev/null 2>&1 || rc=$?
[[ $rc -eq 1 ]] || { echo "FAIL 7a: RPC dead must be 1, got $rc" >&2; exit 1; }
au_reset 1 1 "869559 869560"
rc=0; autoupgrade_health_check 869559 >/dev/null 2>&1 || rc=$?
[[ $rc -eq 0 ]] || { echo "FAIL 7a: tip advanced must be 0, got $rc" >&2; exit 1; }
# RPC answered earlier with a flat tip, then one slow/failed poll: still a stall (2), not a failure
au_reset 1 1 "869559"
AU_RPCSEQ=(1 0 0 0 0 0 0 0 0 0 0 0)
rc=0; autoupgrade_health_check 869559 >/dev/null 2>&1 || rc=$?
[[ $rc -eq 2 ]] || { echo "FAIL 7a: earlier RPC answer + flat tip must be 2, got $rc" >&2; exit 1; }

# 7b incident: no new release, service active, tip flat -> no health wait, no rollback, no restart
au_reset 1 1 "869559"
AU_UPGRADE=upgrade_noop; rc="$(au_run)"
[[ "$rc" == 0 && "$(nrestarts)" == 0 ]] || { echo "FAIL 7b: no-op run on a flat tip restarted ($(nrestarts)) rc=$rc" >&2; exit 1; }
[[ "$(cat "$BIN/falcon-pl-node")" == node-2.11.3 && "$(kv_get "$NODE_ENV" VERSION)" == 2.11.3 ]] || { echo "FAIL 7b: binaries/VERSION touched" >&2; exit 1; }

# 7c new binary installed, service active, chain stalled -> keep it, no rollback, no restart
au_reset 1 1 "869559"
AU_UPGRADE=upgrade_new; rc="$(au_run)"
[[ "$rc" == 0 && "$(nrestarts)" == 0 ]] || { echo "FAIL 7c: flat tip after a real upgrade rolled back/restarted ($(nrestarts)) rc=$rc" >&2; exit 1; }
[[ "$(cat "$BIN/falcon-pl-node")" == node-2.11.4 && "$(kv_get "$NODE_ENV" VERSION)" == 2.11.4 ]] || { echo "FAIL 7c: new binary not kept" >&2; exit 1; }

# 7d new binary, service dead after upgrade -> real failure: roll back to the old binary and restart
au_reset 1 1 "869559"
upgrade_new_dies() { upgrade_new; echo 0 >"$AU_SVC_F"; }
AU_UPGRADE=upgrade_new_dies; rc="$(au_run)"
[[ "$rc" == 1 && "$(nrestarts)" == 1 ]] || { echo "FAIL 7d: dead service after upgrade must roll back + restart once (restarts=$(nrestarts) rc=$rc)" >&2; exit 1; }
[[ "$(cat "$BIN/falcon-pl-node")" == node-2.11.3 && "$(cat "$BIN/falcon-pl-ctl")" == ctl-2.11.3 && "$(kv_get "$NODE_ENV" VERSION)" == 2.11.3 ]] || { echo "FAIL 7d: not rolled back" >&2; exit 1; }

# 7e new binary, RPC never answers -> real failure: roll back
au_reset 1 1 "869559"
upgrade_new_rpcdead() { upgrade_new; echo 0 >"$AU_RPC_F"; }
AU_UPGRADE=upgrade_new_rpcdead; rc="$(au_run)"
[[ "$rc" == 1 && "$(cat "$BIN/falcon-pl-node")" == node-2.11.3 ]] || { echo "FAIL 7e: dead RPC after upgrade must roll back (rc=$rc)" >&2; exit 1; }

# 7f healthy upgrade (tip advances) -> success, keep new binary, no extra restart
au_reset 1 1 "869559 869559 869560"
AU_UPGRADE=upgrade_new; rc="$(au_run)"
[[ "$rc" == 0 && "$(nrestarts)" == 0 && "$(cat "$BIN/falcon-pl-node")" == node-2.11.4 ]] || { echo "FAIL 7f: healthy upgrade (rc=$rc restarts=$(nrestarts))" >&2; exit 1; }

# 7g upgrade step fails before replacing anything, service running -> nothing to roll back, no restart
au_reset 1 1 "869559"
AU_UPGRADE=upgrade_fail; rc="$(au_run)"
[[ "$rc" == 1 && "$(nrestarts)" == 0 && "$(cat "$BIN/falcon-pl-node")" == node-2.11.3 ]] || { echo "FAIL 7g: failed download restarted a running node (restarts=$(nrestarts) rc=$rc)" >&2; exit 1; }

# 7h upgrade step fails, service actually down -> still recovers (start it)
au_reset 0 1 "869559"
AU_UPGRADE=upgrade_fail; rc="$(au_run)"
[[ "$rc" == 1 && "$(nrestarts)" == 1 ]] || { echo "FAIL 7h: dead service not recovered (restarts=$(nrestarts) rc=$rc)" >&2; exit 1; }

# 7i no new release but service is down -> start it, no rollback
au_reset 0 1 "869559"
AU_UPGRADE=upgrade_noop; rc="$(au_run)"
[[ "$rc" == 1 && "$(nrestarts)" == 1 && "$(cat "$BIN/falcon-pl-node")" == node-2.11.3 ]] || { echo "FAIL 7i: dead service with no release (restarts=$(nrestarts) rc=$rc)" >&2; exit 1; }

# 7j stall probe: our tip AND best peer tip flat -> defer, do not even run the upgrade
export FALCON_AUTOUPGRADE_STALL_PROBE_SECS=1
au_reset 1 1 "869559 869559" "869559 869559"
AU_UPGRADE=upgrade_new; rc="$(au_run)"
[[ "$rc" == 0 && ! -s "$UPGRADE_CALLS" && "$(nrestarts)" == 0 && "$(cat "$BIN/falcon-pl-node")" == node-2.11.3 ]] || { echo "FAIL 7j: upgrade ran mid-stall (calls=$(cat "$UPGRADE_CALLS") rc=$rc)" >&2; exit 1; }
# 7j2 idle healthy chain (flat tips, has_work=false): load-driven blocks, must NOT defer
au_reset 1 1 "869559 869559 869559" "869559 869559 869559"
AU_WORK=false
AU_UPGRADE=upgrade_new; rc="$(au_run)"
[[ "$(cat "$UPGRADE_CALLS")" == new && "$(cat "$BIN/falcon-pl-node")" == node-2.11.4 && "$(nrestarts)" == 0 ]] || { echo "FAIL 7j2: idle chain deferred the upgrade (calls=$(cat "$UPGRADE_CALLS") rc=$rc)" >&2; exit 1; }
# 7k stall probe: we are flat but peers advance (we are the laggard) -> proceed
au_reset 1 1 "869556 869556 869556 869560" "869559 869559 869560 869560"
AU_UPGRADE=upgrade_new; rc="$(au_run)"
[[ "$(cat "$UPGRADE_CALLS")" == new && "$(cat "$BIN/falcon-pl-node")" == node-2.11.4 ]] || { echo "FAIL 7k: lagging seat must still upgrade (calls=$(cat "$UPGRADE_CALLS") rc=$rc)" >&2; exit 1; }
# 7l stall probe: chain advancing -> proceed
au_reset 1 1 "869559 869561 869562" "869559 869561 869562"
AU_UPGRADE=upgrade_new; rc="$(au_run)"
[[ "$(cat "$UPGRADE_CALLS")" == new && "$rc" == 0 ]] || { echo "FAIL 7l: moving chain must upgrade (rc=$rc)" >&2; exit 1; }
# 7m stall probe: node down -> probe does not block recovery
au_reset 0 1 "869559"
AU_UPGRADE=upgrade_noop; rc="$(au_run)"
[[ "$(cat "$UPGRADE_CALLS")" == noop && "$(nrestarts)" == 1 ]] || { echo "FAIL 7m: probe blocked a down node" >&2; exit 1; }
export FALCON_AUTOUPGRADE_STALL_PROBE_SECS=0
grep -q 'treating as a chain stall, not a bad binary' "$INSTALLER" || { echo "FAIL 7: stall log line missing" >&2; exit 1; }

echo "PASS: all installer tests (Items #1, #8, #13, 2.10.1 autoupgrade default + adopt, 2.11.4 flat-tip stall) succeeded"
