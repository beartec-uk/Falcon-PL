#!/usr/bin/env bash
# Falcon PL public testnet 2300: one-command node installer and manager.
#
#   curl -fsSL https://falcon-fpl.com/install.sh | bash                          # observer (non-validator) node
#   curl -fsSL https://falcon-fpl.com/install.sh | bash -s -- --validator --id myname --contact you@example.com
#
# After install the same script is available as `falcon-node`:
#   falcon-node status | balance | dash | web | logs | start | stop | restart | upgrade | validator | heartbeat | uninstall [--purge]
#
# Release channels (opt-in beta; the default is stable and unchanged):
#   ... | bash -s -- --channel beta            # install the newest signed BETA prerelease
#   falcon-node upgrade --channel beta         # switch an existing node to beta
#   falcon-node upgrade --channel stable       # switch back to the latest stable release
#   falcon-node upgrade                        # stay on the channel recorded at install (default stable)
#
# Dashboards (read-only; no keys are read):
#   falcon-node dash      # live terminal dashboard (q quits)
#   falcon-node web       # browser dashboard on 127.0.0.1:19480; prints the SSH tunnel command for your laptop
#   falcon-node balance   # one line: liquid FPL, bonded, pending rewards, unbonding
#
# What it does (idempotent; safe to re-run):
#   1. Checks OS (Linux), arch (x86_64), glibc, tools, disk.
#   2. Downloads the release (falcon-pl-node, falcon-pl-ctl), verifies the minisign signature on SHA256SUMS, then SHA256.
#   3. Generates the node key LOCALLY (keys/ is 0700). keys/pl_keys.json holds PUBLIC keys only ({scheme, publics});
#      each secret is in keys/<account>.json (0600), never leaves this machine and is never printed.
#   4. Writes a systemd unit (system unit as root, user unit otherwise; `--no-systemd` for containers),
#      peers over the public seed (no Tailscale), starts a non-validator node and waits for sync.
#   5. --validator: builds the application (validator public key + proof of possession, 2.9.62+),
#      waits for Scott's admission approval, waits for the bond account to be funded (>= MIN_BOND_NEW),
#      submits the Bond (signed locally), then switches the node to the validator id once the seat is active.
#
# Nothing here sends funds on its own except the Bond in validator mode, and only after approval + funding
# (and an interactive confirmation unless --yes). Docs: docs/PUBLIC_NODE.md in the Falcon-PL repo.
set -euo pipefail

INSTALLER_VERSION="2.11.4"
RELEASE_REPO="${FALCON_RELEASE_REPO:-beartec-jpg/falcon-pl-releases}"
# Pinned minisign public key of the Falcon PL release key (key id 8ACFFC29EE09FAEC).
# A valid SHA256SUMS.minisig is REQUIRED. FALCON_MINISIGN_PUBKEY="" disables the check, but only together
# with a custom FALCON_RELEASE_BASE (local devnet rehearsals).
RELEASE_MINISIGN_PUBKEY_PINNED="RWTs+gnuKfzPik0Xbcf+m1hD/JrCUnWqaD/OAZFZEY2fcNc90D67mZlM"
RELEASE_MINISIGN_PUBKEY="${FALCON_MINISIGN_PUBKEY-$RELEASE_MINISIGN_PUBKEY_PINNED}"
MINISIGN_TARBALL_URL="${FALCON_MINISIGN_URL:-https://github.com/jedisct1/minisign/releases/download/0.11/minisign-0.11-linux.tar.gz}"
MINISIGN_TARBALL_SHA256="${FALCON_MINISIGN_SHA256:-f0a0954413df8531befed169e447a66da6868d79052ed7e892e50a4291af7ae0}"
NETWORK_PROFILE="network-2300.env"

# ---------- output helpers ----------
if [[ -t 1 ]]; then B=$'\e[1m'; G=$'\e[32m'; Y=$'\e[33m'; R=$'\e[31m'; N=$'\e[0m'; else B=; G=; Y=; R=; N=; fi
say()  { printf '%s\n' "${B}falcon-node:${N} $*"; }
ok()   { printf '%s\n' "${G}ok${N} $*"; }
warn() { printf '%s\n' "${Y}warn${N} $*" >&2; }
die()  { printf '%s\n' "${R}error${N} $*" >&2; exit 1; }

# ---------- defaults / args ----------
CMD="install"
ROLE="observer"
VAL_ID=""
BOND_ACCOUNT=""
CONTACT=""
PAYOUT=""
WANT_VERSION="${FALCON_VERSION:-}"
CHANNEL="${FALCON_CHANNEL:-}"   # stable | beta; empty = recorded channel, else stable
FALCON_HOME="${FALCON_HOME:-}"
LISTEN="${FALCON_LISTEN:-127.0.0.1:19400}"
USE_SYSTEMD="auto"
START=1
YES=0
PURGE=0
WATCHER=0
SYNC_TIMEOUT="${FALCON_SYNC_TIMEOUT:-900}"
SYNC_LAG_OK="${FALCON_SYNC_LAG_OK:-10}"
FORCE_VERSION=0
WAIT=1
POLL_SECS="${FALCON_POLL_SECS:-60}"

usage() {
  sed -n '2,30p' "${BASH_SOURCE[0]:-/dev/null}" 2>/dev/null | sed 's/^# \{0,1\}//' || true
  cat <<USAGE
Commands: install (default) | status | balance | dash | web | logs | start | stop | restart | upgrade | autoupgrade [on|off|status|run] | adopt | validator | heartbeat | uninstall
Options:
  --validator            validator mode (application -> approval -> funding -> bond -> activation)
  --id NAME              validator id (lowercase letters, digits, '-', 3-32 chars)
  --bond-account NAME    account that pays the bond (default: <id>-bond, key generated locally)
  --contact TEXT         contact for the application (email / GitHub / X handle)
  --payout ACCOUNT       optional: after each epoch, send this seat's spendable FPL to ACCOUNT
  --payout-address ACCOUNT  same as --payout; from the seat-payout height the node also sets it on
                         chain (SetSeatPayout, seat key) so validator rewards land in ACCOUNT directly
  --watcher              also install an hourly heartbeat timer (watcher presence; costs the 2 FPL fee per hour)
  --version X.Y.Z        release to install (default: latest)
  --channel stable|beta  stable (default) = latest release; beta = newest signed prerelease (opt-in, testing)
  --home DIR             install dir (default: /var/lib/falcon-pl-2300 as root, ~/falcon-pl-2300 otherwise)
  --listen ADDR          local node listen address (default 127.0.0.1:19400)
  --no-systemd           run the node with nohup + pidfile (containers / no systemd)
  --no-start             install only
  --no-wait              validator: do not block waiting for approval/funding (re-run 'falcon-node validator')
  --sync-timeout SECS    wait this long for sync (default 900)
  --force-version        install even if the release version differs from the live network
  --purge                with uninstall: also delete keys and data (irreversible)
  --web-listen IP:PORT   web: dashboard address (default 127.0.0.1:19480)
  --allow-remote         web: allow a non-loopback --web-listen (no auth; trusted networks only)
  --account NAME         balance: account to show (default: this node's id)
  --yes                  non-interactive (assume yes to confirmations)
  --no-autoupgrade       install/upgrade/adopt: leave the auto-upgrade timer off (default: on, hourly, signed releases only)
  --unit NAME            adopt: existing systemd unit of a hand-built node to bring under falcon-node
                         (keeps its keys, data, id, peers and unit; only ExecStart is redirected via a drop-in)
USAGE
}

AUTOUPGRADE_ACTION="status"
NO_AUTOUPGRADE=0
ADOPT_UNIT=""
ADOPTED=0
AUTOUPGRADE_JITTER_SECS="${FALCON_AUTOUPGRADE_JITTER_SECS:-}"
SAVED_NODE_ID=""

parse_args() {
  if [[ $# -gt 0 && "$1" != -* ]]; then CMD="$1"; shift; fi
  if [[ "$CMD" == "autoupgrade" && $# -gt 0 && "$1" != -* ]]; then AUTOUPGRADE_ACTION="$1"; shift; fi
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --jitter) AUTOUPGRADE_JITTER_SECS="${2:-0}"; shift 2 ;;
      --validator) ROLE="validator"; shift ;;
      --observer) ROLE="observer"; shift ;;
      --id) VAL_ID="${2:-}"; shift 2 ;;
      --bond-account) BOND_ACCOUNT="${2:-}"; shift 2 ;;
      --contact) CONTACT="${2:-}"; shift 2 ;;
      --payout|--payout-address) PAYOUT="${2:-}"; shift 2 ;;
      --watcher) WATCHER=1; shift ;;
      --version) WANT_VERSION="${2#v}"; shift 2 ;;
      --channel) CHANNEL="${2:-}"; shift 2 ;;
      --home) FALCON_HOME="${2:-}"; shift 2 ;;
      --listen) LISTEN="${2:-}"; shift 2 ;;
      --no-systemd) USE_SYSTEMD="no"; shift ;;
      --no-start) START=0; shift ;;
      --no-wait) WAIT=0; shift ;;
      --sync-timeout) SYNC_TIMEOUT="${2:-}"; shift 2 ;;
      --force-version) FORCE_VERSION=1; shift ;;
      --purge) PURGE=1; shift ;;
      --allow-remote) ALLOW_REMOTE=1; shift ;;
      --web-listen) WEB_LISTEN="${2:-}"; shift 2 ;;
      --account) BAL_ACCOUNT="${2:-}"; shift 2 ;;
      --yes|-y) YES=1; shift ;;
      --no-autoupgrade) NO_AUTOUPGRADE=1; shift ;;
      --unit) ADOPT_UNIT="${2:-}"; shift 2 ;;
      -h|--help) usage; exit 0 ;;
      *) die "unknown argument: $1 (see --help)" ;;
    esac
  done
}

# ---------- environment ----------
IS_ROOT=0; [[ "$(id -u)" -eq 0 ]] && IS_ROOT=1
SVC_USER="falcon-pl"
UNIT="falcon-pl-node"

resolve_home() {
  if [[ -z "$FALCON_HOME" ]]; then
    # Re-use an existing install if we are running as its manager copy.
    local src="${BASH_SOURCE[0]:-}" self_dir
    if [[ -n "$src" && -e "$src" ]]; then src="$(readlink -f "$src" 2>/dev/null || echo "$src")"; fi
    self_dir="$(cd "$(dirname "${src:-.}")" 2>/dev/null && pwd || true)"
    if [[ -n "$self_dir" && -f "$self_dir/../config/node.env" ]]; then
      FALCON_HOME="$(cd "$self_dir/.." && pwd)"
    elif [[ $IS_ROOT -eq 1 ]]; then
      FALCON_HOME="/var/lib/falcon-pl-2300"
    else
      FALCON_HOME="$HOME/falcon-pl-2300"
    fi
  fi
  BIN="$FALCON_HOME/bin"; KEYS="$FALCON_HOME/keys"; DATA="$FALCON_HOME/data"; LOGS="$FALCON_HOME/logs"
  CONF="$FALCON_HOME/config"; RUN="$FALCON_HOME/run"; VALDIR="$FALCON_HOME/validator"
  NODE_ENV="$CONF/node.env"; NET_ENV="$CONF/$NETWORK_PROFILE"
  # 2.10.1: an adopted (hand-built) seat keeps its own unit name and service user.
  if [[ -f "$NODE_ENV" ]]; then
    local u; u="$(kv_get "$NODE_ENV" UNIT)"
    if [[ -n "$u" ]]; then UNIT="$u"; AUTOU_UNIT="$u-autoupgrade"; fi
    if [[ "$(kv_get "$NODE_ENV" ADOPTED)" == "1" ]]; then ADOPTED=1; fi
    u="$(kv_get "$NODE_ENV" SVC_USER)"
    if [[ -n "$u" ]]; then SVC_USER="$u"; fi
  fi
  return 0
}

have() { command -v "$1" >/dev/null 2>&1; }

systemd_mode() {
  # Echo: system | user | none
  if [[ "$USE_SYSTEMD" == "no" ]]; then echo none; return; fi
  if [[ -f "$CONF/node.env" ]] && grep -q '^SERVICE_MODE=' "$CONF/node.env"; then
    kv_get "$CONF/node.env" SERVICE_MODE; return
  fi
  if ! have systemctl || [[ ! -d /run/systemd/system ]]; then echo none; return; fi
  if [[ $IS_ROOT -eq 1 ]]; then echo system; return; fi
  if systemctl --user show-environment >/dev/null 2>&1; then echo user; else echo none; fi
}

sctl() { if [[ "$SERVICE_MODE" == "user" ]]; then systemctl --user "$@"; else systemctl "$@"; fi; }

as_svc() {
  # Run a command as the service user (system mode) so files keep the right owner.
  if [[ $IS_ROOT -eq 1 && "$SERVICE_MODE" == "system" ]] && id "$SVC_USER" >/dev/null 2>&1; then
    if have runuser; then runuser -u "$SVC_USER" -- "$@"; else su -s /bin/sh "$SVC_USER" -c "$(printf '%q ' "$@")"; fi
  else
    "$@"
  fi
}

# KEY=VALUE files are parsed, never sourced.
kv_get() { # file key
  local line
  line="$(grep -E "^$2=" "$1" 2>/dev/null | tail -1 || true)"
  printf '%s' "${line#*=}"
}
service_user_for_env() {
  local u="" up=""
  if [[ "${SERVICE_MODE:-}" == "system" ]]; then
    up="$(unit_path 2>/dev/null || true)"
    if [[ -n "$up" && -f "$up" ]]; then
      u="$(grep -E '^User=' "$up" 2>/dev/null | tail -1 | cut -d= -f2- || true)"
    fi
    [[ -n "$u" ]] || u="${SVC_USER:-falcon-pl}"
  fi
  printf '%s' "$u"
}

ensure_node_env_readable() {
  local f="${1:-${NODE_ENV:-}}"
  [[ -n "$f" && -f "$f" ]] || return 0
  local d; d="$(dirname "$f")"
  chmod 0755 "$d" 2>/dev/null || true
  # Recover NODE_ID if missing so upgrades/re-runs never leave node.env without NODE_ID.
  local cur_id; cur_id="$(kv_get "$f" NODE_ID)"
  if [[ -z "$cur_id" ]]; then
    local rec_id="${SAVED_NODE_ID:-}"
    if [[ -z "$rec_id" && -n "${VALDIR:-}" && -f "$VALDIR/state" ]]; then
      local vst; vst="$(kv_get "$VALDIR/state" STAGE)"
      if [[ "$vst" == "bonded" || "$vst" == "active" ]]; then
        rec_id="$(kv_get "$VALDIR/state" ID)"
      fi
    fi
    [[ -n "$rec_id" ]] || rec_id="$(kv_get "$f" OBSERVER_ID)"
    if [[ -z "$rec_id" && -n "${DATA:-}" && -d "$DATA" ]]; then
      local snap
      for snap in "$DATA"/*.json; do
        [[ -f "$snap" && "$snap" != *.tmp.json ]] || continue
        rec_id="$(basename "$snap" .json)"
        break
      done
    fi
    if [[ -n "$rec_id" ]]; then
      printf 'NODE_ID=%s\n' "$rec_id" >>"$f"
    fi
  fi
  local u; u="$(service_user_for_env)"
  if [[ $IS_ROOT -eq 1 && -n "$u" && "$u" != "root" ]] && id "$u" >/dev/null 2>&1; then
    chown "$u:$u" "$d" "$f" 2>/dev/null || true
    chmod 0644 "$f" 2>/dev/null || true
  else
    chmod 0644 "$f" 2>/dev/null || true
  fi
}

kv_set() { # file key value
  local f="$1" k="$2" v="$3" tmp
  [[ "$v" =~ ^[A-Za-z0-9.,:/@_+-]*$ ]] || die "refusing unsafe value for $k"
  mkdir -p "$(dirname "$f")"
  touch "$f"; tmp="$(mktemp "$f.XXXX")"
  grep -vE "^$k=" "$f" >"$tmp" || true
  printf '%s=%s\n' "$k" "$v" >>"$tmp"
  # Keep the existing inode. mv would replace a falcon-pl:640 node.env
  # with a root:600 file and the service exits 78/CONFIG.
  cat "$tmp" >"$f"
  rm -f "$tmp"
  if [[ "$f" == "${NODE_ENV:-}" || "$f" == */node.env ]]; then
    ensure_node_env_readable "$f"
  fi
}
validate_profile() {
  local f="$1" n=0 line
  while IFS= read -r line || [[ -n "$line" ]]; do
    [[ -z "$line" || "$line" == \#* ]] && continue
    [[ "$line" =~ ^[A-Z0-9_]+=[A-Za-z0-9.,:/@_+-]*$ ]] || die "bad line in network profile: $line"
    n=$((n + 1))
  done <"$f"
  [[ $n -ge 10 ]] || die "network profile looks empty"
  [[ "$(kv_get "$f" NETWORK_ID)" =~ ^[0-9]+$ ]] || die "network profile: NETWORK_ID missing"
}
net() { kv_get "$NET_ENV" "$1"; }

# ---------- JSON helpers (python3 if present, grep fallback for flat numeric fields) ----------
json_num() { # file field  -> first top-level-ish numeric value
  grep -oE "\"$2\": *[0-9]+" "$1" 2>/dev/null | head -1 | grep -oE '[0-9]+$' || true
}
json_str() {
  grep -oE "\"$2\": *\"[^\"]*\"" "$1" 2>/dev/null | head -1 | sed -E 's/.*: *"([^"]*)"/\1/' || true
}
py() { have python3 || die "python3 is required for validator mode"; python3 "$@"; }

# ---------- preflight ----------
preflight() {
  say "preflight"
  [[ "$(uname -s)" == "Linux" ]] || die "Linux only (got $(uname -s))"
  local arch; arch="$(uname -m)"
  case "$arch" in
    x86_64|amd64) ;;
    aarch64|arm64) die "arm64 binaries are not published yet (x86_64 only). Build from source or use an x86_64 host." ;;
    *) die "unsupported architecture: $arch" ;;
  esac
  for t in curl sha256sum tar gzip grep sed awk mktemp; do have "$t" || die "missing required tool: $t"; done
  # glibc floor (binaries are built on Ubuntu 22.04; actual floor is glibc_min in BUILDINFO.txt, 2.34)
  if have getconf; then
    local g; g="$(getconf GNU_LIBC_VERSION 2>/dev/null | awk '{print $2}')"
    if [[ -n "$g" ]] && [[ "$(printf '%s\n%s\n' "$g" "2.34" | sort -V | head -1)" != "2.34" ]]; then
      die "glibc $g is too old (need >= 2.34: Ubuntu 22.04+, Debian 12+, RHEL 9+)"
    fi
  fi
  local parent="$FALCON_HOME"; while [[ ! -d "$parent" ]]; do parent="$(dirname "$parent")"; done
  local free_mb; free_mb="$(df -Pm "$parent" | awk 'NR==2{print $4}')"
  [[ "${free_mb:-0}" -ge 4096 ]] || die "need >= 4 GB free in $parent (have ${free_mb} MB)"
  local mem_mb; mem_mb="$(awk '/MemTotal/{print int($2/1024)}' /proc/meminfo 2>/dev/null || echo 0)"
  [[ "$mem_mb" -ge 1800 ]] || warn "only ${mem_mb} MB RAM; 2 GB+ recommended (4 GB for validators)"
  if [[ "$ROLE" == "validator" ]]; then
    [[ "$mem_mb" -ge 3500 ]] || warn "validators should have >= 4 GB RAM and 2+ vCPU"
    have python3 || die "validator mode needs python3 (apt install python3)"
  fi
  if grep -qw avx512f /proc/cpuinfo 2>/dev/null; then :; fi  # binaries never need AVX-512 (portable build)
  ok "Linux $arch, ${mem_mb} MB RAM, ${free_mb} MB free"
}

# ---------- download + verify ----------
REL_TAG=""
resolve_release_tag() { # sets REL_TAG: the pinned --version, or the tag "latest" points at right now
  if [[ -n "${FALCON_RELEASE_BASE:-}" ]]; then REL_TAG="custom"; return; fi
  if [[ -n "$WANT_VERSION" ]]; then REL_TAG="v$WANT_VERSION"; return; fi
  if [[ "$CHANNEL" == "beta" ]]; then
    # Newest published (non-draft) release. Signature + checksums are verified exactly as for stable.
    local j; j="$(curl -fsSL --retry 3 --connect-timeout 15 -H 'Accept: application/vnd.github+json' \
      "https://api.github.com/repos/$RELEASE_REPO/releases?per_page=30" 2>/dev/null || true)"
    # Newest published (non-draft) release, prerelease or not: once a beta is
    # promoted to stable (or a newer stable ships) the beta channel follows it
    # instead of staying on an older prerelease. GitHub lists newest first.
    REL_TAG="$(printf '%s' "$j" | tr -d '\n' | grep -oE '"tag_name": *"v[^"]+"[^{}]*"draft": *false' \
      | head -1 | sed -E 's/^"tag_name": *"([^"]+)".*/\1/')"
    [[ -n "$REL_TAG" ]] || die "no published release found in $RELEASE_REPO (try again later, or use --version)"
    return
  fi
  local u; u="$(curl -fsSIL -o /dev/null -w '%{url_effective}' --retry 3 --connect-timeout 15 \
    "https://github.com/$RELEASE_REPO/releases/latest" 2>/dev/null || true)"
  if [[ "$u" =~ /releases/tag/(v[0-9][0-9A-Za-z.+-]*)$ ]]; then REL_TAG="${BASH_REMATCH[1]}"; else REL_TAG=""; fi
}

release_base() {
  if [[ -n "${FALCON_RELEASE_BASE:-}" ]]; then echo "${FALCON_RELEASE_BASE%/}"; return; fi
  if [[ -n "$REL_TAG" ]]; then
    # Pin every download to one tag, so a release published mid-install cannot mix files.
    echo "https://github.com/$RELEASE_REPO/releases/download/$REL_TAG"
  else
    echo "https://github.com/$RELEASE_REPO/releases/latest/download"
  fi
}

fetch() { # url dest
  curl -fsSL --proto '=https,file,http' --retry 3 --connect-timeout 15 -o "$2" "$1"
}

install_minisign_binary() {
  local mtmp dest_dir="${FALCON_MINISIGN_DEST_DIR:-/usr/local/bin}" dest
  if [[ -z "${FALCON_MINISIGN_DEST_DIR:-}" && $EUID -ne 0 && ! -w /usr/local/bin ]]; then
    dest_dir="$HOME/.local/bin"
  fi
  mkdir -p "$dest_dir" 2>/dev/null || return 1
  dest="$dest_dir/minisign"
  export PATH="$dest_dir:$PATH"
  mtmp="$(mktemp -d)"
  say "downloading prebuilt minisign 0.11 ($MINISIGN_TARBALL_URL)"
  if ! fetch "$MINISIGN_TARBALL_URL" "$mtmp/minisign-0.11-linux.tar.gz"; then
    rm -rf "$mtmp"
    return 1
  fi
  if ! printf '%s  %s\n' "$MINISIGN_TARBALL_SHA256" "$mtmp/minisign-0.11-linux.tar.gz" | sha256sum -c --quiet -; then
    warn "minisign tarball SHA-256 checksum mismatch"
    rm -rf "$mtmp"
    return 1
  fi
  if ! tar -xzf "$mtmp/minisign-0.11-linux.tar.gz" -C "$mtmp" || [[ ! -f "$mtmp/minisign-linux/x86_64/minisign" ]]; then
    warn "minisign tarball missing minisign-linux/x86_64/minisign"
    rm -rf "$mtmp"
    return 1
  fi
  cp "$mtmp/minisign-linux/x86_64/minisign" "$dest" || { rm -rf "$mtmp"; return 1; }
  chmod 0755 "$dest" || { rm -rf "$mtmp"; return 1; }
  rm -rf "$mtmp"
  have minisign || return 1
  ok "installed minisign 0.11 to $dest"
}

download_release() {
  resolve_release_tag
  local base tmp; base="$(release_base)"
  tmp="$(mktemp -d)"; DL="$tmp"
  say "release tag: ${REL_TAG:-latest (tag not resolved)} (installer $INSTALLER_VERSION)"
  say "downloading release from $base"
  fetch "$base/SHA256SUMS" "$tmp/SHA256SUMS" || die "cannot download SHA256SUMS from $base"
  if [[ -n "$RELEASE_MINISIGN_PUBKEY" ]]; then
    if ! have minisign; then
      if [[ $EUID -eq 0 ]] && have apt-get; then
        say "installing minisign (to verify the release signature)"
        DEBIAN_FRONTEND=noninteractive apt-get install -y -qq minisign >/dev/null 2>&1 \
          || { apt-get update -qq >/dev/null 2>&1 && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq minisign >/dev/null 2>&1; } \
          || install_minisign_binary \
          || die "could not install minisign; install it (https://jedisct1.github.io/minisign/) and re-run"
      else
        install_minisign_binary \
          || die "minisign is required to verify the release signature: sudo apt install minisign (or https://jedisct1.github.io/minisign/), then re-run"
      fi
    fi
    fetch "$base/SHA256SUMS.minisig" "$tmp/SHA256SUMS.minisig" || die "missing SHA256SUMS.minisig"
    minisign -Vm "$tmp/SHA256SUMS" -P "$RELEASE_MINISIGN_PUBKEY" -x "$tmp/SHA256SUMS.minisig" >/dev/null \
      || die "SIGNATURE CHECK FAILED for SHA256SUMS: do not install"
    ok "SHA256SUMS signature verified (minisign)"
  else
    [[ -n "${FALCON_RELEASE_BASE:-}" ]] || die "the signature check can only be disabled with a custom FALCON_RELEASE_BASE"
    warn "signature check DISABLED (FALCON_MINISIGN_PUBKEY empty, custom release base): SHA256 only"
  fi
  local tarname; tarname="$(grep -oE 'falcon-pl-[0-9][0-9.]*-linux-x86_64\.tar\.gz' "$tmp/SHA256SUMS" | head -1)"
  [[ -n "$tarname" ]] || die "SHA256SUMS lists no linux-x86_64 tarball"
  REL_VERSION="$(sed -E 's/falcon-pl-([0-9.]+)-linux.*/\1/' <<<"$tarname")"
  local f
  for f in "$tarname" install-falcon-node.sh "$NETWORK_PROFILE" BUILDINFO.txt; do
    fetch "$base/$f" "$tmp/$f" || die "cannot download $f"
  done
  (cd "$tmp" && grep -E "  ($tarname|install-falcon-node.sh|$NETWORK_PROFILE|BUILDINFO.txt)\$" SHA256SUMS | sha256sum -c --quiet -) \
    || die "CHECKSUM MISMATCH: do not install"
  tar -xzf "$tmp/$tarname" -C "$tmp"
  local d="$tmp/falcon-pl-$REL_VERSION"
  (cd "$d" && grep -E '  falcon-pl-(node|ctl)$' "$tmp/SHA256SUMS" | sha256sum -c --quiet -) || die "binary checksum mismatch"
  validate_profile "$tmp/$NETWORK_PROFILE"
  NET_ENV="$tmp/$NETWORK_PROFILE"   # use the verified profile until install_files copies it
  ok "release ${REL_TAG:-$REL_VERSION} (product $REL_VERSION) verified ($(grep -E '  falcon-pl-node$' "$tmp/SHA256SUMS" | cut -c1-16)…)"
}

# ---------- public peering available? ----------
require_public_seed() { # the shipped network profile decides; empty SEEDS = no public peering yet
  if [[ -z "$(net SEEDS)" || -z "$(net STATUS_RPC)" ]]; then
    die "this release's network profile has no public seed yet (the public endpoints are moving to new hosts). Nothing was installed. Watch $(net SITE)/validator for the next release."
  fi
}

# ---------- live network check ----------
public_status() { # dest file; uses the downloaded/installed ctl
  local ctl="$1" out="$2" rpc; rpc="$(net STATUS_RPC)"
  timeout 40 "$ctl" --addr "$rpc" status >"$out" 2>/dev/null
}

# Product versions that can roll together without isolating peers.
# 2.9.x with x >= 60 (no leading zero), or any later 2.x (2.10, 2.11, 2.12, …).
# Those later 2.x binaries still advertise HELLO_WIRE_VERSION 2.9.100, so a
# newer GitHub release can follow a live 2.x network without --force-version.
wire_compatible() {
  [[ "$1" =~ ^([0-9]+)\.([0-9]+)\.(0|[1-9][0-9]*)$ ]] || return 1
  local maj="${BASH_REMATCH[1]}" min="${BASH_REMATCH[2]}" patch="${BASH_REMATCH[3]}"
  if [[ "$maj" -eq 2 && "$min" -eq 9 && "$patch" -ge 60 ]]; then
    return 0
  fi
  if [[ "$maj" -eq 2 && "$min" -ge 10 ]]; then
    return 0
  fi
  return 1
}

check_network_version() {
  local ctl="$1" st; st="$(mktemp)"
  if public_status "$ctl" "$st"; then
    LIVE_VERSION="$(json_str "$st" product_version)"
    LIVE_TIP="$(json_num "$st" tip_height)"
    ok "public network reachable: product $LIVE_VERSION, tip $LIVE_TIP (via $(net STATUS_RPC))"
    if [[ -n "$LIVE_VERSION" && "$LIVE_VERSION" != "$REL_VERSION" ]]; then
      if wire_compatible "$REL_VERSION" && wire_compatible "$LIVE_VERSION"; then
        ok "release $REL_VERSION peers with the network's $LIVE_VERSION (2.9.x >= 2.9.60 and later 2.x are wire-compatible)"
        # Wire-compatible is not consensus-current: an older pinned release can
        # miss later rule gates. Say so instead of passing silently.
        if [[ "$(printf '%s\n%s\n' "$REL_VERSION" "$LIVE_VERSION" | sort -V | head -1)" == "$REL_VERSION" && "$REL_VERSION" != "$LIVE_VERSION" ]]; then
          warn "release $REL_VERSION is OLDER than the network's $LIVE_VERSION; upgrade soon (later rule gates may need it)"
        fi
      elif [[ "$CHANNEL" == "beta" ]]; then
        warn "beta $REL_VERSION is newer than the network's $LIVE_VERSION; any 2.9.x >= 2.9.60 peers with it (beta channel)"
      elif [[ $FORCE_VERSION -eq 1 ]]; then
        warn "release $REL_VERSION != live $LIVE_VERSION (peers refuse mismatched versions); continuing (--force-version)"
      else
        die "release $REL_VERSION != live network $LIVE_VERSION; peers refuse mismatched versions. Use --version $LIVE_VERSION (or --force-version)."
      fi
    fi
  else
    warn "public status endpoint $(net STATUS_RPC) not reachable right now (TCP). The node will keep retrying."
  fi
  rm -f "$st"
}

# ---------- install files ----------
ensure_user() {
  [[ $IS_ROOT -eq 1 && "$SERVICE_MODE" == "system" ]] || return 0
  if ! id "$SVC_USER" >/dev/null 2>&1; then
    useradd --system --home-dir "$FALCON_HOME" --shell /usr/sbin/nologin "$SVC_USER" 2>/dev/null \
      || adduser --system --home "$FALCON_HOME" --no-create-home "$SVC_USER" \
      || die "cannot create user $SVC_USER"
    ok "created system user $SVC_USER"
  fi
}

install_files() {
  mkdir -p "$BIN" "$KEYS" "$DATA" "$LOGS" "$CONF" "$RUN" "$VALDIR"
  chmod 700 "$KEYS" "$VALDIR"
  local d="$DL/falcon-pl-$REL_VERSION" changed=0 b
  for b in falcon-pl-node falcon-pl-ctl; do
    if [[ -f "$BIN/$b" ]] && cmp -s "$d/$b" "$BIN/$b"; then continue; fi
    [[ -f "$BIN/$b" ]] && cp -p "$BIN/$b" "$BIN/$b.prev"
    install -m 0755 "$d/$b" "$BIN/$b.new" && mv -f "$BIN/$b.new" "$BIN/$b"
    changed=1
  done
  install -m 0755 "$DL/install-falcon-node.sh" "$BIN/falcon-node"
  install -m 0644 "$DL/$NETWORK_PROFILE" "$CONF/$NETWORK_PROFILE"
  NET_ENV="$CONF/$NETWORK_PROFILE"
  install -m 0644 "$DL/BUILDINFO.txt" "$CONF/BUILDINFO.txt"
  install -m 0644 "$DL/SHA256SUMS" "$CONF/SHA256SUMS"
  BIN_CHANGED=$changed
  if [[ $IS_ROOT -eq 1 && "$SERVICE_MODE" == "system" ]]; then
    chown -R "$SVC_USER:$SVC_USER" "$FALCON_HOME"
    if [[ $ADOPTED -ne 1 || ! -e /usr/local/bin/falcon-node || "$(readlink -f /usr/local/bin/falcon-node)" == "$BIN/falcon-node" ]]; then
      ln -sf "$BIN/falcon-node" /usr/local/bin/falcon-node
    fi
  else
    mkdir -p "$HOME/.local/bin" && ln -sf "$BIN/falcon-node" "$HOME/.local/bin/falcon-node" || true
  fi
  ok "binaries in $BIN ($( [[ $changed -eq 1 ]] && echo updated || echo unchanged ))"
}

pubkey_of() { # id -> public key hex from keys/pl_keys.json (public data only)
  tr -d '\n ' <"$KEYS/pl_keys.json" | grep -oE "\"$1\":\"[0-9a-fA-F]+\"" | head -1 | sed -E 's/.*:"([0-9a-fA-F]+)"/\1/'
}
fingerprint() { printf '%s' "$1" | sha256sum | cut -c1-16; }

gen_key() { # account
  local acct="$1"
  if [[ -f "$KEYS/pl_keys.json" ]] && [[ -n "$(pubkey_of "$acct")" ]] && [[ -f "$KEYS/$acct.json" ]]; then
    return 0
  fi
  as_svc "$BIN/falcon-pl-ctl" gen-wallet --keys-dir "$KEYS" --account "$acct" --scheme "$(net SCHEME)" >/dev/null
  chmod 600 "$KEYS/$acct.json" 2>/dev/null || true
  [[ -n "$(pubkey_of "$acct")" ]] || die "key generation for $acct failed"
  ok "generated key for '$acct' locally (fingerprint $(fingerprint "$(pubkey_of "$acct")")); public key in $KEYS/pl_keys.json (safe to share); secret in $KEYS/$acct.json (never share)"
}

ensure_node_config() {
  touch "$NODE_ENV"
  local nid; nid="$(kv_get "$NODE_ENV" NODE_ID)"
  if [[ -z "$nid" ]]; then
    local h; h="$(hostname 2>/dev/null | tr '[:upper:]' '[:lower:]' | tr -cd 'a-z0-9-' | cut -c1-12 | sed 's/-*$//')"
    nid="obs-${h:-node}-$(od -An -N3 -tx1 /dev/urandom | tr -d ' \n')"
    kv_set "$NODE_ENV" NODE_ID "$nid"
    kv_set "$NODE_ENV" OBSERVER_ID "$nid"
  fi
  kv_set "$NODE_ENV" LISTEN "$LISTEN"
  kv_set "$NODE_ENV" SERVICE_MODE "$SERVICE_MODE"
  kv_set "$NODE_ENV" VERSION "$REL_VERSION"
  [[ -n "$(kv_get "$NODE_ENV" NODE_ROLE)" ]] || kv_set "$NODE_ENV" NODE_ROLE observer
  gen_key "$(kv_get "$NODE_ENV" NODE_ID)"
  install_qc_profile
  install_ring_publics
  ensure_node_env_readable "$NODE_ENV"
  write_runner
}

# 2.9.78: network 2300 seat key ring (PUBLIC keys only). Seats verify historical
# blocks with these keys from keys/pl_keys.json; until Fix B (702000) a tx from a
# ring-key account counts as key-bound. A joiner without them rejects block
# 670269 (watcher-eth eth_exec_headers): "key bind: account has no key and this
# key is not committed". Add-only merge: never replaces an id already present.
RING_PUBLICS_2300='{"scheme":"falcon-512","publics":{"alice":"092b022f852895255fae07f08adb8fb1e242266e21bd7a39c997aaeedd7e75fd09901a29b295b5b4309efa5c1c76294756f384d4adc54ea3dd5a4ed77687c49a06ba4bd6a4ed1d67003c5046e3162ae5aa829891a52a91b5358215114f784cb93c577553b623c5a463096b49a012d2490ea6b4ed67eacbc428a0b3479d84f21cb44a4bbdeec799ba1338c8e9f471caf284dd84c088d03f4355a4e97cddef6715e73a0984b4a6db249502aa0d941fdec43a1d1d49d8deba93d828b096e4e9479a388787d3e515243768d2989b9242d813088f37573d450179a8309f26031b90988f405042c266c14e7151df94ef5c2d3b7efa78e7a28c07aa99a48c919805948c182e0353ae2af7652e28a70e0d93c7b155d245e9961aed6e0662a07f37b95f9420f8f6c413527fb5fa85705ac0f676f825c9f0da5118dcf557bd95d3b65deb735906d93f89c9b2b65823157d9e1b3854ea185c7474c206b19f627d678dd17757715295800b35b3252156ea228820f927c3b208f31026b4977e6fea6ea020cae90c0c6c1505f3dc128d0f18a1b9b7544a11bc1961dc2de1ae642043eb19777bdee55354ec18b4d1aac23c2b2e783846e25de24e400af08820cd883a30d3b5c74ac96712af386c441191594d500062702861d9bb09d523b502758bd353d243b033d0326539a90eb4b97a8154ad6ed9614a6fd069da5a0366df2fa13df78893d5bf74f01743311bf0451c58403757cf25e120f84c5c95b44ac8f7dd6d68b2ceaf8320dc997e6e804b17d64d958c4a022a881802092171ae587905ae057629e5587d7642f7f706bd32e207a651ed6957b4be69df452c4a1859b237c50585c4d197452ada3368c793622078667a1b9624cf8a877d36b940d6f9a71af226ec146659683202b522656622d28ba15d7968848bd1e3078985f2fa13c9d335a1b04f33b5a8c05ea93b47e49307abbc35c60d9c5366d087e40b4bb9223dfca6a5add60cbd4d9b93424992e52211e854c6aa2af29892021daa0039240cce74bbf6fbcbd19c2d3fc538eacf62b594b266d1aa58c76bc55d83f000d16176fadbf4dfad45e665d5f818212b4968fac24c8b62582ac960c8f024a08702f15c178db13a69392b1e1bd9b708e0de2092bca4809c53bf6b08ae588d53db02655384b667d1577240f6468ffb5a0e27e74d809b82c25ea030db582eed3f22c54b578a52b798df0e43aec00f4575dc1d1de4cff09d174a16c8c2ab3e0416012a3d54c959683015e8543a11d2","bob":"09429005c1e525f10eca44a520238125b8ce042d2d399bc518ca2565388b9e22c25b5a5c22cdbbe864ae91a4549f1ac6cf3c3ec497f49aa28d9a2e70ca0ee91d947e1cc1f7a60a1acc98f7890f8f15fabda7b1db792d0cf989f1201f301510763d08b52f094e73039e1fb71242e3cf8e6e4a49582babd5aab76add922669d67845163337e63f7c6552f35a1678b87d48a0b7498394f9fae6aadf0e5cfe892ad8e0561be5c823bd100435a82f25402b737af57e3911970554c4cd9a8d6ef39fbcf915dc290547c532794227840fdce7807002e157cca98421c23287d946a1459bde2a99e63974267707caeb96520bc32b7592c2dce31e9345f22bd81f260442d1f6c645f58599f6a7e72bb766403ba861d0410c958ef6d899eb4e293f860acc5b1821ee892da3fc2752db2992acbba022b4c7c29df18b6a20b44a14268520f7176513f280068162ab82c787c23ed3280e6137fad547194e985f580d86e7d2bd332c279666c9d72f0922d7d92c6dae5c9aa6da485d981e3e7080aaa2387ec4e00f6fbba1bc72f5c0951f74d438504505b75b444db4bf9854057513bb8bab7e047290518b1cf531c8191473de06aa590b343a874e34d23b20b5cc9a0fe5e34b84d7db895ed8274b0a6301f20887261ac73229c5b04ad47c1c16f2959d88229c200dc410cd3200fd67cafa40c07722498666a0b310a464fa14294f2025c106d40ef23ff171b4f04ea82c713f6b420c8aa7c4fb25dbd8eb487584fa3bc77d5866cd524d1e8112103494ead64492be47284a9834a029d694f961d166211fcb3f67bda8887f0901c022bc0952a2d7d65b8442df745be62d315e18e2fe2c354bc8d84bed0e6233a12ea339aac940d8fca0468c55a4e172256c2e111c4d1006b3ee254f90b569b2af351ef1eee70c1e64bb7157633fe85998b9ef7a509d751a4d0ab0be1a46046523c6db61c0ace038f919550e8e02c8555bca4884cd2ef439a9b777a5d691ace78941714c3a6f509e3a3182a1d1aa8868e130966bd779932253b525eab2b7c0c035e15c9020251183d1686d53c8fa7331ac00bf182706861a871de51bb95d837b7a2ee9955be87d28b9eda8d0dd294c0d6ad2a11a170122b2c1d66f750ad0d5d5a0a6396522e8f9dfa3a31980544557ad280cf56c468061f366ad9c26a2470e398196a5adc623129dd3b84183f9ad823a0bc31df93b19f1e0bbe5eb54e01be324230068819193202804b9f9f538bccd9ba9c1b9063a226db20a3607456005","btc-headers":"09294503ab9684255de1c720b7698a9a983589ef56c0b3c13ca31da3b3a97e1aa59a598c35ccb3abfc5e9b3cce9b16d6029943714c2bab40baa11492c69c41197f8efe408be98e843c85a6629f7c0800d9db2e1cd2b05d1a9a45e0c34ebabc890f80781f2ab9b704446336ad82639a27700a5d1f4425afe06ce02b45148faeb0a80118b813751f8db611ff5f294825115017a3c98e7e6b5810c18d1f11641185257f985d1a8a4f47652849db4141127a4ff01df35e162866f1261a2428d28e65d079079883436da4a413899c45fa8cf65e5dd5330afae987e4c46a9e6c196be13e78801505bc256d700d1b8547ab60920e6a576e463719d14394f099e082e46b102da3af8e18aef3405fdc97d181e7b6099f3b7961939faac86ecaf9f4d52123acd82e07dd12b62a248101e8686fa5858c78884ad95238d2e647289b1c7449325c6957a77e9897c3cd9a1ce06cd46346648a09a41018a750570528778e4c476fd95dd83008b4017850f07bc7c4198ed827f310b0a885f7fa1009ff9c29613866c66f7f8cf761b88c8592684ee23526db9eac9da2eb5ade90fd2f55ba5073778ac9c6c3c2f39d753c333ad842adf066624746617e495c878ac25b8dd1e105a82604219953b8864eada55d757882e70e4036a8548c6fb2388e1a23a30fd34bd67b89068bbc452d8f78c50a33334edbe6a347b8464c13c2b1e6b27b4cadc1ce52f55f16c05a1b08c2323e68aaf0983d3fb47f728e44ad644d5162bb82454ed20743e2acee297ebe77e7234a33b92911b289fcb0510c25b8e33ea69a60d67c2a34165192e263d868440dc3ca64211b89440a419ed5591db89c6852e0fe27aaae1219efc656600467ff08c2969637b011915e7e52b751d1ebd688e9d89283afb01f6072b71d53746af851b1050753a4b502b56ad0a2901cdda2fe6a9c2739d9556f538d0b4d75b8491bd76a1627e869e22b4a6654973313d9b48da26b33d7515a8d94676fd69a4dfef02292623c70cebce2b8ef4834a1f339308d2b475e0d52d9169018cd3a332fd6e0bb68f6884764709b166d7af04fe200929413cf66776eb9bcab14a64c02f00e71669e3c4b749401bd5e2677e85fa33145c342e8bf73cf2d8b64d1e046fb63663d2a9fb3569e531081cb52a20a55444cba7373609f85c21306569afbba48e388a5c4c161d6f14b4d40fd28a55597ed430fa1bcdc74898b31bfd9a8c160d7bb4b0db232b769f039a67b394dd5a5447dbc4357ebbcab750ee2ebe540","builder":"095b6cf626d355a9397ef4f9fd9c13350cfd026206c72f5c2e5344af8e6f617eb57d21e32b3a1d904e5b691cf0dfba5e245c5b967b2818e7c12ad661f103e0896c50fe2bc853ec7d8016122b9dce7be12d33a3d2063cf9c762c68452750060f435978a520149260588d70b2d81b05110b9a410d6d7559867ba4edac0b85af26135d692eb29a47ecdb2408fe9e12fb5fffa96da3f71692d5623ede21668755adb19a46dcc7f4a70540e65ed34649b1834273076da7463a60209331bb86285b162fef0831d20664e34488c63689f01e1f7731ef84f3245e41b14d1445c8d18ac63a55ca2590372549b353dd057f583713e71a81a3ecc48a392d5941d069ab16c6be796c1aa001e61b1ab6b585af87c298a1fe591d02ee3fe8c5052b8bc0478111baadda6c7881b8f797a2e5b9c295d48042693a8e6971a5636627964a939a41ee83ed2b3bfe2a6b60227690bbd1637988a677354d16775296b2e645f054fc19da158ad4966de9eb2f991d3014328897436784e23c90de5f525a84bae65c236277a65d19d20de698094cdae5a52a952d3d54cae40e5db14cd1a783a594c05b0b252bd357cd1133f964e4b55284857aa6dc40605c78670dd71e32f52ab1ec73b868f9b8c7ec5c030530c3abe48b8f52345a7043768008b7eae5c8e63e6875db1fc8781684222a3d5980638178c62091372b7e0ae9280e325f66c2618b5e507db473b299ade1113062f78d61b95c9cf52b6bc96c5b5a89325beb3b8c2d8b2bcd087a19ddc380500055751a214a9700d4044a85778355b900556f82d70c8896218eb99e8bb65ba46c9456a1596cd510b3e7ce272060946054cc177c109388b4a53a84fc26d79b84c1b092d6d7d219cc1311a5887b1ee4418ebf43672edc2981c6916554c22a3a9760eb05a37b64f916f149c262e502a2a8d36a2bb920fa8d12b08f89fe6950d77e52ded48baf0b58518e38b689aa199524261566ce533e149d15ba261ca3e54258e04a403ae68242f9c30b853c68d9db090caed1fb93ee640f71005ddafa50f4155e2767955bae0b0167d9dc4051a658a8d7ac88243a89e551fe2aff4d8a62f0079a2743b131813789b883204dca9c6e0481d568214d9375aeaeec99f786926db26ee531ebc025b8935a945d04113d6057f7d59c987e22c9285eb193a0cc3aee511a355d97d475cc066aaeae791187314aa1e49a131f2a9460523165df415fdae5b9df04fd05bd5564694bcbb5dd2bc637d9eca4d8f78b4dac458a70722","carol":"09ac78df77f48c4e3125849371aef6099def29d1a67b6c40e588a99a904ba1fdfb17484eaafc4f16f66c99a8692457bc404b259db8a56a6feb327decc8cb8d434a5035966342913a7adfb2e889af530ac216f150f02fbd059a84e1988e1c42f5a700b80e5a6f1128530c26e5bf16d4c5b3b1887b65f768aaa8866e492886b2641213db011ec2af8a1fd539aa6ca98a8158669fbbb4a015f22019bbac99d5e19f1bb1a7ae87d40a8a55bfbae456fb08e0a91cf5502c1234813a9d2b81877130dae1ab18c86c811995d1a8429c029efaf162c5810b1d62878ca3bb8f86f329106f86168efe5365c4a2a88419e10ea85d498814f2c3a65c5da84839dfc992288ad6544edc5249bdc849d21db1943677f33a1dbe4f6a911a775b4901f6671380531db178ce932424049db8a8429a9443421efc62d806b375287e33cbe636a514b090309a1734a46f7ae597c5a46464aa584e21ac3d9dd014592c61c2cbca2a08780739dbc935c8588e6c27900f0ee6bc71061b635371226474f93f50223781b7601a2113ae4ee6e643a19f191afe03ee177f79309fe9d1882f5b1e5b29a1d8c56b3e7350c1c8194ef481d85210e9179846f370aec70235b3995867ad3d209604a341000ad15f81d72c522bbd567772e382a4710a9334db3a173c6fa3366a206a6531b8079035a6b279a069c49511ea12ab844c5094e109216a01317b294aa093213028bd008205165b4211dc7537506d492e6887f84bc6b5fc8af3e764f4544db3d71d0c4b2394c181969e148cda2762afce8b7bce2259fa1e837171389bfb1adb395d48e668d84a1eac16f557eb6e2af199116d883431f997f7b1a06c914e17b27950831372596b59ef5a835683fbdb1fde78eab31671d92047966447439f81253c44355e26e81765b603e4ce8b46f03d1a029a844c4045aabd4aec74b669e1cf47bd02ac64da209da35f20f522c99e5193dc9a52268fab6bed9912008293773e2b127bc79053310440860d8b66d40543ab001e6afa8bba26274f3ffa07f8e307b879f24464f4cf4e6c7d0786846183bd15679bc10797a6d065d287d4955a32b1a9cc098d6c85b76a91dfc639186f09339d9664216adacc08fc9770dcd904c6ed557902370f0bfb7cb9b9eb2f408942ccd4353a9e6d24e81e60c4106f1a44bd14d56076ba455cd9a553db079202f3a0e2d281b40316174b7f79747ee392e9cf10161033ac4c3838ecc9643eec800b29ab67c60ea74e04f14ba921df5e282f63b1dcb8","community":"090b48463128d24d9aaa7057f0e1ba2ca5f244dedd8258c464290fe63f346dddd82628786c5a683865936b854eb9f332905d080dfad80cecc47a399e3329e908260c635bdb5b5130a1cd33b1522218629b4690521aaf21a1aa53014d48f45d1420abfab9bd12a67b270124ec2cb6d560a5b224bb570aea3b16c580419741879d70b657cad6b9a46c54082fe931a4f05654d9d053477011a955da52afddebfa0ba91d2a9ec959e2a06c011576ba5d09006800ead138945da71593ab450438262e37c719c9b176988056edebcd6a142f29a78b3f4cad65d9b7d43254eef223bd2d198831a820602a9ba891146190eb1036925ab4628a1a1f5aef85704adb9e368e89fe2e790a14c6a57853746f15dfc79ee9c34e4d496613d06b0c4e3968f6ef4c54b60f8326eb7d3599139a9f6378294689f16816c21d56b5d59ecad28910d84318c1883f76ca5a2149ec112af297cfe85506c1afbb2fee40584e066a4b21fc5e94111461ce4f63b607f82a5002ab448d068eebc2243566065dcc8b0a5eb89baa8d6562547c869da9e731a4fd316de28875c4c3d81e06a35a7ef6f1cb291c5f70eb60450e9a1535a8b89c8de35e8ebdf3b11130b6c0515baa0745574107b3e20f564fcda1708b281ea10102502e19cb20f0dc6b00dce86ede9222e881c354513de546efaeb92d40f8a043e461dcbc65fe4a5b00791508f9c4f49beec9b9d41ab85634ff812a44bd4e46e6f5908441ad298132d2e84078952b17106fdd4a7d8a6a82e1f147900a123363b59d26d353bf96591c3188fb2c214f43bd0c20da114619c075d3bc5d253ed2cc83358bb39758961ade521ba6c4042043e8cf95a843020707e22f9e57c9475b1a627e3376a9910d540000a93d9d1cac0a6225d06b7037a6b3aad1c75f1f8452519ba5f7477182a6822cb419045ea820e7ab49ed2df55b6a946438e1c07a9f46bedccd44f30ada715e658a5f6926550db9c6e7c8951a4c0a78ca0cb344466d8b67902a2e3e72db8398ef4f2445696c09738428da558c9f6f40990190f75f756635a0d77b50f21666e421afe5842dd555b442ecc3a3b484356318645f72388739c47b4648c2599fa4cf0372bfd564ab545f88ce2a3786e54ff5c2c0191cc77b8ec3e396ad8e4afd29b1716949bf0ede584782a61b1842031984d58cbd077292dfdf62400c360d2c35abd60b103ca95c025ebf201bc582a334230267011ca9f9a7c2b44b3e0f26d83524dff070c5a5f165985f13f5150a6b5158","dave":"09017e26d3469e1b6c19eb2242a04f97f660836b069289794390ad87e119d8a6984d2aee579dccb0552edfa63ed9ebb18d026ff4e0315fce4c84c431f93d668c59b8d8bbccd2e32830c46581c0770b3e2a481c45a065fafbb83c887843796d7b87a395017e9ae438da163a2665a1fa0e145fea8f031e131740ed0887edc97582a6f14b18836d597953d1814f695a5d8382b9c248248d3e069941ea87cc2ff4dce1e5b94808b667547e8b48f2d689a5e8a975634ae80b0eb6a9cb387c435d6a1afb930f28685eed4020e00e48bc014296ba2c1436d1c5b73ed5c4612d5714cfdea72f1e593305dc77af16834babdad7215caa31055f6198aeab118ddc879eaab4b126816e333d74471f6cca21d67134426b54ace5b3d8cfc7977d41fc714ade639e119d333cc6dbb95dad226f06af493514806752a77be1253b6757534071583709a6d4113adab3e8d551bed44a75e7dcdf511662ca70e4c55eed3ef10287b979ec4956fa8d8b0a898c24e2546c4d044b2aa0a34728e97d8531a40051b289c11e489b2e3438868e9048bdcac955a35a2347b52bb6815b668222ed104a04b73d26af55226966371279d251130e244ea954561e7376a6d489c981205db9a9e4e6a8f74b0271c03a58c79d4e77e1e7815f63b9c759041eda3c12cc93ea4bbd79ed48639a21d6af684c784cda6541d8613b6e582d8522c7f709d39b01546b062c23c19b8a3f0436ae6f80dc9a07781e9c8d5c3587756eabadb6476393489037b0a472dfd49f0faa0131c491ac5fca10c3825fbf8a0c66b7bd4ee61018ad3730273b85103a9b1bcc00a70da5388446f159485ed8c769d0b2f4eb49a5242b8f3e9bb0dac65035e8533b1d851332dc6866a25ba97bd12cc5c406914dda33bb796c81b3448927244eec8f8cb1cb8b262c1fa41d41dc94389e0ab850ffac5d3182f0484d03e4951c75f9cd8503088da46321270da81cfe7604cf646cc44a83994e878a71210102164166d251655f020a4d05a908e85c9a88115855d84c317e86f086ea6b562d6eb37aefe582a00ed99b2f668d2155f573fcddbfb71a5f0300a95e8a0a0c29b89d02ab96e8c5ee5dc6114d0140a558bc7316640ae9d9cb64d0d63bf1a022502e3df5e42f5a608edb0586674599eadfb1dc26cf2a4ea91ac66f026e44e70245439492a684b80a599c3dbda316025675211cd0c418c687a7f17a1a1041278f2c44965901b4a2e807d335e9f91b2683dbcaa44e282a3df649a81ebff68b463be6e9","faucet":"09262cf8f61614cd963e59f66a880aade245cb03075d09ad25bb4746f388ecdf93715fe55d4d10893828cf37fed0da4b8c48b72e0c1817042517017e1a58d16846869602c65e6f6af876f8f2d6e74988edda1e99663ae6e7e25a1c529ec84ec03006c330e69094442da57f81d7f9280d4004587047bcee9c294d1815ea9c44966033d24c5a2e2575aa7bb764241a255582716b9747c299d6102e5f80d57c0181806055aef2f1010f8b89e28353fee0ed59590dfac2ee3a5e08c6066049bd5bb20177ea635f8f1270b99b6ad60a526ee47acf1543da35c1284a223e327f3496cb0572c41f54104fbc7c6c32423b58d763ecb9c89968536ff949e6459838a2b1969186a01b6a6cb4f1ff18b0006efa81b1da7e8ea1b567054c4862e8da8a3d4ec764b8f15bd187c02a3469d8198aa49ade42665facaf97d6bdf81c834b479c8d243948086b185b6bb32324119a44704b03eea8752fb2fb2ba56dd13e640486444efe027461e5436f162af49c5c895f226fa57bae633ce5db6947208975d922e81b21162016e9f920065e21255507ca9fce5eb58815c163c8692dd7a6c86a022dd6e11bddd8b773e93d86d2e0f589d9da9b9641842eed93900462ae03ac40e62d083b26426dd3f5a56a4c54b9c6fd5b74256101177212b171758c94bc5bd2af6938a7fb20fa9e9158a6491ad98158e8a311405f76d47448b6d67d84dcbf23c164fa315233c4481c070c16fbbaf71e7b789a03e9be26f97c605bb531573b359a29b04fd35fa9402448408c683665a478db2ba87a9d3413eb034c24a4acf744eb9fbbd2fba06c65b7994c4f723e5f0419d540a5eba46a35f5dad5c562194d01d46a0c857246e19af7ff423b61c25dc4eb4c2847deb88066af94702ad4144fce05b1f1e9d6e5031e64dddaa17d240f45f06a37272f0a5875c94934573b8976f893c5563a1aa14ef40b5ad07146c1a5720b3f1bc12be02461315f8431333510873d62bb54dae2df03da060810a43c126cfa21f22d432c7cecc2369e702f4537517c8195a2307761f1931d8f70ad353a534ca0d6a99380c9f76e1049b40e625698c253332891732e3986220dc45793ca8dc0234f6d6e362147510e5286c5afd63615295ca1aeb92b6c222378928b1a8dc5887ec7044697589f395af9051d784d002fc566c0d3680ecdb91a9cc0b678f2533d8ee30e0d0f48e28ac6590470fa942e3a7be4146a6f84573512f5fb910cef643a48f58209179244ebe4afe3a32615309aea1b83","sally":"09b665ff8bb21470844822500602bc4cb5db0b254da90429ca016959d801ca04d504e63200e84278880e724b2c6eb3e8d0794a7e0330b59cd778c0b1142d08057676564b0a5767020218d9001ac2a0d614e16217dd5d75d126ecd2818ffc99fbbdc1985d7c147a9068b348a1e6854915c9ad491320462c478e5246a011284668463fa4c42f2e3a4ed974245fc643043d5b67684a608e1c44fd6ea7107996137e072720d12c93e905ce1a5c4778649325b11e61018b18ca8a7a1d40fa84da801061bbcba2a83b9d1aa758037e4f5e69d4726d4058c840e6651c3f817e987378ede93654be5322286d747661d8c18d0c4c8d10eb27119e8ce17aa03aa60a0f3872aadd97351d5dc6a6c06ffc1bc0ca44d808d602828625349c491166be40f8107e306e7545b2eaf38ff59817375435a69e167125c0212a2e3f94c596bc07925d96ca49cc8fb5ab80f2dc4e76ae03ab38ae8fa17dd9d6019a170a5daf92826e93b60e7ab159401c6be87f730fa57c91fe8b6be742e1acf959903fda235e4d02504e87394a1a6ee3c552e3883e2904eba768271e869b64a17a468ab45afbc3de9c0da7d8fc2c897fec9665d026209b791d21f746894a1c2f89b54dcb1baadbd9765596343859533010fb7e801289c94cd8aba4e2a0ef82477a54d575d10aa02824b923cb91098c0a0ff264e9ada90c82e7e35205b92a5328e1eb0127555512af6a11afaa18e3b58d1d424a4a1990585427123bcbe75e8e56deed712065f195be726301061d84dca45afe26a6afce5ad71dc9878c425402b511682318b617bb218035b18956b281390d3a54f471e06e1049fb32b8c54d4154a6d63129bdad28bb295bdda5922c881bdc286312a5a15acac31aa5b143d419c619a4b087c2870de68ca2a9c587c50b89ccaee808a9db7b84412919a1e10a197c4208637793de4aa19c881260349a70682ce1308d0a69c6dc7f7b382c022250ad15ee15326b50289974a3d0536838a29c4e1b3b2b0d7b8031f136232f4e0906eb589f5a71da99865f6400588874014e0477572a0c567d0d589989a701e327358a18f8d69ac4d822b68a617fa5e685822058686772237d82c5a05e710735b0c10b8da34bc8e4a424c25e544a3825a402983760b52b3992560d055f655f2fd972d0d7d9e4d83f96314ee3632d84455a05a18e1f3c56d95fd021da6489350d77c9cffc74bc9f12a6a1ac42bda23767064c53a643b3bca17a886032f97b86cf6ec16251a46ccd1bb6f2f2540f7d","v1":"09a93987f1dfeb448e6a78854f61cd122ae1c70a88cc962c6883729ee50e9085b47186a757816d821705e1b9ad5e91a521f329f955141050cd0fb5709303634f776a6975eaebcf301492d83c914575e128a023d3f49955b897849b4e81b286ab5722bba47654d8984a081524a742118a3e2cc4188916abe973021fa39f92b2607d06d46ed2bf6c485ab116c22c61493d02c610ac95ba164a9d677715dc8d46a9825a0cbacbb5734f181eddb3f5c3a0577fba5eda422feca872f4b4ea696c041403e44a8a4b7e90a9b6b0a16e5b61fbc55b6e4f989196553c69a751a820d0036373a92a8562bfeebb1a613418b263abac5c435b805e2c519ab9cad7d89d7d657706e38859650195b526d4cbb50485f66ca12fb7207ac140686981063ed8bbd4719519057a8fe887995e89b06490f102aa119b6286336acd482863ad227660dc56f312984d919f1ac00e307c45f692ede26ba27d54c67ac05ebc5e3c642f245607ad0e91345a6b68f834d7ae12c89e10f91c001caf8dbd5f8b95592a1621b173876d98b8cef86ab1db9fbe4a847a7aed248c9a6bb03f5c09bc486231748b5e02b0f466ababbc33b566758c69214decbae1fb9dc1933e6629f7996d0ce936a15c576f78307d1163afcbbf4db4e90c6b438bec00a633e6c681be5936ae87798e0680d777c93c14740c07a8c0556df96700d60ced0ebe04e1dd969abadedd037229df68f6f266b215522c02971a364a1448680ae0271e254ea6b6a0bd6c351b803fe1dd8bc6345b0006fa5f337a968b12ed5d83653dc2d89186f61a6c857b1a8297372cc91524de98168aa087d75d6f20d0174749a960427093413b58d608e2a7490994d7301888a5fd04d806b9361af345a8359a731b53cd7213514dda44df3015300b20aec3667329f3da869c045c306a95eda13f6021671a3a6b0d26ac4530c0a4960aa4dd68374d471c8db4c50de2589036a652f25d903c89f19b28df199022753b8142c21b1a8a31eb92463ab1b284a8eb0e91f643123b067806492b0317e084783292cbc7d1fc57592160c21a691a603da18c02414850bc212393894e8e48c57384576b04c916ec965536c1b551fa99cb7e785b07a04e6447f6b5801801e2afd69318cd0f999d3dd5f7546fff3ffd9324be51eb35ca06daaadaba43401fe1c2042f57f817d463cff079dc8f6369d9895940f3a9202ed97a0e81664256feaa7d1da165976d1510ecd534e86a6fb2fb1aaa6c2177e52786ee1e0118801c61f55174","v10":"09636e85954b2516545549f1830c7265d187d87d588c550a0ab1afe99387e5d88956280a2c08a5219e5f813474ff056aa2c88080560b624de47965f2d74dace722aace23744b3732860aaa0cc67b25e5d9fb0457653f464410d21ae9acada485442e6cbb3462a77c1c473a79a9e9abd1325c16053a13e2278864f72596ab98946472b88754b82e9ac0d9f111f296c559a375606b728a6a6882efdc80b072f0466ffa464d5e4a0f2c752c81db3b842e3d3ae8b35066c7db170a6873cf2032bc456fa3baae5c4918bc7710d4110e58939ac827cc8a963ad9bea26858c89295cf9cce8a1a747654094b1d7c6b812ac3658be1cd99e5873a1b8c9d547c93f3566a53188d59ccaefa30d13c689029908570b7454997c406f4e74e4c80fec6b361d82a0ec648441e561b77ca8b9419ac873946d766f69e85248664570cc98385d0347b03a85701e2507530d94b464c83b244871725ee678aaf40dd330dba39a4c02896c6771bfe94330a094809db29a98cf2d867f48d5034423be54656637841f1d5cb5d1f280aaf43f85cf636bdb7b26b9e7f59a2bc4467a5f449484cb4c8218d05edbd98c897be9e11701367c43d450aa33006da97a3a4f02bb2827b6619ba776ea8dc23e28702860ae8596030db94629e24a2b788e6222baa1aabd99218ba7dd88072c6d00b1da552f80feaec3b422cb5eca81e933deae635135a070c39d41dd67682c2c5ab41c8ea84c287171d276a5b161f0158a9808531a1b3b7a7fd7a34b2950b21d92e0197b31598e7b2bcf770df902a1a2e14359152f2247a755371929019509992051afdb8292dc7d9c80cac6c7e68132a8b53f94e6b54e7cc2f2cb0d9e08cc58b0c6027ea445cad982fd630472386dedf3504e6a1a42629805be2ac3b99fedb236e99a650dac83062b62511de258f83c66e5618269b6e02ab2d9720f95778bc3d1e07de8707a9f47050754ded05d8c98b101714947a46453985017bf401a92ec0121d2e26034e46c710c2d7844c8c18012593b3f9cb902dc04346262627a3d53e0acdd8509a81b6c547058f68a062b94784199ce43155a24e43069c076b1c438cb7a20556136fbca7e40ef13e661358d4fc96b828569928ff832a41156fd67903e1206c6a9a74e73358113e06ba3a7e57f5a235e741c09cd39f823c4395e41605512fc17baf01779aaf0482643816fede45274b3ebd4caa2332509c420d2d99a0cdf189220a82c3e50077fd1b44cd61876992f208df8ab263b06f0572a95e","v11":"09b8e950b419d5c40882d09091ea4579950fe1874a0ea03166609f205a08058737ef4afc2a4d222a438e29005c9d47d85080bce48bf030c2057260d8f9d762d19f8c29c6800bf5436648f153a63bbb404bd4b6cbdc5df15b70f416276ff9d38759148cb6a053c2c0ed324a4ed1b53d5ee81bdd546a679bb8a8d06e559d0847336149d32ad9935ad5e97b8024c79c8e015ae6dfef107e06859aa2af7a9a41daf65a025f9ee33235a21a1b9d38f9ea8e200f2df0b54f838e2951e2e224e94d3642f4c2d71e0038180b3bc2001c206cd76bb50500afbcb18a0a556288c1f31a4403e4bd31a0c3c3993344c288bb6bab76bce91b452e06c4a28d4a1b6c9f913e3eb88118ab471e342258e4cb841824e141c28ee38bc81d84e4998d5b78b2367b4b7db25971e9afca3798c16682cd203023d24b43b5c6dc490c05232a285876f8f186ecefe610910320e925de4d844742148102661e8be41255ad61684b56c45adc97ca43a589422b569c564703222d77791879eb04b5be2ccb77b65968b6b8f5c7b94b66905960dba029453f4c31bba8e3819335a0964309e3089db1096a43f47a04d0c95b245201fd3c555d6ea9542d98c35489da2f7084790b9cf66d982ad372dac01d6d8f17959a765b58b3e40e98b311c536b43f072860e86f774643df4fc00df4c92e7c8e9eef70ef2acd37d0b4f63fc8ff872a1e92e448698870fb23fc90008569f6e63f55927c2a5f892fcafc51a0a94506d61e2104baa91f64d369354f740341b31746dbd61bd6c0b1c15a38660de10b2da778db6a6f8f5a7ff4318ea18d162a457f28e6aa7880430c8c8dac8afbb99e0db938e8c5b4b303fc690d75f5b4dc4533de6495299c94097691db8240c29a0dba8272ede52bb5fd1435025841aa9822e583ee3959e8e5bf0ce3a86cc3421f2df934de54794b42d655c97a12aa4618515a53607fe66e1e09784849da329942af32a38c1aa4a46a68c101fdb4b518791a0cf02dd238e5465599026add9a1ad8a4b288f429902a25146e5e02f1ef492d64e12a834a903fb1dce68720ee21f6f3b0bc6e215fcd96e94fc330abfced84d001345baad6d5978f8b40598df497e935bdd049b5ff2f97592dc2e383998b4dc096b934d5de151c81938e5c8763ecf25814af888de1a719356c4546a5a835652f5c59e299c86c29606c794465eacadb2af27cd807c70895edae893b63912c24fa87ad20725a7a3bf47b4c3ca65546a2ad14287351f8104a0a93970044a98ecd7a","v12":"097682303ad28afe68c1a34070530d858a1cf1cc62c962d29ca42613f0b24e867424579187929b11c1da90813e1b84c0c2e588bc427742c047116297d21de61f20541d661d67dfbbfefad0e005e642453bb4ff9f298950223b94eea4847e81c1241856b07532a25e5ea581e092537e2e2b93e4a6fb00504e44f44019226a32175a818149cd588786eb06ec83e714a6c94acec0804e60bd96cea633515e0f17b544ae217a42ea928d48652d6bd03f8999af8e69ba9ac0bcbe18c6a3904cc495d119fa33c847b3283604b56cb5734a5a56ad0b2e7b6e75c91eeb4e8be2c2345d551564cd035a6f8c4623e647200f28a79b305fa2bb173dbae0cab41d456c630e97248d03ab80eca17bb019611d989ba95607802c911a94e9d92fae3eda695d5036a872fca13b056e19c857a30d0a389e6916f367e690951431d4aec94d36bd3e6bb9e7a46a3a8a08e41868a42510e535e3de931053a8a362be3e058c554984d010011188c9e85b99ea266362d0775e36d6427a168f179a1fa21f8925ae5c405aae5f1c796e6eab7391422b9945c2291c35aa5899c20acd1502869106a38fb1550d7aa0dd5a7087ba267a77c859109e2105d2916a7f2876592d418fb0c4dfa6124a39a282b451e16905a6ccef79ead6e697b2e1c7ec04fd7515da2acbd6aa16ad931627990e60b925f67500a39850e64a6614896d5d4e604ba6ce4dc58bf72587d686f5dcfb6f2074b93debc85c001495d5a301f88c854f449950ef1e701e0977abd0d0986c8c65643d1b8e45f513377ba67d1ad82b16889d90acf41063531cf009f0db7556492773640bc7f5eada535aaa910a557f6198b7b15452b5615c8a553380a694c50a798851c345042b70335220b61a91947f6528b929c6c90802ee2c71d3a32521c574ac547212594e1649be10eb225f8766eac323dbf46c0644942a93ae781606cbc8064ebad2d75a7e0fa87b643789b956358e3161b9df565da40d808111d6bf52de8ba067520e79bdc15148c36784a5bb925a13781245e8c54d66680840c0539498340a1ae25a7b2c66054a999639eece72fe742b032ac744f15bc2a752a0804e537ad95bcf4740d5f2214f56ac1cb9a64a52892136d0e51d6b5387196f051526a96a86dba9f819ff2d191551671d119be15c767a869769419e0bcfac54a1b1896154a88e4bc2cf5bcd69a572adbb94626a712b5251812ac31d85e18dd6122aedb445f4873e2c7d352679971f66275440fd5663eb2ca16513f14e281c","v13":"093074502968432030ed96f4cbdcb62914e061feca36be5e1a62b283bd50860a240ece28a21d27364a4b5939789b8acf894b96ea4b29776b8f674e90cac79b53a05afb546ed33a7886d7301895808aa0c8a0fa971f0188925740c6b84dcaec4655d050b51955d4e109e08462d2576801c467414aa763e096655169865ce8b2278da042cb2cc97c41ae17208f661cd17221a0cfc89ee253721698253b0d28d86115e4ba15c015935347802ec5b23e6cf0b199344416ca16a2110f9a6dec4b479273863d9da149ddf3d4481aeb17ec2c3009df963f9c0fd233cef645093ab406299570048717a9a627530d88cad899105bb1408588ae4e0f4a7ab424475f0da543e32e1fbd2bd1df37d712959e386885752bde72087b57f31354bdcd6d048291b99c1e36f24e835c11664717b5cc2574392964ef54c177659bcb326f1241ea0118b6e856aa92b2e5e212b2547e6519a8a6a59f20b25a11669e109076849b4e432f5e603360909d4cf2f54afd0a8bb89e8ebbb0a46389500763bb05feb2e5602345e7a17b8dc77a78cad4628d5eeafd5fb1064ed46a1e48f4a52e5c57aa2584986de3143fd4dbb67c7ff3b4a4b1899c8e9b4ea53428a52323d0123c1fbd3e0a5ecdd7a5cdd4e404c4fd9d7e3ec3e619ffbc08c7e392cd2d3a94b00b71dc2d2fdc79aa1d54f92e8573595d96828f5dbac9c4d7344b45a439d5ccd422482613f490b8bc513b838407ff91ce9879e32e37024ed62bf4ae8410510223ce09bc14c957db7a9cef929dcb3707a4913062d518f543e47b2200f948800f094451717bd5317804ec7795982917083fe703921cad2674d8801f8478298908d92a3b43616669eb5cd542ca8b218d6467adbcd2a7c4c71c410842b5a384a982a8be429bd215845141c22581f21d5d76da16eb4439746f50ed43d74a9ca3eb5715ce9e657eb4165775548df03a005a5d1eac94d8182b350b5639530c5581489ccf3bde44e610960fb2f02cd08632c796e26d85bd0dd82bf3e4534a56dad20956d144aeefb5044b957819c7d99812733014be2668a3837949ee87ee6ed01d34d3a4879ab53af4be006b5559803532714046aa4cdc35c938dd0eab4628f5b644357f01fc43daa4e935bdcbb4be6a381fd988b129c99e6fcc65a09617565a9e33c0d10b56a8669365b3671aa43cf79b8f288434058540f0d0676efe32f37da690769ec824e5d5783aa4c393fda8c64bfda427a5819eb00c92c091c7443ac2e224276fb430063070809a74","v2":"097ba2fed7c382ff0628ea5baa4c6805d9318376584795f0588037cd6d59520691d650ea3d21767776824820042b8455147fa57c9a15b3e17abd06b155c56baa4530efcb2fed26668ef6b4e2d768415c0107d960e533b5a1537c45b95516c290358b3eb09997a8b149306cd59bf9cd68d10964e08056479628087031e6ac091ea820c53a013f33526222b20c399a7e0b2bf5de023c4d87f329cf2b181d31d01928d16062e6a70bec7a5dd92569835a590fba44e3ed133ead3a802ac35b155200765bae2fb906343f7a9e6c3f557ea5a7ec14180c3e5989d714db60b69652be68c133a1264ba89cf384657587261f6d764096e08bee72741645a3e3d0ed2e60714a3b13a89cacbd05cb4e8cb0f9d06404643f5cb5c5a797e6f05a98a8abe0120d9e611cb405674000cea7d41e1e8644b0d1822850b550d8e7e5c660077130aa708b8fbf8fecb2d07c1c428518ac0a9c8eab23ead4cbe1a16e8f04c33a590bf09dca383171dd95709c03e2c6d588200a17c00215de65a83870fc6e5239413670dc608926667685475a05b54e03b40cd32151a5233bbc0cfa74924e496e6ff419e150daedc4b346bed68959561705be8b56384b08a7190a35abea849539ef79f4631e05c6fd0a4d27463fccd12b072dbe67ca2e9215c5081bf416dbb8447ab67e04f5e1810325512d96c4275d6c943777e0625f8b041a74ca23907df1feb8e61aeb890e8fd72a6330af053938c91c42852145648dd89a0fba5e9b756def73a66875a0c0d8af507be02687424e420de585241c7c3231bb1f910b75c8647a7fc405440eac55ae60607f4af8c57e210daaa96d978d81b61f863766d6a6cd9be9ec9a5b63b16239e89590e46a29a282d3509e42a2f9bb951e85ce6225dd1951961b24903d133e5166192add63be4b6662a8096652549fa7210dc021e7630044f3c3e563576d3874e6a4ea2299fc5237942aa59544e4033a699c74d4d74b7ae79479c9b295ee1422512af6981b2de62f95d224d615db737cdad101012f407a6cfa59697957254034d140c7745ca34a6641e272c6289aef8f7a763dede8d38dc84e7291930d40b0b09c54a19dd8639e39164a1f86c92d4a076962e3e618158837c58810af71adeae00321459e9ec6f7d50b5241a8fbba4fca3b8ee4c5ae1de29ebc80dae21caf3d6dd5633159ee95b971bb2c8a793ba63f1a094a907d62ef56cd26684f3ed2528266a31de6cc60f6ecde92299734d306855508f49992038d512a40794d85c6","v3":"09b2d19cdbe02ab7348d945b13c702b0f9d4b75fc25c540a079b3a9b26b51680cbcf479d0fd8eb8b7202d7022ca94404ec30b9b81cd09b190f82eaa35bc51f37aeb85273f49d55ad524b304320b40ec0f142c56e687e29ddf493cab918d02422ae9b48aea4b17620623d7fe5c15b7053428f99d5a8961ff2834a1d281b873971627205124a6892e9b15958401f1f39d2c783949463106a94f0509f6814bf820a47306d425185cc842780deba45354eca8cf95977be26d13d21fab361d19ba7d5785bb55de5111c9b03ed90c49430be50b10d87bb82a520451957bce67ba181a4a80138ec7a42a21613608f5902dd67b875b13590dcdea2d174284823840f2c6f2a83680896baa1b60e8c8754598dbab6098f70042d71c02f4157f0e13aed9a90a61ae500979fca774450c8f84379147522e6e0e4088c6289a82a06d921fee902475d847c3977b3d58dc600d4e511066501a9e6e89a3cd4d76ad0a3b13b62fd1f5d9c277d6b3d2eecc2e5ec5ba98124b65902113e80b654556e487429fa8026b6cc261cb4628853493d55298b21251c747b199155e06aa53851c660420d4d17d58d060d6ef0ac5435cbb2076d3bdcf743751657556d7da78b90b372995b44774e9d5476128357ae659c46c473c664691fd0d33b20010344e5e3d356838a075ad707e7d5b98146f9f5f4ee430c9c7fb6c9de939a55cbe2a2ee0f9ec5b20ae2659dbe3a8e66f292e68dc10385fd69e54405cf466782091a4261694f52f5bd391b342d93e8254eceb46ec97c2a0e759517211aa31a99c6d218550058a071e60d01a6b62f8923567289b61cdb46c7a825b525d0b1dc618f4cb8c23d988168c64da3f52cef055282e471644c853587ba85843b4ab51fb1c145496b481fc33f4642b248a6b28748ca306e83da4529922570213a0742c842b91938da13a5316551f43f250595dc4a409b14fbb57daae71ece240511696a11478fbe76dcb61be984af4978f19b58da82606f14548c53a321a26317e56aac6999e03bde142a1c6be82d69049cc9fe05a826579d0d54267562506f6cebc25f066138587f056998de0a39b052eee1197472d952800c9b200a9e7383a365126426dbb25b96732a2c60a5c9cebf7e81f2ac06236ae4d9c8106d9a60915d4073a69c9c61281693dad055f8739b9a4d513dbed2b6a4cc2b1c4d526061d1227a1aeb320e83d78fe1005a60abddaa022ffafc89cda46400b4389c178ea5a439d8e0c136b055d58da93753b24290864dad","v4":"096d540eeb4610c006d4d40254ea5a331c1c986fd1ed22e5db06ec2a791cad02c9120262bb5a3b412859f039120c57be53d04c24d4924e80e196281f0b2e06f21e76dfe17caf7f96c178a5bb030c28f08150dc62be4aea90077f986e96f557119a8e00840d0d050b2bc83b21b156a31c38706e48fb83d4c86e61eb5704e87d22cc00930d96b3bbead5004fdf31b3149fea24826116c17028fe8dc00899da2099405fb08db53759c6370fcc40b804a9fa2329847540cffa4ec52b7b30a65925563cd27228c85d8d7172c52bcc1d4090fba8431d38092c58df2d5ab4207d720c6b008f4e7125b00f311abd58d5c103af3daaebcbde1305360db6a887a1747c46ee4abf60da19509637278c5e944076b16607a8304a4eb66d28809469afe8ef835e6712ff8122e82381aeec6bc0af344e22a5d06e01f3114c831078dcb9afaec6e5d4c27342302e2c001fa5afb50bd322d8516bae3c4a2dd15b263575a2166c886ed2594465c2685e01ec03559fb6564572e045d12e1ca4c419fd8bdc58754b75e642a89b82fd74451d1019ed54c578de9317b81343d10bcb68480a169a9a6952e5633af4ae803f7031e03e16a7a8191024cd98cd2dd54309ce8f934082d37b9f097f2596814bb2efca328826816eae4f78720368aed1d853a4f844d55d6870ad1251ee4abd9571d3e26d4bb279c8a5a9612df479923528b497d93f9a23fb0c6ce73fccff11210b3e96f41929221c1a9dc99315d2c133662004d80248ab60f8b447d167bf2f0624a0cb11b45d781ff15cce763792915aac2a604a42520889ad9c23c93a5bca1e0979a27d697f0d307ba0a740b26c21bee452054a2d5ea88ace31e767773ad9e900ffe0266c00eb1ba2433d3fb676b775abc63e664b488ac9fe94cd7b862d45bebadebdd931cbb2396602b048a680bddc87fa97c68aa47e1b670a2a836331b75b31e54619d244880563ff26547b42e1e8ec5ea9247343aacf3e8c96d4e9a5de936ebcf55f4aa0255a236b526fe6636ed7a7194ece504185a47a4aff8f2aea33ba6ce72b3efaf1d52b2b5e0272929ecbdc5ba16607f7cfcdbd614dd335c6a78b252873700e3c4a1a52b92ae43a972c853a019f2b6844ebb4d9608774f0b1ebf593977e4a1dc847060f5e9214677e05351621dd63da0bebb4c5230600d6dc9bb22e02ce967f38287ad16a9bb58a3d9a97208a8b3e5e8af7a4123d447241d58bc27731ce4787ed6ae166795715310f4fa65878e3656dba855df6e61e8aaa","v5":"0953fad9c60b8986052a7922c92cd032f4bdd04696ddac1ae7c2bbd1206a359f05c71bc68ef932d08e88b47228aef9586f6744719d825e1cd36d52f89a3222606b2d4e95c86462a09d2e3561d21b438646ebd1af4c23c2e3f27e22171b8a200209cd969aae5e70d1e9e728467f29524f8d0814b1b8291be5a64d5db06a1b1e441a0ab81146bd88f5d652b60d2429180a547b59e6b145c6ab30963d1cd69ee9b0e26408f971485f07fba1c05b41725a0a031ed2b3ad97c5b6d18ac8960471b17e9f743c92c095f2de244a9b265df249026152993c728d956be1f21e21376800cd5a24065a42d9483b21a239c53d4fb17c71c71468d08c066d6d238ca3638d64c810a76ddc41184236f2668e52381e343828277079b48949a75c27d1c3946912637d82d5f63960324239888b088bacbb26b357df64f093ce1f54385bf396c8f2930514172b08e5c0ad56b6a4ee5df560e67d3a48dd20660f30b5c1d505f351f7a8088ef662126866f2d4a2b1d2f3852538c021c254bb2006a22aeaa88a1ee025b51cf341e25ff3028bbf84d91622235dba2eddece890624f69ee7cf237a35022586727caec25337d7950c69557357920405620c55d213dd020dee5b1214c5b5a2c3565b435e6331d93175dbb99d1ac13913e99f87019c84ffc611a7de32f87dc05d5eb0c5c63e06f026d9023aa5e1f3230088e3646bacaed93de950dee29c42e7aafb8a96b7611f65d959d705d596f4008ba95b2979f9dade5e448d735be204cb8200d79a03ee6662aa2a779517cc00ac08971dec9b1458ada75651cd55a9b2527d959e3b6a827808126374be8751db95aea4a2eea1d750c35dec4782d9d6a5412952951716939341091b49612e57bea3206aa420034abaf3c115709a286b67e7607c75011fa1101c27b875092383d0cc1c5a6b04ead10e85c5dda177eb6eb2ec1612d84e700cc53351cf8e3053868b86fae0d86d89a6a0bc412ba5b49dd636cfb0a26ddbca1b4a0356c9f17997104d7d86d6e2acd7fdab1419f162d9daaaf05bf7eb4024a5103a52b553895f4d51b83197df7881117411e0d08624ddf5ac4871b5e85eb9f32d583029120bb00f9d12f5e196caa3ad094400d4a54f9e7e3c5a9b16e5769424c2b8d291a66dc9a36bf898d73af45c57caa43f73242aa262e22e1cf67db817a206403c6a19c7e107bde42143be1626091ebb1064590c8aca07615fde86a608f665a4e23756ba056668df6776b4ebf7bb6fd547ec7bcb97c5664200391","v6":"09516c07da5ea36d6bcedd73e9e73c45a5fc62696b4272c8dc0691109a0844d4b13162f83931ec2890d7dbad5daae080dab35884ad8a041f53b56932d0670b3db5016ec2ea20502c8a5387df6f1996713cf66fe44673c5ce633586356caa03a10b1efc5e04c92065e21b469012064363ca8e2ab7e4b9c059a4dd8f78404c012ff1103336aef2aeb40893059d384eaae9aaf71119b8e975d336c47745f4ab2a73255e7be516aa6f04093c46db806745907959c460ccc178249d4e919de7283428f6578ee7dd1568f4b2e8c32262f5f315fc22fa0cb0eeb73a1c733bf83e70b24b1821902433ce64f598d678c282a9643c7da8385288ac77123bb83b5ef52c2db87671c23e5dc096e1cd0b00270c07c8ce1adb133cca942084515190d4e03d093670d0c7db9ecba2aa08c161698f921fde7fe4c0a0d6a2a690d31a8b7b0f86e616a0e5c934747ab54de4e0bf80081bb8de180380e4e84e6cf9a774a574c7267d555937263b4c623906a52aed90a72b6aaa95fea3c81409224620df509d09bebb9b03d86f5a391a2de1e902926b172ea1b176dcce75cb5ca4649a22d2ebd3741e6de14474d9737f9aeed7f5d7677176d4b2a45e3ca15573c64c188656dca72a4622756b249e90ce0e57113e9f7918a542342ded96220a9a686ed751a28958a9204d7bfe1d694534c5865728c1ad622233380eebab01e636ae83de29e8ba48e7de9b793978489f459da57a3845294c5d9e98aa3beb90a88ed8346850525186113f3bc66b5011d5dad795db0e850502995c1b9c45105f142655b5b560d55907ee9873d2a5d9f383de08d01dc3151835193cbf76a61166a3827a249816f207246cda0bc391ad0d51a0821bd50828c9c43026ce8c62d710ce97cd512601086f87bf6ede1777cb518864d8c69288d6c29efdb52604c91a78223974de08874fb549c51e6ba4106270e6b619a94a39e8e9b0905e270202c16423ce143687f911a65ca4917db3fd5bbc933e28395b1750895450542eacd35ac11785f112809970b983611f10a775fa857e5ae9121566044e594b6ea28b461f66df699c38b2b454fd80def57413576fb3adef061a14e6b97da283834d38109055f3ab4e5a982668320e479a95f2c0442c8830b1a080bb391acc9024861bb72bcebf742963278e2cbc083229a3cd820a4d78ba69a90f6e82cd99ec5d1a98769c5535939b1bd4607aa6ec8dac51cb55bc62cc13c253b700d56a508854c07447d0721606a31ac8693a4c43b4d7a13f","v7":"09949924764aa93e693dccd7ca2dc8913ccca6fad1611210c1905fce4b03b8747063e240701639c762926b40bab0f8c30f224c8c424b6a4a313452ac4174a051b01913c37cdab018c185329683981aa0854a4ed6758b747a7930d96b32a9091bb8df31621a63b1fa62cf55fef8f60726917d306c728189b681003c1566e8c778ea70617b1ee867f9d388868ad35a7ef3000c5b6012018c963e11270fba4a1315282a13c85df70994681182000099042b7921f152f8dcb554b075f91d2ed171309759389a4c399d1197b964d58f44e341312a0d48e97f8b12a2909ee8e8a0c1ae8a2ffd022954ceec8e31d0897cacaf56cce362b361174c35de35d61d697e6584a3b4884c9555c4bbc1c7526a06228b4d148324e0b451e629dbab7578b07a247b4d8a5f1a3cadb538f4218632dbf59afdb2c8db2fcc2355e753a0af5875c09bc1549da95080c03016cf2c46dad5fac3a40510c121648b605196369e897748897c02f3e002c78b23544a5b58418ab6a12658e89bc2b61578746a4332a76acf7b878a5b567470558c11de675e87c2328fb41bb914f38d5a76050a40218fa4785afe43e3ae24fa22386b32479b7e90e6a0d69b18bd8524986478ca53b37c65c8adee18564ac0210a5322266e7e43ede4608524d6d2a6817825d97219e2eb658325cc213684290d6166775fa90bab65b4a0878b7abbe445ab1712da1470a997ed0c3d762c75518cc26c61129c482e8e75b89e4e5a280f4964de97e1dc87f018f1fd762cc388a6b8b2a8c402d7ab35bfb9b510d592b5b626219c1d3b615703fa4bf0b27a108449865351ea2048d7ad3498bef4e4954e10010925d0aa6aff9424871b7d22490e05c288a5d3b98bd98de80e6ff69bfc5273d95df95f2893bbad18854cae412bb46a575e42e2414620751d7c5009d46bda47c18dc92e190c16a81b808d044c0ab8b867d4d1305dfc76329f9617b12eed6a9e64f515fa6565655bd8a9ceee252267a484ba5a5ad4d65f6b69803250677c84b12ff7c05327a608e3a0665ac571080fc53e298da3cee14a0b8f9a985547a36e483a5638708b5924be2b055f20afde5b6d8cf456a5e821903d38934e5832a6a836e038c06fbe1eae4233abec60f1be5b270d83614266a3e56a6a79f8fa94a02a1aa9204ba7c58417912ede10eb90f3851094b6d82c2d6b0858754923f029c5bc91da1e68a32995a49124ca4be659a361d5d002c8395790144d8ec52c6234afcf433de8c807a01f329e5c48c36029","v8":"09589a51729216d2692e7366b7ddaf787a33c93a661a9be27ee10f131811425786e154118b9d79e47acd4b040dec3023de895ab2f39ac5438715692803fc8912876475e6da278126bd18d9b2815473de9d57154ead43058b157b50cc83dcebba324aee1364a5569feaf6b36c8eabdfc0a398eca9e3a594b00c64c922ebe4e57fb5497a1ed28b582e0679db496d68c947a4a3036b6e7c302965a0890ca214741f6b2a5368d53bc360f943c6c070cda6a51d1a4395946df73875ae47aa5c185cd465a1f9d13b76b48a7a23d29750d6d89a461744a970c6a105e3799ba9635815aaee3929a52823097e2a958804322166a351fc331020fe94065a9b1087208afdbd3a8a88582688871ac2c9fe9ea24028336f5b4666a7eb8be6b279108113e3eec829b03cb46b8b0f37887315ba41c8a1b9dfc9bf612c2d98afe43c552513edd692c25fd07d6115c5e14f3233d51660d66ea04b8a5372cee1446fee4170aec1fd51a4af6ba7c01e96cd03c734eb1d68ca8631fce3ab8219fc903b59275fe5ee72501f2a2c341fb64019bc31005e3bc76ab43a89a85b1c5a1c39246824a29b426c7513dbbe652faa159c831d2406335dcc098e29806eb025b02116ca9060c1e5f4234e116a7a29e22d29654077726d12b67ba0e9f2bde264904e0775b9d01d715d2a751e248631aa6186d02ca7adddadb7e11c5364e098f11e55d87b8476078c236644a96c8b486f177721f9daf619f7111c2b0339e34c5619052999a0d315f0c7169201124fddf9c581800611299014cf4ae72f113075dee3f7604deff92ba27c7a12417ab3d1699c0ce362ee0c1b746a37b39e458406921d1335085e452c3e0a4a8d2e3e4d0c39f3447cb6c4e97a0b450760c65a59eedc91b8ccd7701d2ecaa04cbc072a1a6968192c924e138c254e98a11eec2ca50c7966f6af5b22d5f21874a7034df64e9ba7283c987d12f8b3e9ea05da6f93d953fb3bc29914568dda24d1734198c221b679e548059eb148d0c5447c965746d2c0bb76d59b5a88ab060845cc6e0cb23958a0d616558d67fd19b7b60a13a1d003d8a1f2ac72fad71573b82b69cba94c5d09c4425b947a55c4cf0338a2cf475e6e32ce89e676b0ffc367cd135350f1036cd9973188d857c92b883814bdf203e6cc2e36d9e7ff963a305c24c524057776b68c57f2605214cdd5135063a07ff5c755b7c83a32f64c024729e63a75dd5ac7c92c292218bac748a30232a913f16befb971dbf69fd25101299e58fb10d3","v9":"0954b2fb456a0b0da48ce79051698cbfd15aa1e543ff616d8b56b8a4a00b59fa03c414a399f0fcc8ff5acd3bea398beee12a6bbcfef68fd9f2afc508ba7b08d0670544769f2db309450da2d1640caadd462683a5e05eb9372a6ed50db1ac6440f91ab0477a478b971f0d2ef8ddc72349aa80d4b1266ba38b35109320f8dff5567004a87f019114de56616910320a5031b46e0b71ba1c66ead6281053d913eaae0a4837fa12d06225ef7082d68403e1d69cf08ed9b2d94340c6aa3aa79ffb19454019b5025a9726a617b0ec9b10f91bd6ae8fc95108e0d0aecd69252c64b147419f7165d1caf1139d220d9b34f39052a650d17a92687392881d24d6aa9b1c0075170125ee98ad7279134bc57eac78d14c13e38916a7642454d44fb443f69993efbf72bd93741f533640e3a647829e5764d7a1d18ea7637175a5fa66fa9a5e0bb3f6c06274a0b8c70e638619fa2982dac8a952d1d07b12db7f58f8d4dbad520100e9f4901145de5eb66269a719036d11da527c1b5330169868a964d21688564b246e12b6cc92a835d7db9264dae1186f6dbfc90c4774923c5fd96c911a528845d0f023a907f038f0a4258d955c191ad0248700585d154e204c1514478ef831ead8407baa1f5228e6287599637a63e42d061afe07e9ed536b3c15d9e900473aa20ac4fbc44098b927d78b89bc0add6562d50328301862689e0d13bcc001282ed8acb581bdb2ae698212f895e01bd37222ba5bd5c090731414cb18c8156b2624a1d7ecc022316168181bdce559bed3134091d281022ea2816a71197649b206e2309cc47891cbcc257a8535e7758419764a09b8099f64a15a31a68e05ba9c19008b9e6f9136058010c12068b9eacda1bc88e9665ec4aa031771b50e4945cc0eb59e083313f15f0e10d8009b2f451e4ecd690b328a5c0f72d9602e894e61c91ce032abcc6b027848ee4b3f3196ceb7bdaabc3e18bb77eb09eea141c723cdc9519c50f2a4118170b1ec4fda9255cc561ecca09c556ab7b59e492dd44266c5028527c0d95566369056e3e3060038b6a5e633680491545045d8a44e36577916b671fc6af6fbcd4b37e06197e544252bfa72fb7dad2527540a8b5d04f99901491ab068aa4f91b0e338d6a2361a3ee37ba63e2eb533391e5c808a318f1447e2e90fe18562260e7c272de5e109684464be7a05fb15fa28cddc3681ae9324e691e071df38539c09728f9d5a32e1be414d5cd86a782f54378b88a1b54fe0fe061a00a5562935cf7c","watcher-browser":"09a4d80e485f080dbeaa075b8aa623997a1487b26ace777a9691c6847da3c6782b46c57087b466d20c552d015a7dfb829c78a8f54e571d21510150b5b6cdedf58406fad8e71eb91be27668a36e51343a3dd043eba55719147ac945bc8989b1a3482cf2294d3232c2d440b5f159eb56ce5084a433674f93c6abb9ff1a7ba50f420817b671650f101ab503d66caa3aa2d1b1a784db1b4c4e5823d6e145b25160929f355dbda1e4945ff72064dab7f46ada0dd4d1f4525be0362a90037da3da0b04bac3bb218945b93e01774f4264fd41a0d24e0347cc3fc730680307090e87945ee09569bdc642afdca22adb4692c7de53c9315b4f85139032aff622677445560a69d017b39afeb1165f078c90d657a9338e0839381a874cd8fa67a820675f4ab58631d9a5b0ebed1e257bd8786f0f6cd8b3d471677f248d41611145ae689a0b52c71cb863341b2363e6b18e4d756a6e211a6394a570349b110aa675a4fb2c856b850826b5ddea0ff90332acd34b31c1eb097895e65ae15c27f059c48b2214268d8f46694a3099aeac48216666268ccc6bbdbaaa9b5f6161a81cb62987c77f182cc3d12da95a20814167c26abb6e90591635d578956c9eca5b478794328037d8c9066da6da65d5137eb8ce07a1a8129833e6b3f0116dc04bc62ea107deaf4424c3a8d84589071c3bf9050cdf1e85f23570a2ab2d9803714c6b0179447513ab9180ab1d3c36cc24209dd88149fb9d369ca8724acb519c375816988fcbdb803e774ad4e2918264bd816f5a553488d7d39f9eb2237eadaa1b6156985a850b752f3413d9c49b2d577987b5b2abb6e13240152fc9f4a9324cc1576be4d2a42bcc57d7c385d484327a32dae6df2aa976e6761da3ae685aa2ef1568059eaee6169c19739879916b1d291cfca698e554ba55fd7e987ac3ea9c7e56f8f1948427123de6da4d65843cc787acda383868623167e6f34764fb13dd0a159944a4a52343ea6e088a71d886b91b996dca278c957791e27ba0c8c205aa833245685807549584c7abad0eecbbe55469bea502c780ae6bf413392d27e45c06302ed98bc29aebaefddff608624fb879a680051126ae80e33b8c6514195ea190a6df069799728159da4c41c97980a1a4fe781981478d5c6905cdbbe4b5563f83c4c4618f28477641597b465486616c35970ba07e5451aa57b65ff7355a3139e256eb71d881a0be9584a5756b965044f3584e3cc3b360d97460b1c213d538468503811cd02c9b60d7a9224987","watcher-eth":"09943ea11440cbf868a50eb3849c428c3597465053158ee810dab09eacbf0e4757182ecb7fd623505ca23d55cabb624bcc2564b027724c4af2b79a1cd6a5cd0779de38a24f9addbd324d911268354330a94b56288f722e2f0615896e2fa4df454607fb16a911814bcfc7a2dd835b9baf5b756df008f184f23b51b36a449d3a93588c1015235377ce0d1387a08995c6f6323c06b10685ffdbb7859aaebd1290a810725ad9c0c644942b882ec1f9b2e899880819263b5d6e97bad31aaf9702b4d9d023af437c618d0201c0a5a31a2a73739897db0d662b279f2344338909c1ef57372ea62d62dc009d32fc0db6de8dbbb6da29448acc5b430afb403252a04b6d90607250936015ec686542af2246d727a44958224962d8bc443666a2f9a76b6a394881a2e1a2a2e4604a041820e86d4ec424c08f0ce47855eea79360de97b5d6066e27ed81ceab20654f85b1a9e25ae8511206c826f7e8aaa06c88ba3b009f239000a4557908846a8c0e91f20cbd0931ba951f5fe8a261dff6569929469cc631ba4a856860f761ba505216e9de76ec923c24b4b862bfee68bf617bd9d7adc2a3325de7c75df03020643a34a8f77974820532dac22a4872583e0c89aa0169a91c91fa9bcc69f188c1981bbc7c751b9c8db345a3e243ce2fb68ac8738cc9659be1e90b698633acda4dbbac4d8fbf4c2ecb58064560f670e298a776539155fb874527ac543683929059199c07f3f345428562a7403e5aa5559e4f8adcd3194c5ce9477a6362aa7db531518e6e6651e0757c248166a8fc685ad8c6af0e96b7d9070d6099764a1fc57b9335dea2644f0d35a6b7f9ce9c916bf13f855cc35f7af862b5d062e9a2a1dcea40953a18306d562293a6693da171145461453ab7542b17617b90f5a01a2a2e1d2952f1808844bcf8fb7127a6be9c7e54a5ba04d337654697c7222c71e6a4604415d5a7d11b9b7a839ab3557364a84c1586657474b85b35a16151c6afa86743528ed7f60c6a46a9a8dbab266f9d1e5eaac55b0664c8c2017b8c21019832b1a800b61ac81f2bd91c0e30960a82cf129575dd23f31f6fd7676af3e1cda6880115d5004912f115a5c965dd1d365f60428a860960162de00577ddcf9004ad495f1ef050e65ae698034638167646f0ea5c523d61c107d69369adca03268325ab01f53b33dec48a89a5f7818e2654e958125c0f3ca975a949f02b7855f1b7639fdfd55502ee02e4963f73d12863c705ebbd2e57b945501966f22eb77c1040"}}'
RING_CHANGED=0
install_ring_publics() {
  local nid dest
  nid="$(kv_get "$NET_ENV" NETWORK_ID 2>/dev/null || true)"
  [[ "$nid" == "2300" ]] || return 0
  dest="$KEYS/pl_keys.json"
  [[ -f "$dest" ]] || die "missing $dest (run the installer first)"
  have python3 || die "python3 is required to add the network 2300 public key ring (sudo apt install python3), then re-run"
  local added
  added="$(RING="$RING_PUBLICS_2300" python3 - "$dest" <<'PY'
import json, os, sys
dst = sys.argv[1]
src = json.loads(os.environ["RING"])
d = json.load(open(dst))
if d.get("scheme", src["scheme"]) != src["scheme"]:
    sys.exit("scheme mismatch in " + dst)
p = d.setdefault("publics", {})
added = [k for k in sorted(src["publics"]) if k not in p]
for k in added:
    p[k] = src["publics"][k]
if added:
    tmp = dst + ".tmp"
    with open(tmp, "w") as f:
        json.dump(d, f)
    os.chmod(tmp, 0o644)
    os.replace(tmp, dst)
print(len(added))
PY
)" || die "could not update $dest"
  if [[ -n "${SVC_USER:-}" && "$SVC_USER" != "root" ]]; then
    chown "$SVC_USER:$SVC_USER" "$dest" 2>/dev/null || true
  fi
  if [[ "$added" != "0" ]]; then
    RING_CHANGED=1
    ok "network key ring: added $added public key(s) to $dest"
  fi
}

# Network 2300 QC profile. Same file the seats load from keys/lc/bridge.json.
# Without it a joiner snapshot leaves qc_start_height at 0 and every v4
# ledger is rejected ("v4 header before qc_start_height").
install_qc_profile() {
  local nid dest
  nid="$(kv_get "$NET_ENV" NETWORK_ID 2>/dev/null || true)"
  [[ "$nid" == "2300" ]] || return 0
  dest="$KEYS/lc/bridge.json"
  if [[ -f "$dest" ]]; then
    return 0
  fi
  mkdir -p "$KEYS/lc"
  cat >"$dest" <<'EOF'
{
  "start_height": 116957,
  "network_id": 2300,
  "key_root": "1c2c1bfbca036b7566dd53d7f8ccbeebe371b9d20e15a8dc9c2e720f0ff6091d",
  "qc_header_version": 4,
  "qc_start_height": 353091
}
EOF
  chmod 644 "$dest"
  if [[ -n "${SVC_USER:-}" && "$SVC_USER" != "root" ]]; then
    chown -R "$SVC_USER:$SVC_USER" "$KEYS/lc" 2>/dev/null || true
  fi
  ok "QC profile $dest"
}

write_runner() {
  cat >"$BIN/run-node.sh" <<'RUNNER'
#!/usr/bin/env bash
# Generated by falcon-node. Reads config/node.env + config/network-2300.env (parsed, not sourced).
set -euo pipefail
H="$(cd "$(dirname "$0")/.." && pwd)"
g() { local l; l="$(grep -E "^$2=" "$1" | tail -1 || true)"; printf '%s' "${l#*=}"; }
N="$H/config/node.env"; P="$H/config/network-2300.env"
# 2.9.74: node.env may be mid-rewrite by the installer; retry ~5 s before giving up.
ID=""; for _ in 1 2 3 4 5 6 7 8 9 10; do ID="$(g "$N" NODE_ID)"; [[ -n "$ID" ]] && break; sleep 0.5; done
[[ -n "$ID" ]] || { echo "no NODE_ID in $N" >&2; exit 78; }
cd "$H"
# Cap glibc malloc arenas so periodic snapshot serialization returns freed pages to the OS.
export MALLOC_ARENA_MAX="${MALLOC_ARENA_MAX:-2}"
# Seat payout: pass the payout account to builds that know --payout-address.
PAYOUT_ARGS=(); PA="$(g "$N" PAYOUT_ACCOUNT)"
if [[ -n "$PA" && "$PA" != "$ID" ]] && "$H/bin/falcon-pl-node" --help 2>/dev/null | grep -q -- '--payout-address'; then
  PAYOUT_ARGS=(--payout-address "$PA")
fi
exec "$H/bin/falcon-pl-node" --id "$ID" --join --role val \
  --listen "$(g "$N" LISTEN)" --keys-dir keys \
  --snapshot "data/$ID.json" --snapshot-out "data/$ID.json" \
  --max-chain-ledgers "$(g "$P" MAX_CHAIN_LEDGERS)" \
  --validators "$(g "$P" GENESIS_VALIDATORS)" --scheme "$(g "$P" SCHEME)" \
  --load-wallets 0 --bond "$(g "$P" GENESIS_BOND)" --network-id "$(g "$P" NETWORK_ID)" \
  --seal-interval-ms "$(g "$P" SEAL_INTERVAL_MS)" --pack-budget-ms "$(g "$P" PACK_BUDGET_MS)" \
  --progress-timeout-ms "$(g "$P" PROGRESS_TIMEOUT_MS)" --max-txs "$(g "$P" MAX_TXS)" \
  --max-mempool-txs "$(g "$P" MAX_MEMPOOL_TXS)" --epoch-ms "$(g "$P" EPOCH_MS)" \
  --first-claim-epoch "$(g "$P" FIRST_CLAIM_EPOCH)" --unbond-cooldown-ms "$(g "$P" UNBOND_COOLDOWN_MS)" \
  --snapshot-interval-ms "$(g "$P" SNAPSHOT_INTERVAL_MS)" --online-epoch-heights "$(g "$P" ONLINE_EPOCH_HEIGHTS)" \
  --admin-sock "run/node.admin.sock" --lock-public-wire \
  --peers "$(g "$P" SEEDS)" --hubs "$(g "$P" HUBS)" \
  ${PAYOUT_ARGS[@]+"${PAYOUT_ARGS[@]}"}
RUNNER
  chmod 0755 "$BIN/run-node.sh"
  cat >"$BIN/fdash" <<'FDASH'
#!/usr/bin/env bash
# Generated by falcon-node. Launches the live terminal dashboard with seat-claim enabled.
set -euo pipefail
H="$(cd "$(dirname "$(readlink -f "$0")")/.." && pwd)"
g() { local l; l="$(grep -E "^$2=" "$1" | tail -1 || true)"; printf '%s' "${l#*=}"; }
N="$H/config/node.env"; P="$H/config/network-2300.env"
L="$(g "$N" LISTEN)"
case "$L" in 0.0.0.0:*|:*) ADDR="127.0.0.1:${L##*:}" ;; "") ADDR="127.0.0.1:19400" ;; *) ADDR="$L" ;; esac
CTL="$H/bin/falcon-pl-ctl"
if "$CTL" dash --help 2>/dev/null | grep -q -- '--keys-dir'; then
  exec "$CTL" --addr "$ADDR" dash --keys-dir "$H/keys" --scheme "$(g "$P" SCHEME)" --network-id "$(g "$P" NETWORK_ID)" "$@"
fi
exec "$CTL" --addr "$ADDR" dash "$@"
FDASH
  chmod 0755 "$BIN/fdash"
  if [[ $IS_ROOT -eq 1 && "$SERVICE_MODE" == "system" ]]; then
    if [[ ! -e /usr/local/bin/fdash || -L /usr/local/bin/fdash ]]; then
      ln -sf "$BIN/fdash" /usr/local/bin/fdash
    fi
  else
    if [[ ! -e "$HOME/.local/bin/fdash" || -L "$HOME/.local/bin/fdash" ]]; then
      mkdir -p "$HOME/.local/bin" && ln -sf "$BIN/fdash" "$HOME/.local/bin/fdash" || true
    fi
  fi
}

# ---------- service ----------
unit_path() {
  if [[ "$SERVICE_MODE" == "user" ]]; then echo "${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user/$UNIT.service"
  else echo "/etc/systemd/system/$UNIT.service"; fi
}

write_unit() {
  [[ "$SERVICE_MODE" == "none" ]] && return 0
  local p tmp; p="$(unit_path)"; mkdir -p "$(dirname "$p")"; tmp="$(mktemp)"
  {
    echo "# Managed by falcon-node (installer $INSTALLER_VERSION). Re-run the installer to regenerate."
    echo "[Unit]"
    echo "Description=Falcon PL testnet 2300 node ($FALCON_HOME)"
    echo "After=network-online.target"
    echo "Wants=network-online.target"
    echo
    echo "[Service]"
    echo "Type=simple"
    if [[ "$SERVICE_MODE" == "system" ]]; then
      echo "User=$SVC_USER"
      echo "Group=$SVC_USER"
    fi
    echo "WorkingDirectory=$FALCON_HOME"
    echo "Environment=MALLOC_ARENA_MAX=2"
    echo "ExecStart=$BIN/run-node.sh"
    echo "Restart=on-failure"
    echo "RestartSec=5"
    echo "RestartPreventExitStatus=78"
    echo "LimitNOFILE=65536"
    echo "TimeoutStopSec=60"
    echo "StandardOutput=append:$LOGS/node.log"
    echo "StandardError=append:$LOGS/node.log"
    if [[ "$SERVICE_MODE" == "system" ]]; then
      echo "NoNewPrivileges=yes"
      echo "PrivateTmp=yes"
      echo "ProtectSystem=strict"
      echo "ProtectHome=yes"
      echo "ReadWritePaths=$FALCON_HOME"
      echo "ProtectKernelTunables=yes"
      echo "ProtectControlGroups=yes"
      echo "RestrictSUIDSGID=yes"
    fi
    echo
    echo "[Install]"
    if [[ "$SERVICE_MODE" == "system" ]]; then echo "WantedBy=multi-user.target"; else echo "WantedBy=default.target"; fi
  } >"$tmp"
  if [[ -f "$p" ]] && cmp -s "$tmp" "$p"; then rm -f "$tmp"; UNIT_CHANGED=0; else mv "$tmp" "$p"; chmod 0644 "$p"; UNIT_CHANGED=1; fi
  sctl daemon-reload
  sctl enable "$UNIT" >/dev/null 2>&1 || true
  if [[ "$SERVICE_MODE" == "user" ]] && have loginctl; then
    loginctl enable-linger "$(id -un)" >/dev/null 2>&1 \
      || warn "could not enable lingering; the node stops when you log out (run: sudo loginctl enable-linger $(id -un))"
  fi
  ok "systemd $SERVICE_MODE unit $p"
  write_logrotate
}

write_logrotate() {
  [[ $IS_ROOT -eq 1 && "$SERVICE_MODE" == "system" && -d /etc/logrotate.d ]] || return 0
  cat >"/etc/logrotate.d/$UNIT" <<LR
$LOGS/*.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    copytruncate
    maxsize 100M
}
LR
  chmod 0644 "/etc/logrotate.d/$UNIT"
}

node_pid() { local f="$RUN/node.pid"; [[ -f "$f" ]] && kill -0 "$(cat "$f")" 2>/dev/null && cat "$f"; }

svc_start() {
  case "$SERVICE_MODE" in
    none)
      if node_pid >/dev/null; then return 0; fi
      nohup "$BIN/run-node.sh" >>"$LOGS/node.log" 2>&1 &
      echo $! >"$RUN/node.pid"
      ;;
    *) sctl start "$UNIT" ;;
  esac
}
svc_stop() {
  case "$SERVICE_MODE" in
    none)
      local p; p="$(node_pid || true)"
      if [[ -n "$p" ]]; then kill "$p"; for _ in $(seq 1 30); do kill -0 "$p" 2>/dev/null || break; sleep 1; done; fi
      rm -f "$RUN/node.pid"
      ;;
    *) sctl stop "$UNIT" 2>/dev/null || true ;;
  esac
}
svc_restart() { svc_stop; svc_start; }
svc_active() {
  case "$SERVICE_MODE" in
    none) node_pid >/dev/null ;;
    *) sctl is-active --quiet "$UNIT" ;;
  esac
}

# ---------- status ----------
local_rpc() { kv_get "$NODE_ENV" LISTEN; }
local_status() { timeout 30 "$BIN/falcon-pl-ctl" --addr "$(local_rpc)" status >"$1" 2>/dev/null; }

wait_sync() {
  say "waiting for sync (timeout ${SYNC_TIMEOUT}s; a fresh node first downloads a ~100 MB snapshot)"
  local t0 now st pub tip best lt=0 lag
  t0="$(date +%s)"; st="$(mktemp)"; pub="$(mktemp)"
  while :; do
    now="$(date +%s)"
    tip=""; best=""
    if local_status "$st"; then tip="$(json_num "$st" tip_height)"; best="$(json_num "$st" best_peer_tip)"; fi
    if public_status "$BIN/falcon-pl-ctl" "$pub"; then lt="$(json_num "$pub" tip_height)"; fi
    if [[ -n "$tip" && "${lt:-0}" -gt 0 ]]; then
      lag=$(( lt > tip ? lt - tip : 0 ))
      printf '  t+%4ss  local tip %-9s public tip %-9s lag %s\n' "$((now - t0))" "$tip" "$lt" "$lag"
      if [[ "$tip" -gt 0 && "$lag" -le "$SYNC_LAG_OK" ]]; then
        ok "synced: local tip $tip, public tip $lt (lag $lag) after $((now - t0))s"
        rm -f "$st" "$pub"; return 0
      fi
    else
      printf '  t+%4ss  node starting / pulling snapshot (local tip %s, best peer %s)\n' "$((now - t0))" "${tip:-?}" "${best:-?}"
    fi
    if (( now - t0 >= SYNC_TIMEOUT )); then
      warn "not synced after ${SYNC_TIMEOUT}s. The node keeps running and retrying. Diagnostics:"
      diagnostics
      rm -f "$st" "$pub"; return 1
    fi
    sleep 10
  done
}

diagnostics() {
  echo "  service active: $(svc_active && echo yes || echo no)"
  echo "  last log lines ($LOGS/node.log):"
  tail -n 12 "$LOGS/node.log" 2>/dev/null | sed 's/^/    /' || true
  echo "  seed reachability:"
  local s; for s in $(net SEEDS | tr ',' ' '); do
    if timeout 5 bash -c "exec 3<>/dev/tcp/${s%:*}/${s##*:}" 2>/dev/null; then echo "    $s open"; else echo "    $s UNREACHABLE (outbound TCP blocked?)"; fi
  done
}

cmd_status() {
  load_installed
  local st pub; st="$(mktemp)"; pub="$(mktemp)"
  echo "home:      $FALCON_HOME"
  echo "version:   $(kv_get "$NODE_ENV" VERSION) (installer $INSTALLER_VERSION)"
  echo "node id:   $(kv_get "$NODE_ENV" NODE_ID) (role $(kv_get "$NODE_ENV" NODE_ROLE))"
  echo "service:   $SERVICE_MODE, $(svc_active && echo running || echo STOPPED)"
  if local_status "$st"; then
    echo "local:     tip $(json_num "$st" tip_height), best peer $(json_num "$st" best_peer_tip), product $(json_str "$st" product_version)"
  else
    echo "local:     node RPC $(local_rpc) not answering"
  fi
  if public_status "$BIN/falcon-pl-ctl" "$pub"; then
    echo "public:    tip $(json_num "$pub" tip_height), product $(json_str "$pub" product_version) ($(net STATUS_RPC))"
  else
    echo "public:    $(net STATUS_RPC) unreachable"
  fi
  if [[ -f "$VALDIR/state" ]]; then
    echo "validator: id $(kv_get "$VALDIR/state" ID), stage $(kv_get "$VALDIR/state" STAGE), bond account $(kv_get "$VALDIR/state" BOND_ACCOUNT)"
    [[ -f "$VALDIR/application.json" ]] && echo "           application: $VALDIR/application.json"
    local vid; vid="$(kv_get "$VALDIR/state" ID)"
    if [[ -n "$vid" ]]; then
      echo "seat:      rewards $(account_field "$vid" seat_claimable) FPL (validator bucket), payout $(account_str "$vid" seat_payout) (config: $(kv_get "$NODE_ENV" PAYOUT_ACCOUNT))"
    fi
  fi
  rm -f "$st" "$pub"
}

# ---------- dash (live health view; q quits) ----------
# Local node RPC for the dash: a wildcard listen is dialled on loopback.
dash_rpc() { local a; a="$(local_rpc)"; case "$a" in 0.0.0.0:*|:*) echo "127.0.0.1:${a##*:}" ;; *) echo "$a" ;; esac; }

cmd_dash() {
  load_installed
  if "$BIN/falcon-pl-ctl" dash --help >/dev/null 2>&1; then
    # 2.9.80: `c` claims seat rewards, signed with the seat key in $KEYS.
    if "$BIN/falcon-pl-ctl" dash --help 2>/dev/null | grep -q -- '--keys-dir'; then
      exec "$BIN/falcon-pl-ctl" --addr "$(dash_rpc)" dash --keys-dir "$KEYS" \
        --scheme "$(net SCHEME)" --network-id "$(net NETWORK_ID)"
    fi
    exec "$BIN/falcon-pl-ctl" --addr "$(dash_rpc)" dash
  fi
  # Older falcon-pl-ctl without `dash`: refresh the plain status view.
  local k
  while :; do
    [[ -t 1 ]] && printf '\033[H\033[2J'
    echo "falcon-node dash (legacy: this release has no health view; run 'falcon-node upgrade') · q quits"
    cmd_status
    [[ -t 0 ]] || return 0
    if read -r -s -n 1 -t 2 k; then [[ "$k" == q || "$k" == Q ]] && return 0; fi
  done
}

# ---------- web (localhost browser dashboard) ----------
# Loopback only by default. From another machine: ssh -L 19480:127.0.0.1:19480 <node-host>
# then open http://127.0.0.1:19480/ . --allow-remote (with --web-listen <tailscale-ip>:19480) has no auth.
# Laptop-side tunnel for the web dashboard: ssh -N -L PORT:127.0.0.1:PORT user@host
web_tunnel_hint() { # listen
  local port="${1##*:}" host user
  host="$(hostname -I 2>/dev/null | awk '{print $1}')"; [[ -n "$host" ]] || host="$(hostname 2>/dev/null || echo '<this-server>')"
  user="${SUDO_USER:-${USER:-$(id -un 2>/dev/null || echo user)}}"
  echo "ssh -N -L ${port}:127.0.0.1:${port} ${user}@${host}"
}

cmd_web() {
  load_installed
  "$BIN/falcon-pl-ctl" web --help >/dev/null 2>&1 || die "this release has no web dashboard; run 'falcon-node upgrade'"
  local extra=(); [[ "${ALLOW_REMOTE:-0}" == 1 ]] && extra+=(--allow-remote)
  local wl="${WEB_LISTEN:-127.0.0.1:19480}"
  if [[ "${ALLOW_REMOTE:-0}" != 1 ]]; then
    say "web dashboard on http://${wl}/ (this server only; Ctrl-C stops)"
    say "on your laptop run:   $(web_tunnel_hint "$wl")"
    say "then open             http://127.0.0.1:${wl##*:}/"
  fi
  exec "$BIN/falcon-pl-ctl" --addr "$(dash_rpc)" web --listen "${WEB_LISTEN:-127.0.0.1:19480}" ${extra[@]+"${extra[@]}"}
}

# ---------- balance (read-only one-liner; no keys read) ----------
cmd_balance() {
  load_installed
  local acct=() ; [[ -n "${BAL_ACCOUNT:-}" ]] && acct=(--account "$BAL_ACCOUNT")
  if "$BIN/falcon-pl-ctl" balance --help >/dev/null 2>&1; then
    exec "$BIN/falcon-pl-ctl" --addr "$(dash_rpc)" balance ${acct[@]+"${acct[@]}"}
  fi
  # Older falcon-pl-ctl (< 2.9.79): the existing account query.
  local id="${BAL_ACCOUNT:-$(kv_get "$NODE_ENV" NODE_ID)}"
  echo "$id: liquid $(account_field "$id" balance) FPL · pending rewards $(account_field "$id" claimable) FPL (bond: see 'falcon-node status' / $(net SITE)/validator)"
}

load_installed() {
  [[ -f "$NODE_ENV" ]] || die "no install found in $FALCON_HOME (run the installer first)"
  SERVICE_MODE="$(kv_get "$NODE_ENV" SERVICE_MODE)"; SERVICE_MODE="${SERVICE_MODE:-none}"
  SAVED_NODE_ID="$(kv_get "$NODE_ENV" NODE_ID)"
  ensure_node_env_readable "$NODE_ENV"
  REL_VERSION="$(kv_get "$NODE_ENV" VERSION)"
  # Channel: an explicit --channel wins; otherwise keep the one recorded at install (default stable).
  [[ -n "$CHANNEL" ]] || CHANNEL="$(kv_get "$NODE_ENV" CHANNEL 2>/dev/null || true)"
  [[ -n "$CHANNEL" ]] || CHANNEL="stable"
}

# ---------- validator flow (2.9.62: `ctl bond-v2` carries pubkey + PoP, admission approval, 50k min bond) ----------
ctl_supports_v2_bond() {
  "$BIN/falcon-pl-ctl" --help 2>/dev/null | grep -qE '^\s+bond-v2\b'
}
onboarding_open() { # the network profile shipped in the release is the switch (VALIDATOR_ONBOARDING=open)
  [[ "$(net VALIDATOR_ONBOARDING)" == "open" ]]
}
legacy_devnet() {
  # Rehearsal hook for PRIVATE devnets running pre-2.9.62 binaries: bond without PoP/approval.
  # Refused on the public network ids.
  [[ "${FALCON_DEVNET_LEGACY_BOND:-0}" == "1" ]] || return 1
  [[ "$(net NETWORK_ID)" != "2300" ]] || die "FALCON_DEVNET_LEGACY_BOND is for private devnets only"
  return 0
}
vstate() { kv_get "$VALDIR/state" "$1"; }
vset() { kv_set "$VALDIR/state" "$1" "$2"; }

status_json() { # dest; the NETWORK's view (public seat endpoint) first, the local node only as a fallback.
  # Never judge readiness from the local node: a joiner always believes it is ready.
  public_status "$BIN/falcon-pl-ctl" "$1" || local_status "$1"
}

validator_info() { # status-file id -> "present bond jailed inactive lottery_ready pubkey_fp"
  py - "$1" "$2" <<'PY'
import json, sys, hashlib
t = open(sys.argv[1]).read(); d = json.loads(t[t.find('{'):]); b = d.get('body', d)
vid = sys.argv[2]
for v in b.get('validators', []) or []:
    if v.get('id') == vid:
        v2 = v.get('v2') or {}
        inactive = v2.get('inactive', v.get('inactive'))
        key = 'set' if v2.get('public_key_set') else '-'
        print('1', v.get('bond', 0) or 0, int(bool(v.get('jailed'))), int(bool(inactive)),
              int(bool(v.get('lottery_ready'))), key)
        sys.exit(0)
print('0 0 0 0 0 -')
PY
}

approval_of() { # status-file id -> pubkey hex approved for id (2.9.62 status.approvals), or empty
  py - "$1" "$2" <<'PY'
import json, sys
t = open(sys.argv[1]).read(); d = json.loads(t[t.find('{'):]); b = d.get('body', d)
a = (b.get('approvals') or {}).get(sys.argv[2])
if isinstance(a, dict):
    print(a.get('public_key', ''), a.get('expires_height', ''))
elif isinstance(a, str):
    print(a, '')
PY
}

account_field() { # account field -> numeric field of the account query (via local node)
  local out; out="$(timeout 30 "$BIN/falcon-pl-ctl" --addr "$(local_rpc)" account --account "$1" 2>/dev/null || true)"
  grep -oE "\"$2\": *[0-9]+" <<<"$out" | head -1 | grep -oE '[0-9]+$' || echo 0
}
account_balance() { account_field "$1" balance; }
account_str() { # account field -> string field of the account query ("none" when null/absent)
  local out; out="$(timeout 30 "$BIN/falcon-pl-ctl" --addr "$(local_rpc)" account --account "$1" 2>/dev/null || true)"
  grep -oE "\"$2\": *\"[^\"]*\"" <<<"$out" | head -1 | sed -E 's/.*: *"([^"]*)"/\1/' | grep . || echo none
}

confirm() {
  [[ $YES -eq 1 ]] && return 0
  if [[ -r /dev/tty ]]; then
    local a; printf '%s [y/N] ' "$1" >/dev/tty; read -r a </dev/tty || a=""
    [[ "$a" == "y" || "$a" == "Y" || "$a" == "yes" ]]
  else
    warn "no terminal to confirm '$1'; re-run with --yes"; return 1
  fi
}

write_application() {
  # The proof of possession is not in the application: `ctl bond-v2` signs it with the validator key and
  # the chain checks it against the approved key when the bond lands.
  local id="$1" acct="$2" pk bpk nid; pk="$(pubkey_of "$id")"; bpk="$(pubkey_of "$acct")"; nid="$(net NETWORK_ID)"
  py - "$VALDIR/application.json" "$id" "$pk" "$acct" "$REL_VERSION" "$CONTACT" "$nid" "$(kv_get "$NODE_ENV" OBSERVER_ID)" "$bpk" <<'PY'
import json, sys, time, hashlib
out, vid, pk, acct, ver, contact, nid, obs, bpk = sys.argv[1:10]
def key_hash(h):
    # v2.9.65 C-1: sha256 of the raw 897-byte Falcon key (0xFB prefix stripped) = PayToKey commitment
    b = bytes.fromhex(h) if h else b""
    if len(b) == 898 and b[0] == 0xFB: b = b[1:]
    return hashlib.sha256(b).hexdigest() if len(b) == 897 else ""
app = {
    "kind": "falcon-pl-validator-application", "v": 1, "network_id": int(nid),
    "id": vid, "validator_public_key": pk,
    "validator_key_fingerprint": hashlib.sha256(pk.encode()).hexdigest()[:16],
    "pop_message": f"fpl-pop|{nid}|{vid}|{acct}",
    "bond_account": acct, "bond_account_public_key": bpk, "bond_account_key_hash": key_hash(bpk),
    "node_version": ver, "observer_node_id": obs,
    "contact": contact, "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
}
json.dump(app, open(out, "w"), indent=2)
PY
  chmod 600 "$VALDIR/application.json"
}

print_apply_instructions() {
  local id="$1" fp url repo; fp="$(fingerprint "$(pubkey_of "$id")")"; repo="$(net APPLICATIONS_REPO)"
  url="$(py - "$VALDIR/application.json" "$(net APPLY_URL)" <<'PY'
import base64, json, sys
app = json.load(open(sys.argv[1]))
print(sys.argv[2] + "#app=" + base64.urlsafe_b64encode(json.dumps(app, separators=(",", ":")).encode()).decode().rstrip("="))
PY
)"
  cat <<MSG

${B}Validator application ready${N}  ($VALDIR/application.json, public data only)
  id:              $id
  key fingerprint: $fp
  bond account:    $(vstate BOND_ACCOUNT)
  bond key hash:   $(py -c 'import json,sys;print(json.load(open(sys.argv[1])).get("bond_account_key_hash",""))' "$VALDIR/application.json")

Send it to Scott for admission (either):
  1. Open this link, check the details, press "Open GitHub application":
     $url
  2. Or open an issue at https://github.com/$repo/issues/new?template=validator-application.yml
     and paste the contents of $VALDIR/application.json

Scott approves with his admission key (he runs, not you):
  falcon-pl-ctl --addr <seat> approve-validator --id $id --pubkey <validator_public_key> --expires +20000 \\
    --keys-dir <admission keys> --network-id $(net NETWORK_ID)

Scott funds the bond account with PayToKey (a plain pay leaves it keyless and the bond is refused):
  falcon-pl-ctl --addr <seat> faucet --to $(vstate BOND_ACCOUNT) --amount <bond + fees> --key-hash <bond_account_key_hash> \\
    --scheme falcon-512 --keys-dir <faucet keys> --network-id $(net NETWORK_ID)

This script then waits for the approval (re-run 'falcon-node validator' any time to resume).
MSG
}

cmd_validator() {
  load_installed
  [[ "$(kv_get "$NODE_ENV" NODE_ROLE)" == "validator" || -n "$VAL_ID" || -f "$VALDIR/state" ]] || die "use: falcon-node validator --id NAME"
  have python3 || die "validator mode needs python3"
  local id acct minb fee nid st; st="$(mktemp)"
  id="${VAL_ID:-$(vstate ID)}"
  [[ "$id" =~ ^[a-z][a-z0-9-]{2,31}$ ]] || die "validator id must match ^[a-z][a-z0-9-]{2,31}\$ (got '$id')"
  [[ "$id" =~ ^v[0-9]+$ || "$id" =~ ^(faucet|treasury|community|builder|alice|bob)$ || "$id" == watcher-* ]] && die "id '$id' is reserved"
  if [[ -n "$(vstate ID)" && "$(vstate ID)" != "$id" ]]; then die "this install already applied as '$(vstate ID)'"; fi
  [[ -n "$(vstate ID)" ]] || check_seat_name_clash "$BIN/falcon-pl-ctl" "$id"
  acct="${BOND_ACCOUNT:-$(vstate BOND_ACCOUNT)}"; acct="${acct:-$id-bond}"
  minb="$(net MIN_BOND_NEW)"; fee="$(net TX_FEE)"; nid="$(net NETWORK_ID)"
  vset ID "$id"; vset BOND_ACCOUNT "$acct"; [[ -n "$CONTACT" ]] && vset CONTACT "$CONTACT"
  CONTACT="${CONTACT:-$(vstate CONTACT)}"
  kv_set "$NODE_ENV" NODE_ROLE validator
  install_payout

  if ! legacy_devnet && { ! ctl_supports_v2_bond || ! onboarding_open; }; then
    vset STAGE waiting-for-2.9.62
    warn "validator onboarding is not open on network $nid yet: it opens after $(net FIRST_VALIDATOR_VERSION) activates and every seat has a public endpoint (validator key + proof of possession in the bond, admission by approval, ${minb} FPL minimum)."
    warn "your node keeps running as an observer. After the network upgrades, run: falcon-node upgrade && falcon-node validator"
    rm -f "$st"; return 0
  fi
  if legacy_devnet; then minb="${FALCON_DEVNET_MIN_BOND:-1000}"; fi

  # 1) keys (validator key + bond account key), generated locally
  gen_key "$id"; gen_key "$acct"
  # 2) application
  if [[ ! -f "$VALDIR/application.json" ]]; then write_application "$id" "$acct"; fi
  local stage; stage="$(vstate STAGE)"
  if [[ -z "$stage" || "$stage" == waiting-for-2.9.62 ]]; then vset STAGE applied; print_apply_instructions "$id"; fi

  # 3) approval (2.9.62 status.approvals[id] == our key), unless already bonded
  local present="0" bond="0" jailed="0" inactive="0" ready="0" pkfp="-" mypk; mypk="$(pubkey_of "$id")"
  while :; do
    status_json "$st" || { warn "status unavailable; retrying"; sleep "$POLL_SECS"; continue; }
    read -r present bond jailed inactive ready pkfp <<<"$(validator_info "$st" "$id")"
    [[ "$present" == 1 ]] && break
    if legacy_devnet; then break; fi
    local appr exp; read -r appr exp <<<"$(approval_of "$st" "$id")"
    if [[ -n "$appr" ]]; then
      [[ "$appr" == "$mypk" ]] || die "an approval for '$id' exists but for a DIFFERENT key; contact Scott"
      ok "approved by the admission key${exp:+ (expires at height $exp)}"; vset STAGE approved; break
    fi
    [[ $WAIT -eq 1 ]] || { say "not approved yet; re-run 'falcon-node validator' later"; rm -f "$st"; return 0; }
    (( ${apoll:=0} % 10 == 0 )) && say "waiting for admission approval of '$id' (checks every ${POLL_SECS}s; Ctrl-C is safe, resume with 'falcon-node validator')"
    apoll=$((apoll + 1))
    sleep "$POLL_SECS"
  done

  # 4) funding + 5) bond
  if [[ "$present" != 1 ]]; then
    # need = bond + bond fee + (one-time key-enrolment pay of 1 FPL + its fee, see below)
    local need=$((minb + fee)) bal npoll=0
    [[ "$(vstate ENROLLED)" == 1 ]] || need=$((need + fee + 1))
    while :; do
      bal="$(account_balance "$acct")"
      [[ "$bal" -ge "$need" ]] && break
      vset STAGE awaiting-funds
      [[ $WAIT -eq 1 ]] || { say "fund '$acct' with >= $need FPL, then re-run 'falcon-node validator'"; rm -f "$st"; return 0; }
      if (( npoll % 10 == 0 )); then
        say "bond account '$acct' has $bal FPL; needs >= $need FPL (bond $minb + fees). Waiting (checks every ${POLL_SECS}s)."
        say "  testnet: ask Scott for a grant (he runs: falcon-pl-ctl faucet --to $acct --amount $need --key-hash $(py -c 'import json,sys;print(json.load(open(sys.argv[1])).get("bond_account_key_hash",""))' "$VALDIR/application.json") --scheme falcon-512 --network-id $nid)"
      fi
      npoll=$((npoll + 1))
      sleep "$POLL_SECS"
    done
    ok "bond account '$acct' funded ($bal FPL)"
    # A brand-new account's Falcon key is not on the ledger yet. Bond is not an enrolling tx, so the first
    # tx from the bond account is a 1 FPL Pay back to the faucet, which enrols its public key.
    if [[ "$(vstate ENROLLED)" != 1 ]]; then
      as_svc "$BIN/falcon-pl-ctl" --addr "$(local_rpc)" pay --from "$acct" --to faucet --amount 1 --fee "$fee" \
        --scheme "$(net SCHEME)" --keys-dir "$KEYS" --network-id "$nid" >"$VALDIR/enroll-result.json" 2>&1 \
        || { tail -n 5 "$VALDIR/enroll-result.json" >&2; die "key enrolment pay refused; see $VALDIR/enroll-result.json"; }
      local seq0 seq1; seq0="$(account_field "$acct" sequence)"
      for _ in $(seq 1 60); do sleep 5; seq1="$(account_field "$acct" sequence)"; [[ "${seq1:-0}" -gt "${seq0:-0}" ]] && break; done
      [[ "${seq1:-0}" -gt "${seq0:-0}" ]] || die "key enrolment pay not committed after 5 min"
      vset ENROLLED 1
      ok "bond account key enrolled on the ledger"
    fi
    confirm "Submit Bond of $minb FPL from '$acct' to validator '$id' on network $nid?" || { say "bond not submitted"; rm -f "$st"; return 0; }
    local bondcmd=(bond) extra=()
    if ! legacy_devnet; then bondcmd=(bond-v2); extra=(--validator-keys "$KEYS"); fi
    set +e
    as_svc "$BIN/falcon-pl-ctl" --addr "$(local_rpc)" "${bondcmd[@]}" --id "$id" --from "$acct" --amount "$minb" --fee "$fee" \
      --scheme "$(net SCHEME)" --keys-dir "$KEYS" --network-id "$nid" "${extra[@]}" >"$VALDIR/bond-result.json" 2>&1
    local rc=$?
    set -e
    [[ $rc -eq 0 ]] || { tail -n 5 "$VALDIR/bond-result.json" >&2; die "bond refused by the node (exit $rc); see $VALDIR/bond-result.json"; }
    vset STAGE bond-submitted
    ok "bond submitted: $(grep -oE 'tx_id=[0-9a-f]+' "$VALDIR/bond-result.json" | head -1)"
    say "waiting for the bond to be committed"
    for _ in $(seq 1 60); do
      sleep 5; status_json "$st" || continue
      read -r present bond jailed inactive ready pkfp <<<"$(validator_info "$st" "$id")"
      [[ "$present" == 1 ]] && break
    done
    [[ "$present" == 1 ]] || die "bond not visible after 5 min; check 'falcon-node status' and $VALDIR/bond-result.json"
  fi
  ok "validator '$id' is bonded (bond $bond, validator key on chain: $pkfp)"
  vset STAGE bonded

  # 6) activation: run the node as the validator id (own node only)
  if [[ "$(kv_get "$NODE_ENV" NODE_ID)" != "$id" ]]; then
    # The observer already has a synced snapshot under its old id. Starting
    # as the seat id looks for data/<seat>.json and would join from height 0.
    local old os ns
    old="$(kv_get "$NODE_ENV" NODE_ID)"
    if [[ -n "$old" && "$old" != "$id" && -f "$DATA/$old.json" ]]; then
      os="$(stat -c%s "$DATA/$old.json" 2>/dev/null || echo 0)"
      ns=0
      [[ -f "$DATA/$id.json" ]] && ns="$(stat -c%s "$DATA/$id.json" 2>/dev/null || echo 0)"
      if [[ "$ns" -lt "$os" ]]; then
        cp -a "$DATA/$old.json" "$DATA/$id.json"
        if [[ -n "${SVC_USER:-}" && "$SVC_USER" != "root" ]]; then
          chown "$SVC_USER:$SVC_USER" "$DATA/$id.json" 2>/dev/null || true
        fi
        ok "kept the synced snapshot for $id"
      fi
    fi
    kv_set "$NODE_ENV" NODE_ID "$id"
    if [[ -n "${SVC_USER:-}" && "$SVC_USER" != "root" ]]; then
      chown "$SVC_USER:$SVC_USER" "$NODE_ENV" 2>/dev/null || true
      chmod 640 "$NODE_ENV" 2>/dev/null || true
    fi
    svc_restart
    ok "node restarted as validator '$id'"
  fi
  for _ in $(seq 1 120); do
    public_status "$BIN/falcon-pl-ctl" "$st" && read -r present bond jailed inactive ready pkfp <<<"$(validator_info "$st" "$id")"
    if [[ "$jailed" == 1 ]]; then die "validator '$id' is jailed; see docs (UNJAIL)"; fi
    if [[ "$ready" == 1 && "$inactive" != 1 ]]; then
      vset STAGE active
      ok "validator '$id' is ACTIVE (lottery_ready as seen by the seat at $(net STATUS_RPC)). Dashboard: $(net SITE)/validator"
      rm -f "$st"; return 0
    fi
    sleep 10
  done
  warn "validator bonded but not lottery_ready yet (it must catch up and pong at tip). Check 'falcon-node status'."
  rm -f "$st"
}

# ---------- watcher heartbeat ----------
cmd_heartbeat() {
  load_installed
  local acct; acct="$(kv_get "$NODE_ENV" WATCHER_ACCOUNT)"
  [[ -n "$acct" ]] || die "no watcher account configured (install with --watcher)"
  as_svc "$BIN/falcon-pl-ctl" --addr "$(local_rpc)" heartbeat --account "$acct" --fee "$(net TX_FEE)" \
    --scheme "$(net SCHEME)" --keys-dir "$KEYS" --network-id "$(net NETWORK_ID)"
}
install_watcher() {
  local acct; acct="$(kv_get "$NODE_ENV" WATCHER_ACCOUNT)"
  if [[ -z "$acct" ]]; then acct="watch-$(kv_get "$NODE_ENV" NODE_ID | sed 's/^obs-//')"; kv_set "$NODE_ENV" WATCHER_ACCOUNT "$acct"; fi
  gen_key "$acct"
  [[ "$SERVICE_MODE" == "none" ]] && { warn "no systemd: schedule 'falcon-node heartbeat' hourly yourself (cron)"; return 0; }
  local d; d="$(dirname "$(unit_path)")"
  cat >"$d/$UNIT-heartbeat.service" <<U
[Unit]
Description=Falcon PL watcher heartbeat ($acct)
After=$UNIT.service
[Service]
Type=oneshot
$( [[ "$SERVICE_MODE" == "system" ]] && echo "User=$SVC_USER" )
ExecStart=$BIN/falcon-node heartbeat --home $FALCON_HOME
U
  cat >"$d/$UNIT-heartbeat.timer" <<U
[Unit]
Description=Hourly Falcon PL watcher heartbeat
[Timer]
OnCalendar=hourly
RandomizedDelaySec=900
Persistent=true
[Install]
WantedBy=timers.target
U
  sctl daemon-reload; sctl enable --now "$UNIT-heartbeat.timer" >/dev/null 2>&1 || warn "could not enable the heartbeat timer"
  ok "watcher account '$acct' (fund it with a few FPL from the faucet: each heartbeat costs $(net TX_FEE) FPL)"
}

valid_payout() {
  [[ "$1" =~ ^[a-z][a-z0-9.]{2,31}$ && "$1" != *..* && "$1" != *. ]]
}

install_payout() {
  [[ -n "$PAYOUT" ]] || return 0
  valid_payout "$PAYOUT" || die "payout account must be 3–32 chars: a-z, 0-9, dots (got '$PAYOUT')"
  kv_set "$NODE_ENV" PAYOUT_ACCOUNT "$PAYOUT"
  cat >"$BIN/auto-payout.sh" <<'PAY'
#!/usr/bin/env bash
# Once per new epoch, claim this seat's rewards and send the spendable balance
# to PAYOUT_ACCOUNT. The bond account is never touched. No payout configured: exit.
set -euo pipefail
H="$(cd "$(dirname "$0")/.." && pwd)"
g() { local l; l="$(grep -E "^$2=" "$1" | tail -1 || true)"; printf '%s' "${l#*=}"; }
N="$H/config/node.env"; P="$H/config/network-2300.env"
PAYOUT="$(g "$N" PAYOUT_ACCOUNT)"
[[ -n "$PAYOUT" ]] || exit 0
ID="$(g "$N" NODE_ID)"
[[ -n "$ID" && "$ID" != obs-* && "$ID" != "$PAYOUT" ]] || exit 0
ADDR="$(g "$N" LISTEN)"
FEE="$(g "$P" TX_FEE)"; FEE="${FEE:-2}"
SCHEME="$(g "$P" SCHEME)"; NID="$(g "$P" NETWORK_ID)"
CTL="$H/bin/falcon-pl-ctl"
mark="$H/data/payout-epoch"
epoch="$("$CTL" --addr "$ADDR" status | python3 -c 'import sys,json; d=json.load(sys.stdin); b=d.get("body",d); print(b.get("epoch") or 0)')"
last=0; [[ -f "$mark" ]] && last="$(cat "$mark")"
[[ "$epoch" -gt "$last" ]] || exit 0
"$CTL" --addr "$ADDR" claim --account "$ID" --fee "$FEE" --scheme "$SCHEME" --keys-dir "$H/keys" --network-id "$NID" >/dev/null 2>&1 || true
bal="$("$CTL" --addr "$ADDR" account --account "$ID" | python3 -c 'import sys,json
raw=sys.stdin.read()
i=raw.find("{")
d=json.loads(raw[i:])
b=d.get("body",d)
if isinstance(b,str): b=json.loads(b)
print(int(b.get("balance") or 0))')"
send=$((bal - FEE))
if [[ "$send" -le 0 ]]; then printf '%s\n' "$epoch" >"$mark"; exit 0; fi
"$CTL" --addr "$ADDR" pay --from "$ID" --to "$PAYOUT" --amount "$send" --fee "$FEE" --scheme "$SCHEME" --keys-dir "$H/keys" --network-id "$NID"
printf '%s\n' "$epoch" >"$mark"
PAY
  chmod 755 "$BIN/auto-payout.sh"
  if [[ "$SERVICE_MODE" == "none" ]]; then
    warn "no systemd: run $BIN/auto-payout.sh after each epoch (cron). Payout account is $PAYOUT"
    return 0
  fi
  local d; d="$(dirname "$(unit_path)")"
  cat >"$d/$UNIT-payout.service" <<U
[Unit]
Description=Falcon PL epoch payout to $PAYOUT
After=$UNIT.service
[Service]
Type=oneshot
$( [[ "$SERVICE_MODE" == "system" ]] && echo "User=$SVC_USER" )
ExecStart=$BIN/auto-payout.sh
U
  cat >"$d/$UNIT-payout.timer" <<U
[Unit]
Description=Check Falcon PL epoch payout
[Timer]
OnBootSec=5min
OnUnitActiveSec=30min
Persistent=true
[Install]
WantedBy=timers.target
U
  sctl daemon-reload
  sctl enable --now "$UNIT-payout.timer" >/dev/null 2>&1 || warn "could not enable the payout timer"
  ok "auto-payout to '$PAYOUT' after each epoch (spendable FPL on the seat account; the bond stays put)"
}

# ---------- commands ----------
AUTOU_UNIT="falcon-pl-autoupgrade"

autoupgrade_unit_dir() {
  dirname "$(unit_path)"
}

write_autoupgrade() {
  cat >"$BIN/falcon-node-autoupgrade" <<'AUTOUP'
#!/usr/bin/env bash
# Generated by falcon-node. Runs falcon-node autoupgrade with jitter, health verification, and rollback.
set -euo pipefail
H="$(cd "$(dirname "$(readlink -f "$0")")/.." && pwd)"
exec "$H/bin/falcon-node" autoupgrade run --home "$H" "$@"
AUTOUP
  chmod 0755 "$BIN/falcon-node-autoupgrade"
  if [[ $IS_ROOT -eq 1 && "$SERVICE_MODE" == "system" ]]; then
    chown "$SVC_USER:$SVC_USER" "$BIN/falcon-node-autoupgrade" 2>/dev/null || true
    if [[ ! -e /usr/local/bin/falcon-node-autoupgrade || ( -L /usr/local/bin/falcon-node-autoupgrade && $ADOPTED -ne 1 ) ]]; then
      ln -sf "$BIN/falcon-node-autoupgrade" /usr/local/bin/falcon-node-autoupgrade
    fi
  else
    if [[ ! -e "$HOME/.local/bin/falcon-node-autoupgrade" || -L "$HOME/.local/bin/falcon-node-autoupgrade" ]]; then
      mkdir -p "$HOME/.local/bin" && ln -sf "$BIN/falcon-node-autoupgrade" "$HOME/.local/bin/falcon-node-autoupgrade" || true
    fi
  fi
  [[ "$SERVICE_MODE" == "none" ]] && return 0
  local d; d="$(autoupgrade_unit_dir)"
  mkdir -p "$d"
  cat >"$d/$AUTOU_UNIT.service" <<U
[Unit]
Description=Falcon PL node auto-upgrade ($FALCON_HOME)
After=network-online.target $UNIT.service
Wants=network-online.target
[Service]
Type=oneshot
WorkingDirectory=$FALCON_HOME
Environment=FALCON_HOME=$FALCON_HOME
ExecStart=$BIN/falcon-node-autoupgrade
StandardOutput=append:$LOGS/autoupgrade.log
StandardError=append:$LOGS/autoupgrade.log
U
  cat >"$d/$AUTOU_UNIT.timer" <<U
[Unit]
Description=Periodic Falcon PL node auto-upgrade check ($FALCON_HOME)
[Timer]
OnActiveSec=15min
OnUnitActiveSec=1h
Persistent=true
[Install]
WantedBy=timers.target
U
  chmod 0644 "$d/$AUTOU_UNIT.service" "$d/$AUTOU_UNIT.timer"
  sctl daemon-reload >/dev/null 2>&1 || true
}

# Post-upgrade health check. Return codes:
#   0  service active and the tip advanced past prev_tip (healthy)
#   2  service active and the local RPC answers, but the tip is flat: the CHAIN
#      is stalled, not the binary (2.11.4; 12 Nov 2026 h=869559). Callers must
#      not roll back or restart on 2: a restart mid-stall resets the seat's
#      view round and turned a 3-block lag into a 22-minute deadlock.
#   1  service down / crashed, or the local RPC never answered (real failure)
autoupgrade_health_check() { # prev_tip
  local prev_tip="${1:-0}"
  local timeout_secs="${FALCON_AUTOUPGRADE_HEALTH_TIMEOUT:-120}"
  local poll_secs="${FALCON_AUTOUPGRADE_POLL_SECS:-2}"
  local t0 now st cur_tip="" active rpc_ok=0
  t0="$(date +%s)"
  st="$(mktemp)"
  while :; do
    rpc_ok=0
    if svc_active && local_status "$st"; then
      rpc_ok=1
      cur_tip="$(json_num "$st" tip_height)"
      if [[ -n "$cur_tip" && "$cur_tip" -gt "$prev_tip" ]]; then
        ok "autoupgrade health check passed: service active and tip advanced ($prev_tip -> $cur_tip)"
        rm -f "$st"
        return 0
      fi
    fi
    now="$(date +%s)"
    if (( now - t0 >= timeout_secs )); then
      rm -f "$st"
      active=no; svc_active && active=yes
      if [[ "$active" == yes && $rpc_ok -eq 1 && -n "$cur_tip" ]]; then
        warn "autoupgrade health check: service active and RPC answering but tip flat after ${timeout_secs}s (prev tip: $prev_tip, current tip: $cur_tip); treating as a chain stall, not a bad binary: no rollback, no restart"
        return 2
      fi
      warn "autoupgrade health check failed after ${timeout_secs}s (service active: $active, rpc: $( [[ $rpc_ok -eq 1 ]] && echo yes || echo no ), prev tip: $prev_tip, current tip: ${cur_tip:-none})"
      return 1
    fi
    sleep "$poll_secs"
  done
}

# 2.11.4: did this run actually replace a binary? (.prev is the pre-run copy.)
autoupgrade_bins_changed() {
  local b
  for b in falcon-pl-node falcon-pl-ctl; do
    if [[ -f "$BIN/$b.prev" && -f "$BIN/$b" ]] && ! cmp -s "$BIN/$b" "$BIN/$b.prev"; then
      return 0
    fi
  done
  return 1
}

# 2.11.4: recover from a failed autoupgrade run. Roll back only when a binary
# was actually replaced. With the binaries unchanged, "rolling back" restored
# the same version and restarted a running node (v3/v12 at h=869559); now the
# node is only (re)started when the service is really down.
autoupgrade_recover() { # prev_ver
  if autoupgrade_bins_changed; then
    rollback_autoupgrade "$1"
    return
  fi
  if svc_active; then
    warn "autoupgrade: binaries unchanged and service active; nothing to roll back, not restarting"
  else
    warn "autoupgrade: binaries unchanged but service is down; starting it"
    svc_restart || true
  fi
}

# 2.11.4: before an upgrade restarts the node, make sure the network is not in
# a stall. Restarting a committee seat mid-stall resets its view round and can
# deadlock the open height. Returns 1 (defer) only when both our tip and the
# best peer tip stay flat for the probe window; a seat that is merely lagging
# (peers advancing) or a stopped/unreachable node is not deferred.
autoupgrade_stall_probe() {
  local probe="${FALCON_AUTOUPGRADE_STALL_PROBE_SECS:-90}" st t1 p1 t2 p2
  [[ "$probe" =~ ^[0-9]+$ ]] && (( probe > 0 )) || return 0
  svc_active || return 0
  st="$(mktemp)"
  if ! local_status "$st"; then rm -f "$st"; return 0; fi
  t1="$(json_num "$st" tip_height)"; p1="$(json_num "$st" best_peer_tip)"
  sleep "$probe"
  if ! svc_active || ! local_status "$st"; then rm -f "$st"; return 0; fi
  t2="$(json_num "$st" tip_height)"; p2="$(json_num "$st" best_peer_tip)"
  rm -f "$st"
  [[ -n "$t1" && -n "$t2" ]] || return 0
  if [[ "$t2" == "$t1" && "${p2:-0}" -le "${p1:-0}" ]]; then
    warn "autoupgrade deferred: tip flat at $t2 for ${probe}s (best peer tip ${p2:-none}); chain looks stalled, not restarting mid-stall (next timer run retries)"
    return 1
  fi
  return 0
}

rollback_autoupgrade() { # prev_ver
  local prev_ver="${1:-}" b restored=0
  warn "rolling back binaries in $BIN to previous version (${prev_ver:-.prev})"
  for b in falcon-pl-node falcon-pl-ctl; do
    if [[ -f "$BIN/$b.prev" ]]; then
      cp -p "$BIN/$b.prev" "$BIN/$b.rollback" && chmod 0755 "$BIN/$b.rollback" && mv -f "$BIN/$b.rollback" "$BIN/$b"
      restored=1
    fi
  done
  if [[ -n "$prev_ver" ]]; then
    kv_set "$NODE_ENV" VERSION "$prev_ver"
  fi
  ensure_node_env_readable "$NODE_ENV"
  if [[ $restored -eq 1 ]]; then
    svc_restart || true
    ok "rolled back to ${prev_ver:-previous binary} and restarted service"
  else
    warn "no .prev binary backup found in $BIN to roll back"
  fi
}

# 2.10.1: auto-upgrade is ON by default for install and upgrade. Opt out with
# --no-autoupgrade or 'falcon-node autoupgrade off' (remembered as AUTOUPGRADE_OPTOUT=1).
autoupgrade_apply_default() {
  if [[ "$SERVICE_MODE" == "none" ]]; then
    [[ -n "$(kv_get "$NODE_ENV" AUTOUPGRADE)" ]] || kv_set "$NODE_ENV" AUTOUPGRADE off
    return 0
  fi
  if [[ $NO_AUTOUPGRADE -eq 1 ]]; then
    kv_set "$NODE_ENV" AUTOUPGRADE off; kv_set "$NODE_ENV" AUTOUPGRADE_OPTOUT 1
    sctl disable --now "$AUTOU_UNIT.timer" >/dev/null 2>&1 || true
    ok "autoupgrade off (--no-autoupgrade)"; return 0
  fi
  if [[ "$(kv_get "$NODE_ENV" AUTOUPGRADE_OPTOUT)" == "1" ]]; then
    say "autoupgrade stays off (you opted out; 'falcon-node autoupgrade on' re-enables it)"; return 0
  fi
  kv_set "$NODE_ENV" AUTOUPGRADE on
  if sctl enable --now "$AUTOU_UNIT.timer" >/dev/null 2>&1; then
    ok "autoupgrade on (default; hourly, signed releases only; opt out: --no-autoupgrade or 'falcon-node autoupgrade off')"
  else
    warn "could not enable $AUTOU_UNIT.timer"
  fi
}

cmd_autoupgrade() {
  load_installed
  local act="${AUTOUPGRADE_ACTION:-status}"
  case "$act" in
    on|enable)
      write_autoupgrade
      kv_set "$NODE_ENV" AUTOUPGRADE on
      kv_set "$NODE_ENV" AUTOUPGRADE_OPTOUT 0
      if [[ -n "${AUTOUPGRADE_JITTER_SECS:-}" ]]; then
        kv_set "$NODE_ENV" AUTOUPGRADE_JITTER_SECS "$AUTOUPGRADE_JITTER_SECS"
      fi
      if [[ "$SERVICE_MODE" != "none" ]]; then
        sctl enable --now "$AUTOU_UNIT.timer" >/dev/null 2>&1 || warn "could not enable $AUTOU_UNIT.timer"
      fi
      ok "autoupgrade enabled (timer: $AUTOU_UNIT.timer)"
      ;;
    off|disable)
      write_autoupgrade
      kv_set "$NODE_ENV" AUTOUPGRADE off
      kv_set "$NODE_ENV" AUTOUPGRADE_OPTOUT 1
      if [[ "$SERVICE_MODE" != "none" ]]; then
        sctl disable --now "$AUTOU_UNIT.timer" >/dev/null 2>&1 || true
      fi
      ok "autoupgrade disabled"
      ;;
    status)
      local cfg_state timer_state="disabled" jitter
      cfg_state="$(kv_get "$NODE_ENV" AUTOUPGRADE)"
      [[ -n "$cfg_state" ]] || cfg_state="off"
      jitter="${AUTOUPGRADE_JITTER_SECS:-$(kv_get "$NODE_ENV" AUTOUPGRADE_JITTER_SECS)}"
      [[ -n "$jitter" ]] || jitter="300"
      if [[ "$SERVICE_MODE" != "none" ]] && sctl is-enabled --quiet "$AUTOU_UNIT.timer" 2>/dev/null; then
        timer_state="enabled"
      fi
      echo "autoupgrade: $cfg_state (timer: $timer_state, jitter: ${jitter}s, rollback backup: $( [[ -f "$BIN/falcon-pl-node.prev" ]] && echo present || echo none ))"
      ;;
    run)
      local jitter delay prev_ver prev_tip=0 st b
      jitter="${AUTOUPGRADE_JITTER_SECS:-$(kv_get "$NODE_ENV" AUTOUPGRADE_JITTER_SECS)}"
      [[ -n "$jitter" ]] || jitter="300"
      if [[ "$jitter" =~ ^[0-9]+$ ]] && (( jitter > 0 )); then
        delay=$(( RANDOM % jitter + 1 ))
        say "autoupgrade jitter: sleeping ${delay}s (max ${jitter}s)"
        sleep "$delay"
      fi
      prev_ver="$(kv_get "$NODE_ENV" VERSION)"
      st="$(mktemp)"
      if local_status "$st"; then
        prev_tip="$(json_num "$st" tip_height)"
        prev_tip="${prev_tip:-0}"
      fi
      rm -f "$st"
      if ! autoupgrade_stall_probe; then
        return 0
      fi
      for b in falcon-pl-node falcon-pl-ctl; do
        [[ -f "$BIN/$b" ]] && cp -p "$BIN/$b" "$BIN/$b.prev"
      done
      if ! ( YES=1 cmd_upgrade ); then
        warn "falcon-node upgrade failed during autoupgrade"
        autoupgrade_recover "$prev_ver"
        return 1
      fi
      if ! autoupgrade_bins_changed; then
        # No new release: nothing was replaced, so there is nothing to verify.
        # (Before 2.11.4 the hourly run waited for the tip to move and, on a
        # stalled chain, "rolled back" to the same version and restarted.)
        if svc_active; then
          ok "autoupgrade: already on the latest release; nothing to verify"
          return 0
        fi
        warn "autoupgrade: no new release, but the service is down"
        autoupgrade_recover "$prev_ver"
        return 1
      fi
      local hc=0
      autoupgrade_health_check "$prev_tip" || hc=$?
      if (( hc == 2 )); then
        warn "autoupgrade: new binary is running but the chain tip is flat; keeping it (no rollback, no restart)"
        return 0
      fi
      if (( hc != 0 )); then
        autoupgrade_recover "$prev_ver"
        return 1
      fi
      ok "autoupgrade completed and verified healthy"
      ;;
    *)
      die "usage: falcon-node autoupgrade [on|off|status|run] [--jitter SECS]"
      ;;
  esac
}

cmd_install() {
  preflight
  download_release
  require_public_seed
  check_network_version "$DL/falcon-pl-$REL_VERSION/falcon-pl-ctl"
  [[ -n "$VAL_ID" ]] && check_seat_name_clash "$DL/falcon-pl-$REL_VERSION/falcon-pl-ctl" "$VAL_ID"
  SERVICE_MODE="$(systemd_mode)"
  ensure_user
  install_files
  ensure_node_config
  kv_set "$NODE_ENV" CHANNEL "$CHANNEL"
  write_unit
  write_autoupgrade
  autoupgrade_apply_default
  [[ $WATCHER -eq 1 ]] && install_watcher
  install_payout
  rm -rf "$DL"
  if [[ $START -eq 1 ]]; then
    if svc_active && [[ "${BIN_CHANGED:-0}" -eq 0 && "${UNIT_CHANGED:-0}" -eq 0 ]]; then
      ok "node already running (nothing changed)"
    elif svc_active; then
      svc_restart; ok "node restarted on $REL_VERSION"
    else
      svc_start; ok "node started"
    fi
    wait_sync || true
  fi
  if [[ "$ROLE" == "validator" ]]; then cmd_validator; fi
  cat <<DONE

${B}Falcon PL node installed${N} ($FALCON_HOME, node id $(kv_get "$NODE_ENV" NODE_ID))
  falcon-node status      # sync + validator state
  falcon-node logs        # follow the node log
  falcon-node balance     # liquid FPL, bonded, pending rewards, unbonding (one line)
Dashboards (read-only):
  falcon-node dash        # live terminal dashboard (q quits)
  falcon-node web         # browser dashboard on 127.0.0.1:19480 (prints the SSH tunnel command for your laptop)
  falcon-node validator --id NAME --contact X   # apply to become a validator (2.9.62+)
  falcon-node uninstall   # remove service + binaries (keys kept unless --purge)
Explorer: $(net SITE)/scan    Validators: $(net SITE)/validator
DONE
}

cmd_upgrade() {
  load_installed
  preflight; download_release; require_public_seed; check_network_version "$DL/falcon-pl-$REL_VERSION/falcon-pl-ctl"
  install_files
  if [[ $ADOPTED -eq 1 ]]; then
    write_adopt_runner; write_adopt_dropin   # hand-built seat: keep its unit, keys and arguments
  else
    write_runner; write_unit
  fi
  write_autoupgrade; rm -rf "$DL"
  [[ $ADOPTED -eq 1 ]] || { install_qc_profile; install_ring_publics; }
  # 2.9.74: write node.env BEFORE the restart. Rewriting it right after the
  # restart raced the new runner ("no NODE_ID", exit 78, unit not restarted).
  [[ -n "$(kv_get "$NODE_ENV" NODE_ID)" || -z "${SAVED_NODE_ID:-}" ]] || kv_set "$NODE_ENV" NODE_ID "$SAVED_NODE_ID"
  kv_set "$NODE_ENV" VERSION "$REL_VERSION"
  kv_set "$NODE_ENV" CHANNEL "$CHANNEL"
  ensure_node_env_readable "$NODE_ENV"
  if [[ "${BIN_CHANGED:-0}" -eq 1 || "${UNIT_CHANGED:-0}" -eq 1 || "${RING_CHANGED:-0}" -eq 1 ]]; then
    svc_restart
    local up=0
    for _ in $(seq 1 15); do sleep 1; if svc_active; then up=1; else up=0; fi; done
    [[ $up -eq 1 ]] || die "node did not stay up after the upgrade to $REL_VERSION; see $LOGS/node.log ('falcon-node logs'), then run 'falcon-node start'"
    ok "restarted on $REL_VERSION (running, channel $CHANNEL)"
  else
    ok "already on $REL_VERSION"
  fi
  autoupgrade_apply_default
}

# ---------- adopt (2.10.1): bring a hand-built node under falcon-node ----------
# Keeps the seat's systemd unit (User, EnvironmentFile, drop-ins, logs), its working
# directory, keys, snapshot and exact command-line arguments. Only ExecStart is
# redirected, through a drop-in, to <home>/bin/run-node.sh, which runs the verified
# release binary with the same arguments. Never generates or reads keys.
write_adopt_runner() {
  cat >"$BIN/run-node.sh" <<'RUNNER'
#!/usr/bin/env bash
# Generated by falcon-node (adopted seat). Runs the release binary in the seat's
# original directory with its original arguments (config/node.args).
set -euo pipefail
H="$(cd "$(dirname "$0")/.." && pwd)"
g() { local l; l="$(grep -E "^$2=" "$1" | tail -1 || true)"; printf '%s' "${l#*=}"; }
W="$(g "$H/config/node.env" WORKDIR)"
[[ -n "$W" && -d "$W" ]] || { echo "no WORKDIR in $H/config/node.env" >&2; exit 78; }
read -r -a A <"$H/config/node.args" || true
[[ ${#A[@]} -gt 0 ]] || { echo "empty $H/config/node.args" >&2; exit 78; }
cd "$W"
exec "$H/bin/falcon-pl-node" "${A[@]}"
RUNNER
  chmod 0755 "$BIN/run-node.sh"
}

write_adopt_dropin() {
  local d="/etc/systemd/system/$UNIT.service.d" p tmp
  p="$d/90-falcon-node-adopt.conf"; mkdir -p "$d"; tmp="$(mktemp)"
  cat >"$tmp" <<U
# Managed by falcon-node (adopted seat, home $FALCON_HOME). To undo: delete this file,
# systemctl daemon-reload, restart $UNIT (original unit kept in $CONF/adopted-$UNIT.service.orig).
[Service]
ExecStart=
ExecStart=$BIN/run-node.sh
U
  if [[ -f "$p" ]] && cmp -s "$tmp" "$p"; then rm -f "$tmp"; UNIT_CHANGED=0; else mv "$tmp" "$p"; chmod 0644 "$p"; UNIT_CHANGED=1; fi
  sctl daemon-reload
}

cmd_adopt() {
  [[ $IS_ROOT -eq 1 ]] || die "adopt must run as root"
  have systemctl && [[ -d /run/systemd/system ]] || die "adopt needs systemd"
  [[ "$ADOPT_UNIT" =~ ^[A-Za-z0-9@._-]+$ ]] || die "adopt: --unit NAME is required (the existing systemd unit, e.g. falcon-pl-v13)"
  ADOPT_UNIT="${ADOPT_UNIT%.service}"
  [[ ! -f "$NODE_ENV" ]] || die "adopt: $FALCON_HOME already holds an install; pick another --home (nothing changed)"
  local frag; frag="$(systemctl show -p FragmentPath --value "$ADOPT_UNIT.service" 2>/dev/null || true)"
  [[ -n "$frag" && -f "$frag" ]] || die "adopt: unit $ADOPT_UNIT not found"
  [[ "$(systemctl cat "$ADOPT_UNIT.service" 2>/dev/null | grep -cE '^ExecStart=')" == "1" ]] \
    || die "adopt: $ADOPT_UNIT has more than one ExecStart (drop-in override?); nothing changed"
  local es wd usr
  es="$(grep -E '^ExecStart=' "$frag" | tail -1)"; es="${es#ExecStart=}"
  wd="$(grep -E '^WorkingDirectory=' "$frag" | tail -1 | cut -d= -f2-)"
  usr="$(grep -E '^User=' "$frag" | tail -1 | cut -d= -f2-)"; usr="${usr:-root}"
  [[ -n "$wd" && -d "$wd" ]] || die "adopt: $ADOPT_UNIT has no usable WorkingDirectory"
  [[ "$es" =~ ^[A-Za-z0-9.,:/@_+=\ -]+$ ]] || die "adopt: ExecStart uses quoting/variables that adopt does not handle; nothing changed"
  local -a argv; read -r -a argv <<<"$es"
  local oldbin="${argv[0]}" nid="" lst="" kd="" i
  [[ -x "$oldbin" ]] || die "adopt: $oldbin is not executable"
  for ((i = 1; i < ${#argv[@]}; i++)); do
    case "${argv[$i]}" in
      --id) nid="${argv[$((i + 1))]:-}" ;;
      --listen) lst="${argv[$((i + 1))]:-}" ;;
      --keys-dir) kd="${argv[$((i + 1))]:-}" ;;
    esac
  done
  [[ "$nid" =~ ^[a-z][a-z0-9-]{0,31}$ ]] || die "adopt: no valid --id in $ADOPT_UNIT ExecStart"
  [[ -n "$lst" && -n "$kd" ]] || die "adopt: ExecStart lacks --listen/--keys-dir"
  ( cd "$wd" && [[ -d "$kd" ]] ) || die "adopt: keys dir $kd not found under $wd"
  case "$lst" in 0.0.0.0:*|:*) lst="127.0.0.1:${lst##*:}" ;; esac
  # Adopt the version that is running, so adopting changes nothing but the launcher.
  [[ -n "$WANT_VERSION" ]] || WANT_VERSION="$("$oldbin" --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || true)"
  [[ -n "$WANT_VERSION" ]] || die "adopt: could not read the running version from $oldbin --version (pass --version X.Y.Z)"
  SERVICE_MODE="system"; SVC_USER="$usr"; UNIT="$ADOPT_UNIT"; AUTOU_UNIT="$UNIT-autoupgrade"; ADOPTED=1
  id "$SVC_USER" >/dev/null 2>&1 || die "adopt: unit user $SVC_USER does not exist"
  say "adopting $UNIT (id $nid, user $SVC_USER, dir $wd) into $FALCON_HOME at $WANT_VERSION"
  preflight; download_release; require_public_seed; check_network_version "$DL/falcon-pl-$REL_VERSION/falcon-pl-ctl"
  if ! cmp -s "$DL/falcon-pl-$REL_VERSION/falcon-pl-node" "$oldbin"; then
    [[ $FORCE_VERSION -eq 1 ]] || { rm -rf "$DL"; die "adopt: $oldbin is not the signed $REL_VERSION release binary; nothing changed (--force-version adopts anyway)"; }
    warn "$oldbin differs from the $REL_VERSION release binary; adopting anyway (--force-version)"
  else
    ok "running binary is the signed $REL_VERSION release binary"
  fi
  install_files
  printf '%s\n' "${argv[*]:1}" >"$CONF/node.args"
  cp -p "$frag" "$CONF/adopted-$UNIT.service.orig"
  touch "$NODE_ENV"
  kv_set "$NODE_ENV" NODE_ID "$nid"
  kv_set "$NODE_ENV" LISTEN "$lst"
  kv_set "$NODE_ENV" SERVICE_MODE system
  kv_set "$NODE_ENV" VERSION "$REL_VERSION"
  kv_set "$NODE_ENV" CHANNEL "${CHANNEL:-stable}"
  kv_set "$NODE_ENV" ADOPTED 1
  kv_set "$NODE_ENV" UNIT "$UNIT"
  kv_set "$NODE_ENV" SVC_USER "$SVC_USER"
  kv_set "$NODE_ENV" WORKDIR "$wd"
  chown -R "$SVC_USER:$SVC_USER" "$CONF" 2>/dev/null || true
  chmod 0644 "$CONF/node.args"
  write_adopt_runner
  write_autoupgrade
  rm -rf "$DL"
  local st prev=0; st="$(mktemp)"
  local_status "$st" && prev="$(json_num "$st" tip_height)"; rm -f "$st"
  write_adopt_dropin
  if [[ $START -eq 1 ]]; then
    svc_restart
    local hc=0
    FALCON_AUTOUPGRADE_HEALTH_TIMEOUT="${FALCON_AUTOUPGRADE_HEALTH_TIMEOUT:-300}" autoupgrade_health_check "${prev:-0}" || hc=$?
    (( hc != 2 )) || warn "adopted $UNIT is running but the chain tip is flat (chain stall); keeping the adoption"
    if (( hc == 1 )); then
      warn "adopted $UNIT did not come back healthy; restoring its original ExecStart"
      rm -f "/etc/systemd/system/$UNIT.service.d/90-falcon-node-adopt.conf"; sctl daemon-reload; svc_restart || true
      die "adopt failed; $UNIT is back on $oldbin (managed files left in $FALCON_HOME for inspection)"
    fi
  fi
  # Auto-upgrade is switched on by the next 'upgrade', which installs the matching manager.
  ok "adopted $UNIT into $FALCON_HOME (keys, data and arguments unchanged). Next: curl -fsSL $(net SITE)/install.sh | bash -s -- upgrade$( [[ "$FALCON_HOME" != /var/lib/falcon-pl-2300 ]] && echo " --home $FALCON_HOME")"
}

cmd_uninstall() {
  load_installed
  [[ $ADOPTED -ne 1 ]] || die "adopted seat: uninstall is not supported (it would remove the seat's own unit); delete /etc/systemd/system/$UNIT.service.d/90-falcon-node-adopt.conf to undo the adoption"
  if [[ $PURGE -eq 1 ]]; then
    confirm "PURGE $FALCON_HOME including keys (validator/bond keys and any funds they control become unrecoverable)?" || die "aborted"
  fi
  svc_stop
  if [[ "$SERVICE_MODE" != "none" ]]; then
    local d; d="$(dirname "$(unit_path)")"
    sctl disable "$UNIT" "$UNIT-heartbeat.timer" "$AUTOU_UNIT.timer" >/dev/null 2>&1 || true
    sctl stop "$UNIT-heartbeat.timer" "$AUTOU_UNIT.timer" >/dev/null 2>&1 || true
    rm -f "$(unit_path)" "$d/$UNIT-heartbeat.service" "$d/$UNIT-heartbeat.timer" "$d/$AUTOU_UNIT.service" "$d/$AUTOU_UNIT.timer"
    sctl daemon-reload || true
  fi
  rm -f /usr/local/bin/falcon-node /usr/local/bin/falcon-node-autoupgrade 2>/dev/null || true
  rm -f "$HOME/.local/bin/falcon-node" "$HOME/.local/bin/falcon-node-autoupgrade" 2>/dev/null || true
  [[ -L /usr/local/bin/fdash ]] && rm -f /usr/local/bin/fdash 2>/dev/null || true
  [[ -L "$HOME/.local/bin/fdash" ]] && rm -f "$HOME/.local/bin/fdash" 2>/dev/null || true
  rm -f "/etc/logrotate.d/$UNIT" 2>/dev/null || true
  if [[ $PURGE -eq 1 ]]; then
    rm -rf "$FALCON_HOME"
    [[ $IS_ROOT -eq 1 ]] && id "$SVC_USER" >/dev/null 2>&1 && userdel "$SVC_USER" 2>/dev/null || true
    ok "purged $FALCON_HOME"
  else
    rm -rf "$BIN" "$DATA" "$RUN" "$LOGS"
    ok "removed service, binaries and chain data; kept keys + config in $FALCON_HOME (use --purge to delete)"
  fi
}

# 2.9.79-beta.3: a seat id that equals a wallet account with its own on-chain key
# would share that id with the seat key on every node ("bad tx crypto: key mismatch").
# Refuse unless the on-chain key is this install's own key for that id.
check_seat_name_clash() { # ctl id
  local ctl="$1" id="$2" out fp mine=""
  out="$(timeout 30 "$ctl" --addr "$(net STATUS_RPC)" account --account "$id" 2>/dev/null)" || { warn "could not check whether '$id' is a wallet account (network unreachable)"; return 0; }
  fp="$(printf '%s' "$out" | tr -d '\n ' | grep -oE '"key_fp":"[0-9a-f]{16}"' | head -1 | cut -d'"' -f4)"
  if [[ -z "$fp" ]]; then
    printf '%s' "$out" | tr -d '\n ' | grep -q '"exists":true' && printf '%s' "$out" | tr -d '\n ' | grep -qE '"sequence":[1-9]' \
      && warn "'$id' is an existing account that has sent transactions; if it is a wallet, pick another validator id"
    return 0
  fi
  [[ -f "$KEYS/pl_keys.json" ]] && mine="$(pubkey_of "$id")"
  if [[ -n "$mine" && "$(fingerprint "$(printf '%s' "$mine" | tr 'A-F' 'a-f')")" == "$fp" ]]; then return 0; fi
  die "validator id '$id' is an existing wallet account with its own on-chain key; pick a different --id (nothing was changed)"
}

validate_id_arg() { # fail before anything is downloaded or installed
  [[ -z "$VAL_ID" ]] && return 0
  [[ "$VAL_ID" =~ ^[a-z][a-z0-9-]{2,31}$ ]] || die "--id must match ^[a-z][a-z0-9-]{2,31}\$ (got '$VAL_ID'); nothing was installed"
  if [[ "$VAL_ID" =~ ^v[0-9]+$ || "$VAL_ID" =~ ^(faucet|treasury|community|builder|alice|bob)$ || "$VAL_ID" == watcher-* ]]; then
    die "--id '$VAL_ID' is reserved; nothing was installed"
  fi
}

main() {
  parse_args "$@"
  case "${CHANNEL:-}" in ""|stable|beta) ;; *) die "--channel must be stable or beta (got '$CHANNEL')" ;; esac
  [[ "$CMD" == "install" && -z "$CHANNEL" ]] && CHANNEL="stable"
  validate_id_arg
  resolve_home
  case "$CMD" in
    install) cmd_install ;;
    status) cmd_status ;;
    balance) cmd_balance ;;
    dash) cmd_dash ;;
    web) cmd_web ;;
    logs) load_installed; exec tail -n 50 -F "$LOGS/node.log" ;;
    start) load_installed; svc_start; ok started ;;
    stop) load_installed; svc_stop; ok stopped ;;
    restart) load_installed; svc_restart; ok restarted ;;
    upgrade) cmd_upgrade ;;
    adopt) cmd_adopt ;;
    autoupgrade) cmd_autoupgrade ;;
    validator) cmd_validator ;;
    heartbeat) cmd_heartbeat ;;
    uninstall) cmd_uninstall ;;
    help) usage ;;
    *) die "unknown command '$CMD' (see --help)" ;;
  esac
}

main "$@"
