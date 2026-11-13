#!/usr/bin/env python3
"""Falcon PL testnet4 bridge intake (lead operator seat). TESTNET DESIGN TEST.

Holds NO depositor key and NO coins of users. Per request it:
  1. derives the depositor P2WSH address from the browser's pubkey (fpl_depositor_ext address)
  2. waits for the user's funding UTXO (esplora, >=1 conf)
  3. reserves an operator kickoff UTXO, writes graphs/req-<id>/request.json, starts the
     coordinator (ceremony with the operator seats) + `fpl_depositor_ext prepare`
  4. serves the depositor PSBTs to the browser, takes its signatures (`finish`)
  5. once final.json exists and the kit bound/cosigned on the ledger, broadcasts the
     peg-in deposit + confirm (coordinator --resume --broadcast-peg-in, ledger binding gate)
  The kit (fpl-operatord) then mints BTC4 (Btc4PegIn), fronts payouts, watches.

Public API (behind the site proxy):   GET /v1/info, POST /v1/deposits, GET /v1/deposits/<id>,
  GET /v1/deposits?account=, POST /v1/deposits/<id>/signatures
Seat API (tailnet listener only):      GET /seat/requests, GET /seat/<id>/files,
  GET /seat/<id>/file/<rel>, PUT /seat/<id>/file/<pub|nonces|sigs|attest>/<seat>.json (X-Seat)
Seat writes need `Authorization: Bearer <token>`; seats.json = {seat: sha256(token) hex}
(n-of-n keys are per-ceremony RAM keys, so they cannot be pinned; the token gates who may
announce one). FPL_LOCAL_SEAT: this seat's own participant is spawned locally.

Env: FPL_OP_HOME FPL_EX FPL_NETWORK(testnet4) FPL_ESPLORA FPL_SEATS FPL_OPERATOR_SECRET
     (or FPL_OPERATOR_SECRET_FILE) FPL_PROOF_DIR FPL_LOCAL_SEAT FPL_FALCON_CTL FPL_FALCON_RPC FPL_INTAKE_LISTEN(127.0.0.1:8790) FPL_SEAT_LISTEN(tailnet ip:8791)
     FPL_MIN_SATS(50000) FPL_MAX_SATS(2000000)
Ceremony supervision (see "ceremony supervision" below): FPL_MAX_CEREMONIES(2) FPL_CEREMONY_MEM_MB(4608)
     FPL_MEM_HEADROOM_MB(1024) FPL_COORD_MAX_RETRIES(3) FPL_COORD_BACKOFF_SECS(60) FPL_COORD_BACKOFF_MAX_SECS(900)
     FPL_COORD_GRACE_SECS(45) FPL_STAGE_TIMEOUT_<STATE>(secs) FPL_STALL_REALERT_SECS(21600)
     FPL_DISCORD_WEBHOOK_URL / DISCORD_HEALTH_WEBHOOK_URL or FPL_DISCORD_ENV_FILE (0600; URL never logged)
CLI: fpl_bridge_intake.py --plan   print what the supervisor would do to each live request (no changes)
"""
import hashlib, json, os, re, secrets, signal, subprocess, sys, threading, time, urllib.error, urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

E = os.environ.get
if E("FPL_OPERATOR_SECRET_FILE") and not E("FPL_OPERATOR_SECRET"):
    # key stays in its 0600 file on the seat; only this process (and its coordinator children) see it
    with open(E("FPL_OPERATOR_SECRET_FILE")) as _f:
        os.environ["FPL_OPERATOR_SECRET"] = _f.read().strip()
HOME = E("FPL_OP_HOME", "/opt/fpl-operator")
EX = E("FPL_EX", HOME + "/bin")
NET = E("FPL_NETWORK", "testnet4")
ESP = E("FPL_ESPLORA", "https://mempool.space/testnet4/api/").rstrip("/") + "/"
SEATS = E("FPL_SEATS", "host1,host2,seat3")
GRAPHS = os.path.join(HOME, "graphs")
STATE = os.path.join(HOME, "intake")
MIN_SATS, MAX_SATS = int(E("FPL_MIN_SATS", "50000")), int(E("FPL_MAX_SATS", "2000000"))
SEAT_SUBDIRS = ("pub", "nonces", "sigs", "attest")
SEAT_SHARED = ("request.json", "graphs.json", "nonced.json", "final.json", "transcript.json",
               "peg_in_unsigned.json", "peg_in_signed.json", "depositor_request.json")
LOCK = threading.RLock()
# Testnet4 tBTC faucet drip in sats (default 0.1 tBTC). Keep <= FPL_MAX_SATS
# so one drip can be bridged.
FAUCET_SATS = max(1000, int(E("FPL_FAUCET_SATS", "10000000")))
os.makedirs(STATE, exist_ok=True); os.makedirs(GRAPHS, exist_ok=True)


def log(*a):
    print(time.strftime("%H:%M:%S"), *a, flush=True)


def run(args, **kw):
    return subprocess.run(args, capture_output=True, text=True, timeout=kw.pop("timeout", 120), **kw)


def utxo_confirmed(u: dict) -> bool:
    if u.get('status', {}).get('confirmed'):
        return True
    try:
        r = subprocess.run([
            '/opt/fpl-tn4btc/bin/bitcoin-cli',
            '-conf=/opt/fpl-tn4btc/bitcoin.conf',
            '-datadir=/opt/fpl-tn4btc/data',
            'gettxout', str(u['txid']), str(u['vout']), 'false'
        ], capture_output=True, text=True, timeout=5)
        if r.returncode == 0 and r.stdout.strip():
            d = json.loads(r.stdout)
            return int(d.get('confirmations', 0)) >= 1
    except Exception:
        pass
    return False


def esplora(path, data=None):
    req = urllib.request.Request(ESP + path, data=data.encode() if data else None)
    with urllib.request.urlopen(req, timeout=20) as r:
        b = r.read().decode()
    try:
        return json.loads(b)
    except ValueError:
        return b


def coord_base(d):
    return [EX + "/fpl_ceremony_coordinator", "--dir", d, "--network", NET, "--esplora", ESP, "--seats", SEATS]


def funding_info():
    out = run(coord_base(GRAPHS + "/.probe") + ["--print-funding-addresses"]).stdout
    kv = dict(l.split()[:2] for l in out.splitlines() if len(l.split()) >= 2)
    return kv["operator"], int(kv["peg_in_fee"]), int(kv["peg_out_fee"])


# Lazy: unit tests import this file without a coordinator binary. The service
# process fills these in main() before serving.
OP_ADDR, PEG_IN_FEE, PEG_OUT_FEE = None, 0, 0
SEAT_TOKENS = json.load(open(os.path.join(STATE, "seats.json"))) if os.path.exists(os.path.join(STATE, "seats.json")) else {}


def path(i):
    return os.path.join(STATE, f"{i}.json")


def load(i):
    with open(path(i)) as f:
        return json.load(f)


def save(r):
    now = int(time.time())
    try:
        prev = load(r["id"]).get("state")
    except Exception:
        prev = None
    if prev != r.get("state"):
        r["state_since"] = now
    elif not r.get("state_since"):
        # legacy record (before state_since existed): its last save is the best age we have
        r["state_since"] = int(r.get("updated") or r.get("created") or now)
    r["updated"] = now
    tmp = path(r["id"]) + ".tmp"
    with open(tmp, "w") as f:
        json.dump(r, f, indent=1)
    os.replace(tmp, path(r["id"]))


def all_reqs():
    return [load(f[:-5]) for f in sorted(os.listdir(STATE)) if re.fullmatch(r"[0-9a-f]{16}\.json", f)]


def gdir(r):
    return os.path.join(GRAPHS, "req-" + r["id"])


def spent_deposit_txids(status):
    """Lowercased BTC4 spent_deposits from a falcon-pl-ctl status JSON object.

    Matches fpl-operator ledger.rs btc4_rail: status or status["body"], rails[]
    where asset == "BTC4".
    """
    if not isinstance(status, dict):
        return set()
    body = status.get("body")
    root = body if isinstance(body, dict) else status
    spent = set()
    for rail in root.get("rails") or []:
        if not isinstance(rail, dict) or rail.get("asset") != "BTC4":
            continue
        for txid in rail.get("spent_deposits") or []:
            if isinstance(txid, str) and txid:
                spent.add(txid.lower())
    return spent


def request_minted(req, spent):
    """True when this request's peg-in confirm txid has been consumed on the BTC4 rail."""
    txid = (req.get("peg_in_confirm_txid") or "").strip().lower()
    return bool(txid) and txid in spent


def reserved_kickoff_set(reqs):
    """Kickoff outpoints still pinned by a live request.

    Minted requests release their kickoff after the peg-in proof is consumed
    (BTC4 spent_deposits). awaiting_mint still reserves: the ceremony graph may
    still need that unspent outpoint until mint completes.
    """
    return {r.get("kickoff") for r in reqs
            if r.get("kickoff") and r.get("state") not in ("failed", "expired", "minted")}


def reserved_kickoffs():
    return reserved_kickoff_set(all_reqs())


def reserved_fundings(exclude_id=None):
    """Depositor funding outpoints already bound to a live request (one coin -> one request)."""
    return {r.get("funding") for r in all_reqs()
            if r.get("funding") and r["id"] != exclude_id and r.get("state") not in ("failed", "expired", "minted")}


def outpoint_unspent(txid, vout):
    """False if the outpoint is already spent (confirmed or in mempool) per esplora."""
    try:
        return not esplora(f"tx/{txid}/outspend/{vout}").get("spent")
    except Exception:
        return False  # unknown -> don't bind now, retry next pass


def pick_kickoff(need):
    used = reserved_kickoffs()
    utxos = [u for u in esplora(f"address/{OP_ADDR}/utxo") if utxo_confirmed(u) and u["value"] >= need]
    utxos = [u for u in sorted(utxos, key=lambda u: u["value"]) if f"{u['txid']}:{u['vout']}" not in used]
    return (f"{utxos[0]['txid']}:{utxos[0]['vout']}", utxos[0]["value"]) if utxos else (None, 0)


def falcon_ctl_status():
    """falcon-pl-ctl status JSON, or {} if unset/unavailable."""
    ctl = E("FPL_FALCON_CTL")
    if not ctl:
        return {}
    try:
        args = [ctl] + (["--addr", E("FPL_FALCON_RPC")] if E("FPL_FALCON_RPC") else []) + ["status"]
        return json.loads(run(args).stdout or "{}")
    except Exception:
        return {}


def ledger_bound(dep_txid):
    """All ACTIVE operators have a binding (graph or cosign) for this peg-in confirm txid."""
    if NET == "regtest" and E("FPL_INTAKE_REGTEST_NO_LEDGER") == "1":
        return True  # regtest e2e only; testnet4 always requires the ledger bindings
    if not E("FPL_FALCON_CTL"):
        return False
    st = falcon_ctl_status()
    root = st.get("body") if isinstance(st.get("body"), dict) else st
    bo = (root or {}).get("bridge_operators") or {}
    active = [o.get("btc_xonly_hex") for o in (bo.get("operators") or {}).values() if str(o.get("status", "")).lower() == "active"]
    g = bo.get("graphs") or {}
    return bool(active) and all(f"{dep_txid.lower()}:{x}" in g for x in active)



# ---------------------------------------------------------------------------
# ceremony supervision
#
# Incident 2026-11-13: four fundings confirmed in one block, four BitVM2 ceremonies
# started in one pass (~4.2 GB RSS per coordinator), the unit's 10G memcg OOM-killed
# one coordinator and request 65bb17492517646e sat in `signed` forever: nothing
# restarted the coordinator and no state had a timeout. This section adds
#   (a) a global ceremony limit sized to memory (funded -> ceremony_pubkeys deferred),
#   (b) coordinator supervision with bounded retries + backoff, then failed,
#   (c) stage timeouts for every non-terminal state,
#   (d) alerts (log + Discord health webhook) on death, retry, failure, stall.
# Safety rule: a request is only auto-failed while its peg-in deposit is NOT on chain
# or in the mempool (funds still at the depositor-only address). After broadcast the
# kickoff stays reserved (the graph needs it) and the request is flagged `stalled`
# with repeating alerts for a human instead.

def _env_int(k, d):
    try:
        return int(E(k, str(d)))
    except ValueError:
        return d


MAX_CEREMONIES = max(1, _env_int("FPL_MAX_CEREMONIES", 2))
CEREMONY_MEM_MB = _env_int("FPL_CEREMONY_MEM_MB", 4608)     # observed peak ~4.2 GB anon
MEM_HEADROOM_MB = _env_int("FPL_MEM_HEADROOM_MB", 1024)
COORD_MAX_RETRIES = _env_int("FPL_COORD_MAX_RETRIES", 3)
COORD_BACKOFF_SECS = _env_int("FPL_COORD_BACKOFF_SECS", 60)
COORD_BACKOFF_MAX_SECS = _env_int("FPL_COORD_BACKOFF_MAX_SECS", 900)
COORD_GRACE_SECS = _env_int("FPL_COORD_GRACE_SECS", 45)
STALL_REALERT_SECS = _env_int("FPL_STALL_REALERT_SECS", 6 * 3600)
PROC = E("FPL_PROC", "/proc")
COORD_BIN, PART_BIN = "fpl_ceremony_coordinator", "fpl_ceremony_participant"

TERMINAL_STATES = ("expired", "failed", "minted")
CEREMONY_STATES = ("ceremony_pubkeys", "awaiting_signature", "signed")
PRE_BROADCAST_STATES = ("waiting_operator_liquidity", "funded", "ceremony_pubkeys",
                        "awaiting_signature", "signed", "presigned")
POST_BROADCAST_STATES = ("broadcasting", "peg_in_confirmed", "awaiting_mint")
_H = 3600
DEFAULT_STAGE_TIMEOUTS = {
    "awaiting_funding": 3 * 86400,     # existing rule -> expired
    "waiting_operator_liquidity": 24 * _H,
    "funded": 12 * _H,                 # queued for a ceremony slot
    "ceremony_pubkeys": 2 * _H,        # seats announce in seconds
    "awaiting_signature": 24 * _H,     # depositor's wallet must sign
    "signed": 3 * _H,                  # ceremony normally 3-5 min
    "presigned": 24 * _H,              # ledger binding by all active operators
    "broadcasting": 24 * _H,           # stall alert only (post-broadcast)
    "peg_in_confirmed": 24 * _H,       # stall alert only
    "awaiting_mint": 24 * _H,          # stall alert only
}


def stage_timeout(state):
    return _env_int("FPL_STAGE_TIMEOUT_" + state.upper(), DEFAULT_STAGE_TIMEOUTS.get(state, 0))


def state_age(r, now):
    return now - int(r.get("state_since") or r.get("updated") or r.get("created") or now)


# ---- alerts (URL never logged) ----
_ALERTED = {}


def _webhook_url():
    u = E("FPL_DISCORD_WEBHOOK_URL") or E("DISCORD_HEALTH_WEBHOOK_URL")
    f = E("FPL_DISCORD_ENV_FILE")
    if not u and f and os.path.isfile(f):
        with open(f) as fh:
            lines = fh.read().splitlines()
        for line in lines:
            k, _, v = line.strip().partition("=")
            if k.strip().removeprefix("export ") in ("FPL_DISCORD_WEBHOOK_URL", "DISCORD_HEALTH_WEBHOOK_URL") and v:
                u = v.strip().strip('"').strip("'")
                break
    return u


def _post_discord(text):
    u = _webhook_url()
    if not u:
        return
    try:
        q = urllib.request.Request(u, data=json.dumps({"content": text[:1800]}).encode(), method="POST",
                                   headers={"Content-Type": "application/json", "User-Agent": "fpl-bridge-intake"})
        urllib.request.urlopen(q, timeout=10).read()
    except Exception as e:
        log("alert post failed:", type(e).__name__)  # never the URL


def alert(kind, r, msg, min_interval=900):
    """Log always; post to Discord at most once per (request, kind) per min_interval."""
    rid = r.get("id", "?") if isinstance(r, dict) else str(r)
    key = (rid, kind)
    now = time.time()
    log("ALERT", kind, rid, msg)
    if now - _ALERTED.get(key, 0) < min_interval:
        return
    _ALERTED[key] = now
    text = f"[{NET} bridge intake] {kind} req {rid}: {msg}"
    threading.Thread(target=_post_discord, args=(text,), daemon=True).start()


# ---- processes / memory ----
def _cmdline(pid):
    try:
        with open(f"{PROC}/{pid}/cmdline", "rb") as fh:
            raw = fh.read()
    except OSError:
        return []
    return [c.decode(errors="replace") for c in raw.split(b"\0") if c]


def _is_zombie(pid):
    try:
        with open(f"{PROC}/{pid}/stat") as fh:
            return fh.read().rsplit(")", 1)[1].split()[0] in ("Z", "X")
    except (OSError, IndexError):
        return True


def _rss_mb(pid):
    try:
        with open(f"{PROC}/{pid}/status") as fh:
            for line in fh:
                if line.startswith("VmRSS:"):
                    return int(line.split()[1]) // 1024
    except (OSError, ValueError):
        pass
    return 0


def ceremony_procs(d=None, names=(COORD_BIN, PART_BIN)):
    """Live (non-zombie) ceremony processes, optionally only those for graph dir d.
    Returns [(pid, binary, args)]. Found by /proc scan, so processes that outlived an
    intake restart (KillMode=process) are adopted."""
    out = []
    try:
        pids = [x for x in os.listdir(PROC) if x.isdigit()]
    except OSError:
        return out
    for pid in pids:
        args = _cmdline(pid)
        if not args or os.path.basename(args[0]) not in names or "--dir" not in args:
            continue
        i = args.index("--dir")
        pd = args[i + 1] if i + 1 < len(args) else ""
        if d is not None and os.path.normpath(pd) != os.path.normpath(d):
            continue
        if _is_zombie(pid):
            continue
        out.append((int(pid), os.path.basename(args[0]), args))
    return out


def live_ceremony_coordinators():
    """{graph dir: pid} for ceremony coordinators (not --resume broadcast/scenario runs)."""
    res = {}
    for pid, name, args in ceremony_procs(None, (COORD_BIN,)):
        if "--resume" in args:
            continue
        res[os.path.normpath(args[args.index("--dir") + 1])] = pid
    return res


def mem_available_mb():
    """min(host MemAvailable, this unit's cgroup v2 memory.max - memory.current)."""
    avail = None
    try:
        for line in open(E("FPL_MEMINFO", "/proc/meminfo")):
            if line.startswith("MemAvailable:"):
                avail = int(line.split()[1]) // 1024
    except OSError:
        pass
    try:
        rel = [l.split("::", 1)[1].strip() for l in open("/proc/self/cgroup") if l.startswith("0::")][0]
        base = os.path.join(E("FPL_CGROUP_ROOT", "/sys/fs/cgroup"), rel.lstrip("/"))
        mx = open(os.path.join(base, "memory.max")).read().strip()
        if mx != "max":
            cur = int(open(os.path.join(base, "memory.current")).read().strip())
            cg = (int(mx) - cur) // (1 << 20)
            avail = cg if avail is None else min(avail, cg)
    except (OSError, IndexError, ValueError):
        pass
    return avail


def ceremony_slot_free(exclude_dir=None):
    """(ok, reason). At most MAX_CEREMONIES live ceremony coordinators, and enough
    memory for one more: available - (still-ramping coordinators' remaining growth)
    must cover CEREMONY_MEM_MB + MEM_HEADROOM_MB."""
    live = {k: v for k, v in live_ceremony_coordinators().items()
            if exclude_dir is None or k != os.path.normpath(exclude_dir)}
    if len(live) >= MAX_CEREMONIES:
        return False, f"{len(live)} ceremonies running (max {MAX_CEREMONIES})"
    avail = mem_available_mb()
    if avail is not None:
        ramp = sum(max(0, CEREMONY_MEM_MB - _rss_mb(pid)) for pid in live.values())
        need = CEREMONY_MEM_MB + MEM_HEADROOM_MB
        if avail - ramp < need:
            return False, f"memory {avail} MB free, {ramp} MB still ramping, need {need} MB"
    return True, ""


def spawn_ceremony_coordinator(r, d, restart=False):
    lg = open(os.path.join(d, "coordinator.log"), "a")
    if restart:
        lg.write(f"\n=== intake: coordinator restart attempt {int(r.get('coord_attempts') or 1)} "
                 f"at {time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime())} UTC ===\n"); lg.flush()
        # a killed coordinator may leave a half-written lock-script cache; regenerate it
        cache = os.path.join(d, "bridge_data", "cache")
        if os.path.isdir(cache) and os.listdir(cache):
            os.replace(cache, cache + f".aside-{int(time.time())}")
    p = subprocess.Popen(coord_base(d) + ["--deposit-outpoint", r["funding"], "--deposit-amount", str(r["funding_sats"]),
                         "--evm-address", "fpl:" + r["account"], "--kickoff-outpoint", r["kickoff"],
                         "--kickoff-amount", str(r["kickoff_sats"]), "--timeout-secs", "86400"],
                         stdout=lg, stderr=lg, start_new_session=True, cwd=d)
    lg.close()  # the child holds its own descriptor
    r["coord_pid"] = p.pid
    r["coord_spawned"] = int(time.time())
    if not restart:
        r["coord_attempts"] = 1
    return p.pid


def spawn_broadcast(r, d):
    lg = open(os.path.join(d, "broadcast.log"), "a")
    args = coord_base(d) + ["--resume", "--broadcast-peg-in"]
    if E("FPL_FALCON_CTL"):
        args += ["--falcon-ctl", E("FPL_FALCON_CTL")] + (["--falcon-rpc", E("FPL_FALCON_RPC")] if E("FPL_FALCON_RPC") else [])
    p = subprocess.Popen(args, stdout=lg, stderr=lg, start_new_session=True, cwd=d)
    lg.close()
    r["bcast_pid"] = p.pid
    r["bcast_spawned"] = int(time.time())
    return p.pid


def kill_ceremony_procs(d):
    killed = []
    for pid, name, _ in ceremony_procs(d):
        try:
            os.kill(pid, signal.SIGTERM); killed.append(pid)
        except OSError:
            pass
    return killed


def tx_seen(txid):
    """True if esplora knows txid (mempool or chain), False on 404, None if unknown."""
    if not txid:
        return False
    try:
        esplora(f"tx/{txid}/status")
        return True
    except urllib.error.HTTPError as e:
        return False if e.code == 404 else None
    except Exception:
        return None


def broadcast_seen(r):
    """True/False/None (unknown) for 'is any peg-in tx of this request out there'."""
    seen = [tx_seen(r.get("deposit_txid")), tx_seen(r.get("peg_in_confirm_txid"))]
    if any(x is True for x in seen):
        return True
    if any(x is None for x in seen):
        return None
    return False


def fail_request(r, reason, kind, now):
    """Mark failed (releases kickoff + funding reservation) only if nothing was broadcast."""
    seen = broadcast_seen(r)
    if seen is None:
        r["last_error"] = f"{reason} (fail deferred: esplora unavailable)"
        return True
    if seen:
        return mark_stalled(r, f"{reason}; NOT failed: peg-in tx already broadcast, manual action needed", now)
    killed = kill_ceremony_procs(gdir(r))
    r.update(state="failed", last_error=reason, failed_reason=kind, failed_at=int(now))
    r.pop("stalled", None)
    alert("failed", r, f"{reason}. Funds stay at the depositor address; kickoff "
                       f"{(r.get('kickoff') or '-')[:16]} released; killed pids {killed}", min_interval=0)
    return True


def mark_stalled(r, reason, now):
    last = int(r.get("stall_alerted_at") or 0)
    r["stalled"] = reason
    if now - last >= STALL_REALERT_SECS:
        r["stall_alerted_at"] = int(now)
        alert("stalled", r, reason, min_interval=0)
    return True


def timeout_action(r, now):
    """None or (action, reason): action in fail|stall. Pure (no I/O): used by --plan too."""
    s = r["state"]
    if s in TERMINAL_STATES or s == "awaiting_funding":   # awaiting_funding: existing 3d -> expired
        return None
    lim = stage_timeout(s)
    age = state_age(r, now)
    if not lim or age <= lim:
        return None
    why = f"stage timeout: {s} for {age // 60} min (limit {lim // 60} min)"
    return ("fail" if s in PRE_BROADCAST_STATES else "stall", why)


def supervise(r, now=None):
    """Liveness + timeouts for one request (caller holds LOCK and saves on True)."""
    now = int(now or time.time())
    s, d = r["state"], gdir(r)
    ta = timeout_action(r, now)
    if ta:
        act, why = ta
        if act == "fail":
            return fail_request(r, why, "stage_timeout_" + s, now)
        return mark_stalled(r, why, now)

    if s in CEREMONY_STATES and not os.path.exists(os.path.join(d, "final.json")):
        if live_ceremony_coordinators().get(os.path.normpath(d)):
            if r.pop("coord_dead_since", None) is not None:
                return True
            return False
        if now - int(r.get("coord_spawned") or 0) < COORD_GRACE_SECS:
            return False
        if os.path.exists(os.path.join(d, "graphs.json")):
            return fail_request(r, "ceremony coordinator died after graphs.json was published; the signing "
                                   "rounds cannot resume (participants hold RAM-only nonces)", "coordinator_died_mid_signing", now)
        seat = E("FPL_LOCAL_SEAT")
        if seat and not os.path.exists(os.path.join(d, "attest", seat + ".json")) \
                and not ceremony_procs(d, (PART_BIN,)):
            return fail_request(r, f"local ceremony participant ({seat}) is gone; its RAM-only n-of-n key "
                                   "is lost so this ceremony cannot finish", "participant_died", now)
        attempts = int(r.get("coord_attempts") or 1)
        changed = False
        if not r.get("coord_dead_since"):
            r["coord_dead_since"] = now
            alert("coordinator_died", r, f"ceremony coordinator not running in state {s} (no final.json); "
                                         f"attempt {attempts} of {1 + COORD_MAX_RETRIES}")
            changed = True
        if attempts > COORD_MAX_RETRIES:
            return fail_request(r, f"ceremony coordinator died {attempts} times (max retries {COORD_MAX_RETRIES})",
                                "coordinator_retries_exhausted", now)
        backoff = min(COORD_BACKOFF_SECS * (2 ** (attempts - 1)), COORD_BACKOFF_MAX_SECS)
        if now - int(r["coord_dead_since"]) < backoff:
            return changed
        ok, why = ceremony_slot_free(exclude_dir=d)
        if not ok:
            note = "coordinator restart waiting for slot: " + why
            if r.get("last_error") != note:
                r["last_error"] = note
                changed = True
            return changed
        r["coord_attempts"] = attempts + 1
        spawn_ceremony_coordinator(r, d, restart=True)
        r.pop("coord_dead_since", None)
        r["last_error"] = f"coordinator restarted (attempt {attempts + 1})"
        alert("coordinator_restarted", r, f"restarted ceremony coordinator, attempt {attempts + 1} "
                                          f"of {1 + COORD_MAX_RETRIES} (pid {r['coord_pid']})", min_interval=0)
        return True

    if s == "broadcasting":
        if [p for p in ceremony_procs(d, (COORD_BIN,)) if "--resume" in p[2]]:
            return False
        if now - int(r.get("bcast_spawned") or 0) < COORD_GRACE_SECS:
            return False
        if tx_seen(r.get("peg_in_confirm_txid")) is not False:
            return False   # confirm is out there (or unknown): step() tracks confirmations
        attempts = int(r.get("bcast_attempts") or 1)
        if attempts > COORD_MAX_RETRIES:
            return mark_stalled(r, f"peg-in broadcast process died {attempts} times and the confirm tx is "
                                   "not on chain; manual action needed", now)
        backoff = min(COORD_BACKOFF_SECS * (2 ** (attempts - 1)), COORD_BACKOFF_MAX_SECS)
        if now - int(r.get("bcast_spawned") or 0) < backoff:
            return False
        r["bcast_attempts"] = attempts + 1
        spawn_broadcast(r, d)
        alert("broadcast_restarted", r, f"peg-in broadcast process gone, confirm tx unseen; respawned "
                                        f"(attempt {attempts + 1})", min_interval=0)
        return True
    return False


def plan(reqs, now=None):
    """Read-only report of what supervise() would do on the next pass."""
    now = int(now or time.time())
    rows = []
    for r in reqs:
        if r.get("state") in TERMINAL_STATES:
            continue
        ta = timeout_action(r, now)
        rows.append({"id": r["id"], "account": r.get("account"), "state": r["state"],
                     "age_h": round(state_age(r, now) / 3600, 1),
                     "timeout_h": round(stage_timeout(r["state"]) / 3600, 1),
                     "kickoff": r.get("kickoff"), "action": ta[0] if ta else "none",
                     "reason": ta[1] if ta else ""})
    return rows


def step(r):
    """Advance one request; returns True if changed."""
    s, d = r["state"], gdir(r)
    if s == "awaiting_funding":
        if time.time() - r["created"] > 3 * 86400:
            r["state"] = "expired"; return True
        used = reserved_fundings(r["id"])
        for u in esplora(f"address/{r['address']}/utxo"):
            op = f"{u['txid']}:{u['vout']}"
            if op in used:
                continue  # coin already bound to another request (shared per-pubkey address)
            if utxo_confirmed(u) and MIN_SATS + PEG_IN_FEE <= u["value"] <= MAX_SATS + PEG_IN_FEE \
                    and outpoint_unspent(u["txid"], u["vout"]):
                r.update(state="funded", funding=f"{u['txid']}:{u['vout']}", funding_sats=u["value"]); return True
        return False
    if s in ("funded", "waiting_operator_liquidity"):
        ok, why = ceremony_slot_free()
        if not ok:
            reason = "waiting_ceremony_slot: " + why
            if r.get("last_error") != reason:
                r["last_error"] = reason
                return True
            return False
        amt = r["funding_sats"] - PEG_IN_FEE
        ko, kv = pick_kickoff(amt + PEG_OUT_FEE)
        if not ko:
            changed = s != "waiting_operator_liquidity"
            reason = (
                "waiting_operator_liquidity: no confirmed unreserved operator kickoff "
                f"UTXO large enough for this deposit plus peg-out fee (need {amt + PEG_OUT_FEE} sats); "
                "intake does not aggregate smaller coins"
            )
            if r.get("last_error") != reason:
                r["last_error"] = reason
                changed = True
            r["state"] = "waiting_operator_liquidity"
            return changed
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, "request.json"), "w") as f:
            json.dump({"id": r["id"], "depositor_account": r["account"], "depositor_pubkey": r["depositor_pubkey"],
                       "funding": r["funding"], "amount": r["funding_sats"]}, f)
        evm = "fpl:" + r["account"]
        r.update(kickoff=ko, kickoff_sats=kv)
        spawn_ceremony_coordinator(r, d)
        lg2 = open(os.path.join(d, "prepare.log"), "a")
        subprocess.Popen([EX + "/fpl_depositor_ext", "prepare", "--network", NET, "--dir", d, "--depositor-pubkey", r["depositor_pubkey"],
                          "--funding", r["funding"], "--amount", str(r["funding_sats"]), "--evm-address", evm, "--seats", SEATS,
                          "--timeout-secs", "3600"], stdout=lg2, stderr=lg2, start_new_session=True, cwd=d)
        if E("FPL_LOCAL_SEAT"):
            lg3 = open(os.path.join(d, "participant.log"), "a")
            subprocess.Popen([EX + "/fpl_ceremony_participant", "--dir", d, "--id", E("FPL_LOCAL_SEAT"), "--timeout-secs", "86400"],
                             stdout=lg3, stderr=lg3, start_new_session=True, cwd=d)
        r.update(state="ceremony_pubkeys", kickoff=ko, kickoff_sats=kv)
        r.pop("last_error", None)
        return True
    if s == "ceremony_pubkeys" and os.path.exists(os.path.join(d, "depositor_request.json")):
        q = json.load(open(os.path.join(d, "depositor_request.json")))
        r.update(state="awaiting_signature", deposit_txid=q.get("deposit_txid"), peg_in_confirm_txid=q.get("peg_in_confirm_txid")); return True
    if s == "signed" and os.path.exists(os.path.join(d, "final.json")):
        r["state"] = "presigned"; return True
    if s == "presigned" and ledger_bound(r["peg_in_confirm_txid"]):
        lg = open(os.path.join(d, "broadcast.log"), "a")
        args = coord_base(d) + ["--resume", "--broadcast-peg-in"]
        if E("FPL_FALCON_CTL"):
            args += ["--falcon-ctl", E("FPL_FALCON_CTL")] + (["--falcon-rpc", E("FPL_FALCON_RPC")] if E("FPL_FALCON_RPC") else [])
        p = subprocess.Popen(args, stdout=lg, stderr=lg, start_new_session=True, cwd=d)
        r.update(bcast_pid=p.pid, bcast_spawned=int(time.time()), bcast_attempts=1)
        r["state"] = "broadcasting"; return True
    if s in ("broadcasting", "peg_in_confirmed"):
        try:
            t = esplora(f"tx/{r['peg_in_confirm_txid']}/status")
        except Exception:
            return False
        if isinstance(t, dict) and t.get("confirmed"):
            ns = "peg_in_confirmed"
            tip = int(esplora("blocks/tip/height"))
            r["confirmations"] = tip - t["block_height"] + 1
            if r["confirmations"] >= 6:
                ns = "awaiting_mint"
            r["state"] = ns; return True
    if s == "awaiting_mint":
        spent = spent_deposit_txids(falcon_ctl_status())
        if request_minted(r, spent):
            r["state"] = "minted"
            return True
        return False
    return False


def worker_pass(now=None):
    """One pass over live requests: supervision (liveness, timeouts) then the normal step.
    Each request is re-read under LOCK so an HTTP handler's concurrent change is never
    overwritten by a stale copy."""
    for rid in [r["id"] for r in all_reqs() if r["state"] not in TERMINAL_STATES]:
        try:
            with LOCK:
                r = load(rid)
                if r["state"] in TERMINAL_STATES:
                    continue
                before = r["state"]
                changed = supervise(r, now)
                if r["state"] not in TERMINAL_STATES and step(r):
                    changed = True
                if changed:
                    save(r)
                    if r["state"] != before:
                        log("req", r["id"], "->", r["state"])
        except Exception as e:  # keep serving; record last error
            try:
                with LOCK:
                    r = load(rid)
                    r["last_error"] = str(e)[:300]; save(r)
            except Exception:
                pass


def worker():
    while True:
        worker_pass()
        time.sleep(15)


def public_view(r):
    v = {k: r.get(k) for k in ("id", "account", "state", "address", "funding", "funding_sats", "deposit_txid",
                                "peg_in_confirm_txid", "kickoff", "confirmations", "created", "updated", "last_error")}
    v["network"] = NET
    d = gdir(r)
    if r["state"] == "awaiting_signature":
        v["depositor_request"] = json.load(open(os.path.join(d, "depositor_request.json")))
    t = os.path.join(d, "transcript.json")
    if os.path.exists(t):
        tr = json.load(open(t))
        v["ceremony"] = {"seats": tr.get("seats"), "nonced_sha256": tr.get("nonced_sha256"), "graphs": tr.get("graphs"),
                         "attestations": len(tr.get("attestations") or [])}
    return v


ACCT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
PUBK = re.compile(r"^0[23][0-9a-f]{64}$")


class H(BaseHTTPRequestHandler):
    seat_mode = False

    def send(self, code, obj):
        b = json.dumps(obj).encode() if not isinstance(obj, bytes) else obj
        self.send_response(code)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(b)))
        self.end_headers(); self.wfile.write(b)

    def body(self, cap=1 << 20):
        n = int(self.headers.get("content-length") or 0)
        if n > cap:
            raise ValueError("too large")
        return self.rfile.read(n)

    def log_message(self, *a):
        pass

    def do_GET(self):
        p = self.path.split("?")[0].rstrip("/")
        qs = dict(x.split("=", 1) for x in self.path.split("?", 1)[1].split("&") if "=" in x) if "?" in self.path else {}
        if self.seat_mode:
            return self.seat_get(p)
        if p == "/v1/info":
            return self.send(200, {"network": NET, "seats": SEATS.split(","), "peg_in_fee": PEG_IN_FEE, "min_sats": MIN_SATS,
                                   "max_sats": MAX_SATS, "testnet_design_test": True})
        if p == "/v1/deposits":
            a = qs.get("account", "")
            return self.send(200, [public_view(r) for r in all_reqs() if r["account"] == a][-20:])
        m = re.fullmatch(r"/v1/deposits/([0-9a-f]{16})", p)
        if m and os.path.exists(path(m[1])):
            return self.send(200, public_view(load(m[1])))
        self.send(404, {"error": "not found"})

    def do_POST(self):
        if self.seat_mode:
            return self.send(405, {})
        p = self.path.rstrip("/")
        try:
            j = json.loads(self.body(256 << 10) or b"{}")
        except ValueError:
            return self.send(400, {"error": "bad json"})
        if p == "/v1/faucet":
            addr = str(j.get("address", "")).strip()
            if not re.fullmatch(r"(?:tb1[ac-hj-np-z02-9]{25,87}|[mn2][a-km-zA-HJ-NP-Z1-9]{25,34})", addr):
                return self.send(400, {"error": "valid Testnet4 BTC address (tb1...) required"})
            faucet_file = os.path.join(STATE, "faucet_claims.json")
            now = int(time.time())
            with LOCK:
                try:
                    claims = json.load(open(faucet_file)) if os.path.exists(faucet_file) else {}
                except Exception:
                    claims = {}
                last_ts = int(claims.get(addr.lower(), 0))
                if now - last_ts < 21600:
                    rem_h = max(1, (21600 - (now - last_ts) + 3599) // 3600)
                    return self.send(429, {"error": f"This Testnet4 BTC address already claimed within 6h (try again in ~{rem_h}h)."})
                cli = ["/opt/fpl-tn4btc/bin/bitcoin-cli", "-conf=/opt/fpl-tn4btc/bitcoin.conf", "-datadir=/opt/fpl-tn4btc/data"]
                out = run(cli + ["-rpcwallet=fpl-operator", "-named", "sendtoaddress", f"address={addr}", f"amount={FAUCET_SATS / 1e8:.8f}", "fee_rate=1"], timeout=30)
                if out.returncode != 0 or not out.stdout.strip():
                    log("faucet err", addr, out.stderr or out.stdout)
                    return self.send(502, {"error": "tBTC faucet send failed: " + (out.stderr or out.stdout).strip()[-200:]})
                txid = out.stdout.strip()
                claims[addr.lower()] = now
                with open(faucet_file + ".tmp", "w") as fh:
                    json.dump(claims, fh)
                os.replace(faucet_file + ".tmp", faucet_file)
            # Best-effort relay raw tx to mempool.space/testnet4 so user sees it immediately
            try:
                raw = run(cli + ["getrawtransaction", txid], timeout=10)
                if raw.returncode == 0 and raw.stdout.strip():
                    raw_hex = raw.stdout.strip()
                    try:
                        req = urllib.request.Request(ESP + "tx", data=raw_hex.encode(), method="POST")
                        urllib.request.urlopen(req, timeout=8).read()
                    except Exception:
                        pass
            except Exception:
                pass
            log(f"faucet sent {FAUCET_SATS} sats", addr, txid)
            return self.send(200, {"ok": True, "txid": txid, "address": addr, "amount_sats": FAUCET_SATS, "amount_btc": f"{FAUCET_SATS / 1e8:g}"})
        if p == "/v1/deposits":
            acct, pk = str(j.get("account", "")).strip(), str(j.get("depositor_pubkey", "")).lower()
            if not ACCT.match(acct) or not PUBK.match(pk):
                return self.send(400, {"error": "account / compressed depositor_pubkey required"})
            open_n = sum(1 for r in all_reqs() if r["state"] == "awaiting_funding")
            if open_n >= 50:
                return self.send(429, {"error": "too many open requests"})
            out = run([EX + "/fpl_depositor_ext", "address", "--network", NET, "--depositor-pubkey", pk])
            if out.returncode:
                return self.send(400, {"error": "bad pubkey"})
            r = {"id": secrets.token_hex(8), "account": acct, "depositor_pubkey": pk, "address": out.stdout.strip(),
                 "state": "awaiting_funding", "created": int(time.time())}
            save(r); log("new req", r["id"], acct)
            v = public_view(r); v["send_sats_min"] = MIN_SATS + PEG_IN_FEE; v["send_sats_max"] = MAX_SATS + PEG_IN_FEE
            return self.send(201, v)
        m = re.fullmatch(r"/v1/deposits/([0-9a-f]{16})/signatures", p)
        if m and os.path.exists(path(m[1])):
            with LOCK:
                r = load(m[1])
                if r["state"] != "awaiting_signature":
                    return self.send(409, {"error": "state " + r["state"]})
                f = os.path.join(gdir(r), "browser_signed.json")
                with open(f, "w") as fh:
                    json.dump(j, fh)
                out = run([EX + "/fpl_depositor_ext", "finish", "--dir", gdir(r), "--signed", f])
                if out.returncode:
                    return self.send(400, {"error": "signatures rejected", "detail": (out.stderr or out.stdout)[-400:]})
                r["state"] = "signed"; save(r)
            return self.send(200, public_view(r))
        self.send(404, {"error": "not found"})

    # ---- seat sync (tailnet listener only) ----
    def seat_get(self, p):
        if p == "/seat/requests":
            return self.send(200, [r["id"] for r in all_reqs() if r["state"] in ("ceremony_pubkeys", "awaiting_signature", "signed", "presigned")])
        m = re.fullmatch(r"/seat/([0-9a-f]{16})/files", p)
        if m:
            # public ceremony files only: never bridge_data/ (operator WOTS secrets) or logs
            d = os.path.join(GRAPHS, "req-" + m[1]); out = []
            for rel in SEAT_SHARED:
                if os.path.isfile(os.path.join(d, rel)):
                    out.append([rel, os.path.getsize(os.path.join(d, rel))])
            for sub in SEAT_SUBDIRS:
                for f in sorted(os.listdir(os.path.join(d, sub))) if os.path.isdir(os.path.join(d, sub)) else []:
                    if re.fullmatch(r"[A-Za-z0-9_-]+\.json", f):
                        out.append([f"{sub}/{f}", os.path.getsize(os.path.join(d, sub, f))])
            return self.send(200, out)
        m = re.fullmatch(r"/seat/([0-9a-f]{16})/file/((?:pub|nonces|sigs|attest)/[A-Za-z0-9_-]+\.json|[a-z_]+\.json)", p)
        if m and (m[2] in SEAT_SHARED or "/" in m[2]):
            f = os.path.join(GRAPHS, "req-" + m[1], m[2])
            if os.path.isfile(f):
                return self.send(200, open(f, "rb").read())
        self.send(404, {"error": "not found"})

    def do_PUT(self):
        if not self.seat_mode:
            return self.send(405, {})
        m = re.fullmatch(r"/seat/([0-9a-f]{16})/file/(pub|nonces|sigs|attest)/([A-Za-z0-9_-]+)\.json", self.path)
        seat = self.headers.get("x-seat", "")
        if not m or m[3] != seat or seat not in SEATS.split(","):
            return self.send(403, {"error": "seat may only write its own files"})
        tok = self.headers.get("authorization", "").removeprefix("Bearer ").strip()
        if not tok or SEAT_TOKENS.get(seat) != hashlib.sha256(tok.encode()).hexdigest():
            return self.send(401, {"error": "seat token"})
        d = os.path.join(GRAPHS, "req-" + m[1])
        if not os.path.isdir(d):
            return self.send(404, {})
        b = self.body(96 << 20)  # nonce/sig files are ~20-25 MB per seat
        f = os.path.join(d, m[2], seat + ".json")
        if os.path.exists(f):
            return self.send(200 if open(f, "rb").read() == b else 409, {})
        os.makedirs(os.path.dirname(f), exist_ok=True)
        with open(f + ".tmp", "wb") as fh:
            fh.write(b)
        os.replace(f + ".tmp", f)
        self.send(201, {})


class SeatH(H):
    seat_mode = True


def serve(addr, cls):
    h, p = addr.rsplit(":", 1)
    ThreadingHTTPServer((h, int(p)), cls).serve_forever()


if __name__ == "__main__":
    if "--plan" in sys.argv[1:]:
        for row in plan(all_reqs()):
            print(json.dumps(row))
        sys.exit(0)
    OP_ADDR, PEG_IN_FEE, PEG_OUT_FEE = funding_info()
    log("intake", NET, "operator funding", OP_ADDR, "seats", SEATS)
    threading.Thread(target=worker, daemon=True).start()
    if E("FPL_SEAT_LISTEN"):
        threading.Thread(target=serve, args=(E("FPL_SEAT_LISTEN"), SeatH), daemon=True).start()
    serve(E("FPL_INTAKE_LISTEN", "127.0.0.1:8790"), H)
