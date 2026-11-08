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
"""
import hashlib, json, os, re, secrets, subprocess, threading, time, urllib.request
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
    r["updated"] = int(time.time())
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
        lg = open(os.path.join(d, "coordinator.log"), "a")
        subprocess.Popen(coord_base(d) + ["--deposit-outpoint", r["funding"], "--deposit-amount", str(r["funding_sats"]),
                          "--evm-address", evm, "--kickoff-outpoint", ko, "--kickoff-amount", str(kv), "--timeout-secs", "86400"],
                         stdout=lg, stderr=lg, start_new_session=True, cwd=d)
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
        subprocess.Popen(args, stdout=lg, stderr=lg, start_new_session=True, cwd=d)
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


def worker():
    while True:
        for r in all_reqs():
            if r["state"] in ("expired", "failed", "minted"):
                continue
            try:
                with LOCK:
                    if step(r):
                        save(r); log("req", r["id"], "->", r["state"])
            except Exception as e:  # keep serving; record last error
                r["last_error"] = str(e)[:300]; save(r)
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
    OP_ADDR, PEG_IN_FEE, PEG_OUT_FEE = funding_info()
    log("intake", NET, "operator funding", OP_ADDR, "seats", SEATS)
    threading.Thread(target=worker, daemon=True).start()
    if E("FPL_SEAT_LISTEN"):
        threading.Thread(target=serve, args=(E("FPL_SEAT_LISTEN"), SeatH), daemon=True).start()
    serve(E("FPL_INTAKE_LISTEN", "127.0.0.1:8790"), H)
