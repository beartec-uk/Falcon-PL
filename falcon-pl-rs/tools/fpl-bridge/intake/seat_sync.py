#!/usr/bin/env python3
"""Operator seat side of the intake ceremony (host2, seat3). TESTNET DESIGN TEST.
Mirrors graphs/req-<id>/ from the lead's tailnet seat API, runs this seat's
fpl_ceremony_participant (RAM-only key, wiped after signing) and uploads only this
seat's own pub/nonces/sigs/attest file. The kit (fpl-operatord) then cosigns the
graph on the ledger from the mirrored final.json + request.json.
Env: FPL_OP_HOME FPL_EX FPL_SEAT_ID FPL_LEAD_SEAT_URL (http://<lead tailnet ip>:8791)
     FPL_SEAT_TOKEN_FILE ($FPL_OP_HOME/keys/intake-seat.token)"""
import json, os, subprocess, time, urllib.request
E = os.environ.get
HOME = E("FPL_OP_HOME", "/opt/fpl-operator"); EX = E("FPL_EX", HOME + "/bin")
SEAT = E("FPL_SEAT_ID"); LEAD = E("FPL_LEAD_SEAT_URL").rstrip("/")
TOK = open(E("FPL_SEAT_TOKEN_FILE", HOME + "/keys/intake-seat.token")).read().strip()
GRAPHS = os.path.join(HOME, "graphs"); OWN = ("pub", "nonces", "sigs", "attest")
procs = {}


def get(p):
    with urllib.request.urlopen(LEAD + p, timeout=20) as r:
        return r.read()


def put(p, b):
    q = urllib.request.Request(LEAD + p, data=b, method="PUT", headers={"x-seat": SEAT, "authorization": "Bearer " + TOK})
    try:
        urllib.request.urlopen(q, timeout=20)
    except urllib.error.HTTPError as e:
        if e.code != 409:
            raise


def sync(rid):
    d = os.path.join(GRAPHS, "req-" + rid); os.makedirs(d, exist_ok=True)
    for rel, size in json.loads(get(f"/seat/{rid}/files")):
        if rel.split("/")[0] in OWN and rel.endswith("/" + SEAT + ".json"):
            continue
        f = os.path.join(d, rel)
        if os.path.exists(f) and os.path.getsize(f) == size:
            continue
        b = get(f"/seat/{rid}/file/{rel}"); os.makedirs(os.path.dirname(f), exist_ok=True)
        open(f + ".tmp", "wb").write(b); os.replace(f + ".tmp", f)
    if rid not in procs and not os.path.exists(os.path.join(d, "attest", SEAT + ".json")):
        lg = open(os.path.join(d, "participant.log"), "a")
        procs[rid] = subprocess.Popen([EX + "/fpl_ceremony_participant", "--dir", d, "--id", SEAT, "--timeout-secs", "86400"],
                                      stdout=lg, stderr=lg, start_new_session=True)
    for sub in OWN:
        f = os.path.join(d, sub, SEAT + ".json")
        if os.path.exists(f) and not os.path.exists(f + ".up"):
            put(f"/seat/{rid}/file/{sub}/{SEAT}.json", open(f, "rb").read()); open(f + ".up", "w").close()


def reap(live):
    """Stop our participant for requests the lead no longer lists (failed/expired/done).
    Exited participants of still-listed requests are NOT respawned (their RAM-only key is
    gone; a new key could not join the same ceremony) - the lead times the request out."""
    for rid in list(procs):
        if rid in live:
            continue
        p = procs.pop(rid)
        if p.poll() is None:
            p.terminate()
            try:
                p.wait(timeout=10)
            except subprocess.TimeoutExpired:
                p.kill()
            print(time.strftime("%H:%M:%S"), "stopped participant for", rid, "(no longer listed by lead)", flush=True)


while True:
    try:
        live = json.loads(get("/seat/requests"))
        reap(set(live))
        for rid in live:
            sync(rid)
    except Exception as e:
        print(time.strftime("%H:%M:%S"), "sync error:", e, flush=True)
    time.sleep(3)
