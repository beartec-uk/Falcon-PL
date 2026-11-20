#!/usr/bin/env python3
"""Operator seat side of the intake ceremony (co-signer seats, e.g. falcon2 and
beartec-brain). TESTNET DESIGN TEST.
Mirrors graphs/req-<id>/ from the lead's tailnet seat API, runs this seat's
fpl_ceremony_participant (RAM-only key, wiped after signing) and uploads only this
seat's own pub/nonces/sigs/attest file. The kit (fpl-operatord) then cosigns the
graph on the ledger from the mirrored final.json + request.json.

Participant lifecycle:
  * one participant per listed request, spawned once;
  * stopped when the lead stops listing the request (failed/expired/done), including a
    participant left running by an earlier seat_sync process (found via /proc);
  * never respawned once this seat has announced a key (pub/<seat>.json): the earlier
    participant's RAM-only key is gone, a new key cannot join the same ceremony, and a
    second participant would only burn memory. The lead times the request out.
  * one bad request never blocks syncing the others.
The unit uses KillMode=process so a seat_sync restart leaves running participants alone
(with systemd's default control-group mode a restart would kill them mid-ceremony).

Env: FPL_OP_HOME FPL_EX FPL_SEAT_ID FPL_LEAD_SEAT_URL (http://<lead tailnet ip>:8791)
     FPL_SEAT_TOKEN_FILE ($FPL_OP_HOME/keys/intake-seat.token) FPL_SEAT_POLL_SECS(3) FPL_PROC(/proc)"""
import json, os, signal, subprocess, time, urllib.error, urllib.request
E = os.environ.get
HOME = E("FPL_OP_HOME", "/opt/fpl-operator"); EX = E("FPL_EX", HOME + "/bin")
SEAT = E("FPL_SEAT_ID") or ""; LEAD = (E("FPL_LEAD_SEAT_URL") or "").rstrip("/")
GRAPHS = os.path.join(HOME, "graphs"); OWN = ("pub", "nonces", "sigs", "attest")
PROC = E("FPL_PROC", "/proc")
PART_BIN = "fpl_ceremony_participant"
procs = {}
_tok = None


def log(*a):
    print(time.strftime("%H:%M:%S"), *a, flush=True)


def token():
    global _tok
    if _tok is None:
        with open(E("FPL_SEAT_TOKEN_FILE", HOME + "/keys/intake-seat.token")) as f:
            _tok = f.read().strip()
    return _tok


def get(p):
    with urllib.request.urlopen(LEAD + p, timeout=20) as r:
        return r.read()


def put(p, b):
    q = urllib.request.Request(LEAD + p, data=b, method="PUT",
                               headers={"x-seat": SEAT, "authorization": "Bearer " + token()})
    try:
        urllib.request.urlopen(q, timeout=20)
    except urllib.error.HTTPError as e:
        if e.code != 409:
            raise


def req_dir(rid):
    return os.path.join(GRAPHS, "req-" + rid)


def should_spawn(rid, d):
    """Spawn only if we have no participant for rid and this seat never announced a key."""
    if rid in procs:
        return False
    if os.path.exists(os.path.join(d, "attest", SEAT + ".json")):
        return False
    if os.path.exists(os.path.join(d, "pub", SEAT + ".json")):
        return False   # an earlier participant ran (key gone): never start a second one
    if participant_pids().get(rid):
        return False   # still running from an earlier seat_sync process
    return True


def sync(rid):
    d = req_dir(rid); os.makedirs(d, exist_ok=True)
    for rel, size in json.loads(get(f"/seat/{rid}/files")):
        if rel.split("/")[0] in OWN and rel.endswith("/" + SEAT + ".json"):
            continue
        f = os.path.join(d, rel)
        if os.path.exists(f) and os.path.getsize(f) == size:
            continue
        b = get(f"/seat/{rid}/file/{rel}"); os.makedirs(os.path.dirname(f), exist_ok=True)
        with open(f + ".tmp", "wb") as fh:
            fh.write(b)
        os.replace(f + ".tmp", f)
    if should_spawn(rid, d):
        with open(os.path.join(d, "participant.log"), "a") as lg:
            procs[rid] = subprocess.Popen([EX + "/" + PART_BIN, "--dir", d, "--id", SEAT, "--timeout-secs", "86400"],
                                          stdout=lg, stderr=lg, start_new_session=True)
        log("started participant for", rid, "pid", procs[rid].pid)
    for sub in OWN:
        f = os.path.join(d, sub, SEAT + ".json")
        if os.path.exists(f) and not os.path.exists(f + ".up"):
            with open(f, "rb") as fh:
                put(f"/seat/{rid}/file/{sub}/{SEAT}.json", fh.read())
            open(f + ".up", "w").close()


def _cmdline(pid):
    try:
        with open(os.path.join(PROC, pid, "cmdline"), "rb") as f:
            return [a.decode(errors="replace") for a in f.read().split(b"\0") if a]
    except OSError:
        return []


def participant_pids():
    """{rid: [pid, ...]} for this seat's participants running on the host (any parent)."""
    out = {}
    try:
        pids = [p for p in os.listdir(PROC) if p.isdigit()]
    except OSError:
        return out
    for pid in pids:
        a = _cmdline(pid)
        if not a or os.path.basename(a[0]) != PART_BIN:
            continue
        try:
            d = a[a.index("--dir") + 1]
            sid = a[a.index("--id") + 1]
        except (ValueError, IndexError):
            continue
        base = os.path.basename(os.path.normpath(d))
        if sid != SEAT or not base.startswith("req-") \
                or os.path.dirname(os.path.normpath(d)) != os.path.normpath(GRAPHS):
            continue
        out.setdefault(base[4:], []).append(int(pid))
    return out


def _stop_pid(pid, kill=os.kill, sleep=time.sleep):
    try:
        kill(pid, signal.SIGTERM)
    except OSError:
        return
    for _ in range(20):
        sleep(0.5)
        try:
            kill(pid, 0)
        except OSError:
            return
    try:
        kill(pid, signal.SIGKILL)
    except OSError:
        pass


def reap(live, stop_pid=_stop_pid):
    """Stop our participants for requests the lead no longer lists (failed/expired/done),
    both the ones this process spawned and ones left by an earlier seat_sync process.
    Exited participants of still-listed requests are NOT respawned (see module doc)."""
    stopped = []
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
            stopped.append(rid)
            log("stopped participant for", rid, "(no longer listed by lead)")
    for rid, pids in participant_pids().items():
        if rid in live:
            continue
        for pid in pids:
            stop_pid(pid)
        stopped.append(rid)
        log("stopped orphan participant for", rid, "pids", pids, "(no longer listed by lead)")
    return stopped


def tick():
    live = json.loads(get("/seat/requests"))
    reap(set(live))
    for rid in live:
        try:
            sync(rid)
        except Exception as e:   # one bad request must not block the others
            log("sync error for", rid + ":", type(e).__name__, str(e)[:200])


def main():
    if not SEAT or not LEAD:
        raise SystemExit("FPL_SEAT_ID and FPL_LEAD_SEAT_URL are required")
    token()   # fail fast if the token file is missing (never printed)
    poll = float(E("FPL_SEAT_POLL_SECS", "3"))
    while True:
        try:
            tick()
        except Exception as e:
            log("sync error:", type(e).__name__, str(e)[:200])
        time.sleep(poll)


if __name__ == "__main__":
    main()
