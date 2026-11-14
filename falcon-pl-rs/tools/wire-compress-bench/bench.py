#!/usr/bin/env python3
"""Falcon PL wire compression bench (testing only, box-local).

Encodings x codecs over real testnet-2300 block bodies, plus gossip messages
built from them (shapes taken from WireMsg in fd-pl lib.rs). Writes JSON.
Sizes and times are MEASURED on the machine that runs it. Encodings marked
(est) estimate a schema'd binary wire the node does not implement yet.
"""
import base64, random, glob, json, os, re, sys, time, statistics
import zstandard as zstd, lz4.frame, brotli, snappy, msgpack

BODIES = sys.argv[1] if len(sys.argv) > 1 else "/workspace/qsag/bodies"
REPS = int(os.environ.get("REPS", "5"))
HEX_RE = re.compile(r"^[0-9a-f]{32,}$")
HEADER_KEYS = ["height","parent_hash","network_id","packer","packer_public_key","tx_ids",
  "state_root_after","sealed_at_ms","sealed_utc_ms","packer_sig","ledger_hash",
  "skipped_predecessors","parent_cert","slashes","claim_root","current_committee_root",
  "next_committee_root","inner_hash","current_committee","next_committee"]

def js(o): return json.dumps(o, separators=(",", ":")).encode()
def lean_sig(h): return "b64:" + base64.b64encode(bytes.fromhex(h)).decode() if h else h

def body_hex(d): return d
def body_lean(d):                       # PR #44
    e = dict(d); e["txs"] = [dict(t, signature=lean_sig(t["signature"])) for t in d["txs"]]
    if e.get("batch_sig"): e["batch_paths"] = []
    return e
def body_lean_nopk(d):                  # + drop packer_public_key (follow-up)
    e = body_lean(d); e["packer_public_key"] = ""; return e

def to_bin(o):
    """Schema'd binary estimate: dict keys dropped (positional, like bincode),
    hex / b64: strings -> raw bytes, ints as msgpack varints."""
    if isinstance(o, dict): return [to_bin(v) for v in o.values()]
    if isinstance(o, list): return [to_bin(v) for v in o]
    if isinstance(o, str):
        if o.startswith("b64:"): return base64.b64decode(o[4:])
        if len(o) % 2 == 0 and HEX_RE.match(o): return bytes.fromhex(o)
    return o
def enc_json(o): return js(o)
def enc_bin(o): return msgpack.packb(to_bin(o), use_bin_type=True)

ENCODINGS = {
    "hex_json (today)": (body_hex, enc_json, False),
    "lean_json (PR#44)": (body_lean, enc_json, False),
    "lean_json_nopk": (body_lean_nopk, enc_json, False),
    "binary (est)": (body_lean, enc_bin, True),
    "binary_nopk (est)": (body_lean_nopk, enc_bin, True),
}

def tag(t, **kw): return dict(type=t, **kw)
def messages(d, xf, ser, bin_gossip):
    """Steady-state per-block gossip on one link. Code path (falcon_pl_node.rs):
    packer fans ProposeHeader + LedgerBodyById (txs cleared) + its LedgerOk;
    every seat votes LedgerOk; txs reached peers earlier via mempool gossip
    (hex JSON today and in PR #44; raw in the binary estimate)."""
    b = xf(d)
    hdr = {k: b.get(k) for k in HEADER_KEYS if k in b}
    m = {"header": [ser(tag("propose_header", header=hdr, catchup=False))],
         "body_by_id": [ser(tag("ledger_body_by_id", ledger=dict(b, txs=[])))],
         "body_full": [ser(tag("ledger_body", ledger=b))]}
    c = d.get("parent_cert") or {}
    sigs = c.get("signatures") or []
    com = c.get("committee") or ["v%d" % i for i in range(6)]
    # One vote per seat (6). Cert sigs are real seat Falcon sigs; seats not in
    # the cert get a fresh random sig of the same length (Falcon sigs are
    # near-random), so no artificial repeats inflate stream compression.
    rnd = random.Random(d["height"])
    vs = list(sigs) + [bytes(rnd.getrandbits(8) for _ in range(len(sigs[0]) // 2)).hex()
                       for _ in range(6 - len(sigs))] if sigs else [""] * 6
    m["votes"] = [ser(tag("ledger_ok", height=d["height"], ledger_hash=d["ledger_hash"],
                          voter=com[i % len(com)], signature=vs[i],
                          **({"round": c["round"]} if c.get("round") else {}))) for i in range(6)]
    m["cert"] = [ser(c)] if c else []
    tser = ser if bin_gossip else enc_json
    m["txs"] = [tser(tag("submit_tx", tx=t)) for t in d["txs"]]
    m["tx_inv"] = [ser(tag("tx_inv", ids=d["tx_ids"]))] if d["tx_ids"] else []
    return m
LIVE = ["header", "body_by_id", "votes", "txs", "tx_inv"]

class Z:
    def __init__(s, lvl, dic=None):
        s.c = zstd.ZstdCompressor(level=lvl, dict_data=dic); s.d = zstd.ZstdDecompressor(dict_data=dic)
    def comp(s, b): return s.c.compress(b)
    def dec(s, b): return s.d.decompress(b)
def codecs(dic):
    c = {"none": (lambda b: b, lambda b: b),
         "lz4": (lambda b: lz4.frame.compress(b), lz4.frame.decompress),
         "snappy": (snappy.compress, snappy.decompress),
         "brotli-5": (lambda b: brotli.compress(b, quality=5), brotli.decompress),
         "brotli-11": (lambda b: brotli.compress(b, quality=11), brotli.decompress)}
    for l in (1, 3, 9, 19):
        z = Z(l); c[f"zstd-{l}"] = (z.comp, z.dec)
    z = Z(3, dic); c["zstd-3+dict"] = (z.comp, z.dec)
    z = Z(19, dic); c["zstd-19+dict"] = (z.comp, z.dec)
    return c

def timeit(f, items):
    ts = []
    for _ in range(REPS):
        t0 = time.perf_counter_ns()
        for x in items: f(x)
        ts.append(time.perf_counter_ns() - t0)
    return statistics.median(ts) / 1000 / max(1, len(items))

def main():
    ds = sorted((json.load(open(f)) for f in glob.glob(os.path.join(BODIES, "*.json"))), key=lambda d: d["height"])
    train, test = ds[:200], ds[200:]
    out = {"n_train": len(train), "n_test": len(test), "heights": [ds[0]["height"], ds[-1]["height"]],
           "test_heights": [test[0]["height"], test[-1]["height"]], "rows": [], "split": {}, "stream": {}}
    for ename, (xf, ser, bg) in ENCODINGS.items():
        samples = []
        for d in train:  # dictionary sees only the older 200 blocks
            for k, v in messages(d, xf, ser, bg).items():
                if k != "body_full": samples += v
            samples.append(ser(xf(d)))
        dic = zstd.train_dictionary(112 * 1024, samples)
        tm = [messages(d, xf, ser, bg) for d in test]
        kinds = {k: [x for m in tm for x in m[k]] for k in tm[0]}
        kinds["block"] = [ser(xf(d)) for d in test]
        for cname, (cf, df) in codecs(dic).items():
            row = {"enc": ename, "codec": cname}
            for k, items in kinds.items():
                comp = [cf(x) for x in items]
                assert all(df(c) == x for c, x in zip(comp, items)), (ename, cname, k)
                row[k] = {"n": len(items), "raw": sum(map(len, items)), "comp": sum(map(len, comp)),
                          "c_us": timeit(cf, items), "d_us": timeit(df, comp)}
            out["rows"].append(row)
            print(ename, cname, "block", row["block"]["comp"], "c_us", round(row["block"]["c_us"], 1), flush=True)
    z3 = zstd.ZstdCompressor(level=3)
    sig_hex = b""; sig_raw = b""; rest = b""
    for d in test:
        sh = [t["signature"] for t in d["txs"]] + [t.get("public_key", "") for t in d["txs"]] + \
             ((d.get("parent_cert") or {}).get("signatures") or []) + [d["packer_sig"], d["batch_sig"], d["packer_public_key"]]
        sh = [s for s in sh if s]
        sig_hex += "".join(sh).encode(); sig_raw += b"".join(bytes.fromhex(s) for s in sh)
        e = json.loads(js(d))
        for t in e["txs"]: t["signature"] = ""; t["public_key"] = ""
        if e.get("parent_cert"): e["parent_cert"]["signatures"] = []
        e["packer_sig"] = e["batch_sig"] = e["packer_public_key"] = ""
        rest += js(e)
    for name, b in (("sig_and_key_hex", sig_hex), ("sig_and_key_raw_bytes", sig_raw), ("structure_json_rest", rest)):
        out["split"][name] = {"raw": len(b), "zstd3": len(z3.compress(b)), "brotli11": len(brotli.compress(b, quality=11))}
    for ename, (xf, ser, bg) in ENCODINGS.items():
        seq = []
        for d in test:
            m = messages(d, xf, ser, bg)
            for k in LIVE: seq += m[k]
        for lvl, wl in ((1, 0), (3, 0), (3, 17), (19, 0)):
            prm = zstd.ZstdCompressionParameters.from_level(lvl, **({"window_log": wl} if wl else {}))
            def run():
                co = zstd.ZstdCompressor(compression_params=prm).compressobj(); outb = []
                for x in seq: outb.append(co.compress(x) + co.flush(zstd.COMPRESSOBJ_FLUSH_BLOCK))
                return outb
            frames = run()
            dobj = zstd.ZstdDecompressor().decompressobj()
            assert b"".join(dobj.decompress(f) for f in frames) == b"".join(seq)
            t0 = time.perf_counter_ns()
            for _ in range(REPS): run()
            cus = (time.perf_counter_ns() - t0) / 1000 / REPS / len(test)
            t0 = time.perf_counter_ns()
            for _ in range(REPS):
                dobj = zstd.ZstdDecompressor().decompressobj()
                for f in frames: dobj.decompress(f)
            dus = (time.perf_counter_ns() - t0) / 1000 / REPS / len(test)
            out["stream"][f"{ename} | zstd-{lvl} stream" + (f" wlog{wl}" if wl else "")] = {
                "raw": sum(map(len, seq)), "comp": sum(map(len, frames)), "c_us_per_block": cus, "d_us_per_block": dus}
    json.dump(out, open(os.environ.get("OUT", "results.json"), "w"), indent=1)
    print("wrote", os.environ.get("OUT", "results.json"))

if __name__ == "__main__":
    main()
