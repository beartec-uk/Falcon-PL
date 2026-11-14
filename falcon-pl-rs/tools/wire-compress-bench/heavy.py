"""Same live-bundle model, restricted to the heaviest blocks (>=50 txs) in all 300."""
import json, glob, zstandard as zstd, bench
ds = sorted((json.load(open(f)) for f in glob.glob(__import__("os").environ.get("BODIES","/workspace/qsag/bodies")+"/*.json")), key=lambda d: d["height"])
heavy = [d for d in ds if len(d["txs"]) >= 50]
print("heavy blocks", len(heavy), "mean txs", sum(len(d["txs"]) for d in heavy) / len(heavy))
def bundle(enc, mode):
    xf, ser, bg = bench.ENCODINGS[enc]; seq = []
    for d in heavy:
        m = bench.messages(d, xf, ser, bg)
        for k in bench.LIVE: seq += m[k]
    if mode == "none": return sum(map(len, seq))
    if mode == "zstd-3 msg": z = zstd.ZstdCompressor(level=3); return sum(len(z.compress(x)) for x in seq)
    co = zstd.ZstdCompressor(level=3).compressobj()
    return sum(len(co.compress(x) + co.flush(zstd.COMPRESSOBJ_FLUSH_BLOCK)) for x in seq)
base = bundle("hex_json (today)", "none")
for enc in bench.ENCODINGS:
    for mode in ("none", "zstd-3 msg", "zstd-3 stream"):
        b = bundle(enc, mode); print(f"{enc:20s} {mode:14s} {b/len(heavy):8.0f} B/blk {100*(1-b/base):+5.1f}%")
floor = sum(sum(len(t["signature"]) // 2 for t in d["txs"]) + 6 * 666 + len(d["packer_sig"]) // 2 + len(d["batch_sig"]) // 2 for d in heavy) / len(heavy)
print("sig floor", round(floor), "B/blk", f"{100*(1-floor*len(heavy)/base):.1f}% max")
