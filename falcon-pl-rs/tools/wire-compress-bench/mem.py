"""Peak RSS cost (KiB) of one codec compressing+decompressing the test blocks,
measured as ru_maxrss delta in a fresh process. Usage: mem.py <codec> <enc>"""
import sys, resource, json, glob
import bench, zstandard as zstd, lz4.frame, brotli, snappy
codec, enc = sys.argv[1], sys.argv[2]
xf, ser, bg = bench.ENCODINGS[enc]
ds = sorted((json.load(open(f)) for f in glob.glob(__import__("os").environ.get("BODIES","/workspace/qsag/bodies")+"/*.json")), key=lambda d: d["height"])
blocks = [ser(xf(d)) for d in ds[200:]]
dic = None
if "dict" in codec:
    samples = [ser(xf(d)) for d in ds[:200]]
    dic = zstd.train_dictionary(112 * 1024, samples)
cs = bench.codecs(dic or zstd.ZstdCompressionDict(b"\0" * 64))
cf, df = cs[codec]
r0 = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
for b in blocks: assert df(cf(b)) == b
r1 = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
print(json.dumps({"codec": codec, "enc": enc, "rss_delta_kib": r1 - r0}))
