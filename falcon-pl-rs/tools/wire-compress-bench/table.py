import json,sys
r=json.load(open(sys.argv[1])); rows=r["rows"]; N=r["n_test"]
base={k:v["raw"] for k,v in rows[0].items() if isinstance(v,dict)}
LIVE=["header","body_by_id","votes","txs","tx_inv"]
def live(row,f="comp"): return sum(row[k][f] for k in LIVE)
def live_us(row,f): return sum(row[k][f]*row[k]["n"] for k in LIVE)/N
B0=base["block"]; L0=sum(base[k] for k in LIVE)
print(f"test blocks {N}, heights {r['test_heights']}; today block avg {B0/N:.0f} B, live gossip bundle avg {L0/N:.0f} B")
print("| encoding | codec | block B/blk | block vs today | c µs/blk | d µs/blk | live bundle B/blk | bundle vs today | bundle c+d µs/blk | tx msg B | vote msg B |")
print("|---|---|---|---|---|---|---|---|---|---|---|")
for w in rows:
    b=w["block"]; 
    print(f"| {w['enc']} | {w['codec']} | {b['comp']/N:.0f} | {100*(1-b['comp']/B0):+.1f}% | {b['c_us']:.0f} | {b['d_us']:.0f} | {live(w)/N:.0f} | {100*(1-live(w)/L0):+.1f}% | {live_us(w,'c_us')+live_us(w,'d_us'):.0f} | {w['txs']['comp']/w['txs']['n']:.0f} | {w['votes']['comp']/w['votes']['n']:.0f} |")
print(); print("split (signatures/keys vs structure, hex body):")
for k,v in r["split"].items(): print(f"  {k}: raw {v['raw']} zstd3 {v['zstd3']} ({100*v['zstd3']/v['raw']:.1f}%) brotli11 {v['brotli11']} ({100*v['brotli11']/v['raw']:.1f}%)")
print(); print("per-link streaming zstd-3 over live bundle:")
for k,v in r["stream"].items(): print(f"  {k}: raw {v['raw']/N:.0f} -> {v['comp']/N:.0f} B/blk ({100*(1-v['comp']/L0):+.1f}% vs today raw), c {v['c_us_per_block']:.0f} d {v.get('d_us_per_block',0):.0f} µs/blk")
print(); print("component share of today's live bundle:", {k:f"{100*base[k]/L0:.1f}%" for k in LIVE})
