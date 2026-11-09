#!/usr/bin/env python3
"""Evaluate a snap_rehearsal.sh artifact dir against scenario expectations.
Usage: evaluate.py ART_DIR SCENARIO   (SCENARIO: basic|pressure|reask|stall|two|large)
Criteria are fixed per scenario; nothing is relaxed on failure."""
import json,re,sys,os
art,scen=sys.argv[1],sys.argv[2]
strip=lambda s: re.sub(r"\x1b\[[0-9;]*m","",s)
L=lambda i: strip(open(f"{art}/logs/{i}.log",errors="replace").read()) if os.path.exists(f"{art}/logs/{i}.log") else ""
meta=open(art+"/meta.txt").read()
joiners=re.search(r"JOINERS=(.*?) WALLETS",meta).group(1).split()
v1=L("v1"); res={"scenario":scen,"checks":{}}
C=res["checks"]
def chk(name,ok,detail=None):
    C[name]={"ok":bool(ok),"detail":detail}
synced=json.load(open(art+"/joiners_synced.json")) if os.path.exists(art+"/joiners_synced.json") else []
rows=[json.loads(l) for l in open(art+"/trace.jsonl")] if os.path.exists(art+"/trace.jsonl") else []
ts=lambda line: line[11:23]
def tsec(line):
    h,m,s=line[11:19].split(":"); return int(h)*3600+int(m)*60+float(line[17:26]) - float(line[17:19]) + int(s) if False else int(h)*3600+int(m)*60+float(line[17:26])
for j in joiners:
    jl=L(j)
    offers=re.findall(r"snapshot offer tip=(\d+) bytes=(\d+) chunks=(\d+) from=(\S+)",jl)
    adopt=[l for l in jl.splitlines() if "snapshot adopted" in l]
    serves=re.findall(rf"snapshot serving tip=(\d+) bytes=(\d+) chunks=(\d+) to={j}\b",v1)
    chk(f"{j}.offer_from_v1_multichunk", offers and offers[0][3]=="v1" and int(offers[0][2])>=2, offers[:2])
    chk(f"{j}.served_to_{j}_by_v1", len(serves)>=1, serves[:3])
    chk(f"{j}.adopted", len(adopt)==1, [a[11:] for a in adopt])
    chk(f"{j}.no_hash_mismatch_or_assemble_fail", "snapshot hash mismatch" not in jl and "assemble failed" not in jl)
    chk(f"{j}.tip_and_hash_match_v1", j in synced, rows[-1].get(j) if rows else None)
    recv=len(re.findall(r"snapshot chunk recv idx=",jl))
    C[f"{j}.info"]={"ok":True,"detail":{"chunks_recv_events":recv,"hole_fill_requests":len(re.findall(r"snapshot hole-fill request",jl)),
        "stalled":re.findall(r"snapshot source \S+ stalled[^\n]*",jl)[:2],"kept":re.findall(r"kept for resume[^\n]*",jl)[:2],
        "resumes":re.findall(r"offer resumes kept download[^\n]*",jl)[:2],"slow_skip_offers":jl.count("skipped (slow source)"),
        "offer_to_adopt_s": (round(tsec(adopt[0])-tsec([l for l in jl.splitlines() if "snapshot offer tip=" in l][0]),3) if adopt and offers else None)}}
# mesh health
mesh=[l.split() for l in open(art+"/mesh_after.txt").read().splitlines()]
pre=json.load(open(art+"/v1_pre_joiner.json")).get("body",{}).get("tip_height") if os.path.exists(art+"/v1_pre_joiner.json") else None
tips=[int(m[1]) for m in mesh if len(m)>=3 and m[1]!="None"]
from collections import Counter
if tips:
    t,n=Counter(tips).most_common(1)[0]; hs={m[2] for m in mesh if len(m)>=3 and m[1]==str(t)}
else: t=n=0; hs=set()
chk("mesh.healthy_majority_agree_and_progressed", n>=5 and len(hs)==1 and pre is not None and t>=pre, {"tips":tips,"pre_joiner_tip":pre})
chk("no_panic", not any("panicked" in L(i) for i in ["v1","v2","v3","v4","v5","v6"]+joiners))
# bounded memory: VmHWM from /proc for v1 + joiners
hwm={}
for line in open(art+"/rss_final.txt"):
    m=re.search(r"^(\S+) .*VmHWM:\s*(\d+)",line)
    if m: hwm[m.group(1)]=int(m.group(2))
C["mem.vmhwm_kb"]={"ok":True,"detail":hwm}
v1_def=max([int(x) for x in re.findall(r"catch-up reply deferred \(catch-up lane full\)[^\n]*total=(\d+)",v1)]+[0])
v1_ctl_ok=re.findall(r"snapshot control reply sent after (\d+) waits[^\n]*",v1)
v1_ctl_fail=re.findall(r"snapshot control reply failed[^\n]*",v1)
C["v1.pressure_counters"]={"ok":True,"detail":{"data_deferred":v1_def,"control_sent_after_wait":v1_ctl_ok[:5],"control_failed":len(v1_ctl_fail),
   "withheld":len(re.findall(r"withheld",v1)),"chunk_serves":len(re.findall(r"snapshot chunk serve idx=",v1)),"lane_full_log_lines":v1.count("catch-up lane full")}}
if scen in ("pressure","two","reask","large"):
    if scen!="large":
        chk("pressure.v1_data_deferred_gt0", v1_def>0, v1_def)
        chk("pressure.joiner_hole_fill_gt0", all(len(re.findall(r"snapshot hole-fill request",L(j)))>0 for j in joiners))
if scen=="reask":
    chk("reask.offer_sent_after_wait_on_full_lane", len(v1_ctl_ok)>=1, v1_ctl_ok[:3])
    chk("reask.no_control_failures", len(v1_ctl_fail)==0, v1_ctl_fail[:3])
if scen=="two":
    chk("two.distinct_serves", all(re.search(rf"to={j}\b",v1) for j in joiners) and len(joiners)==2)
if scen=="stall":
    j=joiners[0]; jl=L(j)
    st=[l for l in jl.splitlines() if re.search(r"snapshot source v1 stalled",l)]
    kp=[l for l in jl.splitlines() if "kept for resume" in l]
    rs=[l for l in jl.splitlines() if "offer resumes kept download" in l]
    chk("stall.source_marked_stalled", len(st)>=1, [x[11:] for x in st[:2]])
    chk("stall.partial_kept_for_resume", len(kp)>=1, [x[11:] for x in kp[:2]])
    chk("stall.resumed_same_sha", len(rs)>=1, [x[11:] for x in rs[:2]])
    if st and rs:
        gap=tsec(rs[0])-tsec(st[0])
        chk("stall.cooldown_honoured_25s_to_120s", 25<=gap<=120, round(gap,1))
    chk("stall.no_offer_from_stalled_source_during_cooldown", jl.count("skipped (slow source)")==0, jl.count("skipped (slow source)"))
res["PASS"]=all(v["ok"] for v in C.values())
print(json.dumps(res,indent=1))
open(art+"/EVAL.json","w").write(json.dumps(res,indent=1))
