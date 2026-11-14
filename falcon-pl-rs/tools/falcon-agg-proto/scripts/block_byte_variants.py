import sys
import json,glob,zlib,base64,re,subprocess
HEX=re.compile(r'^[0-9a-f]+$')
def b64ify(o, keys):
    if isinstance(o,dict):
        return {k:(base64.b64encode(bytes.fromhex(v)).decode() if k in keys and isinstance(v,str) and v and HEX.match(v) and len(v)%2==0 else b64ify(v,keys)) for k,v in o.items()}
    if isinstance(o,list):
        return [b64ify(x,keys) for x in o]
    return o
SIGK={'signature','packer_sig','batch_sig'}
tot=dict()
def add(k,v): tot[k]=tot.get(k,0)+v
files=sorted(glob.glob(sys.argv[1] + '/*.json'))
raw_all=b''
for f in files:
    raw=open(f,'rb').read(); L=json.loads(raw)
    add('A_current_json',len(raw))
    add('A_current_json_zlib6',len(zlib.compress(raw,6)))
    # B: drop batch_paths (receiver recomputes the Merkle root from the txs it already has)
    B=dict(L); B.pop('batch_paths',None)
    bj=json.dumps(B,separators=(',',':')).encode(); add('B_drop_batch_paths',len(bj))
    # C: B + drop packer_public_key (registered on-chain; H_act registry)
    C=dict(B); C.pop('packer_public_key',None)
    cj=json.dumps(C,separators=(',',':')).encode(); add('C_plus_drop_packer_pk',len(cj))
    # D: C + signatures base64 instead of hex (still JSON)
    D=b64ify(C,SIGK)
    if D.get('parent_cert'): D['parent_cert']['signatures']=[base64.b64encode(bytes.fromhex(s)).decode() for s in C['parent_cert']['signatures']]
    dj=json.dumps(D,separators=(',',':')).encode(); add('D_plus_sigs_base64',len(dj))
    # E: C with raw binary sigs (estimate = C minus half of all sig hex chars)
    sighex=sum(len(t['signature']) for t in C['txs'])+len(C['packer_sig'])+len(C.get('batch_sig',''))+sum(len(s) for s in (C.get('parent_cert') or {}).get('signatures',[]))
    add('E_plus_sigs_binary_est',len(cj)-sighex//2)
    # F: sigs pruned after finality (keep sig_root in batch_root): C minus all tx sig chars
    add('F_archive_tx_sigs_pruned',len(cj)-sum(len(t['signature'])+len('"signature":"",') for t in C['txs']))
    raw_all+=raw+b'\n'
n=len(files)
base=tot['A_current_json']
for k,v in tot.items(): print(f'{k:28s} per_block={v/n:9.0f}  vs_current={100*v/base:5.1f}%')
pass
