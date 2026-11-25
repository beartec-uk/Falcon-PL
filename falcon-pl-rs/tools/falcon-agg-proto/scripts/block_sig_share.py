import sys
import json,glob,statistics as st,collections
rows=[];siglens=[];pks=collections.Counter();pklens=[]
agg=collections.Counter()
for f in glob.glob(sys.argv[1] + '/*.json'):
    raw=open(f,'rb').read(); L=json.loads(raw)
    total=len(raw)
    c=collections.Counter()
    c['total']=total
    for tx in L.get('txs',[]):
        s=tx.get('signature',''); c['tx_sig_hex']+=len(s); siglens.append(len(s)//2)
        p=tx.get('public_key',''); c['tx_pk_hex']+=len(p)
        if p: pks[p]+=1; pklens.append(len(p)//2)
        c['ntx']+=1; c['tx_with_pk']+= bool(p)
    c['packer_sig_hex']=len(L.get('packer_sig',''))
    c['packer_pk_hex']=len(L.get('packer_public_key',''))
    pc=L.get('parent_cert') or {}
    c['cert_sig_hex']=sum(len(s) for s in pc.get('signatures',[]))
    c['cert_nsig']=len(pc.get('signatures',[]))
    c['batch_sig_hex']=len(L.get('batch_sig',''))
    c['batch_paths_hex']=sum(len(x) for p in L.get('batch_paths',[]) for x in p)
    c['slash_hex']=sum(len(s.get('sig_a',''))+len(s.get('sig_b','')) for s in L.get('slashes',[]))
    c['tx_ids_hex']=sum(len(x) for x in L.get('tx_ids',[]))
    agg.update(c); rows.append((L['height'],c))
n=len(rows); rows.sort()
print('blocks',n,'heights',rows[0][0],'-',rows[-1][0])
for k,v in sorted(agg.items()): print(f'{k:16s} total={v:>12,} per_block={v/n:>10,.1f}')
sig_json = agg['tx_sig_hex']+agg['packer_sig_hex']+agg['cert_sig_hex']+agg['batch_sig_hex']+agg['slash_hex']
pk_json = agg['tx_pk_hex']+agg['packer_pk_hex']
print('sig chars share of JSON bytes: %.1f%%'%(100*sig_json/agg['total']))
print('pk chars share of JSON bytes: %.1f%%'%(100*pk_json/agg['total']))
print('batch_paths share: %.1f%%'%(100*agg['batch_paths_hex']/agg['total']))
print('tx sig raw bytes: min %d median %d mean %.1f max %d'%(min(siglens),st.median(siglens),st.mean(siglens),max(siglens)) if siglens else 'no tx sigs')
print('pk raw len', set(pklens), 'distinct pks', len(pks), 'pk occurrences', sum(pks.values()))
ntx=[c['ntx'] for _,c in rows]; print('txs/block min %d median %d mean %.1f max %d'%(min(ntx),st.median(ntx),st.mean(ntx),max(ntx)))
print('cert nsig distribution', collections.Counter(c['cert_nsig'] for _,c in rows))
# blocks with zero txs
print('empty blocks', sum(1 for x in ntx if x==0))
import sys
json.dump({'agg':agg,'n':n,'siglens':siglens},open('/tmp/fpl_block_sig_share.json','w'))
