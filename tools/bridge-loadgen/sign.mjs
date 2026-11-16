// Simulates the site's browser depositor (same @scure/btc-signer code path
// the Bridge page uses): reads depositor_request.json, signs the three PSBTs
// with the depositor key, writes signed.json. The key comes from the env
// (FPL_BROWSER_SECRET hex) in this test; on the site it never leaves the browser.
//   node sign.mjs <depositor_request.json> <signed.json>
//   node sign.mjs --pubkey            (prints the compressed pubkey for the secret)
import * as btc from '@scure/btc-signer';
import { hex } from '@scure/base';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { readFileSync, writeFileSync } from 'node:fs';

const priv = hex.decode(process.env.FPL_BROWSER_SECRET || '');
if (priv.length !== 32) throw new Error('FPL_BROWSER_SECRET (32-byte hex) required');
if (process.argv[2] === '--pubkey') {
  console.log(hex.encode(secp256k1.getPublicKey(priv, true)));
  process.exit(0);
}
export function signDepositorPsbt(psbtHex, key) {
  const tx = btc.Transaction.fromPSBT(hex.decode(psbtHex), {
    allowUnknownInputs: true,
    allowUnknownOutputs: true,
    disableScriptCheck: true,
  });
  tx.signIdx(key, 0, [btc.SigHash.ALL]);
  return hex.encode(tx.toPSBT());
}
const req = JSON.parse(readFileSync(process.argv[2], 'utf8'));
const out = {};
for (const k of ['deposit', 'refund', 'confirm']) out[k] = signDepositorPsbt(req.psbts[k], priv);
writeFileSync(process.argv[3], JSON.stringify(out));
console.log('signed', Object.keys(out).join(','), 'for graph', req.graph_id);
