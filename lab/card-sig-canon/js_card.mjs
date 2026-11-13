// @a2a-js/sdk side: sign cards with the SDK, verify candidates with the SDK verifier.
// usage: node js_card.mjs sign   < cards.jsonl      > signed_js.jsonl
//        node js_card.mjs verify < candidates.jsonl > verdict_js.jsonl
// Run with NODE_PATH pointing at a node_modules that has @a2a-js/sdk 1.3.0 and jose.
import { createRequire } from 'node:module';
import readline from 'node:readline';
import crypto from 'node:crypto';
const require = createRequire(process.env.NODE_PATH + '/');
const sdk = require('@a2a-js/sdk');
console.debug = () => {};

const SEED = '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60';
const PUB = 'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a';
const der = (prefix, hex) => Buffer.concat([Buffer.from(prefix, 'hex'), Buffer.from(hex, 'hex')]);
const priv = crypto.createPrivateKey({ key: der('302e020100300506032b657004220420', SEED), format: 'der', type: 'pkcs8' });
const pub = crypto.createPublicKey({ key: der('302a300506032b6570032100', PUB), format: 'der', type: 'spki' });

const rl = readline.createInterface({ input: process.stdin, crlfDelay: Infinity });
const mode = process.argv[2];
const signer = sdk.generateAgentCardSignature(priv, { alg: 'EdDSA', kid: 'owner-b', typ: 'JOSE' });
const verifier = sdk.verifyAgentCardSignature(async () => pub);
for await (const line of rl) {
  if (!line) continue;
  const rec = JSON.parse(line);
  if (mode === 'sign') {
    const signed = await signer(rec.card);
    // a JS server serves the object it holds, i.e. JSON.stringify of the signed card
    console.log(JSON.stringify({ id: rec.id, signer: 'js', features: rec.features, wire: JSON.stringify(signed) }));
  } else {
    let ok = false, err;
    try { await verifier(JSON.parse(rec.wire)); ok = true; } catch (e) { err = String(e.message).slice(0, 60); }
    console.log(JSON.stringify({ cid: rec.cid, js_sdk: ok }));
  }
}
