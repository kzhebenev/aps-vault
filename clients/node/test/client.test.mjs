// node --test clients/node/test   (after `npm run build`)
import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { Vault, VaultError, generateKeyPair, unseal, SEALED_ALG, SEALED_ALG_GOST, sealGost } from '../dist/index.js';
import { streebog256, streebog512, hmacStreebog256, kdfTree256, Kuznyechik, MGM, publicFromPrivate, encodePoint, decodePoint, onCurve, vko, unsealGost } from '../dist/gost.js';
import { createPrivateKey, createPublicKey, diffieHellman, generateKeyPairSync, hkdfSync, createCipheriv } from 'node:crypto';

const SPKI = Buffer.from('302a300506032b656e032100', 'hex');
const clientPair = generateKeyPair();
// GOST fixture shared by every client port (clients/fixtures/gost-sealed.json)
const FX = JSON.parse(fs.readFileSync(path.join(path.dirname(fileURLToPath(import.meta.url)), '../../fixtures/gost-sealed.json'), 'utf8'));
const H = (s) => Uint8Array.from(Buffer.from(s, 'hex'));
const hex = (b) => Buffer.from(b).toString('hex');
const B64 = (s) => Uint8Array.from(Buffer.from(s, 'base64'));
const scalar = (b64) => BigInt('0x' + Buffer.from(b64, 'base64').toString('hex'));
const gostPair = generateKeyPair({ gost: true });
// seal like the server: ephemeral X25519 → HKDF(info = label||epk||pk) → AES-256-GCM with the name as AAD
function sealLikeServer(payload, clientPkB64, name) {
  const eph = generateKeyPairSync('x25519');
  const epk = eph.publicKey.export({ type: 'spki', format: 'der' }).subarray(SPKI.length);
  const pk = Buffer.from(clientPkB64, 'base64');
  const shared = diffieHellman({ privateKey: eph.privateKey, publicKey: createPublicKey({ key: Buffer.concat([SPKI, pk]), format: 'der', type: 'spki' }) });
  const key = Buffer.from(hkdfSync('sha256', shared, Buffer.alloc(0), Buffer.concat([Buffer.from('aps-vault/sealed/v1'), epk, pk]), 32));
  const nonce = Buffer.alloc(12, 7);
  const c = createCipheriv('aes-256-gcm', key, nonce); c.setAAD(Buffer.from(name));
  const ct = Buffer.concat([c.update(JSON.stringify(payload)), c.final(), c.getAuthTag()]);
  return { alg: SEALED_ALG, v: 1, epk: epk.toString('base64'), nonce: nonce.toString('base64'), ct: ct.toString('base64') };
}

let failing = false, hits = 0;
const srv = http.createServer((req, res) => {
  const json = (code, body) => { res.writeHead(code, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(body)); };
  if (req.headers.authorization !== 'Bearer vlt_test_token') return json(401, { detail: 'invalid token' });
  if (failing) return json(503, {});
  hits++;
  if (req.method === 'GET' && req.url === '/api/v1/m/secret/db-password') return json(200, { name: 'db-password', value: 's3cr3t', login: 'app', updated_at: 'x' });
  if (req.method === 'GET' && req.url === '/api/v1/m/secret/sealed-db') return json(200, { name: 'sealed-db', version: 1, current_version: 1, updated_at: 'x', sealed: sealLikeServer({ value: 'pg-pass', login: 'core', totp: '123456' }, clientPair.publicKey, 'sealed-db') });
  // the server-produced GOST envelope from the fixture (AAD = its name, core-db)
  if (req.method === 'GET' && req.url === `/api/v1/m/secret/${FX.envelope.name}`) return json(200, { name: FX.envelope.name, version: 1, current_version: 1, updated_at: 'x', sealed: FX.envelope.sealed });
  if (req.method === 'GET' && req.url === '/api/v1/m/secret/gost-db') return json(200, { name: 'gost-db', version: 2, current_version: 2, updated_at: 'x', sealed: sealGost({ value: 'gost-pass', login: 'svc', totp: '654321' }, gostPair.publicKey, 'gost-db') });
  if (req.method === 'POST' && req.url === '/api/v1/m/secret/new') {
    let b = ''; req.on('data', c => b += c); req.on('end', () => { const o = JSON.parse(b); assert.equal(o.value, 'v'); assert.equal(o.login, 'u'); json(200, { id: 7, name: 'new', created: true }); });
    return;
  }
  if (req.url === '/api/v1/m/health') return json(200, { status: 'ok' });
  json(404, { detail: 'not found' });
});
await new Promise(r => srv.listen(0, '127.0.0.1', r));
const base = `http://127.0.0.1:${srv.address().port}`;

test('rejects a master password as token', () => {
  assert.throws(() => new Vault({ baseUrl: base, token: 'my master password' }));
});

test('get, cache, fail-open', async () => {
  const v = new Vault({ baseUrl: base, token: 'vlt_test_token', cacheTtlMs: 200, maxRetries: 1 });
  assert.equal(await v.get('db-password'), 's3cr3t');
  assert.equal((await v.getFull('db-password')).login, 'app');
  assert.equal(hits, 1, 'second call served from cache');
  await new Promise(r => setTimeout(r, 250));
  failing = true;
  assert.equal(await v.get('db-password'), 's3cr3t', 'stale value while vault is down');
  await assert.rejects(v.get('never-seen'));
  failing = false;
});

test('404 is not retried and carries status', async () => {
  const v = new Vault({ baseUrl: base, token: 'vlt_test_token' });
  const before = hits;
  await assert.rejects(v.get('missing'), (e) => e instanceof VaultError && e.status === 404);
  assert.equal(hits, before + 1);
});

test('put and health', async () => {
  const v = new Vault({ baseUrl: base, token: 'vlt_test_token' });
  assert.deepEqual(await v.put('new', 'v', { login: 'u' }), { id: 7, name: 'new', created: true });
  assert.equal((await v.health()).status, 'ok');
});

test('401 for a wrong token', async () => {
  const v = new Vault({ baseUrl: base, token: 'vlt_wrong' });
  await assert.rejects(v.get('db-password'), (e) => e instanceof VaultError && e.status === 401);
});

test('sealed delivery: decrypts with the bound private key, refuses others, needs the key', async () => {
  const v = new Vault({ baseUrl: base, token: 'vlt_test_token', clientPrivateKey: clientPair.privateKey, cacheTtlMs: 0 });
  assert.equal(await v.get('sealed-db'), 'pg-pass');
  const full = await v.getFull('sealed-db');
  assert.equal(full.login, 'core'); assert.equal(full.version, 1); assert.equal('sealed' in full, false, 'envelope is replaced by the payload');
  assert.equal(await v.totp('sealed-db'), '123456');
  const other = new Vault({ baseUrl: base, token: 'vlt_test_token', clientPrivateKey: generateKeyPair().privateKey, cacheTtlMs: 0 });
  await assert.rejects(other.get('sealed-db'), /does not open/);
  delete process.env.VAULT_CLIENT_KEY;
  await assert.rejects(new Vault({ baseUrl: base, token: 'vlt_test_token', cacheTtlMs: 0 }).get('sealed-db'), /sealed values/);
  // AAD: an envelope for one name does not open under another
  const env = sealLikeServer({ value: 'x' }, clientPair.publicKey, 'a');
  assert.throws(() => unseal(env, clientPair.privateKey, 'b'), /does not open/);
  assert.equal(unseal(env, clientPair.privateKey, 'a').value, 'x');
  assert.throws(() => unseal({ ...env, alg: 'RSA' }, clientPair.privateKey, 'a'), /unsupported/);
});

test('sealed delivery: opens the server-produced fixture (interop with backend/sealed.py)', () => {
  const sk = 'AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=';
  const env = { alg: SEALED_ALG, v: 1, epk: 'qId7VmcoFhnApxHZznkoaKFl/wIl/z2HauZI+GMVI1Q=', nonce: 'qTsci1J2iUT0nr58', ct: 'DmXYnxSzPc9d6MIdODi2I9bd2nw4yi3mBUWcxVHLDVlX/ax+BH5DcqBh2PBcBt8E7eTZouxd0SyW+fzJ4dlXL+F4SL2HrSY=' };
  assert.deepEqual(unseal(env, sk, 'core-db'), { value: 'pg-pass-2026', login: 'core', totp: '123456' });
  assert.throws(() => unseal(env, sk, 'other'), /does not open/);
});

// ── GOST (clients/GOST-PORTING.md §6) ─────────────────────────────────────────

test('gost: Streebog M1/M2 256+512 and the empty string', () => {
  assert.equal(hex(streebog256(H(FX.streebog.M1))), FX.streebog.M1_256);
  assert.equal(hex(streebog512(H(FX.streebog.M1))), FX.streebog.M1_512);
  assert.equal(hex(streebog256(H(FX.streebog.M2))), FX.streebog.M2_256);
  assert.equal(hex(streebog512(H(FX.streebog.M2))), FX.streebog.M2_512);
  assert.equal(hex(streebog256(new Uint8Array(0))), FX.streebog.empty_256);
  // multi-block + partial tail (M2 is 72 bytes): same digest whatever the split, and 64-byte-aligned input pads to a full block
  assert.equal(hex(streebog512(new Uint8Array(64))).length, 128);
  assert.notEqual(hex(streebog256(new Uint8Array(64))), hex(streebog256(new Uint8Array(63))));
});

test('gost: HMAC-Streebog-256 and KDF_TREE vectors (R 50.1.113)', () => {
  const h = FX.hmac_streebog256;
  assert.equal(hex(hmacStreebog256(H(h.key), H(h.data))), h.mac);
  const k = FX.kdf_tree_256;
  assert.equal(hex(kdfTree256(H(k.key), H(k.label), H(k.seed))), k.out);
  // a key longer than the 64-byte block is hashed first (the vault's vlt_ tokens are 83 chars)
  const long = new Uint8Array(83).fill(0x61);
  assert.equal(hex(hmacStreebog256(long, H(h.data))), hex(hmacStreebog256(streebog256(long), H(h.data))));
  assert.notEqual(hex(kdfTree256(H(k.key), H(k.label), H(k.seed))), hex(kdfTree256(H(k.key), H(k.label), H('af21434145656379'))));
});

test('gost: Kuznyechik vector (GOST R 34.12-2015) encrypt + decrypt', () => {
  const c = new Kuznyechik(H(FX.kuznyechik.key));
  assert.equal(hex(c.encryptBlock(H(FX.kuznyechik.pt))), FX.kuznyechik.ct);
  assert.equal(hex(c.decryptBlock(H(FX.kuznyechik.ct))), FX.kuznyechik.pt);
  assert.throws(() => new Kuznyechik(new Uint8Array(16)), /32 bytes/);
});

test('gost: MGM RFC 9058 vector — encrypt, decrypt, tampering refused', () => {
  const v = FX.mgm_rfc9058;
  // RFC 9058 Appendix A.1 plaintext (the fixture carries the same bytes; asserted explicitly so a fixture
  // edit can never silently change what this test proves)
  const rfcPt = '1122334455667700ffeeddccbbaa9988' + v.pt.slice(32);
  assert.equal(v.pt, rfcPt);
  const m = new MGM(new Kuznyechik(H(v.key)));
  const sealed = m.seal(H(v.nonce), H(rfcPt), H(v.aad));
  assert.equal(hex(sealed.subarray(0, sealed.length - 16)), v.ct);
  assert.equal(hex(sealed.subarray(sealed.length - 16)), v.tag);
  assert.equal(hex(m.open(H(v.nonce), H(v.ct + v.tag), H(v.aad))), rfcPt);
  // tampering: a flipped ciphertext bit, a flipped tag bit, a different AAD, a different nonce — all refused
  const flip = (buf, i) => { const b = Uint8Array.from(buf); b[i] ^= 1; return b; };
  assert.throws(() => m.open(H(v.nonce), flip(sealed, 0), H(v.aad)), /tag mismatch/);
  assert.throws(() => m.open(H(v.nonce), flip(sealed, sealed.length - 1), H(v.aad)), /tag mismatch/);
  assert.throws(() => m.open(H(v.nonce), sealed, flip(H(v.aad), 3)), /tag mismatch/);
  assert.throws(() => m.open(flip(H(v.nonce), 15), sealed, H(v.aad)), /tag mismatch/);
  assert.throws(() => m.open(H(v.nonce), sealed.subarray(0, 10), H(v.aad)), /too short/);
  assert.throws(() => m.seal(flip(H(v.nonce), 0).map((b, i) => i === 0 ? b | 0x80 : b), H(rfcPt), H(v.aad)), /top bit/);
  // empty plaintext / AAD still round-trips
  assert.equal(m.open(H(v.nonce), m.seal(H(v.nonce), new Uint8Array(0)), new Uint8Array(0)).length, 0);
});

test('gost: keypair vector (private → public), key encodings, off-curve point refused', () => {
  const d = scalar(FX.keypair.private_b64);
  const pub = publicFromPrivate(d);
  assert.equal('0x' + pub.x.toString(16), FX.keypair.public_x_hex_be);
  assert.equal('0x' + pub.y.toString(16), FX.keypair.public_y_hex_be);
  assert.equal(Buffer.from(encodePoint(pub)).toString('base64'), FX.keypair.public_b64);
  const back = decodePoint(B64(FX.keypair.public_b64));
  assert.equal(back.x, pub.x); assert.equal(back.y, pub.y);
  assert.equal(onCurve(pub), true);
  // off-curve: bump Y by one, X/Y out of range, wrong length, point at infinity
  const bad = B64(FX.keypair.public_b64); bad[32] ^= 1;
  assert.throws(() => decodePoint(bad), /not on the GOST curve/);
  assert.equal(onCurve({ x: pub.x, y: pub.y + 1n }), false);
  assert.equal(onCurve({ x: pub.x, y: pub.y + BigInt(FX.curve.p) }), false, 'coordinates must be reduced');
  assert.equal(onCurve(null), false);
  assert.throws(() => decodePoint(new Uint8Array(32)), /64 bytes/);
  // generated GOST pair: 32-byte scalar in [1, q), 64-byte point on the curve; X25519 default unchanged
  const skRaw = B64(gostPair.privateKey), pkRaw = B64(gostPair.publicKey);
  assert.equal(skRaw.length, 32); assert.equal(pkRaw.length, 64);
  const dd = scalar(gostPair.privateKey);
  assert.ok(dd >= 1n && dd < BigInt(FX.curve.q));
  assert.equal(Buffer.from(encodePoint(publicFromPrivate(dd))).toString('base64'), gostPair.publicKey);
  assert.equal(B64(generateKeyPair().publicKey).length, 32);
  assert.equal(B64(generateKeyPair({}).privateKey).length, 32);
});

test('gost: VKO vector (RFC 7836 §4.3)', () => {
  const v = FX.vko;
  const kek = vko(scalar(v.private_b64), decodePoint(B64(v.peer_public_b64)), H(v.ukm_hex));
  assert.equal(hex(kek), v.kek_hex);
  // symmetric: d_peer · (d · G) with the same UKM gives the same KEK (fresh pair as the peer)
  const peerD = scalar(gostPair.privateKey);
  const k1 = vko(scalar(v.private_b64), decodePoint(B64(gostPair.publicKey)), H(v.ukm_hex));
  const k2 = vko(peerD, decodePoint(B64(FX.keypair.public_b64)), H(v.ukm_hex));
  assert.equal(hex(k1), hex(k2));
  assert.notEqual(hex(vko(scalar(v.private_b64), decodePoint(B64(v.peer_public_b64)), H('0202030405060708'))), v.kek_hex, 'UKM changes the KEK');
  assert.throws(() => vko(scalar(v.private_b64), decodePoint(B64(v.peer_public_b64)), new Uint8Array(8)), /non-zero/);
  assert.throws(() => vko(scalar(v.private_b64), decodePoint(B64(v.peer_public_b64)), new Uint8Array(7)), /8 bytes/);
});

test('gost: the fixture envelope opens via unseal(); wrong key, wrong name, tampering, bad epk refused', () => {
  const env = FX.envelope.sealed, sk = FX.keypair.private_b64, name = FX.envelope.name;
  assert.equal(env.alg, SEALED_ALG_GOST);
  assert.deepEqual(unseal(env, sk, name), FX.envelope.payload);
  assert.deepEqual(unsealGost(env, sk, name), FX.envelope.payload);
  assert.throws(() => unseal(env, gostPair.privateKey, name), (e) => e instanceof VaultError && /does not open/.test(e.message));
  assert.throws(() => unseal(env, sk, 'other'), /does not open/);
  assert.throws(() => unseal(env, clientPair.privateKey, name), /does not open/, 'an X25519 key is not a GOST scalar for this envelope');
  const ct = B64(env.ct); ct[0] ^= 1;
  assert.throws(() => unseal({ ...env, ct: Buffer.from(ct).toString('base64') }, sk, name), /does not open/);
  const epk = B64(env.epk); epk[40] ^= 1;
  assert.throws(() => unseal({ ...env, epk: Buffer.from(epk).toString('base64') }, sk, name), /does not open/, 'off-curve ephemeral point');
  assert.throws(() => unseal({ ...env, ukm: 'AAAAAAAAAAA=' }, sk, name), /does not open/, 'zero UKM');
  assert.throws(() => unseal({ ...env, v: 2 }, sk, name), /unsupported/);
  assert.throws(() => unseal({ ...env, alg: 'GOST-SOMETHING' }, sk, name), /unsupported/);
  // round trip with a freshly generated pair through the client-side sealer
  const mine = sealGost({ value: 'v', notes: 'n' }, gostPair.publicKey, 'n1');
  assert.deepEqual(unseal(mine, gostPair.privateKey, 'n1'), { value: 'v', notes: 'n' });
  assert.throws(() => unseal(mine, gostPair.privateKey, 'n2'), /does not open/);
  assert.throws(() => sealGost({ value: 'v' }, clientPair.publicKey, 'n1'), /64 bytes/);
});

test('gost: Vault.get() reads the fixture envelope from a fake server with clientPrivateKey', async () => {
  const v = new Vault({ baseUrl: base, token: 'vlt_test_token', clientPrivateKey: FX.keypair.private_b64, cacheTtlMs: 0 });
  assert.equal(await v.get(FX.envelope.name), FX.envelope.payload.value);
  const full = await v.getFull(FX.envelope.name);
  assert.equal(full.login, FX.envelope.payload.login);
  assert.equal(full.version, 1);
  assert.equal('sealed' in full, false, 'envelope is replaced by the payload');
  assert.equal(await v.totp(FX.envelope.name), FX.envelope.payload.totp);
  // a GOST token bound to a freshly generated pair, sealed by the client-side sealer
  const g = new Vault({ baseUrl: base, token: 'vlt_test_token', clientPrivateKey: gostPair.privateKey, cacheTtlMs: 0 });
  assert.equal(await g.get('gost-db'), 'gost-pass');
  assert.equal((await g.getFull('gost-db')).version, 2);
  // wrong GOST key, an X25519 key, and no key at all are all refused
  await assert.rejects(g.get(FX.envelope.name), /does not open/);
  await assert.rejects(new Vault({ baseUrl: base, token: 'vlt_test_token', clientPrivateKey: clientPair.privateKey, cacheTtlMs: 0 }).get(FX.envelope.name), /does not open/);
  delete process.env.VAULT_CLIENT_KEY;
  await assert.rejects(new Vault({ baseUrl: base, token: 'vlt_test_token', cacheTtlMs: 0 }).get(FX.envelope.name), /sealed values/);
});

test.after(() => srv.close());
