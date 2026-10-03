// node --test clients/node/test   (after `npm run build`)
import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { Vault, VaultError, generateKeyPair, unseal, SEALED_ALG } from '../dist/index.js';
import { createPrivateKey, createPublicKey, diffieHellman, generateKeyPairSync, hkdfSync, createCipheriv } from 'node:crypto';

const SPKI = Buffer.from('302a300506032b656e032100', 'hex');
const clientPair = generateKeyPair();
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

test.after(() => srv.close());
