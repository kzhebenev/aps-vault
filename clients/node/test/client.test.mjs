// node --test clients/node/test   (after `npm run build`)
import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { Vault, VaultError } from '../dist/index.js';

let failing = false, hits = 0;
const srv = http.createServer((req, res) => {
  const json = (code, body) => { res.writeHead(code, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(body)); };
  if (req.headers.authorization !== 'Bearer vlt_test_token') return json(401, { detail: 'invalid token' });
  if (failing) return json(503, {});
  hits++;
  if (req.method === 'GET' && req.url === '/api/v1/m/secret/db-password') return json(200, { name: 'db-password', value: 's3cr3t', login: 'app', updated_at: 'x' });
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
  srv.close();
});
