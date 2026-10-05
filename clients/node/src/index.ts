/**
 * @aps-vault/client — Node 20.19+ client for the APS Vault machine API. Built-in fetch; node:crypto for everything
 * but ML-KEM, which comes from @noble/post-quantum.
 *
 *   import { Vault } from '@aps-vault/client';
 *   const v = new Vault({ baseUrl: 'https://vault.example.com', token: process.env.VAULT_TOKEN! });
 *   const dbPassword = await v.get('db-password');
 *
 * - values cached for cacheTtlMs (default 5 min); a stale cached value is returned while the
 *   vault is unreachable (failOpenCache) so a vault restart does not take the service down;
 * - retries 429/5xx/network errors with 1 s / 2 s / 4 s back-off;
 * - put() needs a token with can_write; totp() needs can_read_totp and is never cached;
 * - nothing is logged; VaultError carries status and the server's detail.
 * - sealed delivery (0.17): a token bound to this app's X25519 public key gets values encrypted
 *   to it; pass `clientPrivateKey` (base64 raw 32 bytes, or VAULT_CLIENT_KEY) and the client
 *   decrypts in-process with node:crypto. `generateKeyPair()` makes the pair.
 * - GOST envelope (0.19): a token bound to a GOST R 34.10-2012 public key (64 bytes X‖Y) gets a
 *   VKO → KDF_TREE → Kuznyechik-MGM envelope; `generateKeyPair({ gost: true })` makes that pair and
 *   `unseal()` dispatches on `alg`. Pure TypeScript (src/gost.ts), no dependencies.
 * - post-quantum hybrid envelope (0.27): a token bound to an X25519 + ML-KEM-768 (FIPS 203) public key
 *   (1216 bytes) gets a key agreed over BOTH shared secrets, HKDF-SHA256 → AES-256-GCM; the private key is
 *   96 bytes (X25519 sk ‖ ML-KEM seed). `generateKeyPair({ pqc: true })` makes the pair; ML-KEM comes from
 *   the one dependency, @noble/post-quantum. Needs a vault 0.27+.
 */
import { createPrivateKey, createPublicKey, diffieHellman, generateKeyPairSync, hkdfSync, createDecipheriv, createECDH, createHmac, randomBytes, KeyObject } from 'node:crypto';
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import { SEALED_ALG_GOST, generateGostKeyPair, unsealGost, type GostSealedEnvelope, SEALED_ALG_GOST_PQC, generateGostPqcKeyPair, unsealGostPqc, type GostPqcSealedEnvelope } from './gost.js';

export { SEALED_ALG_GOST, generateGostKeyPair, unsealGost, sealGost, type GostSealedEnvelope,
         SEALED_ALG_GOST_PQC, generateGostPqcKeyPair, gostPqcPublicFromPrivate, unsealGostPqc, sealGostPqc, type GostPqcSealedEnvelope } from './gost.js';

export interface VaultOptions {
  baseUrl: string;
  token: string;
  cacheTtlMs?: number;      // default 300_000; 0 disables
  timeoutMs?: number;       // default 5000
  maxRetries?: number;      // default 3
  failOpenCache?: boolean;  // default true
  clientPrivateKey?: string | KeyProvider; // base64 private key (X25519 / GOST / P-256 / PQC hybrid by the token's key, default VAULT_CLIENT_KEY) or a hardware KeyProvider (P-256)
}

/** `ukm` — GOST envelopes only; `kem` — ML-KEM-768 ciphertext of the two post-quantum hybrids (X25519+ML-KEM, GOST+ML-KEM). */
export interface SealedEnvelope { alg: string; v: number; epk: string; nonce: string; ct: string; ukm?: string; kem?: string; }

export const SEALED_ALG = 'X25519-HKDF-SHA256-AES256GCM';
const SEALED_INFO = Buffer.from('aps-vault/sealed/v1');
// DER prefixes that turn a raw 32-byte X25519 key into SPKI / PKCS#8 for node:crypto
const SPKI_PREFIX = Buffer.from('302a300506032b656e032100', 'hex');
const PKCS8_PREFIX = Buffer.from('302e020100300506032b656e04220420', 'hex');

const rawPublic = (k: KeyObject): Buffer => (k.export({ type: 'spki', format: 'der' }) as Buffer).subarray(SPKI_PREFIX.length);

const SEALED_OPEN_ERROR = 'vault: sealed value does not open with this private key (wrong key, or the token is bound to another key)';

/**
 * A key pair for sealed delivery: { privateKey, publicKey } in standard base64.
 * Default: X25519, raw 32 bytes each. `{ gost: true }`: GOST R 34.10-2012 (256-bit, paramSetB) —
 * private = 32-byte big-endian scalar, public = X‖Y little-endian 64 bytes.
 */
export const SEALED_ALG_P256 = 'P256-HKDF-SHA256-AES256GCM';
const SEALED_INFO_P256 = Buffer.from('aps-vault/sealed-p256/v1');
const SEALED_OPEN_ERR = 'vault: sealed value does not open with this private key (wrong key, or the token is bound to another key)';

/** A private key the client does not hold itself (0.22): a TPM / HSM / smart card behind PKCS#11, a cloud KMS, …
 *  The provider returns the public point (65 bytes, uncompressed) and performs one ECDH with the vault's ephemeral point. */
export interface KeyProvider { publicKey(): Buffer; ecdh(peerPoint: Buffer): Buffer | Promise<Buffer>; }

/** P-256 key pair in software — the curve a TPM 2.0 or any PKCS#11 token can hold for the hardware version. */
export function generateP256KeyPair(): { privateKey: string; publicKey: string } {
  const e = createECDH('prime256v1'); e.generateKeys();
  return { privateKey: e.getPrivateKey().toString('base64'), publicKey: e.getPublicKey(null, 'uncompressed').toString('base64') };
}

function p256Open(env: SealedEnvelope, our: Buffer, shared: Buffer, name: string): Record<string, string | null> {
  const epk = Buffer.from(env.epk, 'base64');
  const k = Buffer.from(hkdfSync('sha256', shared, Buffer.alloc(0), Buffer.concat([SEALED_INFO_P256, epk, our]), 32));
  const ct = Buffer.from(env.ct, 'base64');
  const d = createDecipheriv('aes-256-gcm', k, Buffer.from(env.nonce, 'base64'), { authTagLength: 16 });
  d.setAAD(Buffer.from(name, 'utf8')); d.setAuthTag(ct.subarray(ct.length - 16));
  try { return JSON.parse(Buffer.concat([d.update(ct.subarray(0, ct.length - 16)), d.final()]).toString('utf8')); }
  catch { throw new VaultError(0, SEALED_OPEN_ERR); }
}

/** Open a P-256 envelope with a software scalar (base64) or a KeyProvider (hardware). */
export async function unsealP256(env: SealedEnvelope, key: string | KeyProvider, name: string): Promise<Record<string, string | null>> {
  const epk = Buffer.from(env.epk, 'base64');
  let our: Buffer, shared: Buffer;
  try {
    if (typeof key === 'string') { const e = createECDH('prime256v1'); e.setPrivateKey(Buffer.from(key, 'base64')); our = e.getPublicKey(null, 'uncompressed'); shared = e.computeSecret(epk); }
    else { our = key.publicKey(); shared = Buffer.from(await key.ecdh(epk)); }
  } catch { throw new VaultError(0, SEALED_OPEN_ERR); }
  return p256Open(env, our, shared, name);
}

// ── post-quantum hybrid X25519 + ML-KEM-768 (0.27, FIPS 203) ─────────────────────────────────────
export const SEALED_ALG_PQC = 'X25519MLKEM768-HKDF-SHA256-AES256GCM';
const SEALED_INFO_PQC = Buffer.from('aps-vault/sealed-pqc/v1');
const PQC_SK_LEN = 96, MLKEM_SEED_LEN = 64;   // private = X25519 sk (32) ‖ ML-KEM seed d‖z (64); public = X25519 pk (32) ‖ ML-KEM ek (1184) = 1216
const PQC_KEY_ERR = 'vault: hybrid private key must be 96 bytes — X25519 sk (32) ‖ ML-KEM-768 seed (64), base64';

/** HKDF-SHA256 (RFC 5869), empty salt, L = 32 — one Expand block. node's hkdfSync caps `info` at 1024 bytes and the
 *  hybrid info is 23 + 32 + 1088 = 1143 bytes (label ‖ epk ‖ kem ciphertext), so it is spelled out with HMAC. */
function hkdfSha256Long(ikm: Buffer, info: Buffer): Buffer {
  const prk = createHmac('sha256', Buffer.alloc(32)).update(ikm).digest();                 // Extract, salt = 32 zero bytes
  return createHmac('sha256', prk).update(info).update(Buffer.from([1])).digest();       // Expand, T(1) = HMAC(PRK, info ‖ 0x01)
}

/** X25519 private half as a KeyObject + the 64-byte ML-KEM seed of a 96-byte hybrid private key (base64). */
function pqcSplit(privateKeyB64: string): { xsk: KeyObject; seed: Uint8Array } {
  const raw = Buffer.from(privateKeyB64, 'base64');
  if (raw.length !== PQC_SK_LEN) throw new VaultError(0, `${PQC_KEY_ERR}; got ${raw.length} bytes`);
  const xsk = createPrivateKey({ key: Buffer.concat([PKCS8_PREFIX, raw.subarray(0, 32)]), format: 'der', type: 'pkcs8' });
  return { xsk, seed: Uint8Array.from(raw.subarray(32)) };
}

/** Hybrid pair for the post-quantum envelope: random X25519 (node:crypto) + random 64-byte seed from which the
 *  ML-KEM-768 pair is derived (FIPS 203 KeyGen_internal), so any client re-derives the same public key from
 *  the private one — see `pqcPublicFromPrivate`. */
export function generatePqcKeyPair(): { privateKey: string; publicKey: string } {
  const { privateKey, publicKey } = generateKeyPairSync('x25519');
  const xsk = (privateKey.export({ type: 'pkcs8', format: 'der' }) as Buffer).subarray(PKCS8_PREFIX.length);
  const seed = randomBytes(MLKEM_SEED_LEN);
  const kem = ml_kem768.keygen(Uint8Array.from(seed));
  return { privateKey: Buffer.concat([xsk, seed]).toString('base64'),
           publicKey: Buffer.concat([rawPublic(publicKey), Buffer.from(kem.publicKey)]).toString('base64') };
}

/** The 1216-byte public key (base64) that belongs to a 96-byte hybrid private key — what the token is bound to. */
export function pqcPublicFromPrivate(privateKeyB64: string): string {
  const { xsk, seed } = pqcSplit(privateKeyB64);
  return Buffer.concat([rawPublic(createPublicKey(xsk)), Buffer.from(ml_kem768.keygen(seed).publicKey)]).toString('base64');
}

/** Open a hybrid envelope: ss_x = X25519(sk_x, epk); ss_kem = ML-KEM-768.Decaps(dk, kem);
 *  key = HKDF-SHA256(ss_x ‖ ss_kem, salt = ∅, info = label ‖ epk ‖ kem); AES-256-GCM with the name as AAD.
 *  Unlike the X25519 envelope the info does NOT include our own public key. A wrong key or any tampered field
 *  (ML-KEM rejects implicitly — a bad `kem` gives a different secret, not an exception) ends in the GCM tag check. */
export function unsealPqc(env: SealedEnvelope, privateKeyB64: string, name: string): Record<string, string | null> {
  const { xsk, seed } = pqcSplit(privateKeyB64);
  if (typeof env.kem !== 'string') throw new VaultError(0, 'vault: hybrid sealed envelope has no kem field');
  const epk = Buffer.from(env.epk, 'base64'), kemCt = Buffer.from(env.kem, 'base64');
  let ikm: Buffer;
  try {
    const ssX = diffieHellman({ privateKey: xsk, publicKey: createPublicKey({ key: Buffer.concat([SPKI_PREFIX, epk]), format: 'der', type: 'spki' }) });
    const ssKem = ml_kem768.decapsulate(Uint8Array.from(kemCt), ml_kem768.keygen(seed).secretKey);
    ikm = Buffer.concat([ssX, Buffer.from(ssKem)]);
  } catch { throw new VaultError(0, SEALED_OPEN_ERR); }
  const key = hkdfSha256Long(ikm, Buffer.concat([SEALED_INFO_PQC, epk, kemCt]));
  const ct = Buffer.from(env.ct, 'base64');
  try {
    const d = createDecipheriv('aes-256-gcm', key, Buffer.from(env.nonce, 'base64'), { authTagLength: 16 });
    d.setAAD(Buffer.from(name, 'utf8')); d.setAuthTag(ct.subarray(ct.length - 16));
    return JSON.parse(Buffer.concat([d.update(ct.subarray(0, ct.length - 16)), d.final()]).toString('utf8'));
  } catch { throw new VaultError(0, SEALED_OPEN_ERR); }
}

export function generateKeyPair(opts: { gost?: boolean; p256?: boolean; pqc?: boolean; gostPqc?: boolean } = {}): { privateKey: string; publicKey: string } {
  if (opts.gostPqc) return generateGostPqcKeyPair();
  if (opts.gost) return generateGostKeyPair();
  if (opts.p256) return generateP256KeyPair();
  if (opts.pqc) return generatePqcKeyPair();
  const { privateKey, publicKey } = generateKeyPairSync('x25519');
  const sk = (privateKey.export({ type: 'pkcs8', format: 'der' }) as Buffer).subarray(PKCS8_PREFIX.length);
  return { privateKey: sk.toString('base64'), publicKey: rawPublic(publicKey).toString('base64') };
}

/** Open a sealed envelope (GET /api/v1/m/secret/{name} for a key-bound token). */
export function unseal(env: SealedEnvelope, privateKeyB64: string, name: string): Record<string, string | null> {
  if (env?.alg === SEALED_ALG_PQC && env.v === 1) return unsealPqc(env, privateKeyB64, name);
  if (env?.alg === SEALED_ALG_GOST_PQC && env.v === 1) {
    if (typeof env.kem !== 'string') throw new VaultError(0, 'vault: GOST hybrid sealed envelope has no kem field');
    try {
      return unsealGostPqc(env as GostPqcSealedEnvelope, privateKeyB64, name);
    } catch (e) {
      if (e instanceof Error && /96 bytes/.test(e.message)) throw new VaultError(0, 'vault: ' + e.message);
      throw new VaultError(0, SEALED_OPEN_ERROR);
    }
  }
  if (env?.alg === SEALED_ALG_P256 && env.v === 1) {
    let our: Buffer, shared: Buffer;
    try { const e = createECDH('prime256v1'); e.setPrivateKey(Buffer.from(privateKeyB64, 'base64')); our = e.getPublicKey(null, 'uncompressed'); shared = e.computeSecret(Buffer.from(env.epk, 'base64')); }
    catch { throw new VaultError(0, SEALED_OPEN_ERR); }
    return p256Open(env, our, shared, name);
  }
  if (env?.alg === SEALED_ALG_GOST && env.v === 1) {
    try {
      return unsealGost(env as GostSealedEnvelope, privateKeyB64, name);
    } catch {
      throw new VaultError(0, SEALED_OPEN_ERROR);
    }
  }
  if (env?.alg !== SEALED_ALG || env.v !== 1) throw new VaultError(0, `vault: unsupported sealed envelope ${env?.alg} v${env?.v}`);
  const sk = createPrivateKey({ key: Buffer.concat([PKCS8_PREFIX, Buffer.from(privateKeyB64, 'base64')]), format: 'der', type: 'pkcs8' });
  const pk = rawPublic(createPublicKey(sk));
  const epk = Buffer.from(env.epk, 'base64');
  const shared = diffieHellman({ privateKey: sk, publicKey: createPublicKey({ key: Buffer.concat([SPKI_PREFIX, epk]), format: 'der', type: 'spki' }) });
  const key = Buffer.from(hkdfSync('sha256', shared, Buffer.alloc(0), Buffer.concat([SEALED_INFO, epk, pk]), 32));
  const ct = Buffer.from(env.ct, 'base64');
  const d = createDecipheriv('aes-256-gcm', key, Buffer.from(env.nonce, 'base64'), { authTagLength: 16 });
  d.setAAD(Buffer.from(name, 'utf8'));
  d.setAuthTag(ct.subarray(ct.length - 16));
  try {
    return JSON.parse(Buffer.concat([d.update(ct.subarray(0, ct.length - 16)), d.final()]).toString('utf8'));
  } catch {
    throw new VaultError(0, SEALED_OPEN_ERROR);
  }
}

export interface Secret {
  name: string;
  value: string;
  login?: string;
  notes?: string;
  totp?: string | null;
  updated_at: string;
}

export class VaultError extends Error {
  constructor(public status: number, message: string, public body?: unknown) {
    super(message);
    this.name = 'VaultError';
  }
}

const sleep = (ms: number) => new Promise(r => setTimeout(r, ms));

/** Node enrolment (0.21): make this machine's key pair, redeem the one-time code, receive a token sealed to the new key.
 *  Keep `token` and `privateKey` with mode 0600 (VAULT_TOKEN / VAULT_CLIENT_KEY); the token alone opens nothing. */
export async function enroll(baseUrl: string, code: string, opts: { name?: string; gost?: boolean; p256?: boolean; pqc?: boolean; gostPqc?: boolean; hardwareKey?: KeyProvider; timeoutMs?: number } = {}):
  Promise<{ token: string; privateKey: string; publicKey: string; tokenName: string; folderName: string; vaultUrl: string }> {
  // with a hardware KeyProvider the private key stays in the token and `privateKey` comes back empty;
  // `pqc` sends the 1216-byte hybrid public key (vault 0.27+); `gostPqc` the 1248-byte GOST hybrid key (vault 0.32+)
  const pair = opts.hardwareKey ? { privateKey: '', publicKey: opts.hardwareKey.publicKey().toString('base64') } : generateKeyPair({ gost: !!opts.gost, p256: !!opts.p256, pqc: !!opts.pqc, gostPqc: !!opts.gostPqc });
  const ctrl = new AbortController(); const timer = setTimeout(() => ctrl.abort(), opts.timeoutMs ?? 10_000);
  try {
    const res = await fetch(baseUrl.replace(/\/+$/, '') + '/api/enroll', { method: 'POST', signal: ctrl.signal,
      headers: { 'Content-Type': 'application/json', Accept: 'application/json', 'User-Agent': '@aps-vault/client/0.38.1' },
      body: JSON.stringify({ code, public_key: pair.publicKey, name: opts.name ?? (await import('node:os')).hostname().slice(0, 64) }) });
    const body: any = await res.json().catch(() => ({}));
    if (!res.ok) throw new VaultError(res.status, `vault enrol: HTTP ${res.status} ${body?.detail ?? res.statusText}`, body);
    return { token: body.raw_token, privateKey: pair.privateKey, publicKey: pair.publicKey, tokenName: body.token_name, folderName: body.folder_name, vaultUrl: body.vault_url || baseUrl };
  } finally { clearTimeout(timer); }
}

export class Vault {
  private readonly baseUrl: string;
  private readonly token: string;
  private readonly cacheTtlMs: number;
  private readonly timeoutMs: number;
  private readonly maxRetries: number;
  private readonly failOpen: boolean;
  private readonly clientKey?: string | KeyProvider;
  private readonly cache = new Map<string, { value: Secret; expiresAt: number }>();

  constructor(opts: VaultOptions) {
    if (!opts.baseUrl) throw new Error('vault: baseUrl required');
    if (!opts.token?.startsWith('vlt_')) throw new Error('vault: a service token (vlt_…) is required, not a master password');
    this.baseUrl = opts.baseUrl.replace(/\/+$/, '');
    this.token = opts.token;
    this.cacheTtlMs = opts.cacheTtlMs ?? 300_000;
    this.timeoutMs = opts.timeoutMs ?? 5000;
    this.maxRetries = opts.maxRetries ?? 3;
    this.failOpen = opts.failOpenCache ?? true;
    this.clientKey = opts.clientPrivateKey ?? process.env.VAULT_CLIENT_KEY ?? undefined;
  }

  /** VAULT_URL + VAULT_TOKEN from the environment. */
  static fromEnv(extra: Partial<VaultOptions> = {}): Vault {
    return new Vault({ baseUrl: process.env.VAULT_URL ?? '', token: process.env.VAULT_TOKEN ?? '', ...extra });
  }

  /** Current value, or an older one by number (`version`) — e.g. the previous encryption key during a rotation. */
  async get(name: string, version?: number): Promise<string> { return (await this.getFull(name, version)).value; }

  /** Version metadata without values: { current_version, versions: [{ version, current, changed_at }] }. */
  async versions(name: string): Promise<{ current_version: number; versions: { version: number; current: boolean; changed_at: string }[] }> {
    return this.req('GET', `/api/v1/m/secret/${encodeURIComponent(name)}/versions`);
  }

  async getFull(name: string, version?: number): Promise<Secret> {
    if (!name) throw new Error('vault: name required');
    const key = version ? `${name}@${version}` : name;
    const hit = this.cache.get(key);
    if (hit && hit.expiresAt > Date.now()) return hit.value;
    let value: Secret;
    try {
      const raw = await this.req<Secret & { sealed?: SealedEnvelope }>('GET', `/api/v1/m/secret/${encodeURIComponent(name)}${version ? `?version=${version}` : ''}`);
      if (raw.sealed) {
        if (!this.clientKey) throw new VaultError(0, 'vault: this token delivers sealed values — pass clientPrivateKey (or VAULT_CLIENT_KEY)');
        const { sealed, ...rest } = raw;
        // 0.37: the AAD is the requested name, never the response's own — a swapped envelope of another secret fails
        const opened = typeof this.clientKey === 'string' ? unseal(sealed, this.clientKey, name)
          : sealed.alg === SEALED_ALG_P256 ? await unsealP256(sealed, this.clientKey, name)
          : (() => { throw new VaultError(0, `vault: a hardware key opens only the P-256 envelope, the token sent ${sealed.alg}`); })();
        value = { ...rest, ...opened } as Secret;
      } else if (this.clientKey) {
        // 0.37: with a key configured a plaintext answer is refused — a tampering proxy could have dropped the envelope
        throw new VaultError(0, 'vault: a client key is configured but the response is not sealed — refusing (a proxy may have replaced it)');
      } else value = raw;
    } catch (e) {
      const transient = !(e instanceof VaultError) || e.status === 429 || e.status >= 500;
      if (hit && this.failOpen && transient) return hit.value;
      throw e;
    }
    if (this.cacheTtlMs > 0) this.cache.set(key, { value, expiresAt: Date.now() + this.cacheTtlMs });
    return value;
  }

  /** Create or update a secret in the token's folder (token must have can_write). */
  async put(name: string, value: string, meta: { login?: string; tags?: string; url?: string } = {}): Promise<{ id: number; created: boolean }> {
    const r = await this.req<{ id: number; name: string; created: boolean }>(
      'POST', `/api/v1/m/secret/${encodeURIComponent(name)}`,
      { value, login: meta.login ?? '', tags: meta.tags ?? '', url: meta.url ?? '' });
    this.cache.delete(name);
    return r;
  }

  /** Current TOTP code (token needs can_read_totp); null when the secret has no seed. */
  async totp(name: string): Promise<string | null> {
    this.cache.delete(name);
    const s = await this.getFull(name);
    this.cache.delete(name);           // codes change every 30 s — never serve from cache
    return s.totp ?? null;
  }

  async list(): Promise<Array<{ id: number; name: string; tags: string; url: string; updated_at: string }>> {
    return this.req('GET', '/api/v1/m/secrets');
  }

  async health(): Promise<Record<string, unknown>> { return this.req('GET', '/api/v1/m/health'); }

  clearCache(): void { this.cache.clear(); }

  private async req<T>(method: string, path: string, body?: unknown): Promise<T> {
    let lastErr: unknown;
    for (let attempt = 0; attempt <= this.maxRetries; attempt++) {
      const ctrl = new AbortController();
      const timer = setTimeout(() => ctrl.abort(), this.timeoutMs);
      try {
        const res = await fetch(this.baseUrl + path, {
          method, signal: ctrl.signal,
          headers: { Authorization: `Bearer ${this.token}`, Accept: 'application/json',
                     'Content-Type': 'application/json', 'User-Agent': '@aps-vault/client/0.38.1' },
          body: body === undefined ? undefined : JSON.stringify(body),
        });
        clearTimeout(timer);
        if (res.ok) return (await res.json()) as T;
        let parsed: any; try { parsed = await res.json(); } catch { /* not json */ }
        const err = new VaultError(res.status, `vault ${method} ${path}: HTTP ${res.status} ${parsed?.detail ?? res.statusText}`, parsed);
        if (!(res.status === 429 || res.status >= 500)) throw err;
        lastErr = err;
      } catch (e) {
        clearTimeout(timer);
        if (e instanceof VaultError && !(e.status === 429 || e.status >= 500)) throw e;
        lastErr = e;
      }
      if (attempt < this.maxRetries) await sleep(1000 * 2 ** attempt);
    }
    throw lastErr instanceof Error ? lastErr : new Error(`vault: request failed: ${lastErr}`);
  }
}

export default Vault;
