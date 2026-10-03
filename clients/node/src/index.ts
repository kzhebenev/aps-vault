/**
 * @aps-vault/client — Node 18+ client for the APS Vault machine API. Built-in fetch only.
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
 */
import { createPrivateKey, createPublicKey, diffieHellman, generateKeyPairSync, hkdfSync, createDecipheriv, KeyObject } from 'node:crypto';

export interface VaultOptions {
  baseUrl: string;
  token: string;
  cacheTtlMs?: number;      // default 300_000; 0 disables
  timeoutMs?: number;       // default 5000
  maxRetries?: number;      // default 3
  failOpenCache?: boolean;  // default true
  clientPrivateKey?: string; // base64 raw X25519 private key for sealed tokens (default: VAULT_CLIENT_KEY)
}

export interface SealedEnvelope { alg: string; v: number; epk: string; nonce: string; ct: string; }

export const SEALED_ALG = 'X25519-HKDF-SHA256-AES256GCM';
const SEALED_INFO = Buffer.from('aps-vault/sealed/v1');
// DER prefixes that turn a raw 32-byte X25519 key into SPKI / PKCS#8 for node:crypto
const SPKI_PREFIX = Buffer.from('302a300506032b656e032100', 'hex');
const PKCS8_PREFIX = Buffer.from('302e020100300506032b656e04220420', 'hex');

const rawPublic = (k: KeyObject): Buffer => (k.export({ type: 'spki', format: 'der' }) as Buffer).subarray(SPKI_PREFIX.length);

/** An X25519 key pair for sealed delivery: { privateKey, publicKey } as base64 raw 32 bytes. */
export function generateKeyPair(): { privateKey: string; publicKey: string } {
  const { privateKey, publicKey } = generateKeyPairSync('x25519');
  const sk = (privateKey.export({ type: 'pkcs8', format: 'der' }) as Buffer).subarray(PKCS8_PREFIX.length);
  return { privateKey: sk.toString('base64'), publicKey: rawPublic(publicKey).toString('base64') };
}

/** Open a sealed envelope (GET /api/v1/m/secret/{name} for a key-bound token). */
export function unseal(env: SealedEnvelope, privateKeyB64: string, name: string): Record<string, string | null> {
  if (env?.alg !== SEALED_ALG || env.v !== 1) throw new VaultError(0, `vault: unsupported sealed envelope ${env?.alg} v${env?.v}`);
  const sk = createPrivateKey({ key: Buffer.concat([PKCS8_PREFIX, Buffer.from(privateKeyB64, 'base64')]), format: 'der', type: 'pkcs8' });
  const pk = rawPublic(createPublicKey(sk));
  const epk = Buffer.from(env.epk, 'base64');
  const shared = diffieHellman({ privateKey: sk, publicKey: createPublicKey({ key: Buffer.concat([SPKI_PREFIX, epk]), format: 'der', type: 'spki' }) });
  const key = Buffer.from(hkdfSync('sha256', shared, Buffer.alloc(0), Buffer.concat([SEALED_INFO, epk, pk]), 32));
  const ct = Buffer.from(env.ct, 'base64');
  const d = createDecipheriv('aes-256-gcm', key, Buffer.from(env.nonce, 'base64'));
  d.setAAD(Buffer.from(name, 'utf8'));
  d.setAuthTag(ct.subarray(ct.length - 16));
  try {
    return JSON.parse(Buffer.concat([d.update(ct.subarray(0, ct.length - 16)), d.final()]).toString('utf8'));
  } catch {
    throw new VaultError(0, 'vault: sealed value does not open with this private key (wrong key, or the token is bound to another key)');
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

export class Vault {
  private readonly baseUrl: string;
  private readonly token: string;
  private readonly cacheTtlMs: number;
  private readonly timeoutMs: number;
  private readonly maxRetries: number;
  private readonly failOpen: boolean;
  private readonly clientKey?: string;
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
        value = { ...rest, ...unseal(sealed, this.clientKey, raw.name ?? name) } as Secret;
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
                     'Content-Type': 'application/json', 'User-Agent': '@aps-vault/client/0.17.0' },
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
