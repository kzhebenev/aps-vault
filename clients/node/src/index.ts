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
 */

export interface VaultOptions {
  baseUrl: string;
  token: string;
  cacheTtlMs?: number;      // default 300_000; 0 disables
  timeoutMs?: number;       // default 5000
  maxRetries?: number;      // default 3
  failOpenCache?: boolean;  // default true
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
      value = await this.req<Secret>('GET', `/api/v1/m/secret/${encodeURIComponent(name)}${version ? `?version=${version}` : ''}`);
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
    const s = await this.req<Secret>('GET', `/api/v1/m/secret/${encodeURIComponent(name)}`);
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
                     'Content-Type': 'application/json', 'User-Agent': '@aps-vault/client/0.8.0' },
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
