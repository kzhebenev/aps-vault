// APS Vault — web UI core (vanilla JS, no build step).
// Rules: no innerHTML with untrusted data — textContent/createElement only; icons are inline
// SVG paths; every user-visible Russian string goes through tr() (i18n.js) so the English UI
// stays complete (tools/i18n-transform.py --list shows the keys, ops/checks/ui-i18n.mjs checks).
//
// Layout: topbar → sidebar (scopes, folders, pages) → content = list pane + detail pane, or a
// full page (tokens, audit, settings…). Navigation is hash-routed (#/folder/3/s/12) so every
// screen is a URL and the browser back button works.

const PREFS = {
  get(k, d) { try { const v = localStorage.getItem('vault_' + k); return v === null ? d : JSON.parse(v); } catch { return d; } },
  set(k, v) { try { localStorage.setItem('vault_' + k, JSON.stringify(v)); } catch {} },
};

const state = {
  initialized: null, unlocked: false, health: null,
  folders: [], secrets: [],
  route: { view: 'all', id: null, secret: null },
  q: '', sort: PREFS.get('sort', 'name'),
  focus: -1,                 // keyboard focus in the list
  sidebarOpen: false,
  lastActivity: Date.now(),
  detail: null,              // currently open secret (full)
  totpTimer: null,
  prefs: {
    autolockMin: PREFS.get('autolock', 15),
    clipSec: PREFS.get('clip', 30),
    revealSec: PREFS.get('reveal', 30),
  },
};

// ── API ──────────────────────────────────────────────────────────────────────
function getCsrf() {
  const m = document.cookie.match(/(?:^|;)\s*vault_csrf=([^;]+)/);
  if (m) return decodeURIComponent(m[1]);
  try { return localStorage.getItem('vault_csrf') || ''; } catch { return ''; }
}
function setCsrf(t) { if (t) try { localStorage.setItem('vault_csrf', t); } catch {} }

const api = {
  async req(method, url, body, raw = false) {
    const opts = { method, credentials: 'include', headers: {} };
    if (body !== undefined) { opts.headers['Content-Type'] = 'application/json'; opts.body = JSON.stringify(body); }
    if (!['GET', 'HEAD', 'OPTIONS'].includes(method)) { const t = getCsrf(); if (t) opts.headers['X-CSRF-Token'] = t; }
    const r = await fetch(url, opts);
    const text = await r.text();
    if (raw) { if (!r.ok) throw Object.assign(new Error(`HTTP ${r.status}`), { status: r.status }); return text; }
    const data = text ? JSON.parse(text) : null;
    if (!r.ok) throw Object.assign(new Error(data?.detail || `HTTP ${r.status}`), { status: r.status });
    if (data?.csrf_token) setCsrf(data.csrf_token);
    return data;
  },
  health: () => api.req('GET', '/api/health'),
  init: (mp, init_token) => api.req('POST', '/api/init', { master_password: mp, init_token: init_token || '' }),
  unlock: (mp, totp_code) => api.req('POST', '/api/auth/unlock', totp_code ? { master_password: mp, totp_code } : { master_password: mp }),
  lock: () => api.req('POST', '/api/auth/lock'),
  lockAll: () => api.req('POST', '/api/auth/lock?all=1'),
  recover: (recovery_code, new_master_password) => api.req('POST', '/api/auth/recover', { recovery_code, new_master_password }),
  changePassword: (d) => api.req('POST', '/api/auth/change-password', d),
  twofaStatus: () => api.req('GET', '/api/auth/2fa/status'),
  twofaSetup: () => api.req('POST', '/api/auth/2fa/setup'),
  twofaVerify: (code, secret_base32) => api.req('POST', '/api/auth/2fa/verify', { code, secret_base32 }),
  twofaDisable: (totp_code) => api.req('POST', '/api/auth/2fa/disable', { totp_code }),
  ssoUnlockStatus: () => api.req('GET', '/api/auth/sso-unlock/status'),
  ssoUnlockEnable: (master_password) => api.req('POST', '/api/auth/sso-unlock/enable', { master_password }),
  ssoUnlockDisable: () => api.req('POST', '/api/auth/sso-unlock/disable'),
  listFolders: () => api.req('GET', '/api/folders'),
  createFolder: (name, description) => api.req('POST', '/api/folders', { name, description }),
  deleteFolder: (id) => api.req('DELETE', `/api/folders/${id}`),
  listSecrets: () => api.req('GET', '/api/secrets'),
  getSecret: (id) => api.req('GET', `/api/secrets/${id}`),
  totp: (id) => api.req('GET', `/api/secrets/${id}/totp`),
  createSecret: (d) => api.req('POST', '/api/secrets', d),
  updateSecret: (id, d) => api.req('PATCH', `/api/secrets/${id}`, d),
  rotateSecret: (id, generate) => api.req('POST', `/api/secrets/${id}/rotate`, { generate }),
  approvalsSettings: () => api.req('GET', '/api/approvals/settings'),
  approvalsList: () => api.req('GET', '/api/approvals'),
  setApprover: (master_password, approver_password) => api.req('POST', '/api/approvals/approver', { master_password, approver_password }),
  clearApprover: () => api.req('DELETE', '/api/approvals/approver'),
  requestApproval: (id, reason) => api.req('POST', `/api/secrets/${id}/approvals`, { reason }),
  approvalStatus: (aid) => api.req('GET', `/api/approvals/${aid}`),
  getSecretApproved: (id, aid) => api.req('GET', `/api/secrets/${id}?approval=${aid}`),
  webauthnStatus: () => api.req('GET', '/api/auth/webauthn/status'),
  webauthnList: () => api.req('GET', '/api/auth/webauthn/credentials'),
  webauthnRegisterOptions: (name) => api.req('POST', '/api/auth/webauthn/register/options', { name }),
  webauthnRegisterFinish: (d) => api.req('POST', '/api/auth/webauthn/register/finish', d),
  webauthnDelete: (id) => api.req('DELETE', `/api/auth/webauthn/credentials/${id}`),
  webauthnSecondFactor: (enabled) => api.req('POST', '/api/auth/webauthn/second-factor', { enabled }),
  webauthnOptions: (purpose) => api.req('POST', `/api/auth/webauthn/options?purpose=${purpose}`),
  webauthnUnlock: (credential, prf_output) => api.req('POST', '/api/auth/webauthn/unlock', { credential, prf_output }),
  hsmStatus: () => api.req('GET', '/api/auth/hsm/status'),
  hsmEnable: (master_password, pin) => api.req('POST', '/api/auth/hsm/enable', { master_password, pin }),
  hsmDisable: () => api.req('POST', '/api/auth/hsm/disable'),
  hsmUnlock: (pin) => api.req('POST', '/api/auth/hsm/unlock', pin == null ? {} : { pin }),
  deleteSecret: (id) => api.req('DELETE', `/api/secrets/${id}`),
  toggleFavorite: (id) => api.req('POST', `/api/secrets/${id}/favorite`),
  history: (id) => api.req('GET', `/api/secrets/${id}/history`),
  createShare: (d) => api.req('POST', '/api/share', d),
  createNoteShare: (d) => api.req('POST', '/api/share/note', d),
  revokeNoteShare: (id) => api.req('DELETE', `/api/shares/note/${id}`),
  listShares: () => api.req('GET', '/api/shares'),
  revokeShare: (id) => api.req('DELETE', `/api/shares/${id}`),
  stats: () => api.req('GET', '/api/stats'),
  exportJson: () => api.req('GET', '/api/export'),
  importJson: (d) => api.req('POST', '/api/import', d),
  listWebhooks: () => api.req('GET', '/api/webhooks'),
  createWebhook: (d) => api.req('POST', '/api/webhooks', d),
  deleteWebhook: (id) => api.req('DELETE', `/api/webhooks/${id}`),
  listTokens: () => api.req('GET', '/api/tokens'),
  createToken: (d) => api.req('POST', '/api/tokens', d),
  revokeToken: (id) => api.req('DELETE', `/api/tokens/${id}`),
  audit: (lim) => api.req('GET', `/api/audit?limit=${lim || 200}`),
  hibp: (prefix) => api.req('GET', `/api/tools/hibp/${prefix}`, undefined, true),
};

// ── DOM helpers ──────────────────────────────────────────────────────────────
function el(tag, props, ...children) {
  const e = document.createElement(tag);
  if (props) for (const [k, v] of Object.entries(props)) {
    if (v === undefined || v === null || v === false) continue;
    if (k === 'class') e.className = v;
    else if (k === 'style' && typeof v === 'object') Object.assign(e.style, v);
    else if (k.startsWith('on') && typeof v === 'function') e.addEventListener(k.slice(2).toLowerCase(), v);
    else if (k === 'dataset') Object.assign(e.dataset, v);
    else if (k === 'text') e.textContent = v;
    else if (k in e && k !== 'list') { try { e[k] = v; } catch { e.setAttribute(k, v); } }
    else e.setAttribute(k, v);
  }
  for (const c of children.flat(Infinity)) {
    if (c == null || c === false) continue;
    e.appendChild(typeof c === 'string' || typeof c === 'number' ? document.createTextNode(String(c)) : c);
  }
  return e;
}
function clear(n) { while (n.firstChild) n.removeChild(n.firstChild); return n; }
function frag(...nodes) { const f = document.createDocumentFragment(); for (const n of nodes.flat(Infinity)) if (n) f.appendChild(n); return f; }

const ICONS = {
  lock: 'M19 11H5a2 2 0 0 0-2 2v7a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7a2 2 0 0 0-2-2zM7 11V7a5 5 0 0 1 10 0v4',
  unlock: 'M19 11H5a2 2 0 0 0-2 2v7a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7a2 2 0 0 0-2-2zM7 11V7a5 5 0 0 1 9.9-1',
  key: 'M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4',
  eye: 'M2 12s3-7 10-7 10 7 10 7-3 7-10 7-10-7-10-7zM12 9a3 3 0 1 0 0 6 3 3 0 0 0 0-6z',
  eye_off: 'M9.88 9.88a3 3 0 0 0 4.24 4.24M10.73 5.08A10.43 10.43 0 0 1 12 5c7 0 10 7 10 7a13.16 13.16 0 0 1-1.67 2.68M6.61 6.61A13.526 13.526 0 0 0 2 12s3 7 10 7a9.74 9.74 0 0 0 5.39-1.61M2 2l20 20',
  copy: 'M9 9h10a2 2 0 0 1 2 2v10a2 2 0 0 1-2 2H9a2 2 0 0 1-2-2V11a2 2 0 0 1 2-2zM5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1',
  plus: 'M5 12h14M12 5v14', x: 'M18 6L6 18M6 6l12 12', check: 'M20 6L9 17l-5-5',
  folder: 'M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z',
  folder_open: 'M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2zM2 11h20',
  folder_in: 'M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2zM12 11v6M9 14l3 3 3-3',
  search: 'M11 19a8 8 0 1 0 0-16 8 8 0 0 0 0 16zM21 21l-4.35-4.35',
  log: 'M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8zM14 2v6h6M16 13H8M16 17H8M10 9H8',
  pencil: 'M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4z',
  trash: 'M3 6h18M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2M10 11v6M14 11v6',
  shield: 'M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z',
  shield_check: 'M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10zM9 12l2 2 4-4',
  inbox: 'M22 12h-6l-2 3h-4l-2-3H2M5.45 5.11L2 12v6a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-6l-3.45-6.89A2 2 0 0 0 16.76 4H7.24a2 2 0 0 0-1.79 1.11z',
  note: 'M4 4h16v16H4zM8 8h8M8 12h8M8 16h5',
  clock: 'M12 22a10 10 0 1 0 0-20 10 10 0 0 0 0 20zM12 6v6l4 2',
  info: 'M12 22a10 10 0 1 0 0-20 10 10 0 0 0 0 20zM12 16v-4M12 8h.01',
  alert: 'M12 9v4M12 17h.01M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z',
  chevron_right: 'M9 18l6-6-6-6', chevron_down: 'M6 9l6 6 6-6', arrow_left: 'M19 12H5M12 19l-7-7 7-7',
  file: 'M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8zM14 2v6h6',
  star: 'M12 2l3.09 6.26L22 9.27l-5 4.87 1.18 6.88L12 17.77l-6.18 3.25L7 14.14 2 9.27l6.91-1.01z',
  share: 'M18 8a3 3 0 1 0 0-6 3 3 0 0 0 0 6zM6 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6zM18 22a3 3 0 1 0 0-6 3 3 0 0 0 0 6zM8.59 13.51l6.83 3.98M15.41 6.51l-6.82 3.98',
  download: 'M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4M7 10l5 5 5-5M12 15V3',
  upload: 'M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4M17 8l-5-5-5 5M12 3v12',
  refresh: 'M23 4v6h-6M1 20v-6h6M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15',
  sun: 'M12 17a5 5 0 1 0 0-10 5 5 0 0 0 0 10zM12 1v2M12 21v2M4.22 4.22l1.42 1.42M18.36 18.36l1.42 1.42M1 12h2M21 12h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42',
  moon: 'M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z',
  monitor: 'M20 3H4a2 2 0 0 0-2 2v10a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2V5a2 2 0 0 0-2-2zM8 21h8M12 17v4',
  settings: 'M12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6zM19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.6 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.6a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z',
  menu: 'M3 12h18M3 6h18M3 18h18', more: 'M12 13a1 1 0 1 0 0-2 1 1 0 0 0 0 2zM19 13a1 1 0 1 0 0-2 1 1 0 0 0 0 2zM5 13a1 1 0 1 0 0-2 1 1 0 0 0 0 2z',
  link: 'M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71',
  external: 'M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6M15 3h6v6M10 14L21 3',
  zap: 'M13 2L3 14h9l-1 8 10-12h-9l1-8z',
  activity: 'M22 12h-4l-3 9L9 3l-3 9H2',
  calendar: 'M19 4H5a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2V6a2 2 0 0 0-2-2zM16 2v4M8 2v4M3 10h18',
  help: 'M12 22a10 10 0 1 0 0-20 10 10 0 0 0 0 20zM9.09 9a3 3 0 0 1 5.83 1c0 2-3 3-3 3M12 17h.01',
  globe: 'M12 22a10 10 0 1 0 0-20 10 10 0 0 0 0 20zM2 12h20M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z',
  user: 'M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2M12 11a4 4 0 1 0 0-8 4 4 0 0 0 0 8z',
  tag: 'M20.59 13.41l-7.17 7.17a2 2 0 0 1-2.83 0L2 12V2h10l8.59 8.59a2 2 0 0 1 0 2.82zM7 7h.01',
  dice: 'M19 3H5a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2V5a2 2 0 0 0-2-2zM8 8h.01M16 8h.01M12 12h.01M8 16h.01M16 16h.01',
  server: 'M20 2H4a2 2 0 0 0-2 2v4a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2V4a2 2 0 0 0-2-2zM20 14H4a2 2 0 0 0-2 2v4a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-4a2 2 0 0 0-2-2zM6 6h.01M6 18h.01',
  heart: 'M20.84 4.61a5.5 5.5 0 0 0-7.78 0L12 5.67l-1.06-1.06a5.5 5.5 0 0 0-7.78 7.78l1.06 1.06L12 21.23l7.78-7.78 1.06-1.06a5.5 5.5 0 0 0 0-7.78z',
  filter: 'M22 3H2l8 9.46V19l4 2v-8.54L22 3z',
};
function icon(name, size = 16) {
  const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
  svg.setAttribute('width', size); svg.setAttribute('height', size); svg.setAttribute('viewBox', '0 0 24 24');
  svg.setAttribute('fill', 'none'); svg.setAttribute('stroke', 'currentColor'); svg.setAttribute('stroke-width', '1.75');
  svg.setAttribute('stroke-linecap', 'round'); svg.setAttribute('stroke-linejoin', 'round'); svg.classList.add('icon');
  for (const d of (ICONS[name] || ICONS.info).split('M').slice(1)) {
    const p = document.createElementNS('http://www.w3.org/2000/svg', 'path'); p.setAttribute('d', 'M' + d); svg.appendChild(p);
  }
  return svg;
}

// ── small utilities ─────────────────────────────────────────────────────────
function toast(msg, type = 'info', ms = 3500) {
  const t = el('div', { class: `toast ${type}`, role: 'status' }, icon(type === 'error' ? 'alert' : type === 'ok' ? 'check' : 'info', 14), el('span', null, msg));
  document.getElementById('toasts').appendChild(t);
  setTimeout(() => t.remove(), ms);
}
function copyFallback(text) {
  // plain-http origins (a vault on a LAN address) have no navigator.clipboard — execCommand still works
  const ta = el('textarea', { value: text, style: { position: 'fixed', top: '-1000px', opacity: '0' }, readOnly: true });
  document.body.appendChild(ta); ta.select(); let ok = false;
  try { ok = document.execCommand('copy'); } catch {} ta.remove(); return ok;
}
async function copyText(text, label = tr('Значение')) {
  try {
    let viaApi = true;
    try { await navigator.clipboard.writeText(text); } catch { viaApi = false; if (!copyFallback(text)) throw new Error('copy'); }
    const sec = viaApi ? state.prefs.clipSec : 0;   // the fallback cannot read the clipboard back to clear it
    toast(sec ? tr`${label}: в буфере, очистится через ${sec} с` : tr`${label}: в буфере`, 'ok', 2500);
    if (sec) setTimeout(async () => {
      try { if ((await navigator.clipboard.readText()) === text) { await navigator.clipboard.writeText(''); toast(tr('Буфер обмена очищен'), 'info', 2000); } } catch {}
    }, sec * 1000);
  } catch { toast(tr('Не удалось скопировать'), 'error'); }
}
function timeAgo(iso) {
  if (!iso) return '';
  const sec = (Date.now() - new Date(iso).getTime()) / 1000;
  if (sec < 60) return tr('только что');
  if (sec < 3600) return tr`${Math.floor(sec / 60)} мин назад`;
  if (sec < 86400) return tr`${Math.floor(sec / 3600)} ч назад`;
  if (sec < 86400 * 30) return tr`${Math.floor(sec / 86400)} дн назад`;
  return new Date(iso).toLocaleDateString(I18N.locale);
}
function fmtDate(iso, withTime = true) {
  if (!iso) return '';
  const d = new Date(iso.endsWith('Z') || iso.includes('+') ? iso : iso + 'Z');
  return withTime ? d.toLocaleString(I18N.locale, { dateStyle: 'medium', timeStyle: 'short' }) : d.toLocaleDateString(I18N.locale, { dateStyle: 'medium' });
}
function daysUntil(iso) { return iso ? Math.ceil((new Date(iso.endsWith('Z') ? iso : iso + 'Z').getTime() - Date.now()) / 86400000) : null; }
function expiryState(s) {
  if (!s.expires_at) return null;
  const d = daysUntil(s.expires_at);
  if (d < 0) return { cls: 'danger', text: tr`просрочен ${-d} дн`, days: d };
  if (d <= 30) return { cls: 'warn', text: d === 0 ? tr('истекает сегодня') : tr`истекает через ${d} дн`, days: d };
  return { cls: '', text: tr`до ${fmtDate(s.expires_at, false)}`, days: d };
}
function debounce(fn, ms) { let t; return (...a) => { clearTimeout(t); t = setTimeout(() => fn(...a), ms); }; }
function hashHue(str) { let h = 0; for (const c of str) h = (h * 31 + c.charCodeAt(0)) >>> 0; return h % 360; }
function avatar(name, size = 34) {
  const hue = hashHue(name || '?');
  return el('span', { class: 'avatar', style: { background: `linear-gradient(135deg, hsl(${hue} 60% 48%), hsl(${(hue + 40) % 360} 60% 38%))`, width: size + 'px', height: size + 'px' } },
    (name || '?').trim().slice(0, 2).toUpperCase());
}
function tags(s) { return (s.tags || '').split(',').map(t => t.trim()).filter(Boolean); }
function hostOf(url) { try { return new URL(url).hostname; } catch { return url; } }
function kbd(k) { return el('span', { class: 'kbd' }, k); }
function confirmDialog(title, text, { danger = false, ok = tr('Удалить') } = {}) {
  return new Promise(resolve => {
    const m = modal({ narrow: true },
      el('h2', null, danger ? icon('alert', 18) : icon('help', 18), title),
      el('p', { class: 'muted', style: { margin: 0 } }, text),
      el('div', { class: 'foot' },
        el('button', { class: 'btn', onclick: () => { m.remove(); resolve(false); } }, tr('Отмена')),
        el('button', { class: `btn ${danger ? 'danger' : 'primary'}`, onclick: () => { m.remove(); resolve(true); }, autofocus: true }, ok)));
  });
}

// ── overlays ────────────────────────────────────────────────────────────────
function modal(opts, ...nodes) {
  if (opts && opts.nodeType) { nodes.unshift(opts); opts = {}; }
  const { narrow = false, wide = false, top = false, onClose } = opts || {};
  const overlay = el('div', { class: `overlay ${top ? 'top' : ''}`, onclick: (e) => { if (e.target === overlay) { overlay.remove(); onClose?.(); } } });
  const box = el('div', { class: `modal ${narrow ? 'narrow' : ''} ${wide ? 'wide' : ''}`, role: 'dialog', 'aria-modal': 'true' }, ...nodes);
  overlay.appendChild(box); document.body.appendChild(overlay);
  overlay.close = () => { overlay.remove(); onClose?.(); };
  const f = box.querySelector('[autofocus], input, textarea, button'); if (f) f.focus();   // synchronously: a delayed focus steals keystrokes already going into another field
  return overlay;
}
function drawer(title, body, foot, { onClose } = {}) {
  const overlay = el('div', { class: 'overlay', style: { background: 'transparent' }, onclick: (e) => { if (e.target === overlay) close(); } });
  const d = el('div', { class: 'drawer', role: 'dialog', 'aria-modal': 'true' },
    el('div', { class: 'head' }, el('h2', null, title), el('button', { class: 'btn ghost icon', onclick: () => close(), title: tr('Закрыть') }, icon('x', 18))),
    el('div', { class: 'bodyx' }, ...body),
    foot ? el('div', { class: 'foot' }, ...foot) : null);
  overlay.appendChild(d); document.body.appendChild(overlay);
  function close() { overlay.remove(); onClose?.(); }
  overlay.close = close;
  const f = d.querySelector('input, textarea'); if (f) f.focus();
  return overlay;
}
function topOverlay() { const all = document.querySelectorAll('.overlay'); return all[all.length - 1] || null; }

// ── theme & language ────────────────────────────────────────────────────────
const THEMES = ['auto', 'dark', 'light'];
function getTheme() { try { return localStorage.getItem('vault_theme') || 'auto'; } catch { return 'auto'; } }
function applyTheme(t) {
  try { if (t === 'auto') localStorage.removeItem('vault_theme'); else localStorage.setItem('vault_theme', t); } catch {}
  if (t === 'auto') delete document.documentElement.dataset.theme; else document.documentElement.dataset.theme = t;
}
function cycleTheme() { const t = THEMES[(THEMES.indexOf(getTheme()) + 1) % THEMES.length]; applyTheme(t); renderTopbarTheme(); toast({ auto: tr('Тема: как в системе'), dark: tr('Тема: тёмная'), light: tr('Тема: светлая') }[t], 'info', 1500); }
function themeIcon() { return icon({ auto: 'monitor', dark: 'moon', light: 'sun' }[getTheme()], 16); }
function renderTopbarTheme() { const b = document.getElementById('theme-btn'); if (b) { clear(b); b.appendChild(themeIcon()); } }

// ── routing ─────────────────────────────────────────────────────────────────
function parseHash() {
  const h = (location.hash || '#/all').replace(/^#\/?/, '');
  const seg = h.split('/').filter(Boolean);
  const r = { view: seg[0] || 'all', id: null, secret: null };
  const pages = ['tokens', 'shares', 'webhooks', 'audit', 'health', 'settings'];
  if (pages.includes(r.view)) return r;
  if (r.view === 'folder' || r.view === 'tag') { r.id = r.view === 'folder' ? parseInt(seg[1]) : decodeURIComponent(seg[1] || ''); if (seg[2] === 's') r.secret = parseInt(seg[3]); }
  else if (r.view === 'secret') { r.view = 'all'; r.secret = parseInt(seg[1]); }
  else { if (!['all', 'fav', 'expiring'].includes(r.view)) r.view = 'all'; if (seg[1] === 's') r.secret = parseInt(seg[2]); }
  return r;
}
function routeHash(view, id, secret) {
  let h = '#/' + view;
  if (view === 'folder' || view === 'tag') h += '/' + (view === 'tag' ? encodeURIComponent(id) : id);
  if (secret) h += '/s/' + secret;
  return h;
}
function go(view, id = null, secret = null) { location.hash = routeHash(view, id, secret); }
function goSecret(id) { const r = state.route; go(r.view === 'folder' || r.view === 'tag' ? r.view : (['fav', 'expiring'].includes(r.view) ? r.view : 'all'), r.id, id); }
function isPage(view) { return ['tokens', 'shares', 'webhooks', 'audit', 'health', 'settings'].includes(view); }

// ── data ────────────────────────────────────────────────────────────────────
async function refreshData() {
  try {
    [state.folders, state.secrets] = await Promise.all([api.listFolders(), api.listSecrets()]);
  } catch (e) {
    if (e.status === 401) { state.unlocked = false; renderUnlock(); throw e; }
    toast(e.message, 'error'); throw e;
  }
}
function scopedSecrets() {
  const r = state.route; let list = state.secrets;
  if (r.view === 'folder') list = list.filter(s => s.folder_id === r.id);
  else if (r.view === 'tag') list = list.filter(s => tags(s).includes(r.id));
  else if (r.view === 'fav') list = list.filter(s => s.is_favorite);
  else if (r.view === 'expiring') list = list.filter(s => s.expires_at && daysUntil(s.expires_at) <= 30);
  if (state.q) {
    const q = state.q.toLowerCase();
    list = list.filter(s => `${s.name} ${s.tags} ${s.url} ${s.folder_name}`.toLowerCase().includes(q));
  }
  const by = state.sort;
  return [...list].sort((a, b) => {
    if (by === 'updated') return (b.updated_at || '').localeCompare(a.updated_at || '');
    if (by === 'accessed') return (b.last_accessed || '').localeCompare(a.last_accessed || '');
    return a.name.localeCompare(b.name, I18N.locale);
  });
}
function scopeTitle() {
  const r = state.route;
  if (r.view === 'folder') return state.folders.find(f => f.id === r.id)?.name || tr('Папка');
  if (r.view === 'tag') return '#' + r.id;
  if (r.view === 'fav') return tr('Избранное');
  if (r.view === 'expiring') return tr('Истекают');
  return tr('Все секреты');
}

// ── auth screens ────────────────────────────────────────────────────────────
function brandBlock(sub) {
  return el('div', { class: 'brand' }, el('span', { class: 'logo' }, icon('shield', 26)), el('h1', null, 'APS Vault'), sub ? el('p', { class: 'lead' }, sub) : null);
}
function renderInit() {
  const app = clear(document.getElementById('app'));
  const mp1 = el('input', { type: 'password', class: 'input mono', placeholder: tr('минимум 12 символов'), autocomplete: 'new-password' });
  const mp2 = el('input', { type: 'password', class: 'input mono', placeholder: tr('повтор'), autocomplete: 'new-password' });
  const initTok = el('input', { type: 'password', class: 'input mono', placeholder: tr('init token (VAULT_INIT_TOKEN из .env)'), autocomplete: 'off' });
  const meter = strengthMeter(mp1);
  const submit = async () => {
    if (mp1.value.length < 12) return toast(tr('master-password короче 12 символов'), 'error');
    if (mp1.value !== mp2.value) return toast(tr('пароли не совпадают'), 'error');
    try { const r = await api.init(mp1.value, initTok.value); showRecoveryCode(r.recovery_code, () => location.reload()); }
    catch (e) { toast(e.message, 'error'); }
  };
  [mp1, mp2, initTok].forEach(i => i.addEventListener('keydown', e => { if (e.key === 'Enter') submit(); }));
  app.appendChild(el('div', { class: 'auth' }, el('div', { class: 'card' },
    brandBlock(tr('Первый запуск — задай master-password')),
    el('div', { class: 'field' }, el('label', null, 'Master password'), mp1, meter),
    el('div', { class: 'field' }, el('label', null, tr('Подтверждение')), mp2),
    el('div', { class: 'field' }, el('label', null, 'Init token'), initTok),
    el('div', { class: 'callout warn' }, icon('alert', 16), el('div', null, tr('Master-password нельзя восстановить. При утере поможет только recovery-code, который покажется один раз после инициализации.'))),
    el('button', { class: 'btn primary wide', onclick: submit }, tr('Инициализировать')))));
  mp1.focus();
}
function showRecoveryCode(code, onClose, title) {
  const m = modal({ narrow: true },
    el('h2', null, icon('key', 18), title || 'Recovery code'),
    el('p', { class: 'muted', style: { margin: 0 } }, tr('Запиши код в надёжное место. Показывается ОДИН РАЗ. Без него и без master-password восстановления нет.')),
    el('div', { class: 'codebox' }, code),
    el('div', { class: 'foot' },
      el('button', { class: 'btn', onclick: () => copyText(code, 'Recovery code') }, icon('copy', 14), tr('Копировать')),
      el('button', { class: 'btn primary', onclick: () => { m.remove(); onClose?.(); } }, tr('Я записал, продолжить'))));
}
function renderUnlock() {
  const app = clear(document.getElementById('app'));
  if (state.totpTimer) { clearInterval(state.totpTimer); state.totpTimer = null; }
  const mp = el('input', { type: 'password', class: 'input mono', placeholder: 'master password', autocomplete: 'current-password' });
  const code = el('input', { type: 'text', class: 'input mono hidden', placeholder: tr('код из приложения 2FA'), inputmode: 'numeric', autocomplete: 'one-time-code', maxlength: 8 });
  const btn = el('button', { class: 'btn primary wide', onclick: submit }, icon('unlock', 16), tr('Войти'));
  async function submit(assertion) {
    btn.disabled = true;
    try {
      await api.req('POST', '/api/auth/unlock', { master_password: mp.value, totp_code: code.classList.contains('hidden') ? undefined : code.value.trim(), webauthn: assertion });
      state.unlocked = true; await enterApp();
    } catch (e) {
      if (/security key required/i.test(e.message) && !assertion) {
        toast(tr('Коснись ключа безопасности или подтверди биометрией'), 'info', 6000);
        try { const o = await api.webauthnOptions('second_factor'); const a = await webauthnGet(o); return submit(a.credential); } catch (er) { toast(tr`Ключ не подтверждён: ${er.message}`, 'error'); }
      }
      else if (/2FA|totp/i.test(e.message) && code.classList.contains('hidden')) { code.classList.remove('hidden'); code.focus(); toast(tr('Включена 2FA: введи код из приложения'), 'info'); }
      else toast(e.message, 'error');
    } finally { btn.disabled = false; }
  }
  // touch-to-unlock with a security key / Touch ID (PRF) — shown when such a key is registered
  const keyBox = el('div', { class: 'stack hidden' });
  api.webauthnStatus().then(st => {
    if (!st.prf_unlock || !window.PublicKeyCredential) return;
    keyBox.classList.remove('hidden');
    keyBox.append(el('div', { class: 'row', style: { gap: '10px' } }, el('div', { class: 'divider', style: { flex: 1 } }), el('span', { class: 'xs faint' }, tr('или')), el('div', { class: 'divider', style: { flex: 1 } })),
      el('button', { class: 'btn wide', 'data-testid': 'webauthn-unlock', onclick: async (e) => {
        e.currentTarget.disabled = true;
        try { const o = await api.webauthnOptions('unlock'); const a = await webauthnGet(o); if (!a.prf_output) throw new Error(tr('ключ не вернул PRF — войди паролем')); await api.webauthnUnlock(a.credential, a.prf_output); state.unlocked = true; await enterApp(); }
        catch (er) { toast(er.message, 'error', 6000); e.currentTarget.disabled = false; }
      } }, icon('key', 15), tr('Войти ключом безопасности / Touch ID')));
  }).catch(() => {});
  [mp, code].forEach(i => i.addEventListener('keydown', e => { if (e.key === 'Enter') submit(); }));
  const sso = el('div', { class: 'stack hidden' });
  fetch('/api/auth/oidc/status', { credentials: 'same-origin' }).then(r => r.ok ? r.json() : { enabled: false }).then(d => {
    if (!d?.enabled) return;
    sso.classList.remove('hidden');
    sso.appendChild(el('div', { class: 'row', style: { gap: '10px' } }, el('div', { class: 'divider', style: { flex: 1 } }), el('span', { class: 'xs faint' }, tr('или')), el('div', { class: 'divider', style: { flex: 1 } })));
    sso.appendChild(el('a', { href: '/api/auth/oidc/login', class: 'btn wide' }, icon('user', 15), tr('Войти через SSO')));
  }).catch(() => {});
  // PKCS#11 token: unlock with the token's PIN when the cell is enabled
  const hsmBox = el('div', { class: 'stack hidden' });
  api.hsmStatus().then(st => {
    if (!st.enabled) return;
    hsmBox.classList.remove('hidden');
    const pin = el('input', { type: 'password', class: 'input mono', placeholder: tr('PIN токена'), autocomplete: 'off', inputmode: 'numeric', 'data-testid': 'hsm-pin' });
    const go_ = async () => { try { await api.hsmUnlock(pin.value); state.unlocked = true; await enterApp(); } catch (er) { toast(er.message, 'error', 6000); } };
    pin.addEventListener('keydown', e => { if (e.key === 'Enter') go_(); });
    hsmBox.append(el('div', { class: 'row', style: { gap: '10px' } }, el('div', { class: 'divider', style: { flex: 1 } }), el('span', { class: 'xs faint' }, tr('или')), el('div', { class: 'divider', style: { flex: 1 } })),
      el('div', { class: 'row' }, pin, el('button', { class: 'btn', 'data-testid': 'hsm-unlock', onclick: go_, title: st.token ? `${st.token.manufacturer} ${st.token.model}` : '' }, icon('server', 15), tr('Войти PIN-кодом токена'))));
  }).catch(() => {});
  const recoverLink = el('button', { class: 'btn ghost sm', onclick: showRecoverDialog }, tr('Забыл master-password?'));
  app.appendChild(el('div', { class: 'auth' }, el('div', { class: 'card' },
    brandBlock(tr('Введи master-password')), mp, code, btn, keyBox, hsmBox, sso, el('div', { class: 'row', style: { justifyContent: 'center' } }, recoverLink))));
  mp.focus();
}
function showRecoverDialog() {
  const rc = el('input', { class: 'input mono', placeholder: 'XXXXXXXXXXXXXXXXXXXXXXXX', autocomplete: 'off' });
  const np = el('input', { type: 'password', class: 'input mono', placeholder: tr('новый master-password (≥12)') });
  const meter = strengthMeter(np);
  const m = modal({ narrow: true },
    el('h2', null, icon('key', 18), tr('Восстановление по recovery-коду')),
    el('p', { class: 'muted small', style: { margin: 0 } }, tr('Данные сохраняются: ключи папок перешифровываются под новый пароль. Все сессии будут закрыты, выдастся новый recovery-код.')),
    el('div', { class: 'field' }, el('label', null, 'Recovery code'), rc),
    el('div', { class: 'field' }, el('label', null, tr('Новый master-password')), np, meter),
    el('div', { class: 'foot' },
      el('button', { class: 'btn', onclick: () => m.remove() }, tr('Отмена')),
      el('button', { class: 'btn primary', onclick: async () => {
        try { const r = await api.recover(rc.value.trim(), np.value); m.remove(); showRecoveryCode(r.new_recovery_code, () => location.reload(), tr('Новый recovery code')); }
        catch (e) { toast(e.message, 'error'); }
      } }, tr('Сменить пароль'))));
}

// ── WebAuthn in the browser: JSON ⇄ ArrayBuffer, create / get with the PRF extension ───────
const b64u = { enc: (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''),
               dec: (s) => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - s.length % 4) % 4)), c => c.charCodeAt(0)) };
function webauthnPrepare(o) {
  const pk = { ...o, challenge: b64u.dec(o.challenge) };
  if (o.user) pk.user = { ...o.user, id: b64u.dec(o.user.id) };
  for (const k of ['excludeCredentials', 'allowCredentials']) if (o[k]) pk[k] = o[k].map(c => ({ ...c, id: b64u.dec(c.id) }));
  if (o.extensions?.prf?.eval?.first) pk.extensions = { ...o.extensions, prf: { eval: { first: b64u.dec(o.extensions.prf.eval.first) } } };
  return pk;
}
function webauthnSerialize(cred) {
  const r = cred.response, ext = cred.getClientExtensionResults ? cred.getClientExtensionResults() : {};
  const out = { id: cred.id, rawId: b64u.enc(cred.rawId), type: cred.type, clientExtensionResults: {},
    response: { clientDataJSON: b64u.enc(r.clientDataJSON) } };
  if (r.attestationObject) { out.response.attestationObject = b64u.enc(r.attestationObject); out.response.transports = r.getTransports ? r.getTransports() : []; }
  if (r.authenticatorData) { out.response.authenticatorData = b64u.enc(r.authenticatorData); out.response.signature = b64u.enc(r.signature); out.response.userHandle = r.userHandle ? b64u.enc(r.userHandle) : null; }
  const prf = ext.prf?.results?.first ? b64u.enc(ext.prf.results.first) : null;
  if (ext.prf) out.clientExtensionResults.prf = { enabled: !!ext.prf.enabled || !!prf };
  return { credential: out, prf_output: prf, transports: out.response.transports || [] };
}
async function webauthnCreate(options) { const cred = await navigator.credentials.create({ publicKey: webauthnPrepare(options) }); return webauthnSerialize(cred); }
async function webauthnGet(options) { const cred = await navigator.credentials.get({ publicKey: webauthnPrepare(options) }); return webauthnSerialize(cred); }

// ── password strength & generator ──────────────────────────────────────────
const WORDS = ('able acid aged also area army away baby back ball band bank base bath bear beat been beer bell belt best bill bird blow blue boat body bomb bond bone book boom born boss both bowl bulk burn bush busy call calm came camp card care case cash cast cell chat chip city club coal coat code cold come cook cool cope copy core cost crew crop dark data date dawn days dead deal dean dear debt deep deny desk dial diet dirt disc dish disk does done door dose down draw drew drop drug dual duke dust duty each earn ease east easy edge else even ever evil exit face fact fail fair fall farm fast fate fear feed feel feet fell felt file fill film find fine fire firm fish five flat flow food foot ford form fort four free from fuel full fund gain game gate gave gear gene gift girl give glad goal goes gold golf gone good gray grew grey grow gulf hair half hall hand hang hard harm hate have head hear heat held hell help here hero high hill hire hold hole holy home hope host hour huge hung hunt hurt idea inch into iron item jack jane jean john join jump jury just keen keep kent kept kick kill kind king knee knew know lack lady laid lake land lane last late lead left less life lift like line link list live load loan lock logo long look lord lose loss lost love luck made mail main make male many mark mass matt meal mean meat meet menu mere mike mile milk mill mind mine miss mode mood moon more most move much must name navy near neck need news next nice nick nine none nose note okay once only onto open oral over pace pack page paid pain pair palm park part pass past path peak pick pink pipe plan play plot plug plus poll pool poor port post pull pure push race rail rain rank rare rate read real rear rely rent rest rice rich ride ring rise risk road rock role roll roof room root rose rule rush ruth safe sage said sake sale salt same sand save seat seed seek seem seen self sell send sent sept ship shop shot show shut sick side sign site size skin slip slow snow soft soil sold sole some song soon sort soul spot star stay step stop such suit sure take tale talk tall tank tape task team tech tell tend term test text than that them then they thin this thus till time tiny told toll tone tony took tool tour town tree trip true tune turn twin type unit upon used user vary vast very vice view vote wage wait wake walk wall want ward warm wash wave ways weak wear week well went were west what when whom wide wife wild will wind wine wing wire wise wish with wood word wore work yard yeah year your zero zone ' +
  'amber angel apple arrow atlas badge basil beach berry blade blaze bloom brass bread brick bridge brook cabin candle canyon cedar chalk cherry cliff cloud clover coast comet coral crane creek crest crown crystal delta desert diamond dream eagle ember falcon feather fern field flame flint forest fossil frost garden ginger glacier globe grove harbor hawk hazel heron honey horizon island ivory jade jungle lagoon lantern laurel lemon lily lotus lunar maple marble meadow mesa mint mist mountain nebula north oasis ocean olive onyx orbit orchid otter oyster panda pearl pebble pepper pine planet plum polar prairie prism quartz quill raven reef ridge river rocket rover ruby saffron sail salmon sapphire shadow shell silver sketch slate solar sparrow spruce steel stone storm summit sunset swift thunder tide tiger timber topaz torch trail tulip tundra valley velvet violet walnut willow winter wolf zephyr').split(/\s+/).filter(Boolean);
const WORD_BITS = Math.log2(WORDS.length);

function estimateEntropy(pw) {
  if (!pw) return 0;
  let pool = 0;
  if (/[a-z]/.test(pw)) pool += 26; if (/[A-Z]/.test(pw)) pool += 26; if (/\d/.test(pw)) pool += 10;
  if (/[^A-Za-z0-9]/.test(pw)) pool += 33; if (/[а-яё]/i.test(pw)) pool += 33;
  let bits = pw.length * Math.log2(pool || 1);
  // passphrase-style input: words separated by non-letters count by words, not by characters
  const words = pw.split(/[^A-Za-zА-Яа-яЁё]+/).filter(w => w.length >= 3);
  if (words.length >= 3 && words.join('').length / pw.length > 0.7) bits = Math.min(bits, words.length * WORD_BITS + 4);
  // obvious weaknesses: long runs, sequences, repeated short patterns
  if (/(.)\1{2,}/.test(pw)) bits -= 8;
  if (/(0123|1234|2345|3456|4567|5678|6789|abcd|bcde|qwer|asdf|zxcv)/i.test(pw)) bits -= 10;
  if (/^(.{1,3})\1+$/.test(pw)) bits = Math.min(bits, 10);
  if (/^(password|qwerty|admin|letmein|welcome|123456|пароль)/i.test(pw)) bits = Math.min(bits, 8);
  return Math.max(0, Math.round(bits));
}
function strengthInfo(pw) {
  const bits = estimateEntropy(pw);
  if (!pw) return { bits, label: '', cls: '', pct: 0 };
  if (bits < 40) return { bits, label: tr('слабый'), cls: 'danger', pct: 25 };
  if (bits < 60) return { bits, label: tr('средний'), cls: 'warn', pct: 50 };
  if (bits < 80) return { bits, label: tr('хороший'), cls: 'ok', pct: 75 };
  return { bits, label: tr('отличный'), cls: 'ok', pct: 100 };
}
function strengthMeter(input) {
  const bar = el('div'); const lbl = el('span', { class: 'xs muted' });
  const wrap = el('div', { class: 'stack', style: { gap: '4px' } }, el('div', { class: 'meter' }, bar), el('div', { class: 'row between' }, lbl));
  const upd = () => {
    const i = strengthInfo(input.value);
    bar.style.width = i.pct + '%'; bar.style.background = i.cls === 'danger' ? 'var(--danger)' : i.cls === 'warn' ? 'var(--warn)' : 'var(--ok)';
    lbl.textContent = input.value ? tr`${i.label} · ~${i.bits} бит` : '';
  };
  input.addEventListener('input', upd); upd(); wrap.update = upd;
  return wrap;
}
const GEN_DEFAULTS = { mode: 'random', length: 24, upper: true, digits: true, symbols: true, ambiguous: false, words: 5, sep: '-', capitalize: true, number: true };
function genPassword(o = {}) {
  const g = { ...GEN_DEFAULTS, ...o };
  const rnd = (n) => { const a = new Uint32Array(1); crypto.getRandomValues(a); return a[0] % n; };
  if (g.mode === 'passphrase') {
    const ws = []; for (let i = 0; i < g.words; i++) { let w = WORDS[rnd(WORDS.length)]; if (g.capitalize) w = w[0].toUpperCase() + w.slice(1); ws.push(w); }
    if (g.number) ws[rnd(ws.length)] += String(rnd(100));
    return ws.join(g.sep);
  }
  let lower = 'abcdefghijklmnopqrstuvwxyz', upper = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', digits = '0123456789', symbols = '!@#$%^&*()-_=+[]{};:,.<>?';
  if (g.ambiguous === false) { lower = lower.replace(/[lo]/g, ''); upper = upper.replace(/[IO]/g, ''); digits = digits.replace(/[01]/g, ''); symbols = symbols.replace(/[{}\[\]();:,.<>]/g, ''); }
  const sets = [lower]; if (g.upper) sets.push(upper); if (g.digits) sets.push(digits); if (g.symbols) sets.push(symbols);
  const all = sets.join('');
  for (let attempt = 0; attempt < 20; attempt++) {
    let out = ''; for (let i = 0; i < g.length; i++) out += all[rnd(all.length)];
    if (sets.every(s => [...out].some(c => s.includes(c)))) return out;   // every chosen class present
  }
  return Array.from({ length: g.length }, () => all[rnd(all.length)]).join('');
}
function generatorPanel(target, onApply) {
  const g = { ...GEN_DEFAULTS, ...PREFS.get('gen', {}) };
  const preview = el('div', { class: 'codebox', style: { fontSize: '14px', letterSpacing: '.02em', textAlign: 'left', cursor: 'pointer' }, title: tr('Нажми, чтобы сгенерировать заново') });
  const meter = el('div', { class: 'meter' }, el('div')); const bits = el('span', { class: 'xs muted' });
  let current = '';
  const regen = () => {
    current = genPassword(g); preview.textContent = current;
    const i = strengthInfo(current); meter.firstChild.style.width = i.pct + '%'; meter.firstChild.style.background = i.cls === 'danger' ? 'var(--danger)' : i.cls === 'warn' ? 'var(--warn)' : 'var(--ok)';
    bits.textContent = g.mode === 'passphrase' ? tr`~${Math.round(g.words * WORD_BITS)} бит энтропии (${WORDS.length} слов в словаре)` : tr`~${i.bits} бит · ${i.label}`;
    PREFS.set('gen', g);
  };
  preview.addEventListener('click', regen);
  const seg = el('div', { class: 'seg' },
    el('button', { class: g.mode === 'random' ? 'active' : '', onclick: () => { g.mode = 'random'; render(); } }, tr('Случайный')),
    el('button', { class: g.mode === 'passphrase' ? 'active' : '', onclick: () => { g.mode = 'passphrase'; render(); } }, tr('Парольная фраза')));
  const opts = el('div', { class: 'stack', style: { gap: '8px' } });
  const toggleRow = (label, key) => el('label', { class: 'row between', style: { cursor: 'pointer' } }, el('span', { class: 'small' }, label),
    el('span', { class: `toggle ${g[key] ? 'on' : ''}`, role: 'switch', 'aria-checked': String(!!g[key]), tabindex: 0,
      onclick: (e) => { g[key] = !g[key]; e.currentTarget.classList.toggle('on', g[key]); e.currentTarget.setAttribute('aria-checked', String(g[key])); regen(); },
      onkeydown: (e) => { if (e.key === ' ' || e.key === 'Enter') { e.preventDefault(); e.currentTarget.click(); } } }));
  const slider = (label, key, min, max) => {
    const val = el('span', { class: 'small mono' }, String(g[key]));
    const inp = el('input', { type: 'range', min, max, value: g[key], style: { width: '100%' }, oninput: (e) => { g[key] = parseInt(e.target.value); val.textContent = e.target.value; regen(); } });
    return el('div', { class: 'stack', style: { gap: '2px' } }, el('div', { class: 'row between' }, el('span', { class: 'small' }, label), val), inp);
  };
  function render() {
    seg.children[0].classList.toggle('active', g.mode === 'random'); seg.children[1].classList.toggle('active', g.mode === 'passphrase');
    clear(opts);
    if (g.mode === 'random') opts.append(slider(tr('Длина'), 'length', 8, 64), toggleRow(tr('Заглавные буквы'), 'upper'), toggleRow(tr('Цифры'), 'digits'), toggleRow(tr('Символы'), 'symbols'), toggleRow(tr('Разрешить похожие символы (l, 1, O, 0)'), 'ambiguous'));
    else {
      const sepRow = el('div', { class: 'row between' }, el('span', { class: 'small' }, tr('Разделитель')),
        el('div', { class: 'seg' }, ...['-', '.', '_', ' '].map(s => el('button', { class: g.sep === s ? 'active' : '', onclick: (e) => { g.sep = s; [...e.currentTarget.parentNode.children].forEach(b => b.classList.toggle('active', b === e.currentTarget)); regen(); } }, s === ' ' ? tr('пробел') : s))));
      opts.append(slider(tr('Слов'), 'words', 3, 10), sepRow, toggleRow(tr('С заглавной буквы'), 'capitalize'), toggleRow(tr('Добавить число'), 'number'));
    }
    regen();
  }
  render();
  return el('div', { class: 'card pad stack', style: { gap: '10px' } },
    el('div', { class: 'row between' }, el('span', { class: 'label' }, tr('Генератор')), seg),
    preview, meter, bits, opts,
    el('div', { class: 'row', style: { justifyContent: 'flex-end' } },
      el('button', { class: 'btn sm', onclick: regen }, icon('refresh', 13), tr('Ещё')),
      el('button', { class: 'btn sm', onclick: () => copyText(current, tr('Пароль')) }, icon('copy', 13), tr('Копировать')),
      el('button', { class: 'btn sm primary', onclick: () => { onApply(current); } }, icon('check', 13), tr('Подставить'))));
}
async function sha1Hex(text) {
  const buf = await crypto.subtle.digest('SHA-1', new TextEncoder().encode(text));
  return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();
}
// k-anonymity: only the first 5 hex chars of the SHA-1 leave the browser (see /api/tools/hibp)
async function leakCount(password) {
  const h = await sha1Hex(password);
  const body = await api.hibp(h.slice(0, 5));
  for (const line of body.split('\n')) { const [suf, n] = line.trim().split(':'); if (suf === h.slice(5)) return parseInt(n) || 0; }
  return 0;
}

// ── shell ───────────────────────────────────────────────────────────────────
async function enterApp() {
  await refreshData();
  renderShell();
  onRoute();
  if (!state._wired) { state._wired = true; setupAutoLock(); setupGlobalKeys(); setupDropCreds(); window.addEventListener('hashchange', onRoute); }
}
function renderShell() {
  const app = clear(document.getElementById('app'));
  const search = el('input', { type: 'search', class: 'input', placeholder: tr('Поиск по секретам…'), value: state.q, id: 'search', autocomplete: 'off', spellcheck: false });
  search.addEventListener('input', debounce(() => { state.q = search.value.trim(); state.focus = -1; renderList(); }, 120));
  search.addEventListener('keydown', (e) => { if (e.key === 'Escape') { search.value = ''; state.q = ''; renderList(); search.blur(); } if (e.key === 'ArrowDown') { e.preventDefault(); state.focus = 0; renderList(); document.querySelector('.item.focused')?.focus(); } });
  const topbar = el('header', { class: 'topbar' },
    el('button', { class: 'btn ghost icon menu-btn', onclick: () => { state.sidebarOpen = !state.sidebarOpen; document.getElementById('sidebar').classList.toggle('open', state.sidebarOpen); }, title: tr('Меню') }, icon('menu', 18)),
    el('a', { class: 'brand', href: '#/all' }, el('span', { class: 'logo' }, icon('shield', 16)), 'APS Vault'),
    el('div', { class: 'search' }, el('span', { class: 'icon-l' }, icon('search', 15)), search, kbd('⌘K')),
    el('div', { class: 'actions' },
      el('button', { class: 'btn primary', onclick: () => showSecretEditor(), title: tr('Новый секрет') + ' (N)' }, icon('plus', 15), el('span', { class: 'label-text' }, tr('Секрет'))),
      el('button', { class: 'btn ghost icon', id: 'theme-btn', onclick: cycleTheme, title: tr('Тема') }, themeIcon()),
      el('button', { class: 'btn ghost sm mono', onclick: () => I18N.setLang(I18N.lang === 'ru' ? 'en' : 'ru'), title: tr('Язык') }, I18N.lang === 'ru' ? 'EN' : 'RU'),
      el('button', { class: 'btn ghost icon', onclick: showHelp, title: tr('Горячие клавиши') + ' (?)' }, icon('help', 17)),
      el('button', { class: 'btn', onclick: async () => { try { await api.lock(); } catch {} location.hash = ''; location.reload(); }, title: tr('Заблокировать') }, icon('lock', 14), el('span', { class: 'label-text' }, tr('Заблокировать')))));
  const sidebar = el('aside', { class: 'sidebar', id: 'sidebar' });
  const content = el('section', { class: 'content', id: 'content' });
  app.appendChild(el('div', { class: 'shell' }, topbar, el('div', { class: 'body' }, sidebar, content)));
  renderSidebar();
}
function navItem(label, iconName, active, onclick, count, extra = {}) {
  return el('button', { class: `nav-item ${active ? 'active' : ''} ${extra.class || ''}`, onclick, title: extra.title || label },
    extra.chev || el('span', { class: 'icon' }, icon(iconName, 15)), el('span', { class: 'truncate' }, label), count != null ? el('span', { class: 'count' }, String(count)) : null);
}
function renderSidebar() {
  const sb = clear(document.getElementById('sidebar')); const r = state.route;
  const closeOnMobile = () => { state.sidebarOpen = false; sb.classList.remove('open'); };
  const nav = (view, id) => () => { go(view, id); closeOnMobile(); };
  const favN = state.secrets.filter(s => s.is_favorite).length;
  const expN = state.secrets.filter(s => s.expires_at && daysUntil(s.expires_at) <= 30).length;
  sb.appendChild(el('div', null,
    navItem(tr('Все секреты'), 'inbox', r.view === 'all', nav('all'), state.secrets.length),
    navItem(tr('Избранное'), 'star', r.view === 'fav', nav('fav'), favN),
    navItem(tr('Истекают'), 'calendar', r.view === 'expiring', nav('expiring'), expN, { class: expN ? '' : '' })));
  // folders
  const expanded = new Set(PREFS.get('expanded', []));
  const fsec = el('div', null, el('div', { class: 'nav-title' }, tr('Папки'), el('button', { class: 'btn ghost icon sm', onclick: showFolderEditor, title: tr('Новая папка') }, icon('plus', 13))));
  const sorted = [...state.folders].sort((a, b) => a.name.localeCompare(b.name, I18N.locale));
  for (const f of sorted) {
    const inFolder = state.secrets.filter(s => s.folder_id === f.id);
    const open = expanded.has(f.id);
    const chev = el('span', { class: 'chev', onclick: (e) => { e.stopPropagation(); if (open) expanded.delete(f.id); else expanded.add(f.id); PREFS.set('expanded', [...expanded]); renderSidebar(); } }, icon(open ? 'chevron_down' : 'chevron_right', 13));
    fsec.appendChild(navItem(f.name, 'folder', r.view === 'folder' && r.id === f.id, nav('folder', f.id), inFolder.length, { chev, title: f.description || f.name }));
    if (open) for (const s of [...inFolder].sort((a, b) => a.name.localeCompare(b.name, I18N.locale)))
      fsec.appendChild(el('button', { class: `nav-item leaf ${r.secret === s.id ? 'active' : ''}`, onclick: () => { go('folder', f.id, s.id); closeOnMobile(); } }, icon('file', 12), el('span', { class: 'truncate' }, s.name)));
  }
  if (!sorted.length) fsec.appendChild(el('div', { class: 'xs faint', style: { padding: '2px 10px' } }, tr('Папок ещё нет')));
  sb.appendChild(fsec);
  // tags
  const counts = {}; for (const s of state.secrets) for (const t of tags(s)) counts[t] = (counts[t] || 0) + 1;
  const top = Object.entries(counts).sort((a, b) => b[1] - a[1]).slice(0, 14);
  if (top.length) sb.appendChild(el('div', null, el('div', { class: 'nav-title' }, tr('Теги')),
    el('div', { class: 'chips' }, ...top.map(([t, n]) => el('button', { class: `chip ${r.view === 'tag' && r.id === t ? 'active' : ''}`, onclick: () => { if (r.view === 'tag' && r.id === t) go('all'); else go('tag', t); closeOnMobile(); } }, icon('tag', 11), t, el('span', { class: 'faint xs' }, String(n)))))));
  // pages
  sb.appendChild(el('div', { style: { marginTop: 'auto' } }, el('div', { class: 'nav-title' }, tr('Управление')),
    navItem(tr('Токены'), 'key', r.view === 'tokens', nav('tokens')),
    navItem(tr('Ссылки'), 'link', r.view === 'shares', nav('shares')),
    navItem(tr('Вебхуки'), 'zap', r.view === 'webhooks', nav('webhooks')),
    navItem(tr('Журнал'), 'log', r.view === 'audit', nav('audit')),
    navItem(tr('Здоровье'), 'activity', r.view === 'health', nav('health')),
    navItem(tr('Настройки'), 'settings', r.view === 'settings', nav('settings'))));
}
function onRoute() {
  state.route = parseHash();
  if (state.totpTimer) { clearInterval(state.totpTimer); state.totpTimer = null; }
  renderSidebar();
  const c = clear(document.getElementById('content'));
  if (isPage(state.route.view)) { c.className = 'content single'; c.appendChild(el('div', { class: 'detail-pane' }, el('div', { class: 'page', id: 'page' }))); PAGES[state.route.view](document.getElementById('page')); return; }
  c.className = `content ${state.route.secret ? 'has-detail' : ''}`;
  c.append(el('div', { class: 'list-pane' }, listHead(), el('div', { class: 'list', id: 'list', role: 'listbox' })), el('div', { class: 'detail-pane', id: 'detail' }));
  renderList();
  renderDetail();
}
function listHead() {
  const sortSeg = el('div', { class: 'seg', title: tr('Сортировка') }, ...[['name', tr('Имя')], ['updated', tr('Изменён')], ['accessed', tr('Открыт')]].map(([k, l]) =>
    el('button', { class: state.sort === k ? 'active' : '', onclick: (e) => { state.sort = k; PREFS.set('sort', k); [...e.currentTarget.parentNode.children].forEach(b => b.classList.toggle('active', b === e.currentTarget)); renderList(); } }, l)));
  const r = state.route; const extra = [];
  if (r.view === 'folder') {
    const f = state.folders.find(x => x.id === r.id);
    extra.push(el('button', { class: 'btn ghost icon sm', title: tr('Токен для этой папки'), onclick: () => { go('tokens'); setTimeout(() => PAGES._tokensPreset?.(r.id), 50); } }, icon('key', 14)));
    extra.push(el('button', { class: 'btn ghost icon sm', title: tr('Удалить папку (только пустую)'), onclick: async () => {
      if (!f) return; if (!(await confirmDialog(tr`Удалить папку «${f.name}»?`, tr('Удалить можно только пустую папку. Токены на неё перестанут работать.'), { danger: true }))) return;
      try { await api.deleteFolder(f.id); toast(tr('Папка удалена'), 'ok'); await refreshData(); go('all'); } catch (e) { toast(e.message, 'error'); }
    } }, icon('trash', 14)));
  }
  return el('div', { class: 'list-head' }, el('h2', { class: 'truncate' }, scopeTitle()), ...extra, sortSeg);
}
function renderList() {
  const list = document.getElementById('list'); if (!list) return; clear(list);
  const items = scopedSecrets(); state._visible = items;
  const titleEl = document.querySelector('.list-head h2'); if (titleEl) titleEl.textContent = scopeTitle() + (state.q ? ` · ${items.length}` : '');
  if (!items.length) {
    list.appendChild(el('div', { class: 'empty' }, icon(state.q ? 'search' : 'inbox', 40),
      el('h3', null, state.q ? tr('Ничего не найдено') : tr('Здесь пока пусто')),
      el('p', { class: 'small', style: { margin: 0 } }, state.q ? tr('Попробуй другой запрос или ⌘K для поиска по всему хранилищу') : tr('Создай секрет кнопкой «Секрет» или перетащи текст с учёткой прямо в окно')),
      !state.q && state.folders.length ? el('button', { class: 'btn primary sm', onclick: () => showSecretEditor() }, icon('plus', 13), tr('Новый секрет')) : null,
      !state.folders.length ? el('button', { class: 'btn primary sm', onclick: showFolderEditor }, icon('folder', 13), tr('Создать первую папку')) : null));
    return;
  }
  items.forEach((s, i) => {
    const ex = expiryState(s);
    const row = el('div', { class: `item ${state.route.secret === s.id ? 'active' : ''} ${state.focus === i ? 'focused' : ''}`, role: 'option', tabindex: -1, dataset: { id: s.id },
      onclick: (e) => { if (e.target.closest('.quick')) return; state.focus = i; goSecret(s.id); },
      onkeydown: (e) => { if (e.key === 'Enter') goSecret(s.id); } },
      avatar(s.name),
      el('div', { style: { minWidth: 0 } },
        el('div', { class: 'name' }, el('span', null, s.name), s.is_favorite ? el('span', { class: 'star' }, icon('star', 11)) : null,
          s.has_totp ? el('span', { class: 'badge ok' }, 'TOTP') : null,
          s.machine_only ? el('span', { class: 'badge accent', title: tr('Только для машин: значение не показывается людям') }, icon('server', 10), tr('машины')) : null,
          s.require_approval ? el('span', { class: 'badge warn', title: tr('Чтение только с подтверждением второго лица') }, icon('shield_check', 10), tr('подтверждение')) : null),
        el('div', { class: 'sub' }, el('span', { class: 'truncate' }, state.route.view === 'folder' ? (s.url ? hostOf(s.url) : (s.has_login ? tr('логин') : '')) : s.folder_name),
          ex && ex.cls ? el('span', { class: `badge ${ex.cls}` }, icon('calendar', 10), ex.text) : null,
          ...tags(s).slice(0, 3).map(t => el('span', { class: 'badge' }, t)))),
      el('div', { class: 'meta' }, timeAgo(s.updated_at || s.created_at), el('div', null, s.access_count ? tr`${s.access_count} чтений` : tr('не открывался'))),
      el('div', { class: 'quick' },
        el('button', { class: 'btn ghost icon sm', title: tr('Копировать значение') + ' (C)', onclick: async () => { try { const f = await api.getSecret(s.id); copyText(f.value, s.name); } catch (e) { toast(e.message, 'error'); } } }, icon('copy', 14)),
        s.has_login ? el('button', { class: 'btn ghost icon sm', title: tr('Копировать логин'), onclick: async () => { try { const f = await api.getSecret(s.id); copyText(f.login, tr('Логин')); } catch (e) { toast(e.message, 'error'); } } }, icon('user', 14)) : null,
        s.url && /^https?:\/\//.test(s.url) ? el('a', { class: 'btn ghost icon sm', href: s.url, target: '_blank', rel: 'noopener noreferrer', title: tr('Открыть сайт') }, icon('external', 14)) : null,
        el('button', { class: 'btn ghost icon sm', title: s.is_favorite ? tr('Убрать из избранного') : tr('В избранное'), onclick: async () => { try { await api.toggleFavorite(s.id); await refreshData(); renderSidebar(); renderList(); } catch (e) { toast(e.message, 'error'); } } }, icon('star', 14))));
    list.appendChild(row);
  });
}

// ── detail ──────────────────────────────────────────────────────────────────
async function renderDetail() {
  const pane = document.getElementById('detail'); if (!pane) return; clear(pane);
  const id = state.route.secret;
  if (!id) {
    const n = state.secrets.length;
    pane.appendChild(el('div', { class: 'empty', style: { height: '100%' } }, icon('shield_check', 44),
      el('h3', null, n ? tr('Выбери секрет слева') : tr('Хранилище пустое')),
      el('p', { class: 'small', style: { margin: 0, maxWidth: '36ch' } }, tr('Стрелки ↑↓ или J/K — по списку, Enter — открыть, C — скопировать, N — новый, ? — все клавиши'))));
    return;
  }
  pane.appendChild(el('div', { class: 'empty' }, el('span', { class: 'spin' }, icon('refresh', 20))));
  let s;
  try { s = state._approval?.secretId === id ? await api.getSecretApproved(id, state._approval.id) : await api.getSecret(id); }
  catch (e) {
    if (e.status === 403 && /approval/i.test(e.message)) { state._approval = null; return renderApprovalRequest(pane, id); }
    clear(pane).appendChild(el('div', { class: 'empty' }, icon('alert', 32), el('h3', null, e.message))); return;
  }
  if (state.route.secret !== id) return;   // navigated away meanwhile
  state.detail = s; clear(pane);
  const ex = expiryState(s);
  const back = el('button', { class: 'btn ghost icon menu-btn', onclick: () => go(state.route.view, state.route.id), title: tr('К списку') }, icon('arrow_left', 18));
  const head = el('div', { class: 'detail-head' }, back, avatar(s.name, 44),
    el('div', { style: { minWidth: 0 } }, el('h1', null, s.name),
      el('div', { class: 'crumbs' }, el('a', { href: routeHash('folder', s.folder_id) }, icon('folder', 12), ' ', s.folder_name), ...tags(s).map(t => el('a', { href: routeHash('tag', t), class: 'badge' }, t)),
        ex ? el('span', { class: `badge ${ex.cls}` }, icon('calendar', 10), ex.text) : null)),
    el('div', { class: 'actions' },
      el('button', { class: `btn icon ${s.is_favorite ? '' : 'ghost'}`, title: s.is_favorite ? tr('Убрать из избранного') : tr('В избранное'), style: s.is_favorite ? { color: 'var(--warn)' } : null,
        onclick: async () => { await api.toggleFavorite(s.id); await refreshData(); renderSidebar(); renderList(); renderDetail(); } }, icon('star', 15)),
      el('button', { class: 'btn', onclick: () => showSecretEditor(s.id) }, icon('pencil', 14), tr('Изменить')),
      el('button', { class: 'btn', onclick: () => showMoveDialog(s) }, icon('folder_in', 14), tr('Переместить')),
      s.machine_only ? null : el('button', { class: 'btn', onclick: () => showShareDialog(s.id, s.name) }, icon('share', 14), tr('Поделиться')),
      el('button', { class: 'btn danger icon', title: tr('Удалить'), onclick: async () => {
        if (!(await confirmDialog(tr`Удалить «${s.name}»?`, tr('История значений и ссылки на этот секрет тоже удалятся.'), { danger: true }))) return;
        try { await api.deleteSecret(s.id); toast(tr('Удалён'), 'ok'); await refreshData(); go(state.route.view, state.route.id); } catch (e) { toast(e.message, 'error'); }
      } }, icon('trash', 15))));
  const card = el('div', { class: 'card' });
  const frow = (k, v, ops) => el('div', { class: 'frow' }, el('div', { class: 'k' }, k), v, el('div', { class: 'ops' }, ...(ops || [])));
  const copyBtn = (text, label) => el('button', { class: 'btn ghost icon sm', title: tr('Копировать'), onclick: () => copyText(text, label) }, icon('copy', 14));
  if (s.login) card.appendChild(frow(tr('Логин'), el('div', { class: 'v' }, s.login), [copyBtn(s.login, tr('Логин'))]));
  if (s.machine_only) {
    // machine-only: no value for people at all — only metadata and the rotation button
    card.appendChild(frow(tr('Значение'), el('div', null,
      el('div', { class: 'callout accent', style: { background: 'var(--accent-soft)', color: 'var(--accent)' } }, icon('server', 16), el('div', { class: 'small' }, tr`Только для машин: значение читают сервисные токены папки, людям оно не показывается — ни здесь, ни в истории, ни в экспорте. Версия ${s.version || 1}.`))),
      [el('button', { class: 'btn sm', onclick: () => showRotateDialog(s) }, icon('refresh', 13), tr('Ротация'))]));
  }
  // value: hidden by default, reveal re-hides after N seconds
  const val = el('div', { class: 'v secret-blur' }, s.value); let hideTimer = null;
  const revealBtn = el('button', { class: 'btn ghost icon sm', title: tr('Показать'), onclick: () => {
    const hidden = val.classList.toggle('secret-blur'); clear(revealBtn).appendChild(icon(hidden ? 'eye' : 'eye_off', 14));
    clearTimeout(hideTimer); if (!hidden && state.prefs.revealSec) hideTimer = setTimeout(() => { val.classList.add('secret-blur'); clear(revealBtn).appendChild(icon('eye', 14)); }, state.prefs.revealSec * 1000);
  } }, icon('eye', 14));
  const si = strengthInfo(s.value);
  if (!s.machine_only) card.appendChild(frow(tr('Значение'), el('div', { style: { minWidth: 0 } }, val, el('div', { class: 'row', style: { marginTop: '6px', gap: '10px' } },
    el('div', { class: 'meter', style: { width: '90px' } }, el('div', { style: { width: si.pct + '%', background: si.cls === 'danger' ? 'var(--danger)' : si.cls === 'warn' ? 'var(--warn)' : 'var(--ok)' } })),
    el('span', { class: 'xs muted' }, tr`${si.label} · ~${si.bits} бит · ${s.value.length} симв.`),
    el('button', { class: 'btn ghost sm', onclick: async (e) => {
      const b = e.currentTarget; b.disabled = true;
      try { const n = await leakCount(s.value); toast(n ? tr`Пароль найден в утечках ${n.toLocaleString(I18N.locale)} раз — смени его` : tr('В известных утечках не найден'), n ? 'error' : 'ok', 5000); }
      catch (er) { toast(er.status === 404 ? tr('Проверка утечек выключена (VAULT_HIBP=0)') : tr('База утечек недоступна'), 'warn'); } finally { b.disabled = false; }
    }, title: tr('Проверить по базе утечек (k-анонимность: наружу уходит только префикс хеша)') }, icon('shield_check', 13), tr('Утечки')))),
    [revealBtn, copyBtn(s.value, s.name)]));
  if (s.totp) {
    const codeEl = el('span', { class: 'code' }, s.totp.replace(/(\d{3})(\d{3})/, '$1 $2'));
    const R = 12, C = 2 * Math.PI * R;
    const ring = el('span'); const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg'); svg.setAttribute('class', 'ring'); svg.setAttribute('viewBox', '0 0 28 28');
    const bg = document.createElementNS('http://www.w3.org/2000/svg', 'circle'); bg.setAttribute('class', 'bg'); bg.setAttribute('cx', 14); bg.setAttribute('cy', 14); bg.setAttribute('r', R);
    const fg = document.createElementNS('http://www.w3.org/2000/svg', 'circle'); fg.setAttribute('class', 'fg'); fg.setAttribute('cx', 14); fg.setAttribute('cy', 14); fg.setAttribute('r', R); fg.setAttribute('stroke-dasharray', C);
    svg.append(bg, fg); ring.appendChild(svg);
    const left = el('span', { class: 'xs muted mono' });
    let remaining = 30 - Math.floor(Date.now() / 1000) % 30, period = 30, code = s.totp;
    const tick = async () => {
      remaining -= 1;
      if (remaining <= 0) { try { const t = await api.totp(s.id); code = t.code; period = t.period; remaining = t.remaining; codeEl.textContent = code.replace(/(\d{3})(\d{3})/, '$1 $2'); } catch { remaining = period; } }
      fg.setAttribute('stroke-dashoffset', C * (1 - remaining / period)); svg.classList.toggle('low', remaining <= 5); left.textContent = tr`${remaining} с`;
    };
    api.totp(s.id).then(t => { code = t.code; period = t.period; remaining = t.remaining + 1; codeEl.textContent = code.replace(/(\d{3})(\d{3})/, '$1 $2'); tick(); }).catch(() => {});
    state.totpTimer = setInterval(tick, 1000);
    card.appendChild(frow(tr('Одноразовый код'), el('div', { class: 'totp' }, codeEl, ring, left), [el('button', { class: 'btn ghost icon sm', title: tr('Копировать код'), onclick: () => copyText(code, 'TOTP') }, icon('copy', 14))]));
  }
  if (s.url) card.appendChild(frow('URL', el('div', { class: 'v text' }, /^https?:\/\//i.test(s.url) ? el('a', { href: s.url, target: '_blank', rel: 'noopener noreferrer' }, s.url, ' ', icon('external', 12)) : s.url), [copyBtn(s.url, 'URL')]));
  if (s.notes) {
    const notes = el('div', { class: 'v text secret-blur' }, s.notes);
    card.appendChild(frow(tr('Заметки'), notes, [el('button', { class: 'btn ghost icon sm', title: tr('Показать'), onclick: (e) => { const h = notes.classList.toggle('secret-blur'); clear(e.currentTarget).appendChild(icon(h ? 'eye' : 'eye_off', 14)); } }, icon('eye', 14)), copyBtn(s.notes, tr('Заметки'))]));
  }
  card.appendChild(frow(tr('Срок'), el('div', { class: 'v text' }, s.expires_at ? fmtDate(s.expires_at, false) : el('span', { class: 'faint' }, tr('без срока ротации'))),
    [el('button', { class: 'btn ghost sm', onclick: () => showSecretEditor(s.id, 'expires') }, icon('calendar', 13), tr('Задать'))]));
  const meta = el('div', { class: 'xs faint row wrap', style: { gap: '14px', padding: '0 4px' } },
    el('span', null, tr`Создан ${fmtDate(s.created_at)}`), el('span', null, tr`Изменён ${fmtDate(s.updated_at)}`),
    el('span', null, s.last_accessed ? tr`Открыт ${timeAgo(s.last_accessed)} · ${s.access_count} чтений` : tr('Ещё не открывался')),
    el('span', { title: tr('Версия значения: растёт при каждой смене; машинный API читает старые через ?version=N') }, tr`версия ${s.version || 1}`), el('span', { class: 'mono' }, `id ${s.id}`));
  // history, inline
  const histWrap = el('div', { class: 'card' }); const histBody = el('div', { class: 'hidden' });
  const histBtn = el('button', { class: 'btn ghost sm', onclick: async () => {
    histBody.classList.toggle('hidden'); if (histBody.dataset.loaded) return;
    try {
      const d = await api.history(s.id); histBody.dataset.loaded = '1';
      if (!d.history.length) histBody.appendChild(el('div', { class: 'frow faint small' }, tr('Предыдущих значений нет')));
      for (const h of d.history) {
        if (h.hidden) { histBody.appendChild(frow(el('span', null, h.version ? el('span', { class: 'badge', style: { marginRight: '6px' } }, 'v' + h.version) : null, fmtDate(h.changed_at)), el('div', { class: 'v text faint' }, tr('скрыто: только для машин')), [])); continue; }
        const v = el('div', { class: 'v secret-blur' }, h.value || h.error || '');
        histBody.appendChild(frow(el('span', null, h.version ? el('span', { class: 'badge', style: { marginRight: '6px' } }, 'v' + h.version) : null, fmtDate(h.changed_at)), v, [el('button', { class: 'btn ghost icon sm', onclick: (e) => { const hd = v.classList.toggle('secret-blur'); clear(e.currentTarget).appendChild(icon(hd ? 'eye' : 'eye_off', 14)); } }, icon('eye', 14)), copyBtn(h.value, tr('старое значение'))]));
      }
    } catch (e) { toast(e.message, 'error'); }
  } }, icon('clock', 13), tr('История значений'));
  histWrap.append(el('div', { class: 'frow', style: { gridTemplateColumns: '1fr' } }, histBtn), histBody);
  pane.appendChild(el('div', { class: 'detail fade-in' }, head, card, histWrap, meta));
}

// ── approval-required secret: request → wait for the approver → read ─────────
function renderApprovalRequest(pane, id) {
  const meta = state.secrets.find(x => x.id === id);
  const reason = el('input', { class: 'input', placeholder: tr('Зачем нужен доступ (увидит подтверждающий)'), 'data-testid': 'approval-reason' });
  const box = el('div', { class: 'card pad stack', style: { maxWidth: '560px' } });
  const start = async () => {
    let req;
    try { req = await api.requestApproval(id, reason.value.trim()); }
    catch (e) { return toast(e.status === 409 ? tr('Подтверждающий не настроен: Настройки → Подтверждение чтения') : e.message, 'error', 6000); }
    clear(box).append(
      el('h3', { style: { margin: 0 } }, icon('clock', 16), ' ', tr('Ждём подтверждения')),
      el('p', { class: 'muted small', style: { margin: 0 } }, req.notified ? tr('Подтверждающему отправлено уведомление со ссылкой.') : tr('Уведомление не настроено (VAULT_APPROVAL_NOTIFY_URL) — передай ссылку подтверждающему сам:')),
      req.notified ? null : el('div', { class: 'row' }, el('div', { class: 'codebox', style: { fontSize: '11px', letterSpacing: 0, flex: 1, textAlign: 'left' }, 'data-testid': 'approve-url' }, req.approve_url), el('button', { class: 'btn icon', onclick: () => copyText(req.approve_url, tr('Ссылка')) }, icon('copy', 14))),
      el('div', { class: 'row', style: { gap: '10px' } }, el('span', { class: 'spin' }, icon('refresh', 16)), el('span', { class: 'small muted', id: 'approval-wait' }, tr`Запрос действует до ${fmtDate(req.expires_at)}`)));
    const poll = setInterval(async () => {
      if (state.route.secret !== id) return clearInterval(poll);
      try {
        const st = await api.approvalStatus(req.id);
        if (st.status === 'approved') { clearInterval(poll); state._approval = { id: req.id, secretId: id }; toast(tr('Подтверждено — значение доступно 10 минут'), 'ok'); renderDetail(); }
        else if (st.status !== 'pending') { clearInterval(poll); clear(box).append(el('div', { class: 'callout danger' }, icon('alert', 16), el('div', null, st.status === 'denied' ? tr('Подтверждающий отказал.') : tr('Запрос истёк.'))), el('button', { class: 'btn', onclick: () => renderApprovalRequest(pane, id) }, tr('Запросить снова'))); }
      } catch { clearInterval(poll); }
    }, 3000);
  };
  box.append(
    el('h3', { style: { margin: 0 } }, icon('shield_check', 16), ' ', tr('Нужно подтверждение второго лица')),
    el('p', { class: 'muted small', style: { margin: 0 } }, tr('Значение этого секрета выдаётся только после того, как подтверждающий одобрит запрос. Он увидит имя секрета, твой адрес и причину, но не значение. Одобрение действует 10 минут.')),
    el('div', { class: 'field' }, el('label', null, tr('Причина')), reason),
    el('button', { class: 'btn primary', onclick: start, 'data-testid': 'approval-request' }, icon('share', 14), tr('Запросить подтверждение')));
  clear(pane).appendChild(el('div', { class: 'detail fade-in' },
    el('div', { class: 'detail-head' }, el('button', { class: 'btn ghost icon menu-btn', onclick: () => go(state.route.view, state.route.id) }, icon('arrow_left', 18)), avatar(meta?.name || '?', 44),
      el('div', null, el('h1', null, meta?.name || tr('Секрет')), el('div', { class: 'crumbs' }, meta ? el('a', { href: routeHash('folder', meta.folder_id) }, icon('folder', 12), ' ', meta.folder_name) : null, el('span', { class: 'badge warn' }, icon('shield_check', 10), tr('требует подтверждения')))),
      el('div', { class: 'actions' }, el('button', { class: 'btn', onclick: () => showSecretEditor(id) }, icon('pencil', 14), tr('Изменить')))),
    box));
}

// ── public approve page (/approve/<token>) ────────────────────────────────────
function renderApprovePage(token) {
  const app = clear(document.getElementById('app'));
  const card = el('div', { class: 'card stack', style: { maxWidth: '520px', gap: '16px' } });
  const show = (...nodes) => { clear(card).append(brandBlock(''), ...nodes); };
  app.appendChild(el('div', { class: 'auth' }, card));
  show(el('div', { class: 'empty' }, el('span', { class: 'spin' }, icon('refresh', 20))));
  api.req('GET', `/api/approve/${encodeURIComponent(token)}`).then(info => {
    const pw = el('input', { type: 'password', class: 'input mono', placeholder: tr('пароль подтверждающего'), autocomplete: 'current-password', 'data-testid': 'approver-password' });
    const decide = async (decision) => {
      try {
        const r = await api.req('POST', `/api/approve/${encodeURIComponent(token)}`, { approver_password: pw.value, decision });
        show(el('div', { class: `callout ${r.status === 'approved' ? 'ok' : 'warn'}` }, icon(r.status === 'approved' ? 'check' : 'x', 18), el('div', null, r.status === 'approved' ? tr`Одобрено: запросивший сможет прочитать «${r.secret}» в течение 10 минут.` : tr`Отказано: «${r.secret}» останется закрытым.`)));
      } catch (e) { toast(e.message, 'error'); }
    };
    const row = (k, v) => el('div', { class: 'row between' }, el('span', { class: 'muted small' }, k), el('span', { class: 'mono small' }, v));
    if (info.status !== 'pending') return show(el('div', { class: 'callout warn' }, icon('info', 18), el('div', null, tr`Запрос уже обработан: ${info.status}.`)));
    show(el('div', null, el('div', { class: 'xs muted' }, tr('Запрос на чтение секрета')), el('h2', { style: { margin: '2px 0 0', fontSize: '18px' } }, info.secret)),
      el('div', { class: 'card', style: { padding: '10px 14px' } }, row(tr('Кто'), info.requester_ip || '?'), row(tr('Когда'), fmtDate(info.created_at)), row(tr('Действует до'), fmtDate(info.expires_at)), info.reason ? row(tr('Причина'), info.reason) : null),
      el('p', { class: 'muted small', style: { margin: 0 } }, tr('Ты не увидишь значение — только решаешь, можно ли его показать запросившему. Решение запишется в журнал с твоим адресом.')),
      el('div', { class: 'field' }, el('label', null, tr('Пароль подтверждающего')), pw),
      el('div', { class: 'row' }, el('button', { class: 'btn primary', style: { flex: 1 }, onclick: () => decide('approve'), 'data-testid': 'approve-yes' }, icon('check', 14), tr('Одобрить')), el('button', { class: 'btn danger', style: { flex: 1 }, onclick: () => decide('deny'), 'data-testid': 'approve-no' }, icon('x', 14), tr('Отказать'))));
    pw.focus();
  }).catch(e => show(el('div', { class: 'callout danger' }, icon('alert', 18), el('div', null, e.status === 404 ? tr('Ссылка не найдена.') : e.message))));
}

// ── editors ─────────────────────────────────────────────────────────────────
const GEN_SPECS = [['base64:32', tr('32 байта, base64')], ['hex:32', tr('32 байта, hex')], ['alnum:40', tr('40 букв и цифр')], ['base64:64', tr('64 байта, base64')]];
function genSpecChips(onPick, initial = 'base64:32') {
  let cur = initial; onPick(cur);
  const wrap = el('div', { class: 'chips' });
  for (const [spec, label] of GEN_SPECS) wrap.appendChild(el('button', { type: 'button', class: `chip ${spec === cur ? 'active' : ''}`, dataset: { spec }, onclick: (e) => { cur = spec; onPick(cur); [...wrap.children].forEach(c => c.classList.toggle('active', c === e.currentTarget)); } }, label));
  return wrap;
}
function showRotateDialog(s) {
  let spec = 'base64:32';
  const m = modal({ narrow: true }, el('h2', null, icon('refresh', 18), tr`Ротация «${s.name}»`),
    el('p', { class: 'muted small', style: { margin: 0 } }, tr`Сервер сгенерирует новое значение и сделает его версией ${(s.version || 1) + 1}. Текущее останется версией ${s.version || 1} и будет читаться машинами через ?version=N, пока они перешифровывают данные. Люди значения не увидят.`),
    el('div', { class: 'field' }, el('label', null, tr('Формат нового значения')), genSpecChips((v) => { spec = v; })),
    el('div', { class: 'foot' }, el('button', { class: 'btn', onclick: () => m.remove() }, tr('Отмена')),
      el('button', { class: 'btn primary', 'data-testid': 'rotate-confirm', onclick: async () => {
        try { const r = await api.rotateSecret(s.id, spec); m.remove(); toast(tr`Ротация выполнена: версия ${r.version}`, 'ok'); await refreshData(); renderList(); renderDetail(); } catch (e) { toast(e.message, 'error'); }
      } }, icon('refresh', 14), tr('Выполнить ротацию'))));
}
function folderPicker(selectedId, onPick) {
  const wrap = el('div', { class: 'stack', style: { gap: '6px' } });
  const sorted = [...state.folders].sort((a, b) => a.name.localeCompare(b.name, I18N.locale));
  let sel = selectedId ?? sorted[0]?.id ?? null;
  const render = (filter = '') => {
    clear(wrap);
    if (sorted.length > 8) {
      const f = el('input', { class: 'input', placeholder: tr('Найти папку…'), value: filter, oninput: (e) => render(e.target.value) });
      const listEl = el('div', { class: 'sel-list' }, ...sorted.filter(x => x.name.toLowerCase().includes(filter.toLowerCase())).map(x =>
        el('button', { type: 'button', class: x.id === sel ? 'active' : '', onclick: () => { sel = x.id; onPick(sel); render(filter); } }, icon('folder', 13), x.name)));
      wrap.append(f, listEl); if (filter) setTimeout(() => { f.focus(); f.setSelectionRange(filter.length, filter.length); }, 0);
    } else wrap.appendChild(el('div', { class: 'chips' }, ...sorted.map(x => el('button', { type: 'button', class: `chip ${x.id === sel ? 'active' : ''}`, onclick: () => { sel = x.id; onPick(sel); render(); } }, icon('folder', 12), x.name))));
  };
  render(); onPick(sel);
  wrap.value = () => sel;
  return wrap;
}
async function showSecretEditor(secretId, focusField) {
  let existing = null;
  if (secretId) {
    try { existing = state.detail?.id === secretId ? state.detail : await api.getSecret(secretId); }
    catch (e) {
      if (e.status === 403 && /approval/i.test(e.message)) { const m = state.secrets.find(x => x.id === secretId); existing = { ...m, value: '', login: '', notes: '' }; }   // metadata only; the value stays closed
      else return toast(e.message, 'error');
    }
  }
  if (!state.folders.length) { toast(tr('Сначала создай папку'), 'warn'); return showFolderEditor(); }
  let folderId = existing?.folder_id ?? (state.route.view === 'folder' ? state.route.id : null);
  const name = el('input', { class: 'input', value: existing?.name || '', placeholder: tr('например, prod/db-password'), autocomplete: 'off' });
  const value = el('textarea', { rows: 2, class: 'textarea mono', placeholder: tr('пароль, ключ, токен…') }); if (existing) value.value = existing.value;
  const meter = strengthMeter(value);
  const genWrap = el('div', { class: 'hidden' });
  const genBtn = el('button', { type: 'button', class: 'btn ghost sm', onclick: () => {
    if (genWrap.classList.contains('hidden')) { clear(genWrap).appendChild(generatorPanel(value, (pw) => { value.value = pw; meter.update(); genWrap.classList.add('hidden'); })); }
    genWrap.classList.toggle('hidden');
  } }, icon('dice', 13), tr('Сгенерировать'));
  const login = el('input', { class: 'input', value: existing?.login || '', placeholder: tr('user@example.com или username'), autocomplete: 'off' });
  const url = el('input', { class: 'input', value: existing?.url || '', placeholder: 'https://…', type: 'url' });
  const tagsInp = el('input', { class: 'input', value: existing?.tags || '', placeholder: 'prod, api', list: 'tag-suggestions' });
  const dl = el('datalist', { id: 'tag-suggestions' }); const allTags = new Set(); for (const s of state.secrets) for (const t of tags(s)) allTags.add(t); for (const t of allTags) dl.appendChild(el('option', { value: t }));
  const totp = el('input', { class: 'input mono', placeholder: existing?.has_totp ? tr('(уже задан — оставь пустым чтобы не менять)') : 'JBSWY3DPEHPK3PXP', autocomplete: 'off' });
  const notes = el('textarea', { rows: 3, class: 'textarea' }); if (existing) notes.value = existing.notes || '';
  const expires = el('input', { class: 'input', type: 'date', value: existing?.expires_at ? existing.expires_at.slice(0, 10) : '' });
  // machine-only + server-side generation (new secrets only: an existing value is already known)
  let machineOnly = !!existing?.machine_only, genSpec = 'base64:32', genOn = false;
  const genChips = el('div', { class: 'hidden' }); const valueField = el('div', { class: 'field' });
  const genToggle = existing ? null : el('label', { class: 'row', style: { gap: '8px', cursor: 'pointer' } },
    el('span', { class: 'toggle', role: 'switch', 'aria-checked': 'false', tabindex: 0, 'data-testid': 'gen-server', onclick: (e) => {
      const on = !e.currentTarget.classList.contains('on'); e.currentTarget.classList.toggle('on', on); e.currentTarget.setAttribute('aria-checked', String(on));
      genOn = on; genChips.classList.toggle('hidden', !on); valueField.classList.toggle('hidden', on);
    }, onkeydown: (e) => { if (e.key === ' ' || e.key === 'Enter') { e.preventDefault(); e.currentTarget.click(); } } }),
    el('span', { class: 'small' }, tr('Сгенерировать на сервере — значение никто не увидит')));
  if (!existing) clear(genChips).appendChild(genSpecChips((v) => { genSpec = v; }));
  const moToggle = el('label', { class: 'row', style: { gap: '8px', cursor: 'pointer' } },
    el('span', { class: `toggle ${machineOnly ? 'on' : ''}`, role: 'switch', 'aria-checked': String(machineOnly), tabindex: 0, 'data-testid': 'machine-only', onclick: (e) => {
      machineOnly = !machineOnly; e.currentTarget.classList.toggle('on', machineOnly); e.currentTarget.setAttribute('aria-checked', String(machineOnly));
    }, onkeydown: (e) => { if (e.key === ' ' || e.key === 'Enter') { e.preventDefault(); e.currentTarget.click(); } } }),
    el('div', null, el('div', { class: 'small' }, tr('Только для машин')), el('div', { class: 'xs faint' }, tr('значение не показывается людям: ни в карточке, ни в истории, ни в экспорте, ссылками не делится'))));
  let requireApproval = !!existing?.require_approval;
  const raToggle = el('label', { class: 'row', style: { gap: '8px', cursor: 'pointer' } },
    el('span', { class: `toggle ${requireApproval ? 'on' : ''}`, role: 'switch', 'aria-checked': String(requireApproval), tabindex: 0, 'data-testid': 'require-approval', onclick: (e) => {
      requireApproval = !requireApproval; e.currentTarget.classList.toggle('on', requireApproval); e.currentTarget.setAttribute('aria-checked', String(requireApproval));
    }, onkeydown: (e) => { if (e.key === ' ' || e.key === 'Enter') { e.preventDefault(); e.currentTarget.click(); } } }),
    el('div', null, el('div', { class: 'small' }, tr('Требует подтверждения второго лица')), el('div', { class: 'xs faint' }, tr('человек прочитает значение только после одобрения подтверждающим (Настройки → Подтверждение чтения); машины читают как обычно'))));
  const quick = (days) => el('button', { type: 'button', class: 'chip', onclick: () => { const d = new Date(); d.setDate(d.getDate() + days); expires.value = d.toISOString().slice(0, 10); } }, days >= 365 ? tr`${Math.round(days / 365)} г` : tr`${days} дн`);
  const save = async () => {
    const body = { folder_id: folderId, name: name.value.trim(), value: value.value, login: login.value.trim(), url: url.value.trim(), tags: tagsInp.value.split(',').map(t => t.trim()).filter(Boolean).join(','), notes: notes.value, totp_seed: totp.value.trim(), machine_only: machineOnly, require_approval: requireApproval };
    if (genOn && !existing) { body.generate = genSpec; body.value = ''; }
    if (!body.name) return toast(tr('Имя обязательно'), 'error');
    if (!body.value && !body.generate && !existing) return toast(tr('Значение пустое'), 'error');
    try {
      if (existing) {
        const patch = { name: body.name, login: body.login, url: body.url, tags: body.tags, notes: body.notes, folder_id: folderId, machine_only: machineOnly, require_approval: requireApproval };
        if (body.value) patch.value = body.value;      // an empty field means "keep" (machine-only cards never show the value)
        if (body.totp_seed) patch.totp_seed = body.totp_seed;
        if (expires.value) patch.expires_at = expires.value; else if (existing.expires_at) patch.clear_expires = true;
        await api.updateSecret(existing.id, patch);
      } else {
        if (expires.value) body.expires_at = expires.value;
        const r = await api.createSecret(body); secretId = r.id;
      }
      d.close(); await refreshData(); renderSidebar(); renderList();
      if (secretId) goSecret(secretId); else renderDetail();
      toast(tr('Сохранено'), 'ok');
    } catch (e) { toast(e.message, 'error'); }
  };
  const d = drawer(existing ? tr('Редактировать секрет') : tr('Новый секрет'), [
    el('div', { class: 'field' }, el('label', null, tr('Имя')), name),
    el('div', { class: 'field' }, el('label', null, tr('Папка')), folderPicker(folderId, (id) => { folderId = id; })),
    (() => { valueField.append(el('div', { class: 'field-row' }, el('label', null, existing?.machine_only ? tr('Новое значение (текущее скрыто; пусто — не менять)') : tr('Значение')), genBtn), value, meter, genWrap); return valueField; })(),
    genToggle, genChips, moToggle, raToggle,
    el('div', { class: 'field' }, el('label', null, tr('Логин (email/username, опц.)')), login),
    el('div', { class: 'grid-2' }, el('div', { class: 'field' }, el('label', null, 'URL'), url), el('div', { class: 'field' }, el('label', null, tr('Теги (через запятую)')), tagsInp, dl)),
    el('div', { class: 'field' }, el('div', { class: 'field-row' }, el('label', null, tr('Срок ротации')), el('div', { class: 'chips' }, quick(30), quick(90), quick(180), quick(365), el('button', { type: 'button', class: 'chip', onclick: () => { expires.value = ''; } }, tr('без срока')))), expires,
      el('span', { class: 'xs faint' }, tr('За 30 дней до срока секрет попадёт в «Истекают» и в отчёт о здоровье'))),
    el('div', { class: 'field' }, el('label', null, tr('TOTP seed (base32, опц.)')), totp),
    el('div', { class: 'field' }, el('label', null, tr('Заметки')), notes),
  ], [
    el('button', { class: 'btn primary', onclick: save }, icon('check', 14), tr('Сохранить')),
    el('button', { class: 'btn', onclick: () => d.close() }, tr('Отмена')),
    el('span', { class: 'xs faint', style: { marginLeft: 'auto', alignSelf: 'center' } }, '⌘↵'),
  ]);
  d.addEventListener('keydown', (e) => { if ((e.metaKey || e.ctrlKey) && e.key === 'Enter') { e.preventDefault(); save(); } });
  (focusField === 'expires' ? expires : name).focus();
}
function showFolderEditor() {
  const name = el('input', { class: 'input', placeholder: tr('например, prod или clients/acme'), autocomplete: 'off' });
  const desc = el('input', { class: 'input', placeholder: tr('Описание (опционально)') });
  const create = async () => {
    if (!name.value.trim()) return toast(tr('Имя обязательно'), 'error');
    try { const r = await api.createFolder(name.value.trim(), desc.value.trim()); m.remove(); toast(tr('Папка создана'), 'ok'); await refreshData(); go('folder', r.id); } catch (e) { toast(e.message, 'error'); }
  };
  name.addEventListener('keydown', e => { if (e.key === 'Enter') create(); });
  const m = modal({ narrow: true }, el('h2', null, icon('folder', 18), tr('Новая папка')),
    el('p', { class: 'muted small', style: { margin: 0 } }, tr('У папки свой ключ шифрования; токены выдаются на папку целиком.')),
    el('div', { class: 'field' }, el('label', null, tr('Имя')), name), el('div', { class: 'field' }, el('label', null, tr('Описание')), desc),
    el('div', { class: 'foot' }, el('button', { class: 'btn', onclick: () => m.remove() }, tr('Отмена')), el('button', { class: 'btn primary', onclick: create }, tr('Создать'))));
}
function showMoveDialog(s) {
  let target = s.folder_id;
  const m = modal({ narrow: true }, el('h2', null, icon('folder_in', 18), tr`Переместить «${s.name}»`),
    el('p', { class: 'muted small', style: { margin: 0 } }, tr('Секрет будет перешифрован ключом новой папки. Токены старой папки перестанут его видеть, токены новой — увидят.')),
    folderPicker(s.folder_id, (id) => { target = id; }),
    el('div', { class: 'foot' }, el('button', { class: 'btn', onclick: () => m.remove() }, tr('Отмена')),
      el('button', { class: 'btn primary', onclick: async () => {
        if (target === s.folder_id) return m.remove();
        try { await api.updateSecret(s.id, { folder_id: target }); m.remove(); toast(tr('Перемещён'), 'ok'); await refreshData(); go('folder', target, s.id); } catch (e) { toast(e.message, 'error'); }
      } }, tr('Переместить'))));
}
async function showShareDialog(secretId, secretName) {
  const ttl = el('input', { type: 'number', class: 'input', value: '60', min: 1, max: 10080 });
  const uses = el('input', { type: 'number', class: 'input', value: '1', min: 1, max: 100 });
  const note = el('input', { class: 'input', placeholder: tr('например: пароль от стенда, после входа смени') });
  // two kinds of link: a page for a person (default) or raw JSON for a script; the choice is remembered
  let kind = PREFS.get('share_kind', 'human');
  const kindHint = el('div', { class: 'xs faint' });
  const setKind = (k) => { kind = k; PREFS.set('share_kind', k); kindHint.textContent = k === 'human' ? tr('Получатель откроет страницу: имя, логин, значение с кнопкой «копировать», ваше сообщение. Ссылка вида /share/…') : tr('Скрипт получит JSON {name, login, value, uses_left, expires_at, note} по GET без авторизации. Ссылка вида /api/share/…'); };
  const kindSeg = el('div', { class: 'seg', 'data-testid': 'share-kind' },
    el('button', { type: 'button', class: kind === 'human' ? 'active' : '', onclick: (e) => { setKind('human'); [...e.currentTarget.parentNode.children].forEach(b => b.classList.toggle('active', b === e.currentTarget)); } }, icon('user', 13), tr('Для человека')),
    el('button', { type: 'button', class: kind === 'machine' ? 'active' : '', onclick: (e) => { setKind('machine'); [...e.currentTarget.parentNode.children].forEach(b => b.classList.toggle('active', b === e.currentTarget)); } }, icon('server', 13), tr('Для машины (JSON)')));
  setKind(kind);
  const m = modal({ narrow: true }, el('h2', null, icon('share', 18), tr`Поделиться: ${secretName}`),
    el('p', { class: 'muted small', style: { margin: 0 } }, tr('Публичная ссылка на просмотр без входа. Умирает по сроку или после N открытий; отозвать можно в разделе «Ссылки».')),
    el('div', { class: 'field' }, el('label', null, tr('Вид ссылки')), kindSeg, kindHint),
    el('div', { class: 'grid-2' }, el('div', { class: 'field' }, el('label', null, tr('Срок (минут)')), ttl), el('div', { class: 'field' }, el('label', null, tr('Макс. открытий')), uses)),
    el('div', { class: 'field' }, el('label', null, tr('Сообщение получателю (увидит при открытии)')), note),
    el('div', { class: 'foot' }, el('button', { class: 'btn', onclick: () => m.remove() }, tr('Отмена')),
      el('button', { class: 'btn primary', onclick: async () => {
        try {
          const r = await api.createShare({ secret_id: secretId, ttl_minutes: parseInt(ttl.value) || 60, max_uses: parseInt(uses.value) || 1, note: note.value || '' });
          const fullUrl = `${location.origin}${kind === 'machine' ? r.url.replace('/share/', '/api/share/') : r.url}`; m.remove();
          const m2 = modal({ narrow: true }, el('h2', null, icon('link', 18), tr('Ссылка создана')),
            el('p', { class: 'muted small', style: { margin: 0 } }, kind === 'machine' ? tr('Для машины: GET по этой ссылке вернёт JSON. Каждый запрос — одно открытие.') : tr('Для человека: страница с именем, логином и значением. Открытие страницы считается использованием — предупреди получателя, что ссылка одноразовая.')),
            el('div', { class: 'codebox', style: { fontSize: '12px', letterSpacing: 0 } }, fullUrl),
            el('div', { class: 'foot' }, el('button', { class: 'btn', onclick: () => m2.remove() }, tr('Закрыть')), el('button', { class: 'btn primary', onclick: () => copyText(fullUrl, tr('Ссылка')) }, icon('copy', 14), tr('Копировать'))));
        } catch (e) { toast(e.message, 'error'); }
      } }, tr('Создать ссылку'))));
}

// ── public share page (/share/<token>) — no session, nothing else of the app ─────────
function renderSharePage(token) {
  const app = clear(document.getElementById('app'));
  const card = el('div', { class: 'card stack', style: { maxWidth: '520px', gap: '16px' } });
  const show = (...nodes) => { clear(card).append(brandBlock(''), ...nodes); };
  const open = async () => {
    show(el('div', { class: 'empty' }, el('span', { class: 'spin' }, icon('refresh', 20))));
    let d;
    try { d = await api.req('GET', `/api/share/${encodeURIComponent(token)}`); }
    catch (e) {
      const msg = e.status === 410 ? tr('Ссылка истекла или уже была открыта. Значение повторно не выдаётся — попроси отправителя создать новую.')
        : e.status === 404 ? tr('Ссылка не найдена или отозвана отправителем.') : tr`Не удалось открыть: ${e.message}`;
      return show(el('div', { class: 'callout danger' }, icon('alert', 18), el('div', null, msg)));
    }
    const isNote = d.kind === 'note';
    const val = el('div', { class: 'codebox secret-blur', style: { fontSize: isNote ? '14px' : '15px', letterSpacing: isNote ? 0 : '.02em', textAlign: 'left', wordBreak: isNote ? 'break-word' : 'break-all', whiteSpace: isNote ? 'pre-wrap' : 'normal', fontFamily: isNote ? 'var(--font)' : 'var(--mono)', maxHeight: '50vh', overflowY: 'auto' } }, d.value);
    const reveal = el('button', { class: 'btn', onclick: () => { const h = val.classList.toggle('secret-blur'); clear(reveal).append(icon(h ? 'eye' : 'eye_off', 14), h ? tr('Показать') : tr('Скрыть')); } }, icon('eye', 14), tr('Показать'));
    const rows = [];
    if (d.login) rows.push(el('div', { class: 'field' }, el('div', { class: 'field-row' }, el('label', null, tr('Логин')), el('button', { class: 'btn ghost icon sm', onclick: () => copyText(d.login, tr('Логин')) }, icon('copy', 14))), el('div', { class: 'codebox', style: { fontSize: '14px', letterSpacing: 0, textAlign: 'left' } }, d.login)));
    rows.push(el('div', { class: 'field' }, el('div', { class: 'field-row' }, el('label', null, isNote ? tr('Заметка') : tr('Значение')), el('div', { class: 'row' }, reveal, el('button', { class: 'btn primary', onclick: () => copyText(d.value, d.name) }, icon('copy', 14), tr('Копировать')))), val));
    if (d.note) rows.push(el('div', { class: 'callout info' }, icon('info', 16), el('div', null, el('div', { class: 'xs muted' }, tr('Сообщение от отправителя')), d.note)));
    show(el('div', null, el('div', { class: 'xs muted' }, isNote ? tr('Вам передали заметку') : tr('Вам передали секрет')), el('h2', { style: { margin: '2px 0 0', fontSize: '18px' } }, d.name)),
      ...rows,
      el('div', { class: 'callout warn' }, icon('alert', 16), el('div', { class: 'small' }, d.uses_left > 0 ? tr`Сохрани значение сейчас. Ссылку можно открыть ещё ${d.uses_left} раз, до ${fmtDate(d.expires_at)}.` : tr('Сохрани значение сейчас: ссылка одноразовая и уже использована, повторно страница не откроется.'))),
      el('div', { class: 'xs faint', style: { textAlign: 'center' } }, 'APS Vault · ', el('a', { href: 'https://github.com/kzhebenev/aps-vault', target: '_blank', rel: 'noopener' }, tr('что это'))));
  };
  show(el('div', null, el('div', { class: 'xs muted' }, tr('Вам передали секрет')), el('p', { class: 'muted', style: { margin: '6px 0 0' } }, tr('Ссылка одноразовая: открытие считается использованием. Открывай, когда готов сохранить значение.'))),
    el('button', { class: 'btn primary wide', onclick: open, 'data-testid': 'share-open' }, icon('unlock', 15), tr('Открыть секрет')),
    el('div', { class: 'xs faint', style: { textAlign: 'center' } }, 'APS Vault'));
  app.appendChild(el('div', { class: 'auth' }, card));
}

// ── share a note that is not a stored secret ──────────────────────────────────
function showNoteShareDialog() {
  const title = el('input', { class: 'input', placeholder: tr('Заголовок (увидит получатель)'), maxlength: 128, 'data-testid': 'note-title' });
  const text = el('textarea', { class: 'textarea', rows: 6, placeholder: tr('Текст заметки: адреса, временные пароли, инструкция… До 20 000 символов. Нигде не сохраняется, кроме самой ссылки.'), maxlength: 20000, 'data-testid': 'note-text' });
  const ttl = el('input', { type: 'number', class: 'input', value: '60', min: 1, max: 10080 });
  const uses = el('input', { type: 'number', class: 'input', value: '1', min: 1, max: 100 });
  const msg = el('input', { class: 'input', placeholder: tr('например: после входа смени пароль') });
  let kind = PREFS.get('share_kind', 'human');
  const kindSeg = el('div', { class: 'seg' },
    el('button', { type: 'button', class: kind === 'human' ? 'active' : '', onclick: (e) => { kind = 'human'; PREFS.set('share_kind', kind); [...e.currentTarget.parentNode.children].forEach(b => b.classList.toggle('active', b === e.currentTarget)); } }, icon('user', 13), tr('Для человека')),
    el('button', { type: 'button', class: kind === 'machine' ? 'active' : '', onclick: (e) => { kind = 'machine'; PREFS.set('share_kind', kind); [...e.currentTarget.parentNode.children].forEach(b => b.classList.toggle('active', b === e.currentTarget)); } }, icon('server', 13), tr('Для машины (JSON)')));
  const m = modal(el('h2', null, icon('note', 18), tr('Поделиться заметкой')),
    el('p', { class: 'muted small', style: { margin: 0 } }, tr('Одноразовая ссылка на текст, который не нужно хранить как секрет: доступы для подрядчика, временный пароль, кусок конфига. Текст шифруется ключом из самой ссылки; когда ссылка умирает, текста больше нет.')),
    el('div', { class: 'field' }, el('label', null, tr('Заголовок')), title),
    el('div', { class: 'field' }, el('label', null, tr('Текст')), text),
    el('div', { class: 'field' }, el('label', null, tr('Вид ссылки')), kindSeg),
    el('div', { class: 'grid-2' }, el('div', { class: 'field' }, el('label', null, tr('Срок (минут)')), ttl), el('div', { class: 'field' }, el('label', null, tr('Макс. открытий')), uses)),
    el('div', { class: 'field' }, el('label', null, tr('Сообщение получателю (увидит при открытии)')), msg),
    el('div', { class: 'foot' }, el('button', { class: 'btn', onclick: () => m.remove() }, tr('Отмена')),
      el('button', { class: 'btn primary', 'data-testid': 'note-share-create', onclick: async () => {
        if (!text.value.trim()) return toast(tr('Текст пустой'), 'error');
        try {
          const r = await api.createNoteShare({ text: text.value, title: title.value.trim(), ttl_minutes: parseInt(ttl.value) || 60, max_uses: parseInt(uses.value) || 1, note: msg.value || '' });
          const fullUrl = `${location.origin}${kind === 'machine' ? r.url.replace('/share/', '/api/share/') : r.url}`; m.remove();
          const m2 = modal({ narrow: true }, el('h2', null, icon('link', 18), tr('Ссылка создана')),
            el('p', { class: 'muted small', style: { margin: 0 } }, tr('Текст заметки живёт только в этой ссылке. Отозвать можно в разделе «Ссылки».')),
            el('div', { class: 'codebox', style: { fontSize: '12px', letterSpacing: 0 }, 'data-testid': 'note-share-url' }, fullUrl),
            el('div', { class: 'foot' }, el('button', { class: 'btn', onclick: () => m2.remove() }, tr('Закрыть')), el('button', { class: 'btn primary', onclick: () => copyText(fullUrl, tr('Ссылка')) }, icon('copy', 14), tr('Копировать'))));
          if (state.route.view === 'shares') onRoute();
        } catch (e) { toast(e.message, 'error'); }
      } }, tr('Создать ссылку'))));
}

// ── palette, help, keys, auto-lock, drop ────────────────────────────────────
function openPalette() {
  if (document.getElementById('palette')) return;
  const input = el('input', { class: 'input', placeholder: tr('Поиск: имя, тег, URL, папка…  Enter — открыть, ⌘Enter — скопировать'), autocomplete: 'off' });
  const results = el('div', { class: 'results' }); let idx = 0, matches = [];
  const overlay = el('div', { class: 'overlay top', id: 'palette', onclick: (e) => { if (e.target === overlay) overlay.remove(); } },
    el('div', { class: 'palette' }, input, results, el('div', { class: 'hint' }, el('span', null, kbd('↑↓'), ' ', tr('выбор')), el('span', null, kbd('↵'), ' ', tr('открыть')), el('span', null, kbd('⌘↵'), ' ', tr('копировать')), el('span', null, kbd('esc'), ' ', tr('закрыть')))));
  document.body.appendChild(overlay); setTimeout(() => input.focus(), 20);
  const score = (s, q) => { const t = `${s.name} ${s.tags} ${s.url} ${s.folder_name}`.toLowerCase(); if (s.name.toLowerCase().startsWith(q)) return 3; if (t.includes(q)) return 2; let j = 0; for (const c of s.name.toLowerCase()) { if (c === q[j]) j++; if (j === q.length) return 1; } return 0; };
  const refresh = () => {
    const q = input.value.trim().toLowerCase(); clear(results);
    matches = q ? state.secrets.map(s => ({ s, sc: score(s, q) })).filter(x => x.sc > 0).sort((a, b) => b.sc - a.sc).map(x => x.s).slice(0, 40)
                : [...state.secrets].sort((a, b) => (b.last_accessed || '').localeCompare(a.last_accessed || '')).slice(0, 10);
    if (!q) results.appendChild(el('div', { class: 'xs faint', style: { padding: '4px 10px' } }, tr('Недавно открытые')));
    idx = Math.min(idx, Math.max(0, matches.length - 1));
    matches.forEach((s, i) => results.appendChild(el('div', { class: `res ${i === idx ? 'active' : ''}`, onclick: () => { overlay.remove(); goSecret(s.id); } },
      avatar(s.name, 26), el('span', { class: 'truncate', style: { flex: 1 } }, s.name), el('span', { class: 'xs muted' }, s.folder_name), s.has_totp ? el('span', { class: 'badge ok' }, 'TOTP') : null)));
    if (!matches.length) results.appendChild(el('div', { class: 'empty', style: { padding: '24px' } }, tr('Ничего не найдено')));
  };
  input.addEventListener('input', () => { idx = 0; refresh(); });
  input.addEventListener('keydown', async (e) => {
    if (e.key === 'Escape') return overlay.remove();
    if (e.key === 'ArrowDown') { e.preventDefault(); idx = Math.min(idx + 1, matches.length - 1); refresh(); }
    else if (e.key === 'ArrowUp') { e.preventDefault(); idx = Math.max(idx - 1, 0); refresh(); }
    else if (e.key === 'Enter' && matches[idx]) {
      const s = matches[idx]; overlay.remove();
      if (e.metaKey || e.ctrlKey) { try { const f = await api.getSecret(s.id); copyText(f.value, s.name); } catch (er) { toast(er.message, 'error'); } } else goSecret(s.id);
    }
  });
  refresh();
}
function showHelp() {
  const rows = [['⌘K', tr('поиск по всему хранилищу')], ['/', tr('фокус в строку поиска')], ['N', tr('новый секрет')], ['J / K, ↑ / ↓', tr('по списку')], ['Enter', tr('открыть выбранный')], ['C', tr('скопировать значение выбранного')],
    ['S', tr('поделиться заметкой (одноразовая ссылка на текст)')], ['⌘E', tr('экспорт JSON')], ['⌘↵', tr('сохранить в редакторе')], ['Esc', tr('закрыть окно / сбросить поиск')], ['?', tr('эта подсказка')]];
  const m = modal({ narrow: true }, el('h2', null, icon('help', 18), tr('Горячие клавиши')),
    el('div', { class: 'help-grid' }, ...rows.map(([k, d]) => el('div', null, el('span', { class: 'muted' }, d), kbd(k)))),
    el('div', { class: 'foot' }, el('button', { class: 'btn primary', onclick: () => m.remove() }, tr('Закрыть'))));
}
function setupGlobalKeys() {
  document.addEventListener('keydown', async (e) => {
    const inField = /^(INPUT|TEXTAREA|SELECT)$/.test(e.target.tagName) || e.target.isContentEditable;
    if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') { e.preventDefault(); return openPalette(); }
    if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'e') { e.preventDefault(); return PAGES.exportVault(); }
    if (e.key === 'Escape') { const o = topOverlay(); if (o) { o.close ? o.close() : o.remove(); return; } }
    if (inField || e.metaKey || e.ctrlKey || e.altKey) return;
    const items = state._visible || [];
    const moveFocus = (d) => { if (!items.length) return; state.focus = Math.max(0, Math.min(items.length - 1, (state.focus < 0 ? (d > 0 ? -1 : 0) : state.focus) + d)); renderList(); document.querySelector('.item.focused')?.scrollIntoView({ block: 'nearest' }); };
    if (e.key === '/') { e.preventDefault(); document.getElementById('search')?.focus(); }
    else if (e.key === '?') { e.preventDefault(); showHelp(); }
    else if (e.key.toLowerCase() === 'n' && !isPage(state.route.view)) { e.preventDefault(); showSecretEditor(); }
    else if (e.key.toLowerCase() === 's' && !topOverlay()) { e.preventDefault(); showNoteShareDialog(); }
    else if (e.key === 'j' || e.key === 'ArrowDown') { if (!isPage(state.route.view)) { e.preventDefault(); moveFocus(1); } }
    else if (e.key === 'k' || e.key === 'ArrowUp') { if (!isPage(state.route.view)) { e.preventDefault(); moveFocus(-1); } }
    else if (e.key === 'Enter' && state.focus >= 0 && items[state.focus]) { goSecret(items[state.focus].id); }
    else if (e.key.toLowerCase() === 'c') {
      const s = (state.focus >= 0 && items[state.focus]) || (state.route.secret && state.secrets.find(x => x.id === state.route.secret));
      if (s) { e.preventDefault(); try { const f = state.detail?.id === s.id ? state.detail : await api.getSecret(s.id); copyText(f.value, s.name); } catch (er) { toast(er.message, 'error'); } }
    }
  });
}
function setupAutoLock() {
  const reset = () => { state.lastActivity = Date.now(); };
  ['mousemove', 'keydown', 'click', 'scroll', 'touchstart'].forEach(ev => document.addEventListener(ev, reset, { passive: true }));
  setInterval(async () => {
    const min = state.prefs.autolockMin; if (!min) return;
    if (Date.now() - state.lastActivity > min * 60 * 1000) { try { await api.lock(); } catch {} location.hash = ''; location.reload(); }
  }, 15 * 1000);
}
function setupDropCreds() {
  let zone = null;
  const show = () => { if (zone) return; zone = el('div', { class: 'dropzone' }, el('div', { class: 'card pad', style: { textAlign: 'center', pointerEvents: 'none' } }, icon('download', 32), el('h3', { style: { margin: '8px 0 4px' } }, tr('Отпусти — создам секрет')), el('p', { class: 'muted small', style: { margin: 0 } }, tr('Текст с логином/паролем/URL будет разобран автоматически')))); document.body.appendChild(zone); };
  const hide = () => { zone?.remove(); zone = null; };
  document.addEventListener('dragover', (e) => { if (!state.unlocked || !e.dataTransfer?.types?.includes('text/plain')) return; e.preventDefault(); show(); });
  document.addEventListener('dragleave', (e) => { if (e.clientX <= 0 || e.clientY <= 0 || e.clientX >= innerWidth || e.clientY >= innerHeight) hide(); });
  document.addEventListener('drop', (e) => { if (!state.unlocked) return; hide(); const text = e.dataTransfer?.getData('text/plain'); if (!text) return; e.preventDefault(); showDropParser(text); });
}
function parseCreds(text) {
  const out = { name: '', value: '', login: '', url: '', totp_seed: '', notes: '', folder_id: null };
  const lines = text.split('\n').map(l => l.trim()).filter(Boolean);
  for (const line of lines) {
    if (!out.url) { const m = /https?:\/\/[^\s]+/i.exec(line); if (m) out.url = m[0]; }
    const kv = /^([a-z_\s\-]+)\s*[:=]\s*(.+)$/i.exec(line);
    if (kv) {
      const k = kv[1].trim().toLowerCase(), v = kv[2].trim();
      if (/(login|user(name)?|email|account|логин|почта)/.test(k) && !out.login) out.login = v;
      else if (/(pass(word)?|пароль)/.test(k) && !out.value) out.value = v;
      else if (/(totp|2fa|otp|seed)/.test(k) && !out.totp_seed) out.totp_seed = v;
      else if (/(url|сайт|host|address)/.test(k) && !out.url) out.url = v;
      else if (/(name|имя|title)/.test(k) && !out.name) out.name = v;
      continue;
    }
    if (!out.login && /^[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}$/i.test(line)) out.login = line;
  }
  if (!out.value) for (const line of lines) {
    if (line.length < 6 || line === out.login || line === out.url || /^https?:\/\//.test(line) || /^[a-z_\s\-]+\s*[:=]/i.test(line) || /^[a-z0-9._%+-]+@/i.test(line)) continue;
    out.value = line; break;
  }
  if (!out.name) {
    if (out.url) { try { const u = new URL(out.url.startsWith('http') ? out.url : 'https://' + out.url); out.name = u.hostname + (out.login ? ' — ' + out.login : ''); } catch { out.name = out.url; } }
    else if (out.login) out.name = out.login; else out.name = tr('Новый секрет ') + new Date().toISOString().slice(0, 16);
  }
  out.notes = lines.filter(l => l !== out.value && l !== out.login && l !== out.url && l !== out.totp_seed).join('\n');
  if (out.url) try {
    const host = new URL(out.url.startsWith('http') ? out.url : 'https://' + out.url).hostname;
    const hits = state.secrets.filter(s => s.url && (hostOf(s.url) === host));
    if (hits.length) { const c = {}; for (const h of hits) c[h.folder_id] = (c[h.folder_id] || 0) + 1; out.folder_id = parseInt(Object.entries(c).sort((a, b) => b[1] - a[1])[0][0]); }
  } catch {}
  return out;
}
function showDropParser(text) {
  const p = parseCreds(text); let folderId = p.folder_id;
  const nameInp = el('input', { class: 'input', value: p.name }); const loginInp = el('input', { class: 'input', value: p.login });
  const valInp = el('textarea', { rows: 2, class: 'textarea mono' }); valInp.value = p.value;
  const urlInp = el('input', { class: 'input', value: p.url }); const totpInp = el('input', { class: 'input mono', value: p.totp_seed });
  const notesInp = el('textarea', { rows: 2, class: 'textarea' }); notesInp.value = p.notes;
  const hint = p.folder_id ? el('div', { class: 'callout ok' }, icon('check', 14), tr`Папка угадана по URL: «${state.folders.find(f => f.id === p.folder_id)?.name || ''}»`) : el('div', { class: 'callout info' }, icon('info', 14), tr('Папка не угадалась — выбери вручную'));
  const d = drawer(tr('Секрет из перетащенного текста'), [hint,
    el('div', { class: 'field' }, el('label', null, tr('Имя')), nameInp),
    el('div', { class: 'field' }, el('label', null, tr('Папка')), folderPicker(folderId, (id) => { folderId = id; })),
    el('div', { class: 'grid-2' }, el('div', { class: 'field' }, el('label', null, tr('Логин')), loginInp), el('div', { class: 'field' }, el('label', null, 'URL'), urlInp)),
    el('div', { class: 'field' }, el('label', null, tr('Значение')), valInp, strengthMeter(valInp)),
    el('div', { class: 'field' }, el('label', null, tr('TOTP seed (опц.)')), totpInp),
    el('div', { class: 'field' }, el('label', null, tr('Заметки')), notesInp)],
    [el('button', { class: 'btn primary', onclick: async () => {
      if (!nameInp.value.trim()) return toast(tr('Имя обязательно'), 'error');
      if (!valInp.value.trim()) return toast(tr('Значение пустое'), 'error');
      try {
        const r = await api.createSecret({ folder_id: folderId, name: nameInp.value.trim(), value: valInp.value, login: loginInp.value.trim(), url: urlInp.value || '', tags: '', notes: notesInp.value.trim(), totp_seed: totpInp.value || '' });
        d.close(); await refreshData(); toast(tr('Секрет создан'), 'ok'); go('folder', folderId, r.id);
      } catch (e) { toast(e.message, 'error'); }
    } }, icon('check', 14), tr('Сохранить')), el('button', { class: 'btn', onclick: () => d.close() }, tr('Отмена'))]);
}

window.PAGES = window.PAGES || {};
