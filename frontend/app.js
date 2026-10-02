// APS Vault — vanilla JS client.
// Без эмодзи: только строгие SVG-иконки (Lucide-style outline, 1.5 stroke).
// XSS защита: никакого innerHTML с untrusted, только textContent/createElement.

const state = {
  initialized: null, unlocked: false,
  folders: [], secrets: [],
  selectedFolder: null, searchQuery: '', tagFilter: null,
  expandedFolders: new Set(JSON.parse(localStorage.getItem('vault_expanded') || '[]')),
  tokens: [],
  // v0.3
  paletteOpen: false,        // Cmd+K
  paletteIndex: 0,
  keyboardFocus: { type: 'folder', id: null },   // для tree-нав
  lastActivity: Date.now(),  // auto-lock
};

function saveExpanded() {
  localStorage.setItem('vault_expanded', JSON.stringify([...state.expandedFolders]));
}

// CSRF: backend выставляет non-httpOnly cookie `vault_csrf` при unlock,
// дублирует в /unlock body как csrf_token. Кладём в localStorage для надёжности
// и в каждом write-запросе шлём в X-CSRF-Token.
function getCsrf() {
  const m = document.cookie.match(/(?:^|;)\s*vault_csrf=([^;]+)/);
  if (m) return decodeURIComponent(m[1]);
  return localStorage.getItem('vault_csrf') || '';
}
function setCsrf(t) {
  if (t) localStorage.setItem('vault_csrf', t);
}

const api = {
  async req(method, url, body) {
    const opts = { method, credentials: 'include', headers: {} };
    if (body !== undefined) {
      opts.headers['Content-Type'] = 'application/json';
      opts.body = JSON.stringify(body);
    }
    if (!['GET', 'HEAD', 'OPTIONS'].includes(method)) {
      const t = getCsrf();
      if (t) opts.headers['X-CSRF-Token'] = t;
    }
    const r = await fetch(url, opts);
    const text = await r.text();
    const data = text ? JSON.parse(text) : null;
    if (!r.ok) throw new Error(data?.detail || `HTTP ${r.status}`);
    // Запоминаем CSRF из unlock/init response
    if (data?.csrf_token) setCsrf(data.csrf_token);
    return data;
  },
  health: () => api.req('GET', '/api/health'),
  init: (mp, init_token) => api.req('POST', '/api/init', { master_password: mp, init_token: init_token || '' }),
  unlock: (mp, totp_code) => api.req('POST', '/api/auth/unlock',
    totp_code ? { master_password: mp, totp_code } : { master_password: mp }),
  lock: () => api.req('POST', '/api/auth/lock'),
  twofaStatus: () => api.req('GET', '/api/auth/2fa/status'),
  twofaSetup: () => api.req('POST', '/api/auth/2fa/setup'),
  twofaVerify: (code, secret_base32) => api.req('POST', '/api/auth/2fa/verify', { code, secret_base32 }),
  twofaDisable: (totp_code) => api.req('POST', '/api/auth/2fa/disable', { totp_code }),
  recover: (recovery_code, new_master_password) =>
    api.req('POST', '/api/auth/recover', { recovery_code, new_master_password }),
  // v0.3
  toggleFavorite: (id) => api.req('POST', `/api/secrets/${id}/favorite`),
  history: (id) => api.req('GET', `/api/secrets/${id}/history`),
  createShare: (data) => api.req('POST', '/api/share', data),
  listShares: () => api.req('GET', '/api/shares'),
  revokeShare: (id) => api.req('DELETE', `/api/shares/${id}`),
  stats: () => api.req('GET', '/api/stats'),
  exportJson: () => api.req('GET', '/api/export'),
  importJson: (data) => api.req('POST', '/api/import', data),
  listWebhooks: () => api.req('GET', '/api/webhooks'),
  createWebhook: (data) => api.req('POST', '/api/webhooks', data),
  deleteWebhook: (id) => api.req('DELETE', `/api/webhooks/${id}`),
  listFolders: () => api.req('GET', '/api/folders'),
  createFolder: (name, description) => api.req('POST', '/api/folders', { name, description }),
  deleteFolder: (id) => api.req('DELETE', `/api/folders/${id}`),
  listSecrets: (folder_id, q) => {
    const p = new URLSearchParams();
    if (folder_id) p.set('folder_id', folder_id);
    if (q) p.set('q', q);
    return api.req('GET', `/api/secrets?${p}`);
  },
  createSecret: (d) => api.req('POST', '/api/secrets', d),
  getSecret: (id) => api.req('GET', `/api/secrets/${id}`),
  updateSecret: (id, d) => api.req('PATCH', `/api/secrets/${id}`, d),
  deleteSecret: (id) => api.req('DELETE', `/api/secrets/${id}`),
  listTokens: () => api.req('GET', '/api/tokens'),
  createToken: (d) => api.req('POST', '/api/tokens', d),
  revokeToken: (id) => api.req('DELETE', `/api/tokens/${id}`),
  audit: (lim) => api.req('GET', `/api/audit?limit=${lim || 100}`),
};

// ── DOM helpers ─────────────────────────────────────────────────────────────
function el(tag, props, ...children) {
  const e = document.createElement(tag);
  if (props) {
    for (const [k, v] of Object.entries(props)) {
      if (k === 'class') e.className = v;
      else if (k === 'style' && typeof v === 'object') Object.assign(e.style, v);
      else if (k.startsWith('on') && typeof v === 'function') e.addEventListener(k.slice(2).toLowerCase(), v);
      else if (k === 'dataset') Object.assign(e.dataset, v);
      else if (k in e) e[k] = v;
      else e.setAttribute(k, v);
    }
  }
  for (const c of children.flat()) {
    if (c == null || c === false) continue;
    if (typeof c === 'string' || typeof c === 'number') e.appendChild(document.createTextNode(String(c)));
    else e.appendChild(c);
  }
  return e;
}
function clear(n) { while (n.firstChild) n.removeChild(n.firstChild); }

// ── SVG icons (Lucide-style, минимальный набор) ─────────────────────────────
function icon(name, size = 16) {
  const paths = {
    lock:       'M19 11H5a2 2 0 0 0-2 2v7a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7a2 2 0 0 0-2-2zM7 11V7a5 5 0 0 1 10 0v4',
    unlock:     'M19 11H5a2 2 0 0 0-2 2v7a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7a2 2 0 0 0-2-2zM7 11V7a5 5 0 0 1 9.9-1',
    key:        'M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4',
    eye:        'M2 12s3-7 10-7 10 7 10 7-3 7-10 7-10-7-10-7zM12 9a3 3 0 1 0 0 6 3 3 0 0 0 0-6z',
    eye_off:    'M9.88 9.88a3 3 0 0 0 4.24 4.24M10.73 5.08A10.43 10.43 0 0 1 12 5c7 0 10 7 10 7a13.16 13.16 0 0 1-1.67 2.68M6.61 6.61A13.526 13.526 0 0 0 2 12s3 7 10 7a9.74 9.74 0 0 0 5.39-1.61M2 2l20 20',
    copy:       'M9 9h10a2 2 0 0 1 2 2v10a2 2 0 0 1-2 2H9a2 2 0 0 1-2-2V11a2 2 0 0 1 2-2zM5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1',
    plus:       'M5 12h14M12 5v14',
    x:          'M18 6L6 18M6 6l12 12',
    folder:     'M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z',
    search:     'M11 19a8 8 0 1 0 0-16 8 8 0 0 0 0 16zM21 21l-4.35-4.35',
    log:        'M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8zM14 2v6h6M16 13H8M16 17H8M10 9H8',
    pencil:     'M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4z',
    trash:      'M3 6h18M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2M10 11v6M14 11v6',
    check:      'M20 6L9 17l-5-5',
    shield:     'M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z',
    inbox:      'M22 12h-6l-2 3h-4l-2-3H2M5.45 5.11L2 12v6a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-6l-3.45-6.89A2 2 0 0 0 16.76 4H7.24a2 2 0 0 0-1.79 1.11z',
    note:       'M4 4h16v16H4zM8 8h8M8 12h8M8 16h5',
    clock:      'M12 22a10 10 0 1 0 0-20 10 10 0 0 0 0 20zM12 6v6l4 2',
    info:       'M12 22a10 10 0 1 0 0-20 10 10 0 0 0 0 20zM12 16v-4M12 8h.01',
    alert:      'M12 9v4M12 17h.01M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z',
    chevron_right: 'M9 18l6-6-6-6',
    chevron_down:  'M6 9l6 6 6-6',
    file:       'M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8zM14 2v6h6',
    folder_open: 'M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2zM2 11h20',
    star:       'M12 2l3.09 6.26L22 9.27l-5 4.87 1.18 6.88L12 17.77l-6.18 3.25L7 14.14 2 9.27l6.91-1.01z',
    share:      'M18 8a3 3 0 1 0 0-6 3 3 0 0 0 0 6zM6 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6zM18 22a3 3 0 1 0 0-6 3 3 0 0 0 0 6zM8.59 13.51l6.83 3.98M15.41 6.51l-6.82 3.98',
    download:   'M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4M7 10l5 5 5-5M12 15V3',
    upload:     'M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4M17 8l-5-5-5 5M12 3v12',
    refresh:    'M23 4v6h-6M1 20v-6h6M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15',
  };
  const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
  svg.setAttribute('width', size); svg.setAttribute('height', size);
  svg.setAttribute('viewBox', '0 0 24 24');
  svg.setAttribute('fill', 'none');
  svg.setAttribute('stroke', 'currentColor');
  svg.setAttribute('stroke-width', '1.75');
  svg.setAttribute('stroke-linecap', 'round');
  svg.setAttribute('stroke-linejoin', 'round');
  svg.classList.add('inline-block');
  for (const d of paths[name].split('M').slice(1)) {
    const p = document.createElementNS('http://www.w3.org/2000/svg', 'path');
    p.setAttribute('d', 'M' + d);
    svg.appendChild(p);
  }
  return svg;
}

// ── Toast ────────────────────────────────────────────────────────────────────
function toast(msg, type = 'info') {
  const cls = type === 'error' ? 'bg-red-950 text-red-200 border-red-800' :
              type === 'success' ? 'bg-emerald-950 text-emerald-200 border-emerald-800' :
              'bg-slate-800 text-slate-100 border-slate-600';
  const e = el('div', { class: `fixed top-4 right-4 px-4 py-3 rounded-lg shadow-2xl z-50 max-w-md border ${cls}` }, msg);
  document.body.appendChild(e);
  setTimeout(() => e.remove(), 4000);
}

async function copyToClipboard(text, label = tr('значение')) {
  try {
    await navigator.clipboard.writeText(text);
    toast(tr`${label} в буфере — очистится через 30 сек`, 'success');
    setTimeout(async () => {
      try {
        const cur = await navigator.clipboard.readText();
        if (cur === text) { await navigator.clipboard.writeText(''); toast(tr('буфер очищен')); }
      } catch {}
    }, 30000);
  } catch { toast(tr('Не удалось скопировать'), 'error'); }
}

function timeAgo(iso) {
  if (!iso) return '';
  const sec = (Date.now() - new Date(iso).getTime()) / 1000;
  if (sec < 60) return Math.floor(sec) + tr(' сек назад');
  if (sec < 3600) return Math.floor(sec / 60) + tr(' мин назад');
  if (sec < 86400) return Math.floor(sec / 3600) + tr(' ч назад');
  if (sec < 86400 * 30) return Math.floor(sec / 86400) + tr(' дн назад');
  return new Date(iso).toLocaleDateString(I18N.locale);
}
function debounce(fn, ms) {
  let t; return (...a) => { clearTimeout(t); t = setTimeout(() => fn(...a), ms); };
}

// ── Modal helper ─────────────────────────────────────────────────────────────
function modal(...nodes) {
  const overlay = el('div', { class: 'fixed inset-0 bg-black/70 flex items-center justify-center z-50 p-6', onclick: (e) => { if (e.target === overlay) overlay.remove(); } });
  const card = el('div', { class: 'card rounded-xl p-6 max-w-2xl w-full max-h-[90vh] overflow-y-auto' }, ...nodes);
  overlay.appendChild(card);
  document.body.appendChild(overlay);
  return overlay;
}

// ── Init screen ──────────────────────────────────────────────────────────────
function renderInit() {
  const app = document.getElementById('app');
  clear(app);
  const mp1 = el('input', { type: 'password', class: 'input rounded-lg px-3 py-2 w-full font-mono', placeholder: tr('минимум 12 символов'), autofocus: true });
  const mp2 = el('input', { type: 'password', class: 'input rounded-lg px-3 py-2 w-full font-mono', placeholder: tr('повтор') });
  // init token from VAULT_INIT_TOKEN — proves the person at the form is the one who deployed it
  const initTok = el('input', { type: 'password', class: 'input rounded-lg px-3 py-2 w-full font-mono', placeholder: tr('init token (VAULT_INIT_TOKEN из .env)'), autocomplete: 'off' });
  const btn = el('button', { class: 'btn-primary text-white font-semibold rounded-lg py-2 px-4 w-full', onclick: async () => {
    if (mp1.value.length < 12) return toast(tr('master-password короче 12 символов'), 'error');
    if (mp1.value !== mp2.value) return toast(tr('пароли не совпадают'), 'error');
    try {
      const r = await api.init(mp1.value, initTok.value);
      showRecoveryCodeModal(r.recovery_code, () => location.reload());
    } catch (e) { toast(e.message, 'error'); }
  }}, tr('Инициализировать'));

  const warning = el('div', { class: 'text-xs text-slate-400 bg-amber-950/30 border border-amber-900/50 p-3 rounded-lg flex gap-2' },
    icon('alert', 18), el('div', null, tr('Master-password нельзя восстановить. При утере поможет только recovery-code, который покажется один раз после инициализации.')));

  app.appendChild(el('div', { class: 'min-h-screen flex items-center justify-center p-6' },
    el('div', { class: 'card rounded-xl p-8 max-w-lg w-full' },
      el('div', { class: 'text-center mb-6' },
        el('div', { class: 'inline-flex items-center justify-center w-14 h-14 rounded-full bg-slate-800 mb-3 text-slate-200' }, icon('lock', 26)),
        el('h1', { class: 'text-2xl font-semibold text-white' }, 'APS Vault'),
        el('p', { class: 'text-slate-400 text-sm mt-2' }, tr('Первый запуск — задай master-password'))),
      el('div', { class: 'space-y-4' },
        el('div', null, el('label', { class: 'text-sm text-slate-300 block mb-1' }, 'Master password'), mp1),
        el('div', null, el('label', { class: 'text-sm text-slate-300 block mb-1' }, tr('Подтверждение')), mp2),
        el('div', null, el('label', { class: 'text-sm text-slate-300 block mb-1' }, 'Init token'), initTok),
        warning, btn))));
}

function showRecoveryCodeModal(code, onClose) {
  const codeBox = el('div', { class: 'bg-slate-950 border border-emerald-900/60 rounded-lg p-4 font-mono text-lg text-center text-emerald-300 break-all select-all tracking-wider' }, code);
  const closeBtn = el('button', { class: 'btn-primary text-white font-semibold rounded-lg py-2 px-4 w-full mt-6', onclick: () => { overlay.remove(); onClose(); }}, tr('Я записал, продолжить'));
  const overlay = modal(
    el('h2', { class: 'text-lg font-semibold text-white mb-1 flex items-center gap-2' }, icon('key', 18), 'Recovery code'),
    el('p', { class: 'text-slate-400 text-sm mb-4' }, tr('Запиши код в надёжное место. Показывается ОДИН РАЗ. Без него и без master-password восстановления нет.')),
    codeBox, closeBtn
  );
}

// ── Unlock screen ────────────────────────────────────────────────────────────
function renderUnlock() {
  const app = document.getElementById('app');
  clear(app);
  const mp = el('input', { type: 'password', class: 'input rounded-lg px-3 py-2 w-full font-mono', placeholder: 'master password', autofocus: true });
  const submit = async () => {
    try {
      await api.unlock(mp.value);
      state.unlocked = true;
      await refreshMain();
      renderMain();
    } catch (e) { toast(e.message, 'error'); }
  };
  mp.addEventListener('keydown', e => { if (e.key === 'Enter') submit(); });
  const btn = el('button', { class: 'btn-primary text-white font-semibold rounded-lg py-2 px-4 w-full', onclick: submit }, tr('Войти'));

  // OIDC через Keycloak — кнопка появляется только если backend подтверждает enabled.
  const ssoBox = el('div', { class: 'space-y-2' });
  fetch('/api/auth/oidc/status', { credentials: 'same-origin' })
    .then(r => r.ok ? r.json() : { enabled: false })
    .then(d => {
      if (!d || !d.enabled) return;
      const sep = el('div', { class: 'flex items-center gap-3 text-xs text-slate-500 my-2' },
        el('div', { class: 'h-px flex-1 bg-slate-700' }),
        el('span', null, tr('или')),
        el('div', { class: 'h-px flex-1 bg-slate-700' }));
      const ssoBtn = el('a',
        { href: '/api/auth/oidc/login',
          class: 'card rounded-lg px-3 py-2 w-full flex items-center justify-center gap-2 text-slate-200 hover:text-white text-sm' },
        icon('key', 14), tr(' Войти через Keycloak'));
      ssoBox.appendChild(sep); ssoBox.appendChild(ssoBtn);
    })
    .catch(() => {});

  app.appendChild(el('div', { class: 'min-h-screen flex items-center justify-center p-6' },
    el('div', { class: 'card rounded-xl p-8 max-w-md w-full' },
      el('div', { class: 'text-center mb-6' },
        el('div', { class: 'inline-flex items-center justify-center w-14 h-14 rounded-full bg-slate-800 mb-3 text-slate-200' }, icon('lock', 26)),
        el('h1', { class: 'text-2xl font-semibold text-white' }, 'APS Vault'),
        el('p', { class: 'text-slate-400 text-sm mt-2' }, tr('Введи master-password'))),
      el('div', { class: 'space-y-4' }, mp, btn, ssoBox))));
}

async function refreshMain() {
  try {
    state.folders = await api.listFolders();
    state.secrets = await api.listSecrets(state.selectedFolder, state.searchQuery);
    // Доп. фильтр по тегу (клиентский — server-side нет)
    if (state.tagFilter) {
      state.secrets = state.secrets.filter(s => (s.tags || '').split(',').map(t => t.trim()).includes(state.tagFilter));
    }
  } catch (e) {
    if (e.message.includes('locked') || e.message.includes('session') || e.message.includes('invalid')) {
      state.unlocked = false; renderUnlock(); return;
    }
    toast(e.message, 'error');
  }
}

// ── Header button ─────────────────────────────────────────────────────────────
function headerBtn(iconName, label, onclick, opts = {}) {
  return el('button', {
    class: `card rounded-lg px-3 py-1.5 text-slate-300 hover:text-white hover:border-slate-600 flex items-center gap-1.5 ${opts.class || ''}`,
    onclick, title: opts.title || label,
  }, icon(iconName, 14), label);
}

function renderMain() {
  const app = document.getElementById('app');
  clear(app);

  const search = el('input', { type: 'text', placeholder: tr('Поиск (Cmd+K)'), class: 'input rounded-lg px-3 py-1.5 w-72', value: state.searchQuery });
  search.addEventListener('input', debounce(async () => {
    state.searchQuery = search.value;
    await refreshMain(); renderMain();
  }, 200));

  const hAdd = el('button', { class: 'btn-primary text-white font-semibold rounded-lg px-3 py-1.5 flex items-center gap-1.5', onclick: () => showSecretEditor() }, icon('plus', 14), tr('Секрет'));
  const hAddF = headerBtn('folder', tr('Папка'), showFolderEditor);
  const hTk = headerBtn('key', tr('Токены'), showTokens, { title: 'Service tokens' });
  const hSt = headerBtn('info', 'Stats', showStats, { title: 'Vault stats + token usage' });
  const hAu = headerBtn('log', tr('Журнал'), showAudit, { title: 'Audit log' });
  const hEx = el('button', { class: 'card rounded-lg p-1.5 text-slate-300 hover:text-white', onclick: exportVault, title: tr('Экспорт JSON (Cmd+E)') }, icon('download', 14));
  const hIm = el('button', { class: 'card rounded-lg p-1.5 text-slate-300 hover:text-white', onclick: importVault, title: tr('Импорт JSON') }, icon('upload', 14));
  const hLock = el('button', { class: 'card rounded-lg px-3 py-1.5 text-amber-400 hover:text-amber-300 hover:border-amber-700 flex items-center gap-1.5', onclick: async () => { await api.lock(); location.reload(); }, title: 'Lock vault' }, icon('lock', 14), 'Lock');

  // language switch: the other language's code; reloads with the choice persisted
  const hLang = el('button', { class: 'card rounded-lg px-2 py-1.5 text-xs text-slate-300 hover:text-white font-mono', title: tr('Язык'),
    onclick: () => I18N.setLang(I18N.lang === 'ru' ? 'en' : 'ru') }, I18N.lang === 'ru' ? 'EN' : 'RU');
  const header = el('header', { class: 'flex items-center justify-between p-4 border-b border-slate-800' },
    el('div', { class: 'flex items-center gap-3' },
      el('div', { class: 'text-slate-200' }, icon('shield', 22)),
      el('h1', { class: 'text-lg font-semibold text-white' }, 'APS Vault')),
    el('div', { class: 'flex items-center gap-2 text-sm' }, search, hAdd, hAddF, hTk, hSt, hEx, hIm, hAu, hLang, hLock));

  // ── Sidebar: дерево «папка → секреты внутри» + Избранное + Тег-чипы ──────
  const sidebar = el('aside', { class: 'w-72 border-r border-slate-800 overflow-y-auto p-2 shrink-0' });

  const STALE_DAYS = 90;
  const STALE_MS = STALE_DAYS * 86400 * 1000;
  const isStale = (s) => !s.last_accessed || (Date.now() - new Date(s.last_accessed).getTime()) > STALE_MS;

  // Renders one secret-leaf
  function secretLeaf(s, opts = {}) {
    const indent = opts.indent || 'pl-8';
    const stale = isStale(s);
    const cls = `flex items-center gap-1 ${indent} pr-2 py-1 rounded cursor-pointer text-sm ${stale ? 'text-slate-500' : 'text-slate-400'} hover:bg-slate-800 hover:text-slate-100 group`;
    const row = el('div', { class: cls, onclick: (e) => { if (e.target.closest('.star-btn')) return; showSecretDetails(s.id); }},
      el('span', { class: 'text-slate-600 shrink-0' }, icon('file', 12)),
      el('span', { class: 'flex-1 truncate', title: (s.last_accessed ? 'last access ' + timeAgo(s.last_accessed) : 'never accessed') + ' · ' + (s.access_count || 0) + ' reads' }, s.name),
      stale ? el('span', { class: 'text-[10px] text-slate-600 shrink-0', title: `stale: not accessed in ${STALE_DAYS}d` }, icon('clock', 10)) : null,
      s.has_totp ? el('span', { class: 'text-[10px] text-emerald-500 shrink-0' }, 'TOTP') : null,
      el('button', { class: `star-btn shrink-0 ${s.is_favorite ? 'text-amber-400' : 'text-slate-600 opacity-0 group-hover:opacity-100'} hover:text-amber-300`,
        title: s.is_favorite ? tr('Убрать из избранного') : tr('В избранное'),
        onclick: async (e) => { e.stopPropagation(); try { await api.toggleFavorite(s.id); await refreshMain(); renderMain(); } catch (er) { toast(er.message, 'error'); }},
      }, icon('star', 11)),
    );
    return row;
  }

  // Узел «Все»
  const allCount = state.secrets.length;
  sidebar.appendChild(el('div', {
    class: `flex items-center gap-1 px-2 py-1.5 rounded cursor-pointer ${state.selectedFolder === null ? 'bg-blue-600/20 text-blue-300' : 'text-slate-300 hover:bg-slate-800'}`,
    onclick: async () => { state.selectedFolder = null; await refreshMain(); renderMain(); },
  },
    el('span', { class: 'text-slate-500 w-4 shrink-0' }, ''),
    el('span', { class: 'text-slate-400 shrink-0' }, icon('folder_open', 14)),
    el('span', { class: 'text-sm font-medium flex-1 truncate' }, tr('Все секреты')),
    el('span', { class: 'text-xs text-slate-500 shrink-0' }, String(allCount))));

  // Избранные — над деревом
  const favs = state.secrets.filter(s => s.is_favorite);
  if (favs.length) {
    sidebar.appendChild(el('div', { class: 'text-xs uppercase tracking-wide text-amber-500/70 mt-3 mb-1 px-2 flex items-center gap-1' },
      icon('star', 10), tr`Избранные (${favs.length})`));
    for (const s of [...favs].sort((a,b) => a.name.localeCompare(b.name, 'ru'))) {
      sidebar.appendChild(secretLeaf(s, { indent: 'pl-3' }));
    }
  }

  // Активные теги-чипы (из выделенной папки или всех)
  const tagPool = state.secrets.flatMap(s => (s.tags || '').split(',').map(t => t.trim()).filter(Boolean));
  const tagCounts = {};
  for (const t of tagPool) tagCounts[t] = (tagCounts[t] || 0) + 1;
  const popTags = Object.entries(tagCounts).sort((a,b) => b[1]-a[1]).slice(0, 12);
  if (popTags.length) {
    sidebar.appendChild(el('div', { class: 'text-xs uppercase tracking-wide text-slate-500 mt-3 mb-1 px-2' }, tr('Теги')));
    const wrap = el('div', { class: 'flex flex-wrap gap-1 px-2 mb-2' });
    for (const [t, n] of popTags) {
      const active = state.tagFilter === t;
      wrap.appendChild(el('button', {
        class: `badge ${active ? 'bg-blue-900/60 text-blue-200 border border-blue-700' : 'bg-slate-800 text-slate-400 hover:text-white border border-slate-700'}`,
        onclick: async () => {
          state.tagFilter = active ? null : t;
          await refreshMain(); renderMain();
        }
      }, `${t} ${n}`));
    }
    sidebar.appendChild(wrap);
  }

  sidebar.appendChild(el('div', { class: 'text-xs uppercase tracking-wide text-slate-500 mt-3 mb-1 px-2' }, tr('Папки')));

  // Сортировка папок: сначала «admin», потом по алфавиту
  const sortedFolders = [...state.folders].sort((a, b) => {
    if (a.name === 'admin') return -1;
    if (b.name === 'admin') return 1;
    return a.name.localeCompare(b.name, 'ru');
  });

  for (const f of sortedFolders) {
    const folderSecrets = state.secrets.filter(s => s.folder_id === f.id);
    const isExpanded = state.expandedFolders.has(f.id);
    const isSelected = state.selectedFolder === f.id;

    const chevron = el('span', { class: 'text-slate-500 w-4 shrink-0 cursor-pointer', onclick: (e) => {
      e.stopPropagation();
      if (isExpanded) state.expandedFolders.delete(f.id);
      else state.expandedFolders.add(f.id);
      saveExpanded();
      renderMain();
    }}, icon(isExpanded ? 'chevron_down' : 'chevron_right', 14));

    const node = el('div', {
      class: `flex items-center gap-1 px-2 py-1.5 rounded cursor-pointer ${isSelected ? 'bg-blue-600/20 text-blue-300' : 'text-slate-300 hover:bg-slate-800'}`,
      onclick: async () => {
        state.selectedFolder = f.id;
        if (!isExpanded && folderSecrets.length) {
          state.expandedFolders.add(f.id);
          saveExpanded();
        }
        await refreshMain(); renderMain();
      },
    },
      chevron,
      el('span', { class: 'text-slate-400 shrink-0' }, icon('folder', 14)),
      el('span', { class: 'text-sm flex-1 truncate', title: f.description || f.name }, f.name),
      el('span', { class: 'text-xs text-slate-500 shrink-0' }, String(folderSecrets.length)));
    sidebar.appendChild(node);

    if (isExpanded && folderSecrets.length) {
      const sortedSecs = [...folderSecrets].sort((a, b) => a.name.localeCompare(b.name, 'ru'));
      for (const s of sortedSecs) sidebar.appendChild(secretLeaf(s));
    }
  }

  // List
  const list = el('main', { class: 'flex-1 overflow-y-auto p-4' });
  if (state.secrets.length === 0) {
    list.appendChild(el('div', { class: 'text-center text-slate-500 py-12 flex flex-col items-center gap-3' },
      el('div', { class: 'text-slate-600' }, icon('inbox', 48)),
      el('p', null, tr('Секретов пока нет. Создай первый — кнопка «Секрет» вверху.'))));
  } else {
    const wrap = el('div', { class: 'space-y-2' });
    for (const s of state.secrets) {
      const row = el('div', { class: 'card rounded-lg p-3 hover:border-blue-700/50 cursor-pointer', onclick: () => showSecretDetails(s.id) });
      const badges = el('div', { class: 'flex items-center gap-2 flex-wrap' },
        el('span', { class: 'font-semibold text-white truncate' }, s.name));
      if (s.has_login) badges.appendChild(el('span', { class: 'badge bg-slate-800 text-slate-400 border border-slate-700' }, 'login'));
      if (s.has_totp) badges.appendChild(el('span', { class: 'badge bg-emerald-950 text-emerald-300 border border-emerald-900/60' }, 'TOTP'));
      if (s.has_notes) badges.appendChild(el('span', { class: 'badge bg-slate-800 text-slate-400 border border-slate-700 flex items-center gap-1' }, icon('note', 10), 'notes'));
      const meta = el('div', { class: 'text-xs text-slate-500 mt-0.5' }, s.folder_name + (s.tags ? '  ·  ' + s.tags : '') + (s.url ? '  ·  ' + s.url : ''));
      const right = el('div', { class: 'text-xs text-slate-500 text-right shrink-0 ml-3' },
        s.last_accessed ? timeAgo(s.last_accessed) : tr('не открывался'),
        el('div', { class: 'text-slate-600' }, tr`${s.access_count} доступов`));
      row.appendChild(el('div', { class: 'flex items-start justify-between' },
        el('div', { class: 'flex-1 min-w-0' }, badges, meta), right));
      wrap.appendChild(row);
    }
    list.appendChild(wrap);
  }

  app.appendChild(el('div', { class: 'h-screen flex flex-col' }, header,
    el('div', { class: 'flex-1 flex overflow-hidden' }, sidebar, list)));

  document.onkeydown = (e) => {
    if ((e.metaKey || e.ctrlKey) && e.key === 'k') { e.preventDefault(); search.focus(); }
  };
}

// ── Secret editor ────────────────────────────────────────────────────────────
async function showSecretEditor(secretId) {
  let existing = null;
  if (secretId) {
    try { existing = await api.getSecret(secretId); } catch (e) { return toast(e.message, 'error'); }
  }
  if (!state.folders.length) return toast(tr('Сначала создай папку'), 'error');
  const name = el('input', { class: 'input rounded-lg px-3 py-2 w-full', value: existing?.name || '', placeholder: 'AGENT_API_TOKEN' });
  const folder = el('select', { class: 'input rounded-lg px-3 py-2 w-full' });
  for (const f of state.folders) {
    const opt = el('option', { value: f.id }, f.name);
    if (existing?.folder_id === f.id) opt.selected = true;
    folder.appendChild(opt);
  }
  const value = el('textarea', { rows: 3, class: 'input rounded-lg px-3 py-2 w-full font-mono text-sm' });
  if (existing) value.value = existing.value;
  // v0.3: password generator
  const genBtn = el('button', { type: 'button', class: 'text-xs text-blue-400 hover:text-blue-300 flex items-center gap-1', onclick: () => {
    value.value = genPassword(24);
    toast(tr('Сгенерирован 24-символьный пароль'), 'success');
  }}, icon('refresh', 12), tr('Сгенерировать'));
  const url = el('input', { class: 'input rounded-lg px-3 py-2 w-full', value: existing?.url || '', placeholder: 'https://...' });
  const tags = el('input', { class: 'input rounded-lg px-3 py-2 w-full', value: existing?.tags || '', placeholder: 'prod,api' });
  const totp = el('input', { class: 'input rounded-lg px-3 py-2 w-full font-mono', placeholder: existing?.has_totp ? tr('(уже задан — оставь пустым чтобы не менять)') : 'JBSWY3DPEHPK3PXP' });
  // v0.3.2: отдельное поле login (email / username) — раньше клали в notes.
  const login = el('input', { class: 'input rounded-lg px-3 py-2 w-full', value: existing?.login || '', placeholder: tr('user@example.com или username') });
  const notes = el('textarea', { rows: 3, class: 'input rounded-lg px-3 py-2 w-full' });
  if (existing) notes.value = existing.notes || '';

  const save = el('button', { class: 'btn-primary text-white font-semibold rounded-lg px-4 py-2 flex-1', onclick: async () => {
    const body = { folder_id: parseInt(folder.value), name: name.value.trim(), value: value.value, login: login.value, url: url.value, tags: tags.value, notes: notes.value, totp_seed: totp.value };
    if (!body.name) return toast(tr('Имя обязательно'), 'error');
    try {
      if (existing) {
        const patch = { name: body.name, value: body.value, login: body.login, url: body.url, tags: body.tags, notes: body.notes };
        if (body.totp_seed !== '') patch.totp_seed = body.totp_seed;
        await api.updateSecret(existing.id, patch);
      } else {
        await api.createSecret(body);
      }
      overlay.remove();
      await refreshMain(); renderMain();
      toast(tr('Сохранено'), 'success');
    } catch (e) { toast(e.message, 'error'); }
  }}, tr('Сохранить'));
  const cancel = el('button', { class: 'card rounded-lg px-4 py-2 text-slate-300', onclick: () => overlay.remove() }, tr('Отмена'));
  const buttons = el('div', { class: 'flex gap-2 pt-4 border-t border-slate-700' }, save, cancel);
  if (existing) {
    buttons.appendChild(el('button', { class: 'btn-danger rounded-lg px-4 py-2 flex items-center gap-1.5', onclick: async () => {
      if (!confirm(tr`Удалить «${existing.name}»?`)) return;
      try {
        await api.deleteSecret(existing.id);
        overlay.remove(); await refreshMain(); renderMain();
        toast(tr('Удалён'), 'success');
      } catch (e) { toast(e.message, 'error'); }
    }}, icon('trash', 14), tr('Удалить')));
  }

  const overlay = modal(
    el('h2', { class: 'text-lg font-semibold text-white mb-4' }, existing ? tr('Редактировать секрет') : tr('Новый секрет')),
    el('div', { class: 'space-y-3' },
      el('div', null, el('label', { class: 'text-xs text-slate-400' }, tr('Имя')), name),
      el('div', null, el('label', { class: 'text-xs text-slate-400' }, tr('Папка')), folder),
      el('div', null,
        el('div', { class: 'flex items-center justify-between mb-1' },
          el('label', { class: 'text-xs text-slate-400' }, tr('Значение')),
          genBtn),
        value),
      el('div', null, el('label', { class: 'text-xs text-slate-400' }, tr('Логин (email/username, опц.)')), login),
      el('div', { class: 'grid grid-cols-2 gap-3' },
        el('div', null, el('label', { class: 'text-xs text-slate-400' }, 'URL'), url),
        el('div', null, el('label', { class: 'text-xs text-slate-400' }, tr('Теги')), tags)),
      el('div', null, el('label', { class: 'text-xs text-slate-400' }, tr('TOTP seed (base32, опц.)')), totp),
      el('div', null, el('label', { class: 'text-xs text-slate-400' }, tr('Заметки')), notes),
      buttons));
}

// ── Secret details ───────────────────────────────────────────────────────────
async function showSecretDetails(id) {
  try {
    const s = await api.getSecret(id);
    const valBox = el('div', { class: 'input rounded-lg px-3 py-2 font-mono text-sm break-all blur-secret' }, s.value);
    const revealBtn = el('button', { class: 'text-xs text-slate-400 hover:text-white flex items-center gap-1', onclick: () => {
      const blurred = valBox.classList.toggle('blur-secret');
      revealBtn.innerHTML = '';
      revealBtn.appendChild(icon(blurred ? 'eye' : 'eye_off', 12));
      revealBtn.appendChild(document.createTextNode(blurred ? tr(' показать') : tr(' скрыть')));
    }}, icon('eye', 12), tr(' показать'));
    const copyBtn = el('button', { class: 'text-xs text-blue-400 hover:text-blue-300 flex items-center gap-1', onclick: () => copyToClipboard(s.value, tr('значение')) }, icon('copy', 12), tr(' копировать'));

    const children = [];
    children.push(el('div', { class: 'flex items-start justify-between mb-4' },
      el('div', null,
        el('h2', { class: 'text-lg font-semibold text-white' }, s.name),
        el('div', { class: 'text-sm text-slate-500' }, tr`${s.folder_name}  ·  ${s.access_count} доступов`)),
      el('button', { class: 'text-slate-500 hover:text-white', onclick: () => overlay.remove() }, icon('x', 18))));

    if (s.url) children.push(el('div', null,
      el('label', { class: 'text-xs text-slate-400' }, 'URL'),
      el('div', { class: 'text-sm text-blue-400' }, /^https?:\/\//i.test(s.url) ? el('a', { href: s.url, target: '_blank', rel: 'noopener noreferrer' }, s.url) : el('span', null, s.url))));

    if (s.login) {
      const loginBtn = el('button', { class: 'text-xs text-blue-400 hover:text-blue-300 flex items-center gap-1', onclick: () => copyToClipboard(s.login, tr('Логин')) }, icon('copy', 12));
      children.push(el('div', null,
        el('div', { class: 'flex justify-between items-center mb-1' },
          el('label', { class: 'text-xs text-slate-400' }, tr('Логин')),
          loginBtn),
        el('div', { class: 'input rounded-lg px-3 py-2 text-sm font-mono' }, s.login)));
    }

    children.push(el('div', null,
      el('div', { class: 'flex justify-between items-center mb-1' },
        el('label', { class: 'text-xs text-slate-400' }, tr('Значение')),
        el('div', { class: 'flex gap-3' }, revealBtn, copyBtn)),
      valBox));

    if (s.totp) {
      const totpBtn = el('button', { class: 'text-xs text-blue-400 hover:text-blue-300 flex items-center gap-1', onclick: () => copyToClipboard(s.totp, tr('TOTP-код')) }, icon('copy', 12));
      children.push(el('div', null,
        el('label', { class: 'text-xs text-slate-400' }, tr('TOTP код')),
        el('div', { class: 'flex items-center gap-3' },
          el('code', { class: 'text-2xl font-mono text-emerald-400 tracking-wider' }, s.totp), totpBtn)));
    }

    if (s.notes) {
      const notesBox = el('div', { class: 'input rounded-lg px-3 py-2 text-sm whitespace-pre-wrap blur-secret' }, s.notes);
      const nBtn = el('button', { class: 'text-xs text-slate-400 hover:text-white flex items-center gap-1', onclick: () => notesBox.classList.toggle('blur-secret') }, icon('eye', 12), tr(' показать'));
      children.push(el('div', null,
        el('div', { class: 'flex justify-between items-center mb-1' },
          el('label', { class: 'text-xs text-slate-400' }, tr('Заметки')), nBtn),
        notesBox));
    }

    if (s.tags) children.push(el('div', null,
      el('label', { class: 'text-xs text-slate-400' }, tr('Теги')),
      el('div', { class: 'text-sm' }, s.tags)));

    children.push(el('div', { class: 'text-xs text-slate-500 pt-2 border-t border-slate-700' },
      tr`Создан ${new Date(s.created_at).toLocaleString(I18N.locale)}  ·  обновлён ${new Date(s.updated_at).toLocaleString(I18N.locale)}`));

    children.push(el('div', { class: 'flex gap-2 pt-2 flex-wrap' },
      el('button', { class: 'btn-primary rounded-lg px-4 py-2 flex items-center gap-1.5', onclick: () => { overlay.remove(); showSecretEditor(id); }}, icon('pencil', 14), tr('Редактировать')),
      el('button', { class: 'card rounded-lg px-3 py-2 flex items-center gap-1.5 text-slate-300', onclick: () => { overlay.remove(); showHistory(id); }, title: tr('История значений') }, icon('clock', 14), tr('История')),
      el('button', { class: 'card rounded-lg px-3 py-2 flex items-center gap-1.5 text-slate-300', onclick: () => { overlay.remove(); showShareDialog(id, s.name); }, title: tr('Создать share-link') }, icon('share', 14), tr('Поделиться')),
      el('button', { class: 'card rounded-lg px-4 py-2', onclick: () => overlay.remove() }, tr('Закрыть'))));

    const overlay = modal(...children);
  } catch (e) { toast(e.message, 'error'); }
}

// ── Folder editor ────────────────────────────────────────────────────────────
function showFolderEditor() {
  const name = el('input', { class: 'input rounded-lg px-3 py-2 w-full', placeholder: 'prod-secrets' });
  const desc = el('input', { class: 'input rounded-lg px-3 py-2 w-full', placeholder: tr('Описание (опционально)') });
  const overlay = modal(
    el('h2', { class: 'text-lg font-semibold text-white mb-4' }, tr('Новая папка')),
    el('div', { class: 'space-y-3' }, name, desc,
      el('div', { class: 'flex gap-2 pt-3' },
        el('button', { class: 'btn-primary rounded-lg px-4 py-2 flex-1', onclick: async () => {
          if (!name.value.trim()) return toast(tr('Имя обязательно'), 'error');
          try {
            await api.createFolder(name.value.trim(), desc.value.trim());
            overlay.remove(); await refreshMain(); renderMain();
            toast(tr('Папка создана'), 'success');
          } catch (e) { toast(e.message, 'error'); }
        }}, tr('Создать')),
        el('button', { class: 'card rounded-lg px-4 py-2', onclick: () => overlay.remove() }, tr('Отмена')))));
}

// ── Service tokens ───────────────────────────────────────────────────────────
async function showTokens() {
  try { state.tokens = await api.listTokens(); } catch (e) { return toast(e.message, 'error'); }

  const name = el('input', { class: 'input rounded-lg px-3 py-2 w-full', placeholder: tr('Имя (prod-api)') });
  const folderSel = el('select', { class: 'input rounded-lg px-3 py-2 flex-1' });
  for (const f of state.folders) folderSel.appendChild(el('option', { value: f.id }, f.name));
  const daysInp = el('input', { class: 'input rounded-lg px-3 py-2 w-32', placeholder: tr('дней (∞)'), type: 'number' });
  const cbNotes = el('input', { type: 'checkbox' });
  const cbTotp = el('input', { type: 'checkbox' });
  const cbWrite = el('input', { type: 'checkbox' });
  // PAM-style policy: where the token may be used from and when (docs/ACCESS-POLICIES.md)
  const cidrInp = el('input', { class: 'input rounded-lg px-3 py-2 flex-1 font-mono text-xs', placeholder: tr('Откуда (CIDR, опц.)') + ' 10.0.0.0/8 203.0.113.7', 'data-testid': 'tok-cidrs' });
  const hoursInp = el('input', { class: 'input rounded-lg px-3 py-2 flex-1 font-mono text-xs', placeholder: tr('Когда (окна, опц.)') + ' Mon-Fri 08:00-20:00', 'data-testid': 'tok-hours' });
  const createBtn = el('button', { class: 'btn-primary rounded-lg px-3 py-1 ml-auto', onclick: async () => {
    const body = { name: name.value.trim(), folder_id: parseInt(folderSel.value), can_read_notes: cbNotes.checked, can_read_totp: cbTotp.checked, can_write: cbWrite.checked,
                   allowed_cidrs: cidrInp.value.trim(), allowed_hours: hoursInp.value.trim() };
    const d = parseInt(daysInp.value); if (d > 0) body.expires_days = d;
    if (!body.name) return toast(tr('Имя обязательно'), 'error');
    try {
      const r = await api.createToken(body);
      showRawTokenModal(r.raw_token, async () => { overlay.remove(); await showTokens(); });
    } catch (e) { toast(e.message, 'error'); }
  }}, tr('Создать'));

  const list = el('div', { class: 'space-y-2 max-h-96 overflow-y-auto' });
  if (state.tokens.length === 0) {
    list.appendChild(el('div', { class: 'text-slate-500 text-sm py-4 text-center' }, tr('Токенов нет')));
  } else {
    for (const t of state.tokens) {
      const scopeLabel = `scope: ${t.folder_name}` + (t.can_read_notes ? '  ·  notes' : '') + (t.can_read_totp ? '  ·  TOTP' : '') + (t.can_write ? tr('  ·  запись') : '')
        + (t.allowed_cidrs ? `  ·  ${t.allowed_cidrs}` : '') + (t.allowed_hours ? `  ·  ${t.allowed_hours}` : '');
      const right = t.revoked
        ? el('span', { class: 'badge bg-red-950 text-red-300 border border-red-800/60' }, tr('отозван'))
        : el('button', { class: 'btn-danger rounded px-3 py-1 text-xs', onclick: async () => {
            if (!confirm(tr('Отозвать токен?'))) return;
            try { await api.revokeToken(t.id); overlay.remove(); await showTokens(); } catch (e) { toast(e.message, 'error'); }
          }}, tr('Отозвать'));
      const card = el('div', { class: `card rounded-lg p-3 ${t.revoked ? 'opacity-50' : ''}` },
        el('div', { class: 'flex justify-between items-start' },
          el('div', null,
            el('div', { class: 'font-semibold text-white' }, t.name),
            el('div', { class: 'text-xs text-slate-500' }, scopeLabel),
            el('div', { class: 'text-xs text-slate-600' },
              tr`создан ${timeAgo(t.created_at)}` + (t.last_used ? tr`, использован ${timeAgo(t.last_used)}` : tr(', не использован')) + (t.expires_at ? tr`, до ${new Date(t.expires_at).toLocaleDateString()}` : ''))),
          right));
      list.appendChild(card);
    }
  }

  const overlay = modal(
    el('h2', { class: 'text-lg font-semibold text-white mb-4 flex items-center gap-2' }, icon('key', 18), tr('Service tokens (для интеграций)')),
    el('div', { class: 'card rounded-lg p-4 mb-4 bg-slate-900/40' },
      el('div', { class: 'text-sm font-semibold mb-2 text-slate-300' }, tr('Создать новый')),
      el('div', { class: 'space-y-2' }, name,
        el('div', { class: 'flex gap-2' }, folderSel, daysInp),
        el('div', { class: 'flex gap-2' }, cidrInp, hoursInp),
        el('div', { class: 'flex gap-4 items-center flex-wrap' },
          el('label', { class: 'text-xs text-slate-300 flex items-center gap-1.5' }, cbNotes, tr('читать notes')),
          el('label', { class: 'text-xs text-slate-300 flex items-center gap-1.5' }, cbTotp, tr('читать TOTP')),
          el('label', { class: 'text-xs text-amber-300 flex items-center gap-1.5', title: tr('Токен сможет создавать/перезаписывать секреты в своей папке через API') }, cbWrite, tr('запись секретов')), createBtn))),
    list,
    el('button', { class: 'card rounded-lg px-4 py-2 mt-4 w-full', onclick: () => overlay.remove() }, tr('Закрыть')));
}

function showRawTokenModal(token, onClose) {
  const tokenBox = el('div', { class: 'bg-slate-950 border border-emerald-900/60 rounded-lg p-3 font-mono text-sm break-all select-all text-emerald-300' }, token);
  const overlay = modal(
    el('h2', { class: 'text-lg font-semibold text-white mb-3 flex items-center gap-2' }, icon('key', 18), tr('Service token создан')),
    el('p', { class: 'text-slate-400 text-sm mb-3' }, tr('Сохрани этот токен СЕЙЧАС — повторно не показывается.')),
    tokenBox,
    el('div', { class: 'flex gap-2 mt-4' },
      el('button', { class: 'btn-primary rounded-lg px-4 py-2 flex-1 flex items-center justify-center gap-1.5', onclick: () => copyToClipboard(token, 'service-token') }, icon('copy', 14), tr('Копировать')),
      el('button', { class: 'card rounded-lg px-4 py-2', onclick: () => { overlay.remove(); onClose(); }}, tr('Готово'))));
}

// ── Audit ────────────────────────────────────────────────────────────────────
async function showAudit() {
  try {
    const items = await api.audit(200);
    const list = el('div', { class: 'space-y-1 max-h-[70vh] overflow-y-auto font-mono text-xs' });
    for (const a of items) {
      list.appendChild(el('div', { class: 'card rounded px-2 py-1.5 flex gap-3 items-center' },
        el('span', { class: 'text-slate-500 shrink-0 w-32' }, a.ts.slice(0, 19).replace('T', ' ')),
        el('span', { class: 'text-amber-400 shrink-0 w-32' }, a.action),
        el('span', { class: 'text-slate-300 truncate flex-1' }, a.target || ''),
        el('span', { class: 'text-slate-600 shrink-0' }, `${a.actor}  ·  ${a.ip}`)));
    }
    const overlay = modal(
      el('h2', { class: 'text-lg font-semibold text-white mb-4 flex items-center gap-2' }, icon('log', 18), tr`Audit log (последние ${items.length})`),
      list,
      el('button', { class: 'card rounded-lg px-4 py-2 mt-4 w-full', onclick: () => overlay.remove() }, tr('Закрыть')));
  } catch (e) { toast(e.message, 'error'); }
}

// ── Password generator ──────────────────────────────────────────────────────
function genPassword(len = 24, opts = {}) {
  const sets = [];
  sets.push('abcdefghijklmnopqrstuvwxyz');
  sets.push('ABCDEFGHIJKLMNOPQRSTUVWXYZ');
  sets.push('0123456789');
  if (opts.symbols !== false) sets.push('!@#$%^&*()-_=+[]{};:,.<>?');
  const all = sets.join('');
  const arr = new Uint32Array(len);
  crypto.getRandomValues(arr);
  let out = '';
  for (let i = 0; i < len; i++) out += all[arr[i] % all.length];
  return out;
}

// ── Cmd+K палитра — глобальный поиск по всем секретам ──────────────────────
function openPalette() {
  if (state.paletteOpen) return;
  state.paletteOpen = true; state.paletteIndex = 0;
  const input = el('input', {
    type: 'text', class: 'input rounded-lg px-3 py-2 w-full font-mono',
    placeholder: tr('Поиск по name/tags/url/folder...'),
    autofocus: true,
  });
  const list = el('div', { class: 'max-h-96 overflow-y-auto mt-3 space-y-1' });
  const overlay = el('div', { class: 'fixed inset-0 bg-black/80 flex items-start justify-center z-50 p-6 pt-20', onclick: (e) => { if (e.target === overlay) closePalette(); } });
  const card = el('div', { class: 'card rounded-xl p-4 max-w-2xl w-full' }, input, list);
  overlay.appendChild(card);
  document.body.appendChild(overlay);

  function closePalette() {
    overlay.remove();
    state.paletteOpen = false;
  }

  function score(s, q) {
    const text = `${s.name} ${s.tags} ${s.url} ${s.folder_name}`.toLowerCase();
    const ql = q.toLowerCase();
    if (s.name.toLowerCase().startsWith(ql)) return 3;
    if (text.includes(ql)) return 2;
    // fuzzy: все символы запроса по порядку в name
    let j = 0;
    for (const c of s.name.toLowerCase()) { if (c === ql[j]) j++; if (j === ql.length) return 1; }
    return 0;
  }

  function refresh() {
    const q = input.value.trim();
    clear(list);
    let matches = state.secrets;
    if (q) {
      matches = state.secrets.map(s => ({ s, sc: score(s, q) }))
        .filter(x => x.sc > 0).sort((a, b) => b.sc - a.sc).map(x => x.s).slice(0, 50);
    } else {
      // пусто — показать last 10 accessed
      matches = [...state.secrets].sort((a, b) => {
        const ta = a.last_accessed ? new Date(a.last_accessed).getTime() : 0;
        const tb = b.last_accessed ? new Date(b.last_accessed).getTime() : 0;
        return tb - ta;
      }).slice(0, 10);
      list.appendChild(el('div', { class: 'text-xs text-slate-500 px-2' }, tr('Последние просмотренные:')));
    }
    if (state.paletteIndex >= matches.length) state.paletteIndex = matches.length - 1;
    if (state.paletteIndex < 0) state.paletteIndex = 0;
    matches.forEach((s, i) => {
      const sel = i === state.paletteIndex;
      list.appendChild(el('div', {
        class: `flex items-center gap-2 px-3 py-2 rounded cursor-pointer ${sel ? 'bg-blue-600/20 text-blue-200' : 'text-slate-300 hover:bg-slate-800'}`,
        onclick: () => { closePalette(); showSecretDetails(s.id); },
      },
        el('span', { class: 'text-slate-500 shrink-0' }, icon('file', 12)),
        el('span', { class: 'flex-1 truncate font-mono text-sm' }, s.name),
        el('span', { class: 'text-xs text-slate-500 shrink-0' }, s.folder_name),
        s.has_totp ? el('span', { class: 'text-[10px] text-emerald-500 shrink-0' }, 'TOTP') : null,
        s.is_favorite ? el('span', { class: 'text-amber-400 shrink-0' }, icon('star', 10)) : null,
      ));
    });
  }

  input.addEventListener('input', refresh);
  input.addEventListener('keydown', async (e) => {
    if (e.key === 'Escape') { closePalette(); return; }
    const q = input.value.trim();
    const matches = q ? state.secrets.filter(s => score(s, q) > 0).sort((a, b) => score(b, q) - score(a, q)).slice(0, 50)
                      : [...state.secrets].sort((a, b) => (new Date(b.last_accessed || 0)) - (new Date(a.last_accessed || 0))).slice(0, 10);
    if (e.key === 'ArrowDown') { e.preventDefault(); state.paletteIndex = Math.min(state.paletteIndex + 1, matches.length - 1); refresh(); }
    else if (e.key === 'ArrowUp') { e.preventDefault(); state.paletteIndex = Math.max(state.paletteIndex - 1, 0); refresh(); }
    else if (e.key === 'Enter' && matches[state.paletteIndex]) {
      const s = matches[state.paletteIndex];
      closePalette();
      if ((e.metaKey || e.ctrlKey)) {
        // Cmd+Enter — скопировать value сразу
        try { const full = await api.getSecret(s.id); copyToClipboard(full.value, s.name); }
        catch (er) { toast(er.message, 'error'); }
      } else {
        showSecretDetails(s.id);
      }
    }
  });

  refresh();
}

// ── Stats dashboard ─────────────────────────────────────────────────────────
async function showStats() {
  try {
    const d = await api.stats();
    const list = el('div', { class: 'space-y-1 max-h-96 overflow-y-auto' });
    for (const t of d.tokens_usage || []) {
      list.appendChild(el('div', { class: 'card rounded p-2 flex items-center gap-3 text-sm' },
        el('span', { class: 'flex-1 font-mono text-slate-300' }, t.name),
        el('span', { class: 'text-slate-500' }, t.folder_id ? `scope=${t.folder_id}` : ''),
        el('span', { class: 'text-xs text-slate-500 w-32 text-right' }, t.last_used ? timeAgo(t.last_used) : tr('не использовался')),
        el('span', { class: `font-mono text-sm w-16 text-right ${t.reads_30d > 100 ? 'text-amber-400' : t.reads_30d > 0 ? 'text-emerald-400' : 'text-slate-600'}` }, String(t.reads_30d))));
    }
    const overlay = modal(
      el('h2', { class: 'text-lg font-semibold text-white mb-3 flex items-center gap-2' }, icon('info', 16), 'Vault stats'),
      el('div', { class: 'grid grid-cols-3 gap-3 mb-4' },
        el('div', { class: 'card rounded-lg p-3 text-center' },
          el('div', { class: 'text-3xl font-bold text-white' }, String(d.totals.secrets)),
          el('div', { class: 'text-xs text-slate-500' }, tr('Всего секретов'))),
        el('div', { class: 'card rounded-lg p-3 text-center' },
          el('div', { class: 'text-3xl font-bold text-white' }, String(d.totals.folders)),
          el('div', { class: 'text-xs text-slate-500' }, tr('Папок'))),
        el('div', { class: 'card rounded-lg p-3 text-center' },
          el('div', { class: 'text-3xl font-bold text-amber-400' }, String(d.totals.stale)),
          el('div', { class: 'text-xs text-slate-500' }, tr('Stale (>90 дн)')))),
      el('div', { class: 'text-xs uppercase tracking-wide text-slate-500 mb-2' }, tr('Расход service-tokens за 30 дней:')),
      list,
      el('button', { class: 'card rounded-lg px-4 py-2 mt-4 w-full', onclick: () => overlay.remove() }, tr('Закрыть')));
  } catch (e) { toast(e.message, 'error'); }
}

// ── History modal ──────────────────────────────────────────────────────────
async function showHistory(secretId) {
  try {
    const d = await api.history(secretId);
    const list = el('div', { class: 'space-y-2 max-h-96 overflow-y-auto' });
    if (!d.history.length) list.appendChild(el('div', { class: 'text-slate-500 text-sm py-4 text-center' }, tr('История пуста')));
    for (const h of d.history) {
      const valBox = el('code', { class: 'font-mono text-xs text-emerald-400 break-all blur-secret' }, h.value || h.error || '');
      const reveal = el('button', { class: 'text-xs text-slate-400 hover:text-white', onclick: () => valBox.classList.toggle('blur-secret') }, tr('показать'));
      const cpy = el('button', { class: 'text-xs text-blue-400', onclick: () => copyToClipboard(h.value, tr('старое значение')) }, tr('копировать'));
      list.appendChild(el('div', { class: 'card rounded p-2' },
        el('div', { class: 'text-xs text-slate-500 mb-1 flex justify-between' },
          el('span', null, new Date(h.changed_at).toLocaleString(I18N.locale)),
          el('div', { class: 'flex gap-3' }, reveal, cpy)),
        valBox));
    }
    const overlay = modal(
      el('h2', { class: 'text-lg font-semibold text-white mb-3' }, tr('История значений')),
      list,
      el('button', { class: 'card rounded-lg px-4 py-2 mt-4 w-full', onclick: () => overlay.remove() }, tr('Закрыть')));
  } catch (e) { toast(e.message, 'error'); }
}

// ── Share dialog ──────────────────────────────────────────────────────────
async function showShareDialog(secretId, secretName) {
  const ttl = el('input', { type: 'number', class: 'input rounded-lg px-3 py-2 w-full', value: '60', min: 1, max: 10080 });
  const uses = el('input', { type: 'number', class: 'input rounded-lg px-3 py-2 w-full', value: '1', min: 1, max: 100 });
  const note = el('input', { class: 'input rounded-lg px-3 py-2 w-full', placeholder: tr('Заметка (опционально)') });
  const overlay = modal(
    el('h2', { class: 'text-lg font-semibold text-white mb-3 flex items-center gap-2' }, icon('share', 16), tr`Поделиться: ${secretName}`),
    el('p', { class: 'text-slate-400 text-sm mb-3' }, tr('Создаёт публичную ссылку на одноразовый просмотр (без auth). После N открытий — мёртвая.')),
    el('div', { class: 'space-y-3' },
      el('div', null, el('label', { class: 'text-xs text-slate-400' }, tr('TTL (минут)')), ttl),
      el('div', null, el('label', { class: 'text-xs text-slate-400' }, tr('Макс. открытий')), uses),
      el('div', null, el('label', { class: 'text-xs text-slate-400' }, 'Note'), note),
      el('div', { class: 'flex gap-2 pt-2' },
        el('button', { class: 'btn-primary rounded-lg px-4 py-2 flex-1', onclick: async () => {
          try {
            const r = await api.createShare({
              secret_id: secretId,
              ttl_minutes: parseInt(ttl.value) || 60,
              max_uses: parseInt(uses.value) || 1,
              note: note.value || '',
            });
            const fullUrl = `${location.origin}${r.url.replace('/share/', '/api/share/')}`;
            overlay.remove();
            const sharedOverlay = modal(
              el('h2', { class: 'text-lg font-semibold text-white mb-3' }, tr('Ссылка создана')),
              el('p', { class: 'text-slate-400 text-sm mb-3' }, tr('Скопируй и передай. Истекает через указанный TTL или после N открытий.')),
              el('div', { class: 'bg-slate-950 border border-emerald-700/50 rounded-lg p-3 font-mono text-xs break-all select-all text-emerald-400' }, fullUrl),
              el('div', { class: 'flex gap-2 mt-4' },
                el('button', { class: 'btn-primary rounded-lg px-4 py-2 flex-1', onclick: () => copyToClipboard(fullUrl, tr('ссылка')) }, tr('Копировать')),
                el('button', { class: 'card rounded-lg px-4 py-2', onclick: () => sharedOverlay.remove() }, 'OK')));
          } catch (e) { toast(e.message, 'error'); }
        }}, tr('Создать ссылку')),
        el('button', { class: 'card rounded-lg px-4 py-2', onclick: () => overlay.remove() }, tr('Отмена')))));
}

// ── Export/Import ──────────────────────────────────────────────────────────
async function exportVault() {
  try {
    const d = await api.exportJson();
    const blob = new Blob([JSON.stringify(d, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = `vault-export-${new Date().toISOString().slice(0,10)}.json`;
    document.body.appendChild(a); a.click(); a.remove();
    URL.revokeObjectURL(url);
    toast(tr`Экспорт: ${d.folders.reduce((n,f) => n + f.secrets.length, 0)} секретов`, 'success');
  } catch (e) { toast(e.message, 'error'); }
}

async function importVault() {
  const file = document.createElement('input');
  file.type = 'file'; file.accept = '.json';
  file.onchange = async () => {
    if (!file.files[0]) return;
    try {
      const text = await file.files[0].text();
      const data = JSON.parse(text);
      if (!data.folders) throw new Error(tr('JSON должен содержать поле folders'));
      if (!confirm(tr`Импортировать ${data.folders.length} папок? Существующие секреты будут пропущены.`)) return;
      const r = await api.importJson({ folders: data.folders, create_missing_folders: true, skip_existing: true });
      toast(tr`Создано: ${r.created_secrets} секретов, ${r.created_folders} папок, ${r.skipped} skipped`, 'success');
      await refreshMain(); renderMain();
    } catch (e) { toast(e.message, 'error'); }
  };
  file.click();
}

// ── Auto-lock on inactivity (15 min) ────────────────────────────────────────
const AUTOLOCK_MS = 15 * 60 * 1000;
function setupAutoLock() {
  const reset = () => { state.lastActivity = Date.now(); };
  ['mousemove', 'keydown', 'click', 'scroll', 'touchstart'].forEach(ev =>
    document.addEventListener(ev, reset, { passive: true }));
  setInterval(async () => {
    if (Date.now() - state.lastActivity > AUTOLOCK_MS) {
      try { await api.lock(); } catch {}
      location.reload();
    }
  }, 30 * 1000);
}

// ── Global keyboard handlers ───────────────────────────────────────────────
function setupGlobalKeys() {
  document.addEventListener('keydown', (e) => {
    // Cmd+K / Ctrl+K — палитра
    if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
      e.preventDefault(); openPalette();
    }
    // Cmd+E — экспорт
    else if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'e') {
      e.preventDefault(); exportVault();
    }
    // Esc — закрыть открытое overlay (если не палитра — она сама)
    else if (e.key === 'Escape') {
      const ovs = document.querySelectorAll('.fixed.inset-0');
      if (ovs.length) ovs[ovs.length - 1].remove();
    }
  });
}

// ── Drop creds: drag-and-drop текста с учёткой → парсинг → автодетект папки ─
function setupDropCreds() {
  let dropOverlay = null;

  function showDropZone() {
    if (dropOverlay) return;
    dropOverlay = el('div', {
      class: 'fixed inset-0 z-[60] flex items-center justify-center pointer-events-none',
      style: { background: 'rgba(59,130,246,0.15)', border: '4px dashed #3b82f6' },
    },
      el('div', { class: 'card rounded-xl p-8 text-center', style: { background: 'rgba(15,19,32,0.95)', pointerEvents: 'auto' } },
        el('div', { class: 'inline-flex items-center justify-center w-14 h-14 rounded-full bg-slate-800 mb-3 text-blue-400' }, icon('download', 26)),
        el('h2', { class: 'text-xl font-semibold text-white mb-2' }, 'Drop credentials'),
        el('p', { class: 'text-slate-400' }, tr('Отпусти — vault распарсит и создаст секрет')),
      ));
    document.body.appendChild(dropOverlay);
  }
  function hideDropZone() { dropOverlay?.remove(); dropOverlay = null; }

  document.addEventListener('dragover', (e) => {
    if (!state.unlocked) return;
    if (!e.dataTransfer?.types?.includes('text/plain')) return;
    e.preventDefault();
    showDropZone();
  });
  document.addEventListener('dragleave', (e) => {
    if (e.clientX <= 0 || e.clientY <= 0 || e.clientX >= window.innerWidth || e.clientY >= window.innerHeight) {
      hideDropZone();
    }
  });
  document.addEventListener('drop', (e) => {
    if (!state.unlocked) return;
    hideDropZone();
    const text = e.dataTransfer?.getData('text/plain');
    if (!text) return;
    e.preventDefault();
    showDropParser(text);
  });
}

function parseCreds(text) {
  const out = { name: '', value: '', login: '', url: '', totp_seed: '', notes: '', folder_id: null };
  const lines = text.split('\n').map(l => l.trim()).filter(Boolean);
  for (const line of lines) {
    if (!out.url) {
      const m = /https?:\/\/[^\s]+/i.exec(line);
      if (m) out.url = m[0];
    }
    const kv = /^([a-z_\s\-]+)\s*[:=]\s*(.+)$/i.exec(line);
    if (kv) {
      const k = kv[1].trim().toLowerCase();
      const v = kv[2].trim();
      if (/(login|user(name)?|email|account|логин|почта)/.test(k) && !out.login) out.login = v;
      else if (/(pass(word)?|пароль)/.test(k) && !out.value) out.value = v;
      else if (/(totp|2fa|otp|seed)/.test(k) && !out.totp_seed) out.totp_seed = v;
      else if (/(url|сайт|host|address)/.test(k) && !out.url) out.url = v;
      else if (/(name|имя|title)/.test(k) && !out.name) out.name = v;
      continue;
    }
    if (!out.login && /^[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}$/i.test(line)) {
      out.login = line;
    }
  }
  if (!out.value) {
    for (const line of lines) {
      if (line.length < 6) continue;
      if (line === out.login || line === out.url) continue;
      if (/^https?:\/\//.test(line)) continue;
      if (/^[a-z_\s\-]+\s*[:=]/i.test(line)) continue;
      if (/^[a-z0-9._%+-]+@/i.test(line)) continue;
      out.value = line;
      break;
    }
  }
  if (!out.name) {
    if (out.url) {
      try {
        const u = new URL(out.url.startsWith('http') ? out.url : 'https://' + out.url);
        out.name = u.hostname + (out.login ? ' — ' + out.login : '');
      } catch { out.name = out.url; }
    } else if (out.login) out.name = out.login;
    else out.name = tr('Новый секрет ') + new Date().toISOString().slice(0,16);
  }
  out.notes = lines.filter(l =>
    l !== out.value && l !== out.login && l !== out.url && l !== out.totp_seed
  ).join('\n');
  if (out.url) {
    try {
      const host = new URL(out.url.startsWith('http') ? out.url : 'https://' + out.url).hostname;
      const matches = state.secrets.filter(s => {
        if (!s.url) return false;
        try { return new URL(s.url.startsWith('http') ? s.url : 'https://' + s.url).hostname === host; }
        catch { return s.url.includes(host); }
      });
      if (matches.length) {
        const counts = {};
        for (const m of matches) counts[m.folder_id] = (counts[m.folder_id] || 0) + 1;
        out.folder_id = parseInt(Object.entries(counts).sort((a,b) => b[1]-a[1])[0][0]);
      }
    } catch {}
  }
  return out;
}

function showDropParser(text) {
  const parsed = parseCreds(text);
  const suggestedFolder = state.folders.find(f => f.id === parsed.folder_id);

  const nameInp = el('input', { class: 'input rounded-lg px-3 py-2 w-full', value: parsed.name });
  const loginInp = el('input', { class: 'input rounded-lg px-3 py-2 w-full', value: parsed.login });
  const valInp = el('textarea', { rows: 2, class: 'input rounded-lg px-3 py-2 w-full font-mono text-sm' });
  valInp.value = parsed.value;
  const urlInp = el('input', { class: 'input rounded-lg px-3 py-2 w-full', value: parsed.url });
  const totpInp = el('input', { class: 'input rounded-lg px-3 py-2 w-full font-mono', value: parsed.totp_seed });
  const notesInp = el('textarea', { rows: 2, class: 'input rounded-lg px-3 py-2 w-full text-sm' });
  notesInp.value = parsed.notes;
  const folderSel = el('select', { class: 'input rounded-lg px-3 py-2 w-full' });
  for (const f of state.folders) {
    const o = el('option', { value: f.id }, f.name);
    if (parsed.folder_id === f.id) o.selected = true;
    folderSel.appendChild(o);
  }
  const note = parsed.folder_id
    ? el('p', { class: 'text-xs text-emerald-500 mb-2 flex items-center gap-1' }, icon('check', 12),
        tr(' Автодетект: «') + (suggestedFolder?.name || '') + tr('» (по совпадению url с существующими секретами)'))
    : el('p', { class: 'text-xs text-amber-400 mb-2 flex items-center gap-1' }, icon('alert', 12),
        tr(' Папка не угадалась — выбери вручную'));

  const overlay = modal(
    el('h2', { class: 'text-lg font-semibold text-white mb-3 flex items-center gap-2' },
      icon('download', 16), tr('Drop credentials → Новый секрет')),
    el('p', { class: 'text-xs text-slate-500 mb-3' }, tr('Vault распарсил drag-drop текст. Проверь и сохрани.')),
    note,
    el('div', { class: 'space-y-3' },
      el('div', null, el('label', { class: 'text-xs text-slate-400' }, tr('Имя секрета')), nameInp),
      el('div', null, el('label', { class: 'text-xs text-slate-400' }, tr('Папка')), folderSel),
      el('div', { class: 'grid grid-cols-2 gap-3' },
        el('div', null, el('label', { class: 'text-xs text-slate-400' }, 'Login'), loginInp),
        el('div', null, el('label', { class: 'text-xs text-slate-400' }, 'URL'), urlInp)),
      el('div', null, el('label', { class: 'text-xs text-slate-400' }, tr('Пароль')), valInp),
      el('div', null, el('label', { class: 'text-xs text-slate-400' }, tr('TOTP seed (опц.)')), totpInp),
      el('div', null, el('label', { class: 'text-xs text-slate-400' }, 'Notes'), notesInp),
      el('div', { class: 'flex gap-2 pt-3' },
        el('button', { class: 'btn-primary rounded-lg px-4 py-2 flex-1', onclick: async () => {
          if (!nameInp.value.trim()) return toast(tr('Имя обязательно'), 'error');
          if (!valInp.value.trim()) return toast(tr('Пароль/value пуст'), 'error');
          try {
            const notesParts = [notesInp.value.trim()].filter(Boolean);
            if (loginInp.value && !notesParts.join('').includes(loginInp.value)) {
              notesParts.unshift('login: ' + loginInp.value);
            }
            await api.createSecret({
              folder_id: parseInt(folderSel.value),
              name: nameInp.value.trim(),
              value: valInp.value,
              url: urlInp.value || '',
              tags: '',
              notes: notesParts.join('\n'),
              totp_seed: totpInp.value || '',
            });
            overlay.remove();
            await refreshMain(); renderMain();
            toast(tr('Секрет создан из drop-creds'), 'success');
          } catch (e) { toast(e.message, 'error'); }
        }}, tr('Сохранить')),
        el('button', { class: 'card rounded-lg px-4 py-2', onclick: () => overlay.remove() }, tr('Отмена')))));
}

// ── Bootstrap ────────────────────────────────────────────────────────────────
(async () => {
  try {
    const h = await api.health();
    state.initialized = h.initialized;
    state.unlocked = h.unlocked;
    if (!h.initialized) return renderInit();
    if (!h.unlocked) return renderUnlock();
    await refreshMain();
    renderMain();
    setupAutoLock();
    setupGlobalKeys();
    setupDropCreds();
  } catch (e) {
    document.body.appendChild(el('div', { class: 'p-8 text-red-400' }, tr`Vault не отвечает: ${e.message}`));
  }
})();
