// APS Vault — full pages: tokens, share links, webhooks, audit log, health report, settings.
// Each page renders into the <div class="page"> that app.js prepares; PAGES[view](root).

// Which envelope a token's key selects, by the decoded key length (sealed.py key_kind): 32 X25519, 64 GOST,
// 65 P-256, 1216 X25519+ML-KEM-768, 1248 GOST+ML-KEM-768. Shown next to «запечатано» in the token table.
function sealedKeyKindLabel(pkB64) {
  let n = 0; try { n = atob(pkB64 || '').length; } catch { n = 0; }
  return n === 64 ? 'ГОСТ ' : n === 65 ? 'P-256 ' : n === 1216 ? 'PQC ' : n === 1248 ? 'ГОСТ+PQC ' : '';
}
(() => {
  const P = window.PAGES;
  const H = (root, title, iconName, lead, ...actions) => {
    root.appendChild(el('div', { class: 'row between wrap' }, el('h1', null, icon(iconName, 20), title), actions.length ? el('div', { class: 'row' }, ...actions) : null));
    if (lead) root.appendChild(el('p', { class: 'lead' }, lead));
  };
  const empty = (iconName, title, sub) => el('div', { class: 'empty' }, icon(iconName, 36), el('h3', null, title), sub ? el('p', { class: 'small', style: { margin: 0 } }, sub) : null);
  const table = (cols, rows) => el('table', { class: 'table' }, el('thead', null, el('tr', null, ...cols.map(c => el('th', null, c)))), el('tbody', null, ...rows));

  // ── tokens ───────────────────────────────────────────────────────────────
  let tokenPresetFolder = null;
  P._tokensPreset = (fid) => { tokenPresetFolder = fid; const b = document.getElementById('tok-new'); if (b) b.click(); };
  P.tokens = async (root) => {
    H(root, tr('Токены'), 'key', tr('Машинный доступ: один токен — одна папка. Работает и при заблокированном хранилище, потому что несёт свою копию ключа папки. Показывается один раз.'),
      el('button', { class: 'btn', id: 'enrol-new', onclick: () => showEnrollmentEditor(tokenPresetFolder), title: tr('Узел сам сделает пару ключей и получит запечатанный токен по одноразовому коду') }, icon('server', 14), tr('Код регистрации узла')),
      el('button', { class: 'btn primary', id: 'tok-new', onclick: () => showTokenEditor(tokenPresetFolder) }, icon('plus', 14), tr('Новый токен')));
    tokenPresetFolder = null;
    let tokens, enrolments = [], alerts = []; try { [tokens, enrolments, alerts] = await Promise.all([api.listTokens(), api.listEnrollments(), api.listTokenAlerts()]); } catch (e) { return toast(e.message, 'error'); }
    state.tokenAlerts = alerts.length; renderSidebar();     // the sidebar count was drawn before the page loaded
    // 0.26: the token watch — open alerts first, with the actions that resolve them
    if (alerts.length) {
      const KIND = { canary: [tr('канарейка сработала'), 'danger'], new_network: [tr('новая сеть'), 'warn'], parallel_networks: [tr('две сети одновременно'), 'danger'], rate_spike: [tr('всплеск частоты'), 'warn'], enumeration: [tr('перебор секретов'), 'danger'] };
      const act = async (fn, okText) => { try { await fn(); if (okText) toast(okText, 'ok'); onRoute(); } catch (e) { toast(e.message, 'error'); } };
      root.appendChild(el('div', { 'data-testid': 'token-alerts' }, el('div', { class: 'nav-title' }, icon('alert', 14), ' ', tr`Сторож токенов: ${alerts.length} сигнал(ов)`), el('div', { class: 'card' }, table([tr('Токен'), tr('Что заметил'), tr('Откуда'), tr('Когда'), ''], alerts.map(a => {
        const [label, cls] = KIND[a.kind] || [a.kind, 'warn']; const d = a.detail || {};
        const what = el('div', null, el('span', { class: `badge ${cls}` }, label), a.count > 1 ? el('span', { class: 'xs muted' }, ' ', tr`×${a.count}`) : null,
          el('div', { class: 'xs muted' }, a.kind === 'new_network' ? tr`известные сети: ${(d.known_networks || []).join(', ') || '—'}` : a.kind === 'parallel_networks' ? tr`${d.other_network} и ${d.network} за ${d.seconds_apart} с` : a.kind === 'rate_spike' ? tr`${d.calls_10min} вызовов за 10 мин, обычно ≈ ${d.usual_10min}` : a.kind === 'enumeration' ? tr`${d.new_secrets_10min} новых секретов за 10 мин: ${(d.sample || []).join(', ')}` : tr('любое использование канарейки — чужие руки')),
          a.token_frozen ? el('div', { class: 'xs', style: { color: 'var(--danger)' } }, icon('lock', 10), ' ', tr('токен заморожен')) : null);
        return el('tr', null,
          el('td', null, el('div', { style: { fontWeight: 600 } }, a.token_name), el('div', { class: 'xs muted' }, icon('folder', 10), ' ', a.folder_name)),
          el('td', null, what), el('td', { class: 'mono small' }, a.ip, el('div', { class: 'xs muted' }, a.network)),
          el('td', { class: 'small' }, timeAgo(a.last_at)),
          el('td', { style: { textAlign: 'right', whiteSpace: 'nowrap' } },
            a.token_frozen && !a.token_canary ? el('button', { class: 'btn sm', 'data-testid': 'alert-unfreeze', onclick: () => act(() => api.unfreezeToken(a.token_id), tr('Токен разморожен')) }, icon('unlock', 12), tr('Разморозить')) : null, ' ',
            a.kind === 'new_network' || a.kind === 'parallel_networks' ? el('button', { class: 'btn sm', onclick: () => act(() => api.trustTokenNetwork(a.token_id, a.network), tr`Сеть ${a.network} доверена`) }, icon('globe', 12), tr('Доверять сети')) : null, ' ',
            el('button', { class: 'btn danger sm', 'data-testid': 'alert-revoke', onclick: async () => { if (!(await confirmDialog(tr`Отозвать токен «${a.token_name}»?`, tr('Сервисы с этим токеном сразу получат 401.'), { danger: true, ok: tr('Отозвать') }))) return; act(() => api.revokeToken(a.token_id), tr('Токен отозван')); } }, tr('Отозвать')), ' ',
            el('button', { class: 'btn ghost sm', 'data-testid': 'alert-ack', title: tr('Убрать сигнал из списка; токен остаётся как есть'), onclick: () => act(() => api.ackTokenAlert(a.id)) }, tr('Понятно'))));
      })))));
    }
    const liveCodes = enrolments.filter(e => e.active);
    if (liveCodes.length) root.appendChild(el('div', null, el('div', { class: 'nav-title' }, tr('Действующие коды регистрации')), el('div', { class: 'card' }, table([tr('Папка'), tr('Префикс имени'), tr('Использовано'), tr('Действует до'), tr('Кем выдан'), ''], liveCodes.map(e => el('tr', null,
      el('td', null, el('a', { href: routeHash('folder', e.folder_id) }, icon('folder', 12), ' ', e.folder_name)), el('td', { class: 'mono' }, e.name_prefix + '-…'),
      el('td', null, `${e.used_count} / ${e.max_uses}`), el('td', { class: 'small' }, fmtDate(e.expires_at)), el('td', { class: 'small muted' }, e.created_by),
      el('td', { style: { textAlign: 'right' } }, el('button', { class: 'btn danger sm', onclick: async () => { try { await api.revokeEnrollment(e.id); toast(tr('Код отозван'), 'ok'); onRoute(); } catch (er) { toast(er.message, 'error'); } } }, tr('Отозвать')))))))));
    const active = tokens.filter(t => !t.revoked), revoked = tokens.filter(t => t.revoked);
    if (!tokens.length) return root.appendChild(empty('key', tr('Токенов ещё нет'), tr('Создай токен для сервиса или агента — или выдай код регистрации, и узел получит запечатанный токен сам.')));
    const row = (t) => {
      const perms = [t.can_write ? el('span', { class: 'badge warn' }, tr('запись')) : el('span', { class: 'badge' }, tr('чтение')), t.can_read_notes ? el('span', { class: 'badge' }, 'notes') : null, t.can_read_totp ? el('span', { class: 'badge ok' }, 'TOTP') : null,
        t.canary ? el('span', { class: 'badge danger', title: tr('Канарейка: любое использование — сигнал и заморозка') }, icon('alert', 10), tr('канарейка')) : null,
        t.frozen ? el('span', { class: 'badge danger', title: t.frozen_reason }, icon('lock', 10), tr('заморожен')) : null,
        !t.canary && t.on_anomaly === 'freeze' ? el('span', { class: 'badge', title: tr('При аномалии токен замораживается') }, icon('shield', 10), tr('авто-заморозка')) : null,
        t.alerts_open ? el('span', { class: 'badge warn' }, icon('alert', 10), tr`сигналов: ${t.alerts_open}`) : null];
      const policy = [t.allowed_cidrs ? el('div', { class: 'xs mono muted' }, icon('globe', 10), ' ', t.allowed_cidrs) : null, t.allowed_hours ? el('div', { class: 'xs mono muted' }, icon('clock', 10), ' ', t.allowed_hours) : null,
        t.allowed_cert_fingerprints ? el('div', { class: 'xs mono muted', title: t.allowed_cert_fingerprints }, icon('shield_check', 10), ' mTLS ', t.allowed_cert_fingerprints.split(' ').map(f => f.slice(0, 12) + '…').join(', ')) : null,
        t.sealed ? el('div', { class: 'xs mono muted', title: t.client_public_key }, icon('lock', 10), ' ', tr('запечатано'), ' ', sealedKeyKindLabel(t.client_public_key), t.client_public_key.slice(0, 12) + '…') : null];
      const exp = t.expires_at ? (daysUntil(t.expires_at) < 0 ? el('span', { class: 'badge danger' }, tr('истёк')) : el('span', { class: 'xs muted' }, tr`до ${fmtDate(t.expires_at, false)}`)) : el('span', { class: 'xs faint' }, '∞');
      return el('tr', { style: t.revoked ? { opacity: .55 } : null },
        el('td', null, el('div', { style: { fontWeight: 600 } }, t.name), el('div', { class: 'xs faint mono' }, `id ${t.id}`)),
        el('td', null, el('a', { href: routeHash('folder', t.folder_id) }, icon('folder', 12), ' ', t.folder_name)),
        el('td', null, el('div', { class: 'row wrap', style: { gap: '4px' } }, ...perms), ...policy),
        el('td', null, el('div', { class: 'small' }, t.last_used ? timeAgo(t.last_used) : el('span', { class: 'faint' }, tr('не использовался'))), el('div', { class: 'xs faint' }, tr`создан ${timeAgo(t.created_at)}`)),
        el('td', null, exp),
        el('td', { style: { textAlign: 'right', whiteSpace: 'nowrap' } }, t.revoked ? el('span', { class: 'badge danger' }, tr('отозван')) : t.frozen && !t.canary ? el('button', { class: 'btn sm', onclick: async () => { try { await api.unfreezeToken(t.id); toast(tr('Токен разморожен'), 'ok'); onRoute(); } catch (e) { toast(e.message, 'error'); } } }, icon('unlock', 12), tr('Разморозить')) : null, t.revoked ? null : ' ', t.revoked ? null : el('button', { class: 'btn danger sm', onclick: async () => {
          if (!(await confirmDialog(tr`Отозвать токен «${t.name}»?`, tr('Сервисы с этим токеном сразу получат 401. Отмены нет — только новый токен.'), { danger: true, ok: tr('Отозвать') }))) return;
          try { await api.revokeToken(t.id); toast(tr('Токен отозван'), 'ok'); onRoute(); } catch (e) { toast(e.message, 'error'); }
        } }, tr('Отозвать'))));
    };
    root.appendChild(el('div', { class: 'card' }, table([tr('Имя'), tr('Папка'), tr('Права и политика'), tr('Использован'), tr('Срок'), ''], active.map(row))));
    if (revoked.length) {
      const body = el('div', { class: 'card hidden' }, table([tr('Имя'), tr('Папка'), tr('Права и политика'), tr('Использован'), tr('Срок'), ''], revoked.map(row)));
      root.append(el('button', { class: 'btn ghost sm', onclick: () => body.classList.toggle('hidden') }, icon('chevron_down', 13), tr`Отозванные (${revoked.length})`), body);
    }
  };
  function showEnrollmentEditor(presetFolder) {
    if (!state.folders.length) { toast(tr('Сначала создай папку'), 'warn'); return showFolderEditor(); }
    let folderId = presetFolder ?? null;
    const prefix = el('input', { class: 'input mono', value: 'node', placeholder: 'node', autocomplete: 'off', 'data-testid': 'enrol-prefix' });
    let ttl = 60, uses = 1; const flags = { can_read_notes: false, can_read_totp: false };
    const segOf = (opts, cur, onPick) => { const s = el('div', { class: 'seg' }); for (const [v, l] of opts) s.appendChild(el('button', { type: 'button', class: v === cur ? 'active' : '', onclick: (e) => { onPick(v); [...s.children].forEach(b => b.classList.toggle('active', b === e.currentTarget)); } }, l)); return s; };
    const tgl = (key, label, hint) => el('label', { class: 'row between', style: { cursor: 'pointer', padding: '8px 0' } },
      el('div', null, el('div', { class: 'small' }, label), el('div', { class: 'xs faint' }, hint)),
      el('span', { class: 'toggle', role: 'switch', 'aria-checked': 'false', tabindex: 0, onclick: (e) => { flags[key] = !flags[key]; e.currentTarget.classList.toggle('on', flags[key]); e.currentTarget.setAttribute('aria-checked', String(flags[key])); } }));
    const cidr = el('input', { class: 'input mono', placeholder: tr('Откуда разрешена регистрация (CIDR, опц.)') + ' 10.0.0.0/8', autocomplete: 'off' });
    const d = drawer(tr('Код регистрации узла'), [
      el('p', { class: 'muted small', style: { margin: 0 } }, tr('Узел выполняет одну команду с этим кодом: генерирует свою пару ключей, предъявляет код и публичный ключ и получает токен, запечатанный на свой ключ. Токен никто не копирует руками, приватный ключ не покидает узел.')),
      el('div', { class: 'field' }, el('label', null, tr('Папка (scope)')), folderPicker(folderId, (id) => { folderId = id; })),
      el('div', { class: 'field' }, el('label', null, tr('Префикс имени токена')), prefix, el('span', { class: 'xs faint' }, tr('Имя токена станет «префикс-имяхоста»'))),
      el('div', { class: 'field' }, el('label', null, tr('Код действует')), segOf([[15, tr`${15} мин`], [60, tr`${60} мин`], [24 * 60, tr`${24} ч`], [7 * 24 * 60, tr`${7} дн`]], ttl, (v) => { ttl = v; })),
      el('div', { class: 'field' }, el('label', null, tr('Сколько узлов могут им воспользоваться')), segOf([[1, '1'], [3, '3'], [10, '10'], [50, '50']], uses, (v) => { uses = v; })),
      el('div', { class: 'card', style: { padding: '2px 14px' } }, tgl('can_read_notes', tr('Читать заметки'), tr('поле notes в ответе машинного API')), tgl('can_read_totp', tr('Выдавать TOTP-коды'), tr('текущий одноразовый код по секретам с seed'))),
      el('div', { class: 'field' }, el('label', null, tr('Политика')), cidr, el('span', { class: 'xs faint' }, tr('Ограничение действует и на регистрацию, и на выданные токены'))),
    ], [
      el('button', { class: 'btn primary', 'data-testid': 'enrol-create', onclick: async () => {
        try {
          const r = await api.createEnrollment({ folder_id: folderId, name_prefix: prefix.value.trim() || 'node', ttl_minutes: ttl, max_uses: uses, ...flags, allowed_cidrs: cidr.value.trim() });
          d.close();
          const m = modal({ narrow: true }, el('h2', null, icon('server', 18), tr('Код регистрации')),
            el('p', { class: 'muted small', style: { margin: 0 } }, tr`Показывается один раз. Папка ${r.folder_name}, узлов: ${r.max_uses}, до ${fmtDate(r.expires_at)}. На узле:`),
            el('div', { class: 'codebox', 'data-testid': 'enrol-code' }, r.code),
            el('div', { class: 'codebox small', style: { fontSize: '12px' } }, r.command),
            el('p', { class: 'xs faint', style: { margin: 0 } }, tr('То же делают клиенты: enroll() в Node, Go и Java. Узел сохраняет токен и приватный ключ с правами 0600.')),
            el('div', { class: 'foot' }, el('button', { class: 'btn', onclick: () => copyText(r.code, tr('Код')) }, icon('copy', 14), tr('Копировать код')), el('button', { class: 'btn primary', onclick: () => { m.remove(); onRoute(); } }, tr('Готово'))));
        } catch (e) { toast(e.message, 'error'); }
      } }, icon('server', 14), tr('Выдать код')),
      el('button', { class: 'btn', onclick: () => d.close() }, tr('Отмена')),
    ]);
  }
  function showTokenEditor(presetFolder) {
    if (!state.folders.length) { toast(tr('Сначала создай папку'), 'warn'); return showFolderEditor(); }
    let folderId = presetFolder ?? null;
    const name = el('input', { class: 'input', placeholder: tr('например, core-node-1 или ci-deploy'), autocomplete: 'off' });
    const days = el('input', { class: 'input', type: 'number', min: 1, placeholder: '∞' });
    const flags = { can_read_notes: false, can_read_totp: false, can_write: false };
    const tgl = (key, label, hint, warn) => el('label', { class: 'row between', style: { cursor: 'pointer', padding: '8px 0' } },
      el('div', null, el('div', { class: 'small', style: warn ? { color: 'var(--warn)' } : null }, label), el('div', { class: 'xs faint' }, hint)),
      el('span', { class: 'toggle', role: 'switch', 'aria-checked': 'false', tabindex: 0, onclick: (e) => { flags[key] = !flags[key]; e.currentTarget.classList.toggle('on', flags[key]); e.currentTarget.setAttribute('aria-checked', String(flags[key])); },
        onkeydown: (e) => { if (e.key === ' ' || e.key === 'Enter') { e.preventDefault(); e.currentTarget.click(); } } }));
    const cidr = el('input', { class: 'input mono', placeholder: tr('Откуда (CIDR, опц.)') + ' 10.0.0.0/8 203.0.113.7', 'data-testid': 'tok-cidrs', autocomplete: 'off' });
    const hours = el('input', { class: 'input mono', placeholder: tr('Когда (окна, опц.)') + ' Mon-Fri 08:00-20:00', 'data-testid': 'tok-hours', autocomplete: 'off' });
    const certs = el('input', { class: 'input mono', placeholder: tr('Отпечатки клиентских сертификатов (опц.)') + ' SHA-1/SHA-256 hex', 'data-testid': 'tok-certs', autocomplete: 'off' });
    const pubkey = el('input', { class: 'input mono', placeholder: tr('Публичный ключ клиента, base64 (опц.): X25519 32 байта или ГОСТ Р 34.10-2012 64 байта'), 'data-testid': 'tok-pubkey', autocomplete: 'off', spellcheck: 'false' });
    // 0.26: the token watch — what kind of token, and what to do when it misbehaves
    let kind = 'service', onAnomaly = 'alert';
    const kindTiles = el('div', { class: 'tiles' }, ...[['service', 'key', tr('Сервисный'), tr('читает папку; сторож следит за сетями, частотой и перебором')], ['canary', 'alert', tr('Канарейка'), tr('никто не должен им пользоваться: любое использование — сигнал, токен замораживается, вызывающему — обычный 401')]].map(([k, ic, title, sub]) =>
      el('button', { type: 'button', class: `tile ${kind === k ? 'active' : ''}`, dataset: { kind: k }, 'data-testid': `tok-kind-${k}`, onclick: () => { kind = k; [...kindTiles.children].forEach(c => c.classList.toggle('active', c.dataset.kind === k)); anomalyBox.classList.toggle('hidden', k === 'canary'); } },
        el('div', { class: 'row', style: { gap: '8px', fontWeight: 600 } }, icon(ic, 16), title), el('div', { class: 'xs muted' }, sub))));
    const anomalyChips = el('div', { class: 'chips' }, ...[['alert', tr('уведомить (запрос проходит)')], ['freeze', tr('заморозить до разбора')]].map(([v, l]) => el('button', { type: 'button', class: `chip ${onAnomaly === v ? 'active' : ''}`, onclick: (e) => { onAnomaly = v; [...anomalyChips.children].forEach(c => c.classList.toggle('active', c === e.currentTarget)); } }, l)));
    const anomalyBox = el('div', { class: 'field' }, el('label', null, tr('При аномалии')), anomalyChips, el('span', { class: 'xs faint' }, tr('Новая сеть после периода обучения, две сети за 2 минуты, всплеск частоты, перебор секретов — сигнал в журнал, вебхук и уведомитель; «заморозить» ещё и останавливает токен до разморозки менеджером.')));
    const d = drawer(tr('Новый токен'), [
      el('div', { class: 'field' }, el('label', null, tr('Имя')), name),
      el('div', { class: 'field' }, el('label', null, tr('Папка (scope)')), folderPicker(folderId, (id) => { folderId = id; })),
      el('div', { class: 'field' }, el('label', null, tr('Тип')), kindTiles),
      anomalyBox,
      el('div', { class: 'card', style: { padding: '2px 14px' } },
        tgl('can_read_notes', tr('Читать заметки'), tr('поле notes в ответе машинного API')),
        tgl('can_read_totp', tr('Выдавать TOTP-коды'), tr('текущий одноразовый код по секретам с seed')),
        tgl('can_write', tr('Запись секретов'), tr('создавать и перезаписывать секреты своей папки (PUT /api/v1/m/secret/…)'), true)),
      el('div', { class: 'field' }, el('label', null, tr('Срок действия, дней')), days),
      el('div', { class: 'field' }, el('label', null, tr('Политика доступа')), cidr, hours, certs,
        el('span', { class: 'xs faint' }, tr('Запрос с другого адреса или вне окна получит 403 и попадёт в журнал и SIEM. Пусто — без ограничений.')),
        el('span', { class: 'xs faint' }, tr('Сертификаты: прокси проверяет клиентский сертификат (mTLS) и передаёт отпечаток заголовком X-Client-Cert-Fingerprint; токен с привязкой без такого сертификата получит 403. См. docs/ACCESS-POLICIES.md.'))),
      el('div', { class: 'field' }, el('label', null, tr('Запечатанная доставка')), pubkey,
        el('span', { class: 'xs faint' }, tr('С ключом значения уходят зашифрованными на этот ключ: X25519 + AES-GCM, а для ключа ГОСТ Р 34.10-2012 — VKO + Кузнечик-MGM. Открытый текст не проходит ни через прокси, ни через балансировщик, а украденный токен без приватного ключа бесполезен. Пару ключей делает клиентская библиотека (python -m aps_vault keygen [--gost] и аналоги). См. docs/SEALED.md.'))),
    ], [
      el('button', { class: 'btn primary', onclick: async () => {
        const body = { name: name.value.trim(), folder_id: folderId, ...flags, allowed_cidrs: cidr.value.trim(), allowed_hours: hours.value.trim(), allowed_cert_fingerprints: certs.value.trim(), client_public_key: pubkey.value.trim(), canary: kind === 'canary', on_anomaly: onAnomaly };
        const n = parseInt(days.value); if (n > 0) body.expires_days = n;
        if (!body.name) return toast(tr('Имя обязательно'), 'error');
        try { const r = await api.createToken(body); d.close(); showRawToken(r.raw_token); } catch (e) { toast(e.message, 'error'); }
      } }, icon('key', 14), tr('Создать')),
      el('button', { class: 'btn', onclick: () => d.close() }, tr('Отмена')),
    ]);
  }
  function showRawToken(token) {
    const m = modal({ narrow: true }, el('h2', null, icon('key', 18), tr('Токен создан')),
      el('div', { class: 'callout warn' }, icon('alert', 16), el('div', null, tr('Сохрани его сейчас — повторно не показывается. В конфиг сервиса кладётся как VAULT_TOKEN.'))),
      el('div', { class: 'codebox', style: { fontSize: '12px', letterSpacing: 0 } }, token),
      el('div', { class: 'foot' }, el('button', { class: 'btn', onclick: () => { m.remove(); onRoute(); } }, tr('Готово')), el('button', { class: 'btn primary', onclick: () => copyText(token, tr('Токен')) }, icon('copy', 14), tr('Копировать'))));
  }

  // ── share links ───────────────────────────────────────────────────────────
  P.shares = async (root) => {
    H(root, tr('Ссылки'), 'link', tr('Одноразовые ссылки на просмотр секрета или заметки без входа. Живут до срока или до N открытий; здесь их можно отозвать раньше.'),
      el('button', { class: 'btn primary', 'data-testid': 'note-share', onclick: showNoteShareDialog }, icon('note', 14), tr('Поделиться заметкой')));
    let rows; try { rows = await api.listShares(); } catch (e) { return toast(e.message, 'error'); }
    if (!rows.length) return root.appendChild(empty('link', tr('Ссылок нет'), tr('Создаются из карточки секрета — кнопка «Поделиться», или кнопкой «Поделиться заметкой» здесь (клавиша S).')));
    const stateOf = (l) => l.revoked ? ['danger', tr('отозвана')] : daysUntil(l.expires_at) < 0 || new Date(l.expires_at + 'Z') < new Date() ? ['', tr('истекла')] : l.used_count >= l.max_uses ? ['', tr('использована')] : ['ok', tr('активна')];
    root.appendChild(el('div', { class: 'card' }, table([tr('Секрет'), tr('Заметка'), tr('Открытий'), tr('Истекает'), tr('Статус'), ''], rows.map(l => {
      const [cls, label] = stateOf(l);
      const isNote = l.kind === 'note';
      return el('tr', null, el('td', null, isNote ? el('span', null, el('span', { class: 'badge', style: { marginRight: '6px' } }, icon('note', 10), tr('заметка')), l.secret_name) : el('a', { href: routeHash('secret', l.secret_id) }, l.secret_name)), el('td', { class: 'muted' }, l.note || '—'),
        el('td', { class: 'mono' }, `${l.used_count} / ${l.max_uses}`), el('td', { class: 'small' }, fmtDate(l.expires_at)), el('td', null, el('span', { class: `badge ${cls}` }, label)),
        el('td', { style: { textAlign: 'right' } }, cls === 'ok' ? el('button', { class: 'btn danger sm', onclick: async () => { try { await (isNote ? api.revokeNoteShare(l.id) : api.revokeShare(l.id)); toast(tr('Ссылка отозвана'), 'ok'); onRoute(); } catch (e) { toast(e.message, 'error'); } } }, tr('Отозвать')) : null));
    }))));
  };

  // ── webhooks ─────────────────────────────────────────────────────────────
  P.webhooks = async (root) => {
    H(root, tr('Вебхуки'), 'zap', tr('POST с HMAC-SHA256 подписью на каждое событие: создание, изменение, удаление секретов, выпуск и отзыв токенов. Для чатов, SIEM и автоматизации.'),
      el('button', { class: 'btn primary', onclick: showWebhookEditor }, icon('plus', 14), tr('Новый вебхук')));
    let rows; try { rows = await api.listWebhooks(); } catch (e) { return toast(e.message, 'error'); }
    if (!rows.length) return root.appendChild(empty('zap', tr('Вебхуков нет'), tr('Добавь URL приёмника — подпись проверяется заголовком X-Vault-Signature.')));
    root.appendChild(el('div', { class: 'card' }, table([tr('Имя'), 'URL', tr('События'), tr('Последняя доставка'), ''], rows.map(w => el('tr', null,
      el('td', null, el('div', { style: { fontWeight: 600 } }, w.name), !w.enabled ? el('span', { class: 'badge' }, tr('выключен')) : null),
      el('td', { class: 'mono small', style: { wordBreak: 'break-all' } }, w.url), el('td', { class: 'mono small' }, w.event_filter || '*'),
      el('td', { class: 'small' }, w.last_triggered_at ? el('span', null, timeAgo(w.last_triggered_at), ' ', el('span', { class: `badge ${/^2/.test(w.last_status || '') ? 'ok' : 'danger'}` }, w.last_status || '?')) : el('span', { class: 'faint' }, tr('ещё не было'))),
      el('td', { style: { textAlign: 'right' } }, el('button', { class: 'btn danger sm', onclick: async () => { if (!(await confirmDialog(tr`Удалить вебхук «${w.name}»?`, '', { danger: true }))) return; try { await api.deleteWebhook(w.id); onRoute(); } catch (e) { toast(e.message, 'error'); } } }, tr('Удалить'))))))));
  };
  function showWebhookEditor() {
    const name = el('input', { class: 'input', placeholder: tr('например, alerts-chat') });
    const url = el('input', { class: 'input mono', placeholder: 'https://hooks.example.com/vault', type: 'url' });
    const events = ['*', 'secret:*', 'secret:create', 'secret:update', 'secret:delete', 'token:create', 'token:revoke'];
    let filter = '*';
    const chips = el('div', { class: 'chips' }, ...events.map(ev => el('button', { type: 'button', class: `chip ${ev === filter ? 'active' : ''}`, onclick: (e) => { filter = ev; [...chips.children].forEach(c => c.classList.toggle('active', c === e.currentTarget)); } }, ev)));
    const d = drawer(tr('Новый вебхук'), [
      el('div', { class: 'field' }, el('label', null, tr('Имя')), name), el('div', { class: 'field' }, el('label', null, 'URL'), url),
      el('div', { class: 'field' }, el('label', null, tr('Какие события')), chips),
      el('div', { class: 'callout info' }, icon('info', 14), el('div', { class: 'small' }, tr('Адреса в частных сетях по умолчанию запрещены (SSRF); разрешить — VAULT_WEBHOOK_ALLOW_PRIVATE=1 на сервере.'))),
    ], [el('button', { class: 'btn primary', onclick: async () => {
      if (!name.value.trim() || !url.value.trim()) return toast(tr('Имя и URL обязательны'), 'error');
      try {
        const r = await api.createWebhook({ name: name.value.trim(), url: url.value.trim(), event_filter: filter, enabled: true }); d.close();
        const m = modal({ narrow: true }, el('h2', null, icon('zap', 18), tr('Вебхук создан')), el('p', { class: 'muted small', style: { margin: 0 } }, tr('Секрет подписи показывается один раз — им приёмник проверяет HMAC.')),
          el('div', { class: 'codebox', style: { fontSize: '12px', letterSpacing: 0 } }, r.signing_secret),
          el('div', { class: 'foot' }, el('button', { class: 'btn', onclick: () => { m.remove(); onRoute(); } }, tr('Готово')), el('button', { class: 'btn primary', onclick: () => copyText(r.signing_secret, tr('Секрет подписи')) }, icon('copy', 14), tr('Копировать'))));
      } catch (e) { toast(e.message, 'error'); }
    } }, tr('Создать')), el('button', { class: 'btn', onclick: () => d.close() }, tr('Отмена'))]);
  }

  // ── rotations (0.24) ────────────────────────────────────────────────────
  P.rotations = async (root) => {
    H(root, tr('Ротация'), 'refresh', tr('Хранилище меняет пароль прямо в целевой системе — PostgreSQL или твой HTTP-приёмник, — проверяет, что он принят, и только потом сохраняет новую версию. По расписанию или по кнопке.'));
    let rows, st; try { [rows, st] = await Promise.all([api.listRotations(), api.rotationStatus()]); } catch (e) { return toast(e.message, 'error'); }
    const status = el('div', { class: `callout ${st.configured ? 'ok' : 'warn'}`, 'data-testid': 'rotation-status' }, icon(st.configured ? 'shield_check' : 'alert', 16),
      el('div', { class: 'small', style: { flex: 1 } }, st.configured
        ? tr`Расписание активно: сервер проверяет сроки каждые ${st.tick_sec} с. Запланировано ${st.scheduled}, ждут выполнения ${st.due}, с ошибкой ${st.failing}.`
        : tr`НЕ НАСТРОЕНО: на сервере нет VAULT_ROTATION_KEY — расписание не выполняется, ротации запускаются только вручную. Запланировано ${st.scheduled}.`,
        st.cells_missing?.length ? el('div', { style: { marginTop: '4px' } }, tr`Папки без ячейки автоматизации (сохранены до появления ключа): ${st.cells_missing.join(', ')}`) : null),
      st.configured && st.cells_missing?.length && isOwner() ? el('button', { class: 'btn sm', onclick: async () => { try { const r = await api.writeRotationCells(); toast(tr`Ячейки записаны: папок ${r.folders}`, 'ok'); onRoute(); } catch (e) { toast(e.message, 'error'); } } }, tr('Записать ячейки')) : null);
    root.appendChild(status);
    if (!rows.length) return root.appendChild(empty('refresh', tr('Ротаций ещё нет'), tr('Открой карточку секрета → «Настроить ротацию»: выбери PostgreSQL или HTTP-приёмник и расписание.')));
    root.appendChild(el('div', { class: 'card' }, table([tr('Секрет'), tr('Куда'), tr('Расписание'), tr('Последний запуск'), tr('Следующий'), ''], rows.map(r => el('tr', null,
      el('td', null, el('a', { href: routeHash('folder', r.folder_id, r.secret_id), style: { fontWeight: 600 } }, r.secret_name), el('div', { class: 'xs muted' }, icon('folder', 10), ' ', r.folder_name)),
      el('td', null, el('span', { class: 'badge accent' }, icon(rotationTargetIcon(r.target), 10), rotationTargetLabel(r.target)), el('div', { class: 'xs faint mono' }, r.generate)),
      el('td', { class: 'small' }, r.interval_days ? tr`каждые ${r.interval_days} дн` : el('span', { class: 'faint' }, tr('только вручную'))),
      el('td', { class: 'small' }, r.last_at ? el('div', null, el('span', { class: `badge ${r.last_status === 'err' ? 'danger' : 'ok'}` }, r.last_status === 'err' ? tr('ошибка') : tr('успешно')), ' ', timeAgo(r.last_at), el('div', { class: 'xs muted' }, tr`запусков: ${r.runs}`), r.last_error ? el('div', { class: 'xs', style: { color: 'var(--danger)' } }, r.last_error) : null) : el('span', { class: 'faint' }, tr('ещё не было'))),
      el('td', { class: 'small' }, r.next_at ? fmtDate(r.next_at) : el('span', { class: 'faint' }, '—')),
      el('td', { style: { textAlign: 'right', whiteSpace: 'nowrap' } },
        can(r.folder_id, 'writer') ? el('button', { class: 'btn sm', onclick: async (e) => { const b = e.currentTarget; b.disabled = true; try { const x = await api.runRotation(r.secret_id); toast(tr`Ротация выполнена в системе: версия ${x.version}`, 'ok', 5000); } catch (er) { toast(er.message, 'error', 8000); } finally { onRoute(); } } }, icon('refresh', 12), tr('Выполнить')) : null, ' ',
        can(r.folder_id, 'manager') ? el('button', { class: 'btn danger sm', onclick: async () => { if (!(await confirmDialog(tr`Убрать ротацию «${r.secret_name}»?`, '', { danger: true, ok: tr('Убрать') }))) return; try { await api.deleteRotation(r.secret_id); onRoute(); } catch (er) { toast(er.message, 'error'); } } }, tr('Убрать')) : null))))));
  };

  // ── audit ─────────────────────────────────────────────────────────────────
  const GROUPS = [['all', tr('Все')], ['auth', tr('Вход')], ['secret', tr('Секреты')], ['rotation', tr('Ротация')], ['m:', tr('Машинный API')], ['token', tr('Токены')], ['share', tr('Ссылки')], ['policy', tr('Политика')]];
  P.audit = async (root) => {
    let limit = 200, group = 'all', q = '';
    const search = el('input', { type: 'search', class: 'input', placeholder: tr('Фильтр: действие, объект, IP…'), style: { maxWidth: '320px' } });
    const seg = el('div', { class: 'chips' });
    const exportBtn = el('button', { class: 'btn', onclick: () => {
      const rows = filtered(); const csv = ['ts,action,actor,target,ip,user_agent', ...rows.map(a => [a.ts, a.action, a.actor, a.target, a.ip, a.user_agent].map(v => '"' + String(v || '').replace(/"/g, '""') + '"').join(','))].join('\n');
      const blob = new Blob([csv], { type: 'text/csv' }); const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = `vault-audit-${new Date().toISOString().slice(0, 10)}.csv`; a.click(); URL.revokeObjectURL(a.href);
    } }, icon('download', 14), 'CSV');
    H(root, tr('Журнал'), 'log', tr('Каждое действие с датой, адресом и агентом. То же уходит в syslog/SIEM и в метрики.'), exportBtn);
    root.appendChild(el('div', { class: 'row between wrap' }, seg, search));
    const box = el('div', { class: 'card' }); root.appendChild(box);
    const more = el('button', { class: 'btn wide', onclick: async () => { limit += 500; await load(); } }, tr('Показать ещё'));
    root.appendChild(more);
    let items = [];
    const filtered = () => items.filter(a => (group === 'all' || a.action.startsWith(group) || (group === 'policy' && a.action.includes('policy'))) && (!q || `${a.action} ${a.target} ${a.actor} ${a.ip}`.toLowerCase().includes(q)));
    const cls = (a) => /fail|denied|lockdown|revoke|delete/.test(a) ? 'danger' : /unlock|create|init|enabled/.test(a) ? 'ok' : /read|lock$/.test(a) ? '' : 'accent';
    const render = () => {
      clear(box); const rows = filtered();
      clear(seg); for (const [g, l] of GROUPS) seg.appendChild(el('button', { class: `chip ${g === group ? 'active' : ''}`, onclick: () => { group = g; render(); } }, l, el('span', { class: 'faint xs' }, String(items.filter(a => g === 'all' || a.action.startsWith(g) || (g === 'policy' && a.action.includes('policy'))).length))));
      if (!rows.length) return box.appendChild(empty('log', tr('Записей нет')));
      box.appendChild(table([tr('Когда'), tr('Действие'), tr('Объект'), tr('Кто'), 'IP'], rows.map(a => el('tr', null,
        el('td', { class: 'small mono muted', style: { whiteSpace: 'nowrap' } }, fmtDate(a.ts)), el('td', null, el('span', { class: `badge ${cls(a.action)}` }, a.action)),
        el('td', { class: 'mono small', style: { wordBreak: 'break-all' } }, a.target || ''), el('td', { class: 'small' }, a.actor), el('td', { class: 'mono small muted' }, a.ip || '')))));
      more.classList.toggle('hidden', items.length < limit);
    };
    const load = async () => { try { items = await api.audit(limit); render(); } catch (e) { toast(e.message, 'error'); } };
    search.addEventListener('input', debounce(() => { q = search.value.trim().toLowerCase(); render(); }, 120));
    await load();
  };

  // ── health report ─────────────────────────────────────────────────────────
  P.health = async (root) => {
    H(root, tr('Здоровье'), 'activity', tr('Проверка всех секретов: слабые, повторяющиеся, давно не менялись, просроченные, забытые. Значения расшифровываются только в этой вкладке и никуда не отправляются; проверка утечек шлёт наружу лишь 5 символов хеша.'));
    const box = el('div', { class: 'stack' }, el('div', { class: 'empty' }, el('span', { class: 'spin' }, icon('refresh', 20)))); root.appendChild(box);
    let data, stats; try { [data, stats] = await Promise.all([api.exportJson(), api.stats()]); } catch (e) { clear(box).appendChild(empty('alert', e.message)); return; }
    const all = [], machineOnly = [];
    for (const f of data.folders) for (const s of f.secrets) {
      const entry = { ...s, folder: f.name, meta: state.secrets.find(x => x.name === s.name && x.folder_name === f.name) };
      if (s.value === null || s.machine_only) machineOnly.push(entry); else all.push(entry);   // hidden values cannot be rated
    }
    const now = Date.now();
    const weak = all.filter(s => estimateEntropy(s.value) < 40);
    const byVal = {}; for (const s of all) (byVal[s.value] = byVal[s.value] || []).push(s); const reused = Object.values(byVal).filter(g => g.length > 1);
    const old = all.filter(s => s.meta?.updated_at && now - new Date(s.meta.updated_at + 'Z') > 180 * 86400000);
    const expired = all.filter(s => s.meta?.expires_at && daysUntil(s.meta.expires_at) < 0), expiring = all.filter(s => s.meta?.expires_at && daysUntil(s.meta.expires_at) >= 0 && daysUntil(s.meta.expires_at) <= 30);
    const stale = all.filter(s => !s.meta?.last_accessed || now - new Date(s.meta.last_accessed + 'Z') > 90 * 86400000);
    const score = Math.max(0, Math.round(100 - (weak.length * 12 + reused.length * 10 + expired.length * 10 + old.length * 3 + expiring.length * 2) / Math.max(1, all.length) * 10));
    clear(box);
    const stat = (n, l, cls) => el('div', { class: 'card stat' }, el('div', { class: 'n', style: cls && n ? { color: `var(--${cls})` } : null }, String(n)), el('div', { class: 'l' }, l));
    box.appendChild(el('div', { class: 'stats' }, stat(score, tr('Оценка /100'), score < 60 ? 'danger' : score < 85 ? 'warn' : 'ok'), stat(all.length + machineOnly.length, tr('Секретов')), stat(machineOnly.length, tr('Только для машин'), ''), stat(weak.length, tr('Слабых'), 'danger'), stat(reused.length, tr('Повторов'), 'danger'), stat(expired.length, tr('Просрочено'), 'danger'), stat(expiring.length, tr('Истекают ≤30 дн'), 'warn'), stat(old.length, tr('Старше 180 дн'), 'warn'), stat(stale.length, tr('Не открывались 90 дн'), '')));
    // leak check for everything, on demand
    const leakBox = el('div', { class: 'card pad stack', style: { gap: '8px' } });
    const leakBtn = el('button', { class: 'btn', onclick: async () => {
      leakBtn.disabled = true; const prog = el('div', { class: 'meter' }, el('div', { style: { background: 'var(--accent)' } })); const found = []; clear(leakBox).append(el('div', { class: 'row between' }, el('span', { class: 'label' }, tr('Проверка по базе утечек')), el('span', { class: 'xs muted', id: 'leak-n' })), prog);
      const uniq = Object.keys(byVal); let done = 0;
      for (const v of uniq) {
        try { const n = await leakCount(v); if (n) found.push({ n, items: byVal[v] }); } catch (e) { clear(leakBox).appendChild(el('div', { class: 'callout warn' }, icon('alert', 14), e.status === 404 ? tr('Проверка утечек выключена (VAULT_HIBP=0)') : tr('База утечек недоступна'))); leakBtn.disabled = false; return; }
        done++; prog.firstChild.style.width = Math.round(done / uniq.length * 100) + '%'; document.getElementById('leak-n').textContent = `${done}/${uniq.length}`;
      }
      prog.remove();
      if (!found.length) leakBox.appendChild(el('div', { class: 'callout ok' }, icon('shield_check', 14), tr('Ни один пароль не найден в известных утечках')));
      else leakBox.appendChild(section(tr`В утечках: ${found.length}`, 'danger', found.flatMap(f => f.items.map(s => ({ s, extra: tr`найден ${f.n.toLocaleString(I18N.locale)} раз` })))));
      leakBtn.disabled = false;
    } }, icon('shield_check', 14), tr('Проверить все пароли по базе утечек'));
    leakBox.append(el('div', { class: 'row between wrap' }, el('div', null, el('div', { style: { fontWeight: 600 } }, tr('Утечки')), el('div', { class: 'xs muted' }, tr`${Object.keys(byVal).length} уникальных значений · k-анонимность, наружу уходит только префикс SHA-1`)), leakBtn));
    box.appendChild(leakBox);
    function section(title, cls, entries) {
      if (!entries.length) return null;
      const card = el('div', { class: 'card' }); card.appendChild(el('div', { class: 'frow', style: { gridTemplateColumns: '1fr auto' } }, el('div', { style: { fontWeight: 600 } }, icon('alert', 14), ' ', title), el('span', { class: `badge ${cls}` }, String(entries.length))));
      for (const { s, extra } of entries.slice(0, 50)) card.appendChild(el('div', { class: 'frow', style: { gridTemplateColumns: '1fr auto' } },
        el('div', null, el('a', { href: s.meta ? routeHash('secret', s.meta.id) : '#', style: { fontWeight: 500 } }, s.name), el('span', { class: 'xs muted' }, '  ', s.folder), extra ? el('div', { class: 'xs muted' }, extra) : null),
        s.meta ? el('button', { class: 'btn sm', onclick: () => showSecretEditor(s.meta.id) }, icon('pencil', 12), tr('Изменить')) : null));
      return card;
    }
    box.append(...[
      section(tr('Слабые пароли (< 40 бит)'), 'danger', weak.map(s => ({ s, extra: tr`~${estimateEntropy(s.value)} бит` }))),
      section(tr('Одинаковые значения в разных секретах'), 'danger', reused.flatMap(g => g.map(s => ({ s, extra: tr`ещё в: ${g.filter(x => x !== s).map(x => x.name).join(', ')}` })))),
      section(tr('Просроченная ротация'), 'danger', expired.map(s => ({ s, extra: expiryState(s.meta).text }))),
      section(tr('Истекают в ближайшие 30 дней'), 'warn', expiring.map(s => ({ s, extra: expiryState(s.meta).text }))),
      section(tr('Не менялись больше 180 дней'), 'warn', old.map(s => ({ s, extra: tr`изменён ${timeAgo(s.meta.updated_at)}` }))),
      section(tr('Не открывались 90 дней — может, уже не нужны?'), '', stale.map(s => ({ s, extra: s.meta?.last_accessed ? tr`открыт ${timeAgo(s.meta.last_accessed)}` : tr('не открывался ни разу') })))].filter(Boolean));
    if (machineOnly.length) box.appendChild(el('div', { class: 'callout info' }, icon('server', 16), el('div', { class: 'small' }, tr`${machineOnly.length} секрет(ов) только для машин: значения людям не показываются, поэтому сила и утечки для них не проверяются; ротация — из карточки.`)));
    if (!weak.length && !reused.length && !expired.length && !expiring.length && !old.length) box.appendChild(el('div', { class: 'callout ok' }, icon('shield_check', 16), tr('Всё в порядке: ни одной проблемы не найдено.')));
    // token usage
    if (stats.tokens_usage?.length) box.appendChild(el('div', { class: 'card' }, el('div', { class: 'frow', style: { gridTemplateColumns: '1fr' } }, el('div', { style: { fontWeight: 600 } }, tr('Расход токенов за 30 дней'))),
      table([tr('Токен'), tr('Чтений'), tr('Использован')], stats.tokens_usage.map(t => el('tr', null, el('td', { class: 'mono' }, t.name), el('td', { class: 'mono' }, String(t.reads_30d)), el('td', { class: 'small muted' }, t.last_used ? timeAgo(t.last_used) : tr('не использовался')))))));
    all.forEach(s => { s.value = ''; });   // drop plaintext as soon as the report is built
  };

  // ── settings ─────────────────────────────────────────────────────────────
  P.exportVault = async () => {
    try {
      const d = await api.exportJson(); const blob = new Blob([JSON.stringify(d, null, 2)], { type: 'application/json' });
      const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = `vault-export-${new Date().toISOString().slice(0, 10)}.json`; a.click(); URL.revokeObjectURL(a.href);
      toast(tr`Экспорт: ${d.folders.reduce((n, f) => n + f.secrets.length, 0)} секретов (открытым текстом — храни файл как секрет)`, 'ok', 5000);
    } catch (e) { toast(e.message, 'error'); }
  };
  // 0.29: import from another manager — pick the source, preview what would be created, then import
  P.importOther = () => {
    const SOURCES = [['auto', 'search', tr('Определить по файлу'), tr('формат распознаётся по содержимому')],
      ['bitwarden', 'shield', 'Bitwarden / Vaultwarden', tr('незашифрованный JSON-экспорт')],
      ['keepass', 'lock', 'KeePass XML', tr('экспорт «KeePass XML (2.x)»')],
      ['kdbx', 'lock', 'KeePass .kdbx', tr('сама база 3.1 / 4.x: пароль и/или ключ-файл, читается здесь')],
      ['1password', 'key', '1Password CSV', tr('экспорт CSV из 1Password 8')],
      ['1pux', 'key', '1Password 1PUX', tr('экспорт .1pux (zip)')],
      ['lastpass', 'key', 'LastPass CSV', tr('экспорт CSV из LastPass')],
      ['dashlane', 'key', 'Dashlane', tr('экспорт CSV (zip или credentials.csv)')],
      ['keeper', 'key', 'Keeper', tr('экспорт JSON (CSV — только с заголовком)')],
      ['passbolt', 'key', 'Passbolt', tr('экспорт «CSV (KeePass)» или .kdbx')],
      ['csv', 'file', tr('CSV с заголовком'), tr('колонки name/value, login, notes, url, tags, totp, folder')],
      ['dotenv', 'file', '.env', tr('KEY=VALUE — один секрет на ключ')],
      ['apsvault', 'inbox', 'APS Vault JSON', tr('экспорт этого хранилища')],
      ['passwork', 'shield', 'Passwork', tr('файл экспорта (JSON/CSV) или живой перенос по API')],
      ['hashicorp', 'server', 'HashiCorp Vault / Stronghold', tr('живой перенос из KV v2 по API')]];
    let source = 'auto', mode = 'source', conflict = 'skip', parsed = null, chosenFile = null;
    const tiles = el('div', { class: 'tiles', 'data-testid': 'import-sources' }, ...SOURCES.map(([k, ic, title, sub]) => el('button', { type: 'button', class: `tile ${source === k ? 'active' : ''}`, dataset: { source: k }, 'data-testid': `import-src-${k}`,
      onclick: () => { source = k; [...tiles.children].forEach(c => c.classList.toggle('active', c.dataset.source === k)); fileBox.classList.toggle('hidden', k === 'hashicorp'); kdbxBox.classList.toggle('hidden', !['kdbx', 'auto', 'passbolt'].includes(k)); hcBox.classList.toggle('hidden', k !== 'hashicorp'); pwBox.classList.toggle('hidden', k !== 'passwork'); preview.replaceChildren(); parsed = null; importBtn.disabled = true; } },
      el('div', { class: 'row', style: { gap: '8px', fontWeight: 600 } }, icon(ic, 16), title), el('div', { class: 'xs muted' }, sub))));
    const fileInput = el('input', { type: 'file', 'data-testid': 'import-file', style: { display: 'none' }, onchange: () => { chosenFile = fileInput.files[0] || null; fileName.textContent = chosenFile ? tr`${chosenFile.name} · ${Math.round(chosenFile.size / 1024)} КБ` : tr('файл не выбран'); } });
    const fileName = el('span', { class: 'small muted' }, tr('файл не выбран'));
    const drop = el('div', { class: 'callout info', style: { cursor: 'pointer', justifyContent: 'center' }, onclick: () => fileInput.click(),
      ondragover: (e) => { e.preventDefault(); }, ondrop: (e) => { e.preventDefault(); if (e.dataTransfer.files[0]) { chosenFile = e.dataTransfer.files[0]; fileName.textContent = tr`${chosenFile.name} · ${Math.round(chosenFile.size / 1024)} КБ`; } } },
      icon('upload', 16), el('div', { class: 'small' }, tr('Перетащи файл экспорта сюда или нажми, чтобы выбрать'), el('div', null, fileName)));
    const fileBox = el('div', { class: 'field' }, el('label', null, tr('Файл')), drop, fileInput);
    // KDBX (0.35): the database is opened here, in the session — password and/or key file; neither is stored
    const kdbxPw = el('input', { class: 'input mono', type: 'password', placeholder: tr('пароль базы .kdbx'), autocomplete: 'off', 'data-testid': 'import-kdbx-password' });
    let kdbxKeyfile = null;
    const kdbxKeyInput = el('input', { type: 'file', style: { display: 'none' }, onchange: () => { kdbxKeyfile = kdbxKeyInput.files[0] || null; kdbxKeyName.textContent = kdbxKeyfile ? kdbxKeyfile.name : tr('ключ-файл не выбран'); } });
    const kdbxKeyName = el('span', { class: 'small muted' }, tr('ключ-файл не выбран'));
    const kdbxBox = el('div', { class: 'field', 'data-testid': 'import-kdbx-box' }, el('label', null, tr('База KeePass: пароль и ключ-файл')), kdbxPw,
      el('div', { class: 'row', style: { gap: '8px', alignItems: 'center' } }, el('button', { type: 'button', class: 'btn sm', onclick: () => kdbxKeyInput.click() }, icon('key', 12), tr('Ключ-файл')), kdbxKeyName, kdbxKeyInput),
      el('span', { class: 'xs faint' }, tr('Нужно хотя бы одно из двух. База расшифровывается на сервере в рамках твоей сессии; пароль и ключ-файл не сохраняются.')));
    const hcAddr = el('input', { class: 'input mono', placeholder: 'https://vault.example.com', 'data-testid': 'import-hc-addr' });
    const hcToken = el('input', { class: 'input mono', type: 'password', placeholder: 'hvs.… / vlt_…', autocomplete: 'off', 'data-testid': 'import-hc-token' });
    const hcMount = el('input', { class: 'input mono', placeholder: 'secret', 'data-testid': 'import-hc-mount' });
    const hcPath = el('input', { class: 'input mono', placeholder: tr('путь внутри (опц.)') });
    const hcBox = el('div', { class: 'field hidden' }, el('label', null, 'HashiCorp Vault / Deckhouse Stronghold'), hcAddr, hcToken, el('div', { class: 'row' }, hcMount, hcPath),
      el('span', { class: 'xs faint' }, tr('Токен источника используется для чтения и не сохраняется. Нужны права list на <mount>/metadata/* и read на <mount>/data/*. Адрес в частной сети — только с VAULT_WEBHOOK_ALLOW_PRIVATE=1 на сервере.')));
    // Passwork: a file above, or the live API below (token + master password when the instance encrypts on the client)
    const pwHost = el('input', { class: 'input mono', placeholder: 'https://passwork.example.com', 'data-testid': 'import-pw-host' });
    const pwToken = el('input', { class: 'input mono', type: 'password', placeholder: tr('access token из Passwork'), autocomplete: 'off', 'data-testid': 'import-pw-token' });
    const pwMaster = el('input', { class: 'input mono', type: 'password', placeholder: tr('мастер-пароль Passwork (если включено шифрование на клиенте)'), autocomplete: 'off', 'data-testid': 'import-pw-master' });
    const pwVault = el('input', { class: 'input mono', placeholder: tr('id сейфа (опц., иначе все доступные)') });
    const pwBox = el('div', { class: 'field hidden' }, el('label', null, tr('Passwork по API (вместо файла)')), pwHost, pwToken, pwMaster, pwVault,
      el('span', { class: 'xs faint' }, tr('Токен берётся в профиле Passwork (API). Если в инсталляции включено шифрование на клиенте, нужен мастер-пароль — расшифровка идёт в хранилище, Passwork значений не видит. Токен и мастер-пароль не сохраняются. Если заполнен адрес — переносим по API, иначе разбираем файл.')));
    const into = el('input', { class: 'input', placeholder: tr('имя папки'), 'data-testid': 'import-into' });
    const prefix = el('input', { class: 'input', placeholder: tr('префикс, напр. bw/') });
    const modeChips = el('div', { class: 'chips' }, ...[['source', tr('папки как в источнике')], ['one', tr('всё в одну папку')]].map(([v, l]) => el('button', { type: 'button', class: `chip ${mode === v ? 'active' : ''}`, dataset: { mode: v }, onclick: (e) => { mode = v; [...modeChips.children].forEach(c => c.classList.toggle('active', c === e.currentTarget)); into.classList.toggle('hidden', v !== 'one'); prefix.classList.toggle('hidden', v !== 'source'); } }, l)));
    into.classList.add('hidden');
    const conflictChips = el('div', { class: 'chips' }, ...[['skip', tr('пропустить')], ['version', tr('записать новой версией')], ['rename', tr('добавить с суффиксом (2)')]].map(([v, l]) => el('button', { type: 'button', class: `chip ${conflict === v ? 'active' : ''}`, onclick: (e) => { conflict = v; [...conflictChips.children].forEach(c => c.classList.toggle('active', c === e.currentTarget)); } }, l)));
    const preview = el('div', { 'data-testid': 'import-preview' });
    const importBtn = el('button', { class: 'btn primary', disabled: true, 'data-testid': 'import-go', onclick: async () => {
      if (!parsed) return;
      importBtn.disabled = true;
      try {
        const r = await api.importJson({ folders: parsed.payload.folders, create_missing_folders: true, on_conflict: conflict });
        d.close(); toast(tr`Импорт: создано ${r.created_secrets} секретов, папок ${r.created_folders}, обновлено ${r.updated}, пропущено ${r.skipped}`, 'ok', 7000);
        await refreshData(); renderSidebar(); onRoute();
      } catch (e) { toast(e.message, 'error', 8000); importBtn.disabled = false; }
    } }, icon('upload', 14), tr('Импортировать'));
    const previewBtn = el('button', { class: 'btn', 'data-testid': 'import-preview-btn', onclick: async (e) => {
      const b = e.currentTarget; b.disabled = true; preview.replaceChildren(el('span', { class: 'spin' }, icon('refresh', 16)));
      try {
        const intoName = mode === 'one' ? into.value.trim() : '';
        if (mode === 'one' && !intoName) throw new Error(tr('Укажи имя папки, в которую всё сложить'));
        if (source === 'hashicorp') parsed = await api.importHashicorp({ addr: hcAddr.value.trim(), token: hcToken.value, mount: hcMount.value.trim(), path: hcPath.value.trim(), into_folder: intoName });
        else if (source === 'passwork' && pwHost.value.trim()) parsed = await api.importPasswork({ host: pwHost.value.trim(), token: pwToken.value, master_password: pwMaster.value, vault_id: pwVault.value.trim(), into_folder: intoName });
        else { if (!chosenFile) throw new Error(tr('Сначала выбери файл')); parsed = await api.importParse(chosenFile, source, intoName, mode === 'source' ? prefix.value.trim() : '', kdbxPw.value, kdbxKeyfile); }
        const st = parsed.stats;
        const rows = parsed.payload.folders.flatMap(f => f.secrets.map(x => el('tr', null, el('td', { class: 'small' }, icon('folder', 11), ' ', f.name), el('td', { style: { fontWeight: 500 } }, x.name),
          el('td', { class: 'small muted' }, x.login || '—'), el('td', null, x.totp_seed ? el('span', { class: 'badge ok' }, 'TOTP') : null, x.notes ? el('span', { class: 'badge' }, tr('заметки')) : null, x.url ? el('span', { class: 'badge' }, 'URL') : null, x.is_favorite ? icon('star', 11) : null))));
        preview.replaceChildren(
          el('div', { class: 'callout ok', 'data-testid': 'import-stats' }, icon('shield_check', 16), el('div', { class: 'small' }, tr`Формат: ${parsed.format}. Будет создано ${st.secrets} секретов в ${st.folders} папках; с логином ${st.with_login}, с TOTP ${st.with_totp}, с заметками ${st.with_notes}; пропущено в источнике ${st.skipped}.`)),
          parsed.warnings.length ? el('div', { class: 'callout warn' }, icon('alert', 16), el('div', { class: 'small' }, tr`Предупреждения (${parsed.warnings.length}):`, el('ul', { style: { margin: '4px 0 0 16px', padding: 0 } }, ...parsed.warnings.slice(0, 30).map(w => el('li', null, w))))) : null,
          el('div', { class: 'card', style: { maxHeight: '320px', overflow: 'auto' } }, table([tr('Папка'), tr('Имя'), tr('Логин'), ''], rows.slice(0, 500))),
          rows.length > 500 ? el('div', { class: 'xs muted' }, tr`…и ещё ${rows.length - 500}`) : null);
        importBtn.disabled = st.secrets === 0;
      } catch (er) { parsed = null; importBtn.disabled = true; preview.replaceChildren(el('div', { class: 'callout danger', 'data-testid': 'import-error' }, icon('alert', 16), el('div', { class: 'small' }, er.message))); }
      finally { b.disabled = false; }
    } }, icon('eye', 14), tr('Предпросмотр'));
    const d = drawer(tr('Импорт из другого менеджера'), [
      el('div', { class: 'field' }, el('label', null, tr('Откуда')), tiles),
      fileBox, kdbxBox, hcBox, pwBox,
      el('div', { class: 'field' }, el('label', null, tr('Куда')), modeChips, prefix, into),
      el('div', { class: 'field' }, el('label', null, tr('Если имя уже есть')), conflictChips),
      el('div', { class: 'callout info' }, icon('info', 14), el('div', { class: 'small' }, tr('Файл разбирается на сервере в рамках твоей сессии и не сохраняется; записывается только то, что показано в предпросмотре. Заметка без пароля становится секретом со значением-заметкой; TOTP из otpauth-ссылки сводится к seed.'))),
      preview,
    ], [previewBtn, importBtn, el('button', { class: 'btn', onclick: () => d.close() }, tr('Отмена'))]);
  };
  P.importVault = () => {
    const file = document.createElement('input'); file.type = 'file'; file.accept = '.json';
    file.onchange = async () => {
      if (!file.files[0]) return;
      try {
        const data = JSON.parse(await file.files[0].text());
        if (!data.folders) throw new Error(tr('JSON должен содержать поле folders'));
        if (!(await confirmDialog(tr`Импортировать ${data.folders.length} папок?`, tr('Существующие секреты с теми же именами будут пропущены.'), { ok: tr('Импортировать') }))) return;
        const r = await api.importJson({ folders: data.folders, create_missing_folders: true, skip_existing: true });
        toast(tr`Создано: ${r.created_secrets} секретов, ${r.created_folders} папок, пропущено ${r.skipped}`, 'ok', 5000); await refreshData(); renderSidebar();
      } catch (e) { toast(e.message, 'error'); }
    };
    file.click();
  };
  // ── folder access (0.30): a manager grants roles on the folders they manage ──
  P._folderAccess = async (fid) => {
    const f = state.folders.find(x => x.id === fid); if (!f) return;
    let users; try { users = await api.listUsers(); } catch (e) { return toast(e.message, 'error'); }
    const me = state.me || {};
    const body = el('div', { class: 'stack' });
    const render = () => {
      body.replaceChildren();
      if (!users.length) return body.appendChild(el('div', { class: 'callout info' }, icon('info', 14), el('div', { class: 'small' }, tr('Пользователей ещё нет — их приглашает администратор'))));
      body.appendChild(el('div', { class: 'card' }, table([tr('Кто'), tr('Роль на папке'), ''], users.map(u => {
        const cur = (u.grants || []).find(g => g.folder_id === fid)?.role || null;
        const self = me.kind === 'user' && u.id === me.id;
        const chips = self ? el('span', { class: 'xs muted' }, tr('свою роль меняет администратор')) : roleChips(cur, async (r) => { try { await api.setGrant(u.id, fid, r); toast(tr`${u.email}: ${ROLE_LABEL()[r]}`, 'ok', 1500); u.grants = [...(u.grants || []).filter(g => g.folder_id !== fid), { folder_id: fid, role: r }]; render(); } catch (e) { toast(e.message, 'error'); } }, `access-${u.email}`);
        return el('tr', null, el('td', null, el('div', { style: { fontWeight: 600 } }, u.name || u.email), el('div', { class: 'xs muted' }, u.email)), el('td', null, chips),
          el('td', { style: { textAlign: 'right' } }, cur && !self ? el('button', { class: 'btn ghost sm', 'data-testid': `access-revoke-${u.email}`, onclick: async () => { try { await api.removeGrant(u.id, fid); toast(tr`${u.email}: доступ снят`, 'ok', 1500); u.grants = (u.grants || []).filter(g => g.folder_id !== fid); render(); } catch (e) { toast(e.message, 'error'); } } }, tr('снять')) : null));
      }))));
    };
    render();
    modal({ wide: true }, el('h2', null, icon('user', 18), tr`Доступ к папке «${f.name}»`),
      el('p', { class: 'muted small', style: { margin: 0 } }, tr('Читатель видит значения, редактор меняет секреты, менеджер ещё выпускает токены и выдаёт роли на эту папку. Ключ папки заворачивается на ключ человека прямо здесь — администратор не нужен.')),
      body, el('div', { class: 'foot' }, el('button', { class: 'btn', onclick: (e) => e.currentTarget.closest('.overlay').remove() }, tr('Готово'))));
  };
  // ── users and roles (0.20, owner only) ──
  const ROLE_LABEL = () => ({ reader: tr('читатель'), writer: tr('редактор'), manager: tr('менеджер') });
  const roleChips = (cur, onPick, testid) => { const w = el('div', { class: 'chips', 'data-testid': testid }); for (const r of ['reader', 'writer', 'manager']) w.appendChild(el('button', { type: 'button', class: `chip ${cur === r ? 'active' : ''}`, dataset: { role: r }, onclick: (e) => { onPick(r); [...w.children].forEach(c => c.classList.toggle('active', c === e.currentTarget)); } }, ROLE_LABEL()[r])); return w; };
  const showInviteLink = (url, email) => {
    const full = `${location.origin}${url}`;
    const m = modal({ narrow: true }, el('h2', null, icon('user', 18), tr('Приглашение создано')),
      el('p', { class: 'muted small', style: { margin: 0 } }, tr`Передай ссылку ${email} любым доверенным каналом. Открыв её, человек задаст себе пароль; ссылка одноразовая и действует 7 дней. Повторно она не показывается — при утере выпусти новую кнопкой «Сбросить пароль».`),
      el('div', { class: 'codebox', 'data-testid': 'invite-url' }, full),
      el('div', { class: 'foot' }, el('button', { class: 'btn', onclick: () => copyText(full, tr('Ссылка')) }, icon('copy', 14), tr('Копировать')), el('button', { class: 'btn primary', onclick: () => { m.remove(); onRoute(); } }, tr('Готово'))));
  };
  P.users = async (root) => {
    H(root, tr('Пользователи'), 'user', tr('Именные учётки с ролью на каждую папку: читатель видит значения, редактор меняет секреты, менеджер ещё выпускает токены и ссылки. Всё остальное — папки, настройки, вебхуки, экспорт — остаётся у администратора с master-password.'),
      el('button', { class: 'btn primary', id: 'user-new', onclick: () => showUserEditor() }, icon('plus', 14), tr('Пригласить')));
    let users; try { users = await api.listUsers(); } catch (e) { return toast(e.message, 'error'); }
    if (!users.length) return root.appendChild(empty('user', tr('Пользователей ещё нет'), tr('Пригласи коллегу: он получит ссылку, задаст пароль и увидит только те папки, к которым ты дал доступ.')));
    const grantsCell = (u) => el('div', { class: 'row wrap', style: { gap: '4px' } },
      ...u.grants.map(g => el('span', { class: `badge ${g.role === 'manager' ? 'warn' : g.role === 'writer' ? 'ok' : ''}`, title: ROLE_LABEL()[g.role] }, icon('folder', 10), ' ', g.folder_name, ' · ', ROLE_LABEL()[g.role])),
      u.is_active ? el('button', { class: 'btn ghost sm', onclick: () => showGrantEditor(u), 'data-testid': `grants-${u.email}` }, icon('pencil', 12), tr('Доступ')) : null);
    const row = (u) => el('tr', { style: u.is_active ? null : { opacity: .55 } },
      el('td', null, el('div', { style: { fontWeight: 600 } }, u.name || u.email), el('div', { class: 'xs faint mono' }, u.email)),
      el('td', null, u.is_active ? (u.invite_pending ? el('span', { class: 'badge warn' }, tr('ждёт приглашения')) : u.has_password ? el('span', { class: 'badge ok' }, tr('активен')) : el('span', { class: 'badge' }, tr('без пароля'))) : el('span', { class: 'badge danger' }, tr('отключён'))),
      el('td', null, grantsCell(u)),
      el('td', null, el('div', { class: 'small' }, u.last_login ? timeAgo(u.last_login) : el('span', { class: 'faint' }, tr('не входил'))), el('div', { class: 'xs faint' }, tr`создан ${timeAgo(u.created_at)}`)),
      el('td', { style: { textAlign: 'right' } }, u.is_active ? el('div', { class: 'row', style: { justifyContent: 'flex-end', gap: '6px' } },
        el('button', { class: 'btn sm', title: tr('Новая ссылка-приглашение: старый пароль перестанет действовать, сессии закроются, доступ к папкам сохранится'), onclick: async () => {
          if (!(await confirmDialog(tr`Сбросить пароль ${u.email}?`, tr('Текущий пароль и все сессии пользователя перестанут действовать. Доступ к папкам сохранится — он задаст новый пароль по ссылке.'), { danger: false, ok: tr('Сбросить') }))) return;
          try { const r = await api.reinviteUser(u.id); showInviteLink(r.invite_url, u.email); } catch (e) { toast(e.message, 'error'); } } }, icon('refresh', 13), tr('Сбросить пароль')),
        el('button', { class: 'btn danger sm', onclick: async () => {
          if (!(await confirmDialog(tr`Отключить ${u.email}?`, tr('Сессии закроются сразу, доступ ко всем папкам будет снят. Учётку можно пригласить заново.'), { danger: true, ok: tr('Отключить') }))) return;
          try { await api.deactivateUser(u.id); toast(tr('Пользователь отключён'), 'ok'); onRoute(); } catch (e) { toast(e.message, 'error'); } } }, tr('Отключить'))) : null));
    root.appendChild(el('div', { class: 'card' }, table([tr('Кто'), tr('Статус'), tr('Доступ к папкам'), tr('Активность'), ''], users.map(row))));
  };
  function showUserEditor() {
    if (!state.folders.length) { toast(tr('Сначала создай папку'), 'warn'); return showFolderEditor(); }
    const email = el('input', { class: 'input', type: 'email', placeholder: 'name@company.ru', autocomplete: 'off', 'data-testid': 'user-new-email' });
    const name = el('input', { class: 'input', placeholder: tr('Имя (как показывать в журнале)'), autocomplete: 'off', 'data-testid': 'user-new-name' });
    const grants = {};
    const rows = el('div', { class: 'stack', style: { gap: '8px' } });
    for (const f of [...state.folders].sort((a, b) => a.name.localeCompare(b.name, I18N.locale))) {
      const chips = roleChips(null, (r) => { grants[f.id] = r; }, `new-grant-${f.name}`);
      const none = el('button', { type: 'button', class: 'chip active', onclick: (e) => { delete grants[f.id]; [...chips.children].forEach(c => c.classList.remove('active')); e.currentTarget.classList.add('active'); } }, tr('нет доступа'));
      chips.prepend(none);
      [...chips.children].slice(1).forEach(c => c.addEventListener('click', () => none.classList.remove('active')));
      rows.appendChild(el('div', { class: 'row between wrap', style: { gap: '6px' } }, el('span', { class: 'small', style: { minWidth: '120px' } }, icon('folder', 12), ' ', f.name), chips));
    }
    const d = drawer(tr('Пригласить пользователя'), [
      el('div', { class: 'field' }, el('label', null, 'Email'), email),
      el('div', { class: 'field' }, el('label', null, tr('Имя')), name),
      el('div', { class: 'field' }, el('label', null, tr('Доступ к папкам')), rows,
        el('span', { class: 'xs faint' }, tr('Читатель — видит и копирует значения; редактор — ещё создаёт, меняет, удаляет и ротирует; менеджер — ещё выпускает токены и ссылки на секреты папки. Доступ можно менять потом.'))),
    ], [
      el('button', { class: 'btn primary', 'data-testid': 'user-new-submit', onclick: async () => {
        const body = { email: email.value.trim(), name: name.value.trim(), grants: Object.entries(grants).map(([folder_id, role]) => ({ folder_id: parseInt(folder_id), role })) };
        if (!body.email) return toast(tr('Email обязателен'), 'error');
        try { const r = await api.createUser(body); d.close(); showInviteLink(r.invite_url, r.email); } catch (e) { toast(e.message, 'error'); }
      } }, icon('user', 14), tr('Пригласить')),
      el('button', { class: 'btn', onclick: () => d.close() }, tr('Отмена')),
    ]);
  }
  function showGrantEditor(u) {
    const cur = Object.fromEntries(u.grants.map(g => [g.folder_id, g.role]));
    const rows = el('div', { class: 'stack', style: { gap: '8px' } });
    for (const f of [...state.folders].sort((a, b) => a.name.localeCompare(b.name, I18N.locale))) {
      const chips = roleChips(cur[f.id] || null, async (r) => { try { await api.setGrant(u.id, f.id, r); cur[f.id] = r; none.classList.remove('active'); toast(tr`${f.name}: ${ROLE_LABEL()[r]}`, 'ok', 1500); } catch (e) { toast(e.message, 'error'); } }, `grant-${u.email}-${f.name}`);
      const none = el('button', { type: 'button', class: `chip ${cur[f.id] ? '' : 'active'}`, onclick: async (e) => { try { if (cur[f.id]) await api.removeGrant(u.id, f.id); delete cur[f.id]; [...chips.children].forEach(c => c.classList.remove('active')); e.currentTarget.classList.add('active'); toast(tr`${f.name}: доступ снят`, 'ok', 1500); } catch (er) { toast(er.message, 'error'); } } }, tr('нет доступа'));
      chips.prepend(none);
      rows.appendChild(el('div', { class: 'row between wrap', style: { gap: '6px' } }, el('span', { class: 'small', style: { minWidth: '120px' } }, icon('folder', 12), ' ', f.name), chips));
    }
    const m = modal({}, el('h2', null, icon('user', 18), tr`Доступ: ${u.name || u.email}`),
      el('p', { class: 'muted small', style: { margin: 0 } }, tr('Изменения применяются сразу: ключ папки заворачивается на личный ключ пользователя или снимается.')),
      rows, el('div', { class: 'foot' }, el('button', { class: 'btn primary', onclick: () => { m.remove(); onRoute(); } }, tr('Готово'))));
  }
  // ── a user's own page (0.20) ──
  P.profile = async (root) => {
    H(root, tr('Мой профиль'), 'user');
    const me = state.me || {};
    const setting = (t, d, ctl) => el('div', { class: 'setting' }, el('div', null, el('div', { class: 't' }, t), d ? el('div', { class: 'd' }, d) : null), ctl);
    const grants = Object.entries(me.grants || {}).map(([fid, role]) => { const f = state.folders.find(x => x.id === parseInt(fid)); return f ? el('span', { class: 'badge' }, icon('folder', 10), ' ', f.name, ' · ', ROLE_LABEL()[role]) : null; });
    root.appendChild(el('div', { class: 'card' },
      setting(tr('Учётная запись'), me.email, el('span', { class: 'mono small' }, me.name || '')),
      setting(tr('Мои папки'), tr('Роль на каждую папку выдаёт администратор'), el('div', { class: 'row wrap', style: { gap: '4px' } }, ...grants)),
      setting(tr('Ключи безопасности и биометрия'), tr('YubiKey, Touch ID, Android: с PRF — вход касанием без пароля, без PRF — второй фактор к паролю'), el('button', { class: 'btn primary sm', 'data-testid': 'me-webauthn-add', onclick: () => {
        if (!window.PublicKeyCredential) return toast(tr('Этот браузер не поддерживает WebAuthn'), 'error');
        const nm = el('input', { class: 'input', placeholder: tr('например, YubiKey 5 или Touch ID на MacBook'), value: '' });
        const pw = el('input', { type: 'password', class: 'input mono', placeholder: tr('пароль'), autocomplete: 'current-password' });
        const m = modal({ narrow: true }, el('h2', null, icon('key', 18), tr('Добавить ключ безопасности')),
          el('div', { class: 'field' }, el('label', null, tr('Название')), nm), el('div', { class: 'field' }, el('label', null, tr('Твой пароль')), pw),
          el('div', { class: 'foot' }, el('button', { class: 'btn', onclick: () => m.remove() }, tr('Отмена')), el('button', { class: 'btn primary', 'data-testid': 'me-webauthn-create', onclick: async (e) => {
            e.currentTarget.disabled = true;
            try {
              const o = await api.webauthnRegisterOptions(nm.value.trim() || 'security key'); const c = await webauthnCreate(o);
              const r = await api.webauthnRegisterFinish({ name: nm.value.trim() || 'security key', credential: c.credential, prf_output: c.prf_output, transports: c.transports, master_password: pw.value });
              m.remove(); toast(r.prf ? tr('Ключ добавлен: вход одним касанием доступен') : tr('Ключ добавлен как второй фактор (PRF не поддерживается)'), 'ok', 6000); onRoute();
            } catch (er) { toast(er.message, 'error', 6000); e.currentTarget.disabled = false; }
          } }, tr('Добавить'))));
      } }, icon('plus', 13), tr('Добавить ключ'))),
      setting(tr('Одноразовые коды (TOTP)'), me.totp_enabled ? tr('Включены: при входе паролем нужен код из приложения') : tr('Второй фактор к паролю: Google Authenticator, Яндекс Ключ, 1Password. Seed хранится под твоим личным ключом'),
        me.totp_enabled
          ? el('button', { class: 'btn sm', 'data-testid': 'me-totp-off', onclick: () => {
              const code = el('input', { class: 'input mono', placeholder: tr('код из приложения'), inputmode: 'numeric', maxlength: 8 });
              const m = modal({ narrow: true }, el('h2', null, icon('shield', 18), tr('Выключить одноразовые коды')), el('div', { class: 'field' }, el('label', null, tr('Текущий код')), code),
                el('div', { class: 'foot' }, el('button', { class: 'btn', onclick: () => m.remove() }, tr('Отмена')), el('button', { class: 'btn danger', onclick: async () => { try { await api.meTotpDisable(code.value.trim()); m.remove(); toast(tr('Одноразовые коды выключены'), 'ok'); state.me = await api.me(); onRoute(); } catch (e) { toast(e.message, 'error', 6000); } } }, tr('Выключить'))));
            } }, tr('Выключить'))
          : el('button', { class: 'btn primary sm', 'data-testid': 'me-totp-on', onclick: async () => {
              let setup; try { setup = await api.meTotpSetup(); } catch (e) { return toast(e.message, 'error'); }
              const code = el('input', { class: 'input mono', placeholder: tr('код из приложения'), inputmode: 'numeric', maxlength: 8, 'data-testid': 'me-totp-code' });
              const pw = el('input', { type: 'password', class: 'input mono', placeholder: tr('пароль'), autocomplete: 'current-password', 'data-testid': 'me-totp-password' });
              const m = modal({ narrow: true }, el('h2', null, icon('shield', 18), tr('Включить одноразовые коды')),
                el('p', { class: 'muted small', style: { margin: 0 } }, tr('Отсканируй QR в приложении-аутентификаторе или введи секрет вручную, затем подтверди кодом и паролем.')),
                setup.qr_data_url ? el('img', { src: setup.qr_data_url, alt: 'QR', style: { width: '180px', height: '180px', display: 'block', margin: '0 auto', background: '#fff', padding: '6px', borderRadius: '8px' } }) : null,
                el('div', { class: 'codebox', style: { fontSize: '12px', letterSpacing: '1px' }, 'data-testid': 'me-totp-secret' }, setup.secret_base32),
                el('div', { class: 'field' }, el('label', null, tr('Код из приложения')), code), el('div', { class: 'field' }, el('label', null, tr('Твой пароль')), pw),
                el('div', { class: 'foot' }, el('button', { class: 'btn', onclick: () => m.remove() }, tr('Отмена')), el('button', { class: 'btn primary', 'data-testid': 'me-totp-confirm', onclick: async (e) => {
                  const b = e.currentTarget; b.disabled = true;
                  try { await api.meTotpVerify(setup.secret_base32, code.value.trim(), pw.value); m.remove(); toast(tr('Одноразовые коды включены: при следующем входе понадобится код'), 'ok', 6000); state.me = await api.me(); onRoute(); }
                  catch (er) { toast(er.message, 'error', 6000); b.disabled = false; }
                } }, tr('Включить'))));
            } }, icon('shield', 13), tr('Включить'))),
      setting(tr('Пароль'), tr('Им зашифрован твой личный ключ; администратор его не знает'), el('button', { class: 'btn sm', 'data-testid': 'me-password', onclick: () => {
        const p0 = el('input', { type: 'password', class: 'input mono', placeholder: tr('текущий пароль'), autocomplete: 'current-password' });
        const p1 = el('input', { type: 'password', class: 'input mono', placeholder: tr('новый (не короче 12)'), autocomplete: 'new-password' });
        const mm = modal({ narrow: true }, el('h2', null, icon('key', 18), tr('Сменить пароль')), el('div', { class: 'field' }, el('label', null, tr('Текущий')), p0), el('div', { class: 'field' }, el('label', null, tr('Новый')), p1),
          el('div', { class: 'foot' }, el('button', { class: 'btn', onclick: () => mm.remove() }, tr('Отмена')), el('button', { class: 'btn primary', onclick: async () => { try { await api.mePassword(p0.value, p1.value); mm.remove(); toast(tr('Пароль изменён'), 'ok'); } catch (e) { toast(e.message, 'error', 6000); } } }, tr('Сменить'))));
      } }, tr('Сменить')))));
    let wa = { credentials: [], second_factor: false }; try { wa = await api.webauthnList(); } catch {}
    if (wa.credentials.length) {
      root.appendChild(el('div', { class: 'card' }, setting(tr('Требовать ключ при входе паролем'), tr('Второй фактор: после пароля нужно коснуться любого зарегистрированного ключа. Выключается автоматически, если удалить все ключи'),
        el('span', { class: `toggle ${wa.second_factor ? 'on' : ''}`, role: 'switch', tabindex: 0, 'data-testid': 'me-webauthn-2fa', onclick: async () => { try { let pw = ''; if (wa.second_factor) { pw = await passwordDialog(tr('Отключить ключ как второй фактор?'), tr('Подтверди своим паролем: без ключа для входа снова хватит пароля.')); if (pw === null) return; } await api.webauthnSecondFactor(!wa.second_factor, pw); onRoute(); } catch (er) { toast(er.message, 'error'); } } }))));
      root.appendChild(el('div', null, el('div', { class: 'nav-title' }, tr('Ключи безопасности')), el('div', { class: 'card' }, table([tr('Название'), tr('Вход касанием'), tr('Добавлен'), tr('Использован'), ''], wa.credentials.map(c => el('tr', null,
        el('td', { style: { fontWeight: 600 } }, c.name), el('td', null, el('span', { class: `badge ${c.prf ? 'ok' : ''}` }, c.prf ? 'PRF' : tr('2-й фактор'))),
        el('td', { class: 'small muted' }, fmtDate(c.created_at)), el('td', { class: 'small muted' }, c.last_used ? timeAgo(c.last_used) : '—'),
        el('td', { style: { textAlign: 'right' } }, el('button', { class: 'btn danger sm', onclick: async () => { if (!(await confirmDialog(tr`Удалить ключ «${c.name}»?`, '', { danger: true }))) return; try { await api.webauthnDelete(c.id); onRoute(); } catch (er) { toast(er.message, 'error'); } } }, tr('Удалить')))))))));
    }
  };
  P.settings = async (root) => {
    H(root, tr('Настройки'), 'settings');
    const setting = (t, d, ctl) => el('div', { class: 'setting' }, el('div', null, el('div', { class: 't' }, t), d ? el('div', { class: 'd' }, d) : null), ctl);
    const segOf = (opts, cur, onPick) => { const s = el('div', { class: 'seg' }); for (const [v, l] of opts) s.appendChild(el('button', { class: v === cur ? 'active' : '', onclick: (e) => { onPick(v); [...s.children].forEach(b => b.classList.toggle('active', b === e.currentTarget)); } }, l)); return s; };
    const pref = (key, field) => (v) => { state.prefs[field] = v; PREFS.set(key, v); };
    root.appendChild(el('div', null, el('div', { class: 'nav-title' }, tr('Интерфейс')), el('div', { class: 'card' },
      setting(tr('Тема'), tr('Тёмная, светлая или как в системе'), segOf([['auto', tr('Система')], ['dark', tr('Тёмная')], ['light', tr('Светлая')]], getTheme(), (v) => { applyTheme(v); renderTopbarTheme(); })),
      setting(tr('Язык'), 'Interface language', segOf([['ru', 'Русский'], ['en', 'English']], I18N.lang, (v) => I18N.setLang(v))),
      setting(tr('Автоблокировка'), tr('Закрыть сессию после бездействия'), segOf([[5, tr`${5} мин`], [15, tr`${15} мин`], [30, tr`${30} мин`], [60, tr`${60} мин`], [0, tr('никогда')]], state.prefs.autolockMin, pref('autolock', 'autolockMin'))),
      setting(tr('Очистка буфера обмена'), tr('Через сколько секунд стирать скопированное значение'), segOf([[15, tr`${15} с`], [30, tr`${30} с`], [60, tr`${60} с`], [0, tr('не стирать')]], state.prefs.clipSec, pref('clip', 'clipSec'))),
      setting(tr('Скрывать показанное значение'), tr('Снова размыть значение в карточке через'), segOf([[15, tr`${15} с`], [30, tr`${30} с`], [60, tr`${60} с`], [0, tr('не скрывать')]], state.prefs.revealSec, pref('reveal', 'revealSec'))))));
    // security
    let twofa = { enabled: false }; try { twofa = await api.twofaStatus(); } catch {}
    const sec = el('div', { class: 'card' });
    sec.append(
      setting(tr('Второй фактор (TOTP)'), twofa.enabled ? tr('Включён: при входе нужен код из приложения') : tr('Код из Google Authenticator / Yandex Key / 1Password поверх master-password'),
        twofa.enabled ? el('button', { class: 'btn danger sm', onclick: () => disable2fa() }, tr('Выключить')) : el('button', { class: 'btn primary sm', onclick: () => setup2fa() }, icon('shield_check', 13), tr('Включить'))),
      setting(tr('Сменить master-password'), tr('Ключи папок перешифруются, токены сервисов продолжат работать, все сессии закроются, выдастся новый recovery-код'), el('button', { class: 'btn sm', onclick: showChangePassword }, icon('key', 13), tr('Сменить'))),
      setting(tr('Заблокировать везде'), tr('Закрыть все сессии администратора на всех репликах'), el('button', { class: 'btn sm', onclick: async () => { if (!(await confirmDialog(tr('Закрыть все сессии?'), tr('Все открытые вкладки и устройства попросят master-password заново.'), { ok: tr('Закрыть все') }))) return; try { await api.lockAll(); } catch {} location.hash = ''; location.reload(); } }, icon('lock', 13), tr('Закрыть все сессии'))));
    // SSO unlock across replicas (0.10) — shown when OIDC is configured
    let oidc = { enabled: false }; try { oidc = await api.req('GET', '/api/auth/oidc/status'); } catch {}
    if (oidc.enabled) {
      let sso = { available: false, enabled: false, source: 'none' }; try { sso = await api.ssoUnlockStatus(); } catch {}
      const srcLabel = { node: tr('эта реплика: ключ в памяти после входа паролем'), cell: tr('все реплики: ячейка SSO-разблокировки'), env: tr('пароль в переменной окружения (dev)'), none: tr('нигде — вход через SSO сейчас невозможен') }[sso.source] || sso.source;
      sec.appendChild(setting(tr('Разблокировка по SSO'), sso.available
        ? (sso.enabled ? tr`Включена: вход через SSO работает на любой реплике. Откуда ключ сейчас: ${srcLabel}` : tr`Выключена. Откуда ключ сейчас: ${srcLabel}. Включение потребует master-password; мастер-ключ будет храниться в базе под серверным ключом VAULT_SSO_UNLOCK_KEY`)
        : tr('На сервере не задан VAULT_SSO_UNLOCK_KEY (≥32 случайных байт, одинаковый на всех репликах) — вход через SSO работает только на реплике, где был вход паролем'),
        sso.available ? (sso.enabled
          ? el('button', { class: 'btn danger sm', onclick: async () => { if (!(await confirmDialog(tr('Выключить разблокировку по SSO?'), tr('Вход через SSO снова будет работать только на реплике, где введён master-password.'), { danger: true, ok: tr('Выключить') }))) return; try { await api.ssoUnlockDisable(); toast(tr('Разблокировка по SSO выключена'), 'ok'); onRoute(); } catch (e) { toast(e.message, 'error'); } } }, tr('Выключить'))
          : el('button', { class: 'btn primary sm', onclick: () => {
              const pw = el('input', { type: 'password', class: 'input mono', placeholder: 'master password', autocomplete: 'current-password' });
              const m = modal({ narrow: true }, el('h2', null, icon('user', 18), tr('Включить разблокировку по SSO')),
                el('div', { class: 'callout warn' }, icon('alert', 16), el('div', { class: 'small' }, tr('Мастер-ключ будет храниться в базе, завёрнутый под серверный ключ. Дамп базы вместе с этим ключом раскрывает хранилище — храни VAULT_SSO_UNLOCK_KEY отдельно от бэкапов базы.'))),
                el('div', { class: 'field' }, el('label', null, tr('Подтверди master-password')), pw),
                el('div', { class: 'foot' }, el('button', { class: 'btn', onclick: () => m.remove() }, tr('Отмена')), el('button', { class: 'btn primary', onclick: async () => { try { await api.ssoUnlockEnable(pw.value); m.remove(); toast(tr('Разблокировка по SSO включена'), 'ok'); onRoute(); } catch (e) { toast(e.message, 'error'); } } }, tr('Включить'))));
            } }, icon('user', 13), tr('Включить')))
          : el('span', { class: 'badge' }, tr('недоступно'))));
    }
    // security keys / Touch ID (0.13)
    let wa = { credentials: [], second_factor: false, rp_id: '' }; try { wa = await api.webauthnList(); } catch {}
    const waCtl = el('div', { class: 'row' },
      el('button', { class: 'btn primary sm', 'data-testid': 'webauthn-add', onclick: () => {
        if (!window.PublicKeyCredential) return toast(tr('Этот браузер не поддерживает WebAuthn'), 'error');
        const nm = el('input', { class: 'input', placeholder: tr('например, YubiKey 5 или Touch ID на MacBook'), value: '' });
        const mp = el('input', { type: 'password', class: 'input mono', placeholder: 'master password', autocomplete: 'current-password' });
        const m = modal({ narrow: true }, el('h2', null, icon('key', 18), tr('Добавить ключ безопасности')),
          el('p', { class: 'muted small', style: { margin: 0 } }, tr('YubiKey, Touch ID, Windows Hello, Android. Если ключ умеет PRF (YubiKey 5, passkey в Safari 18+), вход будет одним касанием без пароля; иначе ключ станет вторым фактором.')),
          el('div', { class: 'field' }, el('label', null, tr('Название')), nm), el('div', { class: 'field' }, el('label', null, tr('Твой master-password')), mp),
          el('div', { class: 'foot' }, el('button', { class: 'btn', onclick: () => m.remove() }, tr('Отмена')), el('button', { class: 'btn primary', 'data-testid': 'webauthn-create', onclick: async (e) => {
            e.currentTarget.disabled = true;
            try {
              const o = await api.webauthnRegisterOptions(nm.value.trim() || 'security key');
              const c = await webauthnCreate(o);
              const r = await api.webauthnRegisterFinish({ name: nm.value.trim() || 'security key', credential: c.credential, prf_output: c.prf_output, transports: c.transports, master_password: mp.value });
              m.remove(); toast(r.prf ? tr('Ключ добавлен: вход одним касанием доступен') : tr('Ключ добавлен как второй фактор (PRF не поддерживается)'), 'ok', 6000); onRoute();
            } catch (er) { toast(er.message, 'error', 6000); e.currentTarget.disabled = false; }
          } }, tr('Добавить'))));
      } }, icon('plus', 13), tr('Добавить ключ')));
    sec.appendChild(setting(tr('Ключи безопасности и биометрия'), wa.credentials.length
      ? tr`Зарегистрировано: ${wa.credentials.length}. Вход касанием: ${wa.credentials.some(c => c.prf) ? tr('доступен') : tr('нет (ключи без PRF)')}. Домен (RP ID): ${wa.rp_id}`
      : tr`WebAuthn: YubiKey, Touch ID на Mac, Android. С PRF — вход касанием без пароля; без PRF — второй фактор. Домен (RP ID): ${wa.rp_id}`, waCtl));
    if (wa.credentials.length) {
      sec.appendChild(setting(tr('Требовать ключ при входе паролем'), tr('Второй фактор: после пароля нужно коснуться любого зарегистрированного ключа. Выключается автоматически, если удалить все ключи'),
        el('span', { class: `toggle ${wa.second_factor ? 'on' : ''}`, role: 'switch', tabindex: 0, 'data-testid': 'webauthn-2fa', onclick: async (e) => { try { let pw = ''; if (wa.second_factor) { pw = await passwordDialog(tr('Отключить ключ как второй фактор?'), tr('Подтверди мастер-паролем: без ключа для входа снова хватит пароля.')); if (pw === null) return; } await api.webauthnSecondFactor(!wa.second_factor, pw); onRoute(); } catch (er) { toast(er.message, 'error'); } } })));
      const tbl = el('div', { class: 'card' }, table([tr('Название'), tr('Вход касанием'), tr('Добавлен'), tr('Использован'), ''], wa.credentials.map(c => el('tr', null,
        el('td', { style: { fontWeight: 600 } }, c.name), el('td', null, el('span', { class: `badge ${c.prf ? 'ok' : ''}` }, c.prf ? 'PRF' : tr('2-й фактор'))),
        el('td', { class: 'small muted' }, fmtDate(c.created_at)), el('td', { class: 'small muted' }, c.last_used ? timeAgo(c.last_used) : '—'),
        el('td', { style: { textAlign: 'right' } }, el('button', { class: 'btn danger sm', onclick: async () => { if (!(await confirmDialog(tr`Удалить ключ «${c.name}»?`, '', { danger: true }))) return; try { await api.webauthnDelete(c.id); onRoute(); } catch (er) { toast(er.message, 'error'); } } }, tr('Удалить')))))));
      root.appendChild(el('div', null, el('div', { class: 'nav-title' }, tr('Ключи безопасности')), tbl));
    }
    // PKCS#11 / HSM (0.15)
    let hs = { configured: false, enabled: false }; try { hs = await api.hsmStatus(); } catch {}
    const tokenDesc = hs.token ? `${hs.token.manufacturer} ${hs.token.model} «${hs.token.label}»` : (hs.token_error || '');
    sec.appendChild(setting(tr('Аппаратный токен (PKCS#11)'), !hs.configured
      ? tr('Не настроен: задай VAULT_PKCS11_MODULE (библиотека PKCS#11 — YubiHSM, Nitrokey HSM, Рутокен, SoftHSM2) и метку токена. Тогда мастер-ключ можно завернуть ключом внутри токена и входить PIN-кодом')
      : hs.enabled ? tr`Включён: мастер-ключ зашифрован AES-ключом «${hs.key_label}» внутри токена ${tokenDesc}. Вход — PIN-кодом токена; дамп базы без токена бесполезен.${hs.auto ? tr(' Серверу доступен PIN (авторежим): SSO и смена пароля работают через токен.') : ''}`
      : tr`Токен виден: ${tokenDesc}. Включение спросит master-password и PIN токена; AES-ключ будет создан в токене при первом включении`,
      hs.configured ? (hs.enabled
        ? el('button', { class: 'btn danger sm', onclick: async () => { if (!(await confirmDialog(tr('Выключить вход по токену?'), tr('Ячейка в базе будет удалена; ключ внутри токена останется.'), { danger: true, ok: tr('Выключить') }))) return; try { await api.hsmDisable(); onRoute(); } catch (e) { toast(e.message, 'error'); } } }, tr('Выключить'))
        : el('button', { class: 'btn primary sm', 'data-testid': 'hsm-enable', onclick: () => {
            const mp = el('input', { type: 'password', class: 'input mono', placeholder: 'master password', autocomplete: 'current-password' });
            const pin = el('input', { type: 'password', class: 'input mono', placeholder: tr('PIN токена'), autocomplete: 'off' });
            const m = modal({ narrow: true }, el('h2', null, icon('server', 18), tr('Включить вход по токену')),
              el('p', { class: 'muted small', style: { margin: 0 } }, tr('Мастер-ключ будет зашифрован ключом внутри токена. Токен должен быть доступен серверу (локально или по сети); для кластера — общий токен или сетевой HSM.')),
              el('div', { class: 'field' }, el('label', null, tr('Твой master-password')), mp), el('div', { class: 'field' }, el('label', null, tr('PIN токена')), pin),
              el('div', { class: 'foot' }, el('button', { class: 'btn', onclick: () => m.remove() }, tr('Отмена')), el('button', { class: 'btn primary', 'data-testid': 'hsm-enable-confirm', onclick: async () => { try { await api.hsmEnable(mp.value, pin.value); m.remove(); toast(tr('Вход по токену включён'), 'ok'); onRoute(); } catch (e) { toast(e.message, 'error', 6000); } } }, tr('Включить'))));
          } }, icon('server', 13), tr('Включить')))
        : el('span', { class: 'badge' }, tr('недоступно'))));
    // Cloud KMS (0.16)
    let ks = { configured: false, enabled: false }; try { ks = await api.kmsStatus(); } catch {}
    const kmsName = { aws: 'AWS KMS', yandex: 'Yandex Cloud KMS' }[ks.provider] || ks.provider || 'KMS';
    sec.appendChild(setting(tr('Облачный KMS (AWS, Yandex Cloud)'), !ks.configured
      ? tr('Не настроен: задай VAULT_KMS_PROVIDER (aws | yandex), VAULT_KMS_KEY_ID и учётные данные облака. Тогда мастер-ключ будет зашифрован ключом в облачном KMS, который никогда не покидает облако; каждая расшифровка попадает в журнал облака')
      : ks.enabled ? (ks.pin_bound
          ? tr`Включён с PIN: ${kmsName}, ключ ${ks.key_id}. KMS расшифровывает ячейку только с контекстом из PIN — учётных данных облака недостаточно. Вход — PIN-кодом; дамп базы без доступа к KMS бесполезен`
          : tr`Включён без PIN (авторежим): ${kmsName}, ключ ${ks.key_id}. Ячейку открывает сама учётная запись сервера в облаке — для SSO и смены пароля; прямого входа по ней нет`)
      : tr`Доступен: ${kmsName}${ks.kms?.key_id ? ', ключ ' + ks.kms.key_id : ''}${ks.kms?.credentials === false ? tr('; учётные данные облака не заданы') : ''}. Включение спросит master-password; PIN по желанию — с ним ячейка открывается только знающему PIN, без него сервер открывает её сам (SSO)`,
      ks.configured ? (ks.enabled
        ? el('button', { class: 'btn danger sm', onclick: async () => { if (!(await confirmDialog(tr('Выключить облачную ячейку?'), tr('Ячейка в базе будет удалена; ключ в KMS останется.'), { danger: true, ok: tr('Выключить') }))) return; try { await api.kmsDisable(); onRoute(); } catch (e) { toast(e.message, 'error'); } } }, tr('Выключить'))
        : el('button', { class: 'btn primary sm', 'data-testid': 'kms-enable', onclick: () => {
            const mp = el('input', { type: 'password', class: 'input mono', placeholder: 'master password', autocomplete: 'current-password' });
            const pin = el('input', { type: 'password', class: 'input mono', placeholder: tr('PIN (необязательно, от 4 символов)'), autocomplete: 'off' });
            const m = modal({ narrow: true }, el('h2', null, icon('cloud', 18), tr('Включить облачную ячейку')),
              el('p', { class: 'muted small', style: { margin: 0 } }, tr('Мастер-ключ будет зашифрован ключом в облачном KMS. С PIN — расшифровать может только тот, кто знает PIN (контекст шифрования); без PIN — сервер сам, по своей облачной учётной записи (нужно для SSO).')),
              el('div', { class: 'field' }, el('label', null, tr('Твой master-password')), mp), el('div', { class: 'field' }, el('label', null, tr('PIN')), pin),
              el('div', { class: 'foot' }, el('button', { class: 'btn', onclick: () => m.remove() }, tr('Отмена')), el('button', { class: 'btn primary', 'data-testid': 'kms-enable-confirm', onclick: async () => { try { const r = await api.kmsEnable(mp.value, pin.value); m.remove(); toast(r.pin_bound ? tr('Облачная ячейка включена: вход PIN-кодом') : tr('Облачная ячейка включена (авторежим для SSO)'), 'ok'); onRoute(); } catch (e) { toast(e.message, 'error', 6000); } } }, tr('Включить'))));
          } }, icon('cloud', 13), tr('Включить')))
        : el('span', { class: 'badge' }, tr('недоступно'))));
    // approvals (0.12)
    let appr = { approver_set: false, notify_configured: false }; try { appr = await api.approvalsSettings(); } catch {}
    sec.appendChild(setting(tr('Подтверждение чтения'), appr.approver_set
      ? tr`Подтверждающий назначен. Уведомления: ${appr.notify_configured ? tr('настроены (VAULT_APPROVAL_NOTIFY_URL)') : tr('не настроены — ссылка показывается запросившему')}. Секреты с флагом «требует подтверждения» читаются только после его одобрения`
      : tr('Второй человек со своим паролем одобряет чтение помеченных секретов, не видя значения. Уведомление уходит на любой вебхук: Telegram, Slack, ntfy, свой шлюз'),
      el('div', { class: 'row' },
        el('button', { class: 'btn primary sm', 'data-testid': 'approver-set', onclick: () => {
          const mp = el('input', { type: 'password', class: 'input mono', placeholder: 'master password', autocomplete: 'current-password' });
          const ap = el('input', { type: 'password', class: 'input mono', placeholder: tr('пароль подтверждающего (≥12)'), autocomplete: 'new-password' });
          const m = modal({ narrow: true }, el('h2', null, icon('shield_check', 18), appr.approver_set ? tr('Сменить пароль подтверждающего') : tr('Назначить подтверждающего')),
            el('p', { class: 'muted small', style: { margin: 0 } }, tr('Пароль подтверждающего передай второму человеку. Он не даёт доступа к хранилищу — только право одобрять запросы по ссылке.')),
            el('div', { class: 'field' }, el('label', null, tr('Твой master-password')), mp), el('div', { class: 'field' }, el('label', null, tr('Пароль подтверждающего')), ap, strengthMeter(ap)),
            el('div', { class: 'foot' }, el('button', { class: 'btn', onclick: () => m.remove() }, tr('Отмена')), el('button', { class: 'btn primary', onclick: async () => { try { await api.setApprover(mp.value, ap.value); m.remove(); toast(tr('Подтверждающий назначен'), 'ok'); onRoute(); } catch (e) { toast(e.message, 'error'); } } }, tr('Сохранить'))));
        } }, icon('shield_check', 13), appr.approver_set ? tr('Сменить') : tr('Назначить')),
        appr.approver_set ? el('button', { class: 'btn danger sm', onclick: async () => { if (!(await confirmDialog(tr('Убрать подтверждающего?'), tr('Секреты с флагом «требует подтверждения» станут недоступны людям, пока флаг не снят или не назначен новый подтверждающий.'), { danger: true, ok: tr('Убрать') }))) return; try { await api.clearApprover(); onRoute(); } catch (e) { toast(e.message, 'error'); } } }, tr('Убрать')) : null)));
    root.appendChild(el('div', null, el('div', { class: 'nav-title' }, tr('Безопасность')), sec));
    if (appr.approver_set) {
      let list = []; try { list = await api.approvalsList(); } catch {}
      if (list.length) root.appendChild(el('div', null, el('div', { class: 'nav-title' }, tr('Последние запросы на подтверждение')), el('div', { class: 'card' },
        table([tr('Когда'), tr('Секрет'), tr('Кто'), tr('Причина'), tr('Статус')], list.slice(0, 20).map(a => el('tr', null, el('td', { class: 'small mono muted' }, fmtDate(a.created_at)), el('td', null, a.secret), el('td', { class: 'mono small' }, a.requester_ip), el('td', { class: 'small muted' }, a.reason || '—'),
          el('td', null, el('span', { class: `badge ${a.status === 'approved' ? 'ok' : a.status === 'pending' ? 'warn' : a.status === 'denied' ? 'danger' : ''}` }, a.status))))))));
    }
    // data
    root.appendChild(el('div', null, el('div', { class: 'nav-title' }, tr('Данные')), el('div', { class: 'card' },
      setting(tr('Экспорт JSON'), tr('Все папки и секреты открытым текстом (⌘E). Для переезда и резервной копии; файл хранить как секрет'), el('button', { class: 'btn sm', onclick: P.exportVault }, icon('download', 13), tr('Экспорт'))),
      setting(tr('Импорт из другого менеджера'), tr('Bitwarden, KeePass, 1Password, LastPass, Passwork, CSV, .env, HashiCorp Vault / Stronghold — с предпросмотром'), el('button', { class: 'btn sm', 'data-testid': 'import-other', onclick: P.importOther }, icon('upload', 13), tr('Импорт'))),
      setting(tr('Импорт JSON'), tr('Из экспорта APS Vault; существующие имена пропускаются'), el('button', { class: 'btn sm', onclick: P.importVault }, icon('upload', 13), tr('Импорт'))))));
    // about
    let h = state.health; try { h = await api.health(); } catch {}
    root.appendChild(el('div', null, el('div', { class: 'nav-title' }, tr('О системе')), el('div', { class: 'card' },
      setting(tr('Версия'), null, el('span', { class: 'mono' }, h?.version || '?')),
      setting(tr('Узел'), tr('Реплика, ответившая на этот запрос'), el('span', { class: 'mono' }, h?.node || '?')),
      setting(tr('Криптография'), h?.cipher === 'gost' ? tr('Набор ГОСТ: Кузнечик-MGM, Стрибог, KDF_TREE — соответствие по алгоритму (проверено тестовыми векторами стандартов), не сертифицированное СКЗИ. Выбирается при инициализации (VAULT_CIPHER)') : tr('Набор по умолчанию: AES-256-GCM, HKDF-SHA256, Argon2id. Набор выбирается при инициализации (VAULT_CIPHER=gost — Кузнечик/Стрибог)'), el('span', { class: 'mono small', 'data-testid': 'cipher-label' }, h?.cipher_label || '?')),
      setting(tr('База данных'), null, el('span', { class: `badge ${h?.db === 'ok' ? 'ok' : 'danger'}` }, h?.db || '?')),
      setting(tr('Документация'), tr('API, совместимость с HashiCorp/Stronghold, кластер, политики, SIEM'), el('a', { class: 'btn sm', href: 'https://github.com/kzhebenev/aps-vault#readme', target: '_blank', rel: 'noopener' }, icon('external', 13), 'GitHub')))));
    async function setup2fa() {
      let s; try { s = await api.twofaSetup(); } catch (e) { return toast(e.message, 'error'); }
      const code = el('input', { class: 'input mono', placeholder: '123456', inputmode: 'numeric', autocomplete: 'one-time-code' });
      const m = modal({ narrow: true }, el('h2', null, icon('shield_check', 18), tr('Включить 2FA')),
        el('p', { class: 'muted small', style: { margin: 0 } }, tr('Отсканируй QR в приложении-аутентификаторе и введи первый код.')),
        s.qr_data_url ? el('img', { src: s.qr_data_url, alt: 'QR', style: { width: '180px', height: '180px', margin: '0 auto', borderRadius: '8px', background: '#fff', padding: '6px' } }) : null,
        el('div', { class: 'codebox', style: { fontSize: '12px' } }, s.secret_base32),
        el('div', { class: 'field' }, el('label', null, tr('Код из приложения')), code),
        el('div', { class: 'foot' }, el('button', { class: 'btn', onclick: () => m.remove() }, tr('Отмена')), el('button', { class: 'btn primary', onclick: async () => {
          try { await api.twofaVerify(code.value.trim(), s.secret_base32); m.remove(); toast(tr('2FA включена'), 'ok'); onRoute(); } catch (e) { toast(e.message, 'error'); }
        } }, tr('Подтвердить'))));
    }
    async function disable2fa() {
      const code = el('input', { class: 'input mono', placeholder: '123456', inputmode: 'numeric' });
      const m = modal({ narrow: true }, el('h2', null, tr('Выключить 2FA')), el('div', { class: 'field' }, el('label', null, tr('Текущий код из приложения')), code),
        el('div', { class: 'foot' }, el('button', { class: 'btn', onclick: () => m.remove() }, tr('Отмена')), el('button', { class: 'btn danger', onclick: async () => { try { await api.twofaDisable(code.value.trim()); m.remove(); toast(tr('2FA выключена'), 'ok'); onRoute(); } catch (e) { toast(e.message, 'error'); } } }, tr('Выключить'))));
    }
    function showChangePassword() {
      const cur = el('input', { type: 'password', class: 'input mono', placeholder: tr('текущий master-password'), autocomplete: 'current-password' });
      const np = el('input', { type: 'password', class: 'input mono', placeholder: tr('новый master-password (≥12)'), autocomplete: 'new-password' });
      const np2 = el('input', { type: 'password', class: 'input mono', placeholder: tr('повтор'), autocomplete: 'new-password' });
      const code = el('input', { class: `input mono ${twofa.enabled ? '' : 'hidden'}`, placeholder: tr('код 2FA'), inputmode: 'numeric' });
      const m = modal({ narrow: true }, el('h2', null, icon('key', 18), tr('Сменить master-password')),
        el('div', { class: 'callout warn' }, icon('alert', 16), el('div', { class: 'small' }, tr('После смены все сессии закроются и будет показан новый recovery-код — старый перестанет действовать.'))),
        el('div', { class: 'field' }, el('label', null, tr('Текущий')), cur), el('div', { class: 'field' }, el('label', null, tr('Новый')), np, strengthMeter(np)), el('div', { class: 'field' }, el('label', null, tr('Повтор')), np2), code,
        el('div', { class: 'foot' }, el('button', { class: 'btn', onclick: () => m.remove() }, tr('Отмена')), el('button', { class: 'btn primary', onclick: async () => {
          if (np.value !== np2.value) return toast(tr('пароли не совпадают'), 'error');
          try { const r = await api.changePassword({ current_password: cur.value, new_password: np.value, totp_code: twofa.enabled ? code.value.trim() : undefined }); m.remove(); showRecoveryCode(r.new_recovery_code, () => { location.hash = ''; location.reload(); }, tr('Новый recovery code')); }
          catch (e) { toast(e.message, 'error'); }
        } }, tr('Сменить'))));
    }
  };
})();
