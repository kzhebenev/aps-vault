// APS Vault — full pages: tokens, share links, webhooks, audit log, health report, settings.
// Each page renders into the <div class="page"> that app.js prepares; PAGES[view](root).

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
      el('button', { class: 'btn primary', id: 'tok-new', onclick: () => showTokenEditor(tokenPresetFolder) }, icon('plus', 14), tr('Новый токен')));
    tokenPresetFolder = null;
    let tokens; try { tokens = await api.listTokens(); } catch (e) { return toast(e.message, 'error'); }
    const active = tokens.filter(t => !t.revoked), revoked = tokens.filter(t => t.revoked);
    if (!tokens.length) return root.appendChild(empty('key', tr('Токенов ещё нет'), tr('Создай токен для сервиса или агента: он получит доступ ровно к одной папке.')));
    const row = (t) => {
      const perms = [t.can_write ? el('span', { class: 'badge warn' }, tr('запись')) : el('span', { class: 'badge' }, tr('чтение')), t.can_read_notes ? el('span', { class: 'badge' }, 'notes') : null, t.can_read_totp ? el('span', { class: 'badge ok' }, 'TOTP') : null];
      const policy = [t.allowed_cidrs ? el('div', { class: 'xs mono muted' }, icon('globe', 10), ' ', t.allowed_cidrs) : null, t.allowed_hours ? el('div', { class: 'xs mono muted' }, icon('clock', 10), ' ', t.allowed_hours) : null,
        t.allowed_cert_fingerprints ? el('div', { class: 'xs mono muted', title: t.allowed_cert_fingerprints }, icon('shield_check', 10), ' mTLS ', t.allowed_cert_fingerprints.split(' ').map(f => f.slice(0, 12) + '…').join(', ')) : null];
      const exp = t.expires_at ? (daysUntil(t.expires_at) < 0 ? el('span', { class: 'badge danger' }, tr('истёк')) : el('span', { class: 'xs muted' }, tr`до ${fmtDate(t.expires_at, false)}`)) : el('span', { class: 'xs faint' }, '∞');
      return el('tr', { style: t.revoked ? { opacity: .55 } : null },
        el('td', null, el('div', { style: { fontWeight: 600 } }, t.name), el('div', { class: 'xs faint mono' }, `id ${t.id}`)),
        el('td', null, el('a', { href: routeHash('folder', t.folder_id) }, icon('folder', 12), ' ', t.folder_name)),
        el('td', null, el('div', { class: 'row wrap', style: { gap: '4px' } }, ...perms), ...policy),
        el('td', null, el('div', { class: 'small' }, t.last_used ? timeAgo(t.last_used) : el('span', { class: 'faint' }, tr('не использовался'))), el('div', { class: 'xs faint' }, tr`создан ${timeAgo(t.created_at)}`)),
        el('td', null, exp),
        el('td', { style: { textAlign: 'right' } }, t.revoked ? el('span', { class: 'badge danger' }, tr('отозван')) : el('button', { class: 'btn danger sm', onclick: async () => {
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
    const d = drawer(tr('Новый токен'), [
      el('div', { class: 'field' }, el('label', null, tr('Имя')), name),
      el('div', { class: 'field' }, el('label', null, tr('Папка (scope)')), folderPicker(folderId, (id) => { folderId = id; })),
      el('div', { class: 'card', style: { padding: '2px 14px' } },
        tgl('can_read_notes', tr('Читать заметки'), tr('поле notes в ответе машинного API')),
        tgl('can_read_totp', tr('Выдавать TOTP-коды'), tr('текущий одноразовый код по секретам с seed')),
        tgl('can_write', tr('Запись секретов'), tr('создавать и перезаписывать секреты своей папки (PUT /api/v1/m/secret/…)'), true)),
      el('div', { class: 'field' }, el('label', null, tr('Срок действия, дней')), days),
      el('div', { class: 'field' }, el('label', null, tr('Политика доступа')), cidr, hours, certs,
        el('span', { class: 'xs faint' }, tr('Запрос с другого адреса или вне окна получит 403 и попадёт в журнал и SIEM. Пусто — без ограничений.')),
        el('span', { class: 'xs faint' }, tr('Сертификаты: прокси проверяет клиентский сертификат (mTLS) и передаёт отпечаток заголовком X-Client-Cert-Fingerprint; токен с привязкой без такого сертификата получит 403. См. docs/ACCESS-POLICIES.md.'))),
    ], [
      el('button', { class: 'btn primary', onclick: async () => {
        const body = { name: name.value.trim(), folder_id: folderId, ...flags, allowed_cidrs: cidr.value.trim(), allowed_hours: hours.value.trim(), allowed_cert_fingerprints: certs.value.trim() };
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

  // ── audit ─────────────────────────────────────────────────────────────────
  const GROUPS = [['all', tr('Все')], ['auth', tr('Вход')], ['secret', tr('Секреты')], ['m:', tr('Машинный API')], ['token', tr('Токены')], ['share', tr('Ссылки')], ['policy', tr('Политика')]];
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
        el('span', { class: `toggle ${wa.second_factor ? 'on' : ''}`, role: 'switch', tabindex: 0, 'data-testid': 'webauthn-2fa', onclick: async (e) => { try { await api.webauthnSecondFactor(!wa.second_factor); onRoute(); } catch (er) { toast(er.message, 'error'); } } })));
      const tbl = el('div', { class: 'card' }, table([tr('Название'), tr('Вход касанием'), tr('Добавлен'), tr('Использован'), ''], wa.credentials.map(c => el('tr', null,
        el('td', { style: { fontWeight: 600 } }, c.name), el('td', null, el('span', { class: `badge ${c.prf ? 'ok' : ''}` }, c.prf ? 'PRF' : tr('2-й фактор'))),
        el('td', { class: 'small muted' }, fmtDate(c.created_at)), el('td', { class: 'small muted' }, c.last_used ? timeAgo(c.last_used) : '—'),
        el('td', { style: { textAlign: 'right' } }, el('button', { class: 'btn danger sm', onclick: async () => { if (!(await confirmDialog(tr`Удалить ключ «${c.name}»?`, '', { danger: true }))) return; try { await api.webauthnDelete(c.id); onRoute(); } catch (er) { toast(er.message, 'error'); } } }, tr('Удалить')))))));
      root.appendChild(el('div', null, el('div', { class: 'nav-title' }, tr('Ключи безопасности')), tbl));
    }
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
      setting(tr('Импорт JSON'), tr('Из экспорта APS Vault; существующие имена пропускаются'), el('button', { class: 'btn sm', onclick: P.importVault }, icon('upload', 13), tr('Импорт'))))));
    // about
    let h = state.health; try { h = await api.health(); } catch {}
    root.appendChild(el('div', null, el('div', { class: 'nav-title' }, tr('О системе')), el('div', { class: 'card' },
      setting(tr('Версия'), null, el('span', { class: 'mono' }, h?.version || '?')),
      setting(tr('Узел'), tr('Реплика, ответившая на этот запрос'), el('span', { class: 'mono' }, h?.node || '?')),
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
