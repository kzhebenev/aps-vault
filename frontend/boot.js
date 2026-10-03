// APS Vault — bootstrap: health → init / unlock / app.
(async () => {
  const share = location.pathname.match(/^\/share\/([A-Za-z0-9_-]+)\/?$/);
  if (share) return renderSharePage(share[1]);
  try {
    const h = await api.health();
    state.health = h; state.initialized = h.initialized; state.unlocked = h.unlocked;
    if (h.db === 'error') { document.getElementById('app').appendChild(el('div', { class: 'auth' }, el('div', { class: 'card' }, brandBlock(tr('База данных недоступна')), el('div', { class: 'callout danger' }, icon('alert', 16), tr`Реплика ${h.node} не достучалась до базы. Проверь VAULT_DATABASE_URL и состояние PostgreSQL.`)))); return; }
    if (!h.initialized) return renderInit();
    if (!h.unlocked) return renderUnlock();
    await enterApp();
  } catch (e) {
    document.getElementById('app').appendChild(el('div', { class: 'auth' }, el('div', { class: 'card' }, brandBlock(''), el('div', { class: 'callout danger' }, icon('alert', 16), tr`Vault не отвечает: ${e.message}`))));
  }
})();
