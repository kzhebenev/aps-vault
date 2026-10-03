// APS Vault UI localisation. The source language of the UI is Russian; `t()` maps a Russian
// string (the key) to the active language. Works both as a plain call and as a tagged
// template: tr('Сохранить') and tr`Удалить «${name}»?` — in the tagged form the key is the
// template with ${…} replaced by {0}, {1}, … so one dictionary entry covers all values.
//
// Language: ?lang=en|ru → localStorage 'vault_lang' → browser language. Missing keys fall
// back to the Russian source, so a forgotten string is visible, never blank.
(() => {
  const EN = window.I18N_EN || {};
  function pick() {
    const q = new URLSearchParams(location.search).get('lang');
    if (q === 'en' || q === 'ru') { try { localStorage.setItem('vault_lang', q); } catch {} return q; }
    try { const s = localStorage.getItem('vault_lang'); if (s === 'en' || s === 'ru') return s; } catch {}
    return /^ru\b/i.test(navigator.language || '') ? 'ru' : 'en';
  }
  const lang = pick();
  document.documentElement.lang = lang;
  function translate(key) {
    if (lang === 'ru') return key;
    const v = EN[key];
    return v === undefined ? key : v;
  }
  function t(strings, ...values) {
    if (typeof strings === 'string') return translate(strings);
    // tagged template
    const key = strings.raw.map((s, i) => s + (i < values.length ? `{${i}}` : '')).join('');
    const tpl = translate(key);
    return tpl.replace(/\{(\d+)\}/g, (_, i) => String(values[Number(i)] ?? ''));
  }
  window.I18N = {
    lang,
    locale: lang === 'ru' ? 'ru-RU' : 'en-GB',
    t,
    // drop ?lang= from the URL, otherwise the query would keep overriding the stored choice
    setLang(l) { try { localStorage.setItem('vault_lang', l); } catch {} location.href = location.pathname; },
  };
  window.tr = t;   // `tr`, not `t`: app code uses `t` for loop variables (tokens)
})();
