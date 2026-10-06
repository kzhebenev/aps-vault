// Theme before first paint: dark | light | (absent = system). A file, not an inline script — the UI's CSP is
// script-src 'self' (0.37), which blocks inline scripts.
try { var t = localStorage.getItem('vault_theme'); if (t === 'dark' || t === 'light') document.documentElement.dataset.theme = t; } catch (e) {}
