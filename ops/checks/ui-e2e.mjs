// End-to-end check of the web UI in a real browser against a FRESH vault (ops/checks/e2e-stack.sh).
// Every step asserts what the user sees, not what the state says; 0 JS errors is part of the pass.
//   URL=$(ops/checks/e2e-stack.sh up); node ops/checks/ui-e2e.mjs "$URL" docs/img; ops/checks/e2e-stack.sh down
import puppeteer from '/aps/node_modules/puppeteer/lib/esm/puppeteer/puppeteer.js';
import { mkdirSync, writeFileSync } from 'node:fs';
import { createHmac } from 'node:crypto';
const [,, URL = 'http://127.0.0.1:8189', OUT = '/tmp/aps-vault-e2e-shots'] = process.argv;
mkdirSync(OUT, { recursive: true });
const MASTER = 'e2e master password 2026!';
const errors = []; let passed = 0, failed = 0;
let lastOk = '(start)';
const ok = (name, cond, extra = '') => { lastOk = name; if (cond) { passed++; console.log('  ✓', name); } else { failed++; console.log('  ✗', name, extra); } };
const sleep = (ms) => new Promise(r => setTimeout(r, ms));
const browser = await puppeteer.launch({ headless: 'new', executablePath: '/usr/bin/google-chrome', pipe: true, protocolTimeout: 60000,
  args: ['--no-sandbox', '--disable-gpu', '--disable-dev-shm-usage', '--no-proxy-server', '--disable-background-networking', '--disable-component-update', '--disable-sync',
         '--host-resolver-rules=MAP *.google.com 127.0.0.1,MAP *.googleapis.com 127.0.0.1,MAP *.gstatic.com 127.0.0.1'] });
const page = await browser.newPage();
await page.setViewport({ width: 1366, height: 860 });
page.on('pageerror', e => errors.push('pageerror: ' + e.message));
await page.evaluateOnNewDocument(() => { window.__rej = []; window.addEventListener('unhandledrejection', e => window.__rej.push(String(e.reason && (e.reason.stack || e.reason)))); });
page.on('console', m => { if (m.type() === 'error' && !/net::|ERR_|Failed to load resource/.test(m.text())) errors.push('console: ' + m.text()); });
const ctx = await browser.defaultBrowserContext(); await ctx.overridePermissions(URL, ['clipboard-read', 'clipboard-write']);
const text = () => page.evaluate(() => document.body.innerText);
// DOM click: deterministic (no hit-testing against a toast or a re-rendering meter); real pointer clicks are exercised by page.click elsewhere
const clickText = async (sel, re) => { const h = await page.evaluateHandle((sel, src) => [...document.querySelectorAll(sel)].find(b => new RegExp(src, 'i').test(b.innerText.trim())), sel, re.source); const e = h.asElement(); if (!e) throw new Error(`no element ${sel} ~ ${re}`); await page.evaluate(el => el.click(), e); return e; };
const waitText = (re, t = 10000) => page.waitForFunction((src) => new RegExp(src, 'i').test(document.body.innerText), { timeout: t }, re.source);
const settle = (...res) => page.waitForFunction((srcs) => srcs.every(src => new RegExp(src).test(document.body.innerText)), { timeout: 8000 }, res.map(r => r.source)).catch(() => {});
const typeInto = async (sel, value) => { await page.click(sel, { clickCount: 3 }); await page.keyboard.press('Backspace'); await page.type(sel, value); };
try {
  // ── init ────────────────────────────────────────────────────────────────
  await page.goto(URL + '/?lang=ru', { waitUntil: 'networkidle0', timeout: 20000 });
  await page.waitForSelector('input[type=password]', { timeout: 15000 });
  const phs = await page.$$eval('input', xs => xs.map(i => i.placeholder));
  ok('экран инициализации: поле init token', phs.some(p => /init token/i.test(p)), JSON.stringify(phs));
  await page.screenshot({ path: `${OUT}/init.png` });
  const pw = await page.$$('input[type=password]');
  await pw[0].type(MASTER); await pw[1].type(MASTER); await pw[2].type('wrong-token');
  await clickText('button', /Инициализировать/); await waitText(/init token mismatch/, 5000);
  await settle(/init token mismatch/); ok('неверный init token отклонён (видимая ошибка)', /init token mismatch/.test(await text()));
  await pw[2].click({ clickCount: 3 }); await pw[2].type('e2e-init-token');
  await clickText('button', /Инициализировать/);
  await page.waitForSelector('.codebox', { timeout: 10000 });
  const recovery = await page.$eval('.codebox', e => e.textContent.trim());
  ok('recovery-код показан (24 символа)', recovery.length === 24, recovery);
  await clickText('button', /Я записал/);
  await page.waitForSelector('input[type=password]', { timeout: 15000 }); await sleep(300);
  ok('после init — экран входа', (await page.$$('.auth .stack:not(.hidden) input[type=password]')).length === 1);
  // ── unlock: wrong, then right ──────────────────────────────────────────
  await page.type('input[type=password]', 'not the password at all'); await page.keyboard.press('Enter');
  await waitText(/wrong master password/, 5000); ok('неверный пароль → видимая ошибка', true);
  await typeInto('input[type=password]', MASTER); await page.keyboard.press('Enter');
  await page.waitForSelector('.sidebar', { timeout: 15000 }); await sleep(300);
  await settle(/Создать первую папку|Папок ещё нет/); ok('вход: главный экран, пустое состояние с призывом создать папку', /Создать первую папку|Папок ещё нет/.test(await text()));
  await page.screenshot({ path: `${OUT}/empty.png` });
  // ── folder ──────────────────────────────────────────────────────────────
  await clickText('button', /Создать первую папку/); await page.waitForSelector('.modal input', { timeout: 5000 });
  await page.type('.modal input', 'clients-test'); await page.keyboard.press('Enter');
  await waitText(/Папка создана/, 5000); await sleep(300);
  ok('папка создана и выбрана (URL #/folder/…)', /#\/folder\/\d+/.test(await page.evaluate(() => location.hash)), await page.evaluate(() => location.hash));
  ok('папка видна в сайдбаре', (await page.$$eval('.sidebar .nav-item', xs => xs.map(x => x.innerText))).some(t => /clients-test/.test(t)));
  // ── secret with generator, TOTP and expiry ─────────────────────────────
  await page.keyboard.press('n'); await page.waitForSelector('.drawer', { timeout: 5000 });
  ok('клавиша N открывает редактор', true);
  const inputs = await page.$$('.drawer input, .drawer textarea');
  await inputs[0].type('db-password');
  await clickText('.drawer button', /Сгенерировать/); await page.waitForSelector('.drawer .codebox', { timeout: 5000 });
  const gen = await page.$eval('.drawer .codebox', e => e.textContent.trim());
  ok('генератор дал пароль 24 символа', gen.length === 24, gen);
  await clickText('.drawer button', /Парольная фраза/); await sleep(150);
  const phrase = await page.$eval('.drawer .codebox', e => e.textContent.trim());
  ok('режим парольной фразы: 5 слов через дефис', phrase.split('-').length === 5, phrase);
  await clickText('.drawer button', /Подставить/);
  const val = await page.$eval('.drawer textarea', e => e.value);
  ok('«Подставить» кладёт фразу в значение', val === phrase);
  ok('индикатор силы показывает биты', /бит/.test(await page.$eval('.drawer', e => e.innerText)));
  await page.type('.drawer input[placeholder*="example.com"]', 'app');
  await page.type('.drawer input[type=url]', 'https://db.example.com');
  await page.type('.drawer input[placeholder="prod, api"]', 'prod, db');
  await clickText('.drawer .chip', /^30 дн$/);
  const exp = await page.$eval('.drawer input[type=date]', e => e.value);
  ok('чип «30 дн» заполнил дату', /^\d{4}-\d{2}-\d{2}$/.test(exp), exp);
  await page.type('.drawer input[placeholder="JBSWY3DPEHPK3PXP"]', 'JBSWY3DPEHPK3PXP');
  await page.keyboard.down('Meta'); await page.keyboard.press('Enter'); await page.keyboard.up('Meta');
  await waitText(/Сохранено/, 8000); await page.waitForSelector('.detail', { timeout: 8000 }); await sleep(900);
  ok('секрет сохранён ⌘↵ и открыт в карточке', /db-password/.test(await page.$eval('.detail h1', e => e.innerText)));
  const detail = await page.$eval('.detail', e => e.innerText);
  ok('карточка: логин, значение, TOTP-код из 6 цифр, срок, теги', /app/.test(detail) && /\d{3} \d{3}/.test(detail) && /prod/.test(detail) && /истекает через/.test(detail), detail.slice(0, 300));
  ok('значение по умолчанию размыто', await page.$eval('.detail .secret-blur', e => !!e));
  const totp1 = detail.match(/(\d{3} \d{3})/)[1];
  await page.screenshot({ path: `${OUT}/detail-light.png` });
  // reveal + copy
  await page.click('.detail .frow:nth-child(2) .ops button:first-child'); await sleep(100);
  ok('«показать» снимает размытие', (await page.$$('.detail .frow:nth-child(2) .secret-blur')).length === 0);
  await page.bringToFront();
  await page.click('.detail .frow:nth-child(2) .ops button:last-child'); await waitText(/в буфере|Не удалось скопировать/, 5000);
  const copyMsg = (await text()).match(/[^\n]*(в буфере|Не удалось скопировать)[^\n]*/)?.[0];
  const clip = await page.evaluate(() => navigator.clipboard.readText().catch(e => 'ERR ' + e.message));
  ok('копирование кладёт значение в буфер (тост + содержимое буфера)', clip === phrase && /в буфере/.test(copyMsg), `toast="${copyMsg}" clip="${clip}"`);
  // TOTP countdown
  ok('кольцо таймера TOTP с секундами', /\d+ с/.test(detail));
  // ── list, favorites, expiring scope ─────────────────────────────────────
  ok('«Истекают» в сайдбаре = 1', (await page.$$eval('.sidebar .nav-item', xs => xs.map(x => x.innerText))).some(t => /Истекают\s*1/.test(t.replace(/\n/g, ' '))));
  await page.click('.detail-head .actions button:first-child'); await sleep(500);
  ok('избранное: звезда в списке и счётчик 1', (await page.$$('.item .star')).length === 1 && (await page.$$eval('.sidebar .nav-item', xs => xs.map(x => x.innerText.replace(/\n/g, ' ')))).some(t => /Избранное\s*1/.test(t)));
  // second secret, then sorting and search
  await page.keyboard.press('Escape'); await page.keyboard.press('n'); await page.waitForSelector('.drawer', { timeout: 5000 });
  const in2 = await page.$$('.drawer input, .drawer textarea'); await in2[0].type('api-key'); await page.type('.drawer textarea', 'password');
  ok('слабое значение помечено «слабый»', /слабый/.test(await page.$eval('.drawer', e => e.innerText)));
  await clickText('.drawer .foot button', /Сохранить/); await waitText(/Сохранено/, 8000); await sleep(600);
  ok('в списке 2 секрета', (await page.$$('.item')).length === 2);
  await page.type('#search', 'db-'); await sleep(400);
  ok('поиск сузил список до 1', (await page.$$('.item')).length === 1);
  await page.click('#search', { clickCount: 3 }); await page.keyboard.press('Escape'); await sleep(300);
  ok('Esc сбрасывает поиск', (await page.$$('.item')).length === 2);
  // keyboard: j/k + Enter + c
  await page.keyboard.press('j'); await page.keyboard.press('j'); await page.keyboard.press('k'); await sleep(200);
  ok('J/K двигают фокус в списке', (await page.$$('.item.focused')).length === 1 && await page.$eval('.item.focused .name', e => /api-key/.test(e.innerText)));
  await page.keyboard.press('Enter'); await sleep(900);
  ok('Enter открывает сфокусированный секрет', /api-key/.test(await page.$eval('.detail h1', e => e.innerText)));
  ok('утечки: кнопка проверки есть', (await page.$$eval('.detail button', xs => xs.map(x => x.innerText))).some(t => /Утечки/.test(t)));
  await clickText('.detail button', /Утечки/); await waitText(/утечках|недоступна|выключена/, 12000);
  const leak = await text();
  ok('проверка утечек дала видимый результат («password» найден)', /найден в утечках|недоступна|выключена/.test(leak), 'HIBP: ' + (/найден в утечках/.test(leak) ? 'found' : 'unavailable/disabled'));
  // palette
  await page.keyboard.down('Meta'); await page.keyboard.press('k'); await page.keyboard.up('Meta'); await page.waitForSelector('#palette', { timeout: 3000 });
  await page.type('#palette input', 'db'); await sleep(200); await page.keyboard.press('Enter'); await sleep(900);
  ok('⌘K палитра открывает найденный секрет', /db-password/.test(await page.$eval('.detail h1', e => e.innerText)));
  // move to another folder
  await clickText('.sidebar .nav-title button', /.*/).catch(() => {});
  await page.waitForSelector('.modal input', { timeout: 5000 }); await page.type('.modal input', 'archive'); await page.keyboard.press('Enter'); await waitText(/Папка создана/, 5000); await sleep(400);
  await page.goto(URL + '/#/all/s/1', { waitUntil: 'networkidle0' }); await page.waitForSelector('.detail', { timeout: 8000 }); await sleep(500);
  await clickText('.detail-head button', /Переместить/); await page.waitForSelector('.modal .chip', { timeout: 5000 });
  await clickText('.modal .chip', /archive/); await page.waitForFunction(() => /archive/.test(document.querySelector('.modal .chip.active')?.innerText || ''), { timeout: 3000 });
  await clickText('.modal .foot button', /Переместить/); await waitText(/Перемещён/, 8000); await sleep(600);
  ok('перемещение: URL ведёт в папку archive, крошки показывают archive', /#\/folder\/\d+\/s\/1/.test(await page.evaluate(() => location.hash)) && /archive/.test(await page.$eval('.detail .crumbs', e => e.innerText)));
  const detail2 = await page.$eval('.detail', e => e.innerText);
  ok('после перемещения значение/TOTP читаются', /\d{3} \d{3}/.test(detail2));
  // history after edit
  await clickText('.detail-head button', /Изменить/); await page.waitForSelector('.drawer textarea', { timeout: 5000 });
  await typeInto('.drawer textarea', 'new-value-after-edit-2026'); await clickText('.drawer .foot button', /Сохранить/); await waitText(/Сохранено/, 8000); await sleep(600);
  await clickText('.detail button', /История значений/);
  await page.waitForFunction(() => document.querySelectorAll('.detail .card:nth-of-type(2) .frow').length >= 2, { timeout: 5000 }).catch(() => {});
  const histTxt = await page.$eval('.detail .card:nth-of-type(2)', e => e.innerText);
  ok('история показывает предыдущее значение (размытое, с датой)', (await page.$$('.detail .card:nth-of-type(2) .frow .secret-blur')).length >= 1 && /\d{4}/.test(histTxt), histTxt.slice(0, 120));
  // ── tokens page: create, then machine API works with it ────────────────
  await clickText('.sidebar button', /^Токены$/); await page.waitForSelector('#tok-new', { timeout: 5000 }); await waitText(/Токенов ещё нет/, 5000).catch(() => {});
  await settle(/Токенов ещё нет/); ok('страница токенов: пустое состояние', /Токенов ещё нет/.test(await text()));
  await page.click('#tok-new'); await page.waitForSelector('.drawer', { timeout: 5000 });
  await page.type('.drawer input', 'e2e-reader'); await clickText('.drawer .chip', /archive/); await page.waitForFunction(() => /archive/.test(document.querySelector('.drawer .chip.active')?.innerText || ''), { timeout: 3000 });
  await page.type('[data-testid="tok-cidrs"]', '10.0.0.0/8 127.0.0.1 172.16.0.0/12 192.168.0.0/16');
  await clickText('.drawer .foot button', /Создать/); await page.waitForSelector('.modal .codebox', { timeout: 8000 });
  const tok = await page.$eval('.modal .codebox', e => e.textContent.trim());
  ok('токен показан один раз (vlt_…)', /^vlt_/.test(tok));
  const m = await fetch(`${URL}/api/v1/m/secret/db-password`, { headers: { Authorization: `Bearer ${tok}` } });
  ok('машинный API читает секрет этим токеном (настоящий запрос)', m.status === 200 && (await m.json()).value === 'new-value-after-edit-2026', 'HTTP ' + m.status);
  const kv = await fetch(`${URL}/v1/archive/data/db-password`, { headers: { 'X-Vault-Token': tok } });
  ok('HashiCorp-фасад тоже отвечает этим токеном', kv.status === 200);
  await clickText('.modal .foot button', /Готово/); await sleep(600);
  await settle(/e2e-reader/, /10\.0\.0\.0\/8/); ok('токен в таблице с политикой CIDR', /e2e-reader/.test(await text()) && /10\.0\.0\.0\/8/.test(await text()));
  // ── token watch (0.26): a canary token trips on first use, the page shows the alert, the manager revokes from it ──
  await page.click('#tok-new'); await page.waitForSelector('.drawer .tiles', { timeout: 5000 });
  ok('редактор токена: тип плитками (Сервисный / Канарейка), политика «при аномалии» чипами, без select', (await page.$$('.drawer .tile')).length === 2 && (await page.$$('.drawer select')).length === 0);
  await page.type('.drawer input', 'e2e-canary'); await page.click('[data-testid="tok-kind-canary"]'); await clickText('.drawer .chip', /archive/); await page.waitForFunction(() => /archive/.test(document.querySelector('.drawer .chip.active')?.innerText || ''), { timeout: 3000 });
  await clickText('.drawer .foot button', /Создать/); await page.waitForSelector('.modal .codebox', { timeout: 8000 });
  const canary = await page.$eval('.modal .codebox', e => e.textContent.trim());
  await clickText('.modal .foot button', /Готово/); await sleep(600);
  await settle(/e2e-canary/, /канарейка/); ok('канарейка в таблице с бейджем', /e2e-canary/.test(await text()) && /канарейка/.test(await text()));
  const trip = await fetch(`${URL}/api/v1/m/secret/db-password`, { headers: { Authorization: `Bearer ${canary}` } });
  ok('использование канарейки: вызывающему — обычный 401 без намёка', trip.status === 401 && (await trip.json()).detail === 'invalid service token', 'HTTP ' + trip.status);
  await page.reload({ waitUntil: 'networkidle0' }); await page.waitForSelector('[data-testid="token-alerts"]', { timeout: 10000 }); await sleep(300);   // goto to the same hash URL is a no-op: reload explicitly
  const alertsTxt = await page.$eval('[data-testid="token-alerts"]', e => e.innerText);
  ok('страница токенов: сигнал «канарейка сработала» с адресом источника, токен заморожен', /канарейка сработала/.test(alertsTxt) && /e2e-canary/.test(alertsTxt) && /токен заморожен/.test(alertsTxt));
  ok('в сайдбаре у «Токены» счётчик открытых сигналов', (await page.$$eval('.sidebar .nav-item.alerting .count', xs => xs.map(x => x.innerText)))[0] === '1');
  await page.click('[data-testid="alert-revoke"]'); await clickText('.modal .foot button', /Отозвать/); await waitText(/Токен отозван/, 8000); await sleep(600);
  await settle(/отозван/); ok('отзыв из сигнала: канарейка отозвана, панель сигналов исчезла', (await page.$$('[data-testid="token-alerts"]')).length === 0 && /отозван/.test(await text()));
  ok('отозванная канарейка: 401 как и раньше', (await fetch(`${URL}/api/v1/m/secret/db-password`, { headers: { Authorization: `Bearer ${canary}` } })).status === 401);
  // ── named users with roles (0.20): owner invites, the person sets a password, sees only the granted folder ──
  await clickText('.sidebar button', /^Пользователи$/); await page.waitForSelector('#user-new', { timeout: 5000 }); await waitText(/Пользователей ещё нет/, 5000).catch(() => {});
  await settle(/Пользователей ещё нет/); ok('страница пользователей: пустое состояние', /Пользователей ещё нет/.test(await text()));
  await page.click('#user-new'); await page.waitForSelector('.drawer', { timeout: 5000 });
  await page.type('[data-testid="user-new-email"]', 'reader@example.com'); await page.type('[data-testid="user-new-name"]', 'Рита');
  await page.click('[data-testid="new-grant-archive"] [data-role="reader"]');
  await page.click('[data-testid="user-new-submit"]'); await page.waitForSelector('[data-testid="invite-url"]', { timeout: 8000 });
  const inviteUrl = await page.$eval('[data-testid="invite-url"]', e => e.textContent.trim());
  ok('приглашение создано, ссылка вида /invite/… показана один раз', /\/invite\/[A-Za-z0-9_-]+$/.test(inviteUrl), inviteUrl);
  await clickText('.modal .foot button', /Готово/); await sleep(500);
  await settle(/reader@example.com/, /ждёт приглашения/, /archive · читатель/); ok('пользователь в таблице: ждёт приглашения, доступ archive · читатель', /reader@example.com/.test(await text()) && /ждёт приглашения/.test(await text()) && /archive · читатель/.test(await text()));
  // the invited person, in a separate browser context (own cookies)
  const uctx = await browser.createBrowserContext(); const up = await uctx.newPage(); await up.setViewport({ width: 1280, height: 900 }); up.on('pageerror', e => errors.push('invite page: ' + e.message));
  await up.goto(inviteUrl + '?lang=ru', { waitUntil: 'networkidle0', timeout: 15000 });   // a fresh context has no stored language; the checks below are in Russian await up.waitForSelector('[data-testid="invite-password"]', { timeout: 8000 });
  ok('страница приглашения знает, кого приглашают', /reader@example.com/.test(await up.evaluate(() => document.body.innerText)));
  await up.type('[data-testid="invite-password"]', 'short'); await up.type('[data-testid="invite-password2"]', 'short'); await up.click('[data-testid="invite-submit"]');
  await up.waitForFunction(() => [...document.querySelectorAll('.toast')].some(t => /короче 12/.test(t.innerText)), { timeout: 5000 });
  ok('короткий пароль отвергнут (видимая ошибка)', true);
  const UPW = 'reader password 2026!!';
  await up.click('[data-testid="invite-password"]', { clickCount: 3 }); await up.type('[data-testid="invite-password"]', UPW);
  await up.click('[data-testid="invite-password2"]', { clickCount: 3 }); await up.type('[data-testid="invite-password2"]', UPW);
  await up.click('[data-testid="invite-submit"]'); await up.waitForSelector('[data-testid="invite-done"]', { timeout: 8000 });
  ok('пароль задан, предложен переход ко входу', true);
  await up.goto(URL + '/', { waitUntil: 'networkidle0' }); await up.waitForSelector('[data-testid="login-as"]', { timeout: 8000 });
  await up.evaluate(() => [...document.querySelectorAll('[data-testid="login-as"] button')].find(b => /Пользователь/.test(b.innerText)).click());
  await up.waitForSelector('[data-testid="user-email"]', { timeout: 5000 });
  await up.type('[data-testid="user-email"]', 'reader@example.com'); await up.type('[data-testid="user-password"]', 'wrong wrong wrong!'); await up.click('[data-testid="user-login"]');
  await up.waitForFunction(() => [...document.querySelectorAll('.toast')].some(t => /wrong e-mail or password/.test(t.innerText)), { timeout: 8000 });
  ok('неверный пароль пользователя → отказ', true);
  await up.click('[data-testid="user-password"]', { clickCount: 3 }); await up.type('[data-testid="user-password"]', UPW); await up.click('[data-testid="user-login"]');
  await up.waitForSelector('.sidebar', { timeout: 15000 }); await sleep(600);
  const utext = await up.evaluate(() => document.body.innerText);
  ok('пользователь вошёл: бейдж с именем, видна только папка archive', !!(await up.$('[data-testid="me-badge"]')) && /archive/.test(utext) && !/Вебхуки|Настройки|Пользователи/.test(utext));
  const sidebarFolders = await up.$$eval('.sidebar .nav-item', els => els.map(e => e.innerText.trim()));
  ok('в сайдбаре нет чужих папок и нет кнопки «Новая папка»', !sidebarFolders.some(t => /^clients-test/.test(t)) && !(await up.$('.sidebar .nav-title .btn')));
  ok('читатель не видит кнопку «Секрет» (нет права записи)', !(await up.evaluate(() => [...document.querySelectorAll('.topbar button')].some(b => /Секрет/.test(b.innerText)))));
  await up.evaluate(() => [...document.querySelectorAll('.item')][0]?.click()); await up.waitForSelector('.detail .frow', { timeout: 8000 }); await sleep(300);
  const dtext = await up.evaluate(() => document.querySelector('.detail').innerText);
  ok('карточка секрета открыта читателем без кнопок «Изменить/Удалить/Поделиться»', !/Изменить|Поделиться/.test(dtext) && !(await up.$('.detail-head .btn.danger')));
  const rr = await up.evaluate(async () => { const r = await fetch('/api/secrets', { credentials: 'include' }); return (await r.json()).length; });
  ok('API пользователя отдаёт только секреты выданной папки', rr >= 1 && rr < (await (await fetch(`${URL}/api/secrets`, { headers: { Cookie: (await page.cookies()).map(c => `${c.name}=${c.value}`).join('; ') } })).json()).length);
  // 0.23: the user registers a security key (virtual CTAP2 authenticator with PRF) in the profile and signs in with one touch
  { const ucdp = await up.createCDPSession(); await ucdp.send('WebAuthn.enable', { enableUI: false });
    await ucdp.send('WebAuthn.addVirtualAuthenticator', { options: { protocol: 'ctap2', transport: 'usb', hasResidentKey: true, hasUserVerification: true, isUserVerified: true, hasPrf: true, automaticPresenceSimulation: true } });
    await up.evaluate(() => [...document.querySelectorAll('.sidebar button')].find(b => /Мой профиль/.test(b.innerText)).click()); await up.waitForSelector('[data-testid="me-webauthn-add"]', { timeout: 8000 });
    await up.click('[data-testid="me-webauthn-add"]'); await up.waitForSelector('.modal input[type=password]', { timeout: 5000 });
    await up.type('.modal input:not([type=password])', 'Рита YubiKey'); await up.type('.modal input[type=password]', UPW);
    await up.click('[data-testid="me-webauthn-create"]'); await up.waitForFunction(() => [...document.querySelectorAll('.toast')].some(t => /Ключ добавлен/.test(t.innerText)), { timeout: 15000 });
    await up.waitForFunction(() => /Рита YubiKey/.test(document.querySelector('.page')?.innerText || ''), { timeout: 8000 });
    ok('пользователь зарегистрировал ключ безопасности в профиле (PRF)', /PRF/.test(await up.$eval('.page', e => e.innerText)));
    ok('ключ пользователя не виден владельцу', (await (await fetch(`${URL}/api/auth/webauthn/status`)).json()).credentials === 0 && (await (await fetch(`${URL}/api/auth/webauthn/status?email=reader@example.com`)).json()).prf_unlock === true);
    await up.evaluate(() => [...document.querySelectorAll('.topbar button')].find(b => /Заблокировать/.test(b.innerText)).click()); await up.waitForSelector('[data-testid="login-as"]', { timeout: 10000 });
    await up.evaluate(() => [...document.querySelectorAll('[data-testid="login-as"] button')].find(b => /Пользователь/.test(b.innerText)).click()); await up.waitForSelector('[data-testid="user-email"]', { timeout: 5000 });
    await up.type('[data-testid="user-email"]', 'reader@example.com'); await up.click('[data-testid="user-webauthn"]'); await up.waitForSelector('.sidebar', { timeout: 15000 }); await sleep(400);
    ok('вход пользователя одним касанием ключа без пароля: сессия пользователя (бейдж, только своя папка)', !!(await up.$('[data-testid="me-badge"]')) && /archive/.test(await up.evaluate(() => document.body.innerText))); }
  // ── 0.30: one-time codes for the user; the owner makes them a manager; the manager grants from the folder; the owner rotates the folder key ──
  const totpCode = (b32) => { const A = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'; let bits = '', bytes = []; for (const c of b32.replace(/=+$/, '')) bits += A.indexOf(c).toString(2).padStart(5, '0'); for (let i = 0; i + 8 <= bits.length; i += 8) bytes.push(parseInt(bits.slice(i, i + 8), 2));
    const step = Math.floor(Date.now() / 30000); const msg = Buffer.alloc(8); msg.writeUInt32BE(Math.floor(step / 2 ** 32), 0); msg.writeUInt32BE(step >>> 0, 4);
    const h = createHmac('sha1', Buffer.from(bytes)).update(msg).digest(); const o = h[19] & 0xf; return String(((h[o] & 0x7f) << 24 | h[o + 1] << 16 | h[o + 2] << 8 | h[o + 3]) % 1e6).padStart(6, '0'); };
  await up.evaluate(() => [...document.querySelectorAll('.sidebar button')].find(b => /Мой профиль/.test(b.innerText)).click()); await up.waitForSelector('[data-testid="me-totp-on"]', { timeout: 8000 });
  await up.click('[data-testid="me-totp-on"]'); await up.waitForSelector('[data-testid="me-totp-secret"]', { timeout: 8000 });
  const totpSecret = await up.$eval('[data-testid="me-totp-secret"]', e => e.textContent.trim());
  ok('профиль: включение TOTP показывает QR и секрет (base32)', /^[A-Z2-7]{16,}$/.test(totpSecret) && !!(await up.$('.modal img')), totpSecret);
  await up.type('[data-testid="me-totp-code"]', '000000'); await up.type('[data-testid="me-totp-password"]', UPW); await up.click('[data-testid="me-totp-confirm"]');
  await up.waitForFunction(() => [...document.querySelectorAll('.toast')].some(t => /wrong code/.test(t.innerText)), { timeout: 8000 });
  ok('неверный код отвергнут (видимый тост)', true);
  await up.click('[data-testid="me-totp-code"]', { clickCount: 3 }); await up.type('[data-testid="me-totp-code"]', totpCode(totpSecret)); await up.click('[data-testid="me-totp-confirm"]');
  await up.waitForFunction(() => [...document.querySelectorAll('.toast')].some(t => /Одноразовые коды включены/.test(t.innerText)), { timeout: 10000 }); await sleep(500);
  ok('TOTP включён, профиль показывает «Включены»', /Включены: при входе/.test(await up.$eval('.page', e => e.innerText)));
  await up.evaluate(() => [...document.querySelectorAll('.topbar button')].find(b => /Заблокировать/.test(b.innerText)).click()); await up.waitForSelector('[data-testid="login-as"]', { timeout: 10000 });
  await up.evaluate(() => [...document.querySelectorAll('[data-testid="login-as"] button')].find(b => /Пользователь/.test(b.innerText)).click()); await up.waitForSelector('[data-testid="user-email"]', { timeout: 5000 });
  await up.type('[data-testid="user-email"]', 'reader@example.com'); await up.type('[data-testid="user-password"]', UPW); await up.click('[data-testid="user-login"]');
  await up.waitForFunction(() => { const c = document.querySelector('[data-testid="user-totp"]'); return c && !c.classList.contains('hidden'); }, { timeout: 8000 });
  ok('вход паролем: сервер требует код, поле TOTP появилось', true);
  await up.type('[data-testid="user-totp"]', totpCode(totpSecret)); await up.click('[data-testid="user-login"]'); await up.waitForSelector('.sidebar', { timeout: 15000 }); await sleep(400);
  ok('пароль + код: сессия пользователя открыта', !!(await up.$('[data-testid="me-badge"]')));
  // the owner promotes the reader to manager of «archive» from the folder's access dialog
  const archiveId = (await (await fetch(`${URL}/api/folders`, { headers: { Cookie: (await page.cookies()).map(c => `${c.name}=${c.value}`).join('; ') } })).json()).find(f => f.name === 'archive').id;
  await page.goto(URL + `/#/folder/${archiveId}`, { waitUntil: 'networkidle0' }); await page.waitForSelector('[data-testid="folder-access"]', { timeout: 8000 });
  await page.click('[data-testid="folder-access"]'); await page.waitForSelector('[data-testid="access-reader@example.com"]', { timeout: 8000 });
  await page.evaluate(() => [...document.querySelectorAll('[data-testid="access-reader@example.com"] .chip')].find(c => /менеджер/.test(c.innerText)).click());
  await page.waitForFunction(() => [...document.querySelectorAll('.toast')].some(t => /менеджер/.test(t.innerText)), { timeout: 8000 });
  ok('владелец выдал роль менеджера из диалога доступа к папке', true);
  await page.evaluate(() => document.querySelector('.overlay')?.remove());
  // the manager sees the folder's access dialog with the directory; their own row is read-only
  await up.goto(URL + `/#/folder/${archiveId}`, { waitUntil: 'networkidle0' }); await up.reload({ waitUntil: 'networkidle0' });   // the role changed on the server: a reload picks up the new grants
  await up.waitForSelector('[data-testid="folder-access"]', { timeout: 8000 });
  await up.click('[data-testid="folder-access"]'); await up.waitForSelector('.modal table', { timeout: 8000 });
  const accessTxt = await up.$eval('.modal', e => e.innerText);
  ok('менеджер открыл «Доступ к папке»: видит справочник, свою роль поменять не может', /reader@example.com/.test(accessTxt) && /свою роль меняет администратор/.test(accessTxt));
  await up.evaluate(() => document.querySelector('.overlay')?.remove());
  // the owner rotates the folder key: the e2e-reader token dies, the user still reads
  await page.click('[data-testid="folder-rotate-key"]'); await clickText('.modal .foot button', /Сменить ключ/); await waitText(/Ключ сменён/, 15000); await sleep(600);
  const rotToast = await page.evaluate(() => [...document.querySelectorAll('.toast')].map(t => t.innerText).join(' | '));
  ok('ключ папки сменён, отозванные токены названы (e2e-reader)', /e2e-reader/.test(rotToast), rotToast.slice(0, 120));
  ok('старый токен папки после смены ключа: 401', (await fetch(`${URL}/api/v1/m/secret/db-password`, { headers: { Authorization: `Bearer ${tok}` } })).status === 401);
  const userRead = await up.evaluate(async () => { const l = await (await fetch('/api/secrets', { credentials: 'include' })).json(); const s = await (await fetch(`/api/secrets/${l[0].id}`, { credentials: 'include' })).json(); return s.value; });
  ok('пользователь после смены ключа читает секрет (грант переоформлен)', typeof userRead === 'string' && userRead.length > 0);
  await up.close(); await uctx.close();
  // the owner sees the person in the audit log
  await clickText('.sidebar button', /^Журнал$/); await page.waitForSelector('.page table', { timeout: 8000 }); await sleep(300);
  ok('журнал владельца: действия подписаны e-mail пользователя', /reader@example.com/.test(await page.$eval('.page', e => e.innerText)));
  // ── cipher suite (0.18): what the server runs is what the Settings page says ──
  { const hh = await (await fetch(`${URL}/api/health`)).json();
    await page.goto(URL + '/#/settings', { waitUntil: 'networkidle0' }); await waitText(/Криптография/, 8000);
    const lbl = await page.$eval('[data-testid="cipher-label"]', e => e.innerText);
    ok(`настройки показывают криптонабор сервера (${hh.cipher}: ${lbl})`, lbl === hh.cipher_label && (hh.cipher === 'gost' ? /Кузнечик/.test(lbl) : /AES-256-GCM/.test(lbl)));
    await clickText('.sidebar button', /^Токены$/); await page.waitForSelector('#tok-new', { timeout: 5000 }); }
  // ── sealed delivery (0.17): a token bound to an X25519 key never yields plaintext ──
  const { generateKeyPair, unseal } = await import('/aps/aps-vault/clients/node/dist/index.js');
  const kp = generateKeyPair();
  await page.click('#tok-new'); await page.waitForSelector('.drawer', { timeout: 5000 });
  await page.type('.drawer input', 'e2e-sealed'); await clickText('.drawer .chip', /archive/); await page.waitForFunction(() => /archive/.test(document.querySelector('.drawer .chip.active')?.innerText || ''), { timeout: 3000 });
  await page.type('[data-testid="tok-pubkey"]', 'not-a-key'); await clickText('.drawer .foot button', /Создать/);
  await page.waitForFunction(() => [...document.querySelectorAll('.toast')].some(t => /client_public_key/.test(t.innerText)), { timeout: 8000 });
  ok('неверный публичный ключ отвергнут (видимая ошибка 422)', true);
  await page.click('[data-testid="tok-pubkey"]', { clickCount: 3 }); await page.type('[data-testid="tok-pubkey"]', kp.publicKey);
  await clickText('.drawer .foot button', /Создать/); await page.waitForSelector('.modal .codebox', { timeout: 8000 });
  const stok = await page.$eval('.modal .codebox', e => e.textContent.trim());
  const sr = await fetch(`${URL}/api/v1/m/secret/db-password`, { headers: { Authorization: `Bearer ${stok}` } }); const sbody = await sr.text();
  ok('машинный API отдаёт запечатанный конверт: в ответе нет ни значения, ни поля value', sr.status === 200 && !sbody.includes('new-value-after-edit-2026') && !sbody.includes('"value"') && JSON.parse(sbody).sealed?.alg === 'X25519-HKDF-SHA256-AES256GCM', sbody.slice(0, 120));
  const sj = JSON.parse(sbody);
  ok('приватный ключ клиента (node:crypto) открывает конверт — настоящее значение', unseal(sj.sealed, kp.privateKey, sj.name).value === 'new-value-after-edit-2026');
  let wrongOpened = false; try { unseal(sj.sealed, generateKeyPair().privateKey, sj.name); wrongOpened = true; } catch {}
  ok('чужой приватный ключ конверт не открывает', !wrongOpened);
  const skv = await fetch(`${URL}/v1/archive/data/db-password`, { headers: { 'X-Vault-Token': stok } });
  ok('HashiCorp-фасад запечатанному токену отвечает 403, а не открытым текстом', skv.status === 403 && !(await skv.text()).includes('new-value-after-edit-2026'));
  await clickText('.modal .foot button', /Готово/); await sleep(600);
  await settle(/e2e-sealed/, /запечатано/); ok('токен в таблице помечен «запечатано»', /e2e-sealed/.test(await text()) && /запечатано/.test(await text()));
  // ── node enrolment (0.21): a code from the UI, the "node" enrols itself through the Node client, gets a sealed token ──
  { const { enroll } = await import('/aps/aps-vault/clients/node/dist/index.js');
    await page.click('#enrol-new'); await page.waitForSelector('.drawer', { timeout: 5000 });
    await clickText('.drawer .chip', /archive/); await page.click('[data-testid="enrol-prefix"]', { clickCount: 3 }); await page.type('[data-testid="enrol-prefix"]', 'core');
    await page.click('[data-testid="enrol-create"]'); await page.waitForSelector('[data-testid="enrol-code"]', { timeout: 8000 });
    const code = await page.$eval('[data-testid="enrol-code"]', e => e.textContent.trim());
    ok('код регистрации показан один раз (enr_…)', /^enr_[A-Za-z0-9_-]+$/.test(code), code);
    const en = await enroll(URL, code, { name: 'node-e2e' });
    ok('узел зарегистрировался Node-клиентом: токен core-node-e2e, пара ключей сделана на узле', en.token.startsWith('vlt_') && en.tokenName === 'core-node-e2e' && Buffer.from(en.privateKey, 'base64').length === 32);
    const er = await fetch(`${URL}/api/v1/m/secret/db-password`, { headers: { Authorization: `Bearer ${en.token}` } }); const ej = await er.json();
    ok('выданный токен запечатан на ключ узла и читает папку', er.status === 200 && !!ej.sealed && unseal(ej.sealed, en.privateKey, ej.name).value === 'new-value-after-edit-2026');
    let spent = null; try { await enroll(URL, code, { name: 'node-2' }); } catch (e) { spent = e.status; }
    ok('повторное использование одноразового кода → 410', spent === 410);
    // P-256 (0.22): the curve a TPM holds — software pair here, the envelope type follows the key
    { const ck = (await page.cookies()).map(c => `${c.name}=${c.value}`).join('; '); const csrfC = (await page.cookies()).find(c => c.name === 'vault_csrf').value;
      const archiveId = (await (await fetch(`${URL}/api/folders`, { headers: { Cookie: ck } })).json()).find(f => f.name === 'archive').id;   // db-password lives in "archive" after the move step
      const pr = await (await fetch(`${URL}/api/enrollments`, { method: 'POST', headers: { 'Content-Type': 'application/json', Cookie: ck, 'X-CSRF-Token': csrfC }, body: JSON.stringify({ folder_id: archiveId, name_prefix: 'tpm' }) })).json();
      const pe = await enroll(URL, pr.code, { name: 'node-p256', p256: true });
      const pj = await (await fetch(`${URL}/api/v1/m/secret/db-password`, { headers: { Authorization: `Bearer ${pe.token}` } })).json();
      ok('P-256 ключ узла → конверт P256-HKDF-SHA256-AES256GCM, Node-клиент открывает', pj.sealed?.alg === 'P256-HKDF-SHA256-AES256GCM' && unseal(pj.sealed, pe.privateKey, pj.name).value === 'new-value-after-edit-2026', pj.sealed?.alg); }
    await clickText('.modal .foot button', /Готово/); await sleep(600);
    await settle(/core-node-e2e/); ok('токен узла в таблице помечен «запечатано»; кода в списке действующих больше нет', /core-node-e2e/.test(await text()) && !/core-…/.test(await text())); }
  // ── GOST envelope (0.19): a 64-byte GOST R 34.10 key on the token → VKO + Kuznyechik-MGM, opened by the Node client ──
  { const gk = generateKeyPair({ gost: true });
    await page.click('#tok-new'); await page.waitForSelector('.drawer', { timeout: 5000 });
    await page.type('.drawer input', 'e2e-gost'); await clickText('.drawer .chip', /archive/); await page.waitForFunction(() => /archive/.test(document.querySelector('.drawer .chip.active')?.innerText || ''), { timeout: 3000 });
    await page.type('[data-testid="tok-pubkey"]', gk.publicKey); await clickText('.drawer .foot button', /Создать/); await page.waitForSelector('.modal .codebox', { timeout: 8000 });
    const gtok = await page.$eval('.modal .codebox', e => e.textContent.trim());
    const gr = await fetch(`${URL}/api/v1/m/secret/db-password`, { headers: { Authorization: `Bearer ${gtok}` } }); const gbody = await gr.text(); const gj = JSON.parse(gbody);
    ok('ГОСТ-ключ на токене → конверт VKO + Кузнечик-MGM, открытого текста нет', gr.status === 200 && gj.sealed?.alg === 'VKO-GOSTR3410-2012-256-KDFTREE-KUZNYECHIK-MGM' && !!gj.sealed.ukm && !gbody.includes('new-value-after-edit-2026'), gj.sealed?.alg);
    ok('Node-клиент открывает ГОСТ-конверт своим ключом', unseal(gj.sealed, gk.privateKey, gj.name).value === 'new-value-after-edit-2026');
    let gw = false; try { unseal(gj.sealed, generateKeyPair({ gost: true }).privateKey, gj.name); gw = true; } catch {}
    ok('чужой ГОСТ-ключ конверт не открывает', !gw);
    await clickText('.modal .foot button', /Готово/); await sleep(600);
    await settle(/e2e-gost/, /запечатано ГОСТ/); ok('ГОСТ-токен в таблице помечен «запечатано ГОСТ»', /e2e-gost/.test(await text()) && /запечатано ГОСТ/.test(await text())); }
  // ── GOST post-quantum hybrid (0.32): a 1248-byte GOST‖ML-KEM-768 key → VKO + ML-KEM → KDF_TREE → Kuznyechik-MGM ──
  { const gq = generateKeyPair({ gostPqc: true });
    ok('ГОСТ-гибрид: ключ 96/1248 байт', Buffer.from(gq.privateKey, 'base64').length === 96 && Buffer.from(gq.publicKey, 'base64').length === 1248);
    await page.click('#tok-new'); await page.waitForSelector('.drawer', { timeout: 5000 });
    await page.type('.drawer input', 'e2e-gost-pqc'); await clickText('.drawer .chip', /archive/); await page.waitForFunction(() => /archive/.test(document.querySelector('.drawer .chip.active')?.innerText || ''), { timeout: 3000 });
    await page.type('[data-testid="tok-pubkey"]', gq.publicKey); await clickText('.drawer .foot button', /Создать/); await page.waitForSelector('.modal .codebox', { timeout: 8000 });
    const qtok = await page.$eval('.modal .codebox', e => e.textContent.trim());
    const qr = await fetch(`${URL}/api/v1/m/secret/db-password`, { headers: { Authorization: `Bearer ${qtok}` } }); const qbody = await qr.text(); const qj = JSON.parse(qbody);
    ok('ГОСТ-гибрид на токене → конверт VKO + ML-KEM-768 + Кузнечик-MGM с полями ukm и kem, открытого текста нет', qr.status === 200 && qj.sealed?.alg === 'VKO-GOSTR3410-2012-256-MLKEM768-KDFTREE-KUZNYECHIK-MGM' && typeof qj.sealed?.kem === 'string' && typeof qj.sealed?.ukm === 'string' && !qbody.includes('new-value-after-edit-2026') && !('value' in qj));
    ok('Node-клиент открывает ГОСТ-гибридный конверт своим ключом', unseal(qj.sealed, gq.privateKey, qj.name).value === 'new-value-after-edit-2026');
    let qw = false; try { unseal(qj.sealed, generateKeyPair({ gostPqc: true }).privateKey, qj.name); qw = true; } catch {}
    ok('чужой ГОСТ-гибридный ключ конверт не открывает', !qw);
    let qh = false; try { unseal(qj.sealed, Buffer.concat([Buffer.from(gq.privateKey, 'base64').subarray(0, 32), Buffer.from(generateKeyPair({ gostPqc: true }).privateKey, 'base64').subarray(32)]).toString('base64'), qj.name); qh = true; } catch {}
    ok('правильная ГОСТ-половина с чужим ML-KEM-сидом конверт не открывает', !qh);
    await clickText('.modal .foot button', /Готово/); await sleep(600);
    await settle(/e2e-gost-pqc/, /запечатано ГОСТ\+PQC/); ok('ГОСТ-гибридный токен в таблице помечен «запечатано ГОСТ+PQC»', /e2e-gost-pqc/.test(await text()) && /запечатано ГОСТ\+PQC/.test(await text())); }
  await page.screenshot({ path: `${OUT}/tokens.png` });
  // ── share links: human page (default) and machine JSON ─────────────────
  await page.goto(URL + '/#/all/s/1', { waitUntil: 'networkidle0' }); await page.waitForSelector('.detail', { timeout: 8000 }); await sleep(400);
  await clickText('.detail-head button', /Поделиться/); await page.waitForSelector('[data-testid="share-kind"]', { timeout: 5000 });
  ok('диалог «Поделиться»: по умолчанию выбран вид «Для человека»', await page.$eval('[data-testid="share-kind"] button.active', b => /Для человека/.test(b.innerText)));
  await page.type('.modal input[placeholder*="стенда"]', 'после входа смени пароль');
  await clickText('.modal .foot button', /Создать ссылку/); await page.waitForSelector('.modal .codebox', { timeout: 8000 });
  const humanUrl = await page.$eval('.modal .codebox', e => e.textContent.trim());
  ok('человекочитаемая ссылка вида /share/…', /\/share\/[A-Za-z0-9_-]+$/.test(humanUrl) && !humanUrl.includes('/api/'), humanUrl);
  const p2 = await browser.newPage(); p2.on('pageerror', e => errors.push('share page: ' + e.message));
  await p2.goto(humanUrl, { waitUntil: 'networkidle0', timeout: 15000 });
  const landing = await p2.evaluate(() => document.body.innerText);
  ok('страница получателя: предупреждение об одноразовости и кнопка «Открыть», значение ещё НЕ запрошено', /одноразов/.test(landing) && !/new-value-after-edit/.test(landing) && !!(await p2.$('[data-testid="share-open"]')));
  const before = await (await fetch(`${URL}/api/health`)).ok;   // the link is still unused: a second fresh load shows the landing again
  await p2.click('[data-testid="share-open"]'); await p2.waitForFunction(() => /Копировать|Copy/.test(document.body.innerText), { timeout: 8000 }); await sleep(200);
  const opened = await p2.evaluate(() => document.body.innerText);
  ok('после клика: имя, логин, сообщение отправителя, значение размыто', /db-password/.test(opened) && /app/.test(opened) && /после входа смени пароль/.test(opened) && !!(await p2.$('.secret-blur')));
  await p2.evaluateHandle(() => [...document.querySelectorAll('button')].find(b => /Показать|Reveal/.test(b.innerText)).click()); await sleep(150);
  ok('«Показать» раскрывает значение', (await p2.evaluate(() => document.body.innerText)).includes('new-value-after-edit-2026') && !(await p2.$('.secret-blur')));
  await p2.screenshot({ path: `${OUT}/share-page.png` });
  const p3 = await browser.newPage(); await p3.goto(humanUrl, { waitUntil: 'networkidle0', timeout: 15000 }); await p3.click('[data-testid="share-open"]'); await p3.waitForFunction(() => /истекла или уже|expired or was already/.test(document.body.innerText), { timeout: 8000 });
  ok('второе открытие одноразовой страницы — понятный отказ', true); await p2.close(); await p3.close();
  await page.keyboard.press('Escape');
  // machine kind
  await clickText('.detail-head button', /Поделиться/); await page.waitForSelector('[data-testid="share-kind"]', { timeout: 5000 });
  await clickText('[data-testid="share-kind"] button', /Для машины/); await clickText('.modal .foot button', /Создать ссылку/); await page.waitForSelector('.modal .codebox', { timeout: 8000 });
  const shareUrl = await page.$eval('.modal .codebox', e => e.textContent.trim());
  ok('машинная ссылка вида /api/share/…', /\/api\/share\//.test(shareUrl), shareUrl);
  const sh = await fetch(shareUrl); const shBody = await sh.json().catch(() => ({}));
  ok('машинная ссылка отдаёт JSON с value и login без входа (настоящий запрос)', sh.status === 200 && shBody.value === 'new-value-after-edit-2026' && shBody.login === 'app', 'HTTP ' + sh.status);
  const sh2 = await fetch(shareUrl);
  ok('второе открытие одноразовой ссылки — отказ', sh2.status >= 400);
  await page.keyboard.press('Escape');
  await clickText('.sidebar button', /^Ссылки$/); await page.waitForSelector('.page .table', { timeout: 8000 }); await sleep(200);
  const sharesTxt = await page.$eval('.page', e => e.innerText);
  ok('страница ссылок показывает использованные ссылки', /использована/.test(sharesTxt) && /1 \/ 1/.test(sharesTxt), sharesTxt.slice(0, 200));
  // the kind is remembered: machine was chosen last → next dialog opens on machine
  await page.goto(URL + '/#/all/s/1', { waitUntil: 'networkidle0' }); await page.waitForSelector('.detail', { timeout: 8000 }); await sleep(300);
  await clickText('.detail-head button', /Поделиться/); await page.waitForSelector('[data-testid="share-kind"]', { timeout: 5000 });
  ok('выбор вида ссылки запоминается', await page.$eval('[data-testid="share-kind"] button.active', b => /Для машины/.test(b.innerText)));
  await clickText('[data-testid="share-kind"] button', /Для человека/); await page.keyboard.press('Escape');
  // ── machine-only secret: generated on the server, hidden from people, read by a token, rotated ──
  await page.goto(URL + '/#/folder/1', { waitUntil: 'networkidle0' }); await page.waitForSelector('.list', { timeout: 8000 }); await sleep(300);
  await page.keyboard.press('n'); await page.waitForSelector('.drawer', { timeout: 5000 });
  await page.type('.drawer input', 'file-encryption-key');
  await page.click('[data-testid="gen-server"]'); await sleep(100);
  ok('тумблер «сгенерировать на сервере» прячет поле значения и показывает форматы', (await page.$$('.drawer .chip[data-spec]')).length === 4 && await page.evaluate(() => document.querySelector('.drawer textarea').closest('.field').classList.contains('hidden')));
  await page.click('[data-testid="machine-only"]');
  await clickText('.drawer .foot button', /Сохранить/); await waitText(/Сохранено/, 8000); await page.waitForSelector('.detail', { timeout: 8000 }); await sleep(600);
  const moCard = await page.$eval('.detail', e => e.innerText);
  ok('карточка machine-only: значения нет, есть пояснение и кнопка «Ротация», нет «Поделиться»', /Только для машин/.test(moCard) && /Ротация/.test(moCard) && !/Поделиться/.test(moCard) && !(await page.$('.detail .frow .secret-blur')));
  ok('в списке бейдж «машины»', (await page.$$eval('.item .badge', xs => xs.map(x => x.innerText))).some(t => /машины/.test(t)));
  const moId = parseInt((await page.evaluate(() => location.hash)).split('/s/')[1]);
  // the token created earlier is scoped to "archive"; make one for clients-test via the API with the UI's cookies
  const cookies = (await page.cookies()).map(c => `${c.name}=${c.value}`).join('; '); const csrf = (await page.cookies()).find(c => c.name === 'vault_csrf').value;
  const tk = await (await fetch(`${URL}/api/tokens`, { method: 'POST', headers: { 'Content-Type': 'application/json', Cookie: cookies, 'X-CSRF-Token': csrf }, body: JSON.stringify({ name: 'mo-reader', folder_id: 1 }) })).json();
  const mo1 = await (await fetch(`${URL}/api/v1/m/secret/file-encryption-key`, { headers: { Authorization: `Bearer ${tk.raw_token}` } })).json();
  ok('машина читает сгенерированный ключ (43 символа base64, версия 1)', mo1.value?.length === 43 && mo1.version === 1, JSON.stringify(mo1).slice(0, 120));
  await clickText('.detail button', /^Ротация$/); await page.waitForSelector('[data-testid="rotate-confirm"]', { timeout: 5000 });
  await clickText('.modal .chip', /hex/); await page.click('[data-testid="rotate-confirm"]'); await waitText(/Ротация выполнена: версия 2/, 8000); await sleep(600);
  const mo2 = await (await fetch(`${URL}/api/v1/m/secret/file-encryption-key`, { headers: { Authorization: `Bearer ${tk.raw_token}` } })).json();
  const mo1again = await (await fetch(`${URL}/api/v1/m/secret/file-encryption-key?version=1`, { headers: { Authorization: `Bearer ${tk.raw_token}` } })).json();
  ok('после ротации: версия 2 в hex (64 симв.), версия 1 читается по ?version=1', mo2.version === 2 && mo2.value?.length === 64 && mo1again.value === mo1.value);
  ok('карточка показывает версию 2', /[Вв]ерсия 2/.test(await page.$eval('.detail', e => e.innerText)));
  const expJson = await (await fetch(`${URL}/api/export`, { headers: { Cookie: cookies } })).json();
  const expMo = expJson.folders.flatMap(f => f.secrets).find(x => x.name === 'file-encryption-key');
  ok('в экспорте значение machine-only отсутствует (null)', expMo && expMo.value === null && expMo.machine_only === true);
  await page.screenshot({ path: `${OUT}/machine-only.png` });
  // ── approval workflow: approver set in Settings, flagged secret, request → approve page → read ──
  await page.goto(URL + '/#/settings', { waitUntil: 'networkidle0' }); await waitText(/Подтверждение чтения/, 8000);
  await page.evaluate(() => document.querySelectorAll('.toast').forEach(t => t.remove()));   // a toast in the corner must not swallow the click
  await page.click('[data-testid="approver-set"]'); await page.waitForSelector('.modal input[type=password]', { timeout: 5000 });
  const apIn = await page.$$('.modal input[type=password]'); await apIn[0].type(MASTER); await apIn[1].type('approver password 2026 ok');
  await clickText('.modal .foot button', /Сохранить/); await waitText(/Подтверждающий назначен/, 8000); await sleep(400);
  await settle(/Подтверждающий назначен\./); ok('подтверждающий назначен из настроек', /Подтверждающий назначен\./.test(await text()));
  await page.goto(URL + '/#/folder/1', { waitUntil: 'networkidle0' }); await page.waitForSelector('.list', { timeout: 8000 }); await sleep(300);
  await page.keyboard.press('n'); await page.waitForSelector('.drawer', { timeout: 5000 });
  await page.type('.drawer input', 'root-password'); await page.type('.drawer textarea', 'guarded-value-2026');
  await page.click('[data-testid="require-approval"]');
  await clickText('.drawer .foot button', /Сохранить/); await waitText(/Сохранено/, 8000); await page.waitForSelector('[data-testid="approval-request"]', { timeout: 8000 });
  ok('карточка секрета с флагом: панель запроса вместо значения', !/guarded-value-2026/.test(await text()));
  ok('в списке бейдж «подтверждение»', (await page.$$eval('.item .badge', xs => xs.map(x => x.innerText))).some(t => /подтверждение/.test(t)));
  await page.type('[data-testid="approval-reason"]', 'инцидент 4711'); await page.click('[data-testid="approval-request"]');
  await page.waitForSelector('[data-testid="approve-url"]', { timeout: 8000 });
  const approveUrl = await page.$eval('[data-testid="approve-url"]', e => e.textContent.trim());
  ok('без нотификатора ссылка для подтверждающего показана запросившему', /\/approve\/[A-Za-z0-9_-]+$/.test(approveUrl), approveUrl);
  const ap = await browser.newPage(); ap.on('pageerror', e => errors.push('approve page: ' + e.message));
  await ap.goto(approveUrl, { waitUntil: 'networkidle0', timeout: 15000 }); await ap.waitForSelector('[data-testid="approver-password"]', { timeout: 8000 });
  const apText = await ap.evaluate(() => document.body.innerText);
  ok('страница подтверждающего: секрет, причина, нет значения', /root-password/.test(apText) && /инцидент 4711/.test(apText) && !/guarded-value-2026/.test(apText));
  await ap.type('[data-testid="approver-password"]', 'wrong wrong wrong'); await ap.click('[data-testid="approve-yes"]'); await ap.waitForFunction(() => /wrong approver password/.test(document.body.innerText), { timeout: 5000 });
  ok('неверный пароль подтверждающего → видимая ошибка', true);
  await ap.click('[data-testid="approver-password"]', { clickCount: 3 }); await ap.type('[data-testid="approver-password"]', 'approver password 2026 ok'); await ap.click('[data-testid="approve-yes"]');
  await ap.waitForFunction(() => /Одобрено/.test(document.body.innerText), { timeout: 8000 }); await ap.close();
  await page.waitForFunction(() => /guarded-value-2026|Подтверждено/.test(document.body.innerText) || !!document.querySelector('.detail .secret-blur'), { timeout: 15000 }); await sleep(500);
  ok('после одобрения карточка запросившего показывает значение (размыто)', !!(await page.$('.detail .frow .secret-blur')) && !(await page.$('[data-testid="approval-request"]')));
  await page.screenshot({ path: `${OUT}/approval.png` });
  // ── WebAuthn with Chrome's virtual authenticator (CTAP2, PRF): register in Settings, unlock by touch, second factor ──
  const cdp = await page.target().createCDPSession();
  await cdp.send('WebAuthn.enable', { enableUI: false });
  const { authenticatorId } = await cdp.send('WebAuthn.addVirtualAuthenticator', { options: { protocol: 'ctap2', transport: 'usb', hasResidentKey: true, hasUserVerification: true, isUserVerified: true, hasPrf: true, automaticPresenceSimulation: true } });
  await page.goto(URL + '/#/settings', { waitUntil: 'networkidle0' }); await waitText(/Ключи безопасности/, 8000);
  await page.evaluate(() => document.querySelectorAll('.toast').forEach(t => t.remove()));
  await page.click('[data-testid="webauthn-add"]'); await page.waitForSelector('.modal input[type=password]', { timeout: 5000 });
  await page.type('.modal input:not([type=password])', 'virtual YubiKey'); await page.type('.modal input[type=password]', MASTER);
  await page.click('[data-testid="webauthn-create"]'); await waitText(/Ключ добавлен/, 15000); await sleep(600);
  const waTxt = await text();
  ok('ключ зарегистрирован через настоящий WebAuthn (виртуальный аутентификатор с PRF): вход касанием доступен', /Ключ добавлен: вход одним касанием/.test(waTxt) && /virtual YubiKey/.test(waTxt) && /PRF/.test(waTxt), waTxt.match(/Ключ добавлен[^\n]*/)?.[0]);
  const creds = await cdp.send('WebAuthn.getCredentials', { authenticatorId });
  ok('аутентификатор хранит ровно одну учётку для RP localhost', creds.credentials.length === 1 && creds.credentials[0].rpId === 'localhost');
  // lock → unlock by touch, no password
  await clickText('.topbar button', /Lock|Заблокировать/); await page.waitForSelector('input[type=password]', { timeout: 10000 });
  await page.waitForSelector('[data-testid="webauthn-unlock"]', { timeout: 8000 });
  ok('на экране входа есть кнопка «Войти ключом безопасности / Touch ID»', true);
  await page.click('[data-testid="webauthn-unlock"]'); await page.waitForSelector('.sidebar', { timeout: 15000 });
  ok('вход одним касанием: сессия открыта без ввода пароля', (await page.$$('.item')).length >= 1);
  const h2 = await (await fetch(`${URL}/api/health`, { headers: { Cookie: (await page.cookies()).map(c => `${c.name}=${c.value}`).join('; ') } })).json();
  ok('health подтверждает сессию после WebAuthn-входа', h2.unlocked === true);
  // second factor: password alone is refused, then the key is asked for automatically
  await page.goto(URL + '/#/settings', { waitUntil: 'networkidle0' }); await waitText(/Требовать ключ при входе паролем/, 8000);
  await page.evaluate(() => document.querySelectorAll('.toast').forEach(t => t.remove()));
  await page.click('[data-testid="webauthn-2fa"]'); await sleep(800);
  ok('второй фактор включён', await page.$eval('[data-testid="webauthn-2fa"]', e => e.classList.contains('on')));
  await clickText('.topbar button', /Lock|Заблокировать/); await page.waitForSelector('input[type=password]', { timeout: 10000 }); await sleep(300);
  const r401 = await (await fetch(`${URL}/api/auth/unlock`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ master_password: MASTER }) }));
  ok('API: пароль без ключа → 401 с заголовком X-WebAuthn-Required', r401.status === 401 && r401.headers.get('x-webauthn-required') === '1');
  await page.type('input[type=password]', MASTER); await page.keyboard.press('Enter'); await page.waitForSelector('.sidebar', { timeout: 15000 });
  ok('вход паролем + автоматический запрос ключа → сессия открыта', true);
  // cleanup: second factor off, remove the key
  await page.goto(URL + '/#/settings', { waitUntil: 'networkidle0' }); await waitText(/Требовать ключ при входе паролем/, 8000);
  // 0.37: turning the second factor off needs the master password (a stolen session alone must not drop it)
  await page.evaluate(() => document.querySelectorAll('.toast').forEach(t => t.remove())); await page.click('[data-testid="webauthn-2fa"]');
  await page.waitForSelector('[data-testid="password-dialog-input"]', { timeout: 5000 });
  ok('выключение второго фактора спрашивает мастер-пароль', true);
  await page.type('[data-testid="password-dialog-input"]', 'wrong wrong wrong'); await page.click('[data-testid="password-dialog-ok"]');
  await page.waitForSelector('.toast', { timeout: 5000 }); await sleep(500);
  ok('неверный пароль → фактор остаётся включённым (видимая ошибка)', await page.$eval('[data-testid="webauthn-2fa"]', e => e.classList.contains('on')) && /password|парол/i.test(await page.$eval('.toast', e => e.textContent)),
     await page.$eval('.toast', e => e.textContent));
  await page.evaluate(() => document.querySelectorAll('.toast').forEach(t => t.remove())); await page.click('[data-testid="webauthn-2fa"]');
  await page.waitForSelector('[data-testid="password-dialog-input"]', { timeout: 5000 });
  await page.type('[data-testid="password-dialog-input"]', MASTER); await page.click('[data-testid="password-dialog-ok"]'); await sleep(900);
  ok('верный мастер-пароль → второй фактор выключен', !(await page.$eval('[data-testid="webauthn-2fa"]', e => e.classList.contains('on'))));
  await clickText('.page .table button', /Удалить/); await clickText('.modal .foot button', /Удалить/); await sleep(600);
  ok('ключ удалён, кнопки входа касанием больше нет в статусе', (await (await fetch(`${URL}/api/auth/webauthn/status`)).json()).credentials === 0);
  await cdp.send('WebAuthn.removeVirtualAuthenticator', { authenticatorId });
  await page.screenshot({ path: `${OUT}/webauthn.png` });
  // ── share a note that is not a secret (Links page → dialog → page for a person) ──
  await clickText('.sidebar button', /^Ссылки$/); await page.waitForSelector('[data-testid="note-share"]', { timeout: 8000 });
  await page.evaluate(() => document.querySelectorAll('.toast').forEach(t => t.remove()));
  await page.click('[data-testid="note-share"]'); await page.waitForSelector('[data-testid="note-text"]', { timeout: 5000 });
  await page.type('[data-testid="note-title"]', 'VPN для подрядчика'); await page.type('[data-testid="note-text"]', 'host: vpn.example.com\nuser: contractor\npass: Tmp-2026!');
  await clickText('.modal .seg button', /Для человека/);
  await page.click('[data-testid="note-share-create"]'); await page.waitForSelector('[data-testid="note-share-url"]', { timeout: 8000 });
  const noteUrl = await page.$eval('[data-testid="note-share-url"]', e => e.textContent.trim());
  ok('заметка: ссылка вида /share/…', /\/share\/[A-Za-z0-9_-]+$/.test(noteUrl), noteUrl);
  await page.keyboard.press('Escape'); await sleep(300);
  ok('заметка в списке ссылок с бейджем', /заметка/.test(await page.$eval('.page', e => e.innerText)) && /VPN для подрядчика/.test(await page.$eval('.page', e => e.innerText)));
  const np = await browser.newPage(); np.on('pageerror', e => errors.push('note page: ' + e.message));
  await np.goto(noteUrl, { waitUntil: 'networkidle0', timeout: 15000 }); await np.click('[data-testid="share-open"]'); await np.waitForFunction(() => /Копировать|Copy/.test(document.body.innerText), { timeout: 8000 });
  await np.evaluate(() => [...document.querySelectorAll('button')].find(b => /Показать|Reveal/.test(b.innerText)).click()); await sleep(150);
  const noteTxt = await np.evaluate(() => document.body.innerText);
  ok('страница получателя: «Вам передали заметку», заголовок и многострочный текст', /передали заметку/.test(noteTxt) && /VPN для подрядчика/.test(noteTxt) && /pass: Tmp-2026!/.test(noteTxt) && /user: contractor/.test(noteTxt));
  await np.screenshot({ path: `${OUT}/note-share.png` }); await np.close();
  ok('заметка не стала секретом', !(await (await fetch(`${URL}/api/secrets`, { headers: { Cookie: (await page.cookies()).map(c => `${c.name}=${c.value}`).join('; ') } })).json()).some(x => x.name === 'VPN для подрядчика'));
  // ── PKCS#11 token (SoftHSM2 inside the backend container): enable in Settings, unlock by PIN ──
  await page.goto(URL + '/#/settings', { waitUntil: 'networkidle0' }); await waitText(/Аппаратный токен/, 8000);
  await page.evaluate(() => document.querySelectorAll('.toast').forEach(t => t.remove()));
  ok('настройки видят токен SoftHSM2 через PKCS#11', /SoftHSM/.test(await page.$eval('.page', e => e.innerText)) && !!(await page.$('[data-testid="hsm-enable"]')), (await page.$eval('.page', e => e.innerText)).match(/Аппаратный токен[^\n]*\n[^\n]*/)?.[0]);
  await page.click('[data-testid="hsm-enable"]'); await page.waitForSelector('.modal input[type=password]', { timeout: 5000 });
  const hsmIn = await page.$$('.modal input[type=password]'); await hsmIn[0].type(MASTER); await hsmIn[1].type('0000');
  await page.click('[data-testid="hsm-enable-confirm"]'); await page.waitForFunction(() => [...document.querySelectorAll('.toast')].some(t => /token refused|PIN/.test(t.innerText)), { timeout: 8000 });
  ok('неверный PIN отвергает сам токен (видимая ошибка)', true);
  await hsmIn[1].click({ clickCount: 3 }); await hsmIn[1].type('1234'); await page.click('[data-testid="hsm-enable-confirm"]'); await waitText(/Вход по токену включён/, 10000);
  await page.waitForFunction(() => /Включён: мастер-ключ зашифрован AES-ключом/.test(document.querySelector('.page')?.innerText || ''), { timeout: 8000 }).catch(() => {});
  ok('вход по токену включён: ключ создан в токене', /Включён: мастер-ключ зашифрован AES-ключом/.test(await page.$eval('.page', e => e.innerText)));
  await clickText('.topbar button', /Lock|Заблокировать/); await page.waitForSelector('[data-testid="hsm-pin"]', { timeout: 10000 });
  await page.type('[data-testid="hsm-pin"]', '9999'); await page.click('[data-testid="hsm-unlock"]'); await page.waitForFunction(() => [...document.querySelectorAll('.toast')].some(t => /token refused|PIN/.test(t.innerText)), { timeout: 8000 });
  ok('экран входа: неверный PIN → отказ (тост от токена)', true);
  await page.click('[data-testid="hsm-pin"]', { clickCount: 3 }); await page.type('[data-testid="hsm-pin"]', '1234'); await page.keyboard.press('Enter'); await page.waitForSelector('.sidebar', { timeout: 15000 });
  ok('вход PIN-кодом токена без мастер-пароля: сессия открыта', (await page.$$('.item')).length >= 1);
  await page.goto(URL + '/#/settings', { waitUntil: 'networkidle0' }); await waitText(/Аппаратный токен/, 8000); await page.evaluate(() => document.querySelectorAll('.toast').forEach(t => t.remove()));
  await clickText('.page button', /^Выключить$/); await clickText('.modal .foot button', /Выключить/); await sleep(600);
  ok('вход по токену выключен', (await (await fetch(`${URL}/api/auth/hsm/status`)).json()).enabled === false);
  // ── Cloud KMS (LocalStack AWS KMS in the e2e stack): PIN-bound cell, PIN login, auto mode ──
  await page.goto(URL + '/#/settings', { waitUntil: 'networkidle0' }); await waitText(/Облачный KMS/, 8000); await page.evaluate(() => document.querySelectorAll('.toast').forEach(t => t.remove()));
  ok('настройки видят KMS: AWS KMS + ключ эмулятора', /Доступен: AWS KMS, ключ [0-9a-f-]{36}/.test(await page.$eval('.page', e => e.innerText)) && !!(await page.$('[data-testid="kms-enable"]')), (await page.$eval('.page', e => e.innerText)).match(/Облачный KMS[^\n]*\n[^\n]*/)?.[0]);
  await page.click('[data-testid="kms-enable"]'); await page.waitForSelector('.modal input[type=password]', { timeout: 5000 });
  const kmsIn = await page.$$('.modal input[type=password]'); await kmsIn[0].type('wrong master password'); await kmsIn[1].type('4321');
  await page.click('[data-testid="kms-enable-confirm"]'); await page.waitForFunction(() => [...document.querySelectorAll('.toast')].some(t => /wrong master password/.test(t.innerText)), { timeout: 8000 });
  ok('включение KMS с неверным master-password отвергнуто (видимая ошибка)', true);
  await kmsIn[0].click({ clickCount: 3 }); await kmsIn[0].type(MASTER); await page.click('[data-testid="kms-enable-confirm"]'); await waitText(/Облачная ячейка включена: вход PIN-кодом/, 10000); await sleep(500);
  await page.waitForFunction(() => /Включён с PIN: AWS KMS/.test(document.querySelector('.page')?.innerText || ''), { timeout: 8000 }).catch(() => {});   // the page re-renders after the toast
  ok('ячейка KMS включена с PIN', /Включён с PIN: AWS KMS/.test(await page.$eval('.page', e => e.innerText)));
  await clickText('.topbar button', /Lock|Заблокировать/); await page.waitForSelector('[data-testid="kms-pin"]', { timeout: 10000 });
  await page.type('[data-testid="kms-pin"]', '9999'); await page.click('[data-testid="kms-unlock"]'); await page.waitForFunction(() => [...document.querySelectorAll('.toast')].some(t => /KMS refused/.test(t.innerText)), { timeout: 8000 });
  ok('экран входа: неверный PIN → KMS отказал (тост)', true);
  await page.click('[data-testid="kms-pin"]', { clickCount: 3 }); await page.type('[data-testid="kms-pin"]', '4321'); await page.keyboard.press('Enter'); await page.waitForSelector('.sidebar', { timeout: 15000 });
  ok('вход PIN-кодом через KMS без мастер-пароля: сессия открыта', (await page.$$('.item')).length >= 1);
  await page.goto(URL + '/#/settings', { waitUntil: 'networkidle0' }); await waitText(/Облачный KMS/, 8000); await page.evaluate(() => document.querySelectorAll('.toast').forEach(t => t.remove()));
  await clickText('.page button', /^Выключить$/); await clickText('.modal .foot button', /Выключить/); await sleep(600);
  ok('облачная ячейка выключена', (await (await fetch(`${URL}/api/auth/kms/status`)).json()).enabled === false);
  // auto mode (no PIN): SSO source, no PIN box on the login screen
  await page.goto(URL + '/#/settings', { waitUntil: 'networkidle0' }); await waitText(/Облачный KMS/, 8000); await page.evaluate(() => document.querySelectorAll('.toast').forEach(t => t.remove()));
  await page.click('[data-testid="kms-enable"]'); await page.waitForSelector('.modal input[type=password]', { timeout: 5000 });
  await (await page.$$('.modal input[type=password]'))[0].type(MASTER); await page.click('[data-testid="kms-enable-confirm"]'); await waitText(/авторежим для SSO/, 10000); await sleep(400);
  ok('авторежим: SSO-источник = kms, на экране входа PIN-поля нет', (await (await fetch(`${URL}/api/auth/oidc/status`)).json()).sso_unlock === 'kms' && /Включён без PIN \(авторежим\)/.test(await page.$eval('.page', e => e.innerText)));
  await clickText('.page button', /^Выключить$/); await clickText('.modal .foot button', /Выключить/); await sleep(600);
  ok('авторежим выключен', (await (await fetch(`${URL}/api/auth/kms/status`)).json()).enabled === false);
  // ── rotation in a target system (0.24): an HTTP receiver on this host plays the target ───
  // the receiver is a container on the stack's network (ops/checks/e2e-receiver.py, started by e2e-stack.sh); we talk to it over 127.0.0.1
  const RECV = process.env.E2E_RECEIVER || 'http://127.0.0.1:8190';
  const rotUrl = 'http://aps-vault-e2e-receiver:8190/rotate';
  const recv = async (p, m = 'GET') => { const r = await fetch(RECV + p, { method: m }); const t = await r.text(); return t ? JSON.parse(t) : null; };
  await recv('/reset', 'POST');
  await page.goto(URL + '/#/all/s/1', { waitUntil: 'networkidle0' }); await page.waitForSelector('[data-testid="rotation-row"]', { timeout: 8000 }); await sleep(300);
  ok('карточка: строка «Ротация в системе» — не настроена', /не настроена/.test(await page.$eval('[data-testid="rotation-row"]', e => e.innerText)));
  await page.click('[data-testid="rotation-setup"]'); await page.waitForSelector('.modal .tiles', { timeout: 5000 });
  ok('диалог ротации: цели плитками (PostgreSQL, MySQL/MariaDB, LDAP, SSH, HTTP-приёмник), не выпадающим списком', (await page.$$('.modal .tile')).length === 5 && (await page.$$('.modal select')).length === 0);
  await clickText('.modal .tile', /^LDAP/); await page.waitForSelector('[data-testid="rotation-ldap-url"]', { timeout: 3000 });
  ok('плитка LDAP: адрес каталога, выбор секрета bind, тип каталога чипами (OpenLDAP / AD), TLS чипами', /OpenLDAP · userPassword/.test(await page.$eval('.modal', e => e.innerText)) && /Active Directory · unicodePwd/.test(await page.$eval('.modal', e => e.innerText)) && /StartTLS/.test(await page.$eval('.modal', e => e.innerText)) && !!(await page.$('.modal [data-testid="secret-picker-search"]')));
  await clickText('.modal .tile', /^SSH/); await page.waitForSelector('[data-testid="rotation-ssh-hostkey"]', { timeout: 3000 });
  ok('плитка SSH: хост, порт, ключ хоста, секрет администратора, sudo чипами', /Ключ хоста/.test(await page.$eval('.modal', e => e.innerText)) && /sudo -n chpasswd/.test(await page.$eval('.modal', e => e.innerText)) && !!(await page.$('[data-testid="rotation-ssh-host"]')));
  await page.type('[data-testid="rotation-ssh-host"]', 'db-01'); await page.click('[data-testid="rotation-save"]');
  await page.waitForFunction(() => [...document.querySelectorAll('.toast')].some(t => /ключ хоста|администратора/.test(t.innerText)), { timeout: 5000 });
  ok('SSH без секрета администратора или ключа хоста не сохраняется (видимая ошибка)', (await page.$$('.modal .tiles')).length === 1);
  await page.evaluate(() => document.querySelectorAll('.toast').forEach(t => t.remove()));
  await clickText('.modal .tile', /HTTP/); await page.waitForSelector('[data-testid="rotation-url"]', { timeout: 3000 });
  await page.type('[data-testid="rotation-url"]', rotUrl);
  await clickText('.modal .chip', /^30 дн$/);
  await page.click('[data-testid="rotation-save"]'); await page.waitForSelector('[data-testid="rotation-signing"]', { timeout: 8000 });
  const rotSigning = await page.$eval('[data-testid="rotation-signing"]', e => e.textContent.trim());
  ok('секрет подписи приёмника показан один раз (64 hex)', /^[0-9a-f]{64}$/.test(rotSigning), rotSigning);
  await clickText('.modal .foot button', /Готово/); await sleep(500);
  ok('карточка: HTTP-приёмник · каждые 30 дн · ещё не выполнялась', /HTTP-приёмник/.test(await page.$eval('[data-testid="rotation-row"]', e => e.innerText)) && /каждые 30 дн/.test(await page.$eval('[data-testid="rotation-row"]', e => e.innerText)));
  const rotV0 = (await page.evaluate(async () => (await (await fetch('/api/secrets/1', { credentials: 'include' })).json()))).version;
  await page.click('[data-testid="rotation-run"]'); await waitText(new RegExp(`Ротация выполнена в системе: версия ${rotV0 + 1}`), 10000); await sleep(600);
  const rotGot = await recv('/received');
  const rotBody = JSON.parse(rotGot[0].body);
  const rotSig = 'sha256=' + createHmac('sha256', rotSigning).update(rotGot[0].body).digest('hex');
  ok('приёмник получил новое значение с верной HMAC-подписью', rotGot.length === 1 && rotBody.secret === 'db-password' && rotBody.value.length >= 32 && rotGot[0].headers['x-vault-signature'] === rotSig, JSON.stringify(rotGot[0]?.headers).slice(0, 120));
  ok('карточка: статус последней ротации «успешно»', /успешно/.test(await page.$eval('[data-testid="rotation-row"]', e => e.innerText)));
  const shown = await page.evaluate(async () => (await (await fetch('/api/secrets/1', { credentials: 'include' })).json()));
  ok('значение в хранилище совпадает с принятым приёмником, версия выросла на 1', shown.value === rotBody.value && shown.version === rotV0 + 1 && rotBody.version === rotV0 + 1);
  await recv('/status/500', 'POST');
  await page.click('[data-testid="rotation-run"]'); await page.waitForFunction(() => [...document.querySelectorAll('.toast')].some(t => /HTTP 500/.test(t.innerText)), { timeout: 10000 }); await sleep(500);
  const shown2 = await page.evaluate(async () => (await (await fetch('/api/secrets/1', { credentials: 'include' })).json()));
  ok('отказ приёмника (500): видимая ошибка, значение и версия не изменились', shown2.value === rotBody.value && shown2.version === rotV0 + 1 && /ошибка/.test(await page.$eval('[data-testid="rotation-row"]', e => e.innerText)));
  await recv('/status/200', 'POST');
  await clickText('.sidebar button', /^Ротация$/); await page.waitForSelector('[data-testid="rotation-status"]', { timeout: 8000 }); await sleep(300);
  const rotPage = await page.$eval('.page', e => e.innerText);
  ok('страница «Ротация»: расписание активно (ключ сервера есть), строка db-password с HTTP-приёмником и ошибкой последнего запуска', /Расписание активно/.test(rotPage) && /db-password/.test(rotPage) && /HTTP-приёмник/.test(rotPage) && /HTTP 500/.test(rotPage));
  // ── webhooks / audit / health ──────────────────────────────────────────
  await clickText('.sidebar button', /^Вебхуки$/); await waitText(/Вебхуков нет/, 8000); ok('страница вебхуков: пустое состояние', true);
  await clickText('.sidebar button', /^Журнал$/); await page.waitForSelector('.table', { timeout: 8000 });
  const audit = await text();
  ok('журнал содержит auth:unlock, secret:create, token:create, share:create', ['auth:unlock', 'secret:create', 'token:create', 'share'].every(a => audit.includes(a)), audit.slice(0, 200));
  await clickText('.chip', /Вход/); await sleep(300);
  ok('фильтр журнала «Вход» оставляет только auth:*', (await page.$$eval('.table .badge', xs => xs.map(x => x.innerText))).every(a => a.startsWith('auth')));
  await clickText('.sidebar button', /^Здоровье$/); await waitText(/Оценка/, 15000); await sleep(300);
  const health = await text();
  ok('отчёт о здоровье: оценка, слабый пароль найден (api-key = «password»)', /Оценка/.test(health) && /Слабые пароли/.test(health) && /api-key/.test(health));
  ok('отчёт: секрет со сроком в «истекают»', /Истекают в ближайшие 30 дней/.test(health) && /db-password/.test(health));
  await page.screenshot({ path: `${OUT}/health.png` });
  // ── import from another manager (0.29): a Bitwarden export through the settings page ──
  const bwPath = `${OUT}/bitwarden-e2e.json`;
  writeFileSync(bwPath, JSON.stringify({ encrypted: false, folders: [{ id: 'f1', name: 'Imported-BW' }], items: [
    { id: '1', type: 1, name: 'bw-gitlab', folderId: 'f1', favorite: true, notes: 'from bitwarden', login: { username: 'ci-bot', password: 'bw-pass-1', totp: 'otpauth://totp/GitLab?secret=JBSWY3DPEHPK3PXP', uris: [{ uri: 'https://gitlab.example.com' }] } },
    { id: '2', type: 2, name: 'bw-note', folderId: 'f1', notes: 'the note is the secret', secureNote: { type: 0 } },
    { id: '3', type: 1, name: 'bw-steam', folderId: 'f1', login: { username: 'g', password: 'p', totp: 'steam://ABC' } } ] }));
  await page.goto(URL + '/#/settings', { waitUntil: 'networkidle0' }); await waitText(/Импорт из другого менеджера/, 8000);
  await page.click('[data-testid="import-other"]'); await page.waitForSelector('[data-testid="import-sources"]', { timeout: 5000 });
  ok('импорт: источники плитками (15 вариантов: + .kdbx, Dashlane, Keeper, Passbolt), без select', (await page.$$('[data-testid="import-sources"] .tile')).length === 15 && (await page.$$('.drawer select')).length === 0);
  await page.click('[data-testid="import-src-bitwarden"]');
  const fileEl = await page.$('[data-testid="import-file"]'); await fileEl.uploadFile(bwPath);
  await page.click('[data-testid="import-preview-btn"]'); await page.waitForSelector('[data-testid="import-stats"]', { timeout: 10000 });
  const stats = await page.$eval('[data-testid="import-stats"]', e => e.innerText);
  ok('предпросмотр: формат bitwarden, 3 секрета в 1 папке, 1 с TOTP, предупреждение про Steam', /bitwarden/.test(stats) && /3 секретов в 1 папках/.test(stats) && /с TOTP 1/.test(stats) && /Steam/.test(await page.$eval('[data-testid="import-preview"]', e => e.innerText)));
  ok('предпросмотр показывает строки с папкой и логином', /Imported-BW/.test(await page.$eval('[data-testid="import-preview"]', e => e.innerText)) && /ci-bot/.test(await page.$eval('[data-testid="import-preview"]', e => e.innerText)));
  await page.click('[data-testid="import-go"]'); await waitText(/Импорт: создано 3 секретов, папок 1/, 10000); await sleep(600);
  ok('импорт выполнен: папка Imported-BW в сайдбаре с 3 секретами', (await page.$$eval('.sidebar .nav-item', xs => xs.map(x => x.innerText.replace(/\n/g, ' ')))).some(t => /Imported-BW\s*3/.test(t)));
  const bwSecret = (await page.evaluate(async () => (await (await fetch('/api/secrets', { credentials: 'include' })).json()))).find(x => x.name === 'bw-gitlab');
  await page.goto(URL + `/#/all/s/${bwSecret.id}`, { waitUntil: 'networkidle0' }); await page.waitForSelector('.detail', { timeout: 8000 }); await sleep(600);
  const bwCard = await page.$eval('.detail', e => e.innerText);
  ok('импортированный секрет: логин, одноразовый код и URL на карточке', /ci-bot/.test(bwCard) && /Одноразовый код/.test(bwCard) && /gitlab\.example\.com/.test(bwCard));
  const bwNote = (await page.evaluate(async () => (await (await fetch('/api/secrets', { credentials: 'include' })).json()))).find(x => x.name === 'bw-note');
  const bwNoteFull = await page.evaluate(async (id) => (await (await fetch(`/api/secrets/${id}`, { credentials: 'include' })).json()), bwNote.id);
  ok('заметка без пароля стала секретом со значением-заметкой', bwNoteFull.value === 'the note is the secret');
  // ── import a KeePass .kdbx directly (0.35): the drawer asks for the database password; a wrong one is a visible error ──
  await page.goto(URL + '/#/settings', { waitUntil: 'networkidle0' }); await waitText(/Импорт из другого менеджера/, 8000);
  await page.click('[data-testid="import-other"]'); await page.waitForSelector('[data-testid="import-sources"]', { timeout: 5000 });
  await page.click('[data-testid="import-src-kdbx"]'); await page.waitForSelector('[data-testid="import-kdbx-password"]', { timeout: 3000 });
  ok('плитка .kdbx показывает поле пароля базы и кнопку ключ-файла', /Ключ-файл/.test(await page.$eval('[data-testid="import-kdbx-box"]', e => e.innerText)));
  const kdbxEl = await page.$('[data-testid="import-file"]'); await kdbxEl.uploadFile('/aps/aps-vault/backend/tests/fixtures/kdbx/kdbx4-argon2d-aes.kdbx');
  await page.type('[data-testid="import-kdbx-password"]', 'wrong-pw'); await page.click('[data-testid="import-preview-btn"]'); await page.waitForSelector('[data-testid="import-error"]', { timeout: 15000 });
  ok('неверный пароль базы — видимая ошибка «wrong password or key file», ничего не импортировано', /wrong password or key file/.test(await page.$eval('[data-testid="import-error"]', e => e.innerText)));
  await page.click('[data-testid="import-kdbx-password"]', { clickCount: 3 }); await page.type('[data-testid="import-kdbx-password"]', 'pw-1');
  await page.click('[data-testid="import-preview-btn"]'); await page.waitForSelector('[data-testid="import-stats"]', { timeout: 20000 });
  const kstats = await page.$eval('[data-testid="import-stats"]', e => e.innerText);
  ok('предпросмотр .kdbx: формат kdbx, 3 секрета в 3 папках (Servers, Servers/Backup, корень), 1 с TOTP', /kdbx/.test(kstats) && /3 секретов в 3 папках/.test(kstats) && /с TOTP 1/.test(kstats), kstats);
  ok('предпросмотр .kdbx показывает db01 с логином postgres', /db01/.test(await page.$eval('[data-testid="import-preview"]', e => e.innerText)) && /postgres/.test(await page.$eval('[data-testid="import-preview"]', e => e.innerText)));
  await page.click('[data-testid="import-go"]'); await waitText(/Импорт: создано 3 секретов, папок 3/, 15000); await sleep(600);
  const kdb01 = (await page.evaluate(async () => (await (await fetch('/api/secrets', { credentials: 'include' })).json()))).find(x => x.name === 'db01');
  const kdb01Full = await page.evaluate(async (id) => (await (await fetch(`/api/secrets/${id}`, { credentials: 'include' })).json()), kdb01.id);
  ok('секрет из .kdbx: текущий пароль (не из истории), логин и живой одноразовый код', kdb01Full.value === 'pg-secret-v2' && kdb01Full.login === 'postgres' && /^\d{6}$/.test(kdb01Full.totp || ''));
  // ── settings: theme dark + EN ───────────────────────────────────────────
  await clickText('.sidebar button', /^Настройки$/); await waitText(/Второй фактор/, 8000);
  await clickText('.seg button', /^Тёмная$/); await sleep(300);
  ok('тема «Тёмная» применилась (data-theme=dark, тёмный фон)', await page.evaluate(() => document.documentElement.dataset.theme === 'dark' && getComputedStyle(document.body).backgroundColor.match(/\d+/g).map(Number)[0] < 40));
  await page.goto(URL + '/#/all/s/1', { waitUntil: 'networkidle0' }); await page.waitForSelector('.detail', { timeout: 8000 }); await sleep(900);
  ok('тема переживает перезагрузку', await page.evaluate(() => document.documentElement.dataset.theme === 'dark'));
  await page.screenshot({ path: `${OUT}/main.png` });
  await page.goto(URL + '/#/health', { waitUntil: 'networkidle0' }); await waitText(/Оценка/, 15000); await sleep(400); await page.screenshot({ path: `${OUT}/health-dark.png` });
  await page.goto(URL + '/#/settings', { waitUntil: 'networkidle0' }); await waitText(/Второй фактор/, 8000); await page.screenshot({ path: `${OUT}/settings.png` });
  await clickText('.seg button', /^English$/); await page.waitForNavigation({ waitUntil: 'networkidle0', timeout: 10000 }).catch(() => {}); await sleep(600);
  const en = await text();
  ok('английский интерфейс без кириллицы', !/[А-Яа-яЁё]/.test(en.replace(/clients-test|db-password|api-key|archive/g, '')), (en.match(/[^\n]*[А-Яа-яЁё][^\n]*/g) || []).slice(0, 3).join(' | '));
  await page.goto(URL + '/#/all/s/1', { waitUntil: 'networkidle0' }); await page.waitForSelector('.detail', { timeout: 8000 }); await sleep(900);
  await page.screenshot({ path: `${OUT}/main-en.png` });
  // ── mobile ─────────────────────────────────────────────────────────────
  await page.setViewport({ width: 390, height: 844, isMobile: true, hasTouch: true });
  await page.goto(URL + '/#/all', { waitUntil: 'networkidle0' }); await page.waitForSelector('.item', { timeout: 15000 }); await sleep(400);
  const sbHidden = await page.evaluate(() => getComputedStyle(document.getElementById('sidebar')).transform !== 'none');
  const allCount = (await page.evaluate(async () => (await (await fetch('/api/secrets', { credentials: 'include' })).json()))).length;
  ok('мобильный: сайдбар скрыт, список виден (все секреты)', sbHidden && (await page.$$('.item')).length === allCount && allCount >= 7, `items=${(await page.$$('.item')).length} api=${allCount}`);
  await page.click('.menu-btn'); await sleep(300);
  ok('мобильный: кнопка меню открывает сайдбар', await page.evaluate(() => document.getElementById('sidebar').classList.contains('open')));
  await page.click('.menu-btn'); await sleep(400); await page.click('.item'); await page.waitForSelector('.detail', { timeout: 8000 }); await sleep(300);
  ok('мобильный: карточка открывается на весь экран, кнопка «назад» есть', (await page.$$('.detail .menu-btn')).length === 1 && await page.evaluate(() => getComputedStyle(document.querySelector('.list-pane')).display === 'none'));
  ok('мобильный: нет горизонтальной прокрутки', await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1));
  await page.screenshot({ path: `${OUT}/mobile.png` });
  // ── lock ───────────────────────────────────────────────────────────────
  await page.setViewport({ width: 1366, height: 860 });
  await page.goto(URL + '/#/all', { waitUntil: 'networkidle0' }); await page.waitForSelector('.topbar', { timeout: 8000 });
  await clickText('.topbar button', /Lock|Заблокировать/); await page.waitForSelector('input[type=password]', { timeout: 10000 });
  ok('Lock → экран входа', true);
  const h = await (await fetch(`${URL}/api/health`)).json();
  ok('health после lock: unlocked=false', h.unlocked === false);
} catch (e) { failed++; console.log('  ✗ ИСКЛЮЧЕНИЕ после шага «' + lastOk + '»:', e.message, '| hash:', await page.evaluate(() => location.hash).catch(() => '?'));
  console.log('  диагностика:', await page.evaluate(() => JSON.stringify({ url: location.href, ready: document.readyState, overlays: document.querySelectorAll('.overlay').length, content: document.getElementById('content')?.outerHTML.slice(0, 400), route: window.state && state.route, secrets: window.state && state.secrets.length, rej: window.__rej })).catch(err => 'n/a ' + err.message)); await page.screenshot({ path: `${OUT}/failure.png` }).catch(() => {}); }
finally { await browser.close(); }
console.log(errors.length ? 'JS-ОШИБКИ: ' + JSON.stringify(errors, null, 1) : 'JS-ошибок: 0');
console.log(`ИТОГ: ${passed} ok, ${failed} fail${errors.length ? ', ' + errors.length + ' js errors' : ''}`);
if (failed || errors.length) process.exitCode = 1;
