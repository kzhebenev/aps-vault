// End-to-end check of the web UI in a real browser against a FRESH vault (ops/checks/e2e-stack.sh).
// Every step asserts what the user sees, not what the state says; 0 JS errors is part of the pass.
//   URL=$(ops/checks/e2e-stack.sh up); node ops/checks/ui-e2e.mjs "$URL" docs/img; ops/checks/e2e-stack.sh down
import puppeteer from '/aps/node_modules/puppeteer/lib/esm/puppeteer/puppeteer.js';
import { mkdirSync } from 'node:fs';
const [,, URL = 'http://127.0.0.1:8189', OUT = '/tmp/aps-vault-e2e-shots'] = process.argv;
mkdirSync(OUT, { recursive: true });
const MASTER = 'e2e master password 2026!';
const errors = []; let passed = 0, failed = 0;
const ok = (name, cond, extra = '') => { if (cond) { passed++; console.log('  ✓', name); } else { failed++; console.log('  ✗', name, extra); } };
const sleep = (ms) => new Promise(r => setTimeout(r, ms));
const browser = await puppeteer.launch({ headless: 'new', executablePath: '/usr/bin/google-chrome', pipe: true, protocolTimeout: 60000,
  args: ['--no-sandbox', '--disable-gpu', '--disable-dev-shm-usage', '--no-proxy-server', '--disable-background-networking', '--disable-component-update', '--disable-sync',
         '--host-resolver-rules=MAP *.google.com 127.0.0.1,MAP *.googleapis.com 127.0.0.1,MAP *.gstatic.com 127.0.0.1'] });
const page = await browser.newPage();
await page.setViewport({ width: 1366, height: 860 });
page.on('pageerror', e => errors.push('pageerror: ' + e.message));
page.on('console', m => { if (m.type() === 'error' && !/net::|ERR_|Failed to load resource/.test(m.text())) errors.push('console: ' + m.text()); });
const ctx = await browser.defaultBrowserContext(); await ctx.overridePermissions(URL, ['clipboard-read', 'clipboard-write']);
const text = () => page.evaluate(() => document.body.innerText);
const clickText = async (sel, re) => { const h = await page.evaluateHandle((sel, src) => [...document.querySelectorAll(sel)].find(b => new RegExp(src, 'i').test(b.innerText.trim())), sel, re.source); const e = h.asElement(); if (!e) throw new Error(`no element ${sel} ~ ${re}`); await e.click(); return e; };
const waitText = (re, t = 10000) => page.waitForFunction((src) => new RegExp(src, 'i').test(document.body.innerText), { timeout: t }, re.source);
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
  ok('неверный init token отклонён (видимая ошибка)', /init token mismatch/.test(await text()));
  await pw[2].click({ clickCount: 3 }); await pw[2].type('e2e-init-token');
  await clickText('button', /Инициализировать/);
  await page.waitForSelector('.codebox', { timeout: 10000 });
  const recovery = await page.$eval('.codebox', e => e.textContent.trim());
  ok('recovery-код показан (24 символа)', recovery.length === 24, recovery);
  await clickText('button', /Я записал/);
  await page.waitForSelector('input[type=password]', { timeout: 15000 }); await sleep(300);
  ok('после init — экран входа', (await page.$$('input[type=password]')).length === 1);
  // ── unlock: wrong, then right ──────────────────────────────────────────
  await page.type('input[type=password]', 'not the password at all'); await page.keyboard.press('Enter');
  await waitText(/wrong master password/, 5000); ok('неверный пароль → видимая ошибка', true);
  await typeInto('input[type=password]', MASTER); await page.keyboard.press('Enter');
  await page.waitForSelector('.sidebar', { timeout: 15000 }); await sleep(300);
  ok('вход: главный экран, пустое состояние с призывом создать папку', /Создать первую папку|Папок ещё нет/.test(await text()));
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
  await clickText('.modal .chip', /archive/); await clickText('.modal .foot button', /Переместить/); await waitText(/Перемещён/, 8000); await sleep(600);
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
  ok('страница токенов: пустое состояние', /Токенов ещё нет/.test(await text()));
  await page.click('#tok-new'); await page.waitForSelector('.drawer', { timeout: 5000 });
  await page.type('.drawer input', 'e2e-reader'); await clickText('.drawer .chip', /archive/);
  await page.type('[data-testid="tok-cidrs"]', '10.0.0.0/8 127.0.0.1 172.16.0.0/12 192.168.0.0/16');
  await clickText('.drawer .foot button', /Создать/); await page.waitForSelector('.modal .codebox', { timeout: 8000 });
  const tok = await page.$eval('.modal .codebox', e => e.textContent.trim());
  ok('токен показан один раз (vlt_…)', /^vlt_/.test(tok));
  const m = await fetch(`${URL}/api/v1/m/secret/db-password`, { headers: { Authorization: `Bearer ${tok}` } });
  ok('машинный API читает секрет этим токеном (настоящий запрос)', m.status === 200 && (await m.json()).value === 'new-value-after-edit-2026', 'HTTP ' + m.status);
  const kv = await fetch(`${URL}/v1/archive/data/db-password`, { headers: { 'X-Vault-Token': tok } });
  ok('HashiCorp-фасад тоже отвечает этим токеном', kv.status === 200);
  await clickText('.modal .foot button', /Готово/); await sleep(600);
  ok('токен в таблице с политикой CIDR', /e2e-reader/.test(await text()) && /10\.0\.0\.0\/8/.test(await text()));
  await page.screenshot({ path: `${OUT}/tokens.png` });
  // ── share link ─────────────────────────────────────────────────────────
  await page.goto(URL + '/#/all/s/1', { waitUntil: 'networkidle0' }); await page.waitForSelector('.detail', { timeout: 8000 }); await sleep(400);
  await clickText('.detail-head button', /Поделиться/); await page.waitForSelector('.modal', { timeout: 5000 });
  await clickText('.modal .foot button', /Создать ссылку/); await page.waitForSelector('.modal .codebox', { timeout: 8000 });
  const shareUrl = await page.$eval('.modal .codebox', e => e.textContent.trim());
  const sh = await fetch(shareUrl); const shBody = await sh.json().catch(() => ({}));
  ok('share-ссылка отдаёт значение без входа (настоящий запрос)', sh.status === 200 && shBody.value === 'new-value-after-edit-2026', 'HTTP ' + sh.status);
  const sh2 = await fetch(shareUrl);
  ok('второе открытие одноразовой ссылки — отказ', sh2.status >= 400);
  await page.keyboard.press('Escape');
  await clickText('.sidebar button', /^Ссылки$/); await page.waitForSelector('.page .table', { timeout: 8000 }); await sleep(200);
  const sharesTxt = await page.$eval('.page', e => e.innerText);
  ok('страница ссылок показывает использованную ссылку', /использована/.test(sharesTxt) && /1 \/ 1/.test(sharesTxt), sharesTxt.slice(0, 200));
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
  await page.goto(URL + '/#/all', { waitUntil: 'networkidle0' }); await page.waitForSelector('.item', { timeout: 8000 }); await sleep(400);
  const sbHidden = await page.evaluate(() => getComputedStyle(document.getElementById('sidebar')).transform !== 'none');
  ok('мобильный: сайдбар скрыт, список виден', sbHidden && (await page.$$('.item')).length === 2);
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
} catch (e) { failed++; console.log('  ✗ ИСКЛЮЧЕНИЕ:', e.message); await page.screenshot({ path: `${OUT}/failure.png` }).catch(() => {}); }
finally { await browser.close(); }
console.log(errors.length ? 'JS-ОШИБКИ: ' + JSON.stringify(errors, null, 1) : 'JS-ошибок: 0');
console.log(`ИТОГ: ${passed} ok, ${failed} fail${errors.length ? ', ' + errors.length + ' js errors' : ''}`);
if (failed || errors.length) process.exitCode = 1;
