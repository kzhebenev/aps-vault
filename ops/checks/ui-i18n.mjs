// Headless check of the language switch and the token-policy fields.
//   node ops/checks/ui-i18n.mjs http://127.0.0.1:8186 '<master password>'
import puppeteer from '/aps/node_modules/puppeteer/lib/esm/puppeteer/puppeteer.js';
const [,, URL = 'http://127.0.0.1:8186', MASTER = ''] = process.argv;
const errors = []; const fail = (m) => { errors.push(m); };
const browser = await puppeteer.launch({
  headless: 'new', executablePath: '/usr/bin/google-chrome', pipe: true, protocolTimeout: 30000,
  args: ['--no-sandbox', '--disable-gpu', '--disable-dev-shm-usage', '--no-proxy-server', '--disable-background-networking',
         '--disable-component-update', '--disable-sync', '--host-resolver-rules=MAP *.google.com 127.0.0.1,MAP *.googleapis.com 127.0.0.1,MAP *.gstatic.com 127.0.0.1'],
});
try {
  const page = await browser.newPage();
  await page.setViewport({ width: 1280, height: 800 });
  page.on('pageerror', e => errors.push('pageerror: ' + e.message));
  page.on('console', m => { if (m.type() === 'error' && !/net::|ERR_/.test(m.text())) errors.push('console: ' + m.text()); });

  // English
  await page.goto(URL + '/?lang=en', { waitUntil: 'networkidle0', timeout: 20000 });
  await page.waitForSelector('input[type=password]', { timeout: 15000 });
  let text = await page.evaluate(() => document.body.innerText);
  console.log('EN unlock screen:', /Unlock/.test(text) && /Enter the master password/.test(text) ? 'ok' : 'FAIL → ' + text.slice(0, 120));
  if (!/Unlock/.test(text)) fail('EN unlock screen not translated');
  if (await page.evaluate(() => document.documentElement.lang) !== 'en') fail('<html lang> is not en');
  if (MASTER) {
    await page.type('input[type=password]', MASTER);
    const btn = await page.evaluateHandle(() => [...document.querySelectorAll('button')].find(b => b.innerText.trim() === 'Unlock'));
    await btn.click();
    await page.waitForFunction(() => document.body.innerText.includes('All secrets') || document.body.innerText.includes('Все секреты'), { timeout: 15000 });
    text = await page.evaluate(() => document.body.innerText);
    const low = text.toLowerCase(); const enMain = ['all secrets', 'folders', 'tokens', 'audit', 'secret'].every(w => low.includes(w));
    console.log('EN main screen:', enMain ? 'ok' : 'FAIL → ' + text.slice(0, 200));
    if (!enMain) fail('EN main screen has untranslated chrome');
    if (/[А-Яа-яЁё]/.test(text.replace(/clients-test|db-password|smtp-password|upstream-api/g, ''))) {
      const cyr = text.match(/[^\n]*[А-Яа-яЁё][^\n]*/g); console.log('остатки кириллицы в EN:', cyr); fail('Cyrillic left in EN UI: ' + cyr.slice(0, 3).join(' | '));
    }
    // tokens page → "New token" drawer: policy fields present
    const tk = await page.evaluateHandle(() => [...document.querySelectorAll('button')].find(b => b.innerText.trim() === 'Tokens'));
    await tk.click();
    await page.waitForSelector('#tok-new', { timeout: 10000 });
    await page.click('#tok-new');
    await page.waitForSelector('[data-testid="tok-cidrs"]', { timeout: 10000 });
    const ph = await page.$$eval('[data-testid="tok-cidrs"],[data-testid="tok-hours"]', xs => xs.map(i => i.placeholder));
    console.log('token policy fields:', ph);
    if (!ph[0].startsWith('Allowed networks') || !ph[1].startsWith('Allowed hours')) fail('policy placeholders not English: ' + ph.join(' | '));
    await page.screenshot({ path: '/tmp/aps-vault-tokens-en.png' });
    // language switch back to RU via the header button
    await page.keyboard.press('Escape');
    await page.evaluate(() => document.querySelector('.overlay')?.remove());
    const sw = await page.evaluateHandle(() => [...document.querySelectorAll('header button')].find(b => b.innerText.trim() === 'RU'));
    if (!sw.asElement()) fail('RU switch button not found in header');
    else {
      await Promise.all([page.waitForNavigation({ waitUntil: 'networkidle0', timeout: 15000 }), sw.click()]);
      text = await page.evaluate(() => document.body.innerText);
      console.log('after switch → RU:', text.includes('Все секреты') ? 'ok' : 'FAIL');
      if (!text.includes('Все секреты')) fail('switch to RU did not work');
      if (await page.evaluate(() => localStorage.getItem('vault_lang')) !== 'ru') fail('vault_lang not persisted');
    }
  }
} catch (e) { fail(e.message); }
finally { await browser.close(); }
console.log(errors.length ? `ОШИБКИ: ${JSON.stringify(errors, null, 1)}` : 'JS-ошибок: 0');
console.log(errors.length ? 'ИТОГ: ПРОВАЛ' : 'ИТОГ: OK');
process.exitCode = errors.length ? 1 : 0;
