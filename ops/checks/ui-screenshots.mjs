// Screenshots for docs/img: unlock screen and main screen (after unlocking through the UI).
//   node ops/checks/ui-screenshots.mjs http://127.0.0.1:8186 '<master password>' docs/img
import puppeteer from '/aps/node_modules/puppeteer/lib/esm/puppeteer/puppeteer.js';
import { mkdirSync } from 'node:fs';
const [,, URL = 'http://127.0.0.1:8186', MASTER = '', OUT = 'docs/img'] = process.argv;
mkdirSync(OUT, { recursive: true });
const errors = [];
const browser = await puppeteer.launch({
  headless: 'new', executablePath: '/usr/bin/google-chrome', pipe: true, protocolTimeout: 30000,
  args: ['--no-sandbox', '--disable-gpu', '--disable-dev-shm-usage', '--no-proxy-server', '--disable-background-networking',
         '--disable-component-update', '--disable-sync', '--host-resolver-rules=MAP *.google.com 127.0.0.1,MAP *.googleapis.com 127.0.0.1,MAP *.gstatic.com 127.0.0.1'],
});
try {
  const page = await browser.newPage();
  await page.setViewport({ width: 1280, height: 800, deviceScaleFactor: 1 });
  page.on('pageerror', e => errors.push(e.message));
  page.on('console', m => { if (m.type() === 'error' && !/net::|ERR_/.test(m.text())) errors.push(m.text()); });
  page.on('response', r => { if (r.url().endsWith('/tailwind.css') && r.status() !== 200) errors.push('tailwind.css ' + r.status()); });
  await page.goto(URL.includes('?') ? URL : URL + '/', { waitUntil: 'networkidle0', timeout: 20000 });
  await page.waitForSelector('input[type=password]', { timeout: 15000 });
  // styled? the body background comes from the inline <style>; a Tailwind class must resolve too
  const styled = await page.evaluate(() => { const b = document.querySelector('button'); return b && getComputedStyle(b).borderRadius !== '0px'; });
  console.log('Tailwind применён (скруглённая кнопка):', styled);
  if (!styled) errors.push('Tailwind bundle did not style the button');
  await page.screenshot({ path: `${OUT}/unlock.png` });
  if (MASTER) {
    await page.type('input[type=password]', MASTER);
    const btn = await page.evaluateHandle(() => [...document.querySelectorAll('button')].find(b => /Разблок|Unlock|Войти/i.test(b.innerText)));
    await btn.click();
    await page.waitForFunction(() => !document.querySelector('input[type=password]') || document.body.innerText.includes('clients-test'), { timeout: 15000 });
    await new Promise(r => setTimeout(r, 800));
    const text = await page.evaluate(() => document.body.innerText);
    console.log('главный экран содержит папку clients-test:', text.includes('clients-test'));
    if (!text.includes('clients-test')) errors.push('main screen did not render folders');
    await page.screenshot({ path: `${OUT}/main.png` });
  }
} catch (e) { errors.push(e.message); }
finally { await browser.close(); }
console.log(errors.length ? `ОШИБКИ: ${JSON.stringify(errors)}` : 'JS-ошибок: 0');
if (errors.length) process.exitCode = 1;
