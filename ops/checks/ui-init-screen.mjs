// Headless check of the init screen: the init-token field is present, no JS errors.
//   node ops/checks/ui-init-screen.mjs http://127.0.0.1:8186
import puppeteer from '/aps/node_modules/puppeteer/lib/esm/puppeteer/puppeteer.js';
const URL = process.argv[2] || 'http://127.0.0.1:8186';
const errors = [];
const browser = await puppeteer.launch({
  headless: 'new', executablePath: '/usr/bin/google-chrome', pipe: true, protocolTimeout: 30000,
  args: ['--no-sandbox', '--disable-gpu', '--disable-dev-shm-usage', '--no-proxy-server', '--disable-background-networking',
         '--disable-component-update', '--disable-sync', '--disable-features=OptimizationHints,Translate,SafeBrowsing',
         '--host-resolver-rules=MAP *.google.com 127.0.0.1,MAP *.googleapis.com 127.0.0.1,MAP *.gstatic.com 127.0.0.1,MAP cdn.tailwindcss.com 127.0.0.1'],
});
try {
  const page = await browser.newPage();
  page.on('pageerror', e => errors.push(e.message));
  page.on('console', m => { if (m.type() === 'error' && !/net::|ERR_|tailwindcss/.test(m.text())) errors.push(m.text()); });
  await page.goto(URL + '/', { waitUntil: 'domcontentloaded', timeout: 20000 });
  await page.waitForSelector('input[type=password]', { timeout: 15000 });
  const placeholders = await page.$$eval('input', xs => xs.map(i => i.placeholder));
  console.log('поля:', placeholders);
  const hasInit = placeholders.some(p => /init token/i.test(p));
  const btn = await page.$$eval('button', bs => bs.map(b => b.innerText.trim()).filter(Boolean));
  console.log('кнопки:', btn);
  await page.screenshot({ path: '/tmp/aps-vault-init.png' });
  if (!hasInit) { console.error('FAIL: нет поля init token'); process.exitCode = 1; }
} catch (e) { console.error('FAIL:', e.message); process.exitCode = 1; }
finally { await browser.close(); }
console.log(errors.length ? `JS-ошибки: ${JSON.stringify(errors)}` : 'JS-ошибок: 0');
if (errors.length) process.exitCode = 1;
console.log(process.exitCode ? 'ИТОГ: ПРОВАЛ' : 'ИТОГ: OK');
