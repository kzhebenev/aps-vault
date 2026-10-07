// node examples/node/app.mjs  (after `npm run build` in clients/node)
import { Vault, VaultError } from '../../clients/node/dist/index.js';

const vault = Vault.fromEnv();                 // VAULT_URL + VAULT_TOKEN
try {
  const db = await vault.getFull('db-password');
  const smtp = await vault.get('smtp-password');
  console.log(`connecting as ${db.login ?? 'app'}; smtp password length ${smtp.length}`);
} catch (e) {
  if (e instanceof VaultError) console.error(`vault refused: HTTP ${e.status} — ${e.message}`);
  else console.error(`vault unreachable: ${e.message}`);
  process.exit(1);
}
