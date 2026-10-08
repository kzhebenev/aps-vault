# aps-vault-client (Java)

Dependency-free client for the APS Vault machine API (service tokens). Java 11+, one jar, nothing else.

```java
VaultClient v = new VaultClient("https://vault.example.com", System.getenv("VAULT_TOKEN"));   // or VaultClient.fromEnv()
String dbPassword = v.get("db-password");
VaultClient.Secret smtp = v.getFull("smtp");          // value, login, notes, totp (per token grants)
v.put("db-password", "new-value", "app", "", "");     // token needs can_write
```

- `get` / `getFull` are cached (`cacheTtl`, default 5 min); while the vault is unreachable a stale cached value is
  returned (`failOpenCache`) — for at most 24 hours after it was fetched, `withMaxStale(Duration)` changes it,
  `withMaxStale(null)` = no limit (0.41.1) — the first fetch still fails loudly. 429/5xx/network errors are retried with 1 s, 2 s, 4 s.
- `totp(name)` is never served from cache; `list()`, `health()` return the raw JSON.
- `VaultException` carries the HTTP status and the server's `detail`. Nothing is logged.

Build: `mvn package` (the pom has no dependencies), or simply `javac src/main/java/io/apsvault/*.java`.
Test (no framework, plain `main`): `javac -d /tmp/out src/main/java/io/apsvault/*.java src/test/java/io/apsvault/*.java && java -cp /tmp/out io.apsvault.VaultClientTest`
from `clients/java` (the tests read `../fixtures`). `test-softhsm.sh` runs it in Docker including the PKCS#11 part.

## Sealed delivery

A token bound to this application's public key gets values encrypted to that key; the client decrypts in-process.
Pass the private key (base64) to the constructor or set `VAULT_CLIENT_KEY`. The envelope's `alg` picks the algorithm:

| envelope | key pair | private string | public (bind the token to it) | runs on |
|---|---|---|---|---|
| X25519-HKDF-SHA256-AES256GCM | `generateKeyPair()` | 32 bytes | 32 bytes | Java 11+ |
| VKO-GOSTR3410-2012-256-KDFTREE-KUZNYECHIK-MGM | `generateGostKeyPair()` | 32 bytes | 64 bytes X‖Y | Java 11+ (pure Java, `Gost`) |
| P256-HKDF-SHA256-AES256GCM (hardware keys) | `generateP256KeyPair()` or a PKCS#11 key via `withKeyProvider` | 97 bytes scalar‖point | 65 bytes `0x04‖X‖Y` | Java 11+ |
| X25519MLKEM768-HKDF-SHA256-AES256GCM (post-quantum hybrid, 0.27) | `generatePqcKeyPair()` | 96 bytes X25519 sk ‖ ML-KEM seed | 1216 bytes X25519 pk ‖ ML-KEM ek | **Java 24+** |

Node enrolment: `VaultClient.enroll(url, code, name, "x25519" | "gost" | "p256" | "pqc")` makes the pair, redeems the
one-time code and returns `{token, privateKey, publicKey, tokenName, folderName}`.

### Post-quantum hybrid (0.27)

The hybrid envelope combines an ephemeral X25519 exchange with an ML-KEM-768 (FIPS 203) encapsulation; both shared
secrets go into HKDF-SHA256 (`info = "aps-vault/sealed-pqc/v1" ‖ epk ‖ kem`) and the value is sealed with AES-256-GCM,
AAD = secret name. It stays secret unless *both* X25519 and ML-KEM are broken.

- Opening needs the JDK's `javax.crypto.KEM` with `"ML-KEM"`, which exists from **Java 24**. The client calls it by
  reflection, so the jar still compiles and runs on Java 11–23; there only the hybrid envelope fails, with
  `the post-quantum envelope needs Java 24+ (ML-KEM)`. Every other envelope stays Java 11+.
- The private string is the same 96 bytes every APS Vault client uses (X25519 sk ‖ ML-KEM seed d‖z); the JDK imports
  the seed directly (its ML-KEM private key PKCS#8 is the FIPS 203 seed form).
- `pqcPublicFromPrivate(privateB64)` recomputes the 1216-byte public key. The JDK offers no seed → public derivation,
  so the ML-KEM encapsulation key is derived by this client's own FIPS 203 KeyGen (`MlKem`, plain Java, works on any
  version; checked against the server fixture and against the JDK's own keys in `generatePqcKeyPair()`).
