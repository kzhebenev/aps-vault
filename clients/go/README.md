# APS Vault — Go client

Standard library only, **Go 1.24+** (`crypto/mlkem` for the post-quantum envelope). Zero third-party dependencies.

```go
v, err := vault.New("https://vault.example.com", os.Getenv("VAULT_TOKEN"))
pw, err := v.Get(ctx, "db-password")
```

Values are cached (default 5 min) and served stale when the vault is unreachable — for at most
`Options.MaxStale` after the fetch (default 24h, negative = no limit; 0.41.1); 429/5xx/network errors
are retried with 1s/2s/4s back-off. Nothing is logged.

## Sealed delivery

A token bound to the application's public key receives values encrypted to that key; the client decrypts
in-process when `Options.ClientPrivateKey` (or `VAULT_CLIENT_KEY`) holds the matching private key.
Envelopes, selected by the key the token carries:

| Envelope | Key pair | Private / public key |
|---|---|---|
| `X25519-HKDF-SHA256-AES256GCM` | `GenerateKeyPair` | 32 / 32 bytes |
| `P256-HKDF-SHA256-AES256GCM` (0.22, TPM / PKCS#11 via `KeyProvider`) | `GenerateP256KeyPair` | 32 / 65 bytes |
| `VKO-GOSTR3410-2012-256-KDFTREE-KUZNYECHIK-MGM` (0.19) | `GenerateGostKeyPair` | 32 / 64 bytes |
| `X25519MLKEM768-HKDF-SHA256-AES256GCM` (0.27, post-quantum hybrid) | `GeneratePqcKeyPair` | 96 / 1216 bytes |

### Post-quantum hybrid (0.27)

X25519 + ML-KEM-768 (FIPS 203). The private key is the X25519 scalar (32) followed by the ML-KEM-768
seed `d‖z` (64); the public key is the X25519 point (32) followed by the ML-KEM-768 encapsulation key
(1184). `PqcPublicFromPrivate` recomputes the public key from the private one. The vault performs an
ephemeral X25519 exchange and an ML-KEM encapsulation; the AES-256-GCM key is
`HKDF-SHA256(ss_x25519 ‖ ss_mlkem, info = "aps-vault/sealed-pqc/v1" ‖ epk ‖ kem)` with the secret name as
AAD, so both primitives must be broken to read a value. Enrol with `EnrollWith(ctx, url, code, name, "pqc", nil)`.

## Tests

The tests read `../fixtures/*.json` (server-produced envelopes), so run them with the whole `clients`
directory present:

```sh
cd clients/go && gofmt -l . && go vet ./... && go test ./...
```
