# Access policies (where from, when)

Two layers, both optional. Empty = unrestricted.

## Service tokens

Set at creation (UI → Tokens → new, or `POST /api/tokens`):

| Field | Example | Meaning |
|---|---|---|
| `allowed_cidrs` | `10.20.0.0/16 203.0.113.7` | the token works only from these networks (bare address = /32) |
| `allowed_hours` | `Mon-Fri 08:00-20:00; Sat 10:00-14:00` | the token works only inside these windows, evaluated in `VAULT_TIMEZONE` |

Rules for `allowed_hours`: windows separated by `;`, each `<days> <HH:MM>-<HH:MM>`, days as a
range (`Mon-Fri`) or list (`Sat,Sun`) or omitted (= every day), `24:00` allowed as end,
windows may wrap midnight (`22:00-06:00`). Malformed specs are rejected with 422 at creation.

A denied call returns **403** `access policy: source … not in allowed networks` /
`access policy: outside allowed hours`, is audited as `m:auth:policy_denied` with the reason,
forwarded to the SIEM (CEF severity 8) and written to the fail2ban log as `kind=policy`.
A stolen token used from somewhere else therefore shows up immediately.

The client address is what the backend sees through the trusted proxy chain
(`VAULT_PROXY_HOPS`); test with `GET /api/v1/m/health` from the service host and compare with
the `ip` in `GET /api/audit`.

## Human UI

Global, from the environment:

```
VAULT_UI_ALLOWED_CIDRS=10.0.0.0/8 203.0.113.7
VAULT_UI_ALLOWED_HOURS=Mon-Fri 07:00-22:00
VAULT_TIMEZONE=Europe/Moscow
```

Checked at unlock, at OIDC login and **on every authenticated request** — an open session
stops working the moment the policy no longer matches (laptop leaves the office network,
the working day ends). Denials are audited as `auth:policy_denied`.

The machine API is not affected by the UI policy; tokens have their own.

## Typical setups

- **Production service** — token with `allowed_cidrs` = the service subnet, no hours.
- **CI runner** — token with the runner's egress address and `Mon-Fri 06:00-22:00`.
- **Contractor** — UI policy to office hours; a separate read-only token with a short
  `expires_days` for anything they automate.
- **Break-glass** — a second administrator keeps the recovery code offline; the UI policy
  can be lifted by changing the environment and restarting, which is itself audited by the
  platform.

## Binding a token to a client certificate (mTLS, 0.11)

A token can be limited to one or more client certificates. The TLS-terminating proxy does
the verification; APS Vault only trusts the fingerprint it forwards — and only when the
request really comes from a trusted proxy (`VAULT_TRUSTED_PROXIES`), so a client cannot claim
a certificate by setting the header itself.

nginx in front of the vault:

```nginx
ssl_client_certificate /etc/nginx/client-ca.pem;   # CA that issued the clients' certificates
ssl_verify_client optional;                         # tokens without a binding keep working
location / {
    if ($ssl_client_verify != "SUCCESS") { set $cert_fp ""; }
    if ($ssl_client_verify  = "SUCCESS") { set $cert_fp $ssl_client_fingerprint; }   # SHA-1 hex
    proxy_set_header X-Client-Cert-Fingerprint $cert_fp;
    proxy_pass http://vault;
}
```

Then in the token editor put the fingerprint(s): `openssl x509 -in client.pem -noout -fingerprint -sha1`
(SHA-256 is accepted too; colons and case do not matter). Behaviour:

| token binding | certificate presented | result |
|---|---|---|
| none | any / none | allowed (as before) |
| set | matching, via a trusted proxy | allowed |
| set | other, none, or header from an untrusted peer | 403 `access policy`, audit `m:auth:policy_denied`, security log `policy … cert` |

Header name: `VAULT_CLIENT_CERT_HEADER` (default `X-Client-Cert-Fingerprint`). Do not set it to
a header your proxy passes through from clients unchanged.
