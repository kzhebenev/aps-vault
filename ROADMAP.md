# Roadmap

What we intend to build, roughly in order. Items move to CHANGELOG.md when shipped.

## 0.5 — observability and access policy (shipped 0.5.0/0.5.1)
- [x] Syslog/SIEM forwarding of audit events (RFC 5424 over UDP/TCP, JSON or CEF payload).
- [x] Prometheus `/metrics` (token-protected).
- [x] PAM-style policies: allowed source networks and time windows per service token and for
      the human UI; denials audited and forwarded.
- [x] fail2ban: filter + jail generator on the vault's security log; `sync-bans.sh` pushes the
      vault's own lock-outs into a jail.
- [x] English UI with a language switch; Russian kept.
- [x] Browser extension configurable for any vault URL, published separately.

## 0.6 — clustering (shipped 0.6.0)
- [x] **PostgreSQL storage backend** (`VAULT_DATABASE_URL`, psycopg 3; dialect-aware migrations).
- [x] **Stateless workers**: sessions and the master-key verifier in the shared store; the master
      key wrapped into the session row under a key derived from the client's cookie — any replica
      serves any session, the database alone holds no usable key.
- [x] `/api/ready` vs `/api/health` (down vs locked); schema creation safe under concurrent start.
- [x] Reference deployment `deploy/cluster/` (two replicas, nginx LB, PostgreSQL); the
      two-node test suite; `docs/CLUSTER.md`.
- [ ] OIDC master key hand-over between replicas (today: node-local cache or env) — needs a
      shared secret the IdP does not hold; design open.

## 0.8 — key rotation (shipped 0.8.0)
- [x] Secret versions addressable by the machine API and the KV facade (`?version=N`), versions
      listing, numbered history; clients updated.

## 0.9 — machine-only secrets (shipped 0.9.0)
- [x] Secrets never shown to people: hidden in the card, history, export and share links;
      server-side generation and rotation; audited un-hide.

## Later
- Token binding to mTLS client certificates.
- Approval workflow for sensitive reads (second administrator confirms).
- Hardware-backed master key (PKCS#11 / cloud KMS) as an alternative to the password KDF.
