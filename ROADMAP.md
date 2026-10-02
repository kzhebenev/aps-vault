# Roadmap

What we intend to build, roughly in order. Items move to CHANGELOG.md when shipped.

## 0.5 — observability and access policy (in progress)
- [x] Syslog/SIEM forwarding of audit events (RFC 5424 over UDP/TCP, JSON or CEF payload).
- [x] Prometheus `/metrics` (token-protected).
- [x] PAM-style policies: allowed source networks and time windows per service token and for
      the human UI; denials audited and forwarded.
- [x] fail2ban: filter + jail generator on the vault's security log; `sync-bans.sh` pushes the
      vault's own lock-outs into a jail.
- [x] English UI with a language switch; Russian kept.
- [x] Browser extension configurable for any vault URL, published separately.

## 0.6 — clustering
- [ ] **PostgreSQL storage backend** (SQLAlchemy already; add migrations) so several vault
      instances can share one database.
- [ ] **Stateless workers**: sessions, failed-attempt counters and the wrapped master key
      moved from process memory into the shared store (master key kept wrapped under a
      per-instance key, released on unlock) — multiple replicas behind a load balancer.
- [ ] Health/readiness endpoints that distinguish "locked" from "down"; rolling restarts.
- [ ] Reference deployment next to a clustered application platform: vault replicas use the
      platform's PostgreSQL cluster, machine API behind the same load balancer.

## Later
- Unwrap-only ("machine-only") secrets that are never shown in the UI or exports.
- Token binding to mTLS client certificates.
- Secret versions addressable by the machine API (`?version=N`) for key rotation.
- Approval workflow for sensitive reads (second administrator confirms).
- Hardware-backed master key (PKCS#11 / cloud KMS) as an alternative to the password KDF.
