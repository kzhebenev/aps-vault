# APS Vault on Nomad

`aps-vault.nomad.hcl` runs the backend and the frontend as two tasks of one group on a bridge network:
the frontend publishes port 8087 and proxies `/api/` to the backend on `127.0.0.1:8086` inside the
group; nothing else can reach the backend. The init token and the server key come from a **Nomad
variable** rendered into the task's environment by a template — they are not in the job file.

```bash
nomad var put nomad/jobs/aps-vault init_token="$(openssl rand -hex 24)" sso_unlock_key="$(openssl rand -base64 32)"
# on the client: client { host_volume "aps-vault-data" { path = "/srv/aps-vault" } }
nomad job run examples/nomad/aps-vault.nomad.hcl
nomad job status aps-vault
```

SQLite keeps the job at `count = 1` on the node with the host volume; for several backends use
PostgreSQL (`VAULT_DATABASE_URL`) and `docs/CLUSTER.md`.

The file is HCL-formatted and syntax-checked (`tofu fmt -check`); a live Nomad cluster was not part of
the verification — the job is the compose file translated to Nomad semantics.
