# APS Vault on Docker Swarm

`stack.yml` runs the two images from ghcr.io as a stack: the backend pinned to the node that holds the
data volume (SQLite — one replica), two frontend replicas behind the ingress port, the init token and the
server key as **Swarm secrets** (the backend reads `VAULT_INIT_TOKEN_FILE` / `VAULT_SSO_UNLOCK_KEY_FILE`).
The backend publishes no port; only the frontend's nginx reaches it on the overlay network.

```bash
docker swarm init
printf '%s' "$(openssl rand -hex 24)"    | docker secret create aps_vault_init_token -
printf '%s' "$(openssl rand -base64 32)" | docker secret create aps_vault_sso_unlock_key -
docker node update --label-add aps_vault.data=true $(docker node ls -q | head -1)
docker stack deploy -c examples/docker-swarm/stack.yml aps-vault
docker stack services aps-vault
```

For more than one backend replica switch the store to PostgreSQL (`VAULT_DATABASE_URL`), remove the
placement constraint and read `docs/CLUSTER.md` — every replica needs the same `VAULT_SSO_UNLOCK_KEY`
/ `VAULT_ROTATION_KEY`. Put a TLS-terminating proxy (Traefik, nginx) in front of port 8087.

Checked with `docker compose -f stack.yml config` (schema) — a live Swarm was not part of the
verification; the stack is the single-node compose file translated to Swarm semantics.
