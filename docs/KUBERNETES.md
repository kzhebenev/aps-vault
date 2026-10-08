# Kubernetes: External Secrets Operator (0.25)

Applications in a cluster read Kubernetes Secrets; the vault holds the truth. The bridge is
the [External Secrets Operator](https://external-secrets.io) (ESO): it polls the vault with a
service token and keeps a Kubernetes Secret in sync. No APS-specific controller is needed —
ESO already speaks two of our dialects.

```
   ESO (in the cluster)  ──token──▶  APS Vault            ──▶ Kubernetes Secret  ──▶ pod (env / file)
   vault provider        GET /v1/<folder>/data/<name>      app-credentials        DB_PASSWORD=…
   webhook provider      GET /api/v1/m/secret/<name>
```

## Option 1 — ESO's `vault` provider through the HashiCorp-compatible facade (recommended)

APS Vault answers the KV v2 calls HashiCorp Vault and Deckhouse Stronghold answer
(`docs/COMPATIBILITY.md`), so ESO's standard `vault` provider works unchanged:

```yaml
apiVersion: external-secrets.io/v1
kind: SecretStore
metadata: {name: aps-vault, namespace: demo}
spec:
  provider:
    vault:
      server: "https://vault.example.com"
      path: "devops-demo"            # the folder the token is scoped to  (= KV mount)
      version: "v2"
      auth:
        tokenSecretRef: {name: aps-vault-token, key: token}
```

```yaml
apiVersion: external-secrets.io/v1
kind: ExternalSecret
metadata: {name: app-credentials, namespace: demo}
spec:
  refreshInterval: 15m
  secretStoreRef: {name: aps-vault, kind: SecretStore}
  target: {name: app-credentials, creationPolicy: Owner}
  data:
    - secretKey: DB_PASSWORD
      remoteRef: {key: db-password, property: value}
    - secretKey: DB_USER
      remoteRef: {key: db-password, property: login}
```

`remoteRef.key` is the secret name, `property` one of `value`, `login`, `notes`, `totp` (what
the token is allowed to read). ESO validates the store with `auth/token/lookup-self`; the
facade reports `expire_time` and `ttl` like HashiCorp does, so a token with an expiry shows
as such and a wrong token makes the store `InvalidProviderConfig` with the 403 in its status.
Moving to Stronghold or HashiCorp later means changing `server` and the token — the
manifests stay.

Complete files: `deploy/k8s/external-secrets/secretstore-vault.yaml`, `externalsecret.yaml`.

## Option 2 — ESO's `webhook` provider against the machine API

For an ESO build without the vault provider, or when you want the machine API's exact
semantics:

```yaml
provider:
  webhook:
    url: "https://vault.example.com/api/v1/m/secret/{{ .remoteRef.key }}"
    headers: {Authorization: "Bearer {{ .auth.token }}"}
    secrets: [{name: auth, secretRef: {name: aps-vault-token, key: token}}]
    result: {jsonPath: "$.{{ .remoteRef.property }}"}
```

ESO lets the webhook provider read only Secrets labelled `external-secrets.io/type: webhook`
— put that label on the token Secret or the ExternalSecret stays in
`SecretSyncedError`. Complete file: `clustersecretstore-webhook.yaml` (a `ClusterSecretStore`
for the whole cluster, token Secret in ESO's namespace).

## What to keep in mind

- **A Kubernetes Secret is base64, not encryption.** The value now lives in etcd and in every
  pod that mounts it. Turn on etcd encryption at rest and RBAC on Secrets; the vault's audit
  log shows ESO's reads, not what happens after.
- **Sealed tokens do not fit.** ESO cannot unseal (`docs/SEALED.md`): use a plain token for ESO
  and bind it instead — read-only, one folder, `allowed_cidrs` = the cluster's egress
  addresses, an expiry, mTLS fingerprint if the cluster egress proxy presents a certificate
  (`docs/ACCESS-POLICIES.md`).
- **Rotation.** When the vault rotates a secret (`docs/ROTATION.md`), the Kubernetes Secret
  follows within `refreshInterval`; pods still have to re-read it — a reloader, a rolling
  restart, or an application that watches the mounted file. The vault's `secret:update`
  webhook (`rotated: true`) can trigger that restart.
- **One token per store.** A token sees one folder; one `SecretStore` per folder is the
  natural layout. Several stores may share one token Secret.

## Verified

`deploy/k8s/external-secrets/test-k3s.sh` against a real cluster: k3s v1.31 in Docker, ESO
v2.11.0 from its release manifest, the live vault over the internet. Both providers produced
Kubernetes Secrets whose bytes equal the machine API's answer for the same token (value and
login); a store with a wrong token never became Ready and its ExternalSecret reported
`SecretSyncedError` with the 403 from `lookup-self`; the good store validated through
`lookup-self`. Two things the real run taught us, now fixed: the facade's `lookup-self` lacked
`expire_time` (ESO: "no expiration time found in response") and tokens with an expiry made
the machine API answer 500 (naive/aware datetime comparison) — both in 0.25.0.

```bash
# a throwaway cluster on a Docker host
docker run -d --privileged --name k3s --tmpfs /run --tmpfs /var/run -p 127.0.0.1:6443:6443 rancher/k3s:v1.31.4-k3s1 server --disable traefik --disable servicelb --disable metrics-server
curl -sL https://github.com/external-secrets/external-secrets/releases/download/v2.11.0/external-secrets.yaml | docker exec -i k3s kubectl apply --server-side -f -
KUBECTL="docker exec -i k3s kubectl" VAULT_URL=https://vault.example.com VAULT_TOKEN=vlt_… deploy/k8s/external-secrets/test-k3s.sh <folder> <secret>
```
