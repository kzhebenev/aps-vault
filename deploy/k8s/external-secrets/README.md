# External Secrets Operator → APS Vault

See `docs/KUBERNETES.md`. Files:

- `secretstore-vault.yaml` — token Secret + `SecretStore` using ESO's **vault** provider through the HashiCorp-compatible facade (recommended)
- `externalsecret.yaml` — an `ExternalSecret` producing `app-credentials` with three keys from two vault secrets
- `clustersecretstore-webhook.yaml` — the alternative through ESO's **webhook** provider and the machine API (token Secret must carry `external-secrets.io/type: webhook`)
- `test-k3s.sh` — the real check: creates stores (good, wrong token, webhook) and ExternalSecrets in a namespace, compares the produced Kubernetes Secrets with the machine API byte for byte, asserts the wrong token yields no Secret and a visible `SecretSyncedError`

```bash
kubectl create ns demo
kubectl -n demo create secret generic aps-vault-token --from-literal=token=vlt_…
sed 's#https://vault.example.com#https://vault.YOURS#; s#devops-demo#YOUR-FOLDER#' secretstore-vault.yaml | kubectl apply -f -
kubectl apply -f externalsecret.yaml
kubectl -n demo get externalsecret app-credentials      # READY True
kubectl -n demo get secret app-credentials -o jsonpath='{.data.DB_USER}' | base64 -d
```
