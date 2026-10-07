# CI steps: GitHub Actions and GitLab CI (0.34)

A pipeline needs a database password to run migrations, an API key to publish, a TLS key to deploy. Keep
them in the vault, give the pipeline a **read-only, folder-scoped service token**, and let one step turn
secrets into environment variables for the steps that follow. One script does the work for both systems:
`clients/ci/aps-vault-ci.py` — standard library, fails closed, never prints a value except as a masking
directive, never prints the token.

Item syntax everywhere: `name[.field][:ENV]` — `field` = `value` (default) | `login` | `notes` | `totp`;
`ENV` defaults to the name in UPPER_SNAKE_CASE (`db-password` → `DB_PASSWORD`, `db-password.login` →
`DB_PASSWORD_LOGIN`). All items are read first; one missing secret means nothing is exported.

## GitHub Actions

```yaml
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: kzhebenev/aps-vault/clients/github-action@v0.34.0
        with:
          url: https://vault.example.com
          token: ${{ secrets.APS_VAULT_TOKEN }}          # a vlt_… service token, folder "ci-deploy"
          secrets: |
            db-password:DB_PASSWORD
            db-password.login:DB_USER
            deploy-key
      - run: ./migrate.sh                                 # sees DB_PASSWORD, DB_USER, DEPLOY_KEY
```

The action is a composite step: it runs the script with `--github`, which appends the variables to
`$GITHUB_ENV` (heredoc form, so multi-line values such as keys survive) and emits `::add-mask::` for
every line of every value first — the runner then redacts them from the whole job log. Output
`variables` lists what was exported. For a **sealed** token add `client_key: ${{ secrets.APS_VAULT_CLIENT_KEY }}`;
the action installs `cryptography` on demand and opens the envelope in the runner process.

Pin the action to a release tag. The token belongs in a repository or environment secret; with
environments you can require a reviewer before the deploy job even gets the token.

## GitLab CI

```yaml
include:
  - remote: 'https://raw.githubusercontent.com/kzhebenev/aps-vault/v0.41.6/clients/gitlab-ci/aps-vault.gitlab-ci.yml'

deploy:
  extends: .aps-vault-secrets
  variables:
    APS_VAULT_SECRETS: "db-password:DB_PASSWORD db-password.login:DB_USER deploy-key"
  script:
    - ./migrate.sh
```

`VAULT_URL` and `VAULT_TOKEN` are CI/CD variables (token **masked** and **protected**). The hidden job
`.aps-vault-secrets` fetches the script (pinned to the release in the URL) and `eval`s its `--export`
output in `before_script`, so the variables exist in the job's shell. The second shape in the template,
job `aps-vault-secrets`, writes a **dotenv artifact** in stage `.pre`; jobs with `needs: [aps-vault-secrets]`
receive the variables without fetching themselves (dotenv cannot carry multi-line values — the script
refuses them there and says to use `--export`).

Since 0.37 the template checks the downloaded script against `APS_VAULT_CI_SHA256` (the digest of the script
of the same release, written into the template) before running it, and installs pinned `cryptography` and
`kyber-py` versions for sealed tokens; the dotenv artifact is created with `access: none`, so it is not
downloadable from the pipeline page. If you mirror the script elsewhere, keep the digest. The GitHub action
pins its pip packages the same way, and every action in this repository's workflows is pinned by commit SHA.

GitLab masks only variables it created: values fetched by the job are **not** redacted from logs. Do not
echo them, and prefer the per-job shape so a value never leaves the job that needs it. Self-hosted
GitLab without internet: vendor `aps-vault-ci.py` into the repository and set `APS_VAULT_CI_SCRIPT` to its
path — the template then skips the download.

## Any other CI

```bash
eval "$(python3 aps-vault-ci.py --export db-password:DB_PASSWORD api-key)"
python3 aps-vault-ci.py --dotenv secrets.env db-password api-key        # KEY=value lines, mode 0600
```
`VAULT_URL`, `VAULT_TOKEN` (or `VAULT_TOKEN_FILE`), `VAULT_CLIENT_KEY` from the environment. Exit codes:
1 — vault unreachable, token refused, secret or field missing, sealed value does not open (nothing written);
2 — usage (bad variable name, a variable assigned twice, a master password instead of a token).

## Verified

`backend/tests/test_ci_fetch.py` runs the script against a live server: GitHub mode writes the heredocs
to `$GITHUB_ENV`, masks every line (multi-line key included) and prints the value nowhere else, the token
appears in no output; dotenv mode writes `KEY=value` with mode 0600 and refuses multi-line values; export
mode `eval`s in bash to the exact values; a missing secret, a wrong token, a bad variable name, a
duplicate variable, a master password, a missing field and an unreachable vault each fail with the named
reason and write nothing; a sealed token fails without the key, opens with it, and is refused with another
key. The GitHub workflow `ci.yml` job *action e2e* starts a throwaway vault on the runner, creates a folder,
secrets and tokens through the API, and runs the composite action itself — plain and sealed — then checks
the exported variables. `ops/checks/ci-templates.sh` validates both YAML files and runs the GitLab
template's `before_script` lines against a live vault.
