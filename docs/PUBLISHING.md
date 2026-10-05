# Publishing the clients (0.28)

The release pipeline (`.github/workflows/release.yml`) runs on every `v*` tag and does everything
that needs no stored secret on its own: a GitHub Release with the Python sdist/wheel, the npm
tarball, the Java jar, source and image SBOMs (SPDX) and Sigstore signatures for every asset;
backend and frontend images on `ghcr.io/kzhebenev/aps-vault/{backend,frontend}:<version>`, signed
with Sigstore keyless (the signing identity is the workflow itself). Go needs nothing: the Go
proxy serves `github.com/aps-vault/aps-vault/clients/go` from the tag.

Three registries need an account that only the maintainer can create — the steps below take about
fifteen minutes in total. None of them hands a token to anyone: PyPI and npm trust the workflow
through OIDC, Maven Central gets a scoped token kept in the repository's secrets.

## 1. PyPI — `aps-vault` (trusted publishing, no token)

1. https://pypi.org/account/register/ — e-mail, password, confirm the e-mail, enable 2FA (an
   authenticator app; PyPI requires it for publishing).
2. https://pypi.org/manage/account/publishing/ → **Add a new pending publisher**:
   PyPI project name `aps-vault`, owner `kzhebenev`, repository `aps-vault`, workflow
   `release.yml`, environment `pypi`.
3. In GitHub: repository → Settings → Environments → create `pypi` (no secrets needed).

The next `v*` tag publishes `pip install aps-vault`. Until step 2 is done the PyPI step fails and
the rest of the release still happens.

## 2. npm — `@aps-vault/client` (trusted publishing with provenance)

1. https://www.npmjs.com/signup — account, confirm the e-mail, enable 2FA.
2. Create the organisation `aps-vault` (free for public packages) — the scope of the package.
3. **First publish by hand** (npm lets you configure trusted publishing only for an existing
   package): on a machine with Node 22 and 2FA at hand,
   ```bash
   cd clients/node && npm ci && npm run build && npm publish --access public
   ```
4. Package page → Settings → **Trusted publishing** → GitHub Actions: owner `kzhebenev`,
   repository `aps-vault`, workflow `release.yml`, environment `npm`.
5. GitHub: Settings → Environments → create `npm`.

From then on every tag publishes with provenance (`npm view @aps-vault/client` shows the
attestation).

## 3. Maven Central — `io.github.kzhebenev:aps-vault-client`

1. https://central.sonatype.com → **Sign in with GitHub**. The namespace `io.github.kzhebenev` is
   verified automatically from the login (that is why the groupId is `io.github.kzhebenev`, while
   the Java package stays `io.apsvault`).
2. Account → **Generate User Token** → copy username and password.
3. GitHub → Settings → Secrets and variables → Actions: `CENTRAL_USERNAME`, `CENTRAL_PASSWORD`,
   `GPG_PRIVATE_KEY` (ASCII-armoured private key — generated for the project and stored in the
   vault folder `release-signing`, see below), `GPG_PASSPHRASE`.
4. Publish the public key so Central can verify the signatures:
   `gpg --keyserver keyserver.ubuntu.com --send-keys <fingerprint>` (the fingerprint is in the
   vault next to the key).

The `java` job then runs `mvn -P release deploy` on every tag; Central publishes automatically
(`autoPublish`) and the artifact appears in search within an hour.

## 4. Chrome Web Store — the browser extension

The extension lives in its own repository (`aps-vault-extension`). One-time: a Google account,
https://chrome.google.com/webstore/devconsole, the $5 registration fee, then **New item** → upload
the zip of the extension, fill in the listing (description, screenshots, privacy: the extension
talks only to the vault URL the user enters). Review takes a few days. Automated uploads through
the Web Store API can be added afterwards (OAuth client in the Google Cloud console).

## 4a. Terraform Registry / OpenTofu Registry — `aps-vault/apsvault` (0.33)

Both registries list providers **from a dedicated GitHub repository** named `terraform-provider-apsvault`
whose releases carry `terraform-provider-apsvault_<v>_<os>_<arch>.zip`, `…_SHA256SUMS` and a GPG
signature `…_SHA256SUMS.sig` plus `terraform-registry-manifest.json`. Our release job already builds the
zips and the SHA256SUMS (job *terraform provider binaries*); what is missing is the maintainer's side:
1. a GitHub repository `kzhebenev/terraform-provider-apsvault` (the registry reads only that name
   pattern) — a mirror of `clients/terraform` with its own tags `vX.Y.Z`;
2. a GPG key registered at registry.terraform.io (Settings → Signing keys) and its private half in that
   repository's secrets (`GPG_PRIVATE_KEY`, `GPG_PASSPHRASE` — the Maven key can be reused);
3. "Publish" once on registry.terraform.io; OpenTofu's registry picks providers up through a pull
   request to `opentofu/registry` (`providers/a/aps-vault.json`).
Until then: filesystem mirror or `dev_overrides` (`clients/terraform/README.md`).

## 5. GitHub side (once)

- Settings → Actions → General → Workflow permissions: **Read and write** (the release job
  creates the Release; `packages: write` pushes images).
- Packages: after the first release make `ghcr.io/kzhebenev/aps-vault/backend` and `frontend`
  public (Package settings → Change visibility) so `docker pull` needs no login.

## Verifying what the pipeline produced

```bash
# a release asset
cosign verify-blob --bundle aps_vault-0.28.0-py3-none-any.whl.sigstore.json \
  --certificate-identity-regexp 'https://github.com/kzhebenev/aps-vault/.github/workflows/release.yml@refs/tags/v.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com aps_vault-0.28.0-py3-none-any.whl
# an image
cosign verify ghcr.io/kzhebenev/aps-vault/backend:0.28.0 \
  --certificate-identity-regexp 'https://github.com/kzhebenev/aps-vault/.github/workflows/release.yml@refs/tags/v.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

The SBOMs (`sbom-source.spdx.json`, `sbom-backend-image.spdx.json`) list every dependency of the
server, the clients and the backend image for your vulnerability scanner.

**SLSA provenance (0.36).** Every release asset and both images also carry a build-provenance
attestation (in-toto statement, SLSA v1, signed through Sigstore by `actions/attest-build-provenance`,
GitHub-hosted runner → SLSA Build Level 3) and the backend image an SBOM attestation. They live in
GitHub's attestation store and, for the images, next to the image in the registry:

```bash
gh attestation verify aps_vault-0.38.2-py3-none-any.whl --owner kzhebenev          # a release asset
gh attestation verify oci://ghcr.io/kzhebenev/aps-vault/backend:0.38.2 --owner kzhebenev
gh attestation verify oci://ghcr.io/kzhebenev/aps-vault/backend:0.38.2 --owner kzhebenev --predicate-type https://spdx.dev/Document/v2.3
cosign verify-attestation ghcr.io/kzhebenev/aps-vault/backend:0.38.2 --type slsaprovenance1 \
  --certificate-identity-regexp 'https://github.com/kzhebenev/aps-vault/.github/workflows/release.yml@refs/tags/v.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```
`gh attestation verify` checks the signature, that the attestation was made by this repository's
workflow (`--owner kzhebenev` → any repository of the owner; add `--repo kzhebenev/aps-vault` to pin) and
that the subject digest matches the file or image you hold.

## What was and was not verified

Locally: the Python sdist/wheel build and `twine check`, the npm tarball contents, the Maven
build with the new POM (sources and javadoc jars), the workflow files with `actionlint`. The
publishing steps themselves run only inside GitHub Actions with the maintainer's accounts; they
are written to fail soft (`continue-on-error`) until the accounts exist, so a tag never blocks
the GitHub Release.
