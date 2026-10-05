#!/usr/bin/env python3
"""APS Vault update agent (0.38) — carries out "update to X" requested from Settings → Updates.

Runs next to an installation made from the release images (deploy/images/: docker compose, `VAULT_VERSION` in .env).
It holds the Docker socket, so it trusts nothing it is told: the vault only says *which* version the owner asked for.
Before touching anything the agent checks on its own that

  1. X is a published release (not a draft or pre-release) in the channel it reads itself (VAULT_UPDATE_CHANNEL),
  2. X is newer than what runs (no downgrades — migrations only go forward),
  3. every image (backend, frontend, updater) of X carries the Sigstore signature of the project's release workflow
     for tag vX (cosign keyless; the identity is fixed), and the image it pulled is exactly the signed digest.

Then: stop the backend, back up the data volume (SQLite installs), switch VAULT_VERSION, start, wait until /api/health
answers with X. If X does not come up healthy, the agent puts back the old .env and the backup and starts the old
version. The agent replaces itself last, after it reported the result.

Standard library only. Configuration (environment):
  VAULT_UPDATE_AGENT_TOKEN   required, the same value the vault has
  VAULT_INSTALL_DIR          required, the directory with docker-compose.yml and .env (mounted at the same path)
  VAULT_URL                  default http://backend:8086
  VAULT_UPDATE_CHANNEL       default the project's GitHub Releases API
  VAULT_UPDATE_VERIFY        cosign (default) | off — off is for an air-gapped mirror you verify yourself
  VAULT_UPDATE_IMAGE_REPO    default ghcr.io/kzhebenev/aps-vault (a fork sets its own, with VAULT_UPDATE_IDENTITY)
  VAULT_UPDATE_IDENTITY      default https://github.com/kzhebenev/aps-vault/.github/workflows/release.yml@refs/tags/v{version}
  VAULT_UPDATE_POLL_SEC (15), VAULT_UPDATE_HEALTH_SEC (240), VAULT_DATA_DIR (/vault-data), AGENT_ID (host name)
"""
from __future__ import annotations

import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tarfile
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

AGENT_VERSION = "0.38.2"
ISSUER = "https://token.actions.githubusercontent.com"
SERVICES = ("backend", "frontend", "updater")


class Refused(Exception):
    """The job is not carried out; nothing was changed."""


class Failed(Exception):
    """Something went wrong after the installation was touched; a rollback follows."""


def env(name: str, default: str = "") -> str:
    return os.environ.get(name, default).strip()


def parse_version(s: str):
    m = re.fullmatch(r"v?(\d+)\.(\d+)\.(\d+)", (s or "").strip())
    return tuple(int(x) for x in m.groups()) if m else None


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


_opener = urllib.request.build_opener(_NoRedirect())


class Agent:
    def __init__(self):
        self.token = env("VAULT_UPDATE_AGENT_TOKEN")
        self.install = env("VAULT_INSTALL_DIR")
        if not self.token or not self.install:
            raise SystemExit("VAULT_UPDATE_AGENT_TOKEN and VAULT_INSTALL_DIR are required")
        self.vault = env("VAULT_URL", "http://backend:8086").rstrip("/")
        self.channel = env("VAULT_UPDATE_CHANNEL") or "https://api.github.com/repos/kzhebenev/aps-vault/releases?per_page=30"
        self.verify = env("VAULT_UPDATE_VERIFY", "cosign").lower()
        self.repo = env("VAULT_UPDATE_IMAGE_REPO", "ghcr.io/kzhebenev/aps-vault").rstrip("/")
        self.identity = env("VAULT_UPDATE_IDENTITY", "https://github.com/kzhebenev/aps-vault/.github/workflows/release.yml@refs/tags/v{version}")
        self.poll = max(2, int(env("VAULT_UPDATE_POLL_SEC", "15") or 15))
        self.health_sec = max(10, int(env("VAULT_UPDATE_HEALTH_SEC", "240") or 240))
        self.data_dir = env("VAULT_DATA_DIR", "/vault-data")
        self.agent_id = env("AGENT_ID") or socket.gethostname()[:64]
        self.docker = env("DOCKER_BIN", "docker")
        self.cosign = env("COSIGN_BIN", "cosign")
        self.allow_http = env("VAULT_UPDATE_ALLOW_HTTP") == "1"     # tests and a plain-http mirror inside the company
        self.env_file = os.path.join(self.install, ".env")
        self.compose_file = os.path.join(self.install, "docker-compose.yml")
        self.log_lines: list[str] = []

    # ── small helpers ─────────────────────────────────────────────────────
    def say(self, msg: str) -> None:
        line = f"{datetime.now(timezone.utc).strftime('%H:%M:%S')} {msg}"
        print(line, flush=True)
        self.log_lines.append(line)

    def read_env(self) -> dict:
        out = {}
        with open(self.env_file, encoding="utf-8") as f:
            for line in f:
                k, sep, v = line.rstrip("\n").partition("=")
                if sep and not k.strip().startswith("#"):
                    out[k.strip()] = v.strip().strip('"').strip("'")
        return out

    def current(self) -> str:
        return self.read_env().get("VAULT_VERSION", "")

    def set_version(self, version: str) -> None:
        with open(self.env_file, encoding="utf-8") as f:
            lines = f.read().splitlines()
        found = False
        for i, line in enumerate(lines):
            if re.match(r"^\s*VAULT_VERSION\s*=", line):
                lines[i], found = f"VAULT_VERSION={version}", True
        if not found:
            lines.append(f"VAULT_VERSION={version}")
        tmp = self.env_file + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")
        os.chmod(tmp, os.stat(self.env_file).st_mode & 0o777)
        os.replace(tmp, self.env_file)

    def run(self, *args: str, env_extra: dict | None = None, check: bool = True, timeout: int = 900) -> str:
        e = dict(os.environ, **(env_extra or {}))
        p = subprocess.run(list(args), capture_output=True, text=True, env=e, timeout=timeout)
        out = (p.stdout or "") + (p.stderr or "")
        if check and p.returncode != 0:
            raise Failed(f"{' '.join(args[:4])}… exited {p.returncode}: {out.strip()[-600:]}")
        return out

    def compose(self, *args: str, version: str | None = None, check: bool = True) -> str:
        extra = {"VAULT_VERSION": version} if version else None
        return self.run(self.docker, "compose", "--project-directory", self.install, "-f", self.compose_file,
                        "--env-file", self.env_file, *args, env_extra=extra, check=check)

    def http(self, method: str, url: str, body: dict | None = None, auth: bool = True, timeout: int = 15):
        data = json.dumps(body).encode() if body is not None else None
        h = {"Accept": "application/json", "User-Agent": f"aps-vault-updater/{AGENT_VERSION}"}
        if data is not None:
            h["Content-Type"] = "application/json"
        if auth:
            h["Authorization"] = f"Bearer {self.token}"
        req = urllib.request.Request(url, data=data, method=method, headers=h)
        with _opener.open(req, timeout=timeout) as r:
            raw = r.read(4 * 1024 * 1024)
        return json.loads(raw.decode("utf-8")) if raw else None

    # ── the vault ─────────────────────────────────────────────────────────
    def heartbeat(self) -> dict | None:
        q = urllib.parse.urlencode({"agent_id": self.agent_id, "mode": "images", "agent_version": AGENT_VERSION,
                                    "current": self.current(), "verify": self.verify, "host": socket.gethostname()[:128]})
        return (self.http("GET", f"{self.vault}/api/agent/update?{q}") or {}).get("job")

    def report(self, job_id: int, state: str, step: str, final: bool = False) -> None:
        """Running reports are best effort (the backend is down for part of the update); the final one is retried."""
        body = {"state": state, "step": step[:64], "log": "\n".join(self.log_lines)[-19000:]}
        url = f"{self.vault}/api/agent/update/{job_id}?agent_id={urllib.parse.quote(self.agent_id)}"
        for attempt in range(60 if final else 1):
            try:
                self.http("POST", url, body)
                self.log_lines = []
                return
            except Exception as e:                       # noqa: BLE001 — the vault may be restarting
                if not final:
                    return
                if attempt == 0:
                    print(f"report not delivered yet ({e}); retrying", flush=True)
                time.sleep(5)

    def health(self) -> dict | None:
        try:
            return self.http("GET", f"{self.vault}/api/health", auth=False, timeout=5)
        except Exception:                                # noqa: BLE001
            return None

    def wait_healthy(self, version: str, seconds: int) -> bool:
        deadline = time.time() + seconds
        while time.time() < deadline:
            h = self.health()
            if h and h.get("version") == version and h.get("db") == "ok":
                return True
            time.sleep(3)
        return False

    # ── the checks the vault cannot fake ──────────────────────────────────
    def channel_release(self, version: str) -> dict:
        u = urllib.parse.urlparse(self.channel)
        if u.scheme != "https" and not (u.scheme == "http" and self.allow_http):
            raise Refused("the update channel must be https://")
        req = urllib.request.Request(self.channel, headers={"Accept": "application/vnd.github+json", "User-Agent": f"aps-vault-updater/{AGENT_VERSION}"})
        try:
            with _opener.open(req, timeout=20) as r:
                data = json.loads(r.read(4 * 1024 * 1024).decode("utf-8"))
        except Exception as e:                           # noqa: BLE001
            raise Refused(f"the update channel did not answer: {str(e)[:200]}")
        for rel in data if isinstance(data, list) else []:
            if isinstance(rel, dict) and str(rel.get("tag_name", "")).lstrip("v") == version:
                if rel.get("draft") or rel.get("prerelease"):
                    raise Refused(f"{version} is a draft or pre-release in the channel")
                return rel
        raise Refused(f"{version} is not a published release in the channel {u.hostname}")

    def verify_signature(self, ref: str, version: str) -> str:
        """cosign keyless verification against the release workflow of tag v<version>; returns the signed digest."""
        identity = self.identity.replace("{version}", version)
        p = subprocess.run([self.cosign, "verify", ref, "--certificate-identity", identity, "--certificate-oidc-issuer", ISSUER,
                            "--output", "json"], capture_output=True, text=True, timeout=180)
        m = re.search(r'"docker-manifest-digest"\s*:\s*"(sha256:[0-9a-f]{64})"', p.stdout or "")
        if p.returncode != 0 or not m:
            raise Refused(f"signature check failed for {ref}: {((p.stderr or '') + (p.stdout or '')).strip()[-400:]}")
        return m.group(1)

    def local_digest(self, ref: str) -> str:
        out = self.run(self.docker, "image", "inspect", "--format", "{{json .RepoDigests}}", ref)
        for d in json.loads(out.strip() or "[]"):
            if "@" in d:
                return d.split("@", 1)[1]
        raise Failed(f"no registry digest for {ref} after the pull")

    # ── data ──────────────────────────────────────────────────────────────
    def backup(self, version: str) -> str | None:
        if self.read_env().get("VAULT_DATABASE_URL"):
            self.say("database: external (VAULT_DATABASE_URL) — back it up with your own tooling; the agent skips it")
            return None
        if not os.path.isdir(self.data_dir):
            raise Failed(f"data directory {self.data_dir} is not mounted into the agent")
        bdir = os.path.join(self.install, "backups")
        os.makedirs(bdir, mode=0o700, exist_ok=True)
        name = os.path.join(bdir, f"vault-data-{version}-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}.tar.gz")
        with tarfile.open(name, "w:gz") as t:
            t.add(self.data_dir, arcname=".")
        os.chmod(name, 0o600)
        olds = sorted(f for f in os.listdir(bdir) if f.startswith("vault-data-") and f.endswith(".tar.gz"))
        for f in olds[:-5]:                              # keep the last five
            os.remove(os.path.join(bdir, f))
        self.say(f"backup: {name} ({os.path.getsize(name)} bytes)")
        return name

    def restore(self, archive: str) -> None:
        for entry in os.listdir(self.data_dir):
            p = os.path.join(self.data_dir, entry)
            shutil.rmtree(p) if os.path.isdir(p) and not os.path.islink(p) else os.remove(p)
        with tarfile.open(archive, "r:gz") as t:
            t.extractall(self.data_dir, filter="tar") if sys.version_info >= (3, 12) else t.extractall(self.data_dir)  # noqa: S202 — our own archive
        self.say(f"restored the data from {archive}")

    # ── the job ───────────────────────────────────────────────────────────
    def carry_out(self, job: dict) -> None:
        jid, target = int(job["id"]), str(job["target_version"]).lstrip("v")
        self.log_lines = []
        cur = self.current()
        self.say(f"job {jid}: {cur} → {target} (agent {AGENT_VERSION}, verify={self.verify})")
        try:
            if not parse_version(target) or not parse_version(cur) or parse_version(target) <= parse_version(cur):
                raise Refused(f"{target} is not newer than the installed {cur}")
            self.channel_release(target)
            self.say(f"channel: {target} is a published release")
            refs = {s: f"{self.repo}/{s}:{target}" for s in SERVICES}
            signed = {}
            if self.verify == "cosign":
                for s, ref in refs.items():
                    signed[s] = self.verify_signature(ref, target)
                    self.say(f"signature ok: {ref} {signed[s][:19]}…")
            else:
                self.say("WARNING: signature verification is OFF (VAULT_UPDATE_VERIFY=off)")
            self.report(jid, "running", "signatures verified")
            self.compose("pull", "backend", "frontend", "updater", version=target)
            for s, ref in refs.items():
                if s in signed and self.local_digest(ref) != signed[s]:
                    raise Refused(f"the pulled {ref} is not the signed image (digest differs)")
            self.say("images pulled" + (" and match the signed digests" if signed else ""))
            self.report(jid, "running", "images pulled")
        except (Refused, Failed, subprocess.TimeoutExpired) as e:
            self.say(f"refused: {e}")
            self.report(jid, "failed", "refused — nothing changed", final=True)
            return
        # from here on the installation is touched
        env_copy = self.env_file + ".before-update"
        shutil.copy2(self.env_file, env_copy)
        archive = None
        try:
            self.compose("stop", "backend")
            archive = self.backup(cur)
            self.set_version(target)
            self.compose("up", "-d", "--no-deps", "backend", "frontend")
            self.say(f"started {target}; waiting for /api/health")
            if not self.wait_healthy(target, self.health_sec):
                raise Failed(f"{target} did not answer healthy within {self.health_sec} s")
            self.say(f"healthy on {target}")
            self.report(jid, "done", f"updated to {target}", final=True)
        except (Failed, subprocess.TimeoutExpired, OSError) as e:
            self.say(f"FAILED: {e}; rolling back to {cur}")
            ok = self.rollback(env_copy, archive, cur)
            self.report(jid, "failed", f"rolled back to {cur}" if ok else "ROLLBACK FAILED — see log", final=True)
            return
        # last: replace the agent itself. Not with `compose up updater` from in here — compose stops the old container
        # (this process) halfway and leaves the new one "Created" (found on the first live update, 0.38.0 → 0.38.2).
        # A short-lived helper from the NEW, already verified image does it from outside and exits.
        self.handover(target)

    def handover(self, version: str) -> None:
        project = os.path.basename(self.install.rstrip("/")) or "aps-vault"
        self.run(self.docker, "run", "-d", "--rm", "--name", f"{project}-updater-handover-{int(time.time())}",
                 "-v", "/var/run/docker.sock:/var/run/docker.sock", "-v", f"{self.install}:{self.install}",
                 "-e", f"VAULT_INSTALL_DIR={self.install}", f"{self.repo}/updater:{version}", "--handover", check=False)

    def rollback(self, env_copy: str, archive: str | None, version: str) -> bool:
        try:
            shutil.copy2(env_copy, self.env_file)
            self.compose("stop", "backend", check=False)
            if archive:
                self.restore(archive)
            self.compose("up", "-d", "--no-deps", "backend", "frontend")
            ok = self.wait_healthy(version, self.health_sec)
            self.say(f"rollback: {version} is " + ("healthy" if ok else "NOT healthy"))
            return ok
        except Exception as e:                           # noqa: BLE001
            self.say(f"rollback error: {e}")
            return False

    def loop(self, once: bool = False) -> None:
        print(f"aps-vault updater {AGENT_VERSION}: {self.agent_id}, install {self.install}, vault {self.vault}, verify={self.verify}", flush=True)
        while True:
            try:
                job = self.heartbeat()
                if job:
                    self.carry_out(job)
            except urllib.error.HTTPError as e:
                print(f"vault answered {e.code}: {e.read()[:200]!r}", flush=True)
            except Exception as e:                       # noqa: BLE001 — keep polling
                print(f"poll failed: {e}", flush=True)
            if once:
                return
            time.sleep(self.poll)


def handover_main() -> int:
    """Run in a throwaway container (not part of the compose project): recreate the `updater` service, then exit.
    Waits a little so the old agent finishes its last report."""
    install = env("VAULT_INSTALL_DIR")
    if not install:
        print("VAULT_INSTALL_DIR is required", flush=True)
        return 2
    time.sleep(3)
    p = subprocess.run([env("DOCKER_BIN", "docker"), "compose", "--project-directory", install, "-f", os.path.join(install, "docker-compose.yml"),
                        "--env-file", os.path.join(install, ".env"), "up", "-d", "--no-deps", "--force-recreate", "updater"],
                       capture_output=True, text=True, timeout=600)
    print((p.stdout or "") + (p.stderr or ""), flush=True)
    return p.returncode


if __name__ == "__main__":
    if "--handover" in sys.argv:
        sys.exit(handover_main())
    Agent().loop(once="--once" in sys.argv)
