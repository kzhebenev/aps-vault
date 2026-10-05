"""The update agent against a fake vault, a fake channel, a fake docker and a fake cosign.

The fakes behave like the real tools where it matters: `docker compose up` starts whatever VAULT_VERSION the .env
names (and "migrates" the data directory), `docker image inspect` reports the digest the registry gave, cosign
exits non-zero for an unsigned image. Run: python3 -m pytest agent/tests -q"""
import json
import os
import stat
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import updater  # noqa: E402

SIGNED = "sha256:" + "a" * 64
OTHER = "sha256:" + "b" * 64

FAKE_DOCKER = r'''#!/usr/bin/env python3
import json, os, sys
st_path = os.environ["FAKE_STATE"]
st = json.load(open(st_path))
open(os.environ["FAKE_CALLS"], "a").write(json.dumps(sys.argv[1:]) + "\n")
a = sys.argv[1:]
if a[:2] == ["image", "inspect"]:
    print(json.dumps([a[-1].rsplit(":", 1)[0] + "@" + st["pulled_digest"]])); sys.exit(0)
if a and a[0] == "compose":
    if "pull" in a and st.get("pull_fails"):
        print("pull failed", file=sys.stderr); sys.exit(1)
    if "up" in a and "backend" in a:
        env = dict(l.strip().split("=", 1) for l in open(a[a.index("--env-file") + 1]) if "=" in l and not l.startswith("#"))
        v = env["VAULT_VERSION"]
        st["running"] = None if v in st.get("broken", []) else v
        if v != st["installed_before"]:
            open(os.path.join(os.environ["FAKE_DATA"], "vault.db"), "a").write("migrated-to-" + v + "\n")
    if "stop" in a:
        st["running"] = None
    json.dump(st, open(st_path, "w"))
sys.exit(0)
'''

FAKE_COSIGN = r'''#!/usr/bin/env python3
import json, os, sys
st = json.load(open(os.environ["FAKE_STATE"]))
open(os.environ["FAKE_CALLS"], "a").write(json.dumps(["cosign"] + sys.argv[1:]) + "\n")
ref = sys.argv[2]; ident = sys.argv[sys.argv.index("--certificate-identity") + 1]
if not st.get("cosign_ok", True) or not ident.endswith("@refs/tags/v" + ref.rsplit(":", 1)[1]):
    print("Error: no matching signatures", file=sys.stderr); sys.exit(1)
print(json.dumps([{"critical": {"image": {"docker-manifest-digest": st["signed_digest"]}}}]))
'''


class Vault:
    """Fake vault + channel on one port: /api/health, the agent API, /releases."""

    def __init__(self, state_path):
        self.state_path, self.jobs, self.reports, self.releases = state_path, [], [], []
        vault = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a): pass

            def _send(self, code, obj):
                b = json.dumps(obj).encode()
                self.send_response(code); self.send_header("Content-Type", "application/json"); self.send_header("Content-Length", str(len(b)))
                self.end_headers(); self.wfile.write(b)

            def do_GET(self):
                if self.path.startswith("/api/health"):
                    st = json.load(open(vault.state_path))
                    return self._send(200, {"version": st["running"], "db": "ok"}) if st["running"] else self._send(502, {})
                if self.path.startswith("/releases"):
                    return self._send(200, vault.releases)
                if self.path.startswith("/api/agent/update"):
                    if self.headers.get("Authorization") != "Bearer tok":
                        return self._send(401, {"detail": "invalid agent token"})
                    return self._send(200, {"job": vault.jobs.pop(0) if vault.jobs else None})
                self._send(404, {})

            def do_POST(self):
                n = int(self.headers.get("Content-Length", 0))
                vault.reports.append(json.loads(self.rfile.read(n)))
                self._send(200, {})

        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.srv.server_port}"


@pytest.fixture
def world(tmp_path, monkeypatch):
    inst, data = tmp_path / "install", tmp_path / "data"
    inst.mkdir(); data.mkdir()
    (inst / "docker-compose.yml").write_text("name: aps-vault\n")
    (inst / ".env").write_text("# install\nVAULT_VERSION=1.0.0\nVAULT_INIT_TOKEN=x\n")
    os.chmod(inst / ".env", 0o600)
    (data / "vault.db").write_text("original\n")
    state = tmp_path / "state.json"
    state.write_text(json.dumps({"running": "1.0.0", "installed_before": "1.0.0", "pulled_digest": SIGNED, "signed_digest": SIGNED}))
    calls = tmp_path / "calls.log"; calls.write_text("")
    for name, body in (("docker", FAKE_DOCKER), ("cosign", FAKE_COSIGN)):
        p = tmp_path / name; p.write_text(body); p.chmod(p.stat().st_mode | stat.S_IEXEC)
    v = Vault(str(state))
    v.releases = [{"tag_name": "v1.1.0", "draft": False, "prerelease": False}, {"tag_name": "v1.0.0", "draft": False, "prerelease": False},
                  {"tag_name": "v2.0.0-rc1", "draft": False, "prerelease": True}, {"tag_name": "v3.0.0", "draft": False, "prerelease": True}]
    for k, val in {"VAULT_UPDATE_AGENT_TOKEN": "tok", "VAULT_INSTALL_DIR": str(inst), "VAULT_URL": v.url,
                   "VAULT_UPDATE_CHANNEL": v.url + "/releases", "VAULT_UPDATE_ALLOW_HTTP": "1", "VAULT_DATA_DIR": str(data),
                   "DOCKER_BIN": str(tmp_path / "docker"), "COSIGN_BIN": str(tmp_path / "cosign"), "FAKE_STATE": str(state),
                   "FAKE_CALLS": str(calls), "FAKE_DATA": str(data), "VAULT_UPDATE_HEALTH_SEC": "10", "AGENT_ID": "test-agent"}.items():
        monkeypatch.setenv(k, val)
    monkeypatch.setattr(updater.time, "sleep", lambda s: None)
    return {"inst": inst, "data": data, "state": state, "calls": calls, "vault": v,
            "set": lambda **kw: state.write_text(json.dumps({**json.loads(state.read_text()), **kw})),
            "calls_list": lambda: [json.loads(l) for l in calls.read_text().splitlines()],
            "version": lambda: updater.Agent().current()}


def _run(world, target):
    world["vault"].jobs.append({"id": 7, "target_version": target})
    updater.Agent().loop(once=True)
    return world["vault"].reports


def _compose_verbs(calls):
    return [next(x for x in c if x in ("pull", "stop", "up")) for c in calls if c[0] == "compose"]


def test_update_happy_path_in_the_right_order(world):
    reps = _run(world, "1.1.0")
    assert reps[-1]["state"] == "done" and "updated to 1.1.0" in reps[-1]["step"], reps
    assert world["version"]() == "1.1.0"
    calls = world["calls_list"]()
    cos = [c for c in calls if c[0] == "cosign"]
    assert [c[2] for c in cos] == [f"ghcr.io/kzhebenev/aps-vault/{s}:1.1.0" for s in ("backend", "frontend", "updater")]
    assert all(c[c.index("--certificate-identity") + 1] == "https://github.com/kzhebenev/aps-vault/.github/workflows/release.yml@refs/tags/v1.1.0" for c in cos)
    assert _compose_verbs(calls) == ["pull", "stop", "up"], "pull while running → stop → start new"
    # the agent is replaced last, from OUTSIDE its own container: a helper from the new (verified) image
    assert calls[-1][:3] == ["run", "-d", "--rm"] and calls[-1][-2:] == ["ghcr.io/kzhebenev/aps-vault/updater:1.1.0", "--handover"], calls[-1]
    assert f"{world['inst']}:{world['inst']}" in calls[-1]
    backups = os.listdir(world["inst"] / "backups")
    assert len(backups) == 1 and backups[0].startswith("vault-data-1.0.0-")
    assert oct(os.stat(world["inst"] / "backups" / backups[0]).st_mode & 0o777) == "0o600"
    assert oct(os.stat(world["inst"] / ".env").st_mode & 0o777) == "0o600", ".env keeps its permissions"
    assert "VAULT_INIT_TOKEN=x" in (world["inst"] / ".env").read_text(), "other settings untouched"


@pytest.mark.parametrize("target, why", [("1.0.0", "not newer"), ("0.9.0", "not newer"), ("1.2.0", "not a published release"),
                                         ("2.0.0-rc1", "not newer"), ("3.0.0", "pre-release"), ("latest", "not newer")])
def test_refused_jobs_change_nothing(world, target, why):
    reps = _run(world, target)
    assert reps[-1]["state"] == "failed" and "nothing changed" in reps[-1]["step"] and why in reps[-1]["log"], reps[-1]
    assert world["version"]() == "1.0.0" and not [c for c in world["calls_list"]() if c[0] == "compose"]
    assert (world["data"] / "vault.db").read_text() == "original\n"


def test_unsigned_or_swapped_image_is_refused_before_anything_stops(world):
    world["set"](cosign_ok=False)
    reps = _run(world, "1.1.0")
    assert reps[-1]["state"] == "failed" and "signature check failed" in reps[-1]["log"]
    assert not [c for c in world["calls_list"]() if c[0] == "compose"], "no pull, no stop"
    world["set"](cosign_ok=True, pulled_digest=OTHER)                # the registry served something else than was signed
    world["calls"].write_text("")
    reps = _run(world, "1.1.0")
    assert reps[-1]["state"] == "failed" and "not the signed image" in reps[-1]["log"]
    assert _compose_verbs(world["calls_list"]()) == ["pull"], "pulled, compared, refused — the running vault was never stopped"
    assert world["version"]() == "1.0.0"


def test_a_version_that_does_not_come_up_is_rolled_back_with_its_data(world):
    world["set"](broken=["1.1.0"])
    reps = _run(world, "1.1.0")
    assert reps[-1]["state"] == "failed" and reps[-1]["step"] == "rolled back to 1.0.0", reps[-1]
    assert world["version"]() == "1.0.0"
    assert (world["data"] / "vault.db").read_text() == "original\n", "the data the new version touched is restored"
    assert json.loads(world["state"].read_text())["running"] == "1.0.0"
    assert not [c for c in world["calls_list"]() if "--handover" in c], "a failed update does not replace the agent"


def test_external_database_is_not_backed_up_by_the_agent(world):
    env = world["inst"] / ".env"
    env.write_text(env.read_text() + "VAULT_DATABASE_URL=postgresql+psycopg://v:v@db/v\n")
    reps = _run(world, "1.1.0")
    assert reps[-1]["state"] == "done" and "back it up with your own tooling" in "".join(r["log"] for r in reps)
    assert not (world["inst"] / "backups").exists()


def test_signature_check_off_is_said_out_loud(world, monkeypatch):
    monkeypatch.setenv("VAULT_UPDATE_VERIFY", "off")
    reps = _run(world, "1.1.0")
    assert reps[-1]["state"] == "done" and "signature verification is OFF" in "".join(r["log"] for r in reps)
    assert not [c for c in world["calls_list"]() if c[0] == "cosign"]


def test_channel_must_be_https_and_the_agent_needs_its_token(world, monkeypatch):
    monkeypatch.setenv("VAULT_UPDATE_ALLOW_HTTP", "0")
    reps = _run(world, "1.1.0")
    assert reps[-1]["state"] == "failed" and "must be https" in reps[-1]["log"]
    monkeypatch.setenv("VAULT_UPDATE_AGENT_TOKEN", "wrong")
    world["vault"].reports.clear(); world["vault"].jobs.append({"id": 8, "target_version": "1.1.0"})
    updater.Agent().loop(once=True)                                   # 401: logged, nothing done, no crash
    assert world["vault"].reports == [] and world["version"]() == "1.0.0"


def test_handover_recreates_the_updater_service_from_outside(world, monkeypatch):
    """--handover (run in a helper container) recreates exactly the updater service of this installation."""
    monkeypatch.setattr(updater.time, "sleep", lambda s: None)
    assert updater.handover_main() == 0
    last = world["calls_list"]()[-1]
    assert last[0] == "compose" and last[-5:] == ["up", "-d", "--no-deps", "--force-recreate", "updater"], last
    assert last[-1] == "updater" and "--force-recreate" in last and last[last.index("--project-directory") + 1] == str(world["inst"])
