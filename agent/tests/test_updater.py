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
if a[:1] == ["inspect"]:                                   # docker inspect -f {{.Config.Hostname}} <id>
    print(st.get("container_hostname", "backendhost")); sys.exit(0)
if a[:4] == ["run", "--rm", "--entrypoint", "cat"]:      # the release's stock compose file from the new updater image
    sp = st.get("stock_compose_file")
    print(open(sp).read() if sp else "", end=""); sys.exit(0)
if a and a[0] == "compose" and "config" in a:             # docker compose config -q: invalid when the file says so
    cf = a[a.index("-f") + 1]
    sys.exit(1 if "BROKEN" in open(cf).read() else 0)
if a and a[0] == "compose" and "ps" in a:                  # the project's running backend (none if the project is wrong)
    if st["running"] and st.get("project_ok", True):
        print("c0ffee" + "0" * 58)
    sys.exit(0)
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
                    return self._send(200, {"version": st["running"], "db": "ok", "node": st.get("node", "backendhost")}) if st["running"] else self._send(502, {})
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
    return [next(x for x in c if x in ("pull", "stop", "up")) for c in calls if c[0] == "compose" and {"pull", "stop", "up"} & set(c)]


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


@pytest.mark.parametrize("why, state", [("the project has no running backend (COMPOSE_PROJECT_NAME missing)", {"project_ok": False}),
                                        ("the project's backend is not the container that answers as the vault", {"container_hostname": "someoneelse"})])
def test_wrong_compose_project_is_refused_before_anything_stops(world, why, state):
    """0.41.2 (found live on 06.10): a stand started with `-p name` but no COMPOSE_PROJECT_NAME in .env — the agent
    stopped a project that did not exist and later restored the data under the running backend."""
    world["set"](**state)
    reps = _run(world, "1.1.0")
    assert reps[-1]["state"] == "failed" and "nothing changed" in reps[-1]["step"], (why, reps[-1])
    assert "COMPOSE_PROJECT_NAME" in reps[-1]["log"], reps[-1]["log"]
    assert _compose_verbs(world["calls_list"]()) == ["pull"], "pulled, then refused — nothing stopped, nothing started"
    assert world["version"]() == "1.0.0" and (world["data"] / "vault.db").read_text() == "original\n"
    assert not (world["inst"] / "backups").exists(), "no backup taken of a vault the agent does not control"


def test_restore_refuses_while_the_vault_still_answers(world, tmp_path):
    """0.41.2: the second line of defence — data is never replaced under a live process."""
    import tarfile
    arc = tmp_path / "copy.tar.gz"
    with tarfile.open(arc, "w:gz") as t:
        t.add(world["data"], arcname=".")
    (world["data"] / "vault.db").write_text("live\n")
    with pytest.raises(updater.Failed, match="still answers"):
        updater.Agent().restore(str(arc))                          # the fake vault is running 1.0.0
    assert (world["data"] / "vault.db").read_text() == "live\n"
    world["set"](running=None)
    updater.Agent().restore(str(arc))                              # stopped: restored
    assert (world["data"] / "vault.db").read_text() == "original\n"


# ── 0.41.3: the installation's compose file follows the release ──────────────────────────────────────────────────
def _old_stock_text():
    """The compose file of 0.38.0–0.40.x (curl healthcheck), kept as a fixture: its sha256 is in compose-history.txt."""
    return open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures", "compose-0.38.yml"), encoding="utf-8").read()


def _stock_text():
    return open(updater.STOCK_COMPOSE, encoding="utf-8").read()


def test_stock_compose_in_the_agent_is_the_release_file_and_in_history():
    root = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..")
    assert _stock_text() == open(os.path.join(root, "deploy", "images", "docker-compose.yml"), encoding="utf-8").read(), \
        "agent/stock-compose.yml must equal deploy/images/docker-compose.yml (cp it)"
    import hashlib
    assert hashlib.sha256(_stock_text().encode()).hexdigest() in updater.compose_history()
    assert hashlib.sha256(_old_stock_text().encode()).hexdigest() in updater.compose_history()


def test_unedited_old_compose_is_replaced_by_the_release_file(world, tmp_path):
    stock = tmp_path / "stock.yml"; stock.write_text(_stock_text())
    world["set"](stock_compose_file=str(stock))
    (world["inst"] / "docker-compose.yml").write_text(_old_stock_text())
    reps = _run(world, "1.1.0")
    assert reps[-1]["state"] == "done", reps[-1]
    assert (world["inst"] / "docker-compose.yml").read_text() == _stock_text()
    assert (world["inst"] / "docker-compose.yml.before-update").read_text() == _old_stock_text()
    assert "unedited compose file of an earlier release" in "".join(r["log"] for r in reps)
    assert '"curl"' not in (world["inst"] / "docker-compose.yml").read_text()


def test_edited_compose_keeps_edits_only_the_curl_healthcheck_migrates(world, tmp_path):
    stock = tmp_path / "stock.yml"; stock.write_text(_stock_text())
    world["set"](stock_compose_file=str(stock))
    edited = _old_stock_text().replace("restart: unless-stopped", "restart: always  # my edit", 1)
    (world["inst"] / "docker-compose.yml").write_text(edited)
    reps = _run(world, "1.1.0")
    now = (world["inst"] / "docker-compose.yml").read_text()
    assert reps[-1]["state"] == "done" and "# my edit" in now, "hand edits survive"
    assert '"curl"' not in now and "urllib.request.urlopen('http://localhost:8086/api/health'" in now
    assert "only the curl healthcheck migrated" in "".join(r["log"] for r in reps)


def test_invalid_compose_result_is_put_back_and_the_update_refused(world, tmp_path):
    stock = tmp_path / "stock.yml"; stock.write_text(_stock_text() + "\n# BROKEN\n")
    world["set"](stock_compose_file=str(stock))
    (world["inst"] / "docker-compose.yml").write_text(_old_stock_text())
    reps = _run(world, "1.1.0")
    assert reps[-1]["state"] == "failed" and "nothing changed" in reps[-1]["step"], reps[-1]
    assert (world["inst"] / "docker-compose.yml").read_text() == _old_stock_text(), "the previous file is back"
    assert _compose_verbs(world["calls_list"]()) == ["pull"] and world["version"]() == "1.0.0"


def test_rollback_restores_the_compose_file_too(world, tmp_path):
    stock = tmp_path / "stock.yml"; stock.write_text(_stock_text())
    world["set"](stock_compose_file=str(stock), broken=["1.1.0"])
    (world["inst"] / "docker-compose.yml").write_text(_old_stock_text())
    reps = _run(world, "1.1.0")
    assert reps[-1]["step"] == "rolled back to 1.0.0", reps[-1]
    assert (world["inst"] / "docker-compose.yml").read_text() == _old_stock_text()


def test_handover_from_the_new_image_fixes_a_compose_an_older_agent_left(world):
    """An agent ≤0.41.2 updates images only; the handover helper (new image) then migrates the compose file and
    recreates backend+frontend once more before replacing the agent."""
    (world["inst"] / "docker-compose.yml").write_text(_old_stock_text())
    assert updater.handover_main() == 0
    assert (world["inst"] / "docker-compose.yml").read_text() == _stock_text()
    ups = [c for c in world["calls_list"]() if c[0] == "compose" and "up" in c]
    assert ups[0][-2:] == ["backend", "frontend"] and ups[-1][-1] == "updater", ups
