"""Two replicas, one database: the proof that nothing lives in process memory any more.

Two real uvicorn processes (node-a, node-b) start on the same database — SQLite file by
default, PostgreSQL when TEST_DATABASE_URL is set (run_tests.sh pg). Everything that used to
be process state is exercised across nodes: initialisation, the unlock session, lock,
recovery, lock-outs, service tokens and the KV facade. A failing assertion here is a state
leak; passing is what docs/CLUSTER.md promises IQR.
"""
import os
import socket
import subprocess
import sys
import time

import httpx
import pytest
from sqlalchemy import create_engine, text

BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MASTER = "cluster master password 2026"


def _free_port():
    s = socket.socket(); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close(); return p


def _cluster_db_url(tmp_path) -> str:
    base = os.environ.get("TEST_DATABASE_URL", "")
    if not base:
        return f"sqlite:///{tmp_path}/shared.db"
    # PostgreSQL: a database of its own, so the main suite's vault (already initialised) is not in the way
    admin = create_engine(base, isolation_level="AUTOCOMMIT")
    with admin.connect() as c:
        c.execute(text("DROP DATABASE IF EXISTS vault_cluster_test"))
        c.execute(text("CREATE DATABASE vault_cluster_test"))
    admin.dispose()
    return base.rsplit("/", 1)[0] + "/vault_cluster_test"


@pytest.fixture(scope="module")
def cluster(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("cluster")
    url = _cluster_db_url(tmp)
    env = {k: v for k, v in os.environ.items() if not k.startswith("VAULT_")}
    env.update({"VAULT_DATABASE_URL": url, "VAULT_DATA_DIR": str(tmp), "VAULT_INIT_TOKEN": "cluster-init",
                "VAULT_CIPHER": os.environ.get("VAULT_CIPHER", "aes"),      # the nodes run the suite under test (run_tests.sh gost)
                "VAULT_PUBLIC_URL": "https://vault.cluster", "VAULT_FAIL_LIMIT_PER_IP": "3",
                "VAULT_SSO_UNLOCK_KEY": "0011223344556677889900aabbccddeeff00112233445566778899aabbccddeeff"})
    procs, nodes = [], {}
    for name in ("node-a", "node-b"):
        port = _free_port()
        p = subprocess.Popen([sys.executable, "-m", "uvicorn", "main:app", "--host", "127.0.0.1", "--port", str(port),
                              "--http", "h11", "--log-level", "warning"],
                             cwd=BACKEND, env={**env, "VAULT_NODE_NAME": name},
                             stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        procs.append(p); nodes[name] = f"http://127.0.0.1:{port}"
    try:
        for name, base in nodes.items():
            deadline = time.time() + 30
            while time.time() < deadline:
                try:
                    if httpx.get(base + "/api/ready", timeout=2).status_code == 200:
                        break
                except Exception:
                    pass
                if procs[0].poll() is not None or procs[1].poll() is not None:
                    raise RuntimeError("a node died: " + (procs[0].stderr.read() or procs[1].stderr.read()).decode()[-2000:])
                time.sleep(0.2)
            else:
                raise RuntimeError(f"{name} did not become ready")
        yield {"a": nodes["node-a"], "b": nodes["node-b"], "db": url, "procs": procs}
    finally:
        for p in procs:
            if p.poll() is None:
                p.terminate()
        for p in procs:
            try:
                p.wait(timeout=10)
            except Exception:
                p.kill()


def _client(base):
    return httpx.Client(base_url=base, timeout=15)


def test_nodes_are_distinct_and_share_initialisation(cluster):
    a, b = _client(cluster["a"]), _client(cluster["b"])
    ha, hb = a.get("/api/health").json(), b.get("/api/health").json()
    assert ha["node"] == "node-a" and hb["node"] == "node-b"
    assert ha["db"] == "ok" and hb["db"] == "ok" and ha["initialized"] is False
    r = a.post("/api/init", json={"master_password": MASTER, "init_token": "cluster-init"})
    assert r.status_code == 200
    cluster["recovery"] = r.json()["recovery_code"]
    assert b.get("/api/health").json()["initialized"] is True, "init on A is visible on B"
    assert b.post("/api/init", json={"master_password": MASTER, "init_token": "cluster-init"}).status_code == 409


def test_session_from_a_is_served_by_b_and_db_holds_no_usable_key(cluster):
    a, b = _client(cluster["a"]), _client(cluster["b"])
    r = a.post("/api/auth/unlock", json={"master_password": MASTER})
    assert r.status_code == 200
    sid = r.cookies["vault_session"]; csrf = r.json()["csrf_token"]
    cookies = {"vault_session": sid, "vault_csrf": csrf}; hdr = {"X-CSRF-Token": csrf}
    cluster.update(sid=sid, csrf=csrf)
    assert b.get("/api/health", cookies=cookies).json()["unlocked"] is True
    assert b.get("/api/health").json()["unlocked"] is False, "no cookie — locked, on any node"
    assert b.get("/api/folders", cookies=cookies).status_code == 200
    # write on B, read on A — the folder key is unwrapped from the session on each node
    fid = b.post("/api/folders", json={"name": "shared"}, cookies=cookies, headers=hdr).json()["id"]
    sec = b.post("/api/secrets", json={"folder_id": fid, "name": "db-password", "value": "s3cr3t-cluster", "login": "app"},
                 cookies=cookies, headers=hdr).json()
    full = a.get(f"/api/secrets/{sec['id']}", cookies=cookies).json()
    assert full["value"] == "s3cr3t-cluster" and full["login"] == "app"
    cluster.update(fid=fid, secret_id=sec["id"])
    # the shared store knows only the hash of the cookie and a wrapped key
    eng = create_engine(cluster["db"])
    with eng.connect() as c:
        rows = c.execute(text("SELECT sid_hash, master_key_enc FROM ui_sessions")).fetchall()
    eng.dispose()
    import suite
    assert len(rows) == 1 and rows[0][0] == suite.hexdigest(sid.encode())
    assert sid.encode() not in bytes(rows[0][1]) and len(bytes(rows[0][1])) == 32 + 16


def test_lock_on_b_kills_session_on_a(cluster):
    a, b = _client(cluster["a"]), _client(cluster["b"])
    cookies = {"vault_session": cluster["sid"], "vault_csrf": cluster["csrf"]}; hdr = {"X-CSRF-Token": cluster["csrf"]}
    assert b.post("/api/auth/lock", cookies=cookies, headers=hdr).status_code == 200
    assert a.get("/api/folders", cookies=cookies).status_code == 401
    assert a.get("/api/health", cookies=cookies).json()["unlocked"] is False


def test_brute_force_budget_is_shared(cluster):
    a, b = _client(cluster["a"]), _client(cluster["b"])
    for _ in range(2):
        assert a.post("/api/auth/unlock", json={"master_password": "wrong wrong wrong!"}).status_code == 401
    assert b.post("/api/auth/unlock", json={"master_password": "wrong wrong wrong!"}).status_code == 401
    assert b.post("/api/auth/unlock", json={"master_password": MASTER}).status_code == 429, "3 failures across nodes lock the IP everywhere"
    assert a.post("/api/auth/unlock", json={"master_password": MASTER}).status_code == 429
    # clear the lock-out through the shared store, as an operator would
    eng = create_engine(cluster["db"])
    with eng.begin() as c:
        c.execute(text("DELETE FROM lockdown"))
    eng.dispose()


def test_service_token_and_kv_facade_work_on_either_node(cluster):
    a, b = _client(cluster["a"]), _client(cluster["b"])
    r = a.post("/api/auth/unlock", json={"master_password": MASTER}); assert r.status_code == 200
    cookies = {"vault_session": r.cookies["vault_session"], "vault_csrf": r.json()["csrf_token"]}; hdr = {"X-CSRF-Token": r.json()["csrf_token"]}
    tok = a.post("/api/tokens", json={"name": "svc", "folder_id": cluster["fid"]}, cookies=cookies, headers=hdr).json()["raw_token"]
    assert b.get("/api/v1/m/secret/db-password", headers={"Authorization": f"Bearer {tok}"}).json()["value"] == "s3cr3t-cluster"
    kv = b.get("/v1/shared/data/db-password", headers={"X-Vault-Token": tok}).json()
    assert kv["data"]["data"]["value"] == "s3cr3t-cluster"
    cluster.update(sid=cookies["vault_session"], csrf=hdr["X-CSRF-Token"], token=tok)


def test_sso_unlock_cell_enabled_on_a_serves_b(cluster):
    """0.10: enabling SSO unlock on node A (which needs the master password) makes node B —
    a process that never saw the password — able to open sessions for OIDC logins."""
    a, b = _client(cluster["a"]), _client(cluster["b"])
    assert b.get("/api/auth/oidc/status").json()["sso_unlock"] == "none"
    cookies = {"vault_session": cluster["sid"], "vault_csrf": cluster["csrf"]}; hdr = {"X-CSRF-Token": cluster["csrf"]}
    r = a.post("/api/auth/sso-unlock/enable", json={"master_password": MASTER}, cookies=cookies, headers=hdr)
    assert r.status_code == 200, r.text
    assert b.get("/api/auth/oidc/status").json()["sso_unlock"] == "cell"
    assert b.post("/api/auth/sso-unlock/disable", cookies=cookies, headers=hdr).status_code == 200
    assert a.get("/api/auth/oidc/status").json()["sso_unlock"] in ("node", "none")


def test_recovery_on_b_invalidates_everything_on_a(cluster):
    a, b = _client(cluster["a"]), _client(cluster["b"])
    cookies = {"vault_session": cluster["sid"], "vault_csrf": cluster["csrf"]}
    assert a.get("/api/folders", cookies=cookies).status_code == 200
    new_pw = "brand new cluster password 2026"
    r = b.post("/api/auth/recover", json={"recovery_code": cluster["recovery"], "new_master_password": new_pw})
    assert r.status_code == 200
    assert a.get("/api/folders", cookies=cookies).status_code == 401, "sessions dropped cluster-wide"
    assert a.post("/api/auth/unlock", json={"master_password": MASTER}).status_code == 401
    r = a.post("/api/auth/unlock", json={"master_password": new_pw}); assert r.status_code == 200
    c2 = {"vault_session": r.cookies["vault_session"], "vault_csrf": r.json()["csrf_token"]}
    assert b.get(f"/api/secrets/{cluster['secret_id']}", cookies=c2).json()["value"] == "s3cr3t-cluster", "data survives the rewrap"
    # tokens are independent of the master password (own key chain) — still valid after recovery
    assert a.get("/api/v1/m/secret/db-password", headers={"Authorization": f"Bearer {cluster['token']}"}).status_code == 200


def test_node_loss_does_not_take_the_service_down(cluster):
    a_proc = cluster["procs"][0]
    a_proc.terminate(); a_proc.wait(timeout=10)
    b = _client(cluster["b"])
    assert b.get("/api/ready").status_code == 200
    assert b.get("/api/v1/m/secret/db-password", headers={"Authorization": f"Bearer {cluster['token']}"}).status_code == 200
