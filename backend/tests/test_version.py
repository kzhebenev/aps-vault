"""The version the API reports (main.VERSION) must equal the VERSION file at the repository root.
0.30.1 shipped with main.VERSION still at 0.30.0: a host product that pins the vault by version
(ValoDrive's VAULT_VERSION) saw a mismatch in /api/health."""
import pathlib

import main


def test_api_version_equals_version_file():
    root = pathlib.Path(__file__).resolve().parents[2] / "VERSION"
    assert main.VERSION == root.read_text().strip()
