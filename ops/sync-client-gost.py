#!/usr/bin/env python3
"""Regenerate clients/python/aps_vault/gost.py from backend/gost.py + backend/gostec.py — the
Python client vendors the server's GOST primitives verbatim; test_python_client.py fails when
the two drift. Usage: python3 ops/sync-client-gost.py [--check]"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
HEADER = '''"""GOST primitives for the Python client's sealed-delivery envelope (0.19) — a verbatim copy of
backend/gost.py + backend/gostec.py (test_python_client.py checks they stay identical).
Needs the MIT `gostcrypto` package for Streebog: pip install 'aps-vault[gost]'."""
'''


def render() -> str:
    g = (ROOT / "backend" / "gost.py").read_text()
    e = (ROOT / "backend" / "gostec.py").read_text()
    g_body = g[g.find("from __future__"):]
    e_body = e[e.find("import os") + len("import os\n"):].replace("    from gost import streebog256\n", "")
    return HEADER + g_body + "\n\n# ── GOST R 34.10-2012 curve and VKO (backend/gostec.py) ──\n" + e_body


if __name__ == "__main__":
    target = ROOT / "clients" / "python" / "aps_vault" / "gost.py"
    text = render()
    if "--check" in sys.argv:
        sys.exit(0 if target.read_text() == text else 1)
    target.write_text(text)
    print(f"written {target}")
