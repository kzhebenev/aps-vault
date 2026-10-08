"""0.41: security/vex/backend.openvex.json — every statement is a reasoned not_affected for a package the generator knows."""
import json
import os
import runpy

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def test_vex_statements_are_reasoned_and_limited_to_known_packages():
    doc = json.load(open(os.path.join(ROOT, "security", "vex", "backend.openvex.json")))
    reasons = runpy.run_path(os.path.join(ROOT, "ops", "gen-vex.py"))["REASONS"]
    assert doc["@context"].startswith("https://openvex.dev/ns/") and doc["statements"]
    for st in doc["statements"]:
        assert st["status"] == "not_affected", st
        assert st["justification"] in ("vulnerable_code_not_in_execute_path", "vulnerable_code_not_present"), st
        assert len(st["impact_statement"]) > 40, "a reason a person can check"
        assert st["vulnerability"]["name"].startswith(("CVE-", "GHSA-")), st
        for p in st["products"]:
            assert p["@id"].startswith("pkg:deb/debian/") and p["@id"].split("/")[-1] in reasons, p
    assert not any(p["@id"].endswith(("/python3", "/libssl3", "/libssl3t64", "/openssl")) for st in doc["statements"] for p in st["products"]), \
        "the runtime the vault actually uses (Python, OpenSSL) is never waved through"
