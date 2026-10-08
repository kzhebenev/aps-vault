#!/usr/bin/env python3
"""Produce clients/fixtures/pqc-sealed.json and gost-pqc-sealed.json — server-made hybrid (X25519 + ML-KEM-768) envelope that
every client port must open, plus the key pair it was made for. Deterministic keys (fixed X25519 scalar
and ML-KEM seed) so a port can also check that it derives the same public key from the private one.

    cd backend && python ../ops/gen-sealed-fixture.py            # needs cryptography + kyber-py
"""
import base64
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "backend"))
import sealed  # noqa: E402

x_sk = bytes(range(1, 33))                       # 0x01..0x20 — a valid X25519 scalar after clamping inside the library
seed = bytes(range(0x20, 0x60))                  # 64 bytes 0x20..0x5f — the ML-KEM-768 d‖z seed
sk_raw = x_sk + seed
pk_raw = sealed.pqc_public_from_private(sk_raw)
name = "core-db"
payload = {"value": "pg-pass-2026", "login": "core", "notes": "hybrid fixture", "version": 7}
env = sealed.seal(payload, base64.b64encode(pk_raw).decode(), name)
assert sealed.unseal(env, sk_raw, name) == payload
# a second envelope for a payload with non-ASCII text and a different name (AAD)
name2 = "кириллица/путь"
payload2 = {"value": "значение №2 ✓", "login": "svc"}
env2 = sealed.seal(payload2, base64.b64encode(pk_raw).decode(), name2)
assert sealed.unseal(env2, sk_raw, name2) == payload2
out = {
    "note": "Server-produced hybrid envelope (backend/sealed.py seal_pqc): X25519 + ML-KEM-768 (FIPS 203). "
            "Private key = X25519 sk (32) ‖ ML-KEM seed d‖z (64) = 96 bytes; public = X25519 pk (32) ‖ ML-KEM ek (1184) = 1216 bytes. "
            "key = HKDF-SHA256(ikm = ss_x25519 ‖ ss_mlkem, salt = none, info = hkdf_info_prefix ‖ epk ‖ kem); AES-256-GCM, AAD = secret name. "
            "A port must (1) derive public_b64 from private_b64 and (2) open both envelopes; (3) a flipped byte in kem, epk, ct or the name must fail.",
    "alg": sealed.ALG_PQC,
    "hkdf_info_prefix": sealed._INFO_PQC.decode(),
    "keypair": {"private_b64": base64.b64encode(sk_raw).decode(), "public_b64": base64.b64encode(pk_raw).decode(),
                "x25519_sk_hex": x_sk.hex(), "mlkem_seed_hex": seed.hex()},
    "envelopes": [{"name": name, "payload": payload, "sealed": env}, {"name": name2, "payload": payload2, "sealed": env2}],
}
path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "clients", "fixtures", "pqc-sealed.json")
with open(path, "w", encoding="utf-8") as f:
    json.dump(out, f, ensure_ascii=False, indent=2)
print(f"wrote {os.path.relpath(path)}: public key {len(pk_raw)} bytes, kem ct {len(base64.b64decode(env['kem']))} bytes")

# ── 0.32: the GOST hybrid (VKO GOST R 34.10-2012 + ML-KEM-768 → KDF_TREE → Kuznyechik-MGM) ──
gost_sk = bytes(range(1, 33))                    # 0x01..0x20 as a big-endian scalar: well inside [1, q-1]
gsk_raw = gost_sk + seed
gpk_raw = sealed.gost_pqc_public_from_private(gsk_raw)
genv = sealed.seal(payload, base64.b64encode(gpk_raw).decode(), name)
assert genv["alg"] == sealed.ALG_GOST_PQC and sealed.unseal(genv, gsk_raw, name) == payload
genv2 = sealed.seal(payload2, base64.b64encode(gpk_raw).decode(), name2)
assert sealed.unseal(genv2, gsk_raw, name2) == payload2
gout = {
    "note": "Server-produced GOST hybrid envelope (backend/sealed.py seal_gost_pqc): VKO GOST R 34.10-2012 (paramSetB) + ML-KEM-768. "
            "Private key = GOST scalar big-endian (32) ‖ ML-KEM seed d‖z (64) = 96 bytes; public = GOST point X‖Y little-endian (64) ‖ ML-KEM ek (1184) = 1248 bytes. "
            "KEK = VKO(d_eph, client_gost_pk, ukm); ss_kem = ML-KEM-768.Decaps; key = KDF_TREE_GOSTR3411_2012_256(K = KEK ‖ ss_kem (64 bytes), label, seed = epk ‖ kem, 1 key); "
            "Kuznyechik-MGM, AAD = secret name. A port must (1) derive public_b64 from private_b64 and (2) open both envelopes; (3) a flipped byte in kem, epk, ukm, ct or the name must fail.",
    "alg": sealed.ALG_GOST_PQC,
    "kdf_label": sealed._LABEL_GOST_PQC.decode(),
    "keypair": {"private_b64": base64.b64encode(gsk_raw).decode(), "public_b64": base64.b64encode(gpk_raw).decode(),
                "gost_sk_hex": gost_sk.hex(), "mlkem_seed_hex": seed.hex()},
    "envelopes": [{"name": name, "payload": payload, "sealed": genv}, {"name": name2, "payload": payload2, "sealed": genv2}],
}
gpath = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "clients", "fixtures", "gost-pqc-sealed.json")
with open(gpath, "w", encoding="utf-8") as f:
    json.dump(gout, f, ensure_ascii=False, indent=2)
print(f"wrote {os.path.relpath(gpath)}: public key {len(gpk_raw)} bytes")
