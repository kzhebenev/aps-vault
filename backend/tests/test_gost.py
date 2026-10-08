"""GOST primitives (0.18) against the published test vectors — the only honest proof that an
own implementation of a block cipher and an AEAD mode is the standard's one."""
import os

import pytest

import gost
import suite

K = bytes.fromhex("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef")


def test_kuznyechik_gost_r_34_12_2015_vector():
    c = gost.Kuznyechik(K)
    pt = bytes.fromhex("1122334455667700ffeeddccbbaa9988")
    ct = c.encrypt_block(pt)
    assert ct.hex() == "7f679d90bebc24305a468d42b9d4edcd"          # GOST R 34.12-2015, A.1
    assert c.decrypt_block(ct) == pt
    for _ in range(5):                                            # random round trips
        k, b = os.urandom(32), os.urandom(16)
        assert gost.Kuznyechik(k).decrypt_block(gost.Kuznyechik(k).encrypt_block(b)) == b


def test_kuznyechik_matches_gostcrypto():
    """Independent implementation (MIT library) agrees on random blocks."""
    from gostcrypto import gostcipher
    for _ in range(10):
        k, b = os.urandom(32), os.urandom(16)
        ref = gostcipher.new("kuznechik", k, gostcipher.MODE_ECB).encrypt(b)
        assert gost.Kuznyechik(k).encrypt_block(b) == ref


def test_mgm_rfc_9058_vector():
    nonce = bytes.fromhex("1122334455667700ffeeddccbbaa9988")
    aad = bytes.fromhex("0202020202020202010101010101010104040404040404040303030303030303ea0505050505050505")
    pt = bytes.fromhex("1122334455667700ffeeddccbbaa9988" "00112233445566778899aabbcceeff0a"
                       "112233445566778899aabbcceeff0a00" "2233445566778899aabbcceeff0a0011" "aabbcc")
    m = gost.MGM(gost.Kuznyechik(K))
    out = m.seal(nonce, pt, aad)
    assert out[:-16].hex() == ("a9757b8147956e9055b8a33de89f42fc8075d2212bf9fd5bd3f7069aadc16b39"
                               "497ab15915a6ba85936b5d0ea9f6851cc60c14d4d3f883d0ab94420695c76deb2c7552")
    assert out[-16:].hex() == "cf5d656f40c34f5c46e8bb0e29fcdb4c"
    assert m.open(nonce, out, aad) == pt
    # tampering, wrong AAD, wrong key, bad nonce
    bad = bytearray(out); bad[3] ^= 1
    with pytest.raises(ValueError):
        m.open(nonce, bytes(bad), aad)
    with pytest.raises(ValueError):
        m.open(nonce, out, aad + b"x")
    with pytest.raises(ValueError):
        gost.MGM(gost.Kuznyechik(os.urandom(32))).open(nonce, out, aad)
    with pytest.raises(ValueError):
        m.seal(b"\xff" * 16, pt, aad)          # top bit set
    with pytest.raises(ValueError):
        m.seal(b"\x00" * 12, pt, aad)          # wrong length
    assert m.open(nonce, m.seal(nonce, b"", b""), b"") == b""   # empty message is fine
    assert gost.mgm_nonce()[0] & 0x80 == 0 and len(gost.mgm_nonce()) == 16


def test_hmac_streebog_and_kdf_tree_r_50_1_113_vector():
    key = bytes(range(32))
    assert gost.hmac_streebog256(key, bytes.fromhex("0126bdb87800af214341456563780100")).hex() == \
        "a1aa5f7de402d7b3d323f2991c8d4534013137010a83754fd0af6d7cd4922ed9"
    # KDF_TREE with R = 1 and one key builds exactly that HMAC input (01‖label‖00‖seed‖0100)
    assert gost.kdf_tree_256(key, bytes.fromhex("26bdb878"), bytes.fromhex("af21434145656378"), 1).hex() == \
        "a1aa5f7de402d7b3d323f2991c8d4534013137010a83754fd0af6d7cd4922ed9"
    assert len(gost.kdf_tree_256(key, b"l", b"s", 2)) == 64
    # own HMAC equals the library's for ≤64-byte keys, and accepts longer keys (hashed first, RFC 2104)
    from gostcrypto import gosthmac
    for k in (b"k", os.urandom(32), os.urandom(64)):
        assert gost.hmac_streebog256(k, b"data") == gosthmac.new("HMAC_GOSTR3411_2012_256", k, data=b"data").digest()
        assert gost.hmac_streebog512(k, b"data") == gosthmac.new("HMAC_GOSTR3411_2012_512", k, data=b"data").digest()
    long = b"vlt_" + b"x" * 90
    assert gost.hmac_streebog256(long, b"d") == gost.hmac_streebog256(gost.streebog256(long), b"d")
    assert gost.streebog256(b"") != gost.streebog512(b"")[:32]
    assert len(gost.pbkdf2_streebog512(b"pw", b"salt", 2, 32)) == 32


def test_suite_reports_what_runs(client):
    """The health endpoint names the active suite, and the stored suite is the one the vault was
    initialised with (both suites run the whole test-suite via run_tests.sh / run_tests.sh gost)."""
    h = client.get("/api/health").json()
    assert h["cipher"] in suite.SUITES and h["cipher_label"] == suite.LABELS[h["cipher"]]
    assert suite.nonce_len() == (12 if h["cipher"] == "aes" else 16)
    # 0.41.4: gost is experimental (side channels), aes is not — health, and the startup warning, say so
    assert h["cipher_experimental"] is (h["cipher"] == "gost") is suite.experimental()
    if h["cipher"] == "gost":
        assert "EXPERIMENTAL" in suite.experimental_warning() and "docs/GOST.md" in suite.experimental_warning()
    assert len(suite.digest(b"x")) == 32 and len(suite.kdf(b"ikm", b"info")) == 32 and len(suite.kdf(b"ikm", b"info", length=16)) == 16
    assert suite.token_kdf(b"t", b"s" * 16) != suite.token_kdf(b"t", b"x" * 16)
