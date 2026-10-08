"""GOST R 34.10-2012 elliptic curve (256-bit) and VKO key agreement (RFC 7836 §4.3) for the
GOST sealed-delivery envelope (0.19).

Curve: id-tc26-gost-3410-2012-256-paramSetB (= id-GostR3410-2001-CryptoPro-A-ParamSet), a
short-Weierstrass curve y² = x³ + ax + b over GF(p) with prime order q (cofactor 1), the most
widely deployed 256-bit GOST curve. Points are encoded the GOST way: X ‖ Y, each 32 bytes
**little-endian** (64 bytes). Private keys: 32-byte big-endian integers d ∈ [1, q−1].

VKO_GOSTR3410_2012_256(d, Q, UKM) = Streebog-256( Vec(UKM · d · Q) ) with Vec = X‖Y little-endian
(RFC 7836: K = H((m/q)·UKM·x·y·P); here m = q so the factor is UKM). UKM is an 8-byte
little-endian integer ≥ 1.

Affine arithmetic with modular inverses — a few hundred microseconds per scalar multiplication
in CPython, which is fine for one envelope per secret read.
"""
from __future__ import annotations

import os

# id-tc26-gost-3410-2012-256-paramSetB
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD97
A = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD94
B = 0xA6
Q = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF6C611070995AD10045841B09B761B893
GX = 0x1
GY = 0x8D91E471E0989CDA27DF505A453F2B7635294F2DDF23E3B122ACC99C9E9F1E14
CURVE_NAME = "id-tc26-gost-3410-2012-256-paramSetB"

INF = None


def _inv(x: int) -> int:
    return pow(x % P, P - 2, P)


# Jacobian coordinates (X, Y, Z) with x = X/Z², y = Y/Z²: one inversion per scalar multiplication
# instead of one per step — ~10 ms for a 256-bit scalar in CPython, the affine version takes ~120.
def _jdouble(pt):
    X1, Y1, Z1 = pt
    if Y1 == 0:
        return (0, 1, 0)
    S = 4 * X1 * Y1 * Y1 % P
    Z1sq = Z1 * Z1 % P
    M = (3 * X1 * X1 + A * Z1sq * Z1sq) % P
    X3 = (M * M - 2 * S) % P
    Y3 = (M * (S - X3) - 8 * pow(Y1, 4, P)) % P
    Z3 = 2 * Y1 * Z1 % P
    return (X3, Y3, Z3)


def _jadd(p1, p2):
    if p1[2] == 0:
        return p2
    if p2[2] == 0:
        return p1
    X1, Y1, Z1 = p1
    X2, Y2, Z2 = p2
    Z1sq, Z2sq = Z1 * Z1 % P, Z2 * Z2 % P
    U1, U2 = X1 * Z2sq % P, X2 * Z1sq % P
    S1, S2 = Y1 * Z2sq * Z2 % P, Y2 * Z1sq * Z1 % P
    if U1 == U2:
        if S1 != S2:
            return (0, 1, 0)
        return _jdouble(p1)
    H = (U2 - U1) % P
    R = (S2 - S1) % P
    H2 = H * H % P
    H3 = H2 * H % P
    X3 = (R * R - H3 - 2 * U1 * H2) % P
    Y3 = (R * (U1 * H2 - X3) - S1 * H3) % P
    Z3 = H * Z1 * Z2 % P
    return (X3, Y3, Z3)


def _to_affine(pt):
    X, Y, Z = pt
    if Z == 0:
        return INF
    zi = _inv(Z)
    zi2 = zi * zi % P
    return (X * zi2 % P, Y * zi2 * zi % P)


def add(p1, p2):
    """Affine point addition (tests / small cases)."""
    if p1 is INF:
        return p2
    if p2 is INF:
        return p1
    return _to_affine(_jadd((p1[0], p1[1], 1), (p2[0], p2[1], 1)))


def mul(k: int, pt):
    """k·pt by double-and-add in Jacobian coordinates, in pure Python.

    NOT constant-time, and nothing here tries to be: the branch on each bit of k and Python's
    big-integer arithmetic both leak timing that depends on the scalar. This is weaker than the
    X25519 / P-256 envelopes, whose libraries (`cryptography`, Go, Node, Java) are constant-time.
    Where it matters: the vault itself only multiplies fresh single-use scalars (one per sealed
    envelope), so a timing trace of the server reveals nothing that is used twice. A long-term
    GOST private key goes through this code in `sealed.unseal_gost*` — on the machine that opens a
    backup (`backup.open_backup`) and in the Python client — where an attacker who can time many
    operations locally could learn it. That is why the gost profile is marked experimental
    (docs/GOST.md, "Side channels")."""
    k %= Q
    if k == 0 or pt is INF:
        return INF
    result = (0, 1, 0)
    addend = (pt[0], pt[1], 1)
    while k:
        if k & 1:
            result = _jadd(result, addend)
        addend = _jdouble(addend)
        k >>= 1
    return _to_affine(result)


def on_curve(pt) -> bool:
    if pt is INF:
        return False
    x, y = pt
    return 0 <= x < P and 0 <= y < P and (y * y - (x * x * x + A * x + B)) % P == 0


def encode_point(pt) -> bytes:
    x, y = pt
    return x.to_bytes(32, "little") + y.to_bytes(32, "little")


def decode_point(raw: bytes):
    if len(raw) != 64:
        raise ValueError("GOST public key must be 64 bytes (X‖Y little-endian)")
    pt = (int.from_bytes(raw[:32], "little"), int.from_bytes(raw[32:], "little"))
    if not on_curve(pt):
        raise ValueError("point is not on the GOST curve")      # prime order (cofactor 1): on the curve ⇒ in the group
    return pt


def generate_private() -> int:
    while True:
        d = int.from_bytes(os.urandom(32), "big")
        if 1 <= d < Q:
            return d


def public_from_private(d: int):
    return mul(d, (GX, GY))


def generate_keypair() -> tuple[bytes, bytes]:
    """(private 32 bytes big-endian, public 64 bytes X‖Y little-endian)."""
    d = generate_private()
    return d.to_bytes(32, "big"), encode_point(public_from_private(d))


def vko(private: int, peer, ukm: bytes) -> bytes:
    """VKO_GOSTR3410_2012_256: Streebog-256 of the shared point UKM·d·Q (little-endian X‖Y)."""
    from gost import streebog256
    if len(ukm) != 8:
        raise ValueError("UKM must be 8 bytes")
    u = int.from_bytes(ukm, "little")
    if u == 0:
        raise ValueError("UKM must be non-zero")
    shared = mul((u * private) % Q, peer)
    if shared is INF:
        raise ValueError("degenerate shared point")
    return streebog256(encode_point(shared))
