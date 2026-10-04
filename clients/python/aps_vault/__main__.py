"""python -m aps_vault keygen [--gost|--p256|--pqc]          — a key pair for sealed delivery (--pqc: X25519 + ML-KEM-768 hybrid)
   python -m aps_vault enroll <vault-url> <code> [--gost|--p256|--pqc] [--pkcs11 module:token:pin[:label]] [--name <host>] [--out <dir>]
                                                          — with --pkcs11 the key pair is made INSIDE the token (TPM via
                                                            tpm2-pkcs11, HSM, smart card) and never leaves it
                                                          — node enrolment (0.21): make a key pair, redeem the
                                                            one-time code, store token + key (0600) in <dir>
                                                            (default: print them)"""
import os
import sys

from . import Pkcs11Key, enroll, generate_keypair


def _usage(code=2):
    print(__doc__, file=sys.stderr)
    sys.exit(code)


args = sys.argv[1:]
if not args:
    _usage()
if args[0] == "keygen":
    if any(a not in ("--gost", "--p256", "--pqc") for a in args[1:]):
        _usage()
    kind = "gost" if "--gost" in args else "p256" if "--p256" in args else "pqc" if "--pqc" in args else "x25519"
    private, public = generate_keypair(kind)
    print(f"VAULT_CLIENT_KEY={private}        # keep with the token, never in git ({kind})")
    print(f"client_public_key={public}       # paste into the token in the vault UI")
elif args[0] == "enroll":
    if len(args) < 3:
        _usage()
    url, code, rest = args[1], args[2], args[3:]
    kind, name, out, hw = "x25519", "", "", None
    i = 0
    while i < len(rest):
        if rest[i] == "--name" and i + 1 < len(rest):
            name = rest[i + 1]; i += 2
        elif rest[i] == "--out" and i + 1 < len(rest):
            out = rest[i + 1]; i += 2
        elif rest[i] == "--pkcs11" and i + 1 < len(rest):
            parts = rest[i + 1].split(":")
            if len(parts) < 3:
                _usage()
            hw = Pkcs11Key.generate(parts[0], parts[1], parts[2], parts[3] if len(parts) > 3 else "aps-vault-node"); i += 2
        elif rest[i] in ("--gost", "--p256", "--pqc"):
            kind = rest[i][2:]; i += 1
        else:
            _usage()
    try:
        r = enroll(url, code, name=name, kind=kind, hardware_key=hw)
    except Exception as e:
        print(f"enrol failed: {e}", file=sys.stderr)
        sys.exit(1)
    if out:
        os.makedirs(out, mode=0o700, exist_ok=True)
        for fn, val in ((("vault.token", r["token"]),) + ((("vault.key", r["private_key"]),) if hw is None else ())):
            p = os.path.join(out, fn)
            with open(os.open(p, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "w") as f:
                f.write(val + "\n")
        if hw is None:
            print(f"enrolled as {r['token_name']} (folder {r['folder_name']}); VAULT_TOKEN_FILE={out}/vault.token  VAULT_CLIENT_KEY=$(cat {out}/vault.key)  VAULT_URL={r['vault_url']}")
        else:
            print(f"enrolled as {r['token_name']} (folder {r['folder_name']}); VAULT_TOKEN_FILE={out}/vault.token; the private key lives in the PKCS#11 token {hw.token_label!r} as {hw.key_label!r}  VAULT_URL={r['vault_url']}")
    else:
        print(f"VAULT_URL={r['vault_url']}")
        print(f"VAULT_TOKEN={r['token']}          # {r['token_name']} → {r['folder_name']}")
        if hw is None:
            print(f"VAULT_CLIENT_KEY={r['private_key']}   # the private key: 0600, never in git")
        else:
            print(f"# private key inside the PKCS#11 token {hw.token_label!r}, label {hw.key_label!r} — use Pkcs11Key(...) in code")
else:
    _usage()
