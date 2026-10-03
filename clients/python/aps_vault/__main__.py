"""python -m aps_vault keygen [--gost]                       — a key pair for sealed delivery
   python -m aps_vault enroll <vault-url> <code> [--gost] [--name <host>] [--out <dir>]
                                                          — node enrolment (0.21): make a key pair, redeem the
                                                            one-time code, store token + key (0600) in <dir>
                                                            (default: print them)"""
import os
import sys

from . import enroll, generate_keypair


def _usage(code=2):
    print(__doc__, file=sys.stderr)
    sys.exit(code)


args = sys.argv[1:]
if not args:
    _usage()
if args[0] == "keygen":
    if any(a not in ("--gost",) for a in args[1:]):
        _usage()
    kind = "gost" if "--gost" in args else "x25519"
    private, public = generate_keypair(kind)
    print(f"VAULT_CLIENT_KEY={private}        # keep with the token, never in git ({kind})")
    print(f"client_public_key={public}       # paste into the token in the vault UI")
elif args[0] == "enroll":
    if len(args) < 3:
        _usage()
    url, code, rest = args[1], args[2], args[3:]
    gost, name, out = "--gost" in rest, "", ""
    i = 0
    while i < len(rest):
        if rest[i] == "--name" and i + 1 < len(rest):
            name = rest[i + 1]; i += 2
        elif rest[i] == "--out" and i + 1 < len(rest):
            out = rest[i + 1]; i += 2
        elif rest[i] == "--gost":
            i += 1
        else:
            _usage()
    try:
        r = enroll(url, code, name=name, gost=gost)
    except Exception as e:
        print(f"enrol failed: {e}", file=sys.stderr)
        sys.exit(1)
    if out:
        os.makedirs(out, mode=0o700, exist_ok=True)
        for fn, val in (("vault.token", r["token"]), ("vault.key", r["private_key"])):
            p = os.path.join(out, fn)
            with open(os.open(p, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "w") as f:
                f.write(val + "\n")
        print(f"enrolled as {r['token_name']} (folder {r['folder_name']}); VAULT_TOKEN_FILE={out}/vault.token  VAULT_CLIENT_KEY=$(cat {out}/vault.key)  VAULT_URL={r['vault_url']}")
    else:
        print(f"VAULT_URL={r['vault_url']}")
        print(f"VAULT_TOKEN={r['token']}          # {r['token_name']} → {r['folder_name']}")
        print(f"VAULT_CLIENT_KEY={r['private_key']}   # the private key: 0600, never in git")
else:
    _usage()
