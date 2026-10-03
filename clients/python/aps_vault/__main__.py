"""python -m aps_vault keygen [--gost] — a key pair for sealed delivery (0.17 / GOST 0.19)."""
import sys

from . import generate_keypair

args = sys.argv[1:]
if not args or args[0] != "keygen" or any(a not in ("--gost",) for a in args[1:]):
    print("usage: python -m aps_vault keygen [--gost]", file=sys.stderr)
    sys.exit(2)
kind = "gost" if "--gost" in args else "x25519"
private, public = generate_keypair(kind)
print(f"VAULT_CLIENT_KEY={private}        # keep with the token, never in git ({kind})")
print(f"client_public_key={public}       # paste into the token in the vault UI")
