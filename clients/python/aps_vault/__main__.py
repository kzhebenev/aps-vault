"""python -m aps_vault keygen — an X25519 key pair for sealed delivery (0.17)."""
import sys

from . import generate_keypair

if len(sys.argv) < 2 or sys.argv[1] != "keygen":
    print("usage: python -m aps_vault keygen", file=sys.stderr)
    sys.exit(2)
private, public = generate_keypair()
print(f"VAULT_CLIENT_KEY={private}        # keep with the token, never in git")
print(f"client_public_key={public}       # paste into the token in the vault UI")
