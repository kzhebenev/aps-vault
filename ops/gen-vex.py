#!/usr/bin/env python3
"""OpenVEX for the backend image (0.41): the scanner's findings that cannot affect APS Vault, each with its reason.

    trivy image --format json -o trivy.json ghcr.io/kzhebenev/aps-vault/backend:<v>
    ops/gen-vex.py trivy.json <v> > security/vex/backend.openvex.json
    trivy image --vex security/vex/backend.openvex.json ghcr.io/kzhebenev/aps-vault/backend:<v>   # → what is left

Only packages listed in REASONS get a statement, and only "not_affected" with an OpenVEX justification. A new CVE in an
unlisted package stays visible — it has to be looked at, not waved through. The reasons were checked on 05.10.2026:
the backend is a Python process (uvicorn, uid 10001, no capabilities, no-new-privileges) that never runs these
programs; libuuid is loaded by Python's uuid module, but the util-linux CVEs are in the mount helpers and nsenter."""
import datetime as dt
import hashlib
import json
import sys

JUST_PATH = "vulnerable_code_not_in_execute_path"
JUST_ABSENT = "vulnerable_code_not_present"
UTIL_LINUX = ("The vulnerable code is in mount(8) helpers / X-mount options and nsenter(1). The backend never executes "
              "them; it runs as uid 10001 with all capabilities dropped and no-new-privileges, so there is no privileged "
              "mount or namespace operation to subvert. libuuid is loaded by Python's uuid module, but not the affected code.")
REASONS = {
    **{p: (JUST_PATH, UTIL_LINUX) for p in ("util-linux", "bsdutils", "libblkid1", "liblastlog2-2", "libmount1",
                                            "libsmartcols1", "libuuid1", "login", "mount")},
    "libsystemd0": (JUST_ABSENT, "The flaw is in systemd-homed, which is not in the image; the container has no init system."),
    "libudev1": (JUST_ABSENT, "The flaw is in systemd-homed, which is not in the image; the container has no init system."),
    "libacl1": (JUST_PATH, "The backend never calls libacl on paths; the only writable path is the data directory owned by the process itself."),
    **{p: (JUST_PATH, "Terminal handling (ncurses) is never used by the server process; no TTY, no curses/readline import.")
       for p in ("libncursesw6", "libtinfo6", "ncurses-base", "ncurses-bin")},
    "perl-base": (JUST_PATH, "Perl is in the image only because dpkg needs it at build time; the backend never runs perl or Archive::Tar."),
}


def main() -> int:
    trivy, version = json.load(open(sys.argv[1])), sys.argv[2]
    by_cve: dict[str, set] = {}
    for r in trivy.get("Results", []):
        for v in r.get("Vulnerabilities") or []:
            if v["PkgName"] in REASONS:
                by_cve.setdefault(v["VulnerabilityID"], set()).add(v["PkgName"])
    statements = []
    for cve, pkgs in sorted(by_cve.items()):
        just = {REASONS[p][0] for p in pkgs}
        statements.append({
            "vulnerability": {"name": cve},
            # the packages themselves are the products: trivy matches an image product only by its registry digest, so a
            # statement tied to pkg:oci/… is skipped for a locally built or re-tagged image. The file ships with this image.
            "products": [{"@id": f"pkg:deb/debian/{p}"} for p in sorted(pkgs)],
            "status": "not_affected",
            "justification": JUST_ABSENT if just == {JUST_ABSENT} else JUST_PATH,
            "impact_statement": " ".join(sorted({REASONS[p][1] for p in pkgs})),
        })
    ts = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    doc = {"@context": "https://openvex.dev/ns/v0.2.0", "@id": "", "author": "APS Vault maintainers",
           "timestamp": ts, "version": 1, "tooling": f"ops/gen-vex.py for backend {version}", "statements": statements}
    doc["@id"] = "https://github.com/kzhebenev/aps-vault/vex/backend-" + hashlib.sha256(json.dumps(statements, sort_keys=True).encode()).hexdigest()[:16]
    json.dump(doc, sys.stdout, indent=1)
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
