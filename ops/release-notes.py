#!/usr/bin/env python3
"""Release notes from CHANGELOG.md (0.38).

    ops/release-notes.py section 0.38.0     # the body of the GitHub Release; exit 1 when the section is missing
    ops/release-notes.py json               # backend/release_notes.json — the notes the vault shows offline

Until 0.37 the release workflow matched the heading `## 0.37.0` exactly, the real heading is
`## 0.37.0 — 2026-10-05`, so every GitHub Release said only "Release X". A missing section now fails the release."""
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "backend"))
import changelog  # noqa: E402


def main() -> int:
    text = open(os.path.join(ROOT, "CHANGELOG.md"), encoding="utf-8").read()
    if len(sys.argv) == 3 and sys.argv[1] == "section":
        body = changelog.section(text, sys.argv[2])
        if not body:
            print(f"CHANGELOG.md has no section for {sys.argv[2]}", file=sys.stderr)
            return 1
        print(body)
        return 0
    if len(sys.argv) == 2 and sys.argv[1] == "json":
        print(json.dumps(changelog.parse(text), ensure_ascii=False, indent=1))
        return 0
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
