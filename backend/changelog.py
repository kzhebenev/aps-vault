"""CHANGELOG.md → release notes per version (0.38). No dependencies: the release workflow
(`ops/release-notes.py`) and the backend (`release_notes.json`, the Settings → Updates page) use the same parser,
so the notes a person reads in the vault are the notes the release was published with.

A section is a level-2 heading `## X.Y.Z — YYYY-MM-DD[ anything]` and everything up to the next level-2 heading."""
from __future__ import annotations

import re

_HEAD = re.compile(r"^## v?(\d+\.\d+\.\d+)(?:\s+[—–-]\s+(\d{4}-\d{2}-\d{2}))?.*$")


def parse_version(s: str) -> tuple[int, int, int] | None:
    """'0.38.0' / 'v0.38.0' → (0, 38, 0); anything else (pre-releases included) → None."""
    m = re.fullmatch(r"v?(\d+)\.(\d+)\.(\d+)", (s or "").strip())
    return (int(m.group(1)), int(m.group(2)), int(m.group(3))) if m else None


def parse(text: str) -> list[dict]:
    """[{version, date, notes}] in file order (newest first in our CHANGELOG)."""
    out: list[dict] = []
    cur: dict | None = None
    lines: list[str] = []
    for line in text.splitlines():
        m = _HEAD.match(line)
        if m:
            if cur:
                cur["notes"] = "\n".join(lines).strip()
                out.append(cur)
            cur, lines = {"version": m.group(1), "date": m.group(2) or ""}, []
        elif line.startswith("## "):          # a level-2 heading that is not a version ends the section
            if cur:
                cur["notes"] = "\n".join(lines).strip()
                out.append(cur)
            cur, lines = None, []
        elif cur is not None:
            lines.append(line)
    if cur:
        cur["notes"] = "\n".join(lines).strip()
        out.append(cur)
    return out


def section(text: str, version: str) -> str | None:
    v = (version or "").lstrip("v")
    for r in parse(text):
        if r["version"] == v:
            return r["notes"] or None
    return None
