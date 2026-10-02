#!/usr/bin/env python3
"""Wrap Russian UI strings in app.js with tr() and list the keys.

    python3 tools/i18n-transform.py app.js --list        # print keys (singles + template keys)
    python3 tools/i18n-transform.py app.js --apply       # rewrite app.js in place

A real tokenizer, not a regex: comments, '…', "…", `…${…}…` (nested) and regex literals are
recognised, so a quote inside a template or a Cyrillic letter in a comment never trips it.
Already-wrapped strings (tr('…'), tr`…`) are left alone, so the script is idempotent.
"""
import re
import sys

CYR = re.compile(r"[А-Яа-яЁё]")
REGEX_PRECEDERS = set("(,=:[!&|?{};+-*%<>~^")


def tokenize(src: str):
    """Yield (kind, start, end) for 'code' and string tokens; templates are returned as a
    tree: ('template', start, end, [(lit_start, lit_end), ...], [(expr_start, expr_end), ...])."""
    i, n = 0, len(src)
    last_sig = ""      # last significant char, to tell regex from division
    while i < n:
        c = src[i]
        if c == "/" and src.startswith("//", i):
            j = src.find("\n", i); i = n if j < 0 else j; continue
        if c == "/" and src.startswith("/*", i):
            j = src.find("*/", i + 2); i = n if j < 0 else j + 2; continue
        if c in "'\"":
            j = i + 1
            while j < n and src[j] != c:
                j += 2 if src[j] == "\\" else 1
            yield ("str", i, j + 1); i = j + 1; last_sig = c; continue
        if c == "`":
            tok, j = read_template(src, i)
            yield tok; i = j; last_sig = "`"; continue
        if c == "/" and (last_sig in REGEX_PRECEDERS or last_sig == "" or last_sig == "\n"):
            j = i + 1; in_class = False
            while j < n:
                if src[j] == "\\": j += 2; continue
                if src[j] == "[": in_class = True
                elif src[j] == "]": in_class = False
                elif src[j] == "/" and not in_class: break
                elif src[j] == "\n": break
                j += 1
            j += 1
            while j < n and src[j].isalpha(): j += 1
            i = j; last_sig = "/"; continue
        if not c.isspace():
            last_sig = c
        i += 1


def read_template(src: str, i: int):
    """Parse `…` starting at i; returns (('tpl', start, end, lits, exprs), end)."""
    n = len(src); j = i + 1; lits = []; exprs = []; lit_start = j
    while j < n:
        ch = src[j]
        if ch == "\\": j += 2; continue
        if ch == "`":
            lits.append((lit_start, j)); return ("tpl", i, j + 1, lits, exprs), j + 1
        if ch == "$" and src.startswith("${", j):
            lits.append((lit_start, j))
            depth = 1; k = j + 2
            while k < n and depth:
                if src[k] == "{": depth += 1
                elif src[k] == "}": depth -= 1
                elif src[k] in "'\"":
                    q = src[k]; k += 1
                    while k < n and src[k] != q: k += 2 if src[k] == "\\" else 1
                elif src[k] == "`":
                    _, k = read_template(src, k); continue
                k += 1
            exprs.append((j + 2, k - 1)); j = k; lit_start = j; continue
        j += 1
    raise SyntaxError("unterminated template")


_WRAP_CALL = re.compile(r"(?:^|[^A-Za-z0-9_$.])tr\($")
_WRAP_TAG = re.compile(r"(?:^|[^A-Za-z0-9_$.])tr$")


def wrapped_already(src: str, start: int) -> bool:
    """True if the literal is already the argument of t(...) or tagged with t`…`.
    `toast('…')` must NOT count — hence the identifier boundary check."""
    before = src[:start].rstrip()
    if _WRAP_CALL.search(before):
        return True
    return src[start] == "`" and bool(_WRAP_TAG.search(before))


def collect(src: str):
    """Return (edits, keys): edits = [(start, end, replacement)], keys = ordered unique keys."""
    edits, keys = [], []

    def walk(lo, hi):
        sub = src[lo:hi]
        for tok in tokenize(sub):
            kind, s, e = tok[0], tok[1] + lo, tok[2] + lo
            if kind == "str":
                body = src[s + 1:e - 1]
                if CYR.search(body) and not wrapped_already(src, s):
                    edits.append((s, e, f"tr({src[s:e]})"))
                    key = bytes(body, "utf-8").decode("unicode_escape") if "\\" in body else body
                    if key not in keys: keys.append(key)
            elif kind == "tpl":
                lits, exprs = tok[3], tok[4]
                lit_text = "".join(src[a + lo:b + lo] for a, b in lits)
                if CYR.search(lit_text) and not wrapped_already(src, s):
                    edits.append((s, s, "tr"))
                    key = "".join(src[a + lo:b + lo] + (f"{{{i}}}" if i < len(exprs) else "") for i, (a, b) in enumerate(lits))
                    if key not in keys: keys.append(key)
                for a, b in exprs:
                    walk(a + lo, b + lo)
    walk(0, len(src))
    return edits, keys


def main():
    path = sys.argv[1]; mode = sys.argv[2] if len(sys.argv) > 2 else "--list"
    src = open(path, encoding="utf-8").read()
    edits, keys = collect(src)
    if mode == "--list":
        for k in keys: print(k)
        print(f"# {len(keys)} keys, {len(edits)} edits", file=sys.stderr)
        return
    out = src
    for s, e, rep in sorted(edits, key=lambda x: x[0], reverse=True):
        out = out[:s] + rep + out[e:]
    open(path, "w", encoding="utf-8").write(out)
    print(f"applied {len(edits)} edits, {len(keys)} keys", file=sys.stderr)


if __name__ == "__main__":
    main()
