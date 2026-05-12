"""Tiny YAML reader — handles the subset needed for CI workflow files and pnpm-lock.

Supports:
  - mappings (`key: value` and nested `key:` blocks)
  - sequences (`- item` and `- key: value` block items)
  - inline scalars (strings, numbers, booleans, null)
  - block scalars '|' and '>' (folded/literal) with basic stripping
  - quoted strings ('...' and "...")
  - inline flow mappings/sequences `{a: b, c: d}` and `[1, 2, 3]` (limited)
  - comments after `#` (outside strings)
  - multi-doc separated by `---` (returns a list of docs)

Does NOT support: anchors, aliases, tags, complex flow types. Ample for our needs.
"""

from __future__ import annotations

from typing import Any


class YamlError(ValueError):
    pass


def loads(text: str) -> Any:
    docs = _load_all(text)
    if not docs:
        return None
    if len(docs) == 1:
        return docs[0]
    return docs


def load_all(text: str) -> list[Any]:
    return _load_all(text)


def _load_all(text: str) -> list[Any]:
    # Normalize line endings; strip BOM.
    if text.startswith("﻿"):
        text = text[1:]
    lines = text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    docs: list[Any] = []
    cur: list[str] = []
    for ln in lines:
        if ln.strip() == "---":
            if cur:
                docs.append(_parse_doc(cur))
                cur = []
            continue
        if ln.strip() == "...":
            if cur:
                docs.append(_parse_doc(cur))
                cur = []
            continue
        cur.append(ln)
    if cur:
        d = _parse_doc(cur)
        if d is not None or any(l.strip() for l in cur):
            docs.append(d)
    return docs


def _strip_comment(line: str) -> str:
    # Strip `# ...` outside quotes.
    out = []
    in_s = None
    i = 0
    while i < len(line):
        c = line[i]
        if in_s:
            out.append(c)
            if c == "\\" and i + 1 < len(line):
                out.append(line[i + 1])
                i += 2
                continue
            if c == in_s:
                in_s = None
        else:
            if c in ("'", '"'):
                in_s = c
                out.append(c)
            elif c == "#" and (i == 0 or line[i - 1] in (" ", "\t")):
                break
            else:
                out.append(c)
        i += 1
    return "".join(out).rstrip()


def _indent(line: str) -> int:
    n = 0
    for c in line:
        if c == " ":
            n += 1
        elif c == "\t":
            n += 8  # treat as 8 spaces
        else:
            return n
    return n


def _parse_doc(lines: list[str]) -> Any:
    # Skip blank/comment lines at the top.
    pre = []
    for raw in lines:
        s = _strip_comment(raw)
        pre.append(s)
    # Trim trailing blank lines.
    while pre and not pre[-1].strip():
        pre.pop()
    if not pre:
        return None
    p = _Parser(pre)
    return p.parse_block(0)


class _Parser:
    def __init__(self, lines: list[str]):
        self.lines = lines
        self.i = 0

    def _peek(self) -> tuple[int, str]:
        # Skip blank lines
        while self.i < len(self.lines) and not self.lines[self.i].strip():
            self.i += 1
        if self.i >= len(self.lines):
            return -1, ""
        ln = self.lines[self.i]
        return _indent(ln), ln

    def parse_block(self, base_indent: int) -> Any:
        ind, ln = self._peek()
        if ind < 0 or ind < base_indent:
            return None
        body = ln[ind:]
        if body.startswith("- "):
            return self._parse_seq(ind)
        # Flow scalar at root of doc
        if ":" not in body and not body.startswith("- "):
            self.i += 1
            return _scalar(body.strip())
        return self._parse_map(ind)

    def _parse_seq(self, ind: int) -> list:
        out: list = []
        while True:
            cur_ind, ln = self._peek()
            if cur_ind < 0 or cur_ind < ind:
                return out
            body = ln[cur_ind:]
            if not body.startswith("- "):
                if body.startswith("-") and (len(body) == 1 or body[1] == "\n"):
                    body = "- "
                else:
                    return out
            after_dash = body[2:].strip() if len(body) > 2 else ""
            self.i += 1
            if not after_dash:
                # Nested block follows
                out.append(self.parse_block(ind + 2))
            elif ":" in after_dash and not after_dash.startswith("{") and not after_dash.startswith("["):
                # Inline mapping start — re-parse as map at this indent
                self.i -= 1
                self.lines[self.i] = " " * (cur_ind + 2) + body[2:]
                out.append(self._parse_map(cur_ind + 2))
            else:
                out.append(_scalar(after_dash))

    def _parse_map(self, ind: int) -> dict:
        out: dict = {}
        while True:
            cur_ind, ln = self._peek()
            if cur_ind < 0 or cur_ind < ind:
                return out
            if cur_ind > ind:
                # Should not happen at this level
                return out
            body = ln[cur_ind:]
            if body.startswith("- "):
                return out  # belongs to a parent sequence
            colon = _find_unquoted_colon(body)
            if colon < 0:
                # plain scalar in map context — treat as item value of parent? skip
                self.i += 1
                continue
            key = _scalar(body[:colon].strip())
            val_text = body[colon + 1:].strip()
            self.i += 1
            if val_text == "" or val_text == "|" or val_text == ">":
                if val_text in ("|", ">"):
                    out[key] = self._parse_block_scalar(ind + 1, val_text)
                else:
                    nxt_ind, nxt_ln = self._peek()
                    if nxt_ind > ind:
                        out[key] = self.parse_block(nxt_ind)
                    else:
                        out[key] = None
            elif val_text.startswith("|") or val_text.startswith(">"):
                out[key] = self._parse_block_scalar(ind + 1, val_text[0])
            elif val_text.startswith("{") or val_text.startswith("["):
                out[key] = _parse_flow(val_text)
            else:
                out[key] = _scalar(val_text)
        return out

    def _parse_block_scalar(self, base_indent: int, kind: str) -> str:
        chunks: list[str] = []
        actual_base = -1
        while self.i < len(self.lines):
            ln = self.lines[self.i]
            if not ln.strip():
                chunks.append("")
                self.i += 1
                continue
            ind = _indent(ln)
            if actual_base < 0:
                actual_base = ind
            if ind < actual_base:
                break
            chunks.append(ln[actual_base:])
            self.i += 1
        if kind == "|":
            return "\n".join(chunks)
        # folded
        return " ".join(chunks)


def _find_unquoted_colon(s: str) -> int:
    in_q = None
    i = 0
    while i < len(s):
        c = s[i]
        if in_q:
            if c == "\\" and i + 1 < len(s):
                i += 2
                continue
            if c == in_q:
                in_q = None
        else:
            if c in ("'", '"'):
                in_q = c
            elif c == ":":
                # Must be followed by space/EOL or be last
                if i + 1 >= len(s) or s[i + 1] in (" ", "\t"):
                    return i
        i += 1
    # Trailing colon (e.g. `key:`)
    if s.endswith(":"):
        return len(s) - 1
    return -1


def _scalar(s: str) -> Any:
    if not s:
        return None
    if (s.startswith("'") and s.endswith("'") and len(s) >= 2):
        return s[1:-1].replace("''", "'")
    if (s.startswith('"') and s.endswith('"') and len(s) >= 2):
        return _unescape_double(s[1:-1])
    low = s.lower()
    if low in ("null", "~", ""):
        return None
    if low == "true":
        return True
    if low == "false":
        return False
    # Number?
    try:
        return int(s)
    except ValueError:
        pass
    try:
        return float(s)
    except ValueError:
        pass
    return s


def _unescape_double(s: str) -> str:
    out = []
    i = 0
    while i < len(s):
        c = s[i]
        if c == "\\" and i + 1 < len(s):
            n = s[i + 1]
            out.append({"n": "\n", "t": "\t", "r": "\r", '"': '"', "\\": "\\", "/": "/", " ": " "}.get(n, n))
            i += 2
        else:
            out.append(c)
            i += 1
    return "".join(out)


def _parse_flow(text: str) -> Any:
    # Very small flow parser. Not RFC-complete, sufficient for `{a: b, c: d}` and `[1, 2]`.
    text = text.strip()
    if text.startswith("{"):
        body = text[1:-1] if text.endswith("}") else text[1:]
        out: dict = {}
        for part in _split_top(body, ","):
            part = part.strip()
            if not part:
                continue
            if ":" in part:
                k, v = part.split(":", 1)
                out[_scalar(k.strip())] = _scalar(v.strip())
            else:
                out[_scalar(part)] = None
        return out
    if text.startswith("["):
        body = text[1:-1] if text.endswith("]") else text[1:]
        return [_scalar(p.strip()) for p in _split_top(body, ",") if p.strip()]
    return _scalar(text)


def _split_top(s: str, sep: str) -> list[str]:
    out: list[str] = []
    depth = 0
    in_q = None
    cur = []
    for c in s:
        if in_q:
            cur.append(c)
            if c == in_q:
                in_q = None
            continue
        if c in ("'", '"'):
            in_q = c
            cur.append(c)
            continue
        if c in "[{":
            depth += 1
            cur.append(c)
            continue
        if c in "]}":
            depth -= 1
            cur.append(c)
            continue
        if c == sep and depth == 0:
            out.append("".join(cur))
            cur = []
            continue
        cur.append(c)
    out.append("".join(cur))
    return out
