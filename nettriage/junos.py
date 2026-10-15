"""Junos configuration parser.

Accepts either the hierarchical (curly-brace) format produced by
``show configuration`` or the flat ``display set`` format, and normalises
both into a list of *set paths* (tuples of tokens). Everything downstream
works on set paths, which keeps the model builder independent of the input
style an engineer happened to paste from the box.
"""
from __future__ import annotations

import re
from typing import Iterable, List, Tuple

SetPath = Tuple[str, ...]

_TOKEN_RE = re.compile(r'"(?:[^"\\]|\\.)*"|[{};\[\]]|[^\s{};\[\]"]+')


class JunosParseError(ValueError):
    pass


def _strip_comments(text: str) -> str:
    out = []
    for line in text.splitlines():
        s = line.strip()
        if s.startswith("#") or s.startswith("/*") or s.startswith("##"):
            continue
        # trailing "## SECRET-DATA" style annotations
        out.append(re.sub(r"\s##.*$", "", line))
    return "\n".join(out)


def _tokenize(text: str) -> List[str]:
    toks = []
    for t in _TOKEN_RE.findall(_strip_comments(text)):
        if t.startswith('"') and t.endswith('"'):
            t = t[1:-1]
        toks.append(t)
    return toks


def parse_hierarchical(text: str) -> List[SetPath]:
    """Flatten a curly-brace Junos config into set paths."""
    toks = _tokenize(text)
    stack: List[List[str]] = []  # each element: words of the open block header
    words: List[str] = []
    paths: List[SetPath] = []
    i = 0
    while i < len(toks):
        t = toks[i]
        if t == "{":
            stack.append(words)
            words = []
        elif t == "}":
            if words:
                raise JunosParseError(f"statement missing ';' before '}}': {' '.join(words)}")
            if not stack:
                raise JunosParseError("unbalanced '}'")
            stack.pop()
        elif t == ";":
            if words:
                prefix = tuple(w for blk in stack for w in blk)
                paths.append(prefix + tuple(words))
            words = []
        elif t == "[":
            # list value: emit one path per member (mirrors `display set`)
            j = toks.index("]", i)
            members = toks[i + 1:j]
            if j + 1 >= len(toks) or toks[j + 1] != ";":
                raise JunosParseError("list must be terminated by ';'")
            prefix = tuple(w for blk in stack for w in blk) + tuple(words)
            for m in members:
                paths.append(prefix + (m,))
            words = []
            i = j + 1  # skip the ';'
        else:
            words.append(t)
        i += 1
    if stack:
        raise JunosParseError("unterminated block (missing '}')")
    if words:
        raise JunosParseError(f"trailing statement without ';': {' '.join(words)}")
    return paths


def parse_set(text: str) -> List[SetPath]:
    paths: List[SetPath] = []
    for line in _strip_comments(text).splitlines():
        toks = [t[1:-1] if t.startswith('"') else t for t in _TOKEN_RE.findall(line)]
        if not toks:
            continue
        if toks[0] == "set":
            paths.append(tuple(toks[1:]))
        elif toks[0] == "delete":
            target = tuple(toks[1:])
            paths = [p for p in paths if p[: len(target)] != target]
        elif toks[0] in ("deactivate", "activate"):
            continue
        else:
            raise JunosParseError(f"unsupported set-format line: {line.strip()}")
    return paths


def parse(text: str) -> List[SetPath]:
    """Auto-detect the format and return set paths."""
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        if s.startswith(("set ", "delete ")):
            return parse_set(text)
        break
    return parse_hierarchical(text)


def to_set_lines(paths: Iterable[SetPath]) -> str:
    return "\n".join("set " + " ".join(p) for p in paths)


def render_hierarchical(paths: Iterable[SetPath]) -> str:
    """Render set paths back to curly-brace format (used by the lab generator)."""
    tree: dict = {}
    for p in paths:
        node = tree
        for tok in p[:-1]:
            node = node.setdefault(tok, {})
        node.setdefault(p[-1], {})

    def emit(node: dict, depth: int, parent: str = "") -> List[str]:
        lines = []
        pad = "    " * depth
        for key, child in node.items():
            if key in _NAMED or parent in _NAME_CONTAINERS:
                # `unit 0 {`, `area 0.0.0.0 {`, `ge-0/0/0 {` ... one block per name
                if parent in _NAME_CONTAINERS:
                    groups = [((key,), child)]
                else:
                    groups = [((key, name), sub) for name, sub in child.items()]
                for header, body in groups:
                    if body:
                        lines.append(f"{pad}{' '.join(header)} {{")
                        lines.extend(emit(body, depth + 1, header[0]))
                        lines.append(f"{pad}}}")
                    else:
                        lines.append(f"{pad}{' '.join(header)};")
            elif not child:
                lines.append(f"{pad}{key};")
            elif all(not v for v in child.values()) and key not in _FLAG_BLOCKS:
                vals = list(child)
                if len(vals) == 1:
                    lines.append(f"{pad}{key} {vals[0]};")
                else:
                    lines.append(f"{pad}{key} [ {' '.join(vals)} ];")
            else:
                lines.append(f"{pad}{key} {{")
                lines.extend(emit(child, depth + 1, key))
                lines.append(f"{pad}}}")
        return lines

    return "\n".join(emit(tree, 0)) + "\n"


# keywords whose next token is an instance name (rendered on the same line)
_NAMED = {"unit", "area", "group", "neighbor", "vrrp-group", "family", "address", "interface"}
# blocks whose children are bare flags (`lacp { active; }`)
_FLAG_BLOCKS = {"lacp"}
# containers whose children are themselves instance names
_NAME_CONTAINERS = {"interfaces", "vlans"}
