"""Render a Result as a TAC-style case report (Markdown) or JSON."""
from __future__ import annotations

import json
from collections import defaultdict

from .engine import Result


def to_json(r: Result) -> str:
    return json.dumps({
        "lab": r.lab.name,
        "root_causes": [f.to_dict() for f in r.roots],
        "symptoms": [f.to_dict() for f in r.findings if not f.is_root],
        "ospf_adjacencies": [vars(a) for a in r.adjacencies],
        "bgp_sessions": [vars(s) for s in r.sessions],
        "stp_root": r.stp_root,
        "vrrp_masters": r.vrrp_masters,
        "elapsed_ms": round(r.elapsed_ms, 2),
    }, indent=2, default=str)


def to_markdown(r: Result) -> str:
    L = []
    roots = r.roots
    syms = [f for f in r.findings if not f.is_root]
    L.append(f"# NetTriage case report: `{r.lab.name}`\n")
    L.append(f"{len(r.lab.devices)} devices, {len(r.lab.links)} links, {len(r.lab.captures)} capture(s) "
             f"analysed in {r.elapsed_ms:.1f} ms.\n")
    if not roots:
        L.append("**No faults found.** All checks passed.\n")
    else:
        L.append(f"**{len(roots)} root cause(s), {len(syms)} downstream symptom(s).**\n")
        L.append("| # | Severity | Root cause | Devices | Symptoms explained |")
        L.append("|---|---|---|---|---|")
        children = defaultdict(list)
        for s in syms:
            children[s.caused_by].append(s)
        for i, f in enumerate(roots, 1):
            L.append(f"| {i} | {f.severity} | {f.title} | {', '.join(f.devices)} | {len(children[f.key])} |")
        L.append("")
        for i, f in enumerate(roots, 1):
            L.append(f"## {i}. {f.title}")
            L.append(f"`{f.code}` - {f.severity} - source: {f.source}\n")
            L.append("**Evidence**")
            L += [f"- {e}" for e in f.evidence]
            if children[f.key]:
                L.append("\n**Downstream symptoms (resolve with this fix)**")
                L += [f"- {c.title}" for c in children[f.key]]
            if f.fix:
                L.append("\n**Remediation**\n```")
                L += [f"[edit] {d}# {c}" for d, c in f.fix]
                L.append("commit check\ncommit confirmed 5\n```")
            if f.verify:
                L.append("**Verify**\n```")
                L += [f"{d}> {c}" for d, c in f.verify]
                L.append("```")
            L.append("")
    L.append("## Protocol state\n")
    if r.adjacencies:
        L.append("| OSPF adjacency | State | Reason |\n|---|---|---|")
        for a in r.adjacencies:
            L.append(f"| {a.a} {a.a_unit} <-> {a.b} {a.b_unit} | {a.state} | {a.reason} |")
        L.append("")
    if r.sessions:
        L.append("| BGP session | Type | State |\n|---|---|---|")
        for s in r.sessions:
            L.append(f"| {s.a} <-> {s.b} | {s.type} | {s.state} |")
        L.append("")
    if r.bundles:
        L.append("| LAG | State |\n|---|---|")
        for (d, ae), up in sorted(r.bundles.items()):
            L.append(f"| {d} {ae} | {'up' if up else 'DOWN'} |")
        L.append("")
    if r.stp_root:
        L.append(f"RSTP root bridge: **{r.stp_root}**\n")
    if r.vrrp_masters:
        L.append("| VRRP segment | Group -> Master |\n|---|---|")
        for net, m in r.vrrp_masters.items():
            L.append(f"| {net} | {', '.join(f'{g} -> {d}' for g, d in sorted(m.items()))} |")
    return "\n".join(L) + "\n"
