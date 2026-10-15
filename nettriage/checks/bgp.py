"""BGP session checks: neighbor symmetry, peer-AS, update-source, router-id and transport."""
from __future__ import annotations

import ipaddress
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from ..findings import Finding
from ..model import BgpNeighbor, Lab
from .l3 import Rib, effective_router_id


@dataclass
class Session:
    a: str
    b: str
    type: str
    state: str = "Established"
    causes: List[str] = field(default_factory=list)


def _owner(lab: Lab, ip) -> Optional[Tuple[str, str]]:
    for n, d in lab.devices.items():
        u = d.owns(ip)
        if u:
            return n, u
    return None


def _source(lab: Lab, dev: str, nb: BgpNeighbor) -> Optional[ipaddress.IPv4Address]:
    if nb.local_address:
        return nb.local_address
    for _, a in lab.devices[dev].addresses():
        if nb.peer in a.network:
            return a.ip
    return None  # sourced from the egress interface (not a stable address)


def check_bgp(lab: Lab, rib: Rib, prior: List[Finding]) -> Tuple[List[Finding], List[Session]]:
    findings: Dict[str, Finding] = {}
    sessions: List[Session] = []
    prior_keys = {f.key for f in prior}
    pairs: Dict[Tuple[str, str], List[Tuple[str, BgpNeighbor]]] = defaultdict(list)
    for name, dev in lab.devices.items():
        for nb in dev.bgp:
            own = _owner(lab, nb.peer)
            if own and own[0] != name:
                pairs[tuple(sorted((name, own[0])))].append((name, nb))

    def add(f: Finding) -> str:
        findings.setdefault(f.key, f)
        return f.key

    for (x, y), entries in sorted(pairs.items()):
        causes: List[str] = []
        stype = entries[0][1].type
        by_dev = defaultdict(list)
        for d, nb in entries:
            by_dev[d].append(nb)
        for d, p in ((x, y), (y, x)):
            if not by_dev[p]:
                nb = by_dev[d][0]
                src = _source(lab, d, nb) or nb.peer
                D = lab.devices[d]
                grp = nb.group
                causes.append(add(Finding(
                    "BGP_NEIGHBOR_MISSING", "critical",
                    f"{p} has no BGP neighbor statement for {d}", (p, d),
                    evidence=[f"{d}: group {grp} neighbor {nb.peer} (peer-as {nb.peer_as})",
                              f"{p}: no neighbor matching any address of {d}",
                              f"{p} resets the TCP/179 connection: {d} cycles Connect/Active"],
                    fix=[(p, f"set protocols bgp group {grp} neighbor {src}" +
                          ("" if stype == "internal" else f" peer-as {D.asn}"))],
                    verify=[(p, f"show bgp neighbor {src}"), (d, "show bgp summary")],
                    key=f"BGP_NEIGHBOR_MISSING:{p}->{d}")))
        if causes:
            sessions.append(Session(x, y, stype, "Active", causes))
            _session_down(findings, x, y, "Active", causes)
            continue

        for d, p in ((x, y), (y, x)):
            D, P = lab.devices[d], lab.devices[p]
            for nb in by_dev[d]:
                if nb.peer_as is not None and P.asn is not None and nb.peer_as != P.asn:
                    causes.append(add(Finding(
                        "BGP_PEER_AS_MISMATCH", "critical",
                        f"{d} expects AS {nb.peer_as} from {nb.peer} but {p} is AS {P.asn}", (d, p),
                        evidence=[f"{d}: group {nb.group} neighbor {nb.peer} peer-as {nb.peer_as}",
                                  f"{p}: routing-options autonomous-system {P.asn}",
                                  "OPEN rejected with NOTIFICATION 2/2 (OPEN Message Error / Bad Peer AS)"],
                        fix=[(d, f"set protocols bgp group {nb.group} neighbor {nb.peer} peer-as {P.asn}")],
                        verify=[(d, f"show bgp neighbor {nb.peer} | match \"State|Last Error\"")],
                        key=f"BGP_PEER_AS_MISMATCH:{d}->{nb.peer}")))
                src = _source(lab, d, nb)
                expected = [n.peer for n in by_dev[p]]
                if src not in expected:
                    want = next((e for e in expected if D.owns(e)), expected[0])
                    how = f"from {src}" if src else "from its egress interface address"
                    causes.append(add(Finding(
                        "BGP_SOURCE_MISMATCH", "critical",
                        f"{d} sources the session to {nb.peer} {how}, but {p} expects {want}", (d, p),
                        evidence=[f"{d}: group {nb.group} has no matching local-address",
                                  f"{p}: neighbor {want}",
                                  f"{p} sees the SYN from an unconfigured address and refuses it"],
                        fix=[(d, f"set protocols bgp group {nb.group} local-address {want}")],
                        verify=[(d, f"show bgp neighbor {nb.peer} | match \"Local Address|State\"")],
                        key=f"BGP_SOURCE_MISMATCH:{d}->{nb.peer}")))

        rx, ry = effective_router_id(lab.devices[x]), effective_router_id(lab.devices[y])
        if rx and rx == ry:
            k = f"ROUTER_ID_DUPLICATE:{rx}"
            if k not in prior_keys:
                add(Finding("ROUTER_ID_DUPLICATE", "critical", f"Router-ID {rx} shared by {x}, {y}", (x, y),
                            evidence=["BGP OPEN rejected: Bad BGP Identifier (NOTIFICATION 2/3)"],
                            fix=[(y, f"set routing-options router-id <unique loopback of {y}>")],
                            verify=[(y, "show bgp summary")], key=k))
            causes.append(k)

        if stype == "internal" and not causes:
            for d, p in ((x, y), (y, x)):
                for nb in by_dev[d]:
                    if rib.reachable(d, nb.peer):
                        continue
                    own_dev, own_unit = _owner(lab, nb.peer)
                    P = lab.devices[own_dev]
                    if P.ospf and own_unit not in P.ospf:
                        area = sorted({o.area for o in P.ospf.values()})[0]
                        causes.append(add(Finding(
                            "IGP_LOOPBACK_MISSING", "critical",
                            f"{own_dev} {own_unit} ({nb.peer}) is not advertised in OSPF", (own_dev,),
                            evidence=[f"{own_dev}: {own_unit} not under protocols ospf",
                                      f"iBGP peers cannot reach {nb.peer}: sessions sourced from it stay Active"],
                            fix=[(own_dev, f"set protocols ospf area {area} interface {own_unit} passive")],
                            verify=[(d, f"show route {nb.peer} exact"), (own_dev, "show ospf interface")],
                            key=f"IGP_LOOPBACK_MISSING:{own_dev}:{own_unit}")))
                    else:
                        cause = next((f.key for f in prior if f.is_root and f.code.startswith(("OSPF", "IP_", "MTU", "LACP"))), None)
                        causes.append(cause or add(Finding(
                            "BGP_TRANSPORT_UNREACHABLE", "critical",
                            f"{d} has no route to iBGP peer {nb.peer}", (d, p),
                            evidence=[f"{d}: show route {nb.peer} -> no matching route"],
                            verify=[(d, f"show route {nb.peer}")],
                            key=f"BGP_TRANSPORT_UNREACHABLE:{d}->{nb.peer}")))
        causes = list(dict.fromkeys(c for c in causes if c))
        state = "Established" if not causes else ("Idle" if any("PEER_AS" in c or "ROUTER_ID" in c for c in causes) else "Active")
        sessions.append(Session(x, y, stype, state, causes))
        if causes:
            _session_down(findings, x, y, state, causes)
    return list(findings.values()), sessions


def _session_down(findings: Dict[str, Finding], x: str, y: str, state: str, causes: List[str]):
    k = f"BGP_SESSION_DOWN:{x}|{y}"
    findings[k] = Finding(
        "BGP_SESSION_DOWN", "major", f"BGP session {x} <-> {y} is {state}", (x, y),
        evidence=[f"root cause(s): {', '.join(causes)}"],
        verify=[(x, "show bgp summary")], key=k, caused_by=causes[0])
