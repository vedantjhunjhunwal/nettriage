"""Run every check over a lab, correlate symptoms to root causes, return a Result."""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Dict, List

from .capture import analyze_file
from .checks.bgp import Session, check_bgp
from .checks.l2 import check_l2_links, check_lacp, check_stp, stp_root
from .checks.l3 import Adjacency, Rib, check_addressing, check_ospf
from .checks.vrrp import check_vrrp
from .findings import Finding, sort_findings
from .model import Lab, load_lab


@dataclass
class Result:
    lab: Lab
    findings: List[Finding]
    adjacencies: List[Adjacency]
    sessions: List[Session]
    bundles: Dict
    vrrp_masters: Dict
    stp_root: str
    elapsed_ms: float
    rib: Rib = field(repr=False, default=None)

    @property
    def roots(self) -> List[Finding]:
        return [f for f in self.findings if f.is_root]

    @property
    def root_codes(self) -> List[str]:
        return sorted({f.code for f in self.roots if f.source == "config"})


def analyze(lab: Lab) -> Result:
    t0 = time.perf_counter()
    findings: List[Finding] = []
    lacp_f, bundles = check_lacp(lab)
    findings += lacp_f
    findings += check_l2_links(lab, bundles)
    findings += check_addressing(lab)
    ospf_f, adjs = check_ospf(lab, bundles, findings)
    findings += ospf_f
    rib = Rib(lab, adjs)
    bgp_f, sessions = check_bgp(lab, rib, findings)
    findings += bgp_f
    findings += check_stp(lab, bundles)
    vrrp_f, masters = check_vrrp(lab)
    findings += vrrp_f
    for cap in lab.captures:
        findings += analyze_file(cap)
    _correlate_captures(findings)
    # de-duplicate by key, keep first
    uniq: Dict[str, Finding] = {}
    for f in findings:
        uniq.setdefault(f.key, f)
    root, _ = stp_root(lab, bundles)
    elapsed = (time.perf_counter() - t0) * 1000
    return Result(lab, sort_findings(list(uniq.values())), adjs, sessions, bundles, masters, root, elapsed, rib)


# capture symptom -> config root-cause codes that explain it
_CAPTURE_EXPLAINED_BY = {
    "CAP_BGP_NOTIFICATION": ("BGP_PEER_AS_MISMATCH", "ROUTER_ID_DUPLICATE"),
    "CAP_BGP_CONNECTION_REFUSED": ("BGP_NEIGHBOR_MISSING", "BGP_SOURCE_MISMATCH"),
    "CAP_OSPF_HELLO_MISMATCH": ("OSPF_AREA_MISMATCH", "OSPF_TIMER_MISMATCH", "IP_SUBNET_MISMATCH"),
    "CAP_ARP_DUPLICATE_IP": ("IP_DUPLICATE",),
}


def _correlate_captures(findings: List[Finding]):
    """A capture symptom becomes a consequence when config analysis already explains it."""
    for f in findings:
        if f.source != "capture":
            continue
        for g in findings:
            if g.source == "config" and g.is_root and g.code in _CAPTURE_EXPLAINED_BY.get(f.code, ()):
                f.caused_by = g.key
                g.evidence.append(f"corroborated by capture: {f.title}")
                break


def analyze_path(path: str) -> Result:
    return analyze(load_lab(path))
