"""VRRP gateway-redundancy checks and master election."""
from __future__ import annotations

from collections import Counter, defaultdict
from typing import Dict, List, Tuple

from ..findings import Finding
from ..model import Lab


def vrrp_members(lab: Lab):
    seg = defaultdict(list)  # subnet -> [(dev, unit, Unit, Vrrp)]
    for n, d in lab.devices.items():
        for u in d.units.values():
            if u.address:
                for v in u.vrrp:
                    seg[u.address.network].append((n, u.name, u, v))
    return seg


def elect(members) -> Dict[int, str]:
    """Return group -> master device (highest priority, then highest interface IP)."""
    out = {}
    by_group = defaultdict(list)
    for n, _, u, v in members:
        by_group[v.group].append((v.priority, u.address.ip, n))
    for g, cands in by_group.items():
        out[g] = max(cands)[2]
    return out


def check_vrrp(lab: Lab) -> Tuple[List[Finding], Dict[str, Dict[int, str]]]:
    findings: List[Finding] = []
    masters = {}
    for net, mem in sorted(vrrp_members(lab).items(), key=lambda x: str(x[0])):
        masters[str(net)] = elect(mem)
        for n, uname, u, v in mem:
            if v.vip and v.vip not in net:
                findings.append(Finding(
                    "VRRP_VIP_OUTSIDE_SUBNET", "critical",
                    f"{n} {uname}: VRRP group {v.group} VIP {v.vip} is outside {net}", (n,),
                    evidence=[f"{n} {uname}: address {u.address}", f"vrrp-group {v.group} virtual-address {v.vip}",
                              "Junos rejects the group (commit warning) or hosts ARP for an unreachable gateway"],
                    fix=[(n, f"set interfaces {uname.replace('.', ' unit ')} family inet address "
                             f"{u.address.with_prefixlen} vrrp-group {v.group} virtual-address "
                             f"{_vip_guess(mem, net)}")],
                    verify=[(n, "show vrrp detail")],
                    key=f"VRRP_VIP_OUTSIDE_SUBNET:{n}:{uname}"))
        if len(mem) < 2:
            continue
        groups = Counter(v.group for *_, v in mem)
        if len(groups) > 1:
            majority = groups.most_common(1)[0][0]
            odd = [(n, un, u, v) for n, un, u, v in mem if v.group != majority]
            findings.append(Finding(
                "VRRP_GROUP_MISMATCH", "critical",
                f"VRRP group-id mismatch on {net}: both routers become Master", tuple(sorted({m[0] for m in mem})),
                evidence=[f"{n} {un}: vrrp-group {v.group}" for n, un, _, v in mem] +
                         ["advertisements for a different VRID are ignored -> split-brain, duplicate gateway ARP"],
                fix=[(n, f"# re-create {un} vrrp-group {v.group} as vrrp-group {majority} (same VIP/priority)")
                     for n, un, _, v in odd],
                verify=[(n, "show vrrp summary") for n, *_ in mem],
                key=f"VRRP_GROUP_MISMATCH:{net}"))
            continue
        vips = {v.vip for *_, v in mem if v.vip in net}
        if len(vips) > 1:
            findings.append(Finding(
                "VRRP_VIP_MISMATCH", "major", f"VRRP virtual-address differs between members on {net}",
                tuple(sorted({m[0] for m in mem})),
                evidence=[f"{n} {un}: vip {v.vip}" for n, un, _, v in mem],
                fix=[(mem[-1][0], f"# align virtual-address with {sorted(vips)[0]}")],
                verify=[(n, "show vrrp detail") for n, *_ in mem],
                key=f"VRRP_VIP_MISMATCH:{net}"))
    return findings, masters


def _vip_guess(mem, net):
    c = Counter(v.vip for *_, v in mem if v.vip and v.vip in net)
    if c:
        return c.most_common(1)[0][0]
    return list(net.hosts())[0]
