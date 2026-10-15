"""Layer-2 checks: LACP bundles, trunk/access consistency, MTU and RSTP root placement."""
from __future__ import annotations

from collections import defaultdict
from typing import Dict, List, Tuple

from ..findings import Finding
from ..model import Lab

LogicalLink = Tuple[str, str, str, str]  # devA, portA, devB, portB (ae or physical)


def logical_links(lab: Lab) -> List[LogicalLink]:
    seen = set()
    out = []
    for l in lab.links:
        a = lab.effective_port(l.a, l.a_port)
        b = lab.effective_port(l.b, l.b_port)
        key = tuple(sorted([(l.a, a), (l.b, b)]))
        if key in seen:
            continue
        seen.add(key)
        (da, pa), (db, pb) = key
        out.append((da, pa, db, pb))
    return out


def check_lacp(lab: Lab) -> Tuple[List[Finding], Dict[Tuple[str, str], bool]]:
    findings: List[Finding] = []
    bundle_up: Dict[Tuple[str, str], bool] = {}
    # members[(dev, ae)] -> list of (member_port, remote_dev, remote_port, remote_ae)
    members: Dict[Tuple[str, str], list] = defaultdict(list)
    for l in lab.links:
        for (d, p), (rd, rp) in (((l.a, l.a_port), (l.b, l.b_port)), ((l.b, l.b_port), (l.a, l.a_port))):
            ae = lab.devices[d].ports[p].ae_parent
            if ae:
                members[(d, ae)].append((p, rd, rp, lab.devices[rd].ports[rp].ae_parent))

    done = set()
    for (d, ae), mem in sorted(members.items()):
        good = [m for m in mem if m[3]]
        remotes = {(m[1], m[3]) for m in good}
        for p, rd, rp, rae in mem:
            if rae is None:
                target = next((x[3] for x in mem if x[1] == rd and x[3]), None)
                fix_ae = target or ae
                findings.append(Finding(
                    "LACP_MEMBER_MISMATCH", "major",
                    f"{d} {p} is a member of {ae} but {rd} {rp} is not in any bundle",
                    (d, rd),
                    evidence=[f"{d}: {p} -> 802.3ad {ae}", f"{rd}: {rp} -> standalone (no 802.3ad)",
                              f"{d} {p} will stay Attached/Detached, never Collecting-Distributing"],
                    fix=[(rd, f"set interfaces {rp} ether-options 802.3ad {fix_ae}")],
                    verify=[(d, f"show lacp interfaces {ae}"), (rd, f"show lacp interfaces {fix_ae}")],
                    key=f"LACP_MEMBER_MISMATCH:{d}:{p}|{rd}:{rp}"))
        if len(remotes) > 1:
            findings.append(Finding(
                "LACP_MEMBER_MISMATCH", "major",
                f"{d} {ae} members terminate on different remote bundles",
                (d,), evidence=[f"remote bundles: {sorted(remotes)}"],
                fix=[(d, f"# move all {ae} members to ports facing a single remote bundle")],
                verify=[(d, f"show lacp interfaces {ae}")],
                key=f"LACP_SPLIT:{d}:{ae}"))
        up = bool(good)
        for rd, rae in remotes:
            pair = tuple(sorted([(d, ae), (rd, rae)]))
            m1 = lab.devices[d].ports.get(ae)
            m2 = lab.devices[rd].ports.get(rae)
            l1 = m1.lacp if m1 else None
            l2 = m2.lacp if m2 else None
            if l1 == "passive" and l2 == "passive":
                up = False
                if pair not in done:
                    findings.append(Finding(
                        "LACP_BOTH_PASSIVE", "critical",
                        f"LACP passive on both ends of {d} {ae} <-> {rd} {rae}: bundle never negotiates",
                        (d, rd),
                        evidence=[f"{d} {ae}: lacp passive", f"{rd} {rae}: lacp passive",
                                  "passive partners never send LACPDUs, so no actor/partner exchange"],
                        fix=[(d, f"set interfaces {ae} aggregated-ether-options lacp active")],
                        verify=[(d, f"show lacp interfaces {ae}"), (d, f"show interfaces {ae} terse")],
                        key=f"LACP_BOTH_PASSIVE:{pair}"))
            elif (l1 is None) != (l2 is None):
                up = False
                if pair not in done:
                    static, dyn = ((d, ae), (rd, rae)) if l1 is None else ((rd, rae), (d, ae))
                    findings.append(Finding(
                        "LACP_MODE_MISMATCH", "critical",
                        f"{static[0]} {static[1]} is a static LAG but {dyn[0]} {dyn[1]} runs LACP",
                        (d, rd),
                        evidence=[f"{static[0]} {static[1]}: no aggregated-ether-options lacp",
                                  f"{dyn[0]} {dyn[1]}: lacp {l1 or l2}"],
                        fix=[(static[0], f"set interfaces {static[1]} aggregated-ether-options lacp active")],
                        verify=[(static[0], f"show lacp interfaces {static[1]}")],
                        key=f"LACP_MODE_MISMATCH:{pair}"))
            done.add(pair)
        bundle_up[(d, ae)] = up
    return findings, bundle_up


def _link_up(lab: Lab, bundle_up, d, p) -> bool:
    port = lab.devices[d].ports.get(p)
    if port and port.disabled:
        return False
    if p.startswith("ae"):
        return bundle_up.get((d, p), False)
    return True


def check_l2_links(lab: Lab, bundle_up) -> List[Finding]:
    findings: List[Finding] = []
    for da, pa, db, pb in logical_links(lab):
        A, B = lab.devices[da], lab.devices[db]
        # MTU
        ma, mb = A.ports[pa].mtu, B.ports[pb].mtu
        if ma != mb:
            low, high = ((da, pa, ma), (db, pb, mb)) if ma < mb else ((db, pb, mb), (da, pa, ma))
            findings.append(Finding(
                "MTU_MISMATCH", "major",
                f"MTU mismatch on {da} {pa} ({ma}) <-> {db} {pb} ({mb})", (da, db),
                evidence=[f"{da} {pa}: mtu {ma}", f"{db} {pb}: mtu {mb}",
                          "frames larger than the smaller MTU are dropped; OSPF DBD exchange stalls in ExStart"],
                fix=[(low[0], f"set interfaces {low[1]} mtu {high[2]}")],
                verify=[(da, f"show interfaces {pa} | match MTU"), (db, f"show interfaces {pb} | match MTU")],
                key=f"MTU_MISMATCH:{da}:{pa}|{db}:{pb}"))
        ua, ub = A.units.get(f"{pa}.0"), B.units.get(f"{pb}.0")
        if not ua or not ub or not ua.l2_mode or not ub.l2_mode:
            continue
        if ua.l2_mode != ub.l2_mode:
            acc, trk = ((da, pa, ua), (db, pb, ub)) if ua.l2_mode == "access" else ((db, pb, ub), (da, pa, ua))
            findings.append(Finding(
                "L2_MODE_MISMATCH", "critical",
                f"{acc[0]} {acc[1]} is access but {trk[0]} {trk[1]} is trunk", (da, db),
                evidence=[f"{acc[0]} {acc[1]}.0: interface-mode access", f"{trk[0]} {trk[1]}.0: interface-mode trunk",
                          "tagged frames from the trunk are dropped on the access port"],
                fix=[(acc[0], f"set interfaces {acc[1]} unit 0 family ethernet-switching interface-mode trunk")]
                + [(acc[0], f"set interfaces {acc[1]} unit 0 family ethernet-switching vlan members {v}")
                   for v in trk[2].vlans if v not in acc[2].vlans],
                verify=[(acc[0], f"show ethernet-switching interface {acc[1]}")],
                key=f"L2_MODE_MISMATCH:{da}:{pa}|{db}:{pb}"))
            continue
        va, vb = set(A.vlan_ids(ua)), set(B.vlan_ids(ub))
        if va != vb:
            if ua.l2_mode == "access":
                findings.append(Finding(
                    "ACCESS_VLAN_MISMATCH", "major",
                    f"Access VLAN mismatch {da} {pa} ({sorted(va)}) <-> {db} {pb} ({sorted(vb)})", (da, db),
                    evidence=["untagged traffic is bridged between two different VLANs (VLAN leak)"],
                    fix=[(db, f"set interfaces {pb} unit 0 family ethernet-switching vlan members {sorted(va)[0]}")],
                    verify=[(db, f"show ethernet-switching interface {pb}")],
                    key=f"ACCESS_VLAN_MISMATCH:{da}:{pa}|{db}:{pb}"))
                continue
            fixes, ev = [], []
            for (dev, port, have, other_dev) in ((A, pa, va, B), (B, pb, vb, A)):
                missing = sorted((va | vb) - have)
                if missing:
                    ev.append(f"{dev.hostname} {port}.0 does not carry VLAN(s) {missing}")
                    names = {vid: n for n, vid in dev.vlans.items()}
                    for vid in missing:
                        fixes.append((dev.hostname,
                                      f"set interfaces {port} unit 0 family ethernet-switching vlan members {names.get(vid, vid)}"))
            findings.append(Finding(
                "TRUNK_VLAN_MISMATCH", "major",
                f"Trunk VLAN list mismatch on {da} {pa} <-> {db} {pb}", (da, db),
                evidence=ev + ["the missing VLAN is pruned on this link; hosts in it lose this path"],
                fix=fixes, verify=[(da, f"show ethernet-switching interface {pa}"),
                                   (db, f"show ethernet-switching interface {pb}")],
                key=f"TRUNK_VLAN_MISMATCH:{da}:{pa}|{db}:{pb}"))
    return findings


def stp_root(lab: Lab, bundle_up) -> Tuple[str, Dict[str, int]]:
    """Elect the RSTP root over bridges joined by up L2 links. Returns (root, cost-to-root)."""
    bridges = {n: d for n, d in lab.devices.items() if d.rstp_priority is not None}
    if not bridges:
        return "", {}
    adj = defaultdict(set)
    for da, pa, db, pb in logical_links(lab):
        if da in bridges and db in bridges and _link_up(lab, bundle_up, da, pa) and _link_up(lab, bundle_up, db, pb):
            ua, ub = lab.devices[da].units.get(f"{pa}.0"), lab.devices[db].units.get(f"{pb}.0")
            if ua and ub and ua.l2_mode and ub.l2_mode:
                adj[da].add(db)
                adj[db].add(da)
    root = min(bridges, key=lambda n: (bridges[n].rstp_priority, bridges[n].system_mac))
    # BFS hop distance (uniform port cost) for the report
    dist, frontier = {root: 0}, [root]
    while frontier:
        nxt = []
        for n in frontier:
            for m in adj[n]:
                if m not in dist:
                    dist[m] = dist[n] + 1
                    nxt.append(m)
        frontier = nxt
    return root, dist


def check_stp(lab: Lab, bundle_up) -> List[Finding]:
    root, _ = stp_root(lab, bundle_up)
    if not root:
        return []
    gateways = [n for n, d in lab.devices.items()
                if d.rstp_priority is not None and any(u.name.startswith("irb") and u.address for u in d.units.values())]
    if not gateways or root in gateways:
        return []
    # intended root: gateway that is VRRP master most often (highest priority), tie -> lowest bridge prio
    def vrrp_weight(n):
        return -sum(v.priority for u in lab.devices[n].units.values() for v in u.vrrp)
    intended = min(gateways, key=lambda n: (vrrp_weight(n), lab.devices[n].rstp_priority, n))
    r = lab.devices[root]
    return [Finding(
        "STP_ROOT_MISPLACED", "major",
        f"RSTP root bridge is access switch {root}, not a gateway (expected {intended})",
        (root, intended),
        evidence=[f"{root}: bridge-priority {r.rstp_priority}",
                  f"{intended}: bridge-priority {lab.devices[intended].rstp_priority}",
                  "traffic to the default gateway takes a suboptimal path through the access layer"],
        fix=[(root, "delete protocols rstp bridge-priority"),
             (intended, "set protocols rstp bridge-priority 4k")],
        verify=[(intended, "show spanning-tree bridge"), (root, "show spanning-tree interface")],
        key=f"STP_ROOT_MISPLACED:{root}")]
