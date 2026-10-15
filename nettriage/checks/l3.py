"""Layer-3 checks: addressing, OSPF adjacency formation and SPF reachability."""
from __future__ import annotations

import heapq
import ipaddress
from collections import defaultdict
from dataclasses import dataclass
from typing import Dict, List, Optional, Set, Tuple

from ..findings import Finding
from ..model import Device, Lab
from .l2 import logical_links, _link_up


def effective_router_id(dev: Device) -> Optional[ipaddress.IPv4Address]:
    if dev.router_id:
        return dev.router_id
    lo = dev.units.get("lo0.0")
    if lo and lo.address:
        return lo.address.ip
    addrs = sorted(a.ip for _, a in dev.addresses())
    return addrs[0] if addrs else None


@dataclass
class Adjacency:
    a: str
    a_unit: str
    b: str
    b_unit: str
    state: str          # Full | Down | ExStart | Init
    reason: str = ""


def check_addressing(lab: Lab) -> List[Finding]:
    findings = []
    owners: Dict[ipaddress.IPv4Address, List[Tuple[str, str]]] = defaultdict(list)
    for name, dev in lab.devices.items():
        for unit, addr in dev.addresses():
            owners[addr.ip].append((name, unit))
    for ip, own in sorted(owners.items()):
        if len(own) > 1:
            findings.append(Finding(
                "IP_DUPLICATE", "critical", f"Duplicate IP {ip} configured on {len(own)} interfaces",
                tuple(sorted({d for d, _ in own})),
                evidence=[f"{d} {u}: {ip}" for d, u in own] +
                         ["ARP for this address resolves to whichever device answered last (flapping MAC)"],
                fix=[(own[-1][0], f"# re-address {own[-1][1]} to a unique IP in its subnet")],
                verify=[(d, f"show arp no-resolve | match {ip}") for d, _ in own],
                key=f"IP_DUPLICATE:{ip}"))
    for da, pa, db, pb in logical_links(lab):
        ua = lab.devices[da].units.get(f"{pa}.0")
        ub = lab.devices[db].units.get(f"{pb}.0")
        if ua and ub and ua.address and ub.address and ua.address.network != ub.address.network:
            findings.append(Finding(
                "IP_SUBNET_MISMATCH", "critical",
                f"Subnet mismatch on {da} {ua.name} ({ua.address}) <-> {db} {ub.name} ({ub.address})",
                (da, db),
                evidence=[f"{da} {ua.name}: {ua.address.with_prefixlen} (net {ua.address.network})",
                          f"{db} {ub.name}: {ub.address.with_prefixlen} (net {ub.address.network})",
                          "neighbors are not on a common subnet: ARP fails and OSPF hellos are discarded"],
                fix=[(db, f"delete interfaces {pb} unit 0 family inet address {ub.address.with_prefixlen}"),
                     (db, f"set interfaces {pb} unit 0 family inet address "
                          f"{_suggest(ua.address, ub.address)}")],
                verify=[(da, f"ping {ub.address.ip} rapid count 5")],
                key=f"IP_SUBNET_MISMATCH:{da}:{ua.name}|{db}:{ub.name}"))
    return findings


def _suggest(ref: ipaddress.IPv4Interface, cur: ipaddress.IPv4Interface) -> str:
    for h in ref.network.hosts():
        if h != ref.ip:
            return f"{h}/{ref.network.prefixlen}"
    return cur.with_prefixlen


def check_ospf(lab: Lab, bundle_up, prior: List[Finding]) -> Tuple[List[Finding], List[Adjacency]]:
    findings: List[Finding] = []
    adjs: List[Adjacency] = []
    by_key = {f.key: f for f in prior}

    rids = defaultdict(list)
    for n, d in lab.devices.items():
        if d.ospf:
            rid = effective_router_id(d)
            rids[rid].append(n)
    dup_rid_key = {}
    for rid, devs in rids.items():
        if rid is not None and len(devs) > 1:
            k = f"ROUTER_ID_DUPLICATE:{rid}"
            for d in devs:
                dup_rid_key[d] = k
            findings.append(Finding(
                "ROUTER_ID_DUPLICATE", "critical", f"Router-ID {rid} shared by {', '.join(sorted(devs))}",
                tuple(sorted(devs)),
                evidence=[f"{d}: router-id {rid}" for d in sorted(devs)] +
                         ["OSPF neighbors reject hellos ('duplicate router id'); LSAs overwrite each other "
                          "and BGP rejects OPEN messages with the peer's own identifier"],
                fix=[(sorted(devs)[-1], f"set routing-options router-id <unique loopback of {sorted(devs)[-1]}>")],
                verify=[(d, "show ospf overview | match \"Router ID\"") for d in sorted(devs)],
                key=k))

    for da, pa, db, pb in logical_links(lab):
        A, B = lab.devices[da], lab.devices[db]
        ua, ub = f"{pa}.0", f"{pb}.0"
        oa, ob = A.ospf.get(ua), B.ospf.get(ub)
        if not oa and not ob:
            continue
        link_id = f"{da}:{ua}|{db}:{ub}"
        if bool(oa) != bool(ob):
            on, off, on_if, off_if = (da, db, ua, ub) if oa else (db, da, ub, ua)
            other_has_ospf = bool(lab.devices[off].ospf)
            if other_has_ospf:
                area = (oa or ob).area
                findings.append(Finding(
                    "OSPF_NOT_ENABLED", "critical",
                    f"OSPF enabled on {on} {on_if} but not on {off} {off_if}", (on, off),
                    evidence=[f"{off}: {off_if} missing under protocols ospf area {area}"],
                    fix=[(off, f"set protocols ospf area {area} interface {off_if}")],
                    verify=[(off, "show ospf neighbor")],
                    key=f"OSPF_NOT_ENABLED:{link_id}"))
                adjs.append(Adjacency(da, ua, db, ub, "Down", "OSPF_NOT_ENABLED"))
            continue

        def consequence(cause_key, state, why):
            adjs.append(Adjacency(da, ua, db, ub, state, why))
            findings.append(Finding(
                "OSPF_ADJ_DOWN", "major", f"OSPF adjacency {da} {ua} <-> {db} {ub} stuck in {state}",
                (da, db), evidence=[why],
                verify=[(da, f"show ospf neighbor interface {ua} extensive")],
                key=f"OSPF_ADJ_DOWN:{link_id}", caused_by=cause_key))

        roots = []
        if oa.passive or ob.passive:
            pas = [(d, u) for d, u, o in ((da, ua, oa), (db, ub, ob)) if o.passive]
            roots.append(Finding(
                "OSPF_PASSIVE_TRANSIT", "critical",
                f"Transit link {da} {ua} <-> {db} {ub} is passive: no hellos sent", (da, db),
                evidence=[f"{d} {u}: passive" for d, u in pas],
                fix=[(d, f"delete protocols ospf area {(oa if d == da else ob).area} interface {u} passive")
                     for d, u in pas],
                verify=[(da, "show ospf interface"), (da, "show ospf neighbor")],
                key=f"OSPF_PASSIVE_TRANSIT:{link_id}"))
        if oa.area != ob.area:
            roots.append(Finding(
                "OSPF_AREA_MISMATCH", "critical",
                f"OSPF area mismatch on {da} {ua} (area {oa.area}) <-> {db} {ub} (area {ob.area})",
                (da, db),
                evidence=[f"{da} {ua}: area {oa.area}", f"{db} {ub}: area {ob.area}",
                          "hellos carrying a different area id are dropped: neighbor never leaves Down"],
                fix=[(db, f"delete protocols ospf area {ob.area} interface {ub}"),
                     (db, f"set protocols ospf area {oa.area} interface {ub}")],
                verify=[(db, "show ospf neighbor"), (db, "show log messages | match OSPF")],
                key=f"OSPF_AREA_MISMATCH:{link_id}"))
        if (oa.hello, oa.dead) != (ob.hello, ob.dead):
            roots.append(Finding(
                "OSPF_TIMER_MISMATCH", "critical",
                f"OSPF hello/dead mismatch on {da} {ua} ({oa.hello}/{oa.dead}) <-> {db} {ub} ({ob.hello}/{ob.dead})",
                (da, db),
                evidence=[f"{da} {ua}: hello {oa.hello}s dead {oa.dead}s",
                          f"{db} {ub}: hello {ob.hello}s dead {ob.dead}s",
                          "RFC 2328 10.5: hellos with mismatched intervals are discarded"],
                fix=[(db, f"set protocols ospf area {ob.area} interface {ub} hello-interval {oa.hello}"),
                     (db, f"set protocols ospf area {ob.area} interface {ub} dead-interval {oa.dead}")],
                verify=[(db, f"show ospf interface {ub} detail")],
                key=f"OSPF_TIMER_MISMATCH:{link_id}"))
        if oa.if_type != ob.if_type:
            roots.append(Finding(
                "OSPF_NETTYPE_MISMATCH", "major",
                f"OSPF network-type mismatch on {da} {ua} ({oa.if_type}) <-> {db} {ub} ({ob.if_type})",
                (da, db),
                evidence=[f"{da} {ua}: {oa.if_type}", f"{db} {ub}: {ob.if_type}",
                          "adjacency may reach Full but router-LSA link types disagree: SPF drops the link"],
                fix=[(d, f"set protocols ospf area {o.area} interface {u} interface-type p2p")
                     for d, u, o in ((da, ua, oa), (db, ub, ob)) if o.if_type != "p2p"],
                verify=[(da, "show ospf route"), (da, "show ospf database router extensive")],
                key=f"OSPF_NETTYPE_MISMATCH:{link_id}"))
        # independent config mismatches are always reported, even when an upstream
        # problem (link down, subnet, duplicate router-id) also blocks the adjacency
        findings.extend(roots)
        if not (_link_up(lab, bundle_up, da, pa) and _link_up(lab, bundle_up, db, pb)):
            cause = next((f.key for f in prior if f.code.startswith("LACP") and {da, db} <= set(f.devices)), None)
            consequence(cause, "Down", "underlying link/bundle is down")
            continue
        k = f"IP_SUBNET_MISMATCH:{link_id}"
        if k in by_key:
            consequence(k, "Down", "hellos discarded: neighbor not on a common subnet")
            continue
        if da in dup_rid_key and dup_rid_key.get(db) == dup_rid_key[da]:
            consequence(dup_rid_key[da], "Down", "hello rejected: duplicate router id")
            continue
        if roots:
            adjs.append(Adjacency(da, ua, db, ub, "Down", roots[0].code))
            continue
        mk = f"MTU_MISMATCH:{da}:{pa}|{db}:{pb}"
        if mk in by_key:
            consequence(mk, "ExStart", "DBD packets exceed neighbor MTU: exchange never completes (ExStart/Exchange)")
            continue
        adjs.append(Adjacency(da, ua, db, ub, "Full"))
    return findings, adjs


class Rib:
    """Per-device OSPF reachability computed with Dijkstra over Full adjacencies."""

    def __init__(self, lab: Lab, adjs: List[Adjacency]):
        self.lab = lab
        self.graph: Dict[str, List[Tuple[str, int]]] = defaultdict(list)
        for a in adjs:
            if a.state == "Full":
                ca = lab.devices[a.a].ospf[a.a_unit].metric
                cb = lab.devices[a.b].ospf[a.b_unit].metric
                self.graph[a.a].append((a.b, ca))
                self.graph[a.b].append((a.a, cb))
        self.stubs: Dict[str, Set[ipaddress.IPv4Network]] = {}
        for n, d in lab.devices.items():
            nets = set()
            for unit in d.ospf:
                u = d.units.get(unit)
                if u and u.address:
                    nets.add(u.address.network)
            self.stubs[n] = nets
        self._cache: Dict[str, Dict[str, int]] = {}

    def spf(self, src: str) -> Dict[str, int]:
        if src in self._cache:
            return self._cache[src]
        dist = {src: 0}
        pq = [(0, src)]
        while pq:
            c, n = heapq.heappop(pq)
            if c > dist.get(n, 1 << 30):
                continue
            for m, w in self.graph[n]:
                if c + w < dist.get(m, 1 << 30):
                    dist[m] = c + w
                    heapq.heappush(pq, (c + w, m))
        self._cache[src] = dist
        return dist

    def connected(self, dev: str, ip) -> bool:
        return any(ip in a.network for _, a in self.lab.devices[dev].addresses())

    def reachable(self, src: str, ip) -> bool:
        if self.connected(src, ip):
            return True
        if not self.lab.devices[src].ospf:
            return False
        for n in self.spf(src):
            if any(ip in net for net in self.stubs[n]):
                return True
        return False

    def route_table(self, src: str) -> Dict[str, Tuple[int, str]]:
        out = {}
        for n, cost in sorted(self.spf(src).items(), key=lambda x: x[1]):
            for net in self.stubs[n]:
                out.setdefault(str(net), (cost, n))
        return out
