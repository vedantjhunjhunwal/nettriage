"""Reproducible lab generator + fault injector.

Builds a 6-device campus/WAN topology (2 core L3 switches, 2 access switches,
1 edge router, 1 ISP router) with OSPF, iBGP over loopbacks, eBGP, LACP
trunks, RSTP and VRRP. Addressing, ASNs, VLAN-ids, VRRP groups and port
numbers are randomised per seed so the checks cannot key off constants.
Faults are injected by editing the set-path config, exactly like a bad
commit would.
"""
from __future__ import annotations

import ipaddress
import os
import random
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Set, Tuple

from . import junos

Paths = Dict[str, List[tuple]]


@dataclass
class Ctx:
    rng: random.Random
    paths: Paths
    links: List[Tuple[str, str, str, str]]
    p2p: List[Tuple[str, str, str, str]] = field(default_factory=list)       # L3 links (dev, port, dev, port)
    bundles: List[Tuple[str, str, str, str, List[Tuple[str, str]]]] = field(default_factory=list)
    ibgp: List[str] = field(default_factory=list)
    lo: Dict[str, str] = field(default_factory=dict)
    asn: int = 0
    isp_as: int = 0
    vlans: Dict[str, int] = field(default_factory=dict)
    vrrp: Dict[str, int] = field(default_factory=dict)  # vlan name -> group
    irb: Dict[Tuple[str, str], str] = field(default_factory=dict)  # (dev, vlan) -> addr/len
    vip: Dict[str, str] = field(default_factory=dict)


def baseline(seed: int) -> Ctx:
    rng = random.Random(seed)
    P: Paths = {d: [] for d in ("core1", "core2", "acc1", "acc2", "edge1", "isp1")}
    ctx = Ctx(rng, P, [])
    o2 = rng.randint(1, 250)
    ctx.asn = rng.randint(64512, 65534)
    ctx.isp_as = rng.choice([x for x in range(64496, 64511)])
    vids = rng.sample(range(10, 3000), 2)
    ctx.vlans = {f"v{vids[0]}": vids[0], f"v{vids[1]}": vids[1]}
    groups = rng.sample(range(1, 255), 2)
    ctx.vrrp = {n: g for n, g in zip(ctx.vlans, groups)}

    ports = {d: [f"ge-0/0/{i}" for i in rng.sample(range(0, 24), 12)] for d in P}

    def port(d):
        return ports[d].pop()

    def S(d, *t):
        P[d].append(tuple(str(x) for x in t))

    for d in P:
        S(d, "system", "host-name", d)

    # loopbacks / router-ids
    for i, d in enumerate(("core1", "core2", "edge1", "isp1"), 1):
        ctx.lo[d] = f"10.{o2}.255.{i}"
        S(d, "interfaces", "lo0", "unit", 0, "family", "inet", "address", f"{ctx.lo[d]}/32")
        S(d, "routing-options", "router-id", ctx.lo[d])
    for d in ("core1", "core2", "edge1"):
        S(d, "routing-options", "autonomous-system", ctx.asn)
    S("isp1", "routing-options", "autonomous-system", ctx.isp_as)

    # L3 point-to-point links (OSPF area 0, p2p)
    sub = iter(ipaddress.IPv4Network(f"10.{o2}.0.0/24").subnets(new_prefix=30))
    for a, b in (("core1", "core2"), ("core1", "edge1"), ("core2", "edge1")):
        net = next(sub)
        h = list(net.hosts())
        pa, pb = port(a), port(b)
        for d, p, ip in ((a, pa, h[0]), (b, pb, h[1])):
            S(d, "interfaces", p, "unit", 0, "family", "inet", "address", f"{ip}/30")
            S(d, "protocols", "ospf", "area", "0.0.0.0", "interface", f"{p}.0", "interface-type", "p2p")
        ctx.links.append((a, pa, b, pb))
        ctx.p2p.append((a, pa, b, pb))
    for d in ("core1", "core2", "edge1"):
        S(d, "protocols", "ospf", "area", "0.0.0.0", "interface", "lo0.0", "passive")

    # eBGP edge1 <-> isp1
    net = next(sub)
    h = list(net.hosts())
    pe, pi = port("edge1"), port("isp1")
    S("edge1", "interfaces", pe, "unit", 0, "family", "inet", "address", f"{h[0]}/30")
    S("isp1", "interfaces", pi, "unit", 0, "family", "inet", "address", f"{h[1]}/30")
    ctx.links.append(("edge1", pe, "isp1", pi))
    S("edge1", "protocols", "bgp", "group", "TRANSIT", "type", "external")
    S("edge1", "protocols", "bgp", "group", "TRANSIT", "neighbor", h[1], "peer-as", ctx.isp_as)
    S("isp1", "protocols", "bgp", "group", "CUSTOMER", "type", "external")
    S("isp1", "protocols", "bgp", "group", "CUSTOMER", "neighbor", h[0], "peer-as", ctx.asn)

    # iBGP full mesh over loopbacks
    ctx.ibgp = ["core1", "core2", "edge1"]
    for d in ctx.ibgp:
        S(d, "protocols", "bgp", "group", "IBGP", "type", "internal")
        S(d, "protocols", "bgp", "group", "IBGP", "local-address", ctx.lo[d])
        for n in ctx.ibgp:
            if n != d:
                S(d, "protocols", "bgp", "group", "IBGP", "neighbor", ctx.lo[n])

    # VLANs, IRB + VRRP on cores
    for d in ("core1", "core2", "acc1", "acc2"):
        for name, vid in ctx.vlans.items():
            S(d, "vlans", name, "vlan-id", vid)
    for k, (name, vid) in enumerate(ctx.vlans.items()):
        net = ipaddress.IPv4Network(f"172.{16 + k}.{rng.randint(0, 255)}.0/24")
        h = list(net.hosts())
        ctx.vip[name] = str(h[0])
        for d, ip, prio in (("core1", h[1], 200), ("core2", h[2], 100)):
            addr = f"{ip}/24"
            ctx.irb[(d, name)] = addr
            base = ("interfaces", "irb", "unit", vid, "family", "inet", "address", addr)
            S(d, *base)
            S(d, *base, "vrrp-group", ctx.vrrp[name], "virtual-address", h[0])
            S(d, *base, "vrrp-group", ctx.vrrp[name], "priority", prio)
            S(d, *base, "vrrp-group", ctx.vrrp[name], "preempt")
            S(d, "vlans", name, "l3-interface", f"irb.{vid}")
            S(d, "protocols", "ospf", "area", "0.0.0.0", "interface", f"irb.{vid}", "passive")

    # LACP trunks: core1-core2 ae0, coreX-accY
    ae_next = {d: 0 for d in P}
    for a, b in (("core1", "core2"), ("core1", "acc1"), ("core1", "acc2"), ("core2", "acc1"), ("core2", "acc2")):
        aea, aeb = f"ae{ae_next[a]}", f"ae{ae_next[b]}"
        ae_next[a] += 1
        ae_next[b] += 1
        mem = []
        for _ in range(2):
            pa, pb = port(a), port(b)
            S(a, "interfaces", pa, "ether-options", "802.3ad", aea)
            S(b, "interfaces", pb, "ether-options", "802.3ad", aeb)
            ctx.links.append((a, pa, b, pb))
            mem.append((pa, pb))
        for d, ae in ((a, aea), (b, aeb)):
            S(d, "interfaces", ae, "aggregated-ether-options", "lacp", "active")
            S(d, "interfaces", ae, "unit", 0, "family", "ethernet-switching", "interface-mode", "trunk")
            for name in ctx.vlans:
                S(d, "interfaces", ae, "unit", 0, "family", "ethernet-switching", "vlan", "members", name)
            S(d, "protocols", "rstp", "interface", ae)
        ctx.bundles.append((a, aea, b, aeb, mem))
    S("core1", "protocols", "rstp", "bridge-priority", "4k")
    S("core2", "protocols", "rstp", "bridge-priority", "8k")
    for d in ("acc1", "acc2"):
        for i, name in enumerate(ctx.vlans):
            p = port(d)
            S(d, "interfaces", p, "unit", 0, "family", "ethernet-switching", "interface-mode", "access")
            S(d, "interfaces", p, "unit", 0, "family", "ethernet-switching", "vlan", "members", name)
    return ctx


# ---------------------------------------------------------------- fault helpers

def _replace(ctx, dev, match: Callable[[tuple], bool], fn: Callable[[tuple], tuple]):
    ctx.paths[dev] = [fn(p) if match(p) else p for p in ctx.paths[dev]]


def _drop(ctx, dev, match):
    ctx.paths[dev] = [p for p in ctx.paths[dev] if not match(p)]


def _end(ctx, link):
    a, pa, b, pb = link
    return (a, pa) if ctx.rng.random() < 0.5 else (b, pb)


def _ospf_link(ctx):
    link = ctx.rng.choice(ctx.p2p)
    return link, _end(ctx, link)


def f_ospf_area(ctx):
    _, (d, p) = _ospf_link(ctx)
    _replace(ctx, d, lambda t: t[:3] == ("protocols", "ospf", "area") and t[5] == f"{p}.0",
             lambda t: t[:3] + ("0.0.0.1",) + t[4:])
    return {"OSPF_AREA_MISMATCH"}


def f_ospf_timers(ctx):
    _, (d, p) = _ospf_link(ctx)
    ctx.paths[d] += [("protocols", "ospf", "area", "0.0.0.0", "interface", f"{p}.0", "hello-interval", "5"),
                     ("protocols", "ospf", "area", "0.0.0.0", "interface", f"{p}.0", "dead-interval", "20")]
    return {"OSPF_TIMER_MISMATCH"}


def f_mtu(ctx):
    _, (d, p) = _ospf_link(ctx)
    ctx.paths[d].append(("interfaces", p, "mtu", "9192"))
    return {"MTU_MISMATCH"}


def f_ospf_nettype(ctx):
    _, (d, p) = _ospf_link(ctx)
    # `delete ... interface-type` leaves a bare `interface X;` (default broadcast)
    _replace(ctx, d, lambda t: t[:3] == ("protocols", "ospf", "area") and t[5] == f"{p}.0" and "interface-type" in t,
             lambda t: t[:6])
    return {"OSPF_NETTYPE_MISMATCH"}


def f_ospf_passive(ctx):
    _, (d, p) = _ospf_link(ctx)
    ctx.paths[d].append(("protocols", "ospf", "area", "0.0.0.0", "interface", f"{p}.0", "passive"))
    return {"OSPF_PASSIVE_TRANSIT"}


def f_ospf_missing(ctx):
    _, (d, p) = _ospf_link(ctx)
    _drop(ctx, d, lambda t: t[:3] == ("protocols", "ospf", "area") and t[5] == f"{p}.0")
    return {"OSPF_NOT_ENABLED"}


def f_subnet(ctx):
    _, (d, p) = _ospf_link(ctx)
    new = f"172.31.{ctx.rng.randint(0, 255)}.{ctx.rng.choice([1, 5, 9])}/30"
    _replace(ctx, d, lambda t: t[:2] == ("interfaces", p) and "address" in t,
             lambda t: t[:t.index("address") + 1] + (new,))
    return {"IP_SUBNET_MISMATCH"}


def f_dup_ip(ctx):
    name = ctx.rng.choice(list(ctx.vlans))
    src, dst = ("core1", "core2") if ctx.rng.random() < 0.5 else ("core2", "core1")
    old, new = ctx.irb[(dst, name)], ctx.irb[(src, name)]
    _replace(ctx, dst, lambda t: old in t, lambda t: tuple(new if x == old else x for x in t))
    return {"IP_DUPLICATE"}


def f_dup_rid(ctx):
    a, b = ctx.rng.sample(ctx.ibgp, 2)
    _replace(ctx, b, lambda t: t[:2] == ("routing-options", "router-id"), lambda t: t[:2] + (ctx.lo[a],))
    return {"ROUTER_ID_DUPLICATE"}


def f_peer_as(ctx):
    if ctx.rng.random() < 0.5:
        _replace(ctx, "edge1", lambda t: "TRANSIT" in t and "peer-as" in t, lambda t: t[:-1] + (str(ctx.isp_as + 1),))
    else:
        _replace(ctx, "isp1", lambda t: "CUSTOMER" in t and "peer-as" in t, lambda t: t[:-1] + (str(ctx.asn + 1),))
    return {"BGP_PEER_AS_MISMATCH"}


def f_bgp_neighbor_missing(ctx):
    a, b = ctx.rng.sample(ctx.ibgp, 2)
    _drop(ctx, a, lambda t: t[:4] == ("protocols", "bgp", "group", "IBGP") and t[4:6] == ("neighbor", ctx.lo[b]))
    return {"BGP_NEIGHBOR_MISSING"}


def f_bgp_local_address(ctx):
    d = ctx.rng.choice(ctx.ibgp)
    _drop(ctx, d, lambda t: t[:4] == ("protocols", "bgp", "group", "IBGP") and t[4] == "local-address")
    return {"BGP_SOURCE_MISMATCH"}


def f_loopback_igp(ctx):
    d = ctx.rng.choice(ctx.ibgp)
    _drop(ctx, d, lambda t: t[:3] == ("protocols", "ospf", "area") and t[5] == "lo0.0")
    return {"IGP_LOOPBACK_MISSING"}


def _bundle(ctx):
    return ctx.rng.choice(ctx.bundles)


def f_lacp_passive(ctx):
    a, aea, b, aeb, _ = _bundle(ctx)
    for d, ae in ((a, aea), (b, aeb)):
        _replace(ctx, d, lambda t: t[:4] == ("interfaces", ae, "aggregated-ether-options", "lacp"),
                 lambda t: t[:4] + ("passive",))
    return {"LACP_BOTH_PASSIVE"}


def f_lacp_static(ctx):
    a, aea, b, aeb, _ = _bundle(ctx)
    d, ae = (a, aea) if ctx.rng.random() < 0.5 else (b, aeb)
    _drop(ctx, d, lambda t: t[:4] == ("interfaces", ae, "aggregated-ether-options", "lacp"))
    return {"LACP_MODE_MISMATCH"}


def f_lacp_member(ctx):
    a, aea, b, aeb, mem = _bundle(ctx)
    pa, pb = ctx.rng.choice(mem)
    d, p = (a, pa) if ctx.rng.random() < 0.5 else (b, pb)
    _drop(ctx, d, lambda t: t[:2] == ("interfaces", p) and "802.3ad" in t)
    return {"LACP_MEMBER_MISMATCH"}


def f_trunk_vlan(ctx):
    a, aea, b, aeb, _ = _bundle(ctx)
    d, ae = (a, aea) if ctx.rng.random() < 0.5 else (b, aeb)
    name = ctx.rng.choice(list(ctx.vlans))
    _drop(ctx, d, lambda t: t[:2] == ("interfaces", ae) and t[-2:] == ("members", name))
    return {"TRUNK_VLAN_MISMATCH"}


def f_l2_mode(ctx):
    a, aea, b, aeb, _ = ctx.rng.choice([x for x in ctx.bundles if x[2].startswith("acc")])
    keep = ctx.rng.choice(list(ctx.vlans))
    _replace(ctx, b, lambda t: t[:2] == ("interfaces", aeb) and "interface-mode" in t,
             lambda t: t[:-1] + ("access",))
    _drop(ctx, b, lambda t: t[:2] == ("interfaces", aeb) and "members" in t and t[-1] != keep)
    return {"L2_MODE_MISMATCH"}


def f_stp_root(ctx):
    d = ctx.rng.choice(["acc1", "acc2"])
    ctx.paths[d].append(("protocols", "rstp", "bridge-priority", "0"))
    return {"STP_ROOT_MISPLACED"}


def f_vrrp_group(ctx):
    name = ctx.rng.choice(list(ctx.vlans))
    d = ctx.rng.choice(["core1", "core2"])
    g = str(ctx.vrrp[name])
    new = str(ctx.vrrp[name] % 254 + 1)
    addr = ctx.irb[(d, name)]
    _replace(ctx, d, lambda t: addr in t and "vrrp-group" in t,
             lambda t: tuple(new if (i > 0 and t[i - 1] == "vrrp-group") else x for i, x in enumerate(t)))
    return {"VRRP_GROUP_MISMATCH"}


def f_vrrp_vip(ctx):
    name = ctx.rng.choice(list(ctx.vlans))
    d = ctx.rng.choice(["core1", "core2"])
    addr = ctx.irb[(d, name)]
    _replace(ctx, d, lambda t: addr in t and "virtual-address" in t,
             lambda t: t[:-1] + (f"192.168.{ctx.rng.randint(0, 255)}.1",))
    return {"VRRP_VIP_OUTSIDE_SUBNET"}


FAULTS: Dict[str, Callable[[Ctx], Set[str]]] = {
    "ospf_area": f_ospf_area, "ospf_timers": f_ospf_timers, "mtu": f_mtu, "ospf_nettype": f_ospf_nettype,
    "ospf_passive": f_ospf_passive, "ospf_missing": f_ospf_missing, "subnet": f_subnet, "dup_ip": f_dup_ip,
    "dup_router_id": f_dup_rid, "bgp_peer_as": f_peer_as, "bgp_neighbor_missing": f_bgp_neighbor_missing,
    "bgp_local_address": f_bgp_local_address, "loopback_not_in_igp": f_loopback_igp,
    "lacp_both_passive": f_lacp_passive, "lacp_mode": f_lacp_static, "lacp_member": f_lacp_member,
    "trunk_vlan": f_trunk_vlan, "l2_mode": f_l2_mode, "stp_root": f_stp_root,
    "vrrp_group": f_vrrp_group, "vrrp_vip": f_vrrp_vip,
}

# faults that touch the same objects and would mask each other are not combined
_FAMILY = {k: k.split("_")[0] for k in FAULTS}
_FAMILY.update({"mtu": "ospf", "subnet": "ospf", "dup_router_id": "bgp", "loopback_not_in_igp": "bgp",
                "dup_ip": "vrrp", "trunk_vlan": "lacp", "l2_mode": "lacp", "stp_root": "lacp"})


def compatible(f1: str, f2: str) -> bool:
    return _FAMILY[f1] != _FAMILY[f2]


def write_lab(ctx: Ctx, out: str, fmt: str = "mixed"):
    os.makedirs(os.path.join(out, "configs"), exist_ok=True)
    for i, (d, paths) in enumerate(sorted(ctx.paths.items())):
        style = fmt if fmt != "mixed" else ("set" if i % 3 == 2 else "curly")
        text = junos.to_set_lines(paths) + "\n" if style == "set" else junos.render_hierarchical(paths)
        with open(os.path.join(out, "configs", f"{d}.conf"), "w") as f:
            f.write(text)
    with open(os.path.join(out, "links.txt"), "w") as f:
        f.write("# devA portA -- devB portB\n")
        for a, pa, b, pb in ctx.links:
            f.write(f"{a} {pa} -- {b} {pb}\n")


def make(seed: int, faults: List[str]) -> Tuple[Ctx, Set[str]]:
    ctx = baseline(seed)
    expected: Set[str] = set()
    for f in faults:
        expected |= FAULTS[f](ctx)
    return ctx, expected
