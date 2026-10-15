"""Device and topology model built from parsed Junos set paths."""
from __future__ import annotations

import hashlib
import ipaddress
import os
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from . import junos

DEFAULT_MTU = 1514          # Junos default media MTU on GE ports
DEFAULT_RSTP_PRIORITY = 32768


@dataclass
class Vrrp:
    group: int
    vip: Optional[ipaddress.IPv4Address] = None
    priority: int = 100
    preempt: bool = False


@dataclass
class Unit:
    name: str                                  # logical name, e.g. ge-0/0/0.0, irb.10
    address: Optional[ipaddress.IPv4Interface] = None
    l2_mode: Optional[str] = None              # access | trunk (family ethernet-switching)
    vlans: List[str] = field(default_factory=list)
    vrrp: List[Vrrp] = field(default_factory=list)


@dataclass
class Port:
    name: str
    mtu: int = DEFAULT_MTU
    ae_parent: Optional[str] = None            # member of aeX via 802.3ad
    lacp: Optional[str] = None                 # active | passive (on aeX)
    disabled: bool = False


@dataclass
class OspfIf:
    unit: str
    area: str
    hello: int = 10
    dead: int = 40
    if_type: str = "broadcast"
    passive: bool = False
    metric: int = 1


@dataclass
class BgpNeighbor:
    peer: ipaddress.IPv4Address
    group: str
    type: str                                  # internal | external
    peer_as: Optional[int]
    local_address: Optional[ipaddress.IPv4Address]


@dataclass
class Device:
    hostname: str
    ports: Dict[str, Port] = field(default_factory=dict)
    units: Dict[str, Unit] = field(default_factory=dict)
    router_id: Optional[ipaddress.IPv4Address] = None
    asn: Optional[int] = None
    ospf: Dict[str, OspfIf] = field(default_factory=dict)
    bgp: List[BgpNeighbor] = field(default_factory=list)
    rstp_priority: Optional[int] = None        # None => RSTP not configured
    vlans: Dict[str, int] = field(default_factory=dict)   # name -> vlan-id
    vlan_l3: Dict[str, str] = field(default_factory=dict) # vlan name -> irb unit

    @property
    def system_mac(self) -> str:
        h = hashlib.sha1(self.hostname.encode()).hexdigest()[:12]
        return ":".join(h[i:i + 2] for i in range(0, 12, 2))

    def port(self, name: str) -> Port:
        return self.ports.setdefault(name, Port(name))

    def unit(self, name: str) -> Unit:
        return self.units.setdefault(name, Unit(name))

    def addresses(self) -> List[Tuple[str, ipaddress.IPv4Interface]]:
        return [(u.name, u.address) for u in self.units.values() if u.address]

    def owns(self, ip: ipaddress.IPv4Address) -> Optional[str]:
        for name, a in self.addresses():
            if a.ip == ip:
                return name
        return None

    def vlan_ids(self, unit: Unit) -> List[int]:
        out = []
        for v in unit.vlans:
            if v.isdigit():
                out.append(int(v))
            elif v in self.vlans:
                out.append(self.vlans[v])
        return sorted(out)


def _rstp_priority(tok: str) -> int:
    tok = tok.lower()
    return int(tok[:-1]) * 1024 if tok.endswith("k") else int(tok)


def build_device(paths: List[junos.SetPath], default_name: str = "unknown") -> Device:
    dev = Device(hostname=default_name)
    bgp_groups: Dict[str, dict] = {}
    bgp_neighbors: List[Tuple[str, str, Optional[int]]] = []

    for p in paths:
        if p[:2] == ("system", "host-name"):
            dev.hostname = p[2]

        elif p[0] == "interfaces" and len(p) >= 3:
            ifname = p[1]
            rest = p[2:]
            if rest[0] == "disable":
                dev.port(ifname).disabled = True
            elif rest[0] == "mtu":
                dev.port(ifname).mtu = int(rest[1])
            elif rest[0] in ("ether-options", "gigether-options") and rest[1:2] == ("802.3ad",):
                dev.port(ifname).ae_parent = rest[2]
            elif rest[:2] == ("aggregated-ether-options", "lacp"):
                dev.port(ifname).lacp = rest[2] if len(rest) > 2 else "active"
            elif rest[0] == "unit":
                dev.port(ifname)
                uname = f"{ifname}.{rest[1]}"
                u = dev.unit(uname)
                r = rest[2:]
                if r[:3] == ("family", "inet", "address"):
                    addr = ipaddress.IPv4Interface(r[3])
                    if u.address is None or u.address == addr:
                        u.address = addr
                    vr = r[4:]
                    if vr[:1] == ("vrrp-group",):
                        g = int(vr[1])
                        inst = next((x for x in u.vrrp if x.group == g), None)
                        if inst is None:
                            inst = Vrrp(g)
                            u.vrrp.append(inst)
                        if vr[2:3] == ("virtual-address",):
                            inst.vip = ipaddress.IPv4Address(vr[3])
                        elif vr[2:3] == ("priority",):
                            inst.priority = int(vr[3])
                        elif vr[2:3] == ("preempt",):
                            inst.preempt = True
                elif r[:2] == ("family", "ethernet-switching"):
                    s = r[2:]
                    if s[:1] in (("interface-mode",), ("port-mode",)):
                        u.l2_mode = s[1]
                    elif s[:2] == ("vlan", "members"):
                        u.vlans.append(s[2])
                    elif u.l2_mode is None:
                        u.l2_mode = "access"
                    if u.l2_mode is None:
                        u.l2_mode = "access"

        elif p[0] == "vlans" and len(p) >= 4:
            if p[2] == "vlan-id":
                dev.vlans[p[1]] = int(p[3])
            elif p[2] == "l3-interface":
                dev.vlan_l3[p[1]] = p[3]

        elif p[:2] == ("routing-options", "router-id"):
            dev.router_id = ipaddress.IPv4Address(p[2])
        elif p[:2] == ("routing-options", "autonomous-system"):
            dev.asn = int(p[2])

        elif p[:3] == ("protocols", "ospf", "area") and len(p) >= 6 and p[4] == "interface":
            area, ifn = p[3], p[5]
            if "." not in ifn:
                ifn += ".0"
            o = dev.ospf.setdefault(ifn, OspfIf(ifn, area))
            o.area = area
            r = p[6:]
            if r[:1] == ("passive",):
                o.passive = True
            elif r[:1] == ("hello-interval",):
                o.hello = int(r[1])
            elif r[:1] == ("dead-interval",):
                o.dead = int(r[1])
            elif r[:1] == ("interface-type",):
                o.if_type = r[1]
            elif r[:1] == ("metric",):
                o.metric = int(r[1])

        elif p[:3] == ("protocols", "bgp", "group") and len(p) >= 6:
            g = bgp_groups.setdefault(p[3], {"type": None, "peer_as": None, "local": None})
            r = p[4:]
            if r[0] == "type":
                g["type"] = r[1]
            elif r[0] == "peer-as":
                g["peer_as"] = int(r[1])
            elif r[0] == "local-address":
                g["local"] = ipaddress.IPv4Address(r[1])
            elif r[0] == "neighbor":
                pas = int(r[3]) if r[2:3] == ("peer-as",) else None
                bgp_neighbors.append((p[3], r[1], pas))

        elif p[:2] == ("protocols", "rstp"):
            if dev.rstp_priority is None:
                dev.rstp_priority = DEFAULT_RSTP_PRIORITY
            if p[2:3] == ("bridge-priority",):
                dev.rstp_priority = _rstp_priority(p[3])

    # default MTU for ae bundle members follows the bundle
    for port in dev.ports.values():
        if port.ae_parent and port.ae_parent in dev.ports:
            port.mtu = dev.ports[port.ae_parent].mtu

    seen = {}
    for group, peer, pas in bgp_neighbors:
        g = bgp_groups[group]
        key = (group, peer)
        n = seen.get(key)
        if n is None:
            n = BgpNeighbor(ipaddress.IPv4Address(peer), group, g["type"] or "external",
                            g["peer_as"], g["local"])
            seen[key] = n
            dev.bgp.append(n)
        if pas is not None:
            n.peer_as = pas
    for n in dev.bgp:
        if n.type == "internal":
            n.peer_as = dev.asn
    return dev


# ---------------------------------------------------------------- topology

@dataclass(frozen=True)
class Link:
    a: str
    a_port: str
    b: str
    b_port: str

    def ends(self):
        return ((self.a, self.a_port), (self.b, self.b_port))


@dataclass
class Lab:
    devices: Dict[str, Device]
    links: List[Link]
    captures: List[str] = field(default_factory=list)
    name: str = "lab"

    def peer_of(self, dev: str, port: str) -> Optional[Tuple[str, str]]:
        for l in self.links:
            if (l.a, l.a_port) == (dev, port):
                return l.b, l.b_port
            if (l.b, l.b_port) == (dev, port):
                return l.a, l.a_port
        return None

    def effective_port(self, dev: str, port: str) -> str:
        p = self.devices[dev].ports.get(port)
        return p.ae_parent if p and p.ae_parent else port


def parse_links(text: str) -> List[Link]:
    links = []
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        toks = line.replace("--", " ").split()
        if len(toks) != 4:
            raise ValueError(f"bad link line (want: devA portA devB portB): {line}")
        links.append(Link(*toks))
    return links


def load_lab(path: str) -> Lab:
    """Load a lab directory: configs/*.conf, links.txt, optional captures/*.pcap[ng]."""
    devices: Dict[str, Device] = {}
    cfg_dir = os.path.join(path, "configs")
    for fn in sorted(os.listdir(cfg_dir)):
        if not fn.endswith((".conf", ".cfg", ".txt", ".set")):
            continue
        with open(os.path.join(cfg_dir, fn)) as f:
            dev = build_device(junos.parse(f.read()), default_name=os.path.splitext(fn)[0])
        if dev.hostname in devices:
            raise ValueError(f"duplicate host-name {dev.hostname}")
        devices[dev.hostname] = dev
    with open(os.path.join(path, "links.txt")) as f:
        links = parse_links(f.read())
    for l in links:
        for d, p in l.ends():
            if d not in devices:
                raise ValueError(f"links.txt references unknown device {d}")
            devices[d].port(p)
    caps = []
    cap_dir = os.path.join(path, "captures")
    if os.path.isdir(cap_dir):
        caps = [os.path.join(cap_dir, f) for f in sorted(os.listdir(cap_dir))
                if f.endswith((".pcap", ".pcapng", ".cap"))]
    return Lab(devices, links, caps, name=os.path.basename(os.path.normpath(path)))
