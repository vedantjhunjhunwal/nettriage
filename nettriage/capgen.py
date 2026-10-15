"""Synthesise packet captures (real wire-format frames) for capture-triage tests."""
from __future__ import annotations

import random
from typing import Callable, Dict, List, Set, Tuple

from . import pcap as P

Frames = List[Tuple[float, bytes]]


class Cap:
    def __init__(self, seed: int):
        self.rng = random.Random(seed)
        self.t = 1_700_000_000.0 + seed
        self.frames: Frames = []
        o = self.rng.randint(1, 250)
        self.net = f"10.{o}.1"
        self.gw_mac = self._mac()
        self.hosts = [(f"{self.net}.{10 + i}", self._mac()) for i in range(4)]
        self.server = ("192.0.2.10", self._mac())

    def _mac(self):
        return "02:" + ":".join(f"{self.rng.randint(0, 255):02x}" for _ in range(5))

    def emit(self, frame: bytes, dt: float = 0.01):
        self.t += dt * (0.5 + self.rng.random())
        self.frames.append((self.t, frame))

    # --- building blocks
    def arp_exchange(self, ip, mac, target, tmac):
        self.emit(P.ether("ff:ff:ff:ff:ff:ff", mac, 0x0806, P.arp(1, mac, ip, "00:00:00:00:00:00", target)))
        self.emit(P.ether(mac, tmac, 0x0806, P.arp(2, tmac, target, mac, ip)))

    def tcp_flow(self, c, s, sport, dport, segs: List[int], drop: Callable[[int, int], bool] = lambda i, n: False,
                 tries=4):
        (cip, cmac), (sip, smac) = c, s
        isn, sisn = self.rng.randint(0, 2**31), self.rng.randint(0, 2**31)
        E = lambda src, dst, b: P.ether(dst, src, 0x0800, b)
        self.emit(E(cmac, self.gw_mac, P.ipv4(cip, sip, 6, P.tcp(sport, dport, isn, 0, "S"))))
        self.emit(E(self.gw_mac, cmac, P.ipv4(sip, cip, 6, P.tcp(dport, sport, sisn, isn + 1, "SA"))))
        self.emit(E(cmac, self.gw_mac, P.ipv4(cip, sip, 6, P.tcp(sport, dport, isn + 1, sisn + 1, "A"))))
        seq = isn + 1
        for i, n in enumerate(segs):
            payload = bytes(self.rng.getrandbits(8) for _ in range(n))
            for attempt in range(tries):
                # RTO backs off exponentially on each retransmission
                self.emit(E(cmac, self.gw_mac, P.ipv4(cip, sip, 6, P.tcp(sport, dport, seq, sisn + 1, "PA", payload))),
                          0.2 * (2 ** attempt) if attempt else 0.01)
                if not drop(i, n):
                    self.emit(E(self.gw_mac, cmac, P.ipv4(sip, cip, 6, P.tcp(dport, sport, sisn + 1, seq + n, "A"))))
                    break
            else:
                return  # segment never delivered: connection stalls
            seq += n

    def healthy_background(self):
        for ip, mac in self.hosts:
            self.arp_exchange(ip, mac, f"{self.net}.1", self.gw_mac)
        for i, (ip, mac) in enumerate(self.hosts[:2]):
            self.tcp_flow((ip, mac), self.server, 40000 + i, 443, [300, 1448, 1448, 600])
        # OSPF hellos from two routers on a transit segment
        for _ in range(3):
            for rid, src in (("10.255.0.1", "10.9.0.1"), ("10.255.0.2", "10.9.0.2")):
                self.emit(P.ether("01:00:5e:00:00:05", self._mac(), 0x0800,
                                  P.ipv4(src, "224.0.0.5", 89, P.ospf_hello(rid, "0.0.0.0", "255.255.255.252", 10, 40), ttl=1)))
        # BGP: OPENs + keepalive exchange
        a, b = ("10.9.1.1", 65001), ("10.9.1.2", 64500)
        self._bgp_session(a, b)
        # DHCP DORA
        xid, mac = self.rng.getrandbits(32), self._mac()
        for typ, op in ((1, 1), (2, 2), (3, 1), (5, 2)):
            self.emit(P.ether("ff:ff:ff:ff:ff:ff", mac if op == 1 else self.gw_mac, 0x0800,
                              P.ipv4("0.0.0.0" if op == 1 else f"{self.net}.1",
                                     "255.255.255.255", 17,
                                     P.udp(68 if op == 1 else 67, 67 if op == 1 else 68, P.dhcp_msg(typ, xid, mac, op)))))

    def _bgp_session(self, a, b, notify=None):
        (aip, aas), (bip, bas) = a, b
        ma, mb = self._mac(), self._mac()
        E = lambda s, d, x: P.ether(d, s, 0x0800, x)
        self.emit(E(ma, mb, P.ipv4(aip, bip, 6, P.tcp(51000, 179, 1, 0, "S"))))
        self.emit(E(mb, ma, P.ipv4(bip, aip, 6, P.tcp(179, 51000, 9, 2, "SA"))))
        self.emit(E(ma, mb, P.ipv4(aip, bip, 6, P.tcp(51000, 179, 2, 10, "A"))))
        oa = P.bgp_open(aas, aip)
        self.emit(E(ma, mb, P.ipv4(aip, bip, 6, P.tcp(51000, 179, 2, 10, "PA", oa))))
        ob = P.bgp_open(bas, bip)
        if notify:
            n = P.bgp_notification(*notify)
            self.emit(E(mb, ma, P.ipv4(bip, aip, 6, P.tcp(179, 51000, 10, 2 + len(oa), "PA", n))))
            self.emit(E(mb, ma, P.ipv4(bip, aip, 6, P.tcp(179, 51000, 10 + len(n), 2 + len(oa), "FA"))))
        else:
            self.emit(E(mb, ma, P.ipv4(bip, aip, 6, P.tcp(179, 51000, 10, 2 + len(oa), "PA", ob))))


# ---------------------------------------------------------------- capture faults

def c_arp_dup(c: Cap):
    ip, mac = c.hosts[0]
    rogue = c._mac()
    c.emit(P.ether("ff:ff:ff:ff:ff:ff", rogue, 0x0806, P.arp(2, rogue, ip, "ff:ff:ff:ff:ff:ff", ip)))
    c.arp_exchange(f"{c.net}.1", c.gw_mac, ip, rogue)
    return {"CAP_ARP_DUPLICATE_IP"}


def c_pmtu(c: Cap):
    ip, mac = c.hosts[2]
    c.tcp_flow((ip, mac), c.server, 45000, 443, [200, 517, 1448, 1448], drop=lambda i, n: n > 1400)
    return {"CAP_PMTU_BLACKHOLE"}


def c_frag_needed(c: Cap):
    ip, mac = c.hosts[3]
    orig = P.ipv4(ip, c.server[0], 6, P.tcp(46000, 443, 5, 1, "PA", b"\0" * 8))
    c.emit(P.ether(mac, c.gw_mac, 0x0800,
                   P.ipv4(f"{c.net}.1", ip, 1, P.icmp(3, 4, b"\0\0\x05\x78", orig[:28]))))
    return {"CAP_ICMP_FRAG_NEEDED"}


def c_dhcp(c: Cap):
    c.frames = [f for f in c.frames if b"\x63\x82\x53\x63" not in f[1]]
    mac = c._mac()
    for _ in range(4):
        xid = c.rng.getrandbits(32)
        c.emit(P.ether("ff:ff:ff:ff:ff:ff", mac, 0x0800, P.ipv4("0.0.0.0", "255.255.255.255", 17,
                                                                 P.udp(68, 67, P.dhcp_msg(1, xid, mac, 1)))), 2)
    return {"CAP_DHCP_NO_OFFER"}


def c_ospf(c: Cap):
    which = c.rng.choice(["area", "hello", "mask"])
    for _ in range(3):
        c.emit(P.ether("01:00:5e:00:00:05", c._mac(), 0x0800, P.ipv4(
            "10.9.2.1", "224.0.0.5", 89, P.ospf_hello("10.255.0.7", "0.0.0.0", "255.255.255.252", 10, 40), ttl=1)), 1)
        c.emit(P.ether("01:00:5e:00:00:05", c._mac(), 0x0800, P.ipv4(
            "10.9.2.2", "224.0.0.5", 89, P.ospf_hello(
                "10.255.0.8", "0.0.0.1" if which == "area" else "0.0.0.0",
                "255.255.255.248" if which == "mask" else "255.255.255.252",
                5 if which == "hello" else 10, 20 if which == "hello" else 40), ttl=1)), 1)
    c.frames = [f for f in c.frames if not (len(f[1]) > 23 and f[1][23] == 89 and b"\x0a\x09\x00" in f[1][26:30])]
    return {"CAP_OSPF_HELLO_MISMATCH"}


def c_bgp_badas(c: Cap):
    c._bgp_session(("10.9.3.1", 65010), ("10.9.3.2", 64501), notify=(2, 2))
    return {"CAP_BGP_NOTIFICATION"}


def c_bgp_refused(c: Cap):
    ma, mb = c._mac(), c._mac()
    for k in range(3):
        c.emit(P.ether(mb, ma, 0x0800, P.ipv4("10.9.4.1", "10.9.4.2", 6, P.tcp(52000 + k, 179, 7, 0, "S"))), 1)
        c.emit(P.ether(ma, mb, 0x0800, P.ipv4("10.9.4.2", "10.9.4.1", 6, P.tcp(179, 52000 + k, 0, 8, "RA"))))
    return {"CAP_BGP_CONNECTION_REFUSED"}


def c_retrans(c: Cap):
    ip, mac = c.hosts[1]
    lost = set(c.rng.sample(range(20), 5))
    state = {}

    def drop(i, n):
        state[i] = state.get(i, 0) + 1
        return i in lost and state[i] == 1

    c.tcp_flow((ip, mac), c.server, 47000, 8443, [c.rng.choice([400, 900, 1200]) for _ in range(20)], drop=drop)
    return {"CAP_TCP_RETRANSMISSIONS"}


CAP_FAULTS: Dict[str, Callable[[Cap], Set[str]]] = {
    "arp_dup": c_arp_dup, "pmtu_blackhole": c_pmtu, "frag_needed": c_frag_needed, "dhcp_no_offer": c_dhcp,
    "ospf_hello": c_ospf, "bgp_bad_peer_as": c_bgp_badas, "bgp_refused": c_bgp_refused, "tcp_loss": c_retrans,
}


def make_capture(seed: int, faults: List[str], path: str) -> Set[str]:
    c = Cap(seed)
    c.healthy_background()
    exp: Set[str] = set()
    for f in faults:
        exp |= CAP_FAULTS[f](c)
    c.frames.sort()
    P.write_pcap(path, c.frames)
    return exp
