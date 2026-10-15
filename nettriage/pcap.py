"""Dependency-free pcap / pcapng reader + writer and protocol decoders.

Decodes Ethernet (incl. 802.1Q), ARP, IPv4, ICMP, TCP, UDP, DHCP, OSPFv2 hello
and BGP OPEN/NOTIFICATION -- enough to triage the captures a TAC engineer
usually gets attached to a case (Wireshark saves pcapng by default; tcpdump
and Junos `monitor traffic ... write-file` produce classic pcap).
"""
from __future__ import annotations

import ipaddress
import struct
from dataclasses import dataclass, field
from typing import Iterator, List, Optional, Tuple

LINKTYPE_ETHERNET = 1


@dataclass
class Packet:
    ts: float
    raw: bytes
    src_mac: str = ""
    dst_mac: str = ""
    vlan: Optional[int] = None
    ethertype: int = 0
    arp: Optional[dict] = None
    ip: Optional[dict] = None
    icmp: Optional[dict] = None
    tcp: Optional[dict] = None
    udp: Optional[dict] = None
    dhcp: Optional[dict] = None
    ospf: Optional[dict] = None
    bgp: List[dict] = field(default_factory=list)


def _mac(b: bytes) -> str:
    return ":".join(f"{x:02x}" for x in b)


def _ip(b: bytes) -> str:
    return str(ipaddress.IPv4Address(b))


# ------------------------------------------------------------------ readers

def read_packets(path: str) -> List[Packet]:
    with open(path, "rb") as f:
        data = f.read()
    return [decode(ts, raw) for ts, raw in iter_frames(data)]


def iter_frames(data: bytes) -> Iterator[Tuple[float, bytes]]:
    magic = data[:4]
    if magic == b"\x0a\x0d\x0d\x0a":
        yield from _iter_pcapng(data)
        return
    if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
        e = "<"
    elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
        e = ">"
    else:
        raise ValueError("not a pcap/pcapng file")
    nano = magic in (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d")
    linktype = struct.unpack(e + "I", data[20:24])[0]
    if linktype != LINKTYPE_ETHERNET:
        raise ValueError(f"unsupported linktype {linktype} (only Ethernet)")
    off = 24
    while off + 16 <= len(data):
        sec, frac, incl, _orig = struct.unpack(e + "IIII", data[off:off + 16])
        off += 16
        yield sec + frac / (1e9 if nano else 1e6), data[off:off + incl]
        off += incl


def _iter_pcapng(data: bytes) -> Iterator[Tuple[float, bytes]]:
    off, e = 0, "<"
    tsres = {}
    while off + 12 <= len(data):
        btype = struct.unpack(e + "I", data[off:off + 4])[0]
        if btype == 0x0A0D0D0A:
            bom = data[off + 8:off + 12]
            e = "<" if bom == b"\x4d\x3c\x2b\x1a" else ">"
            tsres = {}
            idx = 0
        blen = struct.unpack(e + "I", data[off + 4:off + 8])[0]
        body = data[off + 8:off + blen - 4]
        if btype == 0x00000001:  # IDB
            linktype = struct.unpack(e + "H", body[:2])[0]
            res = 1e-6
            o = 8
            while o + 4 <= len(body):
                code, ln = struct.unpack(e + "HH", body[o:o + 4])
                if code == 0:
                    break
                if code == 9:  # if_tsresol
                    v = body[o + 4]
                    res = 2 ** -(v & 0x7F) if v & 0x80 else 10 ** -v
                o += 4 + ((ln + 3) & ~3)
            tsres[len(tsres)] = (linktype, res)
        elif btype == 0x00000006:  # EPB
            iface, hi, lo, cap, _ = struct.unpack(e + "IIIII", body[:20])
            linktype, res = tsres.get(iface, (1, 1e-6))
            if linktype == LINKTYPE_ETHERNET:
                yield ((hi << 32) | lo) * res, body[20:20 + cap]
        elif btype == 0x00000003:  # SPB
            orig = struct.unpack(e + "I", body[:4])[0]
            yield 0.0, body[4:4 + orig]
        if blen < 12:
            break
        off += blen


# ------------------------------------------------------------------ decoder

def decode(ts: float, raw: bytes) -> Packet:
    p = Packet(ts, raw)
    if len(raw) < 14:
        return p
    p.dst_mac, p.src_mac = _mac(raw[0:6]), _mac(raw[6:12])
    et = struct.unpack("!H", raw[12:14])[0]
    off = 14
    if et == 0x8100 and len(raw) >= 18:
        p.vlan = struct.unpack("!H", raw[14:16])[0] & 0x0FFF
        et = struct.unpack("!H", raw[16:18])[0]
        off = 18
    p.ethertype = et
    body = raw[off:]
    if et == 0x0806 and len(body) >= 28:
        op = struct.unpack("!H", body[6:8])[0]
        p.arp = {"op": op, "sha": _mac(body[8:14]), "spa": _ip(body[14:18]),
                 "tha": _mac(body[18:24]), "tpa": _ip(body[24:28])}
    elif et == 0x0800 and len(body) >= 20:
        ihl = (body[0] & 0x0F) * 4
        total, _id, ff, ttl, proto = struct.unpack("!HHHBB", body[2:10])
        p.ip = {"src": _ip(body[12:16]), "dst": _ip(body[16:20]), "proto": proto, "ttl": ttl,
                "len": total, "df": bool(ff & 0x4000), "id": _id}
        l4 = body[ihl:total] if total >= ihl else body[ihl:]
        if proto == 1 and len(l4) >= 8:
            t, c = l4[0], l4[1]
            ic = {"type": t, "code": c}
            if t == 3 and c == 4:
                ic["mtu"] = struct.unpack("!H", l4[6:8])[0]
            if t in (3, 11) and len(l4) >= 28:
                ic["orig_src"], ic["orig_dst"] = _ip(l4[20:24]), _ip(l4[24:28])
            p.icmp = ic
        elif proto == 6 and len(l4) >= 20:
            sp, dp, seq, ack, offf = struct.unpack("!HHIIH", l4[:14])
            doff = (offf >> 12) * 4
            flags = offf & 0x1FF
            payload = l4[doff:]
            p.tcp = {"sport": sp, "dport": dp, "seq": seq, "ack": ack, "flags": flags,
                     "syn": bool(flags & 2), "rst": bool(flags & 4), "fin": bool(flags & 1),
                     "ackf": bool(flags & 16), "len": len(payload)}
            if 179 in (sp, dp) and payload:
                p.bgp = _bgp_msgs(payload)
        elif proto == 17 and len(l4) >= 8:
            sp, dp = struct.unpack("!HH", l4[:4])
            p.udp = {"sport": sp, "dport": dp}
            if {sp, dp} & {67, 68} and len(l4) >= 8 + 240:
                p.dhcp = _dhcp(l4[8:])
        elif proto == 89 and len(l4) >= 24:
            ver, typ, ln = struct.unpack("!BBH", l4[:4])
            o = {"version": ver, "type": typ, "router_id": _ip(l4[4:8]), "area": _ip(l4[8:12])}
            if typ == 1 and len(l4) >= 44:
                o["mask"] = _ip(l4[24:28])
                o["hello"], o["options"], o["prio"] = struct.unpack("!HBB", l4[28:32])
                o["dead"] = struct.unpack("!I", l4[32:36])[0]
            elif typ == 2 and len(l4) >= 32:  # DBD
                o["mtu"] = struct.unpack("!H", l4[24:26])[0]
            p.ospf = o
    return p


def _bgp_msgs(payload: bytes) -> List[dict]:
    out, o = [], 0
    while o + 19 <= len(payload) and payload[o:o + 16] == b"\xff" * 16:
        ln, typ = struct.unpack("!HB", payload[o + 16:o + 19])
        m = {"type": typ}
        if typ == 1 and ln >= 29:
            _v, asn, hold = struct.unpack("!BHH", payload[o + 19:o + 24])
            m.update(asn=asn, hold=hold, bgp_id=_ip(payload[o + 24:o + 28]))
        elif typ == 3 and ln >= 21:
            m.update(code=payload[o + 19], subcode=payload[o + 20])
        out.append(m)
        if ln < 19:
            break
        o += ln
    return out


def _dhcp(b: bytes) -> dict:
    d = {"op": b[0], "xid": struct.unpack("!I", b[4:8])[0], "chaddr": _mac(b[28:34])}
    if b[236:240] == b"\x63\x82\x53\x63":
        o = 240
        while o < len(b) and b[o] != 255:
            if b[o] == 0:
                o += 1
                continue
            code, ln = b[o], b[o + 1]
            if code == 53:
                d["msg"] = b[o + 2]
            o += 2 + ln
    return d


# ------------------------------------------------------------------ writer (lab captures)

def _csum(b: bytes) -> int:
    if len(b) % 2:
        b += b"\0"
    s = sum(struct.unpack(f"!{len(b)//2}H", b))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return ~s & 0xFFFF


def mac_b(m: str) -> bytes:
    return bytes(int(x, 16) for x in m.split(":"))


def ether(dst: str, src: str, etype: int, payload: bytes, vlan: Optional[int] = None) -> bytes:
    hdr = mac_b(dst) + mac_b(src)
    if vlan is not None:
        hdr += struct.pack("!HH", 0x8100, vlan)
    return hdr + struct.pack("!H", etype) + payload


def ipv4(src: str, dst: str, proto: int, payload: bytes, ttl=64, df=True, ident=0) -> bytes:
    hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), ident, 0x4000 if df else 0, ttl, proto, 0,
                      ipaddress.IPv4Address(src).packed, ipaddress.IPv4Address(dst).packed)
    hdr = hdr[:10] + struct.pack("!H", _csum(hdr)) + hdr[12:]
    return hdr + payload


def tcp(sport, dport, seq, ack, flags: str, payload: bytes = b"") -> bytes:
    fl = sum({"F": 1, "S": 2, "R": 4, "P": 8, "A": 16}[c] for c in flags)
    return struct.pack("!HHIIHHHH", sport, dport, seq, ack, (5 << 12) | fl, 65535, 0, 0) + payload


def udp(sport, dport, payload: bytes) -> bytes:
    return struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload


def arp(op: int, sha: str, spa: str, tha: str, tpa: str) -> bytes:
    return struct.pack("!HHBBH", 1, 0x0800, 6, 4, op) + mac_b(sha) + ipaddress.IPv4Address(spa).packed + \
        mac_b(tha) + ipaddress.IPv4Address(tpa).packed


def icmp(t: int, c: int, rest: bytes = b"\0\0\0\0", data: bytes = b"") -> bytes:
    body = struct.pack("!BBH", t, c, 0) + rest + data
    return body[:2] + struct.pack("!H", _csum(body)) + body[4:]


def ospf_hello(rid: str, area: str, mask: str, hello: int, dead: int, prio=1) -> bytes:
    body = ipaddress.IPv4Address(mask).packed + struct.pack("!HBBI", hello, 0x02, prio, dead) + b"\0" * 8
    hdr = struct.pack("!BBH4s4sHH8s", 2, 1, 24 + len(body), ipaddress.IPv4Address(rid).packed,
                      ipaddress.IPv4Address(area).packed, 0, 0, b"\0" * 8)
    return hdr + body


def bgp_open(asn: int, bgp_id: str, hold=90) -> bytes:
    body = struct.pack("!BHH4sB", 4, asn if asn < 65536 else 23456, hold, ipaddress.IPv4Address(bgp_id).packed, 0)
    return b"\xff" * 16 + struct.pack("!HB", 19 + len(body), 1) + body


def bgp_notification(code: int, sub: int) -> bytes:
    return b"\xff" * 16 + struct.pack("!HBBB", 21, 3, code, sub)


def dhcp_msg(msgtype: int, xid: int, chaddr: str, op: int) -> bytes:
    b = struct.pack("!BBBBIHH", op, 1, 6, 0, xid, 0, 0x8000) + b"\0" * 16 + mac_b(chaddr) + b"\0" * 10 + \
        b"\0" * 192 + b"\x63\x82\x53\x63" + bytes([53, 1, msgtype, 255])
    return b


def write_pcap(path: str, frames: List[Tuple[float, bytes]]):
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, LINKTYPE_ETHERNET))
        for ts, fr in frames:
            sec = int(ts)
            usec = int(round((ts - sec) * 1e6))
            f.write(struct.pack("<IIII", sec, usec, len(fr), len(fr)) + fr)
