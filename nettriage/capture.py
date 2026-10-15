"""Capture triage: turn decoded packets into findings with evidence."""
from __future__ import annotations

import os
from collections import defaultdict
from typing import Dict, List

from .findings import Finding
from .pcap import Packet, read_packets

BGP_ERRORS = {
    (1, 0): "Message Header Error",
    (2, 1): "OPEN: Unsupported Version", (2, 2): "OPEN: Bad Peer AS", (2, 3): "OPEN: Bad BGP Identifier",
    (2, 4): "OPEN: Unsupported Optional Parameter", (2, 6): "OPEN: Unacceptable Hold Time",
    (3, 0): "UPDATE Message Error", (4, 0): "Hold Timer Expired", (5, 0): "FSM Error",
    (6, 2): "Cease: Administrative Shutdown", (6, 3): "Cease: Peer De-configured",
    (6, 4): "Cease: Administrative Reset", (6, 5): "Cease: Connection Rejected",
}
DHCP_TYPES = {1: "DISCOVER", 2: "OFFER", 3: "REQUEST", 5: "ACK", 6: "NAK"}


def analyze_packets(pkts: List[Packet], name: str = "capture") -> List[Finding]:
    fs: List[Finding] = []
    fs += _arp(pkts, name)
    fs += _tcp(pkts, name)
    fs += _icmp(pkts, name)
    fs += _dhcp(pkts, name)
    fs += _ospf(pkts, name)
    fs += _bgp(pkts, name)
    for f in fs:
        f.source = "capture"
    return fs


def analyze_file(path: str) -> List[Finding]:
    return analyze_packets(read_packets(path), os.path.basename(path))


def _arp(pkts, name):
    seen: Dict[str, set] = defaultdict(set)
    first = {}
    for i, p in enumerate(pkts):
        a = p.arp
        # every ARP request, reply and gratuitous ARP carries a sender IP->MAC binding;
        # 0.0.0.0 senders are RFC 5227 probes and carry none
        if a and a["spa"] != "0.0.0.0":
            seen[a["spa"]].add(a["sha"])
            first.setdefault((a["spa"], a["sha"]), i + 1)
    out = []
    for ip, macs in sorted(seen.items()):
        if len(macs) > 1:
            out.append(Finding(
                "CAP_ARP_DUPLICATE_IP", "critical", f"{ip} is claimed by {len(macs)} MAC addresses",
                (name,), evidence=[f"frame {first[(ip, m)]}: {ip} is-at {m}" for m in sorted(macs)] +
                ["two hosts answer ARP for the same address -> intermittent reachability"],
                verify=[("switch", f"show ethernet-switching table | match \"{'|'.join(sorted(macs))}\""),
                        ("router", f"show arp no-resolve | match {ip}")],
                key=f"CAP_ARP_DUPLICATE_IP:{name}:{ip}"))
    return out


def _flow(p):
    return (p.ip["src"], p.tcp["sport"], p.ip["dst"], p.tcp["dport"])


def _tcp(pkts, name):
    out = []
    seqs: Dict[tuple, Dict[int, list]] = defaultdict(lambda: defaultdict(list))
    data_pkts: Dict[tuple, int] = defaultdict(int)
    syns: Dict[tuple, int] = {}
    refused = defaultdict(list)
    max_ack: Dict[tuple, int] = defaultdict(int)
    for i, p in enumerate(pkts):
        if not p.tcp:
            continue
        f = _flow(p)
        rev = (f[2], f[3], f[0], f[1])
        t = p.tcp
        if t["ackf"]:
            max_ack[f] = max(max_ack[f], t["ack"])
        if t["syn"] and not t["ackf"]:
            syns[f] = i + 1
        if t["rst"] and rev in syns:
            refused[rev[3]].append((rev, syns.pop(rev), i + 1))
        if t["len"] > 0:
            data_pkts[f] += 1
            seqs[f][t["seq"]].append((i + 1, t["len"], p.ip["df"]))
    for port, items in sorted(refused.items()):
        ex = items[0]
        bgp = port == 179
        out.append(Finding(
            "CAP_BGP_CONNECTION_REFUSED" if bgp else "CAP_TCP_REFUSED", "critical" if bgp else "minor",
            (f"BGP peer {ex[0][2]} refuses TCP/179 from {ex[0][0]} ({len(items)}x)" if bgp
             else f"TCP/{port} connection refused by {ex[0][2]} ({len(items)}x)"),
            (name,), evidence=[f"frame {ex[1]}: SYN {ex[0][0]}:{ex[0][1]} -> {ex[0][2]}:{port}",
                               f"frame {ex[2]}: RST from {ex[0][2]}"] +
            ([f"{ex[0][2]} has no neighbor {ex[0][0]} configured (or source address differs)"] if bgp else []),
            verify=[("peer", f"show bgp neighbor {ex[0][0]}")] if bgp else [],
            key=f"CAP_TCP_REFUSED:{name}:{port}"))
    for f, by_seq in seqs.items():
        n_re = sum(len(o) - 1 for s, o in by_seq.items() if len(o) > 1)
        if n_re < 3:
            continue
        rev = (f[2], f[3], f[0], f[1])
        big_unacked = [s for s, o in by_seq.items() if len(o) > 1 and o[0][1] >= 1200 and o[0][2]
                       and max_ack.get(rev, 0) <= s]
        small_ok = any(o[0][1] < 1200 and max_ack.get(rev, 0) > s for s, o in by_seq.items())
        frames = [o[1][0] for s, o in sorted(by_seq.items()) if len(o) > 1][:3]
        if big_unacked and small_ok:
            sizes = sorted({o[0][1] for s, o in by_seq.items() if s in big_unacked})
            out.append(Finding(
                "CAP_PMTU_BLACKHOLE", "critical",
                f"Path-MTU black hole on {f[0]}:{f[1]} -> {f[2]}:{f[3]}", (name,),
                evidence=[f"{len(big_unacked)} full-size DF segments ({sizes} bytes payload) retransmitted, never ACKed",
                          "small segments on the same flow are ACKed",
                          "no ICMP 3/4 (fragmentation needed) seen -> filtered or a lower-MTU hop does not send it",
                          f"retransmissions at frames {frames}"],
                fix=[("router", "set interfaces <wan-if> unit 0 family inet tcp-mss 1360"),
                     ("router", "# or align MTU on the low-MTU hop / permit ICMP type 3 code 4")],
                verify=[("host", f"ping {f[2]} size 1472 do-not-fragment")],
                key=f"CAP_PMTU_BLACKHOLE:{name}:{f}"))
        else:
            rate = n_re / max(1, data_pkts[f])
            out.append(Finding(
                "CAP_TCP_RETRANSMISSIONS", "major" if rate >= 0.05 else "minor",
                f"{n_re} retransmissions ({rate:.0%}) on {f[0]}:{f[1]} -> {f[2]}:{f[3]}", (name,),
                evidence=[f"retransmitted segments at frames {frames}",
                          "indicates loss on the path: check interface errors / drops / duplex"],
                verify=[("device", "show interfaces <if> extensive | match \"errors|drops|CRC\"")],
                key=f"CAP_TCP_RETRANSMISSIONS:{name}:{f}"))
    return out


def _icmp(pkts, name):
    out = []
    frag = [(i + 1, p) for i, p in enumerate(pkts) if p.icmp and p.icmp["type"] == 3 and p.icmp["code"] == 4]
    if frag:
        i, p = frag[0]
        out.append(Finding(
            "CAP_ICMP_FRAG_NEEDED", "major",
            f"Path MTU {p.icmp.get('mtu')} reported by {p.ip['src']} ({len(frag)} ICMP 3/4)", (name,),
            evidence=[f"frame {i}: ICMP dest-unreachable/frag-needed from {p.ip['src']}, next-hop MTU {p.icmp.get('mtu')}",
                      f"original packet {p.icmp.get('orig_src')} -> {p.icmp.get('orig_dst')}"],
            verify=[("router", f"show interfaces | match \"MTU\"")],
            key=f"CAP_ICMP_FRAG_NEEDED:{name}"))
    unreach = defaultdict(int)
    for p in pkts:
        if p.icmp and p.icmp["type"] == 3 and p.icmp["code"] in (0, 1):
            unreach[(p.ip["src"], p.icmp.get("orig_dst"))] += 1
    for (src, dst), n in unreach.items():
        if n >= 3:
            out.append(Finding("CAP_ICMP_UNREACHABLE", "minor", f"{src} reports {dst} unreachable ({n}x)",
                               (name,), evidence=["router has no route / no ARP for destination"],
                               verify=[("router", f"show route {dst}")],
                               key=f"CAP_ICMP_UNREACHABLE:{name}:{src}:{dst}"))
    return out


def _dhcp(pkts, name):
    disc, answered = {}, set()
    for i, p in enumerate(pkts):
        d = p.dhcp
        if not d or "msg" not in d:
            continue
        if d["msg"] == 1:
            disc.setdefault(d["xid"], (i + 1, d["chaddr"]))
        elif d["msg"] in (2, 6):
            answered.add(d["xid"])
    lost = {x: v for x, v in disc.items() if x not in answered}
    if lost and len(lost) == len(disc):
        clients = sorted({v[1] for v in lost.values()})
        return [Finding(
            "CAP_DHCP_NO_OFFER", "critical", f"{len(lost)} DHCPDISCOVER(s) never answered", (name,),
            evidence=[f"clients: {', '.join(clients)}", f"first DISCOVER at frame {min(v[0] for v in lost.values())}",
                      "no OFFER on the segment: relay/helper missing or server unreachable"],
            fix=[("gateway", "set forwarding-options dhcp-relay server-group SG <server-ip>"),
                 ("gateway", "set forwarding-options dhcp-relay group G active-server-group SG interface irb.<vlan>")],
            verify=[("gateway", "show dhcp relay statistics")],
            key=f"CAP_DHCP_NO_OFFER:{name}")]
    return []


def _ospf(pkts, name):
    out = []
    by_seg = defaultdict(dict)
    for i, p in enumerate(pkts):
        o = p.ospf
        if o and o["type"] == 1 and "hello" in o:
            # one capture point == one segment; split only by 802.1Q tag
            by_seg[p.vlan][o["router_id"]] = \
                (i + 1, o["area"], o["hello"], o["dead"], o["mask"], p.ip["src"])
    for seg, routers in by_seg.items():
        params = {r: v[1:5] for r, v in routers.items()}
        if len(set(params.values())) > 1:
            fields = ["area", "hello", "dead", "mask"]
            diffs = [fields[k] for k in range(4) if len({v[k] for v in params.values()}) > 1]
            out.append(Finding(
                "CAP_OSPF_HELLO_MISMATCH", "critical",
                f"OSPF hello parameter mismatch ({', '.join(diffs)}) between {', '.join(sorted(routers))}", (name,),
                evidence=[f"frame {v[0]}: rid {r} src {v[5]} area {v[1]} hello {v[2]} dead {v[3]} mask {v[4]}"
                          for r, v in sorted(routers.items())],
                verify=[("router", "show ospf interface detail"), ("router", "show ospf neighbor")],
                key=f"CAP_OSPF_HELLO_MISMATCH:{name}:{seg}"))
    return out


def _bgp(pkts, name):
    out = {}
    opens = {}
    for i, p in enumerate(pkts):
        for m in p.bgp:
            if m["type"] == 1:
                opens[p.ip["src"]] = (i + 1, m["asn"], m["bgp_id"])
            elif m["type"] == 3:
                k = (p.ip["src"], p.ip["dst"], m["code"], m["subcode"])
                if k in out:
                    continue
                desc = BGP_ERRORS.get((m["code"], m["subcode"]), BGP_ERRORS.get((m["code"], 0), "unknown"))
                ev = [f"frame {i + 1}: NOTIFICATION {m['code']}/{m['subcode']} ({desc}) {p.ip['src']} -> {p.ip['dst']}"]
                o = opens.get(p.ip["dst"])
                if o:
                    ev.append(f"frame {o[0]}: OPEN from {p.ip['dst']} advertised AS {o[1]}, BGP-ID {o[2]}")
                if (m["code"], m["subcode"]) == (2, 2) and o:
                    ev.append(f"{p.ip['src']} is configured with a peer-as other than {o[1]}")
                out[k] = Finding(
                    "CAP_BGP_NOTIFICATION", "critical", f"BGP NOTIFICATION {desc} from {p.ip['src']}", (name,),
                    evidence=ev, verify=[("router", f"show bgp neighbor {p.ip['dst']} | match \"Last Error\"")],
                    key=f"CAP_BGP_NOTIFICATION:{name}:{k}")
    return list(out.values())
