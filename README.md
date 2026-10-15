# NetTriage

TAC-style fault triage for Junos networks. Point it at a case bundle (device
configs, a link map, and optional packet captures) and it does what a support
engineer does on the first pass: rebuilds the protocol state, separates the
**root cause** from the **downstream symptoms**, and writes a case report with
evidence, the Junos `set` commands to fix it, and the `show` commands to verify.

Pure Python 3.10+, no runtime dependencies. Packet decoding is hand-written
against the RFC wire formats (no scapy / tshark).

```
python -m nettriage analyze labs/case-01          # Markdown case report
python -m nettriage analyze labs/case-01 --json   # machine-readable
python -m nettriage pcap samples/pmtu_blackhole.pcap
python -m nettriage gen /tmp/lab --seed 3 --fault ospf_area --fault vrrp_group
python -m nettriage eval                          # fault-injection benchmark
python -m pytest -q                               # 52 tests
```

## What it checks

| Layer | Checks | Junos objects |
|---|---|---|
| L2 | LACP both-passive, static-vs-LACP, member not in bundle, trunk VLAN list mismatch, access/trunk mismatch, access VLAN leak, MTU mismatch, RSTP root placed on an access switch | `ae`, `802.3ad`, `lacp`, `family ethernet-switching`, `rstp bridge-priority` |
| L3 | Duplicate IP, subnet mismatch on a link, duplicate router-ID | `family inet`, `routing-options router-id` |
| OSPF | Area, hello/dead, network-type, passive transit link, OSPF on one side only, MTU -> stuck in ExStart; Dijkstra SPF over Full adjacencies to compute reachability | `protocols ospf area ... interface` |
| BGP | Missing neighbor, peer-AS mismatch (NOTIFICATION 2/2), update-source / `local-address` mismatch, iBGP loopback not in IGP, router-ID collision (2/3), transport reachability via the SPF RIB | `protocols bgp group` |
| VRRP | Group-ID mismatch (dual master), VIP outside subnet, VIP mismatch; master election | `vrrp-group` |
| Captures | Duplicate IP via ARP, TCP retransmission rate, connection refused (incl. BGP TCP/179), path-MTU black hole, ICMP frag-needed, DHCP DISCOVER without OFFER, OSPF hello parameter mismatch, BGP NOTIFICATION decode | pcap + pcapng, Ethernet/802.1Q, ARP, IPv4, ICMP, TCP, UDP, DHCP, OSPFv2, BGP |

Configs can be pasted as `show configuration` (curly braces) or `| display set`.

## Root cause vs symptom

Every finding carries a `caused_by` link. Example: removing `lo0.0` from OSPF on
the edge router produces **one** root cause (`IGP_LOOPBACK_MISSING`) and two
correlated symptoms (both iBGP sessions to it stuck in Active), instead of three
unrelated alarms. A capture that shows a BGP NOTIFICATION "Bad Peer AS" is linked
as corroborating evidence to the config-level `peer-as` mismatch.

## Benchmark (`python -m nettriage eval --seeds 30 --pairs 200 --healthy 100`)

The lab generator builds a 6-device campus/WAN topology (2 core L3 switches,
2 access switches, edge router, ISP router; OSPF, iBGP over loopbacks, eBGP,
LACP trunks, RSTP, VRRP) with addressing, ASNs, VLAN-ids, VRRP groups and port
numbers randomised per seed, and injects faults by editing the config like a bad
commit. Configs are written in a mix of curly and set format so the parser is
exercised end to end.

| Suite | Labs | Result |
|---|---|---|
| Healthy configs | 100 | 0 false positives |
| Single injected fault (21 classes x 30 seeds) | 630 | 630 exact root-cause match |
| Two simultaneous faults | 200 | 200 exact match |
| Healthy captures | 100 | 0 false positives |
| Capture faults (8 classes x 30 seeds) | 240 | 240 exact match |

Median analysis time 2.9 ms per 6-device lab. "Exact" means the set of reported
root causes equals the set injected: nothing missed, nothing extra. Full output in
`docs/benchmark.json`.

**Honest limits.** The generator and the checks were written together, so this
measures internal consistency and regression safety, not performance on
arbitrary production networks. Two real bugs were found this way (a fault
generator that deleted the whole OSPF interface, and a duplicate-router-ID check
that masked a second fault on the same link; see the regression test). OSPF is
single-area intra-area SPF only; no IS-IS, multi-area LSA types, route policy,
or BGP best-path import yet. Capture analysis is heuristic.

## Layout

```
nettriage/junos.py        curly + set parser, renderer
nettriage/model.py        device/topology model, lab loader
nettriage/checks/         l2.py  l3.py (OSPF + SPF)  bgp.py  vrrp.py
nettriage/pcap.py         pcap/pcapng reader+writer, protocol decoders
nettriage/capture.py      capture triage rules
nettriage/engine.py       orchestration + root-cause correlation
nettriage/report.py       Markdown / JSON case report
nettriage/labgen.py       topology generator + 21 config fault injectors
nettriage/capgen.py       capture generator + 8 network fault injectors
labs/case-0*/             example cases with generated REPORT.md
samples/*.pcap            example captures (open them in Wireshark too)
```
