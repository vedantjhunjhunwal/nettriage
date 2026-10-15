import ipaddress
import struct

import pytest

from nettriage import capgen, junos, labgen, pcap
from nettriage.capture import analyze_file
from nettriage.checks.l3 import Rib
from nettriage.engine import analyze_path
from nettriage.model import build_device
from nettriage.report import to_markdown

CURLY = """
## Last commit: 2026-10-01 10:00:00 IST by lab
system {
    host-name r1;
}
interfaces {
    ge-0/0/0 {
        description "to r2";
        mtu 9192;
        unit 0 {
            family inet {
                address 10.0.0.1/30;
            }
        }
    }
    ae0 {
        aggregated-ether-options {
            lacp {
                passive;
            }
        }
        unit 0 {
            family ethernet-switching {
                interface-mode trunk;
                vlan {
                    members [ v10 20 ];
                }
            }
        }
    }
}
vlans {
    v10 {
        vlan-id 10;
    }
}
protocols {
    ospf {
        area 0.0.0.1 {
            interface ge-0/0/0.0 {
                interface-type p2p;
                hello-interval 5;
            }
            interface lo0.0 passive;
        }
    }
    rstp {
        bridge-priority 8k;
    }
}
"""


# ---------------------------------------------------------------- parser

def test_curly_parse_flattens_lists_and_comments():
    paths = junos.parse(CURLY)
    assert ("system", "host-name", "r1") in paths
    assert ("interfaces", "ae0", "unit", "0", "family", "ethernet-switching", "vlan", "members", "v10") in paths
    assert ("interfaces", "ae0", "unit", "0", "family", "ethernet-switching", "vlan", "members", "20") in paths
    assert ("interfaces", "ge-0/0/0", "description", "to r2") in paths


def test_set_format_with_delete():
    text = "set system host-name x\nset interfaces ge-0/0/1 mtu 9000\ndelete interfaces ge-0/0/1 mtu\n"
    assert junos.parse(text) == [("system", "host-name", "x")]


@pytest.mark.parametrize("bad", ["system { host-name r1; ", "system { host-name r1 }", "a b"])
def test_parser_rejects_malformed(bad):
    with pytest.raises(junos.JunosParseError):
        junos.parse_hierarchical(bad)


def test_render_round_trip():
    ctx, _ = labgen.make(3, [])
    for paths in ctx.paths.values():
        back = set(junos.parse(junos.render_hierarchical(paths)))
        # only parent statements implied by a deeper statement may disappear (as in `display set`)
        assert all(any(q[:len(p)] == p for q in back) for p in paths)


def test_model_extraction():
    d = build_device(junos.parse(CURLY))
    assert d.hostname == "r1"
    assert d.ports["ge-0/0/0"].mtu == 9192
    assert d.ports["ae0"].lacp == "passive"
    o = d.ospf["ge-0/0/0.0"]
    assert (o.area, o.hello, o.if_type) == ("0.0.0.1", 5, "p2p")
    assert d.ospf["lo0.0"].passive
    assert d.rstp_priority == 8192
    assert d.vlan_ids(d.units["ae0.0"]) == [10, 20]


# ---------------------------------------------------------------- engine

def _analyze(tmp_path, seed, faults):
    ctx, exp = labgen.make(seed, faults)
    labgen.write_lab(ctx, str(tmp_path / "lab"))
    return analyze_path(str(tmp_path / "lab")), exp


@pytest.mark.parametrize("seed", range(5))
def test_healthy_lab_is_clean(tmp_path, seed):
    r, _ = _analyze(tmp_path, seed, [])
    assert r.findings == []
    assert all(a.state == "Full" for a in r.adjacencies)
    assert all(s.state == "Established" for s in r.sessions)
    assert r.stp_root == "core1"


@pytest.mark.parametrize("fault", sorted(labgen.FAULTS))
def test_each_fault_class_named_exactly(tmp_path, fault):
    for seed in (11, 12, 13):
        r, exp = _analyze(tmp_path / str(seed), seed, [fault])
        assert set(r.root_codes) == exp, (fault, seed, [f.title for f in r.findings])
        for f in r.roots:
            assert f.evidence


def test_symptoms_are_linked_to_root(tmp_path):
    r, _ = _analyze(tmp_path, 7, ["loopback_not_in_igp"])
    root = r.roots[0]
    downs = [f for f in r.findings if f.code == "BGP_SESSION_DOWN"]
    assert len(downs) == 2 and all(f.caused_by == root.key for f in downs)
    assert "passive" in root.fix[0][1]


def test_mtu_mismatch_puts_ospf_in_exstart(tmp_path):
    r, _ = _analyze(tmp_path, 4, ["mtu"])
    stuck = [a for a in r.adjacencies if a.state == "ExStart"]
    assert len(stuck) == 1
    assert sum(a.state == "Full" for a in r.adjacencies) == 2


def test_spf_reroutes_around_failed_adjacency(tmp_path):
    r, _ = _analyze(tmp_path, 9, ["ospf_area"])
    # every iBGP loopback still reachable through the remaining triangle
    assert all(s.state == "Established" for s in r.sessions)
    down = next(a for a in r.adjacencies if a.state != "Full")
    cost = r.rib.spf(down.a)[down.b]
    assert cost == 2


def test_report_contains_remediation(tmp_path):
    r, _ = _analyze(tmp_path, 2, ["bgp_peer_as"])
    md = to_markdown(r)
    assert "Remediation" in md and "peer-as" in md and "commit confirmed" in md


def test_vrrp_election(tmp_path):
    r, _ = _analyze(tmp_path, 5, [])
    assert all(set(m.values()) == {"core1"} for m in r.vrrp_masters.values())


# ---------------------------------------------------------------- captures

def test_decoders_round_trip():
    fr = pcap.ether("ff:ff:ff:ff:ff:ff", "02:00:00:00:00:01", 0x0800,
                    pcap.ipv4("10.0.0.1", "224.0.0.5", 89, pcap.ospf_hello("1.1.1.1", "0.0.0.1", "255.255.255.0", 5, 20)),
                    vlan=30)
    p = pcap.decode(0, fr)
    assert p.vlan == 30 and p.ip["proto"] == 89
    assert (p.ospf["area"], p.ospf["hello"], p.ospf["dead"], p.ospf["mask"]) == ("0.0.0.1", 5, 20, "255.255.255.0")
    n = pcap.decode(0, pcap.ether("02:00:00:00:00:02", "02:00:00:00:00:01", 0x0800,
                                  pcap.ipv4("1.1.1.1", "2.2.2.2", 6, pcap.tcp(179, 5000, 1, 1, "PA", pcap.bgp_notification(2, 2)))))
    assert n.bgp == [{"type": 3, "code": 2, "subcode": 2}]


def test_ipv4_checksum_valid():
    hdr = pcap.ipv4("10.1.1.1", "10.2.2.2", 17, b"x" * 10)[:20]
    assert pcap._csum(hdr) == 0


def _pcapng(frames):
    def blk(t, body):
        body += b"\0" * (-len(body) % 4)
        return struct.pack("<II", t, len(body) + 12) + body + struct.pack("<I", len(body) + 12)
    out = blk(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
    out += blk(1, struct.pack("<HHI", 1, 0, 65535))
    for ts, fr in frames:
        us = int(ts * 1e6)
        out += blk(6, struct.pack("<IIIII", 0, us >> 32, us & 0xFFFFFFFF, len(fr), len(fr)) + fr)
    return out


def test_pcapng_reader(tmp_path):
    f = pcap.ether("ff:ff:ff:ff:ff:ff", "02:00:00:00:00:01", 0x0806,
                   pcap.arp(1, "02:00:00:00:00:01", "10.0.0.5", "00:00:00:00:00:00", "10.0.0.1"))
    path = tmp_path / "x.pcapng"
    path.write_bytes(_pcapng([(1.5, f), (2.0, f)]))
    pk = pcap.read_packets(str(path))
    assert len(pk) == 2 and pk[0].arp["spa"] == "10.0.0.5" and abs(pk[0].ts - 1.5) < 1e-6


@pytest.mark.parametrize("fault", sorted(capgen.CAP_FAULTS))
def test_capture_faults(tmp_path, fault):
    path = str(tmp_path / "c.pcap")
    exp = capgen.make_capture(77, [fault], path)
    assert {f.code for f in analyze_file(path)} == exp


def test_healthy_capture_clean(tmp_path):
    path = str(tmp_path / "c.pcap")
    capgen.make_capture(78, [], path)
    assert analyze_file(path) == []


def test_capture_corroborates_config(tmp_path):
    ctx, _ = labgen.make(21, ["bgp_peer_as"])
    d = tmp_path / "lab"
    labgen.write_lab(ctx, str(d))
    (d / "captures").mkdir()
    capgen.make_capture(21, ["bgp_bad_peer_as"], str(d / "captures" / "edge.pcap"))
    r = analyze_path(str(d))
    cap = next(f for f in r.findings if f.code == "CAP_BGP_NOTIFICATION")
    assert not cap.is_root and r.root_codes == ["BGP_PEER_AS_MISMATCH"]


def test_two_faults_on_same_link_both_reported(tmp_path):
    # regression: duplicate router-id used to mask a passive transit link on the same adjacency
    r, exp = _analyze(tmp_path, 91084, ["ospf_passive", "dup_router_id"])
    assert set(r.root_codes) == exp == {"OSPF_PASSIVE_TRANSIT", "ROUTER_ID_DUPLICATE"}
