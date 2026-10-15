# NetTriage case report: `case-02`

6 devices, 14 links, 0 capture(s) analysed in 0.7 ms.

**2 root cause(s), 2 downstream symptom(s).**

| # | Severity | Root cause | Devices | Symptoms explained |
|---|---|---|---|---|
| 1 | critical | edge1 lo0.0 (10.83.255.3) is not advertised in OSPF | edge1 | 2 |
| 2 | critical | LACP passive on both ends of acc1 ae1 <-> core2 ae1: bundle never negotiates | acc1, core2 | 0 |

## 1. edge1 lo0.0 (10.83.255.3) is not advertised in OSPF
`IGP_LOOPBACK_MISSING` - critical - source: config

**Evidence**
- edge1: lo0.0 not under protocols ospf
- iBGP peers cannot reach 10.83.255.3: sessions sourced from it stay Active

**Downstream symptoms (resolve with this fix)**
- BGP session core1 <-> edge1 is Active
- BGP session core2 <-> edge1 is Active

**Remediation**
```
[edit] edge1# set protocols ospf area 0.0.0.0 interface lo0.0 passive
commit check
commit confirmed 5
```
**Verify**
```
core1> show route 10.83.255.3 exact
edge1> show ospf interface
```

## 2. LACP passive on both ends of acc1 ae1 <-> core2 ae1: bundle never negotiates
`LACP_BOTH_PASSIVE` - critical - source: config

**Evidence**
- acc1 ae1: lacp passive
- core2 ae1: lacp passive
- passive partners never send LACPDUs, so no actor/partner exchange

**Remediation**
```
[edit] acc1# set interfaces ae1 aggregated-ether-options lacp active
commit check
commit confirmed 5
```
**Verify**
```
acc1> show lacp interfaces ae1
acc1> show interfaces ae1 terse
```

## Protocol state

| OSPF adjacency | State | Reason |
|---|---|---|
| core1 ge-0/0/20.0 <-> core2 ge-0/0/6.0 | Full |  |
| core1 ge-0/0/14.0 <-> edge1 ge-0/0/12.0 | Full |  |
| core2 ge-0/0/14.0 <-> edge1 ge-0/0/3.0 | Full |  |

| BGP session | Type | State |
|---|---|---|
| core1 <-> core2 | internal | Established |
| core1 <-> edge1 | internal | Active |
| core2 <-> edge1 | internal | Active |
| edge1 <-> isp1 | external | Established |

| LAG | State |
|---|---|
| acc1 ae0 | up |
| acc1 ae1 | DOWN |
| acc2 ae0 | up |
| acc2 ae1 | up |
| core1 ae0 | up |
| core1 ae1 | up |
| core1 ae2 | up |
| core2 ae0 | up |
| core2 ae1 | DOWN |
| core2 ae2 | up |

RSTP root bridge: **core1**

| VRRP segment | Group -> Master |
|---|---|
| 172.16.37.0/24 | 13 -> core1 |
| 172.17.60.0/24 | 19 -> core1 |
