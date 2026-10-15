# NetTriage case report: `case-01`

6 devices, 14 links, 0 capture(s) analysed in 1.2 ms.

**2 root cause(s), 2 downstream symptom(s).**

| # | Severity | Root cause | Devices | Symptoms explained |
|---|---|---|---|---|
| 1 | critical | core1 has no BGP neighbor statement for core2 | core1, core2 | 1 |
| 2 | major | MTU mismatch on core2 ge-0/0/4 (1514) <-> edge1 ge-0/0/13 (9192) | core2, edge1 | 1 |

## 1. core1 has no BGP neighbor statement for core2
`BGP_NEIGHBOR_MISSING` - critical - source: config

**Evidence**
- core2: group IBGP neighbor 10.164.255.1 (peer-as 64626)
- core1: no neighbor matching any address of core2
- core1 resets the TCP/179 connection: core2 cycles Connect/Active

**Downstream symptoms (resolve with this fix)**
- BGP session core1 <-> core2 is Active

**Remediation**
```
[edit] core1# set protocols bgp group IBGP neighbor 10.164.255.2
commit check
commit confirmed 5
```
**Verify**
```
core1> show bgp neighbor 10.164.255.2
core2> show bgp summary
```

## 2. MTU mismatch on core2 ge-0/0/4 (1514) <-> edge1 ge-0/0/13 (9192)
`MTU_MISMATCH` - major - source: config

**Evidence**
- core2 ge-0/0/4: mtu 1514
- edge1 ge-0/0/13: mtu 9192
- frames larger than the smaller MTU are dropped; OSPF DBD exchange stalls in ExStart

**Downstream symptoms (resolve with this fix)**
- OSPF adjacency core2 ge-0/0/4.0 <-> edge1 ge-0/0/13.0 stuck in ExStart

**Remediation**
```
[edit] core2# set interfaces ge-0/0/4 mtu 9192
commit check
commit confirmed 5
```
**Verify**
```
core2> show interfaces ge-0/0/4 | match MTU
edge1> show interfaces ge-0/0/13 | match MTU
```

## Protocol state

| OSPF adjacency | State | Reason |
|---|---|---|
| core1 ge-0/0/20.0 <-> core2 ge-0/0/12.0 | Full |  |
| core1 ge-0/0/22.0 <-> edge1 ge-0/0/3.0 | Full |  |
| core2 ge-0/0/4.0 <-> edge1 ge-0/0/13.0 | ExStart | DBD packets exceed neighbor MTU: exchange never completes (ExStart/Exchange) |

| BGP session | Type | State |
|---|---|---|
| core1 <-> core2 | internal | Active |
| core1 <-> edge1 | internal | Established |
| core2 <-> edge1 | internal | Established |
| edge1 <-> isp1 | external | Established |

| LAG | State |
|---|---|
| acc1 ae0 | up |
| acc1 ae1 | up |
| acc2 ae0 | up |
| acc2 ae1 | up |
| core1 ae0 | up |
| core1 ae1 | up |
| core1 ae2 | up |
| core2 ae0 | up |
| core2 ae1 | up |
| core2 ae2 | up |

RSTP root bridge: **core1**

| VRRP segment | Group -> Master |
|---|---|
| 172.16.36.0/24 | 58 -> core1 |
| 172.17.87.0/24 | 36 -> core1 |
