# TD2 — Firewall Policy From Flows

**Author:** Youssouf FARRAGE | **Group:** OCC2 | **School:** ESILV, 4th year, Major Cybersecurity & IOT Trust | **Date:** 2026-03-05
**Platform:** Microsoft Azure | **Duration:** ~3 hours

---

## Summary

Implementation of a default-deny stateful firewall on `gw-fw` using nftables.
Traffic flows from the TD1 reachability matrix are translated into explicit allow rules.
The policy is validated with 12 tests (6 positive, 6 negative). **Score: 12/12.**

A key prerequisite for this lab on Azure is the configuration of **User Defined Routes (UDR)** and NIC IP Forwarding to force LAN↔DMZ traffic through gw-fw — the Azure fabric routes between subnets internally by default.

---

## Repository Structure

```
TD2_OCC2_YFARRAGE_2026-03-05/
├── README.md                       ← this file
├── report.md                       ← full lab report
│
├── config/
│   ├── policy.md                   ← written firewall policy (flow table)
│   ├── firewall_ruleset.txt        ← nft list ruleset output (with counters)
│   └── rollback.sh                 ← emergency flush script
│
├── tests/
│   ├── TEST_CARDS.md               ← 7 test cards (TD2-T01 through TD2-T07)
│   └── commands.txt                ← all commands used (all phases)
│
├── evidence/
│   ├── counters_before.txt         ← nft counters at 0 (clean baseline)
│   ├── counters_after.txt          ← nft counters after all tests
│   └── deny_logs.txt               ← NFT_FWD_DENY + NFT_IN_DENY kernel logs
│
└── appendix/
    └── failure_modes.md            ← 7 failure modes with causes and fixes
```

---

## Quick Reference

**Firewall host:** gw-fw (eth0=LAN 10.10.10.4, eth1=DMZ 10.10.20.4)

**Rules summary:**

| Chain | Rule | Action |
|-------|------|--------|
| forward | established/related | accept |
| forward | LAN→srv-web TCP/80 | accept (F01) |
| forward | LAN→srv-web TCP/22 | accept (F02) |
| forward | LAN→DMZ ICMP ≤5/s | accept (F03) |
| forward | everything else | drop + log |
| input | loopback | accept |
| input | established/related | accept |
| input | LAN TCP/22 | accept (M01) |
| input | 89.30.39.100 TCP/22 | accept (M02 admin-pc) |
| input | 92.184.117.191 TCP/22 | accept (M03 secondary) |
| input | LAN ICMP | accept (M04) |
| input | everything else | drop + log |
| output | all | accept |

**Emergency rollback:** `sudo nft flush ruleset` (run from Azure Serial Console)

---

## Key Technical Findings

1. **Azure UDR is mandatory** — without it, LAN↔DMZ traffic bypasses gw-fw entirely (TTL stays at 64)
2. **Azure NIC IP Forwarding** is separate from OS-level `ip_forward=1` — both are required
3. **TTL proof**: TTL=63 after UDR confirms gw-fw is in the data path (was 64 in TD1)
4. **nc -vuz UDP false positive**: always reports "succeeded" with DROP policy; confirm via kernel logs
5. **"Permission denied (publickey)"**: SSH application-layer error, NOT a firewall block
6. **Live brute-force**: 19 NFT_IN_DENY entries from internet scanners confirm default-deny value
