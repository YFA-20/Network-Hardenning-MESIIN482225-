# TD3 — IDS/IPS Detection Engineering with Suricata
**Group:** OCC2 | **Student:** Youssouf FARRAGE | **Module:** Network Hardening — ESILV 4th year, Major Cybersecurity & IOT Trust
**Date:** 2026-03-06/08 | **Engine:** Suricata 6.0.4 | **Platform:** Microsoft Azure

---

## Topology

```
Internet (Azure public IP)
        |
    [eth0 - 10.10.10.4]
        |
      gw-fw  ← Suricata 6.0.4 (UTM)
        |
    [eth1 - 10.10.20.4]
        |
   ┌────┴────┐
client      srv-web
10.10.10.10  10.10.20.10
(Kali)       (nginx 1.18.0)
```

**Azure constraint:** Promiscuous mode is not supported. Suricata runs on `gw-fw` in UTM mode, monitoring both eth0 (LAN) and eth1 (DMZ) via af-packet.

---

## What was proven

| Proof | Result |
|---|---|
| Sensor visibility | decoder.pkts 1691→2169, TTL=63 confirms gw-fw routing |
| Community detection | SID 2024364 (Nmap UA) — 29 hits on `nmap -sS -sV -sC` |
| Custom rule | SID 9000001 — GET /admin detected, GET / not detected |
| Tuning | SID 2210059: 49→0 with suppress; SID 2024364: 29/29 preserved |
| Bonus | SID 2400009 + 2402000 — real Spamhaus/Dshield SSH probes detected |

---

## How to reproduce

### Prerequisites
- Azure VMs running (resource group: rg-nh-lab)
- Suricata 6.0.4 active on gw-fw
- ET Open rules loaded (`sudo suricata-update`)

### 1. Verify Suricata is up and rules loaded
```bash
# On gw-fw
sudo systemctl status suricata
sudo grep "rule files processed" /var/log/suricata/suricata.log | tail -1
# Expected: 2 rule files processed. 48796 rules successfully loaded
```

### 2. Visibility proof
```bash
# From client (10.10.10.10)
curl http://10.10.20.10/
ping -c 4 10.10.20.10

# On gw-fw — confirm packets seen
sudo grep "decoder.pkts" /var/log/suricata/stats.log | tail -5
```

### 3. Community rule trigger
```bash
# From client — -sC flag required for NSE User-Agent rule
sudo nmap -sS -sV -sC 10.10.20.10

# On gw-fw
sudo grep "2024364" /var/log/suricata/fast.log | wc -l
# Expected: ≥ 20 hits
```

### 4. Custom rule test
```bash
# Positive test (should trigger)
curl http://10.10.20.10/admin

# Negative test (should NOT trigger)
curl http://10.10.20.10/

# On gw-fw
sudo grep "9000001" /var/log/suricata/fast.log
```

### 5. Verify tuning
```bash
# On gw-fw
sudo grep "2210059" /var/log/suricata/fast.log | wc -l
# Expected: 0
sudo cat /etc/suricata/threshold.conf
# Expected: suppress gen_id 1, sig_id 2210059
```

---

## Repository structure

```
TD3_OCC2_YFARRAGE_2026-03-08/
├── README.md                          ← This file
├── report.md                          ← Full technical report
├── config/
│   ├── local.rules                    ← Custom rule (sid:9000001)
│   ├── interface_selection.txt        ← UTM architecture justification
│   └── suricata_config_extract.txt    ← Key config parameters
├── tests/
│   ├── commands.txt                   ← All trigger commands with context
│   └── TEST_CARDS.md                  ← 8 test cards (T01–T08)
├── evidence/
│   ├── visibility_proof.txt           ← decoder.pkts + TTL=63
│   ├── alerts_excerpt.txt             ← fast.log (AFTER tuning)
│   └── before_after_counts.txt        ← Tuning evidence (84→29 alerts)
└── appendix/
    └── failure_modes.md               ← 8 failure modes (5 encountered)
```

---

## Key configuration files on gw-fw

| File | Purpose |
|---|---|
| `/etc/suricata/suricata.yaml` | Main config (HOME_NET, af-packet, rule-path, threshold-file) |
| `/var/lib/suricata/rules/suricata.rules` | ET Open signatures (48,795 rules) |
| `/var/lib/suricata/rules/local.rules` | Custom rule (1 rule) |
| `/etc/suricata/threshold.conf` | Suppress SID 2210059 |
| `/var/log/suricata/fast.log` | Alert log |
| `/var/log/suricata/eve.json` | Full event log (JSON) |
