# Final Hardening Pack — Group OCC2 / Youssouf FARRAGE

**Module:** Network Hardening — 4th-year Engineering, Major Cybersecurity & IOT Trust (ESILV)
**Platform:** Microsoft Azure (Site A) + AWS eu-west-3 (Site B)  
**Period:** TD1 (2026-03-04) → TD6 (2026-03-15)  
**Normative anchors:** NIST SP 800-53, 800-41, 800-94, 800-52, 800-77

---

## Sanity checks (Appendix C compliance)

| Check | Status |
|---|---|
| Repo readable in 5 minutes | ✅ — start with `executive/Executive_Summary_1p.md` |
| Regression suite runs in <10 min | ✅ — `bash tests/regression/run_all.sh` |
| Every major claim has a reproducible proof artifact | ✅ — see `report/Final_Report.md` claims table |

---

## Quick start

```bash
# Run full regression suite
bash tests/regression/run_all.sh

# Read the executive summary
cat executive/Executive_Summary_1p.md

# Review all security claims
cat report/Final_Report.md
```

---

## Repository structure

```
final-hardening-pack/
  README.md                        ← you are here
  executive/
    Executive_Summary_1p.md        ← non-technical 1-page summary
  architecture/
    reachability_matrix.csv        ← TD1 flow matrix
    assumptions.md                 ← platform constraints (Azure/AWS)
  controls/
    firewall/                      ← TD2 nftables policy
    ids/                           ← TD3 Suricata rules
    remote_access/                 ← TD5 SSH + IPsec config
    tls_edge/                      ← TD4 nginx TLS config
  evidence/
    baseline/                      ← TD1 captures, before states
    after/                         ← TD2-TD5 proof artifacts
  tests/
    TEST_CARDS.md                  ← structured test cards
    regression/
      run_all.sh                   ← orchestrator
      R1_firewall.sh
      R2_tls.sh
      R3_remote_access.sh
      R4_detection.sh
      results/                     ← timestamped run outputs
  report/
    Final_Report.md                ← claims table + risk register
    Risk_Register.md
    30_60_90_Plan.md
    Peer_Review.md
```

---

## Infrastructure summary

| Site | Cloud | Subnet | Key VMs |
|---|---|---|---|
| Site A | Azure (West Europe) | NH-LAN 10.10.10.0/24 | gw-fw (10.10.10.4), kali/client (10.10.10.10) |
| Site A | Azure | NH-DMZ 10.10.20.0/24 | srv-web (10.10.20.10) |
| Site A | Azure | NH-WAN 10.10.99.0/24 | gw-fw WAN NIC (10.10.99.5) |
| Site B | AWS eu-west-3 | NH-DMZ 10.10.20.0/24 | siteB-gw (10.10.20.4), siteB-srv (10.10.20.10) |

Public IPs: Azure pip = **98.66.160.46** | AWS Elastic IP = **35.181.66.138**
