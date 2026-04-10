# TD5 — SSH Hardening + Site-to-Site IPsec VPN
**Group OCC2 / Youssouf FARRAGE — ESILV, 4th year, Major Cybersecurity & IOT Trust — 2026-03-14**

## Contents

| File | Description |
|------|-------------|
| `report.md` | Full lab report |
| `config/sshd_config_excerpt.txt` | Active sshd hardening parameters on siteB-srv |
| `config/ssh_hardening.md` | SSH hardening rationale and configuration walkthrough |
| `config/ipsec_siteA.conf` | strongSwan `/etc/ipsec.conf` on siteA-gw (Azure) |
| `config/ipsec_siteB.conf` | strongSwan `/etc/ipsec.conf` on siteB-gw (AWS) |
| `config/ipsec.secrets` | PSK file — **PSK REDACTED** |
| `tests/TEST_CARDS.md` | 8 test cards (TD5-T01 to TD5-T08) |
| `tests/commands.txt` | All verification commands with expected outputs |
| `evidence/ssh_tests.txt` | SSH positive and negative test outputs |
| `evidence/authlog_excerpt.txt` | `/var/log/auth.log` extract from siteB-srv |
| `evidence/ipsec_status.txt` | Combined `ipsec statusall` output from both gateways (canonical) |
| `evidence/ipsec_status_siteA.txt` | `ipsec statusall` output from siteA-gw (detailed) |
| `evidence/ipsec_status_siteB.txt` | `ipsec statusall` output from siteB-gw (detailed) |
| `evidence/tunnel_ping.txt` | Ping from siteA-client to siteB-srv through IPsec tunnel |
| `evidence/esp_capture.txt` | tcpdump showing ESP-in-UDP packets on WAN interface |
| `evidence/nftables_ruleset.txt` | nftables ruleset on siteA-gw including IKE/NAT-T INPUT rules |
| `appendix/failure_modes.md` | Failure analysis and troubleshooting log |
| `appendix/cloud_delta.md` | Cloud-specific deviations from the VirtualBox spec |

## Architecture

This TD runs on a **cloud-hybrid** infrastructure, not VirtualBox:

| VM (spec name) | Cloud | Role | Key IPs |
|---------------|-------|------|---------|
| `siteA-gw` | Azure | Gateway + strongSwan | LAN: 10.10.10.4 / WAN: 10.10.99.5 / Public: 98.66.160.46 |
| `siteA-client` | Azure | Admin workstation | 10.10.10.10 |
| `siteB-gw` | AWS eu-west-3 | Gateway + strongSwan | DMZ: 10.10.20.4 / WAN: 10.10.99.4 / Public: 35.181.66.138 |
| `siteB-srv` | AWS eu-west-3 | Bastion / target host | 10.10.20.10 |

Both Azure and AWS reserve .0–.3 in every subnet. WAN and DMZ IPs were configured accordingly to align with the TD5 specification.

## Key Results

- SSH hardened: key-only auth, no root login, `AllowUsers awsuser`, `MaxAuthTries 3`
- IKEv2 IPsec tunnel ESTABLISHED: Azure ↔ AWS over public internet with NAT-T
- ESP-in-UDP (port 4500) confirmed by tcpdump — WAN traffic is opaque to passive observers
- Ping: 10/10 packets, 0% loss, avg 4.77 ms through the encrypted tunnel
- All 8 test cards passing
