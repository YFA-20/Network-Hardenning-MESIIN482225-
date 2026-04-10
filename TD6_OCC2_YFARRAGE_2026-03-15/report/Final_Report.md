# Final Report — Network Hardening Pack
**Group OCC2 / Youssouf FARRAGE | ESILV, 4th year, Major Cybersecurity & IOT Trust | TD1→TD6 | 2026-03-04 → 2026-03-15**

---

## 1. Security Claims Table

Every claim below is testable, points to a control, and is backed by three artefacts: a config snippet, a regression test, and a telemetry artefact.

| Claim ID | Claim | Control location | Config snippet | Regression test | Telemetry artefact |
|---|---|---|---|---|---|
| C-FW-01 | Only TCP/80, TCP/443, TCP/22 (from LAN only), and ICMP (rate-limited) are forwarded from LAN to DMZ; all other flows are dropped and logged | nftables FORWARD chain on gw-fw | `controls/firewall/nftables.conf` | `tests/regression/R1_firewall.sh` | `evidence/after/firewall_drops.txt` |
| C-FW-02 | DMZ-initiated traffic toward LAN is blocked by default-deny FORWARD policy | nftables FORWARD chain on gw-fw | `controls/firewall/nftables.conf` | `tests/regression/R1_firewall.sh` (negative N5) | `evidence/after/firewall_drops.txt` (NFT_FWD_DENY IN=eth1) |
| C-FW-03 | gw-fw INPUT chain is default-deny; only LAN SSH and whitelisted admin IPs are accepted | nftables INPUT chain on gw-fw | `controls/firewall/nftables.conf` | `tests/regression/R1_firewall.sh` (negative N6) | `evidence/after/firewall_drops.txt` (NFT_IN_DENY) |
| C-TLS-01 | srv-web offers TLS 1.2 and TLS 1.3 only; TLS 1.0 and 1.1 are disabled | nginx ssl_protocols on srv-web | `controls/tls_edge/nginx_after.conf` | `tests/regression/R2_tls.sh` | `evidence/after/sslscan_after.txt` |
| C-TLS-02 | All negotiated TLS cipher suites carry the ECDHE prefix (forward secrecy guaranteed on every session) | nginx ssl_ciphers on srv-web | `controls/tls_edge/nginx_after.conf` | `tests/regression/R2_tls.sh` | `evidence/after/sslscan_after.txt` |
| C-TLS-03 | HSTS header is present with max-age=300 on all HTTPS responses | nginx add_header on srv-web | `controls/tls_edge/nginx_after.conf` | `tests/regression/R2_tls.sh` | `evidence/after/curl_hsts_check.txt` |
| C-TLS-04 | /api/ endpoint is rate-limited to 1 req/s with burst=2; excess requests return HTTP 503 | nginx limit_req on srv-web | `controls/tls_edge/nginx_conf_ratelimit.txt` | `tests/regression/R2_tls.sh` | `evidence/after/rate_limit_test.txt` |
| C-IDS-01 | Suricata 6.0.4 on gw-fw sees all LAN↔DMZ traffic (packet counter growth confirmed, TTL=63 proof) | Suricata UTM on gw-fw (eth0+eth1) | `controls/ids/suricata.yaml` | `tests/regression/R4_detection.sh` | `evidence/after/suricata_stats.txt` |
| C-IDS-02 | ET Open ruleset (48,795 signatures) detects Nmap NSE scan — SID 2024364 fires reproducibly | Suricata ET Open rules on gw-fw | `controls/ids/suricata.rules` (ET Open) | `tests/regression/R4_detection.sh` | `evidence/after/fast_log_nmap.txt` |
| C-IDS-03 | Custom SID 9000001 detects GET /admin and does not fire on GET / (no false positives) | `controls/ids/local.rules` | `controls/ids/local.rules` | `tests/regression/R4_detection.sh` | `evidence/after/fast_log_admin.txt` |
| C-SSH-01 | SSH password authentication is disabled on siteB-srv; only ED25519 key login is accepted | sshd_config.d/99-td5-hardening.conf on siteB-srv | `controls/remote_access/99-td5-hardening.conf` | `tests/regression/R3_remote_access.sh` | `evidence/after/authlog_excerpt.txt` |
| C-SSH-02 | Root login via SSH is blocked on siteB-srv | sshd_config.d/99-td5-hardening.conf on siteB-srv | `controls/remote_access/99-td5-hardening.conf` | `tests/regression/R3_remote_access.sh` | `evidence/after/authlog_excerpt.txt` |
| C-VPN-01 | IKEv2 IPsec tunnel is ESTABLISHED between Azure (98.66.160.46) and AWS (35.181.66.138) using AES-256/SHA-256/MODP-2048 | strongSwan on siteA-gw and siteB-gw | `controls/remote_access/ipsec.conf` | `tests/regression/R3_remote_access.sh` | `evidence/after/ipsec_status_siteA.txt` |
| C-VPN-02 | Inter-site traffic (10.10.10.0/24 ↔ 10.10.20.0/24) is encrypted in transit — ESP-in-UDP captured on WAN, no cleartext | strongSwan ESP tunnel | `controls/remote_access/ipsec.conf` | `tests/regression/R3_remote_access.sh` | `evidence/after/esp_capture.txt` |

---

## 2. Architecture Summary

### Network zones

| Zone | Subnet | Assets | Trust level |
|---|---|---|---|
| NH-LAN (Site A) | 10.10.10.0/24 | gw-fw (10.10.10.4), kali/client (10.10.10.10) | High — internal |
| NH-DMZ (Site A) | 10.10.20.0/24 | srv-web (10.10.20.10) | Medium — published services |
| NH-WAN | 10.10.99.0/24 | gw-fw WAN (10.10.99.5), siteB-gw WAN (10.10.99.4) | None — internet |
| NH-DMZ (Site B) | 10.10.20.0/24 | siteB-gw (10.10.20.4), siteB-srv (10.10.20.10) | Medium — AWS DMZ |

### Key platform constraints (Azure/AWS)

See `architecture/assumptions.md` for full details. Critical constraints:
- Azure requires UDRs to force LAN↔DMZ traffic through gw-fw (verified by TTL drop 64→63)
- Azure NIC IP Forwarding must be enabled at hypervisor level (distinct from `sysctl ip_forward`)
- Azure SNAT + AWS Elastic IP require `leftid`/`rightid` = public IPs in strongSwan; NAT-T activates automatically
- Azure reserves .0–.3 in every subnet — gw-fw uses .4 instead of .1

---

## 3. TD-by-TD Evidence Map

| TD | Deliverable | Key evidence files |
|---|---|---|
| TD1 | Network baseline, flow matrix, risk analysis | `evidence/baseline/baseline.pcap`, `architecture/reachability_matrix.csv` |
| TD2 | nftables default-deny firewall, 12/12 tests pass | `controls/firewall/nftables.conf`, `evidence/after/firewall_drops.txt` |
| TD3 | Suricata UTM IDS, ET Open + custom rule, tuning | `controls/ids/local.rules`, `evidence/after/fast_log_nmap.txt` |
| TD4 | TLS hardening, rate limiting, edge controls | `controls/tls_edge/nginx_after.conf`, `evidence/after/sslscan_after.txt` |
| TD5 | SSH hardening, IKEv2 IPsec VPN Azure↔AWS | `controls/remote_access/ipsec.conf`, `evidence/after/esp_capture.txt` |

---

## 4. Failure Modes Encountered and Resolved

| ID | Issue | TD | Resolution |
|---|---|---|---|
| FM-07 | tcpdump background job suspended over SSH | TD1 | Two-terminal capture method |
| FM-08 | Azure hypervisor blocks promiscuous mode — sensor-ids not viable | TD1/TD3 | UTM architecture on gw-fw |
| FM-09 | suricata-update rule path mismatch | TD3 | `default-rule-path` corrected via sed |
| FM-10 | threshold-file directive commented out | TD3 | Uncommented + path corrected |
| FM-11 | local.rules at wrong path (0 signatures loaded) | TD3 | Copied to `/var/lib/suricata/rules/` |
| FM-12 | Suricata capture threads not ready — 0 alerts on first scan | TD3 | Wait for "All AFP capture threads are running" |
| FM-13 | nginx `return` directive bypasses `limit_req` (phase ordering) | TD4 | Serve real static file instead |
| FM-14 | nginx `if ($host)` + other `if` blocks — non-atomic evaluation | TD4 | Replaced with method restriction |
| FM-15 | Azure SNAT causes asymmetric routing on gw-fw eth1 | TD5 | Linux policy routing table 101 |
| FM-16 | IKE identity mismatch with double NAT | TD5 | `leftid`/`rightid` set to public IPs |
