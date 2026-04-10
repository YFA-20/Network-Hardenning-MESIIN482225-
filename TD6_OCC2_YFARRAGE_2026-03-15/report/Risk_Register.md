# Risk Register
**Group OCC2 / Youssouf FARRAGE | ESILV, 4th year, Major Cybersecurity & IOT Trust | Updated 2026-03-15**

Scoring: Impact × Exploitability (1–5 each). Source risks from TD1; status updated through TD5.

| ID | Risk | Impact | Exploit. | Score | Status | Control applied |
|---|---|---|---|---|---|---|
| R01 | SSH on gw-fw exposed to 0.0.0.0/0 — live brute-force observed | 5 | 5 | 25 | ✅ MITIGATED | TD2: nftables INPUT restricts SSH to whitelisted IPs |
| R02 | No nftables rules — all forwarded traffic passes unfiltered | 5 | 4 | 20 | ✅ MITIGATED | TD2: default-deny FORWARD chain with 5 explicit allows |
| R03 | LAN↔DMZ bypasses gw-fw — Azure UDR missing | 5 | 4 | 20 | ✅ MITIGATED | TD2: UDRs + NIC IP Forwarding; TTL=63 proof |
| R04 | Plaintext HTTP — no TLS, credentials exposed | 4 | 3 | 12 | ✅ MITIGATED | TD4: TLS 1.2/1.3, ECDHE-only, HSTS |
| R05 | SSH on srv-web accessible from any LAN IP | 4 | 3 | 12 | ✅ MITIGATED | TD5: AllowUsers, key-only, MaxAuthTries 3 |
| R06 | No IDS sensor in DMZ — sensor-ids absent | 3 | 4 | 12 | ⚠️ PARTIAL | TD3: Suricata UTM covers LAN↔DMZ boundary; east-west blind |
| R07 | Inter-site traffic crosses internet in cleartext | 5 | 4 | 20 | ✅ MITIGATED | TD5: IKEv2 IPsec AES-256, ESP-in-UDP confirmed |
| R08 | No SSH key management policy | 3 | 3 | 9 | ⚠️ PARTIAL | TD5: ED25519 keys deployed; no rotation policy yet |
| R09 | No centralized log aggregation | 3 | 2 | 6 | ❌ OPEN | Out of scope TD1–TD5; 30-day plan item |
| R10 | ICMP LAN→DMZ unrestricted | 2 | 2 | 4 | ✅ MITIGATED | TD2: ICMP rate-limited to 5/s |
| R11 | Certificate expiry — no automated renewal | 4 | 3 | 12 | ❌ OPEN | Self-signed cert expires 2026-03-18; ACME not implemented |
| R12 | nginx session tickets enabled — forward secrecy risk | 3 | 2 | 6 | ❌ OPEN | `ssl_session_tickets off` not applied |
| R13 | /api/ has no authentication layer | 4 | 3 | 12 | ❌ OPEN | Out of scope TD4; 60-day plan item |
| R14 | IPsec uses PSK — no certificate auth | 3 | 2 | 6 | ❌ OPEN | Lab constraint; 90-day plan item |
| R15 | Rate limiting scoped to /api/ only | 3 | 2 | 6 | ⚠️ PARTIAL | TD4: /api/ covered; root and other paths uncovered |
