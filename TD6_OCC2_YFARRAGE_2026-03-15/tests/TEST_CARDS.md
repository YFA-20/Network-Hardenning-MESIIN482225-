# TEST_CARDS.md — Structured Test Cards

**Group OCC2 / Youssouf FARRAGE | ESILV, 4th year, Major Cybersecurity & IOT Trust | Final Hardening Pack**

---

## FP-C-FW-01 — FORWARD chain: allowed flows pass

**Claim:** C-FW-01 — Only authorised flows are forwarded LAN→DMZ  
**Setup:** nftables deployed on gw-fw; Azure UDRs active; srv-web running nginx  
**Action:**
```bash
curl -sk https://10.10.20.10          # HTTPS — should succeed
curl -s http://10.10.20.10            # HTTP — should succeed
ssh -o ConnectTimeout=5 awsuser@10.10.20.10  # SSH — should reach sshd
```
**Expected:** HTTP 200, HTTPS 200, SSH prompt (or publickey error — TCP handshake completes)  
**Observed:** See `tests/regression/results/<timestamp>/R1_firewall.txt`  
**Evidence:** `evidence/after/counters_after.txt` — F01, F02, F04 counters increment  
**Telemetry:** No NFT_FWD_DENY entries for these ports

---

## FP-C-FW-02 — FORWARD chain: forbidden ports blocked

**Claim:** C-FW-01, C-FW-02 — Non-authorised flows are dropped  
**Setup:** same as FP-C-FW-01  
**Action:**
```bash
nc -vz -w 3 10.10.20.10 3306   # MySQL — should timeout
nc -vz -w 3 10.10.20.10 12345  # Random — should timeout
nc -vz -w 3 10.10.10.10 22     # DMZ→LAN SSH — should timeout (from srv-web)
```
**Expected:** All three: Connection timed out / refused  
**Observed:** See `tests/regression/results/<timestamp>/R1_firewall.txt`  
**Evidence:** `evidence/after/firewall_drops.txt`  
**Telemetry:** NFT_FWD_DENY IN=eth0 DPT=3306, DPT=12345; NFT_FWD_DENY IN=eth1 DPT=22

---

## FP-C-TLS-01 — TLS protocol version

**Claim:** C-TLS-01 — TLS 1.2 and TLS 1.3 only; legacy disabled  
**Setup:** nginx hardened config deployed; srv-web running  
**Action:**
```bash
openssl s_client -connect 10.10.20.10:443 -tls1_3 < /dev/null 2>&1 | grep "Protocol"
openssl s_client -connect 10.10.20.10:443 -tls1 < /dev/null 2>&1 | grep -E "handshake|alert"
```
**Expected:** TLSv1.3 handshake succeeds; TLS 1.0 handshake fails  
**Observed:** See `tests/regression/results/<timestamp>/R2_tls.txt`  
**Evidence:** `evidence/after/sslscan_after.txt`  
**Telemetry:** sslscan shows "TLSv1.3 enabled", "TLSv1 disabled"

---

## FP-C-TLS-02 — ECDHE-only cipher suites

**Claim:** C-TLS-02 — All suites provide forward secrecy  
**Setup:** same as FP-C-TLS-01  
**Action:**
```bash
openssl s_client -connect 10.10.20.10:443 < /dev/null 2>&1 | grep "Cipher"
```
**Expected:** Cipher shows ECDHE prefix (e.g., ECDHE-RSA-AES256-GCM-SHA384 or TLS_AES_256_GCM_SHA384)  
**Observed:** See `tests/regression/results/<timestamp>/R2_tls.txt`  
**Evidence:** `evidence/after/sslscan_after.txt` — 0 non-ECDHE suites  
**Telemetry:** Before: 16 non-ECDHE suites. After: 0.

---

## FP-C-TLS-03 — HSTS header

**Claim:** C-TLS-03 — HSTS present on every HTTPS response  
**Setup:** same as FP-C-TLS-01  
**Action:**
```bash
curl -vk https://10.10.20.10 2>&1 | grep -i strict
```
**Expected:** `Strict-Transport-Security: max-age=300`  
**Observed:** See `tests/regression/results/<timestamp>/R2_tls.txt`  
**Evidence:** `evidence/after/curl_hsts_check.txt`  
**Telemetry:** nginx access log shows 200 for the request

---

## FP-C-SSH-01 — SSH key-only auth

**Claim:** C-SSH-01, C-SSH-02 — Password and root login disabled  
**Setup:** sshd_config.d/99-td5-hardening.conf deployed on siteB-srv; IPsec tunnel up  
**Action:**
```bash
ssh -o PubkeyAuthentication=no -o ConnectTimeout=5 awsuser@10.10.20.10
ssh -i ~/.ssh/nh_lab_key -o ConnectTimeout=5 root@10.10.20.10
ssh -i ~/.ssh/nh_lab_key awsuser@10.10.20.10 "echo SSH_KEY_OK"
```
**Expected:** First two: Permission denied. Third: `SSH_KEY_OK`  
**Observed:** See `tests/regression/results/<timestamp>/R3_remote_access.txt`  
**Evidence:** `evidence/after/authlog_excerpt.txt`  
**Telemetry:** auth.log shows "Connection closed [preauth]" and "not listed in AllowUsers"

---

## FP-C-VPN-01 — IPsec tunnel established and encrypting

**Claim:** C-VPN-01, C-VPN-02 — IKEv2 tunnel ESTABLISHED; inter-site traffic is ESP-encrypted  
**Setup:** strongSwan running on both gateways; public IPs reachable  
**Action:**
```bash
sudo ipsec statusall | grep -E "ESTABLISHED|IKE proposal|ESP"
ping -c 4 10.10.20.10   # from siteA-client
```
**Expected:** "ESTABLISHED", "AES_CBC_256/HMAC_SHA2_256_128", ping 0% loss  
**Observed:** See `tests/regression/results/<timestamp>/R3_remote_access.txt`  
**Evidence:** `evidence/after/ipsec_status_siteA.txt`, `evidence/after/esp_capture.txt`  
**Telemetry:** tcpdump on eth1 shows ESP-in-UDP (UDP/4500), no cleartext ICMP

---

## FP-C-IDS-01 — Suricata detects Nmap NSE scan

**Claim:** C-IDS-01, C-IDS-02 — IDS sees boundary traffic; SID 2024364 fires  
**Setup:** Suricata running on gw-fw; ET Open rules loaded; gw-fw in data path  
**Action:**
```bash
sudo nmap -sS -sV -sC 10.10.20.10   # from kali/client
sudo grep "2024364" /var/log/suricata/fast.log | tail -5
```
**Expected:** At least 1 alert for SID 2024364 (ET SCAN Possible Nmap User-Agent Observed)  
**Observed:** See `tests/regression/results/<timestamp>/R4_detection.txt`  
**Evidence:** `evidence/after/fast_log_nmap.txt`  
**Telemetry:** fast.log entry: `[1:2024364:4] ET SCAN Possible Nmap User-Agent Observed`

---

## FP-C-IDS-02 — Custom rule SID 9000001

**Claim:** C-IDS-03 — /admin detection rule fires correctly, no false positive on /  
**Setup:** same as FP-C-IDS-01; local.rules loaded  
**Action:**
```bash
curl http://10.10.20.10/admin        # positive test
curl http://10.10.20.10/             # negative test
sudo grep "9000001" /var/log/suricata/fast.log | wc -l  # before = N, after positive = N+1
```
**Expected:** +1 alert after /admin; count unchanged after /  
**Observed:** See `tests/regression/results/<timestamp>/R4_detection.txt`  
**Evidence:** `evidence/after/fast_log_admin.txt`  
**Telemetry:** fast.log: `[1:9000001:1] LOCAL Unauthorized access attempt to /admin`
