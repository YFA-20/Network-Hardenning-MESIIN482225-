# TD5 — Test Cards

---

## TD5-T01 — SSH password authentication is disabled

**Claim:** siteB-srv refuses password-based SSH authentication; only public key auth is accepted.

**Preconditions:** `99-td5-hardening.conf` deployed, sshd restarted. Confirmed `PasswordAuthentication no` also set in `60-cloudimg-settings.conf`.

**Test (positive):**
```bash
ssh -i ~/.ssh/nh_lab_key awsuser@10.10.20.10 "echo SSH_KEY_OK"
```

**Test (negative):**
```bash
ssh -o PubkeyAuthentication=no awsuser@10.10.20.10
# Expected: Permission denied (publickey).
```

**Expected:** Positive test prints `SSH_KEY_OK`; negative test is rejected with `Permission denied`.

**Observed:** SSH_KEY_OK returned on positive test. Negative test closed at [preauth] — confirmed in `evidence/authlog_excerpt.txt` line: `Connection closed by authenticating user awsuser 10.10.20.4 port 50066 [preauth]`.

**Evidence file:** `evidence/ssh_tests.txt`, `evidence/authlog_excerpt.txt`

**Result: PASS ✅**

---

## TD5-T02 — Root login via SSH is disabled

**Claim:** siteB-srv rejects SSH connections with username `root`, regardless of key validity.

**Preconditions:** `PermitRootLogin no` set in `99-td5-hardening.conf`.

**Test (positive — blocked):**
```bash
ssh -i ~/.ssh/nh_lab_key root@10.10.20.10
# Expected: Permission denied
```

**Expected:** Connection rejected; sshd log shows `not listed in AllowUsers`.

**Observed:** `User root from 10.10.20.4 not allowed because not listed in AllowUsers` — confirmed in `evidence/authlog_excerpt.txt` at 11:26:49.

**Evidence file:** `evidence/ssh_tests.txt`, `evidence/authlog_excerpt.txt`

**Result: PASS ✅**

---

## TD5-T03 — Only `awsuser` can connect via SSH

**Claim:** The `AllowUsers awsuser` directive restricts SSH access to the single named admin user.

**Preconditions:** `AllowUsers awsuser` set in `99-td5-hardening.conf`.

**Test (positive):**
```bash
ssh -i ~/.ssh/nh_lab_key awsuser@10.10.20.10 whoami
# Expected: awsuser
```

**Test (negative):**
```bash
ssh -i ~/.ssh/nh_lab_key root@10.10.20.10
# Expected: Permission denied
```

**Expected:** `awsuser` accepted; any other user (including root) rejected.

**Observed:** Positive login accepted (auth.log 11:16:48, 11:26:14). Root rejected (auth.log 11:26:49). External brute-force against other usernames also blocked (auth.log entries for 157.245.99.15, 165.227.106.123).

**Evidence file:** `evidence/authlog_excerpt.txt`

**Result: PASS ✅**

---

## TD5-T04 — SSH logs show accept and deny events

**Claim:** `siteB-srv` auth.log records both successful logins and rejection events, providing a full audit trail.

**Preconditions:** sshd running with hardened config; log collection via `grep sshd /var/log/auth.log`.

**Test:**
```bash
sudo tail -n 50 /var/log/auth.log | grep sshd
```

**Expected:** Lines showing `Accepted publickey`, `Connection closed by authenticating user`, and `not allowed because not listed in AllowUsers`.

**Observed:** All three event types confirmed in `evidence/authlog_excerpt.txt`. Additionally, third-party brute-force attempts from external IPs (157.245.99.15, 68.183.79.252, 165.227.106.123) are visible, demonstrating real-world threat exposure.

**Evidence file:** `evidence/authlog_excerpt.txt`

**Result: PASS ✅**

---

## TD5-T05 — IKEv2 tunnel is ESTABLISHED

**Claim:** strongSwan on both gateways establishes an IKEv2 Security Association with the negotiated AES-256/SHA-256/MODP-2048 proposal.

**Preconditions:** strongSwan installed on siteA-gw (Azure) and siteB-gw (AWS). `/etc/ipsec.conf` and `/etc/ipsec.secrets` deployed with matching PSK. `ipsec restart` run on both gateways. NAT-T active (both gateways behind NAT).

**Test:**
```bash
sudo ipsec statusall
```

**Expected:**
```
site-to-site[N]: ESTABLISHED ...
site-to-site{N}: INSTALLED, TUNNEL ...
  10.10.10.0/24 === 10.10.20.0/24
```

**Observed (siteA-gw):** `ESTABLISHED 38 minutes ago, 10.10.99.5[98.66.160.46]...35.181.66.138[35.181.66.138]`. IKE proposal: `AES_CBC_256/HMAC_SHA2_256_128/PRF_HMAC_SHA2_256/MODP_2048`. ESP in UDP (NAT-T active). SPI pair confirmed symmetric with siteB-gw output.

**Evidence file:** `evidence/ipsec_status_siteA.txt`, `evidence/ipsec_status_siteB.txt`

**Result: PASS ✅**

---

## TD5-T06 — Ping crosses the tunnel (ESP on wire)

**Claim:** ICMP traffic from siteA-client to siteB-srv traverses the IPsec tunnel; WAN capture shows ESP-in-UDP, not cleartext ICMP.

**Preconditions:** Tunnel ESTABLISHED (T05). Routes configured on siteA-client (via 10.10.10.4) and siteB-srv (via 10.10.20.4).

**Test (data plane):**
```bash
# From siteA-client:
ping -c 10 10.10.20.10
```

**Test (WAN capture):**
```bash
# On siteA-gw WAN interface (eth1):
sudo tcpdump -i eth1 -c 15 'udp port 4500 or esp'
```

**Expected:** Ping 0% loss; tcpdump shows `UDP-encap: ESP(...)` packets between public IPs, not cleartext ICMP.

**Observed:** 10/10 packets received, 0% loss, avg RTT 4.77 ms. tcpdump confirms bidirectional ESP-in-UDP/4500 between 10.10.99.5 and 35.181.66.138 (public IP of siteB-gw).

**Evidence file:** `evidence/tunnel_ping.txt`, `evidence/esp_capture.txt`

**Result: PASS ✅**

---

## TD5-T07 — Tunnel is scoped to LAN ↔ DMZ

**Claim:** The IPsec policy covers only `10.10.10.0/24 ↔ 10.10.20.0/24`. Traffic to 10.10.99.0/24 (WAN management) is not tunneled.

**Preconditions:** Tunnel ESTABLISHED.

**Test:**
```bash
sudo ipsec statusall | grep "==="
# Expected: 10.10.10.0/24 === 10.10.20.0/24 only
```

**Test (negative — WAN traffic not tunneled):**
```bash
# Ping from siteA-gw to siteB-gw WAN IP — should NOT generate ESP
ping -c 2 10.10.99.4  # routed directly, not through ESP
```

**Expected:** Only one `===` line in statusall output, matching LAN/DMZ subnets.

**Observed:** `10.10.10.0/24 === 10.10.20.0/24` — single policy entry. WAN-to-WAN traffic routes directly. Scoped tunnel confirmed.

**Evidence file:** `evidence/ipsec_status_siteA.txt`

**Result: PASS ✅**

---

## TD5-T08 — Only UDP 500/4500 required on WAN for IKE/NAT-T

**Claim:** With NAT-T active, the tunnel functions using only UDP/500 (IKE initial) and UDP/4500 (IKE + ESP encapsulated). Raw ESP (IP protocol 50) is not required when both peers are behind NAT.

**Preconditions:** Azure NSG and AWS Security Group configured with inbound allow on UDP/500 and UDP/4500. No raw ESP rule required.

**Test:**
```bash
# Review NSG on siteA-gw WAN NIC:
az network nsg rule list --nsg-name nsg-gw-fw-wan --resource-group <RG> -o table

# Review tcpdump — confirm all IPsec traffic uses UDP/4500
sudo tcpdump -i eth1 'esp' -c 5  # should capture nothing (no raw ESP)
sudo tcpdump -i eth1 'udp port 4500' -c 5  # should capture ESP-in-UDP
```

**Expected:** All ESP traffic encapsulated in UDP/4500; no raw ESP frames on wire.

**Observed:** tcpdump capture shows only `UDP-encap: ESP(...)` on port 4500. No raw ESP packets. NAT-T was auto-negotiated by strongSwan via RFC 3947 NAT-D payloads during IKE_SA_INIT.

**Evidence file:** `evidence/esp_capture.txt`, `evidence/nftables_ruleset.txt`

**Result: PASS ✅**
