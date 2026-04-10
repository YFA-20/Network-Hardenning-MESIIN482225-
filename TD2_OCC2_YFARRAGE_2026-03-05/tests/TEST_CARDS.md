# TD2 Test Cards — Firewall Policy Enforcement
**Author:** Youssouf FARRAGE — Group OCC2 | ESILV, 4th year, Major Cybersecurity & IOT Trust
**Date:** 2026-03-05
**Lab:** TD2 Network Hardening — gw-fw nftables default-deny firewall

---

**Test ID:** TD2-T01

## 1) Claim
HTTP (TCP/80) from LAN client (10.10.10.10) to srv-web (10.10.20.10) is forwarded through gw-fw; the rule F01 counter increments on each request.

## 2) Preconditions
- gw-fw running with `table inet filter` loaded and chain `forward` policy drop
- nginx running on srv-web (10.10.20.10)
- Azure UDR `rt-nh-lan` routes 10.10.20.0/24 via 10.10.20.4 (gw-fw eth1)
- Rule F01: `ip saddr 10.10.10.0/24 ip daddr 10.10.20.10 tcp dport 80 counter accept`

## 3) Configuration fragment
```
ip saddr 10.10.10.0/24 ip daddr 10.10.20.10 tcp dport 80 counter packets 2 bytes 120 accept
```

## 4) Test method
### Positive test (should succeed)
- Command: `curl -sI http://10.10.20.10 | head -5`  (from client 10.10.10.10)
- Expected result: HTTP 200 OK response headers from nginx

### Negative test (should fail)
- Command: `nc -vz -w 3 10.10.20.10 12345`  (from client 10.10.10.10)
- Expected result: connection timed out (packet dropped silently by default-deny)

## 5) Telemetry / evidence
- Firewall counter: `evidence/counters_after.txt` — F01 shows `packets 2 bytes 120` (incremented from 0)
- Deny log: `evidence/deny_logs.txt` — N1 entry `DPT=12345 NFT_FWD_DENY` confirms unlisted port dropped

## 6) Result
- PASS
- TCP/80 to srv-web forwarded correctly. Counter increment (0→2) proves the rule was exercised. DPT=12345 dropped as expected confirming default-deny is active.

## 7) Artifacts
- `tests/commands.txt` (P1 and N1)
- `evidence/counters_before.txt`, `evidence/counters_after.txt`
- `config/firewall_ruleset.txt` (F01)

---

**Test ID:** TD2-T02

## 1) Claim
Unlisted ports (not in the explicit allow-list) from LAN to DMZ are silently dropped; the NFT_FWD_DENY counter increments for each blocked attempt.

## 2) Preconditions
- gw-fw chain `forward` policy drop active
- Default-deny log rule at end of chain: `counter log prefix "NFT_FWD_DENY " limit rate 10/minute`
- Client 10.10.10.10 can reach gw-fw for testing

## 3) Configuration fragment
```
# End of forward chain — catches everything not matched above:
counter packets 24 bytes 1285 log prefix "NFT_FWD_DENY " limit rate 10/minute
```

## 4) Test method
### Positive test (default-deny is working when these fail)
- Command: `nc -vz -w 3 10.10.20.10 12345`  (N1 — random high port)
- Expected result: timed out — packet dropped by default-deny

### Negative test (confirm allowed port NOT in deny counter)
- Command: `curl -sI http://10.10.20.10`  (TCP/80 — allowed)
- Expected result: HTTP 200 — appears in F01 counter, NOT in deny counter

## 5) Telemetry / evidence
- Deny counter: `evidence/counters_after.txt` — `NFT_FWD_DENY` shows `packets 24 bytes 1285`
- Deny logs: `evidence/deny_logs.txt` — entries for DPT=12345, 3306, 23, 3389, 8080, 53(UDP) all tagged `NFT_FWD_DENY`
- F01 counter shows 2 packets for TCP/80 (allowed, not in deny total)

## 6) Result
- PASS
- 24 packets hit the default-deny rule across N1–N6 tests. All 6 negative tests produced `NFT_FWD_DENY` log entries. TCP/80 traffic (2 pkts) was accepted and does NOT appear in deny logs.

## 7) Artifacts
- `tests/commands.txt` (N1–N6)
- `evidence/deny_logs.txt`
- `evidence/counters_after.txt`

---

**Test ID:** TD2-T03

## 1) Claim
Each denied packet produces a kernel log entry prefixed `NFT_FWD_DENY` or `NFT_IN_DENY`, containing source IP, destination IP, and destination port.

## 2) Preconditions
- Log rules in place at end of both chains: `counter log prefix "NFT_FWD_DENY "` and `counter log prefix "NFT_IN_DENY "`
- journald kernel log persistence enabled (persistent across reboots)
- Rate limit 10/minute prevents log flooding

## 3) Configuration fragment
```
# Forward chain (last rule):
counter packets 24 bytes 1285 log prefix "NFT_FWD_DENY " limit rate 10/minute

# Input chain (last rule):
counter packets 32 bytes 2108 log prefix "NFT_IN_DENY " limit rate 10/minute
```

## 4) Test method
### Positive test (deny log produced)
- Command: `nc -vz -w 3 10.10.20.10 3306`  then `sudo journalctl -k | grep NFT_FWD_DENY`
- Expected result: log entry with `SRC=10.10.10.10 DST=10.10.20.10 DPT=3306`

### Negative test (allowed traffic NOT in deny log)
- Command: `curl -sI http://10.10.20.10`  then check logs
- Expected result: no `NFT_FWD_DENY` entry for DPT=80

## 5) Telemetry / evidence
- `evidence/deny_logs.txt` — real journald output from gw-fw (boot -1)
  - N2 example: `NFT_FWD_DENY IN=eth0 OUT=eth1 SRC=10.10.10.10 DST=10.10.20.10 DPT=3306`
  - N6 example: `NFT_IN_DENY IN=eth1 SRC=10.10.20.10 DST=10.10.20.4 DPT=22`
  - Also: external SSH scanners (193.163.125.63, 143.244.190.213) blocked by NFT_IN_DENY

## 6) Result
- PASS
- All 6 negative tests produced log entries. Log format includes SRC, DST, DPT as required. NFT_IN_DENY also captured real internet brute-force attempts, validating that the input chain default-deny is actively blocking external threats.

## 7) Artifacts
- `tests/commands.txt` (deny log capture command)
- `evidence/deny_logs.txt`

---

**Test ID:** TD2-T04

## 1) Claim
`config/rollback.sh` restores full permissive forwarding from a locked-out state within 30 seconds.

## 2) Preconditions
- `config/rollback.sh` present and executable (`chmod +x`)
- Access to gw-fw via SSH or Azure serial console
- `net.ipv4.ip_forward=1` must be re-enabled after flush if unset

## 3) Configuration fragment
```bash
#!/bin/bash
echo "[ROLLBACK] Flushing all nftables rules..."
sudo nft flush ruleset
echo "[ROLLBACK] Setting permissive forwarding..."
sudo sysctl -w net.ipv4.ip_forward=1
echo "[ROLLBACK] Done — all traffic now passes. Re-apply firewall rules manually."
```

## 4) Test method
### Positive test (rollback restores access)
- Command: `bash config/rollback.sh`  then `curl -sI http://10.10.20.10`
- Expected result: script completes in <5s; HTTP 200 from srv-web; `nft list ruleset` shows empty table

### Negative test (verify rules are gone after flush)
- Command: `sudo nft list ruleset` after rollback
- Expected result: empty output (no chains, no rules)

## 5) Telemetry / evidence
- `config/rollback.sh` — script present and executable
- After rollback: `nft list ruleset` returns empty, confirming flush succeeded
- Traffic to previously-blocked ports succeeds after rollback

## 6) Result
- PASS
- Script flushes ruleset in ~1 second. All traffic passes immediately after. Re-applying firewall rules takes <30s. Rollback tested and verified during TD2 session.

## 7) Artifacts
- `config/rollback.sh`
- `config/firewall_ruleset.txt` (for re-application after rollback)

---

**Test ID:** TD2-T05

## 1) Claim
SSH admin access to gw-fw itself (TCP/22 on INPUT chain) is preserved after applying default-deny; LAN admin and authorized external IPs can still connect.

## 2) Preconditions
- INPUT chain policy drop active
- Rules M01 and M02 added BEFORE policy was set to drop (SSH-before-DROP procedure followed)
- LAN client at 10.10.10.10; admin-pc at 89.30.39.100

## 3) Configuration fragment
```
# INPUT chain — SSH access rules added before policy drop was set:
ip saddr 10.10.10.0/24 tcp dport 22 counter packets 1 bytes 60 accept
ip saddr 89.30.39.100 tcp dport 22 counter packets 6 bytes 360 accept
```

## 4) Test method
### Positive test (SSH to gw-fw works)
- Command: `ssh -o ConnectTimeout=3 user@10.10.10.1 hostname`  (from LAN client)
- Expected result: returns "gw-fw"

### Negative test (unauthorized IP blocked)
- Command: `nc -vz -w 3 10.10.10.4 22`  from an IP not in the allow-list
- Expected result: timed out — NFT_IN_DENY entry generated

## 5) Telemetry / evidence
- `evidence/counters_after.txt` — M01 counter shows `packets 1 bytes 60` (LAN SSH used during test)
- M02 counter shows `packets 6 bytes 360` (admin-pc connection during session)
- `evidence/deny_logs.txt` — NFT_IN_DENY entries confirm unauthorized IPs (193.163.125.63, 143.244.190.213 etc.) blocked

## 6) Result
- PASS
- SSH to gw-fw from LAN worked throughout the TD2 session. Counters M01 and M02 confirm successful access. External SSH scanners appear in NFT_IN_DENY, confirming unauthorized access is blocked.

## 7) Artifacts
- `tests/commands.txt` (P4 — SSH to gw-fw)
- `evidence/counters_after.txt` (M01, M02)
- `evidence/deny_logs.txt` (NFT_IN_DENY external IPs)

---

**Test ID:** TD2-T06

## 1) Claim
Every allow rule in the ruleset explicitly specifies source address, destination address, and destination port — no any-any rules exist in the forward or input chains.

## 2) Preconditions
- Final `table inet filter` ruleset loaded on gw-fw
- `nft list ruleset` available for inspection

## 3) Configuration fragment
```
# Example of a fully-scoped rule (NOT any-any):
ip saddr 10.10.10.0/24 ip daddr 10.10.20.10 tcp dport 80 counter accept
#         ^^^^^^^^^^^^^^  ^^^^^^^^^^^^^^^^  ^^^^^^^^^^^
#         source subnet   dest host         dest port
```

## 4) Test method
### Positive test (scoped rules only)
- Command: `sudo nft list table inet filter`  and inspect all accept rules
- Expected result: every `accept` rule has explicit `saddr`, `daddr`, and `dport`/`icmp type`

### Negative test (no wildcard accept)
- Command: `sudo nft list table inet filter | grep -v ct | grep -v iif | grep accept`
- Expected result: no line matching `accept` without address/port qualifiers

## 5) Telemetry / evidence
- `config/firewall_ruleset.txt` — all 5 forward-chain accept rules and 6 input-chain accept rules are fully scoped
- No rule of the form `counter accept` without source/dest qualifiers (except `ct state established,related` and `iif "lo"` which are inherently scoped by state/interface)

## 6) Result
- PASS
- Inspection of ruleset confirms: F01 (saddr+daddr+tcp/80), F02 (saddr+daddr+tcp/22), F03 (saddr+daddr+icmp), F04 (saddr+daddr+tcp/443). No any-any accept rules present.

## 7) Artifacts
- `config/firewall_ruleset.txt`
- `config/policy.md` (design rationale)

---

**Test ID:** TD2-T07

## 1) Claim
Counter comparison between `counters_before.txt` and `counters_after.txt` proves that all positive tests exercised their expected rules and all negative tests incremented the deny counter.

## 2) Preconditions
- `evidence/counters_before.txt` captured before any test traffic
- `evidence/counters_after.txt` captured after all positive and negative tests
- All counters at 0 at test start (fresh ruleset load or reboot with saved nftables.conf)

## 3) Configuration fragment
```
# counters_after.txt — forward chain after all tests:
ct state established,related counter packets 70 bytes 16487 accept
ip ... tcp dport 80  counter packets 2 bytes 120 accept   # P1 HTTP
ip ... tcp dport 22  counter packets 2 bytes 120 accept   # P2 SSH
ip ... icmp ...      counter packets 1 bytes 84  accept   # P3 ping
ip ... tcp dport 443 counter packets 1 bytes 60  accept   # P6 HTTPS
counter packets 24 bytes 1285 log prefix "NFT_FWD_DENY "  # N1-N6
```

## 4) Test method
### Positive test (counters incremented by test traffic)
- Command: `diff evidence/counters_before.txt evidence/counters_after.txt`
- Expected result: every rule shows higher packet/byte counts after tests

### Negative test (deny counter accounts for blocked traffic)
- Command: count `NFT_FWD_DENY` entries in deny_logs.txt and compare to counter
- Expected result: deny counter (24 pkts) consistent with logged entries across N1–N6

## 5) Telemetry / evidence
- `evidence/counters_before.txt` — all forward chain counters at 0 before tests
- `evidence/counters_after.txt` — F01=2pkts, F02=2pkts, F03=1pkt, F04=1pkt, FWD_DENY=24pkts
- `evidence/deny_logs.txt` — 6 negative tests (N1–N6) logged; multiple retries (3 per test × 6 = 18+ pkts) plus extra attempts explain 24-pkt total

## 6) Result
- PASS
- Counter delta unambiguously maps each positive test to its rule: P1→F01(2pkts), P2→F02(2pkts), P3→F03(1pkt), P6→F04(1pkt). Deny counter (24 pkts total) accounts for 3 retries per negative test. All 6 negative tests appear in deny_logs.txt.

## 7) Artifacts
- `evidence/counters_before.txt`
- `evidence/counters_after.txt`
- `evidence/deny_logs.txt`
- `tests/commands.txt`
