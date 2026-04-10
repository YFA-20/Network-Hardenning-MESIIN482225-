# TEST CARDS — TD3 Network Hardening
**Group:** OCC2 | **Student:** Youssouf FARRAGE | **School:** ESILV, 4th year, Major Cybersecurity & IOT Trust | **Date:** 2026-03-06/08
**Engine:** Suricata 6.0.4 | **Sensor:** gw-fw (UTM architecture)

---

## TD3-T01 — Sensor visibility: traffic traverses gw-fw

| Field | Value |
|---|---|
| **Claim** | Suricata on gw-fw captures LAN↔DMZ HTTP and ICMP traffic in real time |
| **Test type** | Positive |
| **Pre-condition** | Suricata running, eth0 and eth1 in af-packet mode |
| **Trigger** | `curl http://10.10.20.10/` and `ping -c 4 10.10.20.10` from client (10.10.10.10) |
| **Expected result** | `decoder.pkts` counter increases; TTL=63 on ping replies proves gw-fw routing |
| **Actual result** | decoder.pkts: 1691 → 2169 over 80 seconds; ping TTL=63 confirmed |
| **Pass / Fail** | **PASS** |
| **Evidence** | `evidence/visibility_proof.txt` |

---

## TD3-T02 — Community rule triggers deterministically on Nmap scan

| Field | Value |
|---|---|
| **Claim** | SID 2024364 (ET SCAN Possible Nmap User-Agent Observed) fires when nmap NSE scripts execute HTTP requests against srv-web |
| **Test type** | Positive |
| **Pre-condition** | ET Open rules loaded (48,795 signatures), Suricata active |
| **Trigger** | `sudo nmap -sS -sV -sC 10.10.20.10` from client |
| **Expected result** | Alert in fast.log with sid:2024364, src=10.10.10.10, dst=10.10.20.10 |
| **Actual result** | 29 alerts for SID 2024364; source/destination IPs match |
| **Pass / Fail** | **PASS** |
| **Evidence** | `evidence/alerts_excerpt.txt` |
| **Note** | `-sC` flag required — NSE scripts inject `Nmap Scripting Engine` HTTP User-Agent; `-sS -sV` alone does not trigger this rule |

---

## TD3-T03 — Custom rule triggers on /admin request (positive test)

| Field | Value |
|---|---|
| **Claim** | SID 9000001 fires when client sends GET /admin to srv-web |
| **Test type** | Positive |
| **Pre-condition** | local.rules loaded (48,796 total), Suricata active |
| **Trigger** | `curl http://10.10.20.10/admin` from client (10.10.10.10) |
| **Expected result** | Alert in fast.log: `[1:9000001:1] LOCAL Unauthorized access attempt to /admin` |
| **Actual result** | `03/08/2026-14:33:36 [1:9000001:1] LOCAL Unauthorized access attempt to /admin {TCP} 10.10.10.10:42666 -> 10.10.20.10:80` |
| **Pass / Fail** | **PASS** |
| **Evidence** | `evidence/alerts_excerpt.txt`, `config/local.rules` |

---

## TD3-T04 — Custom rule does NOT fire on normal root request (negative test)

| Field | Value |
|---|---|
| **Claim** | SID 9000001 does NOT fire on GET / — rule is path-scoped |
| **Test type** | Negative |
| **Pre-condition** | local.rules loaded, fast.log count at 1 (from positive test) |
| **Trigger** | `curl http://10.10.20.10/` from client |
| **Expected result** | SID 9000001 count remains at 1 — no new alert |
| **Actual result** | `grep "9000001" fast.log \| wc -l` → 1 (unchanged) |
| **Pass / Fail** | **PASS** |
| **Evidence** | `tests/commands.txt` |

---

## TD3-T05 — Custom rule is scoped, versioned, and correctly formed

| Field | Value |
|---|---|
| **Claim** | Rule specifies: protocol (http), flow direction (->), HOME_NET, flow keyword, content matchers, sid, rev, priority |
| **Test type** | Static review |
| **Pre-condition** | N/A |
| **Verification** | Review `config/local.rules` for required fields |
| **Expected result** | All mandatory fields present; no overly broad matching |
| **Actual result** | `alert http $HOME_NET any -> $HTTP_SERVERS any (... flow:established,to_server; http.method; content:"GET"; http.uri; content:"/admin"; startswith; sid:9000001; rev:1; priority:1;)` — all fields present |
| **Pass / Fail** | **PASS** |
| **Evidence** | `config/local.rules` |

---

## TD3-T06 — Tuning reduces noise without hiding real detections

| Field | Value |
|---|---|
| **Claim** | After `suppress gen_id 1, sig_id 2210059`, SID 2210059 count drops to 0 while SID 2024364 count is unchanged |
| **Test type** | Before/After comparison |
| **Pre-condition** | Identical test traffic (same nmap command) run before and after tuning |
| **Trigger (before)** | `sudo nmap -sS -sV -sC 10.10.20.10` → count: 2210059=49, 2024364=29 |
| **Trigger (after)** | `sudo nmap -sS -sV -sC 10.10.20.10` → count: 2210059=0, 2024364=29 |
| **Expected result** | Noise eliminated; signal preserved |
| **Actual result** | SID 2210059: 49 → 0 (100% reduction); SID 2024364: 29 → 29 (0% loss) |
| **Pass / Fail** | **PASS** |
| **Evidence** | `evidence/before_after_counts.txt` |

---

## TD3-T07 — Evidence is reproducible

| Field | Value |
|---|---|
| **Claim** | Re-running the documented commands on the same topology produces alerts with matching SIDs, source, and destination |
| **Test type** | Reproducibility |
| **Pre-condition** | VMs running, Suricata active with current config |
| **Trigger** | Execute commands in `tests/commands.txt` in order |
| **Expected result** | fast.log shows SID 2024364 (10.10.10.10 → 10.10.20.10:80) and SID 9000001 (10.10.10.10 → 10.10.20.10:80 for /admin) |
| **Actual result** | Verified during lab session |
| **Pass / Fail** | **PASS** |
| **Evidence** | `tests/commands.txt`, `evidence/alerts_excerpt.txt` |

---

## TD3-T08 (bonus) — Real-world threat intelligence matches detected

| Field | Value |
|---|---|
| **Claim** | Suricata ET DROP rules match inbound traffic from IPs on Spamhaus DROP and Dshield block lists |
| **Test type** | Passive detection (not manually triggered) |
| **Pre-condition** | ET Open rules loaded, gw-fw exposed to internet (Azure public IP) |
| **Trigger** | External SSH probe from 80.94.92.186 and 147.185.132.21 |
| **Expected result** | Alerts with SID 2400009 (Spamhaus) and SID 2402000 (Dshield) |
| **Actual result** | Both alerts present in fast.log during normal lab operation |
| **Pass / Fail** | **PASS** |
| **Evidence** | `evidence/alerts_excerpt.txt` |
| **Note** | These are unsolicited real attacks — not lab-generated traffic |
