# TD3 — IDS/IPS Detection Engineering with Suricata
## Evidence Pack Report

| Field | Value |
|---|---|
| **Module** | Network Hardening — 4th-year Engineering, Major Cybersecurity & IOT Trust (ESILV) |
| **Lab** | TD3 — IDS/IPS: Detection Engineering with Proof |
| **Group / Student** | Group OCC2 / Youssouf FARRAGE — ESILV, 4th year, Major Cybersecurity & IOT Trust |
| **Date** | 2026-03-06 / 2026-03-08 |
| **IDS Engine** | Suricata 6.0.4 RELEASE |
| **Normative anchor** | NIST SP 800-94 — Guide to Intrusion Detection and Prevention Systems |
| **Platform** | Microsoft Azure (resource group: rg-nh-lab) |

---

## Executive Summary

TD1 established the network baseline and identified the risk surface; TD2 implemented a default-deny stateful firewall on `gw-fw` that brought LAN↔DMZ traffic under control. TD3 picks up where that left off: once all inter-zone traffic is funnelled through a single boundary node, what does it actually look like?

Suricata 6.0.4 was configured in UTM mode on `gw-fw` — the same machine that runs nftables — monitoring both eth0 (LAN) and eth1 (DMZ) simultaneously via af-packet. This placement, established in TD1 as the practical architecture for this Azure deployment, gives the sensor full visibility over all inter-zone traffic without requiring promiscuous mode on a separate VM.

Four proofs were collected as required by the TD3 specification. Sensor visibility was confirmed by packet counter growth and TTL routing analysis (TTL=63 on ICMP replies, proving gw-fw is in the data path). The ET Open community ruleset (48,795 signatures) was validated by triggering SID 2024364 reproducibly with an Nmap NSE scan. A custom rule — SID 9000001 — was written to detect GET requests to `/admin`, then confirmed with both a positive and a negative test. Finally, SID 2210059, a structural noise source inherent to dual-interface capture, was suppressed: 49 alerts became 0 with no impact on signal fidelity.

As a bonus, two real-world threat intelligence matches (Spamhaus DROP, Dshield) were observed against inbound SSH probes from external IPs — organic detections that occurred with no manual trigger, demonstrating the value of the ET Open ruleset in a lab directly exposed to the internet.

---

## 1. Topology and Sensor Placement

### 1.1 Network Architecture

| VM | Role | Zone | IP (private) |
|---|---|---|---|
| `gw-fw` | Boundary firewall + IDS sensor (UTM) | NH-LAN + NH-DMZ | 10.10.10.4 / 10.10.20.4 |
| `client` | Traffic generator (Kali Linux) | NH-LAN | 10.10.10.10 |
| `srv-web` | Target service (nginx 1.18.0, OpenSSH 8.9p1) | NH-DMZ | 10.10.20.10 |

This topology is unchanged from TD1 and TD2. Three VMs are deployed on Microsoft Azure (resource group `rg-nh-lab`); the fourth VM from the reference design (`sensor-ids`, 10.10.20.50) could not be created due to the Azure for Students vCPU quota limit of 6, which is fully consumed by the three existing VMs. As documented in TD1, Suricata is co-located on `gw-fw` as the compensating measure.

### 1.2 Sensor Architecture — UTM on gw-fw

The reference design places `sensor-ids` on the DMZ segment in promiscuous mode to capture all intra-DMZ and LAN↔DMZ traffic. That design is not viable on Azure for two independent reasons: the vCPU quota prevents deploying a fourth VM, and the Azure hypervisor delivers only unicast frames addressed to the VM's own MAC address — enabling promiscuous mode on a guest has no effect at the hypervisor level.

The architecture selected from TD1 and maintained throughout TD2 is therefore UTM (Unified Threat Management): Suricata runs directly on `gw-fw`, which routes all LAN↔DMZ traffic and observes every packet natively without needing promiscuous mode. This is the validated cloud-compatible deployment path documented in `oci_cloud_alternative.md`. TD3 builds on this placement rather than reconsidering it.

### 1.3 Monitored Interfaces

| Interface | Zone | IP | Direction observed |
|---|---|---|---|
| `eth0` | NH-LAN | 10.10.10.4 | Traffic from client (egress from LAN) |
| `eth1` | NH-DMZ | 10.10.20.4 | Traffic to srv-web (ingress to DMZ) |

Both interfaces run in `af-packet` mode with `cluster_flow` hashing, ensuring each TCP flow is consistently processed by the same thread. Because each LAN↔DMZ packet enters on one interface and exits on the other, the same flow is seen twice — once on eth0, once on eth1. The stream reassembly engine flags this as a sequence anomaly and generates SID 2210059 events. This is a known and expected property of the dual-interface UTM setup, addressed by tuning in Section 5.

```
Client (10.10.10.10)
       |
    [eth0 - 10.10.10.4]
       |
     gw-fw  ← Suricata 6.0.4
       |
    [eth1 - 10.10.20.4]
       |
   srv-web (10.10.20.10)
```

---

## 2. Sensor Visibility Proof

### 2.1 Method

Traffic was generated from `client` toward `srv-web` while monitoring `decoder.pkts` in `stats.log` on `gw-fw`:

```bash
# From client (Kali 10.10.10.10)
curl http://10.10.20.10/
ping -c 4 10.10.20.10
```

```bash
# On gw-fw — real-time packet counter
sudo grep "decoder.pkts" /var/log/suricata/stats.log | tail -10
```

### 2.2 Results

```
Date: 3/6/2026 -- 09:39:01  decoder.pkts | Total | 1691
Date: 3/6/2026 -- 09:39:09  decoder.pkts | Total | 1726
Date: 3/6/2026 -- 09:39:17  decoder.pkts | Total | 1796
Date: 3/6/2026 -- 09:39:25  decoder.pkts | Total | 1831
Date: 3/6/2026 -- 09:39:33  decoder.pkts | Total | 1866
Date: 3/6/2026 -- 09:39:41  decoder.pkts | Total | 1979
...
Date: 3/6/2026 -- 09:40:13  decoder.pkts | Total | 2169
```

Counter increased by **478 packets** over 72 seconds during active traffic generation.

**TTL routing confirmation:**

```
ping 10.10.20.10 → TTL=63
```

Linux hosts default to TTL=64. The value 63 means exactly one hop decremented the TTL — that hop is `gw-fw`. This confirms all ICMP traffic traverses the firewall before reaching srv-web, and therefore Suricata on gw-fw sees it.

**Conclusion:** Suricata captures LAN↔DMZ traffic. Visibility proof is operational.

---

## 3. Deterministic Detection — Community Rules

### 3.1 Ruleset

ET Open (Emerging Threats Open) rules were loaded via `suricata-update`:

```
48,795 rules successfully loaded from /var/lib/suricata/rules/suricata.rules
```

### 3.2 Trigger

```bash
# From client (Kali 10.10.10.10)
sudo nmap -sS -sV -sC 10.10.20.10
```

The `-sC` flag activates Nmap Scripting Engine (NSE), which sends HTTP requests containing the string `Nmap Scripting Engine` in the User-Agent header. This string is matched by SID 2024364.

> **Note:** `-sS -sV` alone is insufficient. The User-Agent injection only occurs when NSE scripts run (HTTP requests are required). The `-sC` flag is mandatory to trigger this rule.

### 3.3 Alert — SID 2024364

```
Rule: ET SCAN Possible Nmap User-Agent Observed
Classification: Web Application Attack
Priority: 1

03/06/2026-09:54:08.373860  [**] [1:2024364:4] ET SCAN Possible Nmap User-Agent Observed [**]
  [Classification: Web Application Attack] [Priority: 1] {TCP}
  10.10.10.10:58348 -> 10.10.20.10:80

[... 28 additional alerts for the same SID ...]

Total: 29 alerts
Source: 10.10.10.10 (client / Kali) ✓
Destination: 10.10.20.10:80 (srv-web / nginx) ✓
```

### 3.4 Bonus Detections — Threat Intelligence Matches

During normal lab operation, Suricata matched two external IPs against threat intelligence block lists without any manual trigger:

```
03/06/2026-10:19:51  [1:2400009:4637] ET DROP Spamhaus DROP Listed Traffic Inbound group 10
  [Priority: 2] {TCP} 80.94.92.186:59125 -> 10.10.10.4:22

03/06/2026-10:22:36  [1:2402000:7669] ET DROP Dshield Block Listed Source group 1
  [Priority: 2] {TCP} 147.185.132.21:55720 -> 10.10.10.4:22
```

Both source IPs were probing port 22 (SSH) on `gw-fw`. These are real internet-sourced attacks, not lab-generated traffic. Their detection demonstrates that even a lab environment exposed to the internet benefits from threat-intelligence-backed rules — the IDS flagged them automatically with zero configuration effort beyond loading ET Open.

---

## 4. Custom Rule

### 4.1 Objective

Detect unauthorised HTTP GET requests to the `/admin` path on `srv-web`. In a production environment, `/admin` paths expose administrative interfaces and should never be accessible without authentication. Early detection of access attempts allows security teams to investigate before an actual compromise.

### 4.2 Rule Definition

```
alert http $HOME_NET any -> $HTTP_SERVERS any (
    msg:"LOCAL Unauthorized access attempt to /admin";
    flow:established,to_server;
    http.method; content:"GET";
    http.uri; content:"/admin"; startswith;
    sid:9000001; rev:1; priority:1;
)
```

**Rule analysis:**

| Field | Value | Rationale |
|---|---|---|
| `alert http` | Protocol: HTTP | Application-layer inspection, not raw TCP |
| `$HOME_NET any` | Source: any internal IP | Covers all LAN and DMZ hosts |
| `$HTTP_SERVERS any` | Destination: any HTTP server in HOME_NET | Covers srv-web (10.10.20.10) |
| `flow:established,to_server` | Directional filter | Only established flows going to server, not server responses |
| `http.method; content:"GET"` | Method filter | Sticky buffer; matches HTTP method field exactly |
| `http.uri; content:"/admin"; startswith` | URI filter | Sticky buffer; matches URI starting with `/admin` |
| `sid:9000001` | Unique identifier | Custom SID range (9000000+) |
| `rev:1` | Rule version | Enables future versioning without SID collision |
| `priority:1` | Highest priority | Equal to network scan alerts — this warrants immediate investigation |

### 4.3 Test Results

**Positive test:**
```bash
# From client
curl http://10.10.20.10/admin
```

```
fast.log:
03/08/2026-14:33:36.916448  [**] [1:9000001:1] LOCAL Unauthorized access attempt to /admin [**]
  [Classification: (null)] [Priority: 1] {TCP} 10.10.10.10:42666 -> 10.10.20.10:80
```
→ Alert triggered ✓

**Negative test:**
```bash
# From client
curl http://10.10.20.10/
```

```bash
grep "9000001" /var/log/suricata/fast.log | wc -l → 1  (count unchanged)
```
→ No alert for GET / ✓

The rule fires only on the intended path and not on legitimate root requests, confirming correct scope.

---

## 5. Tuning Action — SID 2210059 Suppression

### 5.1 Noise Source — SID 2210059

After loading ET Open rules and running the nmap scan, 49 alerts were generated by SID 2210059:

```
SURICATA STREAM pkt seen on wrong thread
Classification: (null) — Priority: 3
```

These are internal Suricata diagnostic events, not network threats. They arise because each TCP flow traversing `gw-fw` is captured on both eth0 and eth1 — a direct consequence of the dual-interface UTM placement described in Section 1.2. The stream reassembly engine processes the same SYN/ACK sequence from two capture threads and logs an anomaly flag each time.

This noise is structural and predictable in this architecture. The events carry zero security value and bury Priority 1 alerts (SID 2024364) in the alert stream, making the log harder to triage.

### 5.2 Tuning Applied

```bash
# /etc/suricata/threshold.conf
suppress gen_id 1, sig_id 2210059
```

`suppress` was chosen over `threshold` because:
- The event is an engine artifact, not adversary behaviour — no legitimate security value exists
- `track by_src` threshold proved ineffective (each unique source IP was counted separately across different nmap scan ports)
- A global suppress is appropriate when the false positive is architecturally determined

### 5.3 Before / After Evidence

| Metric | BEFORE | AFTER | Delta |
|---|---|---|---|
| SID 2210059 (noise) | 49 | 0 | −49 (−100%) |
| SID 2024364 (signal) | 29 | 29 | 0 (preserved) |
| Total alerts | 84 | 29 | −55 (−65%) |

**Result:** Alert volume reduced by 65% with zero signal loss.

---

## 6. Limitations

### 6.1 TLS Blindness

Suricata on `gw-fw` performs deep packet inspection at the application layer. However, TLS-encrypted traffic (HTTPS, SFTP, encrypted SSH payloads) is opaque to payload-based rules. SID 2024364 relies on an HTTP User-Agent header — if nmap were to target an HTTPS-only endpoint, this rule would not fire.

Mitigation options: JA3/JA3S fingerprinting rules (metadata-based, TLS-aware), SNI extraction, or deployment of a TLS inspection proxy.

### 6.2 Sensor Placement — LAN-internal blind spot

The UTM architecture places Suricata on the LAN↔DMZ boundary. Traffic that stays within the LAN (client-to-client, or client to gw-fw itself) traverses `eth0` but may not be inspected symmetrically depending on flow direction. Additionally, intra-DMZ traffic (srv-web to another DMZ host) would only be seen on `eth1`.

A complete detection architecture would include east-west sensors within each segment.

### 6.3 Rule Coverage Gap — Custom Rule Classification

SID 9000001 does not carry a `classtype` field in its current revision. While `priority:1` ensures it appears at the top of alert streams, SIEM platforms and alert correlation tools rely on `classtype` for automatic triage. This should be addressed in rev:2:

```
classtype:policy-violation;
```

### 6.4 Azure Public Exposure

The lab VMs are reachable from the internet via Azure public IPs. During the lab, real SSH brute-force attempts from Spamhaus-listed IPs (80.94.92.186, 147.185.132.21) were detected. While these are blocked by nftables, the IDS alert volume from external internet noise slightly inflates alert counts and could mask lab-generated events in longer-running sessions.

---

## 7. Troubleshooting — Issues Encountered and Resolved

This section documents the five significant issues encountered during the lab and their resolutions. All are catalogued with root causes in `appendix/failure_modes.md`.

### Issue 1 — Azure promiscuous mode (FM-08)

The standard `sensor-ids` VM design was tested and confirmed non-functional on Azure. Transition to the UTM architecture on `gw-fw` resolved the visibility issue completely. This decision is justified technically in `config/interface_selection.txt`.

### Issue 2 — default-rule-path mismatch (FM-09)

`suricata-update` writes rules to `/var/lib/suricata/rules/` but the default `suricata.yaml` specifies `/etc/suricata/rules/`. Suricata logged `No rule files match` and loaded zero signatures. Fixed by updating `default-rule-path` via `sed`.

### Issue 3 — threshold-file not configured (FM-10)

The `threshold-file` directive was commented out in `suricata.yaml` and pointed to the wrong file extension (`.config` vs `.conf`). The suppress rule was parsed but ignored. Fixed by uncommenting the directive and correcting the path.

### Issue 4 — local.rules path mismatch (FM-11)

`local.rules` was initially created at `/etc/suricata/rules/local.rules`. Because `default-rule-path` is `/var/lib/suricata/rules/`, Suricata resolved the relative filename to the wrong directory. The rule file was being counted (`2 rule files processed`) but contributed 0 signatures. Fixed by copying the file to the correct path.

### Issue 5 — Suricata initialisation timing (FM-12)

After `systemctl restart suricata`, nmap was launched before Suricata's AFP capture threads were active. Suricata 6.x has a ~2-minute gap between service start and full packet capture readiness (`All AFP capture threads are running`). The scan produced zero alerts despite the traffic being visible in `eve.json`. Fixed by waiting for the log confirmation before generating test traffic.

---

*2026-03-08 — Platform: Microsoft Azure | IDS engine: Suricata 6.0.4*
