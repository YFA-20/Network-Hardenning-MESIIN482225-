# FAILURE MODES — TD3 Network Hardening
**Group:** OCC2 | **Student:** Youssouf FARRAGE | **School:** ESILV, 4th year, Major Cybersecurity & IOT Trust | **Date:** 2026-03-06/08

This appendix documents all failure modes encountered during the lab, plus standard failure modes from the TD3 reference sheet. All encountered issues are marked **[ENCOUNTERED]** and include the actual fix applied.

---

## Standard Failure Modes (Reference)

| ID | Failure | Symptom | Fix |
|---|---|---|---|
| FM-01 | Wrong interface selected | Zero alerts despite traffic | Run `ip link`; identify correct interface bound to target segment |
| FM-02 | Promiscuous mode off | Sensor only sees its own traffic | `ip link set <iface> promisc on` + hypervisor "Allow All" |
| FM-03 | Encrypted traffic (TLS) | Payload rules cannot match | Use metadata rules (SNI, JA3) or place sensor on cleartext segment |
| FM-04 | Rule scope too broad | Alerts fire on everything | Narrow: specific ports, flow direction, URI match |
| FM-05 | No threshold on noisy rule | Log fills up, real alerts buried | Add threshold/suppression + document rationale |
| FM-06 | Time mismatch between VMs | Alert timestamps do not correlate | Sync clocks: `timedatectl set-ntp true` |
| FM-07 | Asymmetric routing | Session tracking breaks, missing flows | Place sensor where both directions of flow pass (or use gw-fw UTM) |

---

## Encountered Failure Modes (Lab-specific)

### FM-08 — Azure promiscuous mode constraint [ENCOUNTERED]

| Field | Detail |
|---|---|
| **Failure** | Azure vSwitch drops all non-unicast frames at hypervisor level |
| **Symptom** | sensor-ids VM shows zero packets despite being on the same subnet |
| **Root cause** | Azure does not expose raw layer-2 frames to VMs; promiscuous mode setting has no effect |
| **Fix applied** | Moved Suricata to gw-fw (UTM architecture). gw-fw routes all LAN↔DMZ traffic and therefore sees every packet natively without needing promiscuous mode |
| **Reference** | `config/interface_selection.txt` |

---

### FM-09 — default-rule-path mismatch [ENCOUNTERED]

| Field | Detail |
|---|---|
| **Failure** | suricata.yaml pointed to `/etc/suricata/rules/` but `suricata-update` writes to `/var/lib/suricata/rules/` |
| **Symptom** | `No rule files match /etc/suricata/rules/suricata.rules` in logs; 0 signatures loaded |
| **Root cause** | Default install config and suricata-update use different paths |
| **Fix applied** | `sudo sed -i 's\|default-rule-path: /etc/suricata/rules\|default-rule-path: /var/lib/suricata/rules\|' /etc/suricata/suricata.yaml` |

---

### FM-10 — threshold-file not configured [ENCOUNTERED]

| Field | Detail |
|---|---|
| **Failure** | `threshold-file` line was commented out in suricata.yaml and pointed to wrong extension (`.config` vs `.conf`) |
| **Symptom** | `Threshold config parsed: 0 rule(s) found` — suppress rule had no effect |
| **Root cause** | Default suricata.yaml ships with threshold-file commented out |
| **Fix applied** | `sudo sed -i 's\|# threshold-file: /etc/suricata/threshold.config\|threshold-file: /etc/suricata/threshold.conf\|' /etc/suricata/suricata.yaml` |

---

### FM-11 — local.rules saved to wrong path [ENCOUNTERED]

| Field | Detail |
|---|---|
| **Failure** | Created `/etc/suricata/rules/local.rules` but default-rule-path is `/var/lib/suricata/rules/` |
| **Symptom** | `2 rule files processed` but still 48,795 rules (not 48,796) — custom rule silently absent |
| **Root cause** | Suricata resolves relative rule filenames against default-rule-path |
| **Fix applied** | `sudo cp /etc/suricata/rules/local.rules /var/lib/suricata/rules/local.rules` |
| **Lesson** | Always place custom rule files in `default-rule-path` directory |

---

### FM-12 — Scan ran before Suricata threads were fully initialised [ENCOUNTERED]

| Field | Detail |
|---|---|
| **Failure** | nmap scan was launched immediately after `systemctl restart suricata` |
| **Symptom** | Zero alerts despite nmap completing successfully; eve.json showed HTTP flows but no alerts |
| **Root cause** | Suricata 6.x has a ~2-minute initialisation window between service start and AFP capture thread activation. Packet processing was not yet active when nmap ran |
| **Diagnosis** | `suricata.log`: rules loaded at T+13s but `All AFP capture threads are running` only at T+1m50s |
| **Fix applied** | `sleep 120` after `systemctl restart suricata` before running test traffic |

---

### FM-13 — SID 2210059 noise from dual-interface UTM capture [ENCOUNTERED]

| Field | Detail |
|---|---|
| **Failure** | High volume of `SURICATA STREAM pkt seen on wrong thread` alerts (49 per nmap scan) |
| **Symptom** | fast.log filled with Priority 3 noise; real Priority 1 alerts harder to spot |
| **Root cause** | Suricata sees the same TCP flow on both eth0 and eth1 (ingress + egress on gw-fw). The stream reassembly engine detects the "duplicate" and logs an internal diagnostic event |
| **Fix applied** | `suppress gen_id 1, sig_id 2210059` in `/etc/suricata/threshold.conf` |
| **Rationale** | This is an engine artifact, not adversary behaviour. Suppression (not threshold) is appropriate because the event can never represent a real threat in this architecture |
| **Result** | 49 → 0 alerts; real detections (SID 2024364) fully preserved |
