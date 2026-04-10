# Test Cards — TD1
**Course:** Network Hardening — ESILV, Major Cybersecurity & IOT Trust | **Date:** 2026-03-04 | **Author:** Youssouf FARRAGE

---

**Test ID:** TD1-T01

## 1) Claim
Client (10.10.10.10) can reach srv-web (10.10.20.10) on HTTP port 80 and receives a valid HTTP 200 response.

## 2) Preconditions
- gw-fw running, ip_forward=1
- nginx running on srv-web (`systemctl status nginx`)
- client and srv-web on correct subnets (NH-LAN and NH-DMZ)
- No blocking nftables rule in place yet (baseline state)

## 3) Configuration fragment
```bash
# On srv-web: nginx default site
# /etc/nginx/sites-enabled/default → listen 80 default_server
systemctl status nginx   # Active: active (running)
ss -tulpn | grep :80     # LISTEN 0.0.0.0:80
```

## 4) Test method

### Positive test (should succeed)
- **Command:** `ssh nh-client "curl -s -o /dev/null -w '%{http_code}' http://10.10.20.10"`
- **Expected result:** `200`

### Negative test (should fail)
- **Command:** `ssh nh-client "curl -s -o /dev/null -w '%{http_code}' http://10.10.20.10:443"`
- **Expected result:** connection refused or timeout (HTTPS not configured)

## 5) Telemetry / evidence
- `curl` return code 200 observed during pre-flight checklist
- `evidence/baseline.pcap` does not capture this traffic (Azure UDR issue — see O5 in report.md)
- `evidence/nmap_srvweb.txt`: port 80 open

## 6) Result
- **PASS** — HTTP 200 confirmed during session (2026-03-04)
- **Limitation:** curl/ping traffic does not traverse gw-fw without UDR. The HTTP session is direct at the Azure hypervisor layer, bypassing gw-fw inspection. This is documented as Risk R03.

## 7) Artifacts
- `evidence/baseline.pcap`
- `evidence/nmap_srvweb.txt`
- `tests/commands.txt` (lines 12–14)

---

**Test ID:** TD1-T02

## 1) Claim
No unexpected port is open on srv-web in the range 1–1000. Only ports 22 (SSH) and 80 (HTTP) are open, matching the flow matrix.

## 2) Preconditions
- srv-web running
- Nmap available on client
- client can reach srv-web (pre-flight passed)

## 3) Configuration fragment
```bash
# On srv-web:
ss -tulpn
# Expected output:
# tcp LISTEN 0.0.0.0:22  (sshd)
# tcp LISTEN 0.0.0.0:80  (nginx)
```

## 4) Test method

### Positive test (should succeed — expected ports open)
- **Command:** `ssh nh-client "nmap -sS -p 22,80 10.10.20.10"`
- **Expected result:** Both ports `22/tcp open` and `80/tcp open`

### Negative test (should fail — no unexpected ports)
- **Command:** `ssh nh-client "nmap -sS -p 1-21,23-79,81-1000 10.10.20.10"`
- **Expected result:** All 998 ports `filtered` or `closed` — none `open`

## 5) Telemetry / evidence
- `evidence/nmap_srvweb.txt`: only 22 and 80 open in ports 1–1000
- 998 ports filtered (Azure NSG blocks all others inbound)

## 6) Result
- **PASS** — Nmap scan confirmed only ports 22 and 80 open in range 1–1000
- **Limitation:** Ports above 1000 not scanned. Nmap run without -A (no OS detection, no script scan) to stay within defensive inventory scope.

## 7) Artifacts
- `evidence/nmap_srvweb.txt`
- `tests/commands.txt` (lines 15–17)

---

**Test ID:** TD1-T03

## 1) Claim
The baseline pcap capture contains traffic evidence of SSH administrative access and reveals unsolicited external SSH brute-force attempts against gw-fw.

## 2) Preconditions
- tcpdump running on gw-fw `any` interface
- Admin SSH session active from Kali (89.30.39.100) to gw-fw (10.10.10.4)
- gw-fw public IP reachable from internet

## 3) Configuration fragment
```bash
# Capture command (on gw-fw, interactive terminal):
sudo tcpdump -i any -w /tmp/baseline.pcap -nn
# Duration: ~5 minutes
# Traffic generated: curl http://10.10.20.10, ping -c 4 10.10.20.10
```

## 4) Test method

### Positive test (expected admin traffic present)
- **Command:** `tcpdump -r baseline.pcap -nn 'tcp port 22 and host 89.30.39.100'`
- **Expected result:** Packets visible — SSH session between Kali and gw-fw

### Negative test (LAN→DMZ traffic absent — expected limitation)
- **Command:** `tcpdump -r baseline.pcap -nn 'host 10.10.10.10 and host 10.10.20.10'`
- **Expected result:** 0 packets — confirms Azure UDR issue (Risk R03)

## 5) Telemetry / evidence
- 874 packets total captured
- 159 packets: `89.30.39.100 ↔ 10.10.10.4:22` (admin SSH — F04 ✅)
- 59 packets: external IPs → `10.10.10.4:22` (brute-force — Risk R01 ✅)
- 0 packets: `10.10.10.10 ↔ 10.10.20.10` (LAN→DMZ bypass confirmed — Risk R03 ✅)

## 6) Result
- **PASS** — Capture confirms expected admin traffic (O1, O2) and reveals two unplanned findings (O3 Azure platform noise, O4 brute-force, O5 routing bypass)
- **Limitation:** Capture was taken on gw-fw, not on a dedicated DMZ sensor. HTTP/ICMP traffic between client and srv-web is not visible. This will be addressed when UDR is deployed in TD2.

## 7) Artifacts
- `evidence/baseline.pcap`
- `report.md` — Observations O1 through O5

---

**Test ID:** TD1-T04

## 1) Claim
The topology diagram accurately reflects the observed IP addressing, routing, and zone boundaries as confirmed by `ip addr`, `ip route`, and `ss -tulpn` on each VM.

## 2) Preconditions
- All VMs running
- SSH access to each VM (via ProxyJump through gw-fw)
- Commands `ip addr`, `ip route`, `ss -tulpn` available on all VMs

## 3) Configuration fragment
```bash
# On each VM, run:
hostname && ip addr show && ip route show && ss -tulpn

# gw-fw expected:
# eth0: 10.10.10.4/24, eth1: 10.10.20.4/24
# routes: 10.10.10.0/24 dev eth0, 10.10.20.0/24 dev eth1

# client expected:
# eth0: 10.10.10.10/24, default via 10.10.10.4

# srv-web expected:
# eth0: 10.10.20.10/24, default via 10.10.20.4
```

## 4) Test method

### Positive test (topology matches diagram)
- **Command:** Compare `ip addr` output from each VM against diagram.pdf
- **Expected result:** IPs, subnets, and gateway match the diagram on every VM

### Negative test (cross-zone direct routing without gw-fw fails once UDR+firewall applied)
- **Command (TD2):** `ssh nh-client "ping -c 2 10.10.20.10"` after nftables default-deny applied
- **Expected result (TD2):** Ping fails — gw-fw enforces the trust boundary

## 5) Telemetry / evidence
- `ip addr` output collected on all VMs during Part A (transcribed in report.md)
- `ip route` confirmed default gateway points to gw-fw on client and srv-web
- pcap O2 confirms ProxyJump path through gw-fw

## 6) Result
- **PASS** — All observed IPs match the diagram and flow matrix
- **Limitation:** Topology deviation from course default: gw-fw uses .4 instead of .1 due to Azure reserved addresses (.0–.3). Documented in README.md.
- **Limitation:** sensor-ids absent from topology. Diagram shows this as a dashed/missing node.

## 7) Artifacts
- `report.md` — Part A asset inventory
- `diagram.pdf` (to be added)
- `evidence/baseline.pcap` — confirms observed IP addresses
