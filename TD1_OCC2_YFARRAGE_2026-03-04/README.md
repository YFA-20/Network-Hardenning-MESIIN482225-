# TD1 — Network Baseline for Hardening
**Course:** Network Hardening — ESILV, 4th year, Major Cybersecurity & IOT Trust
**Date:** 2026-03-04
**Group:** OCC2 | **School:** ESILV, 4th year, Major Cybersecurity & IOT Trust
**Team:** Youssouf FARRAGE (solo)

---

## Team members and roles

| Name | Role |
|---|---|
| Youssouf FARRAGE | Network analyst, evidence collector, report author |

---

## Lab topology summary

| VM | Hostname | Zone | IP (lab) | IP (course default) | OS | Key services |
|---|---|---|---|---|---|---|
| gw-fw | nh-gw | LAN + DMZ (trust boundary) | 10.10.10.4 / 10.10.20.4 | 10.10.10.1 / 10.10.20.1 | Ubuntu 22.04 LTS | sshd, ip_forward=1 |
| client | nh-client | NH-LAN (10.10.10.0/24) | 10.10.10.10 | 10.10.10.10 | Ubuntu 22.04 LTS | sshd, nmap, tcpdump |
| srv-web | nh-srvweb | NH-DMZ (10.10.20.0/24) | 10.10.20.10 | 10.10.20.10 | Ubuntu 22.04 LTS | sshd (22), nginx (80) |
| sensor-ids | — | NH-DMZ | **NOT DEPLOYED** | 10.10.20.50 | — | — |

> **Azure deployment note:** The course specifies VirtualBox with IPs starting at .1. On Microsoft Azure,
> addresses .0–.3 are reserved per subnet by the platform. gw-fw therefore uses .4 instead of .1
> on both subnets. All other VMs kept their course-defined IPs (client=.10, srv-web=.10).

> **sensor-ids note:** Not deployed due to Azure for Students vCPU quota limit (6 vCPUs, all consumed
> by gw-fw + client + srv-web). As documented in `0_technical_support/00_environment/oci_cloud_alternative.md`,
> Suricata runs on gw-fw instead (UTM architecture). This is a validated workaround for cloud deployments.

---

## How to reproduce (10 steps)

1. Start all VMs in Azure resource group `rg-nh-lab` (francecentral, zone 2):
   ```bash
   az vm start --ids $(az vm list -g rg-nh-lab --query "[].id" -o tsv)
   ```
2. SSH into gw-fw as jump host: `ssh -i ~/.ssh/nh_lab_key farki@<gw-fw-public-ip>`
3. Verify IP forwarding: `sysctl net.ipv4.ip_forward` (expect: 1)
4. From client via ProxyJump: `ssh nh-client` (configured in ~/.ssh/config)
5. Confirm client→gw-fw reachability: `ping -c 4 10.10.10.4`
6. Confirm client→srv-web reachability: `ping -c 4 10.10.20.10`
7. Confirm HTTP service: `curl http://10.10.20.10` (expect: nginx 200 OK)
8. Run nmap from client: `nmap -sS -sV -p 1-1000 10.10.20.10`
9. Run tcpdump on gw-fw (interactively, 2-terminal method): `sudo tcpdump -i any -w /tmp/baseline.pcap -nn`
10. Generate traffic from client (curl + ping), stop tcpdump with Ctrl+C, scp the pcap

---

## What was tested and how

- **Zone/asset inventory (Part A):** `hostname`, `ip addr`, `ip route`, `ss -tulpn` on all reachable VMs
- **Flow matrix (Part B):** 8 flows derived from lab topology and principle of least privilege
- **Reachability validation (Part C):** nmap scan of srv-web from client (ports 1–1000, SYN+version)
- **Baseline capture (Part D):** tcpdump on gw-fw `any` interface during curl + ping from client
- **Risk analysis (Part E):** grounded in pcap observations and known Azure cloud deviations

---

## Known limitations

- `sensor-ids` not deployed → promiscuous capture on gw-fw only (no dedicated DMZ sensor)
- LAN→DMZ traffic (client→srv-web) **does not traverse gw-fw** in Azure without a UDR (User Defined Route). The pcap therefore does not capture HTTP/ICMP between client and srv-web. This is documented as Risk R03.
- `sensor-ids` not deployed → promiscuous capture impossible in the DMZ. Suricata on gw-fw is the compensating control.
- LAN→DMZ traffic (client→srv-web) does not traverse gw-fw in Azure without a UDR. The baseline pcap therefore does not capture HTTP/ICMP between client and srv-web. Documented as Risk R03 in report.md.
- No HTTPS configured on srv-web (HTTP only, port 80). Documented as Risk R04.
