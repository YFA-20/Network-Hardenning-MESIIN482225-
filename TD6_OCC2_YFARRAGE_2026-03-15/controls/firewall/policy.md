# Firewall Policy — TD2 Network Hardening
**Author:** Youssouf FARRAGE — Group OCC2 | ESILV, 4th year, Major Cybersecurity & IOT Trust
**Date:** 2026-03-05
**Host:** gw-fw (Azure VM, dual-NIC: eth0=LAN 10.10.10.4, eth1=DMZ 10.10.20.4)

---

## 1. Design Philosophy

**Default-deny with explicit allow.**
All traffic through `gw-fw` is dropped unless a rule explicitly permits it.
This is the minimum-privilege principle applied at the network layer.

---

## 2. Traffic Flows Permitted (Forward Chain)

| Rule | Source | Destination | Protocol/Port | Justification |
|------|--------|-------------|---------------|---------------|
| F01 | 10.10.10.0/24 | 10.10.20.10 | TCP/80 | Client HTTP to web server |
| F02 | 10.10.10.0/24 | 10.10.20.10 | TCP/22 | Client SSH to web server |
| F03 | 10.10.10.0/24 | 10.10.20.0/24 | ICMP echo-request (≤5/s) | Diagnostic ping, rate-limited |
| F04 | 10.10.10.0/24 | 10.10.20.10 | TCP/443 | Client HTTPS to web server (prepared for TD4 TLS) |
| F00 | any | any | established/related | Return traffic (stateful tracking) |

**Denied by default:** all other forwarded traffic (Telnet, RDP, MySQL, unknown ports, DMZ-initiated, etc.)

---

## 3. Management Access Permitted (Input Chain)

| Rule | Source | Destination | Protocol/Port | Justification |
|------|--------|-------------|---------------|---------------|
| M01 | 10.10.10.0/24 | gw-fw | TCP/22 | LAN admin SSH |
| M02 | 89.30.39.100 | gw-fw | TCP/22 | Admin-pc (Kali) SSH ProxyJump |
| M03 | 92.184.117.191 | gw-fw | TCP/22 | Secondary admin IP (added during TD2) |
| M04 | 10.10.10.0/24 | gw-fw | ICMP echo-request | LAN diagnostic ping |
| M05 | lo | any | any | Loopback (required for OS) |
| M06 | any | gw-fw | established/related | Return traffic |

**Output chain:** policy accept (gw-fw can initiate outbound, e.g. package updates).

---

## 4. Logging

All denied packets are logged with rate-limiting to prevent log flooding:
- Forward chain denials → `NFT_FWD_DENY` prefix (kernel log / `/var/log/syslog`)
- Input chain denials → `NFT_IN_DENY` prefix

Rate limit: 10 log entries per minute per chain.

---

## 5. Azure Prerequisites

Because Azure routes traffic between subnets via its own fabric by default (bypassing gw-fw), User Defined Routes (UDR) were mandatory:

| Route Table | Destination | Next-hop | Attached to |
|-------------|-------------|----------|-------------|
| rt-nh-lan | 10.10.20.0/24 | VirtualAppliance 10.10.20.4 | NH-LAN subnet |
| rt-nh-dmz | 10.10.10.0/24 | VirtualAppliance 10.10.10.4 | NH-DMZ subnet |

Both gw-fw NICs have Azure IP Forwarding enabled (`enableIPForwarding: true`).
OS-level forwarding also enabled: `net.ipv4.ip_forward = 1`.

---

## 6. Rollback Procedure

In case of lockout, use the VirtualBox/Azure serial console and run:
```bash
nft flush ruleset
```
This instantly removes all rules and restores full connectivity.
A dedicated rollback script is provided at `config/rollback.sh`.
