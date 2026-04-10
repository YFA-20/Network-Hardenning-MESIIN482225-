# TD5 — SSH Hardening + Site-to-Site IPsec VPN

| Field             | Value                                                             |
|-------------------|-------------------------------------------------------------------|
| Module            | Network Hardening — ESILV, 4th year, Major Cybersecurity & IOT Trust |
| Lab               | TD5 — SSH Hardening + Site-to-Site IPsec VPN                    |
| Group / Student   | Group OCC2 / Youssouf FARRAGE — ESILV, 4th year, Major Cybersecurity & IOT Trust |
| Date              | 2026-03-14                                                        |
| Normative anchor  | NIST SP 800-77 Rev.1 (IPsec/VPN) + NIST SP 800-44 (SSH)         |
| Platform          | **Cloud hybrid — Microsoft Azure (Site A) + AWS (Site B)**        |

---

## 1. Platform Context

TD1 through TD4 ran entirely on a three-VM Azure deployment. TD5 introduces a second site on AWS, creating a **genuine cloud-hybrid infrastructure** rather than a VirtualBox simulation. This distinction is fundamental: every decision in this TD — IP addressing, NAT traversal, public key management, policy routing — was made against real cloud constraints, not a sandboxed lab environment.

**Site A (Azure):**
- `siteA-gw` — the existing `gw-fw` VM, extended with a second NIC attached to the NH-WAN subnet. LAN IP: 10.10.10.4 (NH-LAN). WAN IP: 10.10.99.5/24. Azure Public IP (pip-gw-fw-wan): **98.66.160.46**.
- `siteA-client` — the existing `kali` VM at 10.10.10.10.

**Site B (AWS eu-west-3, Paris):**
- `siteB-gw` — new AWS EC2 instance. DMZ IP: **10.10.20.4**. WAN IP: **10.10.99.4/24**. Elastic IP: **35.181.66.138**.
- `siteB-srv` — the equivalent of `srv-web`, AWS EC2. IP: **10.10.20.10**. Accessible via ProxyJump through siteB-gw.

Both cloud providers reserve .0–.3 in every subnet. The WAN and DMZ IPs were configured accordingly: 10.10.99.5 (Azure) and 10.10.99.4 (AWS) rather than .1/.2 as in the spec.

---

## 2. Threat Model

**Assets:**
- `siteB-srv` SSH service: administrative access to a production-equivalent cloud server.
- Inter-site traffic crossing the public internet (WAN segment = internet, not a private wire).

**Adversary profile:**
- Remote attacker on the internet capable of passive interception of unencrypted WAN traffic.
- Credential-based brute-force against SSH (confirmed live in `evidence/authlog_excerpt.txt`: multiple unauthorized connection attempts from public IPs 157.245.99.15, 68.183.79.252, 165.227.106.123 within hours of deployment).
- On-path attacker on the WAN segment able to read cleartext ICMP/TCP if no VPN is present.

**Key threats addressed:**

- Password brute-force on SSH: mitigated by key-only authentication, `MaxAuthTries 3`, and `AllowUsers` scoping.
- Privilege escalation via SSH root login: mitigated by `PermitRootLogin no`.
- Cleartext inter-site traffic: mitigated by IKEv2/IPsec ESP tunnel encrypting all 10.10.10.0/24 ↔ 10.10.20.0/24 traffic with AES-256-CBC/HMAC-SHA-256.
- NAT-based key mismatch in IKE negotiation: mitigated by explicit `leftid`/`rightid` set to public IPs, with NAT-T (ESP-in-UDP/4500) auto-negotiated per RFC 3947.

**Security goals:**
- Only key-based SSH authentication; no password login, no root login.
- All LAN↔DMZ traffic is encrypted in transit over the public WAN.
- Tunnel is scoped to the two production subnets; WAN management traffic is not tunneled.
- All authentication and denial events are logged and auditable.

---

## 3. Policy Statement

> **Who can administer what, from where — and how is it enforced.**

| Subject | Action | Object | Condition | Enforcement |
|---------|--------|--------|-----------|-------------|
| `awsuser` (admin, OCC2) | SSH login | `siteB-srv` (10.10.20.10) | ED25519 key only | `AllowUsers awsuser`, `PubkeyAuthentication yes`, `PasswordAuthentication no` |
| Any other user | SSH login | `siteB-srv` | — | **DENIED** — `AllowUsers` scoping + `PermitRootLogin no` |
| `root` | SSH login | Any host | Any method | **DENIED** — `PermitRootLogin no` |
| NH-LAN (10.10.10.0/24) | Any IP traffic | NH-DMZ (10.10.20.0/24) | Over WAN | **Encrypted** — IPsec ESP tunnel (AES-256-CBC/HMAC-SHA-256) |
| Any host | Any IP traffic | WAN (10.10.99.0/24) | — | **Not tunneled** — tunnel scoped to LAN↔DMZ only |

**Lab simplification noted:** PSK is used for IKEv2 authentication. In production, X.509 certificates issued by an enterprise CA would replace the PSK, enabling per-gateway identity binding and revocation.

---

## 4. Two-Site Topology

### Logical diagram

```
┌─── Site A — Azure (NH-LAN) ─────────┐           PUBLIC INTERNET           ┌─── Site B — AWS (NH-DMZ) ───────────────────┐
│                                       │                                      │                                               │
│  siteA-client (10.10.10.10)           │   pip-gw-fw-wan    Elastic IP        │  siteB-srv                                   │
│                                       │   98.66.160.46 ←→ 35.181.66.138     │  10.10.20.10                                 │
│  siteA-gw                             │       ↑ NAT-T (UDP/4500)  ↑          │                                               │
│  LAN:  10.10.10.4                    │       │  IKEv2 PSK tunnel  │          │                                               │
│  WAN:  10.10.99.5 ─────────────────────────────────────────────── 10.10.99.4 ── siteB-gw                                   │
│                                       │               NH-WAN                 │  WAN: 10.10.99.4                             │
│                                       │            10.10.99.0/24             │  DMZ: 10.10.20.4                             │
│                                       │         (virtual — internet)         │                                               │
└───────────────────────────────────────┘                                      └─────────────────────────────────────────────┘
```

### IP address mapping — spec vs. actual

| TD5 spec address | Actual address | Location | Reason |
|-----------------|----------------|----------|--------|
| siteA-gw NIC2: 10.10.99.1 | **10.10.99.5** | Azure, WAN NIC | Azure reserves .0–.3 in every subnet |
| siteB-gw NIC2: 10.10.99.2 | **10.10.99.4** | AWS, WAN NIC | AWS reserves .0–.3 in every subnet |
| siteA-gw LAN: 10.10.10.1 | **10.10.10.4** | Azure, LAN NIC | Azure-assigned (TD1 baseline) |
| siteB-srv: 10.10.20.10 | **10.10.20.10** | AWS, DMZ NIC | Configured to match spec |
| siteB-gw DMZ: — | **10.10.20.4** | AWS, DMZ NIC | Gateway address for DMZ routing |

---

## 5. Phase 0 — Infrastructure Build

### 5.1 Azure: NIC migration and public IP placement

The existing `gw-fw` had its second NIC (`nic-gw-fw-dmz`) originally placed on the NH-DMZ subnet from TD1. For TD5, the NH-WAN subnet was created and this NIC migrated:

1. VM deallocated (`az vm deallocate`).
2. NIC IP configuration updated to NH-WAN subnet, static IP 10.10.99.5.
3. A new **Standard SKU** Public IP (`pip-gw-fw-wan`, 98.66.160.46) attached to this NIC. The previous Basic SKU public IP on the LAN NIC was removed (architectural error from TD1 — the public IP belongs on the WAN-facing NIC).
4. VM restarted; `ip a s` confirmed `eth1` shows 10.10.99.5/24.

**NSG configuration:** An Azure Network Security Group (`nsg-gw-fw-wan`) was created and attached to the WAN NIC, allowing inbound TCP/22 (SSH admin), UDP/500 (IKE), UDP/4500 (NAT-T), and ESP for the IPsec tunnel.

### 5.2 Asymmetric routing fix

With two public IPs (management SSH arriving on eth1 / 10.10.99.5), Azure's NAT created an asymmetric routing problem: SSH SYN arrived on eth1, but replies left via eth0 (default route), causing timeouts. Fixed with Linux policy routing:

```bash
# Create a dedicated routing table for WAN traffic
echo "101 wan" >> /etc/iproute2/rt_tables

# Add default route in table 101 via WAN gateway
ip route add default via 10.10.99.1 dev eth1 table 101

# Route rule: traffic FROM WAN IP uses table 101
ip rule add from 10.10.99.5 lookup 101 priority 100
```

Made persistent via `/etc/netplan/99-wan-routing.yaml` (postUp routing rules in netplan).

### 5.3 AWS: Site B setup

Site B was deployed on AWS eu-west-3 (Paris) prior to this TD session. Key details:
- Two EC2 instances: `siteB-gw` (t2.micro, Ubuntu 22.04) and `siteB-srv` (t2.micro, Ubuntu 22.04).
- IPs configured to match spec addressing: 10.10.99.4 on siteB-gw WAN NIC, 10.10.20.10 on siteB-srv.
- An **Elastic IP** (35.181.66.138) associated 1:1 with siteB-gw's WAN IP (10.10.99.4) — this is a full NAT, not SNAT.
- AWS Security Groups configured to allow UDP/500, UDP/4500 inbound for IPsec.

### 5.4 IP forwarding and routes

On both gateways:
```bash
sudo sysctl -w net.ipv4.ip_forward=1
echo "net.ipv4.ip_forward = 1" | sudo tee -a /etc/sysctl.d/99-forward.conf
```

Static routes to reach cross-site subnets before IPsec (and through the tunnel after IPsec):
```bash
# On siteA-gw: reach DMZ via WAN
sudo ip route add 10.10.20.0/24 via 10.10.99.4  # next-hop = siteB-gw WAN IP

# On siteA-client: reach both remote subnets
sudo ip route add 10.10.20.0/24 via 10.10.10.4
sudo ip route add 10.10.99.0/24 via 10.10.10.4

# On siteB-gw: reach LAN via WAN
sudo ip route add 10.10.10.0/24 via 10.10.99.5  # next-hop = siteA-gw WAN IP

# On siteB-srv: reach remote subnet via local gateway
sudo ip route add 10.10.10.0/24 via 10.10.20.4  # via siteB-gw DMZ IP
```

Pre-flight validation:
```bash
ping -c 2 10.10.99.5   # siteB-gw → siteA-gw WAN (before tunnel, over internet)
ping -c 2 10.10.20.10  # siteA-client → siteB-srv (after tunnel established)
```

---

## 6. Phase 1 — SSH Hardening

### 6.1 Bastion mindset

`siteB-srv` is a production-equivalent cloud instance exposed via a cloud load-balancer. The auth.log (see `evidence/authlog_excerpt.txt`) shows unsolicited root login attempts from external IPs within hours of the SSH port becoming reachable — real threat, not a simulation. The hardening eliminates the credential surface entirely.

### 6.2 Admin account

On AWS instances, the default user is `awsuser` (provisioned by the AMI cloud-init). This account is used as the dedicated admin user, replacing the generic `ubuntu` user for TD5 purposes. No new account creation was required on this cloud image.

### 6.3 Key-based authentication

SSH key pair `~/.ssh/nh_lab_key` (ED25519) was generated on `siteA-client` during initial AWS setup and deployed to `awsuser@siteB-srv` via cloud-init. Key fingerprint: `ED25519 SHA256:TJd0H81dkHZCDKn//p8lGWRnsbNRv/dsDkMBlo7mQg4` (visible in auth.log).

The key login was verified before any sshd_config changes:
```bash
ssh -i ~/.ssh/nh_lab_key awsuser@10.10.20.10 whoami
# Output: awsuser
```

### 6.4 sshd hardening

On `siteB-srv`, the AWS cloud image places `PasswordAuthentication no` in `/etc/ssh/sshd_config.d/60-cloudimg-settings.conf` by default. The remaining hardening parameters were added in a new drop-in file to avoid modifying the base config:

**`/etc/ssh/sshd_config.d/99-td5-hardening.conf`:**
```
PermitRootLogin no
AllowUsers awsuser
PubkeyAuthentication yes
MaxAuthTries 3
LoginGraceTime 30
```

Config tested before reload:
```bash
sudo sshd -t && sudo systemctl restart ssh
```

### 6.5 Verification

| Test | Command | Expected | Observed |
|------|---------|----------|----------|
| TD5-T01 — key login succeeds | `ssh -i ~/.ssh/nh_lab_key awsuser@10.10.20.10 "echo SSH_KEY_OK"` | `SSH_KEY_OK` | ✅ Accepted publickey (auth.log 11:16:48) |
| TD5-T02 — password auth blocked | `ssh -o PubkeyAuthentication=no awsuser@10.10.20.10` | Permission denied | ✅ Connection closed [preauth] (auth.log 11:26:34) |
| TD5-T03 — root login blocked | `ssh -i ~/.ssh/nh_lab_key root@10.10.20.10` | Permission denied | ✅ "not listed in AllowUsers" (auth.log 11:26:49) |

Evidence: `evidence/authlog_excerpt.txt`.

---

## 7. Phase 2 — IPsec Site-to-Site VPN

### 7.1 Cloud NAT constraints

The TD5 spec assumes gateways with direct WAN reachability (private WAN IPs accessible to each other). In the cloud-hybrid deployment, both gateways are behind NAT:

- **Site A:** Azure SNAT — outbound traffic from 10.10.99.5 appears as 98.66.160.46 on the internet.
- **Site B:** AWS Elastic IP — 1:1 NAT, 10.10.99.4 ↔ 35.181.66.138.

This means raw ESP (IP protocol 50) cannot traverse the NAT; the SPIs would be mangled or dropped. IKEv2 with **NAT-T (NAT Traversal, RFC 3947)** is required: IPsec encapsulates ESP inside UDP/4500 once NAT is detected during IKE negotiation.

strongSwan detects NAT automatically via RFC 3947 NAT-D payloads in IKE_SA_INIT. No manual configuration is needed to enable NAT-T — it activates when the detected source IP differs from the IP in the IKE header.

The IKE identity (`leftid`/`rightid`) must be set to the **public IP** (not the private WAN IP) so that each side can verify the remote's true address:

```
leftid=98.66.160.46    # Azure public IP of siteA-gw
rightid=35.181.66.138  # AWS Elastic IP of siteB-gw
```

### 7.2 strongSwan installation

On both gateways:
```bash
sudo apt update && sudo apt install -y strongswan strongswan-pki libcharon-extra-plugins
sudo systemctl enable strongswan-starter
```

### 7.3 Configuration

**siteA-gw** — `/etc/ipsec.conf`:
```
config setup
    charondebug="ike 2, knl 2, cfg 2"

conn site-to-site
    authby=secret
    left=10.10.99.5
    leftid=98.66.160.46
    leftsubnet=10.10.10.0/24
    right=35.181.66.138
    rightsubnet=10.10.20.0/24
    ike=aes256-sha256-modp2048!
    esp=aes256-sha256-modp2048!
    keyexchange=ikev2
    auto=start
```

**siteB-gw** — `/etc/ipsec.conf` (left/right mirrored):
```
config setup
    charondebug="ike 2, knl 2, cfg 2"

conn site-to-site
    authby=secret
    left=10.10.99.4
    leftid=35.181.66.138
    leftsubnet=10.10.20.0/24
    right=98.66.160.46
    rightsubnet=10.10.10.0/24
    ike=aes256-sha256-modp2048!
    esp=aes256-sha256-modp2048!
    keyexchange=ikev2
    auto=start
```

**Cryptographic profile:**

| Parameter | Value | Justification |
|-----------|-------|---------------|
| IKE cipher | AES-256-CBC | NIST SP 800-77r1 §4.4: AES-256 recommended |
| IKE integrity | HMAC-SHA-256-128 | NIST SP 800-77r1 §4.4: SHA-2 family |
| DH group | MODP-2048 | NIST SP 800-77r1 §4.5: Group 14 minimum |
| ESP cipher | AES-256-CBC | Same as IKE; provides confidentiality |
| ESP integrity | HMAC-SHA-256-128 | Provides data origin authentication |
| Key exchange | IKEv2 | RFC 7296; IKEv1 deprecated |
| Auth method | PSK | Lab scope; production would use X.509 certs |
| `!` suffix | Strict proposal | No fallback to weaker algorithms |

### 7.4 nftables rules on siteA-gw

The existing TD2 nftables forward chain already allowed 10.10.10.0/24 → 10.10.20.10 for TCP/80, TCP/443, TCP/22, and ICMP — these rules remain valid because inner IPsec traffic carries the original LAN/DMZ IP headers. Added INPUT chain rules for IKE/NAT-T:

```
udp dport 500  counter accept comment "IKE"
udp dport 4500 counter accept comment "NAT-T"
ip protocol esp counter accept comment "ESP"
```

Full ruleset: `evidence/nftables_ruleset.txt`.

### 7.5 Tunnel establishment

```bash
# On both gateways:
sudo ipsec restart
sudo ipsec statusall
```

**Established tunnel (siteA-gw):**
```
site-to-site[2]: ESTABLISHED 38 minutes ago, 10.10.99.5[98.66.160.46]...35.181.66.138[35.181.66.138]
site-to-site[2]: IKEv2 SPIs: 853e1a3968c78fd8_i dbe533ea25f4bf2b_r*
site-to-site[2]: IKE proposal: AES_CBC_256/HMAC_SHA2_256_128/PRF_HMAC_SHA2_256/MODP_2048
site-to-site{1}: INSTALLED, TUNNEL, reqid 1, ESP in UDP SPIs: cab7e97e_i c99d2fbf_o
site-to-site{1}: 10.10.10.0/24 === 10.10.20.0/24
```

Full output: `evidence/ipsec_status_siteA.txt`.

### 7.6 Verification

**Ping through the tunnel (from siteA-client):**
```
PING 10.10.20.10 — 10 packets transmitted, 10 received, 0% packet loss
rtt min/avg/max = 2.71/4.77/16.74 ms
```

The TTL of 62 (= 64 − 2 hops: siteA-gw, siteB-gw) confirms the packet traverses both gateways as expected.

**ESP capture on WAN (siteA-gw eth1):**
```
12:15:47 IP 10.10.99.5.4500 > 35.181.66.138.4500: UDP-encap: ESP(spi=0xc99d2fbf,seq=0x8)
12:15:47 IP 35.181.66.138.4500 > 10.10.99.5.4500: UDP-encap: ESP(spi=0xcab7e97e,seq=0x8)
```

The traffic is ESP-in-UDP (NAT-T), not cleartext ICMP. A passive observer on the WAN sees only encrypted ESP payloads. Full capture: `evidence/esp_capture.txt`.

### 7.7 Tunnel scope

The tunnel covers `10.10.10.0/24 ↔ 10.10.20.0/24` only. WAN management traffic (10.10.99.0/24) and internet-bound traffic are not tunneled. This limits the attack surface of the VPN and preserves independent management access to each gateway.

---

## 8. Test Summary

| Card | Claim | Result |
|------|-------|--------|
| TD5-T01 | SSH password auth is disabled | ✅ PASS |
| TD5-T02 | Root login via SSH is disabled | ✅ PASS |
| TD5-T03 | Only `awsuser` can connect via SSH | ✅ PASS |
| TD5-T04 | SSH logs show accept + deny events | ✅ PASS |
| TD5-T05 | IKEv2 tunnel is ESTABLISHED | ✅ PASS |
| TD5-T06 | Ping crosses the tunnel (ESP on wire) | ✅ PASS |
| TD5-T07 | Tunnel is scoped to LAN ↔ DMZ | ✅ PASS |
| TD5-T08 | Only UDP 500/4500 needed on WAN for IKE | ✅ PASS |

---

## 9. Cloud Engineering Notes

This TD was more complex than the VirtualBox-equivalent due to the following real-world cloud constraints:

**Double NAT and IKE identity.** The standard strongSwan configuration assumes direct WAN reachability. With Azure SNAT + AWS Elastic IP, the `leftid`/`rightid` IKE identity fields must explicitly carry the public IPs. Without this, NAT-D payloads cause identity mismatch and the tunnel never establishes.

**Azure NIC architecture.** Azure does not allow a VM to have a public IP on a NIC without an explicit IP configuration update (via `az network nic ip-config update`). NIC migration from NH-DMZ to NH-WAN required full VM deallocation. The asymmetric routing problem (SYN arrives on eth1, reply leaves via eth0) is a specific Azure SNAT behavior requiring Linux policy routing — this does not occur in VirtualBox or on-premises deployments.

**Standard SKU public IP.** Azure's Basic SKU public IP quota was exhausted. Standard SKU IPs require an NSG to be explicitly created and attached (Basic SKU has implicit allow-all). This is a production-hardening requirement that happened to be enforced by quota limits.

**Cloud IP addressing.** Both Azure and AWS reserve .0–.3 in every subnet. To match the spec's 10.10.99.1/10.10.99.2 and 10.10.20.10, addresses were manually configured via the cloud console and assigned to the network interfaces. Cloud images do not automatically bring up additional IPs; they require manual `ip addr add` or cloud-init configuration.

**Real attack surface.** Within hours of deploying `siteB-srv` in AWS, the auth.log recorded unsolicited brute-force attempts against the SSH port from multiple public IPs. The hardening in Phase 1 was validated against real threats, not synthetic test traffic.

---

## 10. Residual Risks

The controls implemented in this TD reduce the attack surface but do not eliminate all risk. The following residual risks should be addressed before any production deployment.

**SSH key management.** The ED25519 key pair used in this lab has no rotation policy. A stolen private key grants permanent access until manually revoked. In production: deploy a PKI with short-lived certificates (OpenSSH CA or Vault SSH Secrets Engine), enforce key rotation every 90 days, and log all key usage centrally.

**Pre-shared key (PSK) for IKEv2.** The PSK is a single credential shared between both gateways. If either gateway is compromised, the PSK must be changed on both sides simultaneously — a manual, error-prone operation. In production: replace PSK with X.509 certificates issued by an enterprise CA. Each gateway holds a unique private key; revocation is per-gateway and does not require coordinated rotation.

**No Multi-Factor Authentication (MFA).** SSH key authentication provides one factor (possession of the private key). A stolen key (without passphrase) is sufficient for access. In production: add a second factor via PAM (TOTP/FIDO2) or use a bastion service (HashiCorp Vault, AWS Systems Manager Session Manager) that enforces MFA independently of the SSH daemon.

**Device posture is not verified.** The current policy scopes access by username and key, but does not verify the health of the connecting device (OS version, disk encryption, endpoint agent). An authorized key used from a compromised workstation grants the same access as from a clean device. In production: integrate with a device trust platform (e.g., certificates tied to managed devices, network access control).

**Tunnel rekeying and forward secrecy.** The current MODP-2048 DH group provides forward secrecy per session, but a quantum-capable adversary recording current traffic could retroactively decrypt it when sufficiently powerful quantum computers become available. In production: migrate to ECDH groups (curve25519) and monitor NIST PQC standards for post-quantum IKE proposals.

**No centralized log aggregation.** Auth.log and strongSwan logs currently live on individual VMs. If a VM is compromised, logs can be tampered with. In production: forward all logs to an immutable SIEM (CloudWatch, Azure Monitor, or a syslog aggregator with write-once storage) before any local modification is possible.
