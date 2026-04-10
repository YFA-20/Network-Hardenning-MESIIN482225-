# TD5 — Cloud vs. VirtualBox Specification Delta

This document maps every deviation from the VirtualBox-based TD5 specification to its cloud equivalent, with justification.

---

## Infrastructure differences

| Spec (VirtualBox) | Actual (Cloud hybrid) | Impact |
|-------------------|----------------------|--------|
| 4 VMs, all local | 4 VMs across 2 clouds | Inter-site traffic is real internet traffic |
| NH-WAN = Internal Network | NH-WAN = public internet | NAT traversal required |
| Static IPs as desired | Azure/AWS reserve .0–.3 | IPs configured starting from .4 |
| Single NIC per gateway | Multi-NIC on Azure VM | Policy routing needed for asymmetric NAT |
| No firewall by default | Azure NSG mandatory on Standard SKU | NSG becomes part of the deliverable |
| VMs always on | Cloud VMs cost money when idle | VMs stopped between sessions; snapshots taken before changes |

---

## IP address mapping

The spec defines specific WAN IPs for each gateway. Cloud subnet constraints shift these:

| Spec | Cloud | Note |
|------|-------|------|
| siteA-gw WAN: 10.10.99.1 | 10.10.99.5 | Azure, NH-WAN NIC — .1 is cloud-reserved |
| siteB-gw WAN: 10.10.99.2 | 10.10.99.4 | AWS, WAN ENI — .2 is cloud-reserved |
| siteB-srv: 10.10.20.10 | 10.10.20.10 | AWS, DMZ ENI — matches spec exactly |
| siteB-gw DMZ: (implicit) | 10.10.20.4 | AWS, DMZ ENI — gateway address for DMZ routing |

Addresses ending in .0–.3 are reserved by both cloud providers and cannot be assigned to instances.

---

## strongSwan configuration delta

The student walkthrough uses:
```
left=10.10.99.1
right=10.10.99.2
```

Cloud hybrid requires:
```
left=10.10.99.5        # private WAN IP (strongSwan bind address)
leftid=98.66.160.46    # public IP (IKE identity, must match what remote sees)
right=35.181.66.138    # remote public IP (used to reach peer; NAT-T negotiated)
```

There is no `rightid` override needed on siteA-gw because the right address is already the public IP. On siteB-gw, `right=98.66.160.46` serves as both the routing target and the identity.

---

## NAT traversal

The spec does not mention NAT-T because VirtualBox Internal Networks are NAT-free. In the cloud:

- Both gateways are behind NAT (Azure SNAT, AWS EIP).
- Raw ESP (IP protocol 50) cannot traverse NAT (SPI fields get mangled or the NAT table has no mapping).
- strongSwan detects NAT via RFC 3947 `NAT-D` payloads during IKE_SA_INIT and automatically switches to ESP-in-UDP (port 4500).
- The tunnel uses `INSTALLED, TUNNEL, ... ESP in UDP` — this is the correct cloud behavior.

No manual configuration is required to enable NAT-T in strongSwan; it is automatic when NAT is detected.

---

## SSH access method

| Spec | Actual |
|------|--------|
| Direct SSH to siteB-srv | ProxyJump via siteB-gw (siteB-srv has no public IP) |
| `ssh admin1@10.10.20.10` | `ssh -J awsuser@35.181.66.138 awsuser@10.10.20.10` (or via `~/.ssh/config` alias `nh-siteB-srv`) |

siteB-srv is accessible via the IPsec tunnel from siteA-client once the tunnel is established (ping and SSH via 10.10.20.10 over the tunnel). External access uses ProxyJump through siteB-gw.

---

## Admin user

| Spec | Actual | Reason |
|------|--------|--------|
| Create `admin1` manually | Use existing `awsuser` | AWS cloud images provision a default user via cloud-init; creating a separate user was not required |

`awsuser` fulfils the same role as the spec's `admin1`: a named, non-root admin with key-only SSH access.

---

## PasswordAuthentication already disabled

The spec instructs the student to explicitly set `PasswordAuthentication no` in `sshd_config`. On the AWS Ubuntu 22.04 cloud image, this is already set in `/etc/ssh/sshd_config.d/60-cloudimg-settings.conf`. The TD5 hardening drop-in (`99-td5-hardening.conf`) adds the remaining directives without redundancy.

---

## Bonus: real-world threat exposure

Within hours of siteB-srv being deployed in AWS eu-west-3 with TCP/22 open, the auth.log recorded brute-force attempts from:
- 157.245.99.15 (DigitalOcean, multiple root login attempts)
- 68.183.79.252 (DigitalOcean)
- 165.227.106.123 (DigitalOcean)

These are internet-wide SSH scanners that probe all new cloud instances. The hardening work in this TD has measurable real-world impact: without key-only auth and AllowUsers scoping, these attempts would pose an actual credential risk.
