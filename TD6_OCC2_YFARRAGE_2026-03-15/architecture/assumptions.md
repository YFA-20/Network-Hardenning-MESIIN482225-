# Architecture Assumptions
**Platform constraints documented for reproducibility**

---

## Azure-specific constraints

| Constraint | Impact | Resolution |
|---|---|---|
| Azure reserves .0–.3 in every subnet | gw-fw uses 10.10.10.4 / 10.10.20.4 / 10.10.99.5 instead of .1 | All configs use actual addresses |
| Azure hypervisor routes intra-VNet traffic at fabric level | LAN↔DMZ traffic bypasses gw-fw without UDRs | Two UDR tables created: rt-nh-lan, rt-nh-dmz |
| Azure NIC IP Forwarding must be enabled at hypervisor level | `sysctl ip_forward=1` alone is insufficient | `az network nic update --ip-forwarding true` on both NICs |
| Azure hypervisor blocks promiscuous mode on guest VMs | Dedicated sensor-ids VM not viable | UTM architecture: Suricata co-located on gw-fw |
| Azure for Students vCPU quota = 6 (3×2 vCPUs) | sensor-ids (4th VM) cannot be created | Documented compensating measure: UTM on gw-fw |
| Azure SNAT on outbound traffic from WAN NIC | Asymmetric routing: SYN arrives eth1, reply leaves eth0 | Linux policy routing table 101 added |
| Standard SKU public IP requires explicit NSG | Basic SKU exhausted; Standard requires NSG attached | nsg-gw-fw-wan created with explicit inbound rules |
| Azure guest agent (168.63.129.16) — permanent background traffic | 56% of capture volume in TD1 baseline | Suppressed in Suricata; documented as known noise |

## AWS-specific constraints

| Constraint | Impact | Resolution |
|---|---|---|
| AWS reserves .0–.3 in every subnet | siteB-gw uses 10.10.99.4 / 10.10.20.4 instead of spec values | All configs use actual addresses |
| AWS Elastic IP is 1:1 NAT (not SNAT) | Public IP (35.181.66.138) ≠ private WAN IP (10.10.99.4) | `leftid`/`rightid` in strongSwan set to public IPs |
| AWS default user = awsuser (AMI cloud-init) | No generic `ubuntu` account available | AllowUsers awsuser in sshd hardening |
| AWS Security Groups = stateful firewall | Provides perimeter protection independent of iptables/nftables | UDP/500 and UDP/4500 opened for IPsec |

## IPsec / NAT-T constraints

Both gateways are behind NAT. Raw ESP (IP protocol 50) cannot traverse NAT — SPIs would be mangled. Solution: NAT-T (RFC 3947) — ESP encapsulated in UDP/4500. strongSwan detects NAT automatically via NAT-D payloads in IKE_SA_INIT. No manual NAT-T configuration required.

`leftid`/`rightid` must be set to public IPs (not private WAN IPs) for IKE identity matching across NAT.

## Lab limitations (not production)

- Self-signed certificates — no PKI/CA trust chain
- HSTS max-age=300 (lab) — production requires ≥31536000
- IPsec authentication: PSK — production requires X.509 certificates
- Certificate validity: 7 days (expires 2026-03-18)
- No automated certificate renewal
