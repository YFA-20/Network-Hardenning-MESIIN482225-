# TD5 — Failure Modes and Troubleshooting Log

This appendix documents issues encountered during the TD5 setup, their root causes, and resolutions.

---

## F01 — SSH timeout on new public IP (98.66.160.46)

**Symptom:** `ssh: connect to host 98.66.160.46 port 22: Connection timed out`

**Root cause:** Asymmetric routing. SSH SYN arrived on `eth1` (WAN interface, 10.10.99.5) via the Azure NAT for pip-gw-fw-wan. The reply was sourced from 10.10.10.4 and routed via `eth0` (default route), causing Azure to SNAT the reply via the wrong public IP. The remote client's TCP session never received a SYN-ACK.

**Resolution:** Linux policy routing:
```bash
ip rule add from 10.10.99.5 lookup 101 priority 100
ip route add default via 10.10.99.1 dev eth1 table 101
```
Traffic originating from the WAN IP now uses a dedicated routing table that routes replies back through `eth1`, preserving the Azure NAT association. Persisted via `/etc/netplan/99-wan-routing.yaml`.

**Lesson:** Azure SNAT is per-NIC, not per-IP. When a VM has multiple NICs with separate public IPs, Linux's default routing (longest prefix match, single table) breaks symmetric NAT traversal.

---

## F02 — Basic SKU public IP quota exhausted

**Symptom:** `az network public-ip create` fails with `IPv4BasicSkuPublicIpCountLimitReached`.

**Root cause:** Azure free-tier account had reached the quota limit for Basic SKU public IPs.

**Resolution:** Created Standard SKU public IP with `--sku Standard`. Standard SKU requires an NSG to be explicitly attached to allow inbound traffic (Basic SKU has implicit allow-all). Created `nsg-gw-fw-wan` and attached it to the WAN NIC.

**Security benefit:** The enforced NSG is actually desirable — it documents the allowed traffic explicitly and prevents accidental exposure.

---

## F03 — Public IP on wrong NIC (LAN instead of WAN)

**Symptom:** Public IP `pip-gw-fw` was attached to `nic-gw-fw-lan` (10.10.10.0/24 subnet) from a TD1 decision. Architecturally incorrect for a WAN-facing gateway.

**Root cause:** In TD1, only one NIC existed and the public IP was placed there for SSH access. When the WAN NIC was added in TD5, the public IP was not moved.

**Resolution:** New public IP `pip-gw-fw-wan` created and attached to the WAN NIC. Old Basic SKU IP deleted (`az network public-ip delete`).

**Architectural note:** The public IP must be on the WAN-facing NIC so that Azure's NAT for inbound connections matches the interface that strongSwan binds to for IKE.

---

## F04 — SCP blocked by SSH passphrase prompt

**Symptom:** `scp` with ProxyJump + passphrase-protected key prompted multiple times and timed out.

**Root cause:** ProxyJump requires the key for the jump host and the target host. A passphrase-protected key requires interaction at each hop.

**Resolution:**
```bash
eval $(ssh-agent -s)
ssh-add ~/.ssh/nh_lab_key
```
With the key loaded in `ssh-agent`, both the ProxyJump and the final hop authenticate silently.

---

## F05 — IPsec tunnel not establishing (leftid/rightid mismatch)

**Symptom:** `NO_PROPOSAL_CHOSEN` or tunnel stuck in `CONNECTING` state.

**Root cause:** With double NAT (Azure SNAT + AWS EIP), strongSwan detects NAT-D mismatch during IKE_SA_INIT. If `leftid`/`rightid` are not set, strongSwan defaults to using the private WAN IP as the identity. The remote peer, receiving packets from the public IP, cannot match this identity.

**Resolution:** Set `leftid` and `rightid` to the public IPs:
```
# siteA-gw:
leftid=98.66.160.46
# siteB-gw:
leftid=35.181.66.138
```
Peers now present their public identity, matching what the other side sees as the IKE packet source.

---

## F06 — Wrong next-hop for siteB-srv route

**Symptom:** Route for return traffic from siteB-srv directed to wrong IP.

**Root cause:** The correct DMZ gateway for siteB-srv is `10.10.20.4` (siteB-gw's DMZ-facing IP used for forwarding).

**Resolution:**
```bash
# On siteB-srv:
sudo ip route add 10.10.10.0/24 via 10.10.20.4
```

---

## IPsec Quick Troubleshooting Reference

| Symptom | Likely cause | Debug command |
|---------|-------------|---------------|
| No SA established | Proposal mismatch | `sudo journalctl -fu strongswan-starter` |
| `NO_PROPOSAL_CHOSEN` | `ike=` or `esp=` differ | Compare configs side-by-side |
| `CONNECTING` but never `ESTABLISHED` | NAT-D identity mismatch | Check `leftid`/`rightid` = public IPs |
| Tunnel up but ping fails | Missing routes or ip_forward | `ip route` on all 4 VMs; `sysctl net.ipv4.ip_forward` |
| UDP 500/4500 blocked | NSG or Security Group | Check cloud firewall rules |
| ESP MTU issues | Large packets fragmented | Reduce MTU or enable PMTUD |
