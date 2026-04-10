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

## F07 — Locked out of SSH after sshd_config change

**Symptom:** After restarting sshd with new hardening parameters, SSH connection to siteB-srv is refused or hangs. No way back in.

**Root cause:** A typo or logic error in `sshd_config` can disable all authentication paths. Alternatively, restarting sshd on a cloud VM before verifying the key works locks the operator out permanently (no console access on t2.micro by default).

**Prevention protocol (mandatory before any sshd restart):**
```bash
# 1. Verify syntax BEFORE restart
sudo sshd -t
# Output must be empty (no errors)

# 2. Test key login in a SEPARATE terminal BEFORE changing config
ssh -i ~/.ssh/nh_lab_key awsuser@10.10.20.10 whoami
# Expected: awsuser

# 3. Keep the existing SSH session open while restarting
# The current session is NOT terminated by systemctl restart ssh
sudo systemctl restart ssh

# 4. Open a NEW session immediately after
ssh -i ~/.ssh/nh_lab_key awsuser@10.10.20.10 echo "still works"
```

**Recovery if locked out:** On AWS, use EC2 Instance Connect or create an AMI and mount the root volume to another instance to fix `/etc/ssh/sshd_config.d/99-td5-hardening.conf`.

---

## F08 — VPN tunnel ESTABLISHED but traffic does not pass

**Symptom:** `ipsec statusall` shows `ESTABLISHED` and `INSTALLED`, but ping from siteA-client to siteB-srv fails (100% packet loss).

**Root cause:** The tunnel can be up at the IKE/ESP level while traffic still fails due to: missing IP forwarding, missing static routes on client/server VMs, or nftables blocking forwarded packets.

**Diagnostic sequence:**
```bash
# 1. Verify ip_forward on both gateways
sysctl net.ipv4.ip_forward         # Must be 1

# 2. Check routes on siteA-client
ip route show | grep 10.10.20      # Must show route via siteA-gw

# 3. Check routes on siteB-srv
ip route show | grep 10.10.10      # Must show route via siteB-gw (10.10.20.4)

# 4. Check nftables forward chain on siteA-gw
sudo nft list chain inet filter forward
# Must not drop ICMP from 10.10.10.0/24 to 10.10.20.0/24

# 5. Trace the packet
sudo tcpdump -i eth0 icmp             # On siteA-gw: does ICMP arrive from siteA-client?
sudo tcpdump -i eth1 'udp port 4500'  # Is it leaving as ESP?
```

**Resolution:** Add missing routes and verify ip_forward. On siteA-gw, if nftables drops the forwarded packet, check the forward chain ICMP rule allows echo-request.

---

## F09 — SSH access only via VPN path (optional Part D)

**Symptom (intended behavior):** After restricting SSH on siteB-srv to accept connections only from the tunnel-sourced subnet (10.10.10.0/24), direct SSH from siteB-gw or from the public internet is blocked.

**Configuration (nftables on siteB-srv):**
```bash
sudo nft add rule inet filter input ip saddr != 10.10.10.0/24 tcp dport 22 drop
```

**Dependency chain:** The IPsec tunnel MUST be established before siteA-client can SSH to siteB-srv. If the tunnel is down, siteA-client cannot connect even with a valid key. This is intentional — it enforces "VPN-first" access.

**Fallback plan:** Maintain an emergency access path (e.g., AWS Systems Manager Session Manager, or a temporary nftables rule via the serial console) to recover if the tunnel is unexpectedly down. For this TD, the fallback is ProxyJump via siteB-gw (which bypasses the restriction from within the DMZ).

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
