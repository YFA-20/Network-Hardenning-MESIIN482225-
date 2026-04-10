# Failure Modes — TD1
**Author:** Youssouf FARRAGE | **Date:** 2026-03-04

Format per issue: Symptom → Root cause → Fix → Proof

---

## FM-01 — Private IP in Azure reserved range

**Symptom:** `az network nic create` failed with `PrivateIPAddressInReservedRange` when specifying `--private-ip-address 10.10.10.1` for gw-fw.

**Root cause:** Azure reserves the first four IPs of each subnet (.0=network, .1=gateway, .2–.3=DNS). These cannot be assigned to VMs. The course documentation assumes VirtualBox where .1 is freely assignable.

**Fix:** Assigned `10.10.10.4` (gw-fw LAN NIC) and `10.10.20.4` (gw-fw DMZ NIC) instead of .1. All other VMs kept their course-default IPs (.10, .10).

**Proof:** Successful NIC creation confirmed by Azure CLI; `ip addr` on gw-fw shows `10.10.10.4/24` and `10.10.20.4/24`.

---

## FM-02 — VM SKU not available in region

**Symptom:** `az vm create` failed with `SkuNotAvailable: Standard_B2s not available in francecentral`.

**Root cause:** Azure for Students subscriptions have limited SKU availability by region. Standard_B2s was not available in francecentral at time of deployment.

**Fix:** Switched to `Standard_D2s_v3` for gw-fw and client (2 vCPU, 8 GB RAM). Used `Standard_D2_v3` for srv-web (Gen1 compatible).

**Proof:** VMs created successfully with D-series SKUs. `az vm list -g rg-nh-lab -o table` shows all VMs running.

---

## FM-03 — VM image generation mismatch (Gen1/Gen2)

**Symptom:** `az vm create` failed with generation mismatch error when combining `Standard_D2_v3` (Gen1 only) with `UbuntuLTS` image (Gen2).

**Root cause:** Standard_D2_v3 only supports Hyper-V Generation 1. The default Ubuntu 22.04 image alias resolves to a Gen2 image.

**Fix:** Used the explicit Gen1 image URN: `Canonical:0001-com-ubuntu-server-jammy:22_04-lts:latest`.

**Proof:** VM created successfully. `az vm show` confirms generation = V1.

---

## FM-04 — vCPU quota exceeded (Azure for Students)

**Symptom:** `az vm create` for sensor-ids failed with `QuotaExceeded: standardDSv3Family (4/4)` then `Total Regional Cores (6/6)`.

**Root cause:** Azure for Students subscriptions are limited to 6 vCPUs per region. gw-fw (2) + client (2) + srv-web (2) = 6 — no quota remaining for sensor-ids (2 vCPUs).

**Fix:** sensor-ids VM not deployed. Suricata installed on gw-fw instead (UTM architecture). This is a validated workaround documented in `0_technical_support/00_environment/oci_cloud_alternative.md`.

**Proof:** Architecture deviation acknowledged in README.md and report.md.

---

## FM-05 — Kali Linux image not found with default URN

**Symptom:** `az vm create --image kali-linux:kali-linux:kali:latest` failed with `Could not resolve version`.

**Root cause:** The Kali Linux image URN on Azure Marketplace uses a non-obvious naming convention. The default alias was incorrect.

**Fix:** Used `az vm image list --publisher kali-linux --location francecentral --all -o table` to enumerate available SKUs. Correct URN: `kali-linux:kali:kali-2025-4:2025.4.0`. Accepted marketplace terms with `az vm image terms accept`.

**Proof:** Kali VM created successfully. Used as physical workstation (local Kali) for the remainder of the lab.

---

## FM-06 — Lost SSH key, locked out of all VMs

**Symptom:** SSH key was lost (not backed up). `Permission denied (publickey)` on all VMs.

**Root cause:** SSH keypair generated in Azure Cloud Shell was not saved outside the Cloud Shell session. Cloud Shell storage is ephemeral across sessions.

**Fix:**
1. Generated new ed25519 keypair on physical Kali: `ssh-keygen -t ed25519 -f ~/.ssh/nh_lab_key`
2. Pushed public key to all VMs via Azure CLI (does not require SSH): `az vm user update --resource-group rg-nh-lab --name <vm> --username farki --ssh-key-value "$(cat ~/.ssh/nh_lab_key.pub)"`

**Proof:** SSH access restored to all VMs from Kali using new keypair.

**Lesson learned:** Always save SSH keypairs outside Cloud Shell (e.g., in Azure Key Vault or a local password manager). Document the key fingerprint.

---

## FM-07 — tcpdump background job stops immediately (stdin issue)

**Symptom:** `ssh nh-gw "sudo tcpdump -i any -w /tmp/baseline.pcap -nn" &` — job immediately shows `[1]+ Stopped`. `baseline.pcap` not created.

**Root cause:** When an SSH session is placed in background with `&`, it detaches from the terminal. If the remote command or SSH itself needs to read from stdin (e.g., passphrase prompt for SSH key), the process is suspended by the terminal job control (SIGTTOU/SIGTTIN). Even with `< /dev/null`, the passphrase prompt prevents the process from starting.

**Fix:** Use two terminal windows. Terminal 1: interactive SSH to gw-fw, run tcpdump interactively. Terminal 2: generate traffic. Stop tcpdump with Ctrl+C in Terminal 1. This avoids background job issues entirely.

**Proof:** `baseline.pcap` successfully created with 874 packets using the 2-terminal method.

---

## FM-08 — LAN→DMZ traffic bypasses gw-fw (Azure routing)

**Symptom:** `curl` and `ping` from client to srv-web succeed, but no corresponding packets appear in tcpdump capture on gw-fw.

**Root cause:** Azure routes intra-VNet traffic at the hypervisor level by default. Without a User Defined Route (UDR) forcing LAN-subnet traffic through gw-fw (10.10.10.4), packets go directly between subnets and never hit gw-fw's network stack.

**Fix (TD2 objective):** Create Azure UDR:
- Route table on NH-LAN subnet: `10.10.20.0/24 → next hop 10.10.10.4 (Virtual Appliance)`
- Route table on NH-DMZ subnet: `10.10.10.0/24 → next hop 10.10.20.4 (Virtual Appliance)`

**Proof (pending TD2):** After UDR applied, tcpdump on gw-fw should capture LAN↔DMZ traffic. Documented as Risk R03.
