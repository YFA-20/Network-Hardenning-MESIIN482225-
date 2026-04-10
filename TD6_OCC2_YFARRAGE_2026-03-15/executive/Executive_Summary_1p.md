# Executive Summary — Network Hardening Project
**ESILV — Group OCC2 / Youssouf FARRAGE | Major Cybersecurity & IOT Trust | March 2026**

---

## What this project did

We inherited a two-site lab network (Azure + AWS) with no security controls in place. Over five weeks we hardened it from the ground up. The result is a network where every access path is controlled, all traffic between sites is encrypted, and every security claim can be re-verified in under ten minutes by running a single script.

---

## The three risks we fixed

**1. Unencrypted traffic between sites (Critical)**
All data exchanged between our Azure site and our AWS site was crossing the public internet in cleartext. We set up an encrypted tunnel (IPsec VPN) between the two sites. We verified with a packet capture that only encrypted traffic is now visible on the wire — no readable data.

**2. Open administrative access (High)**
The gateway's SSH port was reachable from the entire internet. We observed automated attacks hitting it within hours of deployment. We locked it down to specific authorised IP addresses and disabled password login entirely on the target server.

**3. Weak encryption on the web service (High)**
The web server was accepting connection methods that do not guarantee that past traffic stays private if a key is ever stolen. We restricted it to modern encryption only (TLS 1.2/1.3, forward-secret ciphers), and added HTTP attack filters and rate limiting.

---

## Five controls now in place

| # | Control | What it does |
|---|---|---|
| 1 | Default-deny firewall | Blocks all traffic not explicitly listed — 12 tests confirm this works in both directions |
| 2 | Intrusion detection | Monitors all traffic crossing the gateway; flags known attack signatures in real time |
| 3 | TLS hardening | Web service uses only modern, forward-secret encryption; HSTS prevents downgrade attacks |
| 4 | SSH hardening | Key-only access, root login blocked, failed-attempt limit on the AWS server |
| 5 | Site-to-site VPN | All inter-site traffic encrypted end-to-end; confirmed by network capture |

---

## What we did not solve

- **Certificate expiry** — the web server certificate expires 18 March 2026; no automatic renewal is configured yet.
- **Rate limiting scope** — only the /api/ path is rate-limited; other paths are not covered.
- **No centralised logging** — logs from each machine are not yet aggregated in one place.
- **IPsec key management** — currently uses a shared password; should be replaced with certificates for production.

---

## Next actions (30/60/90 days)

- **30 days** — automate certificate renewal (Let's Encrypt + cron), extend rate limiting beyond /api/, set up centralised log aggregation (rsyslog or Loki)
- **60 days** — add authentication to the API endpoints, deploy a web application firewall (ModSecurity or nginx njs), review Suricata ruleset and tune false positives
- **90 days** — migrate IPsec from PSK to certificate authentication (PKI), rebuild infrastructure as code (Terraform + Ansible), integrate security regression tests into the CI/CD pipeline
