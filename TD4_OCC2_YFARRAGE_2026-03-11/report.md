# TD4 — TLS Audit and Hardening

| Field             | Value                                                        |
|-------------------|--------------------------------------------------------------|
| Module            | Network Hardening — ESILV, 4th year, Major Cybersecurity & IOT Trust |
| Lab               | TD4 — TLS Audit and Hardening                               |
| Group / Student   | Group OCC2 / Youssouf FARRAGE — ESILV, 4th year, Major Cybersecurity & IOT Trust |
| Date              | 2026-03-11                                                   |
| Normative anchor  | NIST SP 800-52 Rev.2 + RFC 8446 (TLS 1.3)                   |
| Platform          | Microsoft Azure (3-VM lab: gw-fw, srv-web, kali)             |

---

## 1. Platform Context

TD1 established the network baseline on the three-VM Azure lab: gw-fw (10.10.10.1 / 10.10.20.1) acts as the perimeter gateway, srv-web (10.10.20.10) hosts the web service in the DMZ, and kali (10.10.10.10) serves as the client and audit workstation. TD2 implemented nftables firewall rules on gw-fw, including the TCP/443 forward rule (F04) that allows HTTPS traffic from the LAN into the DMZ. TD3 added Suricata intrusion detection in UTM mode on gw-fw, providing layer-7 visibility over traffic traversing the gateway. TD4 picks up from that foundation and focuses on the transport layer: deploying TLS on srv-web, auditing its configuration, and hardening it to a NIST SP 800-52 Rev.2 profile.

The lab uses self-signed certificates throughout. Certificate authority trust chains are not part of the TD4 scope; the hardening work concerns protocol version selection, cipher suite restriction, and header-level transport enforcement.

## 2. Threat Model

**Asset:** the web service running on srv-web (10.10.20.10, TCP/443) — an nginx endpoint serving content to the LAN client through the DMZ.

**Adversary:** an on-path attacker positioned on the NH-LAN or NH-DMZ segment, or a remote scanner reaching the endpoint through the cloud perimeter. The threat is realistic given the flat Azure virtual network topology where any compromised VM on the same subnet can passively capture traffic.

**Key threats:**

- Negotiation of a cipher suite without forward secrecy — a compromised private key retroactively decrypts all recorded sessions.
- Acceptance of legacy TLS versions (1.0/1.1) — known protocol-level vulnerabilities (BEAST, POODLE, DROWN) and NIST SP 800-52 Rev.2 prohibition.
- Absent or bypassable HSTS — an SSL-stripping attack downgrades the first connection to plaintext before the browser enforces HTTPS.
- Missing rate limiting — a burst of requests against the API endpoint can exhaust server resources or enable credential enumeration.
- Misconfigured edge controls — overly permissive cipher strings (e.g., `HIGH`) accept weaker suites that OpenSSL 3.0 still permits even when RC4/TLS 1.0 are blocked at library level.

**Security goals:**

- Only TLS 1.2 and TLS 1.3 are offered; legacy versions are disabled.
- All negotiated cipher suites provide forward secrecy (ECDHE prefix).
- HSTS prevents protocol downgrade on the client side.
- Rate limiting provides basic availability protection on the API path.

## 3. TLS Profile

The target profile is derived from NIST SP 800-52 Rev.2 §3.3 and aligned with RFC 8446 for TLS 1.3.

**Minimum protocol version:** TLS 1.2 (NIST SP 800-52 Rev.2 §3.3.1 prohibits TLS 1.0 and 1.1). TLS 1.3 is enabled as the preferred version.

**Cipher strategy:** AEAD suites only (GCM, CHACHA20-POLY1305). CBC-mode suites are excluded. All TLS 1.2 suites must carry the ECDHE prefix to guarantee forward secrecy. TLS 1.3 built-in suites (TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256, TLS_AES_128_GCM_SHA256) are inherited from the TLS 1.3 specification and require no explicit configuration.

**Certificate management:** self-signed RSA 2048 / SHA-256 certificate, 7-day validity. Trust model: lab-internal only; clients connect with `-k` (skip verification). This is explicitly documented as a lab constraint. In production, a CA-signed certificate with automated renewal (ACME/Let's Encrypt or enterprise PKI) would be required.

**HSTS policy:** `max-age=300` for the lab (short to accommodate certificate rotation). Production recommendation: `max-age=31536000; includeSubDomains` per NIST SP 800-52 Rev.2 §3.6.

**Operational checks:** `nginx -t` before every reload; `sslscan` after any config change to confirm the cipher profile; certificate expiry monitored manually for the 7-day lab window.

## 4. Certificate Deployment

A self-signed certificate was generated on srv-web:

```bash
sudo mkdir -p /etc/nginx/certs
sudo openssl req -x509 -newkey rsa:2048 -days 7 -nodes \
  -subj "/CN=td4.local" \
  -keyout /etc/nginx/certs/server.key \
  -out /etc/nginx/certs/server.crt
```

The certificate uses RSA 2048-bit keys, SHA-256 as the signature algorithm, and a 7-day validity window (Mar 11–18 2026). The full certificate detail is in `config/cert_info_before.txt`. The certificate is not replaced during the hardening phase. nginx was configured to redirect all HTTP traffic on port 80 to HTTPS on port 443.

## 5. Baseline TLS Audit (Before)

The baseline nginx configuration (`config/nginx_before.conf`) used the following directives:

```nginx
ssl_protocols TLSv1 TLSv1.1 TLSv1.2;
ssl_ciphers "RC4:HIGH:!aNULL:!MD5";
ssl_prefer_server_ciphers on;
# No HSTS header
```

**OpenSSL 3.0 system policy note.** Ubuntu 22.04 ships with OpenSSL 3.0, which enforces a system-level security policy removing TLS 1.0, TLS 1.1, and RC4 at library level regardless of application configuration. The nginx config declared these protocols and cipher but they were not negotiable in practice. The actual observable weaknesses are those that OpenSSL 3.0 still permits.

**Before profile — findings from `evidence/before/sslscan_before.txt`:**

| Item | Finding | Evidence file |
|------|---------|--------------|
| Protocol versions | TLS 1.2 only (TLS 1.3 disabled; TLS 1.0/1.1 blocked by OpenSSL 3.0) | `evidence/before/sslscan_before.txt` |
| Cipher families | 27 suites: ECDHE+AEAD, ECDHE+CBC, non-ECDHE AEAD, non-ECDHE CBC | `evidence/before/sslscan_before.txt` |
| Forward secrecy | Partial — 16 suites without ECDHE have no forward secrecy | `evidence/before/sslscan_before.txt` |
| Certificate subject | CN=td4.local, self-signed | `config/cert_info_before.txt` |
| Key size + signature | RSA 2048, SHA-256 | `config/cert_info_before.txt` |
| Chain status | Self-signed, no chain — expected in lab | `config/cert_info_before.txt` |
| HSTS | Absent | `evidence/before/sslscan_before.txt` |
| Obvious risk | 16 non-ECDHE suites accepted — past traffic decryptable if private key compromised | — |

## 6. TLS Hardening (After)

The hardened nginx configuration (`config/nginx_after.conf`) implements the TLS profile defined in §3:

```nginx
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:
             ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:
             ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:
             !aNULL:!MD5:!RC4:!DH";
ssl_prefer_server_ciphers on;
add_header Strict-Transport-Security "max-age=300" always;
```

Every cipher suite in the allowlist carries the ECDHE prefix, guaranteeing forward secrecy on every session. All suites are GCM or POLY1305 mode — no CBC. TLS 1.3 is re-enabled. A line-by-line rationale for each change is in `config/change_log.md`.

**Before / after comparison:**

| Item | Before | After | Evidence file |
|------|--------|-------|---------------|
| TLS 1.0 / 1.1 | Disabled by OpenSSL 3.0 | Disabled | `evidence/before/sslscan_before.txt` |
| TLS 1.2 | Enabled | Enabled | both scan files |
| TLS 1.3 | **Disabled** | **Enabled** | `evidence/after/sslscan_after.txt` |
| Cipher suite count | 27 | 6 | both scan files |
| Non-ECDHE suites | **16 accepted** | **0** | `evidence/after/sslscan_after.txt` |
| CBC-mode suites | Present | Absent | `evidence/after/sslscan_after.txt` |
| Forward secrecy | Partial | All sessions | `evidence/after/sslscan_after.txt` |
| HSTS | **Absent** | **max-age=300** | curl verification |
| Certificate | RSA 2048, self-signed | unchanged (lab) | `config/cert_info_before.txt` |

HSTS was confirmed independently: `curl -vk https://10.10.20.10 2>&1 | grep -i strict` returned `< Strict-Transport-Security: max-age=300`.

## 7. Edge Controls — Rate Limiting

A rate-limiting zone was added in the `http {}` block of `/etc/nginx/nginx.conf` (see `config/nginx_conf_ratelimit.txt`):

```nginx
limit_req_zone $binary_remote_addr zone=api_limit:10m rate=1r/s;
```

Applied to the `/api/` location:

```nginx
location /api/ {
    limit_req zone=api_limit burst=2 nodelay;
    root /var/www/html;
    index index.html;
}
```

**Implementation note.** An early version used nginx's `return 200` directive inside the location block. This bypasses rate limiting: `return` executes in the rewrite phase (phase 3) before `limit_req` runs in the preaccess phase (phase 7). Serving a real static file resolves the phase ordering issue and allows `limit_req` to intercept correctly. This is documented in `appendix/failure_modes.md` (FM-07).

**Proof.** Twenty parallel curl requests fired from kali to `https://10.10.20.10/api/`. Result: 3 × HTTP 200 (1 base + burst 2), 17 × HTTP 503. The nginx access log confirms all 20 requests arrived at 13:33:37 UTC from 10.10.10.10 — see `evidence/after/rate_limit_test.txt`.

### 7.2 Request Filtering

Three nginx `if` directives were added to the server block to implement basic request inspection at the edge:

- **SQLi pattern block** — `$request_uri` matched against `(select|union|insert|drop|'|--|;)`. Requests carrying common injection tokens return HTTP 403.
- **Scanner User-Agent block** — `$http_user_agent` matched against a denylist of known exploitation tools (`sqlmap`, `nikto`, `nmap`, `masscan`, `havij`). Returns HTTP 403.
- **HTTP method restriction** — only GET, POST, and HEAD are permitted. All other methods return HTTP 405.

**Proof.** Four curl probes from kali against `https://10.10.20.10/`:

| Probe | Expected | Observed |
|-------|----------|---------|
| SQLi URI `?id=1'OR'1'='1` | 403 | 403 |
| User-Agent `sqlmap/1.0` | 403 | 403 |
| Method DELETE | 405 | 405 |
| Normal GET | 200 | 200 |

Curl response codes in `evidence/after/filter_test.txt`. nginx access log in `evidence/after/nginx_access_log_filter.txt`:

```
10.10.10.10 - - [12/Mar/2026:09:31:32 +0000] "GET /?id=1'OR'1'='1 HTTP/1.1" 403 162 "-" "curl/8.18.0"
10.10.10.10 - - [12/Mar/2026:09:31:44 +0000] "GET / HTTP/1.1" 403 162 "-" "sqlmap/1.0"
10.10.10.10 - - [12/Mar/2026:09:32:01 +0000] "DELETE / HTTP/1.1" 405 166 "-" "curl/8.18.0"
10.10.10.10 - - [12/Mar/2026:09:32:12 +0000] "GET / HTTP/1.1" 200 612 "-" "curl/8.18.0"
```

**Implementation note.** A `if ($host ...)` check was evaluated and discarded: nginx evaluates multiple `if` blocks in server context non-atomically, causing the host check to fire on legitimate requests when combined with other `if` blocks. Method restriction was substituted — reliable, testable, and closes an equivalent attack surface.

## 8. Log Triage

**What happened?** During the rate-limiting validation test, kali (10.10.10.10) sent 20 simultaneous GET requests to `/api/` at 13:33:37 UTC. Three requests succeeded; seventeen were rejected by the rate-limiting control.

**Signal:** Source IP `10.10.10.10`, path `/api/`, HTTP status codes 200 and 503, all within a one-second window. The uniform timestamp and single source IP are the signature of a controlled burst test rather than distributed traffic.

**Classification:** benign — controlled test traffic from the lab client, consistent with the rate-limiting validation procedure.

**Exact log excerpt** (from `evidence/after/rate_limit_test.txt`):
```
10.10.10.10 - - [11/Mar/2026:13:33:37 +0000] "GET /api/ HTTP/1.1" 200 7 "-" "curl/8.18.0"
10.10.10.10 - - [11/Mar/2026:13:33:37 +0000] "GET /api/ HTTP/1.1" 503 206 "-" "curl/8.18.0"
```

**In a real SOC context:**

- Verify whether the source IP is an internal scanner or external address; cross-reference with asset inventory.
- Check whether the burst pattern repeats at regular intervals — automated scanning tools typically do.
- Correlate with authentication logs if `/api/` is behind auth — repeated 503 after a credential attempt pattern could indicate a rate-limited brute-force.
- If confirmed as external, escalate to firewall team for IP block and review NSG rules.

## 9. Observations

**O1 — OpenSSL 3.0 system policy.** TLS 1.0, TLS 1.1, and RC4 are blocked at library level on Ubuntu 22.04 regardless of nginx configuration. The nginx baseline config's declared weaknesses were therefore not fully exercised. The actual weaknesses demonstrated — TLS 1.3 disabled, non-ECDHE ciphers accepted, CBC-mode ciphers, missing HSTS — are real and independently correctable.

**O2 — Cipher string permissiveness.** The `HIGH` keyword in OpenSSL's cipher string notation is a broad catch-all that includes both strong and weak suites. Relying on `HIGH` in production is insufficient; an explicit ECDHE-only allowlist is required to enforce forward secrecy.

**O3 — rewrite vs. preaccess phase interaction.** The `return` directive in nginx runs before rate-limiting modules. For any location where access controls are required, content must be served through the normal content phase (static files, proxy_pass) rather than through rewrite-phase shortcuts.

**O4 — HSTS max-age for production.** The `max-age=300` value is intentionally short for lab use. In production, NIST SP 800-52 Rev.2 recommends at least one year, and inclusion in browser HSTS preload lists requires a minimum of two years with `includeSubDomains`.

## 10. Residual Risks

**Certificate rotation.** The self-signed certificate expires on Mar 18 2026. There is no automated renewal. In production, a PKI-integrated or ACME-based renewal process is required, with monitoring of certificate expiry at least 30 days in advance.

**Rate limiting scope.** The `limit_req` zone only covers `/api/`. The root location `/` and any other path are uncovered. A production deployment would extend rate limiting to all authenticated endpoints and apply global connection limits.

**Session ticket policy.** nginx session tickets are enabled by default, which can undermine forward secrecy if the session ticket key is long-lived. Session ticket rotation or explicit disabling (`ssl_session_tickets off`) was not applied in this session.

**Upstream authentication.** The API endpoint at `/api/` has no authentication layer — any client that reaches srv-web can access it. Authentication and authorization controls are outside the scope of TD4 but represent a significant residual risk.

---

*2026-03-11 — Platform: Microsoft Azure | Web server: nginx on srv-web*
