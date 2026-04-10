# TD4 — Test Cards

---

## TD4-T01 — Baseline cipher policy is insufficiently restrictive

**Claim:** The baseline nginx configuration accepts cipher suites without ECDHE, providing no forward secrecy for those sessions.

**Preconditions:** `config/nginx_before.conf` deployed on srv-web, nginx reloaded.

**Test (positive):** Run `sslscan 10.10.20.10:443` from kali. Observe cipher suites listed without ECDHE prefix (e.g., `AES256-GCM-SHA384`, `AES256-SHA`).

**Test (negative):** Verify that the same suites are absent after hardening.

**Expected:** Baseline scan lists ≥ 10 non-ECDHE suites accepted.

**Observed:** 16 non-ECDHE suites accepted in baseline scan (see `evidence/before/sslscan_before.txt`).

**Evidence file:** `evidence/before/sslscan_before.txt`

---

## TD4-T02 — Baseline has TLS 1.3 disabled

**Claim:** The baseline configuration disables TLS 1.3, limiting the server to TLS 1.2 only.

**Preconditions:** `config/nginx_before.conf` deployed.

**Test (positive):** `sslscan 10.10.20.10:443` shows `TLSv1.3 disabled`.

**Test (negative):** After hardening, `TLSv1.3 enabled`.

**Expected:** TLS 1.3 disabled in baseline.

**Observed:** Confirmed — `TLSv1.3 disabled` in baseline scan output.

**Evidence file:** `evidence/before/sslscan_before.txt`

---

## TD4-T03 — After hardening, all cipher suites enforce forward secrecy

**Claim:** The hardened configuration accepts only ECDHE cipher suites, guaranteeing forward secrecy on every session.

**Preconditions:** `config/nginx_after.conf` deployed, nginx reloaded.

**Test (positive):** `sslscan 10.10.20.10:443` lists only suites with ECDHE prefix or TLS 1.3 built-in suites.

**Test (negative):** No suite without ECDHE prefix appears in the output.

**Expected:** 6 suites total, all ECDHE (TLS 1.2) or TLS 1.3 mandatory AEAD suites.

**Observed:** 6 suites — TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256, TLS_AES_128_GCM_SHA256 (TLS 1.3), ECDHE-RSA-AES256-GCM-SHA384, ECDHE-RSA-CHACHA20-POLY1305, ECDHE-RSA-AES128-GCM-SHA256 (TLS 1.2).

**Evidence file:** `evidence/after/sslscan_after.txt`

---

## TD4-T04 — After hardening, TLS 1.2 and TLS 1.3 are both enabled

**Claim:** The hardened configuration enables both TLS 1.2 and TLS 1.3; legacy versions remain disabled.

**Preconditions:** `config/nginx_after.conf` deployed.

**Test (positive):** `sslscan` shows `TLSv1.2 enabled` and `TLSv1.3 enabled`.

**Test (negative):** `TLSv1.0 disabled`, `TLSv1.1 disabled`, `SSLv2 disabled`, `SSLv3 disabled`.

**Expected:** Only TLS 1.2 and TLS 1.3 active.

**Observed:** Confirmed in post-hardening scan.

**Evidence file:** `evidence/after/sslscan_after.txt`

---

## TD4-T05 — HSTS header is present after hardening

**Claim:** The hardened configuration sends `Strict-Transport-Security` on every HTTPS response.

**Preconditions:** `config/nginx_after.conf` deployed.

**Test (positive):** `curl -vk https://10.10.20.10 2>&1 | grep -i strict` returns the HSTS header.

**Test (negative):** Same command against baseline returns no HSTS header.

**Expected:** `Strict-Transport-Security: max-age=300`

**Observed:** `< Strict-Transport-Security: max-age=300` confirmed in curl output.

**Evidence file:** `evidence/after/sslscan_after.txt` (curl verification in `tests/commands.txt`)

---

## TD4-T06 — Rate limiting triggers on burst traffic to /api/

**Claim:** The `limit_req` control rejects requests exceeding 1r/s with burst=2 on the `/api/` endpoint.

**Preconditions:** `config/nginx_after.conf` deployed with `limit_req_zone` in nginx.conf, static file present at `/var/www/html/api/index.html`.

**Test (positive):** Single request to `https://10.10.20.10/api/` returns HTTP 200.

**Test (negative):** 20 simultaneous parallel requests return ≤ 3 × 200 and ≥ 17 × 503.

**Expected:** 3 passes (1 base + burst 2), 17 rejections.

**Observed:** Exactly 3 × 200 and 17 × 503 confirmed in nginx access log at timestamp 13:33:37 UTC.

**Evidence file:** `evidence/after/rate_limit_test.txt`

---

## TD4-T07 — Certificate parameters match documented trust model

**Claim:** The self-signed certificate has RSA 2048-bit key, SHA-256 signature, CN=td4.local, 7-day validity — consistent with the lab trust model.

**Preconditions:** Certificate deployed at `/etc/nginx/certs/server.crt`.

**Test (positive):** `openssl x509 -in /etc/nginx/certs/server.crt -noout -text` confirms all parameters.

**Expected:** RSA 2048, sha256WithRSAEncryption, CN=td4.local, validity Mar 11–18 2026.

**Observed:** All parameters confirmed — see `config/cert_info_before.txt`.

**Evidence file:** `config/cert_info_before.txt`

---

## TD4-T08 — Request filter blocks SQLi, scanner UA, and non-standard methods

**Claim:** The hardened nginx configuration blocks SQL injection patterns in the URI, known scanner User-Agent strings, and non-standard HTTP methods.

**Preconditions:** `config/nginx_after.conf` deployed with filter `if` blocks, nginx reloaded.

**Test (positive):**
```bash
curl -sk -o /dev/null -w "SQLi: %{http_code}\n" "https://10.10.20.10/?id=1'OR'1'='1"
curl -sk -o /dev/null -w "BadUA: %{http_code}\n" -A "sqlmap/1.0" https://10.10.20.10/
curl -sk -o /dev/null -w "BadMethod: %{http_code}\n" -X DELETE https://10.10.20.10/
```

**Test (negative):**
```bash
curl -sk -o /dev/null -w "Normal: %{http_code}\n" https://10.10.20.10/
```

**Expected:** SQLi → 403, BadUA → 403, BadMethod → 405, Normal → 200.

**Observed:** SQLi: 403, BadUA: 403, BadMethod: 405, Normal: 200 — confirmed in `evidence/after/filter_test.txt`.

**Evidence file:** `evidence/after/filter_test.txt`
