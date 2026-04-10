# TD4 — TLS Audit and Hardening
**Group OCC2 / Youssouf FARRAGE — ESILV, 4th year, Major Cybersecurity & IOT Trust — 2026-03-11**

## Contents

| File | Description |
|------|-------------|
| `report.md` | Full lab report |
| `artefacts/nginx_before.conf` | nginx site config — weak TLS baseline (before hardening) |
| `artefacts/nginx_after.conf` | nginx site config — hardened profile (TLS 1.2/1.3, ECDHE-only, HSTS, rate limit) |
| `artefacts/nginx_conf_ratelimit.txt` | `limit_req_zone` directive added to `/etc/nginx/nginx.conf` |
| `artefacts/cert_info_before.txt` | `openssl x509 -text` output of the self-signed certificate |
| `artefacts/sslscan_before.txt` | sslscan output against srv-web before hardening |
| `artefacts/sslscan_after.txt` | sslscan output against srv-web after hardening |
| `artefacts/rate_limit_test.txt` | nginx access.log extract showing 3×200 / 17×503 rate-limit test |

## Key Results

- TLS 1.3 re-enabled, TLS 1.2 retained, TLS 1.0/1.1 eliminated
- Cipher suite count reduced from 27 to 6, all ECDHE (forward secrecy on every session)
- HSTS header added (`max-age=300`)
- Rate limiting: 1 req/s, burst 2 — validated with 20 parallel curl requests
