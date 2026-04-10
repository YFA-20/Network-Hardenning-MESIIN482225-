# Change Log — TLS Hardening (nginx_before.conf → nginx_after.conf)

| Line / Directive | Before | After | Justification |
|---|---|---|---|
| `ssl_protocols` | `TLSv1 TLSv1.1 TLSv1.2` | `TLSv1.2 TLSv1.3` | TLS 1.0 and 1.1 deprecated by RFC 8996; NIST SP 800-52 Rev.2 §3.3.1 requires TLS 1.2 minimum |
| `ssl_ciphers` | `"RC4:HIGH:!aNULL:!MD5"` | ECDHE-only AEAD allowlist | RC4 is broken (Fluhrer/Mantin/Shamir); HIGH is too permissive — includes CBC suites without forward secrecy. Replaced with explicit ECDHE+GCM+CHACHA20 allowlist per NIST SP 800-52 Rev.2 §3.3.3 |
| Forward secrecy | Partial — non-ECDHE suites accepted | Guaranteed — all suites ECDHE | Without ECDHE, a compromised private key decrypts all recorded past sessions |
| TLS 1.3 | Disabled | Enabled | TLS 1.3 mandates AEAD and forward secrecy by design; re-enabling reduces negotiation complexity |
| `add_header Strict-Transport-Security` | Absent | `max-age=300 always` | HSTS prevents protocol downgrade and SSL-stripping attacks; short max-age appropriate for lab cert rotation |
| `limit_req_zone` (nginx.conf) | Absent | `rate=1r/s zone=api_limit` | Rate limiting limits brute-force and DoS impact on the /api endpoint |
| `limit_req` in `/api/` | Absent | `burst=2 nodelay` | Enforces the zone on the API path; nodelay drops excess immediately rather than queuing |
| SQLi filter (`if $request_uri`) | Absent | Block on `select\|union\|insert\|drop\|'\|--\|;` | Prevents common SQL injection patterns from reaching the application layer |
| Bad User-Agent filter (`if $http_user_agent`) | Absent | Block on `sqlmap\|nikto\|nmap\|masscan\|havij` | Denies known scanner and exploitation tool signatures at the perimeter |
| HTTP method restriction (`if $request_method`) | Absent | Allow GET, POST, HEAD only; return 405 otherwise | Restricts attack surface — DELETE, PUT, OPTIONS not required by this endpoint |

## Notes

- The self-signed certificate (RSA 2048 / SHA-256 / CN=td4.local) was not modified. Certificate quality is out of scope for this hardening exercise; the lab trust model accepts self-signed certs.
- RC4 was in the baseline cipher string but OpenSSL 3.0 (Ubuntu 22.04) removes it at library level regardless of nginx configuration.
- TLS 1.0 and 1.1 were in the baseline ssl_protocols but are similarly blocked by OpenSSL 3.0's system security policy. The actual observable weaknesses were non-ECDHE cipher acceptance and TLS 1.3 being disabled.
