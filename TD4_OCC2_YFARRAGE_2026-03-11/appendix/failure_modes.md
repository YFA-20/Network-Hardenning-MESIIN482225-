# Appendix — Failure Modes

| ID | Failure | Symptom | Fix |
|---|---|---|---|
| FM-01 | nginx reload fails | `nginx -t` shows syntax error | Read the exact error line; fix config; always run `nginx -t` before reload |
| FM-02 | Certificate directory missing | `openssl req` fails with "No such file or directory" | `sudo mkdir -p /etc/nginx/certs` before generating the certificate |
| FM-03 | curl from local laptop hangs | Connection times out on port 443 | Azure NSG or nftables blocking TCP/443; verify F04 rule on gw-fw (`sudo nft list chain inet filter forward`) |
| FM-04 | sslscan reports TLS 1.0/1.1 disabled despite config | Expected on Ubuntu 22.04 / OpenSSL 3.0 | OpenSSL 3.0 enforces a system security policy that removes TLS 1.0/1.1 at library level; not a config error — document as environment constraint |
| FM-05 | RC4 ciphers not negotiated despite `RC4` in ssl_ciphers | Expected — no connection error | OpenSSL 3.0 removes RC4 from cipher list; `HIGH` keyword still enables ECDHE and non-ECDHE AES suites |
| FM-06 | Rate limit not triggering with sequential curl loop | All requests return 200 | Sequential requests complete slower than 1r/s; use parallel `&` loop; also verify `limit_req` is NOT in a location block using `return` (rewrite phase bypasses preaccess modules) |
| FM-07 | `return 200` in location block bypasses `limit_req` | Rate limit never fires | `return` executes in rewrite phase (phase 3) before `limit_req` runs in preaccess phase (phase 7); serve real static content or use `proxy_pass` instead |
| FM-08 | HSTS not appearing in curl output | No `Strict-Transport-Security` header | Verify `add_header` is inside the `server {}` block; check for `always` keyword; reload nginx after change |
| FM-09 | Nginx config change has no effect | Old behavior persists | `systemctl reload nginx` was not run, or `nginx -t` failed silently; always run both commands in sequence |
| FM-10 | Wrong sslscan version between before/after scans | Results incomparable | Before scan run on srv-web (OpenSSL 3.0.2 / sslscan 2.0.7); after scan run on kali (OpenSSL 3.5.4 / sslscan 2.1.5); version difference is cosmetic — cipher and protocol results are consistent |
| FM-11 | `if ($http_host ...)` blocks all requests including legitimate ones | Normal GET returns 403 | nginx evaluates multiple `if` blocks in server context non-atomically; `if ($http_host ...)` combined with other `if` blocks fires incorrectly on valid requests. Fix: use `if ($host ...)` — if still failing, replace with HTTP method restriction which behaves reliably in multi-if context |
| FM-12 | nginx returns 403 on normal GET after all filter rules pass | Normal request blocked despite no rule matching | Default Ubuntu nginx creates `index.nginx-debian.html`, not `index.html`; config uses `index index.html` with autoindex off — nginx returns 403 Forbidden when the index file is absent. Fix: `sudo cp /var/www/html/index.nginx-debian.html /var/www/html/index.html` |
