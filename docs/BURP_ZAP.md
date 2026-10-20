# Intercepting with Burp Suite / OWASP ZAP

SentinelX is built to be driven by an intercepting proxy during a presentation. The API is a
plain JSON/HTTP service on `http://127.0.0.1:4000`, with no anti-automation beyond the
documented rate limits, so GET/POST/PUT/DELETE are all interceptable.

## Burp Suite

1. **Proxy → Options**: default listener `127.0.0.1:8080`.
2. Point a browser (or Burp's built-in browser) at the proxy and open the app, **or** feed
   requests straight from Repeater.
3. **Turn interception on** and exercise a flow, e.g. login:

   ```
   POST /api/auth/login HTTP/1.1
   Host: 127.0.0.1:4000
   Content-Type: application/json

   {"username":"alice","password":"Alice#2024!Vault"}
   ```

   The response sets `sx_session` and returns a `csrfToken`. Mutating requests then need
   `X-CSRF-Token: <token>` and the `sx_session` cookie.

4. **Demonstrate SQL injection** against the lab probe (flip `sqli` to vulnerable first):

   ```
   POST /api/lab/sqli/login HTTP/1.1
   Content-Type: application/json

   {"username":"' OR '1'='1' -- ","password":"x"}
   ```

   In vulnerable mode the response returns extracted rows; in hardened mode it returns none.

5. **Demonstrate IDOR** (flip `idor` to vulnerable, sign in as Bob):

   ```
   GET /api/lab/idor/document/1 HTTP/1.1
   Cookie: sx_session=<bob's session>
   ```

   Vulnerable: Alice's document body is returned. Hardened: `403` with the authorization reason.

6. **Headers:** send any request and inspect the response headers; flip the `headers` mode and
   resend to watch CSP/HSTS/etc. appear or disappear and the `X-Powered-By`/banners toggle.

## OWASP ZAP

1. Set the browser proxy to ZAP (default `127.0.0.1:8080`), or use ZAP's HUD.
2. **Spider** `http://127.0.0.1:4000/api` (and the SPA at `:5173`) to populate the site tree.
3. Use **Manual Request Editor** to replay the requests above.
4. ZAP's **passive scan** will flag the missing security headers and verbose errors when the
   corresponding classes are in vulnerable mode — a good cross-check against SentinelX's own
   scanner and Headers Inspector.

> ⚠️ Run active scans only against this local instance. The platform is intentionally
> vulnerable and must never be exposed beyond localhost.

## curl quick-reference

```bash
# Login, keep cookies, grab the CSRF token
RESP=$(curl -s -c jar.txt -X POST http://127.0.0.1:4000/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"analyst","password":"Analyst#2024!Vault"}')
CSRF=$(echo "$RESP" | python3 -c 'import json,sys;print(json.load(sys.stdin)["csrfToken"])')

# Run a scan (analyst role; CSRF + Origin required)
curl -s -b jar.txt -c jar.txt -X POST http://127.0.0.1:4000/api/security/scan \
  -H "X-CSRF-Token: $CSRF" -H 'Origin: http://localhost:5173'

# Flip SQLi to vulnerable (admin only — use the admin account), then probe it
curl -s -b jar.txt http://127.0.0.1:4000/api/lab/sqli/login \
  -H 'Content-Type: application/json' -X POST \
  -d '{"username":"'"'"' OR '"'"'1'"'"'='"'"'1'"'"' -- ","password":"x"}'
```

The **Testing Guide** inside the platform (and the **Request Inspector**) show these same
request/response shapes without leaving the UI.
