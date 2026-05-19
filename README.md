# WAF Bypass Tool

Auto-detect and bypass WAF verification challenges (Vercel, Cloudflare, AWS, Akamai, Imperva, Sucuri, F5, and more).

## Install

```bash
pip install curl_cffi cloudscraper
```

## Usage

```bash
python waf_bypass.py -t https://target.com
```

Or let it prompt for the URL:

```bash
python waf_bypass.py
```

Optional proxy:

```bash
python waf_bypass.py -t https://target.com -p http://127.0.0.1:8080
```

## How it works

1. Probes the target with a TLS-fingerprinted request (curl_cffi impersonating Chrome 136)
2. Detects the WAF from response headers, cookies, and body content
3. Applies the matching bypass strategy

## Supported WAFs

| WAF | Detection | Bypass |
|---|---|---|
| **Vercel** | `x-vercel-challenge-token` / `x-vercel-id` | SHA256 PoW solver |
| **Cloudflare** | `cf-ray` / `__cfduid` / `server: cloudflare` | cloudscraper |
| **AWS WAF** | `x-amz-cf-id` / `x-amzn-*` | TLS profile rotation (Chrome/Firefox/Safari/Edge) |
| **Akamai** | `akamai-grn` / `x-akamai-*` | TLS profile rotation + delayed retry |
| **Imperva** | `x-iinfo` / `incap_ses` cookie | cloudscraper + curl fallback |
| **Sucuri** | `x-sucuri-id` / `server: sucuri` | cloudscraper + curl fallback |
| **F5 BIG-IP** | `x-f5` / `x-asm` | TLS profile rotation |
| **ModSecurity** | `mod_security` / `naxsi` in body | TLS fingerprinting |
| **Unknown** | challenge keywords in body | tries all profiles + solvers |

## Example output

```
[*] Target: https://agath.app/
[*] Host:   agath.app
[*] Detecting WAF... VERCEL
  Status: 429
  Reason: Blocked: HTTP 429; Vercel challenge token; challenge page detected
  -> Vercel PoW solver... BYPASSED [200]

[+] WAF BYPASSED using chrome136 (vercel_solver)
[+] Status: 200
[+] Response size: 13840 bytes
[+] Server: N/A
```

No WAF:

```
[*] Target: https://httpbin.org/
[*] Host:   httpbin.org
[*] Detecting WAF... none
[+] Site accessible directly [200]
```

Cloudflare detected (accessible without block):

```
[*] Target: https://nowsecure.nl/
[*] Host:   nowsecure.nl
[*] Detecting WAF... CLOUDFLARE
  Status: 200
  WAF detected (cloudflare) but site is accessible without bypass
```
