from __future__ import annotations

import sys
import time
import random
import re
import hashlib
import base64
import secrets
from urllib.parse import urlparse
from dataclasses import dataclass, field
from typing import Optional

try:
    from curl_cffi import requests as curl_requests
    from curl_cffi.requests import Session as CurlSession
    HAS_CURL = True
except ImportError:
    HAS_CURL = False

try:
    import cloudscraper
    HAS_CLOUDSCRAPER = True
except ImportError:
    HAS_CLOUDSCRAPER = False

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


# ==============================================================================
# Constants
# ==============================================================================

BROWSER_PROFILES = {
    "chrome136": {
        "impersonate": "chrome136",
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36",
        "sec_ch_ua": '"Chromium";v="136", "Google Chrome";v="136", "Not_A Brand";v="99"',
        "sec_ch_ua_platform": '"Windows"',
    },
    "chrome131": {
        "impersonate": "chrome131",
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
        "sec_ch_ua": '"Chromium";v="131", "Google Chrome";v="131", "Not_A Brand";v="99"',
        "sec_ch_ua_platform": '"Windows"',
    },
    "safari18": {
        "impersonate": "safari18_0",
        "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15",
        "sec_ch_ua": "",
        "sec_ch_ua_platform": '"macOS"',
    },
    "firefox135": {
        "impersonate": "firefox135",
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:135.0) Gecko/20100101 Firefox/135.0",
        "sec_ch_ua": "",
        "sec_ch_ua_platform": '"Windows"',
    },
    "edge136": {
        "impersonate": "chrome136",
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36 Edg/136.0.0.0",
        "sec_ch_ua": '"Chromium";v="136", "Microsoft Edge";v="136", "Not_A Brand";v="99"',
        "sec_ch_ua_platform": '"Windows"',
    },
}

BLOCK_SIGNALS = [
    "just a moment", "checking your browser",
    "please wait", "verify you are human",
    "enable javascript", "enable cookies",
    "you have been blocked", "access denied",
    "sorry, you have been blocked",
]


def _make_std_session() -> requests.Session:
    session = requests.Session()
    retry = Retry(total=3, backoff_factor=1, status_forcelist=[429, 500, 502, 503, 504])
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    return session


# ==============================================================================
# WAF Types
# ==============================================================================

class WAFType:
    NONE = "none"
    VERCEL = "vercel"
    CLOUDFLARE = "cloudflare"
    AWS = "aws"  # AWS WAF / CloudFront
    AKAMAI = "akamai"
    IMPERVA = "imperva"  # Incapsula
    SUCURI = "sucuri"
    F5 = "f5"  # BIG-IP ASM
    FORTINET = "fortinet"  # FortiWeb
    MODSECURITY = "modsecurity"  # ModSecurity / NAXSI
    UNKNOWN = "unknown"


WAF_SIGNATURES = {
    WAFType.VERCEL: {
        "headers": ["x-vercel-challenge", "x-vercel-id"],
        "server": ["vercel"],
    },
    WAFType.CLOUDFLARE: {
        "headers": ["cf-ray", "cf-bm", "__cfduid", "_cf_chl_opt"],
        "server": ["cloudflare"],
        "cookies": ["__cfduid", "cf_clearance", "__cf_bm"],
    },
    WAFType.AWS: {
        "headers": ["x-amz-cf-id", "x-amz-cf-pop", "x-amz-id-1", "x-amz-id-2", "x-amzn-requestid", "x-amzn-trace-id"],
        "server": ["cloudfront", "amazons3", "amazon"],
    },
    WAFType.AKAMAI: {
        "headers": ["akamai-grn", "x-akamai", "x-akamai-transformed"],
        "server": ["akamaighost"],
    },
    WAFType.IMPERVA: {
        "headers": ["x-iinfo", "x-cdn"],
        "server": [],
        "cookies": ["incap_ses", "visid_incap", "nlbi_"],
    },
    WAFType.SUCURI: {
        "headers": ["x-sucuri-id", "x-sucuri-cache", "x-sucuri-rr"],
        "server": ["sucuri"],
    },
    WAFType.F5: {
        "headers": ["x-f5", "x-asm", "x-asm-request"],
        "server": ["big-ip", "f5", "asm"],
    },
    WAFType.FORTINET: {
        "headers": [],
        "server": ["fortiweb", "fortinet"],
    },
    WAFType.MODSECURITY: {
        "headers": [],
        "server": [],
        "body": ["mod_security", "modsecurity", "naxsi", "blocked by", "malicious request"],
    },
}


@dataclass
class WAFResult:
    url: str
    status_code: int = 0
    headers: dict = field(default_factory=dict)
    body: str = ""
    success: bool = False
    method_used: str = ""
    profile_used: str = ""
    error: Optional[str] = None
    bypassed: bool = False


# ==============================================================================
# Vercel PoW Solver
# ==============================================================================

VERCEL_K = [498787, 533737, 619763, 708403, 828071]


def _parse_vercel_token(token: str) -> Optional[dict]:
    try:
        parts = token.split(".")
        if len(parts) < 5:
            return None
        _, request_id, difficulty, challenge_b64, _ = parts
        padding = 4 - len(challenge_b64) % 4
        if padding != 4:
            challenge_b64 += "=" * padding
        challenge_raw = base64.b64decode(challenge_b64)
        challenge_parts = challenge_raw.split(b";")
        return {
            "request_id": int(request_id),
            "difficulty": int(difficulty),
            "seed2": challenge_parts[1].decode("ascii"),
            "seed3": challenge_parts[2].decode("ascii"),
            "count": int(challenge_parts[3].decode("ascii")),
        }
    except Exception:
        return None


def _find_nonce(seed2: str, expected_prefix: str) -> tuple[str, str]:
    while True:
        nonce = secrets.token_hex(8)
        h = hashlib.sha256((seed2 + nonce).encode()).hexdigest()
        if h[:4] == expected_prefix:
            return nonce, h


def _solve_vercel_challenge(token: str) -> Optional[str]:
    parsed = _parse_vercel_token(token)
    if not parsed:
        return None
    M = parsed["request_id"]
    seed2 = parsed["seed2"]
    seed3 = parsed["seed3"]
    count = parsed["count"]
    difficulty = parsed["difficulty"]
    initial_offset = (M * VERCEL_K[M % 5]) % 36
    nonces = []
    prev_hash = None
    for i in range(count):
        if i == 0:
            expected_prefix = seed3[initial_offset:initial_offset + 4]
        else:
            offset = (M * VERCEL_K[(i - 1) % 5]) % difficulty
            expected_prefix = prev_hash[offset:offset + 4]
        nonce, prev_hash = _find_nonce(seed2, expected_prefix)
        nonces.append(nonce)
    return ";".join(nonces)


# ==============================================================================
# WAF Detection
# ==============================================================================

class WAFDetector:
    @staticmethod
    def detect(status_code: int, headers: dict, body: str, cookies: dict = None) -> str:
        h = {k.lower(): v for k, v in headers.items()}
        b = body.lower()
        c = {k.lower(): v for k, v in (cookies or {}).items()}

        for waf_type, sig in WAF_SIGNATURES.items():
            for header_key in sig.get("headers", []):
                if any(header_key in hk for hk in h):
                    return waf_type

            server_val = h.get("server", "")
            for srv_pattern in sig.get("server", []):
                if srv_pattern in server_val.lower():
                    return waf_type

            for cookie_key in sig.get("cookies", []):
                if any(cookie_key in ck for ck in c):
                    return waf_type

            for body_signal in sig.get("body", []):
                if body_signal in b:
                    return waf_type

        if "x-vercel-challenge" in b or "vercel" in b and "challenge" in b:
            return WAFType.VERCEL
        if "cloudflare" in b and any(s in b for s in ["challenge", "ray", "cdn"]):
            return WAFType.CLOUDFLARE
        if "incapsula" in b or "_incapsula_resource" in b:
            return WAFType.IMPERVA
        if "sucuri" in b and "cloudproxy" in b:
            return WAFType.SUCURI

        if status_code in (403, 503, 429):
            if any(s in b for s in ["just a moment", "checking your browser", "verify you are human",
                                      "enable javascript", "enable cookies"]):
                return WAFType.UNKNOWN

        return WAFType.NONE


# ==============================================================================
# WAFBypass
# ==============================================================================

class WAFBypass:
    def __init__(
        self,
        proxy: str = None,
        timeout: int = 30,
        default_profile: str = "chrome136",
        delay: tuple[float, float] = (0.5, 2.0),
        rotate_profiles: bool = True,
    ):
        if not HAS_CURL:
            print("[!] curl_cffi not installed. Install: pip install curl_cffi")
        if not HAS_CLOUDSCRAPER:
            print("[!] cloudscraper not installed. Install: pip install cloudscraper")
        self.proxy = proxy
        self.timeout = timeout
        self.default_profile = default_profile
        self.delay = delay
        self.rotate_profiles = rotate_profiles
        self.results: list[WAFResult] = []

    def _build_curl_session(self, profile_name: str = None) -> CurlSession:
        pname = profile_name or self.default_profile
        if pname not in BROWSER_PROFILES:
            pname = "chrome136"
        profile = BROWSER_PROFILES[pname]
        session = CurlSession(impersonate=profile["impersonate"], timeout=self.timeout)
        if self.proxy:
            session.proxies = {"all": self.proxy}
        session.headers.update({
            "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
            "accept-language": "en-US,en;q=0.9",
            "accept-encoding": "gzip, deflate, br",
            "cache-control": "no-cache",
            "pragma": "no-cache",
            "priority": "u=0, i",
            "sec-fetch-dest": "document",
            "sec-fetch-mode": "navigate",
            "sec-fetch-site": "none",
            "sec-fetch-user": "?1",
            "upgrade-insecure-requests": "1",
        })
        if profile["sec_ch_ua"]:
            session.headers["sec-ch-ua"] = profile["sec_ch_ua"]
            session.headers["sec-ch-ua-mobile"] = "?0"
            session.headers["sec-ch-ua-platform"] = profile["sec_ch_ua_platform"]
        return session

    def _random_delay(self, min_d=None, max_d=None):
        dmin = min_d if min_d is not None else self.delay[0]
        dmax = max_d if max_d is not None else self.delay[1]
        time.sleep(random.uniform(dmin, dmax))

    def _is_blocked(self, status_code: int, body: str, headers: dict) -> tuple[bool, str]:
        body_lower = body.lower()
        reasons = []
        if status_code in (403, 423, 429, 503):
            reasons.append(f"HTTP {status_code}")
        h = {k.lower(): v for k, v in headers.items()}
        if "x-vercel-challenge-token" in h:
            reasons.append("Vercel challenge token")
        if any(signal in body_lower for signal in BLOCK_SIGNALS):
            reasons.append("challenge page detected")
        return len(reasons) > 0, "; ".join(reasons) if reasons else ""

    def _probe(self, url: str, profile_name: str = None) -> tuple[WAFResult, str]:
        result = WAFResult(url=url, method_used="probe", profile_used=profile_name or self.default_profile)
        try:
            session = self._build_curl_session(profile_name)
            self._random_delay()
            resp = session.get(url, allow_redirects=True)
            result.status_code = resp.status_code
            result.headers = dict(resp.headers)
            result.body = resp.text
        except Exception as e:
            result.error = str(e)
            return result, WAFType.NONE
        waf = WAFDetector.detect(
            result.status_code, result.headers, result.body,
            cookies=dict(resp.cookies) if hasattr(resp, 'cookies') else None,
        )
        blocked, reason = self._is_blocked(result.status_code, result.body, result.headers)
        result.success = not blocked and result.status_code == 200
        result.bypassed = result.success
        if blocked:
            result.error = f"Blocked: {reason}"
        return result, waf

    # ======================================================================
    # Solvers
    # ======================================================================

    def _solve_vercel(self, url: str, profile_name: str = "chrome136") -> WAFResult:
        result = WAFResult(url=url, method_used="vercel_solver", profile_used=profile_name)
        try:
            session = self._build_curl_session(profile_name)
            self._random_delay()
            resp = session.get(url, allow_redirects=True)
            token = resp.headers.get("x-vercel-challenge-token")
            if not token and resp.status_code in (423, 403, 429):
                retry_profiles = ["chrome136", "chrome131", "firefox135", "safari18", "edge136"]
                for rp in retry_profiles:
                    self._random_delay(2.0, 5.0)
                    rs = self._build_curl_session(rp)
                    rr = rs.get(url, allow_redirects=True)
                    if rr.status_code == 200:
                        result.status_code = 200
                        result.headers = dict(rr.headers)
                        result.body = rr.text
                        result.method_used = f"rate_limit_retry ({rp})"
                        result.profile_used = rp
                        result.success = True
                        result.bypassed = True
                        return result
                    if rr.headers.get("x-vercel-challenge-token"):
                        token = rr.headers.get("x-vercel-challenge-token")
                        session = rs
                        resp = rr
                        break
                if not token:
                    result.status_code = resp.status_code
                    result.headers = dict(resp.headers)
                    result.body = resp.text
                    blocked, reason = self._is_blocked(resp.status_code, resp.text, dict(resp.headers))
                    result.success = not blocked and resp.status_code == 200
                    result.bypassed = result.success
                    if not result.bypassed:
                        result.error = f"No challenge token, all profiles blocked: {reason}"
                    return result

            if not token:
                result.status_code = resp.status_code
                result.headers = dict(resp.headers)
                result.body = resp.text
                blocked, reason = self._is_blocked(resp.status_code, resp.text, dict(resp.headers))
                result.success = not blocked and resp.status_code == 200
                result.bypassed = result.success
                if not result.bypassed:
                    result.error = f"No challenge token: {reason}"
                return result

            solution = _solve_vercel_challenge(token)
            if not solution:
                result.error = "Failed to solve Vercel challenge"
                return result

            parsed = urlparse(url)
            origin = f"{parsed.scheme}://{parsed.hostname}"
            old_headers = dict(session.headers)
            session.headers.update({
                "accept": "*/*",
                "origin": origin,
                "referer": f"{origin}/.well-known/vercel/security/static/challenge.v2.min.js",
                "sec-fetch-dest": "empty",
                "sec-fetch-mode": "cors",
                "sec-fetch-site": "same-origin",
                "x-vercel-challenge-solution": solution,
                "x-vercel-challenge-token": token,
                "x-vercel-challenge-version": "2",
            })
            session.post(
                f"{origin}/.well-known/vercel/security/request-challenge",
                allow_redirects=False,
            )
            session.headers.clear()
            session.headers.update(old_headers)

            retry = session.get(url, allow_redirects=True)
            result.status_code = retry.status_code
            result.headers = dict(retry.headers)
            result.body = retry.text
            blocked, reason = self._is_blocked(retry.status_code, retry.text, dict(retry.headers))
            result.success = not blocked and retry.status_code == 200
            result.bypassed = result.success
            if blocked:
                result.error = f"Blocked after solve: {reason}"
        except Exception as e:
            result.error = str(e)
        return result

    def _solve_cloudflare(self, url: str) -> WAFResult:
        result = WAFResult(url=url, method_used="cloudscraper", profile_used="cloudflare")
        try:
            if not HAS_CLOUDSCRAPER:
                result.error = "cloudscraper not installed (pip install cloudscraper)"
                return result
            scraper = cloudscraper.create_scraper(delay=self.delay[0])
            if self.proxy:
                scraper.proxies = {"http": self.proxy, "https": self.proxy}
            resp = scraper.get(url, timeout=self.timeout, allow_redirects=True)
            result.status_code = resp.status_code
            result.headers = dict(resp.headers)
            result.body = resp.text
            blocked, reason = self._is_blocked(resp.status_code, resp.text, dict(resp.headers))
            result.success = not blocked and resp.status_code == 200
            result.bypassed = result.success
            if blocked:
                result.error = f"Blocked: {reason}"
        except Exception as e:
            result.error = str(e)
        return result

    def _try_curl_profile(self, url: str, profile_name: str) -> WAFResult:
        result = WAFResult(url=url, method_used="curl_cffi", profile_used=profile_name)
        try:
            session = self._build_curl_session(profile_name)
            self._random_delay()
            resp = session.get(url, allow_redirects=True)
            result.status_code = resp.status_code
            result.headers = dict(resp.headers)
            result.body = resp.text
            blocked, reason = self._is_blocked(resp.status_code, resp.text, dict(resp.headers))
            result.success = not blocked and resp.status_code == 200
            result.bypassed = result.success
            if blocked:
                result.error = f"Blocked: {reason}"
        except Exception as e:
            result.error = str(e)
        return result

    def _try_proxy_rotate(self, url: str, profile_name: str = "chrome136") -> WAFResult:
        result = WAFResult(url=url, method_used="proxy+delay", profile_used=profile_name)
        try:
            session = self._build_curl_session(profile_name)
            self._random_delay(2.0, 5.0)
            resp = session.get(url, allow_redirects=True)
            result.status_code = resp.status_code
            result.headers = dict(resp.headers)
            result.body = resp.text
            blocked, reason = self._is_blocked(resp.status_code, resp.text, dict(resp.headers))
            result.success = not blocked and resp.status_code == 200
            result.bypassed = result.success
            if blocked:
                result.error = f"Blocked: {reason}"
        except Exception as e:
            result.error = str(e)
        return result

    # ======================================================================
    # Main bypass flow
    # ======================================================================

    def bypass(self, url: str) -> WAFResult:
        url = url.strip()
        if not url.startswith(("http://", "https://")):
            url = "https://" + url

        parsed = urlparse(url)
        if not parsed.hostname:
            return WAFResult(url=url, error="Invalid URL", success=False)

        print(f"\n[*] Target: {url}")
        print(f"[*] Host:   {parsed.hostname}")
        print(f"[*] Detecting WAF... ", end="")

        probe_result, waf_type = self._probe(url)
        self.results.append(probe_result)

        if waf_type == WAFType.NONE and probe_result.bypassed:
            print("none")
            print(f"[+] Site accessible directly [{probe_result.status_code}]")
            return probe_result

        waf_display = waf_type.upper()
        print(f"{waf_display}")

        if probe_result.bypassed and waf_type != WAFType.NONE:
            print(f"  Status: {probe_result.status_code}")
            print(f"  WAF detected ({waf_type}) but site is accessible without bypass")
            return probe_result

        print(f"  Status: {probe_result.status_code}")
        if probe_result.error:
            print(f"  Reason: {probe_result.error}")

        best_result: Optional[WAFResult] = probe_result

        if waf_type == WAFType.VERCEL:
            print(f"  -> Vercel solver... ", end="")
            r = self._solve_vercel(url)
            self.results.append(r)
            if r.bypassed:
                print(f"BYPASSED [{r.status_code}]")  ; best_result = r
            else:
                print(f"FAILED ({r.error})")
                if not r.bypassed:
                    for rp in ["chrome136", "chrome131", "firefox135", "safari18", "edge136"]:
                        print(f"  -> rate limit retry ({rp})... ", end="")
                        self._random_delay(2.0, 5.0)
                        rr = self._try_curl_profile(url, rp)
                        self.results.append(rr)
                        if rr.bypassed:
                            print(f"BYPASSED [{rr.status_code}]")  ; best_result = rr ; break
                        print(f"BLOCKED ({rr.error or f'HTTP {rr.status_code}'})")

        elif waf_type == WAFType.CLOUDFLARE:
            print(f"  -> cloudscraper... ", end="")
            r = self._solve_cloudflare(url)
            self.results.append(r)
            if r.bypassed:
                print(f"BYPASSED [{r.status_code}]")  ; best_result = r
            else:
                print(f"FAILED ({r.error})")

        elif waf_type == WAFType.AWS:
            profiles = ["chrome136", "chrome131", "firefox135", "safari18", "edge136"]
            for p in profiles:
                print(f"  -> AWS bypass ({p})... ", end="")
                self._random_delay(1.0, 3.0)
                r = self._try_curl_profile(url, p)
                self.results.append(r)
                if r.bypassed:
                    print(f"BYPASSED [{r.status_code}]")  ; best_result = r ; break
                print(f"BLOCKED ({r.error or f'HTTP {r.status_code}'})")

        elif waf_type == WAFType.AKAMAI:
            profiles = ["chrome136", "chrome131", "edge136"]
            for p in profiles:
                print(f"  -> Akamai bypass ({p})... ", end="")
                self._random_delay(1.0, 3.0)
                r = self._try_curl_profile(url, p)
                self.results.append(r)
                if r.bypassed:
                    print(f"BYPASSED [{r.status_code}]")  ; best_result = r ; break
                print(f"BLOCKED ({r.error or f'HTTP {r.status_code}'})")
            if not best_result or not best_result.bypassed:
                print(f"  -> Akamai slow proxy pass... ", end="")
                r = self._try_proxy_rotate(url)
                self.results.append(r)
                if r.bypassed:
                    print(f"BYPASSED [{r.status_code}]")  ; best_result = r
                else:
                    print(f"BLOCKED")

        elif waf_type in (WAFType.IMPERVA, WAFType.SUCURI):
            print(f"  -> cloudscraper... ", end="")
            r = self._solve_cloudflare(url)
            self.results.append(r)
            if r.bypassed:
                print(f"BYPASSED [{r.status_code}]")  ; best_result = r
            else:
                print(f"FAILED ({r.error})")
                for p in ["chrome136", "firefox135", "safari18"]:
                    print(f"  -> bypass ({p})... ", end="")
                    r2 = self._try_curl_profile(url, p)
                    self.results.append(r2)
                    if r2.bypassed:
                        print(f"BYPASSED [{r2.status_code}]")  ; best_result = r2 ; break
                    print(f"BLOCKED")

        elif waf_type == WAFType.F5:
            for p in ["chrome136", "firefox135"]:
                print(f"  -> F5 bypass ({p})... ", end="")
                r = self._try_curl_profile(url, p)
                self.results.append(r)
                if r.bypassed:
                    print(f"BYPASSED [{r.status_code}]")  ; best_result = r ; break
                print(f"BLOCKED ({r.error or f'HTTP {r.status_code}'})")

        elif waf_type == WAFType.MODSECURITY:
            print(f"  -> ModSecurity bypass (header manipulation)... ", end="")
            r = self._try_curl_profile(url, "chrome136")
            self.results.append(r)
            if r.bypassed:
                print(f"BYPASSED [{r.status_code}]")  ; best_result = r
            else:
                print(f"BLOCKED ({r.error or f'HTTP {r.status_code}'})")

        else:
            print(f"  -> Unhandled WAF, trying generic bypass...")
            for p in ["chrome136", "chrome131", "firefox135", "safari18", "edge136"]:
                print(f"    -> {p}... ", end="")
                r = self._try_curl_profile(url, p)
                self.results.append(r)
                if r.bypassed:
                    print(f"BYPASSED [{r.status_code}]")  ; best_result = r ; break
                print(f"BLOCKED ({r.error or f'HTTP {r.status_code}'})")
            if best_result and not best_result.bypassed:
                print(f"    -> cloudscraper (trial)... ", end="")
                r = self._solve_cloudflare(url)
                self.results.append(r)
                if r.bypassed:
                    print(f"BYPASSED [{r.status_code}]")  ; best_result = r
                else:
                    print(f"BLOCKED")
                if not best_result.bypassed:
                    print(f"    -> Vercel PoW solver... ", end="")
                    r = self._solve_vercel(url, "chrome136")
                    self.results.append(r)
                    if r.bypassed:
                        print(f"BYPASSED [{r.status_code}]")  ; best_result = r
                    else:
                        print(f"BLOCKED")

        print()
        if best_result and best_result.bypassed:
            print(f"[+] WAF BYPASSED using {best_result.profile_used} ({best_result.method_used})")
            print(f"[+] Status: {best_result.status_code}")
            print(f"[+] Response size: {len(best_result.body)} bytes")
            print(f"[+] Server: {best_result.headers.get('Server', 'N/A')}")
        elif best_result:
            print(f"[-] All methods blocked by WAF ({waf_type})")
            print(f"[-] Best result: HTTP {best_result.status_code}")
            if best_result.error:
                print(f"[-] {best_result.error}")
            print(f"[-] Tip: use a proxy or browser automation (Playwright/Selenium)")

        return best_result or WAFResult(url=url, success=False, error="All methods failed")


def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="WAF Bypass Tool — Auto-detect and bypass Vercel, Cloudflare, AWS, Akamai, Imperva, Sucuri, F5, and more",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--target", "-t", type=str, default=None, help="Target URL")
    parser.add_argument("--proxy", "-p", type=str, default=None, help="Proxy URL (e.g., http://127.0.0.1:8080)")
    parser.add_argument("--timeout", type=int, default=30, help="Request timeout in seconds")
    args = parser.parse_args()

    if not args.target:
        args.target = input("Enter target URL: ").strip()

    if not args.target:
        print("No target provided.", file=sys.stderr)
        sys.exit(1)

    bypasser = WAFBypass(proxy=args.proxy, timeout=args.timeout)
    result = bypasser.bypass(args.target)

    if result.bypassed and result.body:
        try:
            save = input("\nSave response body to file? (y/N): ").strip().lower()
            if save == "y":
                safe_name = re.sub(r'[^\w\-_.]', '_', urlparse(args.target).hostname or "output")
                fname = f"{safe_name}_response.html"
                with open(fname, "w", encoding="utf-8") as f:
                    f.write(result.body)
                print(f"Saved to {fname}")
        except (EOFError, OSError):
            pass

    return 0 if result.bypassed else 1


if __name__ == "__main__":
    raise SystemExit(main())
