#!/usr/bin/env python3
"""
Covered On — Security Scanner
Standalone security assessment tool. Checks HTTPS, headers, cookies,
mixed content, DNS email records, server disclosure, CORS, and form security.
No API key needed — uses requests, ssl, socket, dnspython, and BeautifulSoup.
"""

import csv
import logging
import os
import re
import socket
import ssl
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urljoin, urlparse

import dns.resolver
import requests
from bs4 import BeautifulSoup

log = logging.getLogger("security_tool")

# ── Timeout defaults for network requests ──────────────────────────────────
REQUEST_TIMEOUT = 15  # seconds for HTTP requests
DNS_TIMEOUT = 5       # seconds for DNS lookups


@dataclass
class SecurityResult:
    """All findings from a single URL security scan."""

    url: str
    domain: str = ""

    # ── HTTPS & Redirect ──────────────────────────────────────────────────
    http_redirects_to_https: Optional[bool] = None
    redirect_chain: list = field(default_factory=list)
    cert_issuer: Optional[str] = None
    cert_expiry: Optional[str] = None        # ISO date string
    cert_days_remaining: Optional[int] = None
    cert_valid: Optional[bool] = None

    # ── Security Headers ──────────────────────────────────────────────────
    hsts: Optional[str] = None                # max-age=... value
    csp: Optional[str] = None                 # full policy string
    x_frame_options: Optional[str] = None
    x_content_type_options: Optional[str] = None
    referrer_policy: Optional[str] = None
    permissions_policy: Optional[str] = None

    # ── Cookie Security ──────────────────────────────────────────────────
    cookies: list = field(default_factory=list)  # [{name, secure, httponly, samesite}]

    # ── Mixed Content ─────────────────────────────────────────────────────
    mixed_content: list = field(default_factory=list)  # list of HTTP:// resource URLs

    # ── Email Security (DNS) ──────────────────────────────────────────────
    spf_record: Optional[str] = None
    dkim_records: list = field(default_factory=list)
    dmarc_record: Optional[str] = None

    # ── Server Info Disclosure ────────────────────────────────────────────
    server_header: Optional[str] = None
    x_powered_by: Optional[str] = None

    # ── CORS ──────────────────────────────────────────────────────────────
    cors_allow_origin: Optional[str] = None
    cors_allow_methods: Optional[str] = None
    cors_allow_credentials: Optional[str] = None

    # ── Form Security ─────────────────────────────────────────────────────
    insecure_forms: list = field(default_factory=list)  # [{action, method}]

    # ── Meta ──────────────────────────────────────────────────────────────
    error: Optional[str] = None
    findings_count: int = 0       # number of issues found
    risk_level: str = "low"       # low / medium / high / critical
    score: int = 100               # 100 = perfect, lower = more issues


class SecurityScanner:
    """Security assessment scanner for a single URL. No API key needed."""

    def __init__(
        self,
        timeout: int = REQUEST_TIMEOUT,
        dns_timeout: int = DNS_TIMEOUT,
        user_agent: str = "CoveredOn-SecurityScanner/1.0",
    ):
        self.timeout = timeout
        self.dns_timeout = dns_timeout
        self.user_agent = user_agent
        self.session = requests.Session()
        self.session.headers["User-Agent"] = self.user_agent
        # Don't follow redirects automatically — we want to inspect the chain
        self.session.max_redirects = 0
        self.results: list[SecurityResult] = []

    def analyze(self, urls: list[str]) -> list[SecurityResult]:
        """Run all security checks on a list of URLs."""
        self.results = []
        for url in urls:
            result = self._scan_url(url)
            self.results.append(result)
        return self.results

    def _scan_url(self, url: str) -> SecurityResult:
        """Run all security checks against a single URL."""
        # Normalize: ensure scheme is present
        if not url.startswith("http"):
            url = "https://" + url

        parsed = urlparse(url)
        domain = parsed.hostname or url
        result = SecurityResult(url=url, domain=domain)

        try:
            # Step 1: Check HTTP→HTTPS redirect
            self._check_https_redirect(result)

            # Step 2: Fetch the HTTPS page for header/cookie/content checks
            resp = self._fetch_https(result)
            if resp is None:
                return result  # fatal — can't proceed

            # Step 3: Check security headers from response
            self._check_security_headers(result, resp)

            # Step 4: Check cookie security
            self._check_cookie_security(result, resp)

            # Step 5: Check mixed content (if page is HTTPS)
            self._check_mixed_content(result, resp)

            # Step 6: Check DNS email records
            self._check_dns_email(result)

            # Step 7: Check server info disclosure
            self._check_server_disclosure(result, resp)

            # Step 8: Check CORS headers
            self._check_cors(result, resp)

            # Step 9: Check form security
            self._check_form_security(result, resp)

            # Compute score & risk level
            self._compute_score(result)

        except requests.exceptions.Timeout:
            result.error = f"Request timed out after {self.timeout}s"
            log.warning(f"Timeout for {url}")
        except requests.exceptions.ConnectionError as e:
            result.error = f"Connection failed: {e}"
            log.warning(f"Connection error for {url}: {e}")
        except Exception as e:
            result.error = str(e)[:300]
            log.warning(f"Unexpected error for {url}: {e}")

        return result

    # ── Individual Checks ──────────────────────────────────────────────────

    def _check_https_redirect(self, result: SecurityResult):
        """Check if HTTP redirects to HTTPS, and inspect the SSL certificate."""
        domain = result.domain

        # Try HTTP first to see if it redirects to HTTPS
        http_url = f"http://{domain}"
        try:
            # We want to follow redirects manually to inspect the chain
            r = requests.get(
                http_url,
                timeout=self.timeout,
                headers={"User-Agent": self.user_agent},
                allow_redirects=True,
            )
            # Record whether we ended up at HTTPS
            final_scheme = urlparse(r.url).scheme
            result.http_redirects_to_https = final_scheme == "https"

            # Build redirect chain from history
            chain = []
            for hist in r.history:
                chain.append({"from": hist.url, "to": None, "status": hist.status_code})
            if r.history:
                chain[-1]["to"] = r.url
            result.redirect_chain = chain
        except (requests.exceptions.Timeout, requests.exceptions.ConnectionError) as e:
            log.debug(f"HTTP redirect check failed for {domain}: {e}")
            result.http_redirects_to_https = False
        except Exception as e:
            log.debug(f"HTTP redirect check error for {domain}: {e}")

        # Get SSL certificate info
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    if cert is None:
                        result.cert_valid = False
                        return

                    # Issuer
                    issuer_parts = []
                    for field in cert.get("issuer", []):  # type: ignore[union-attr]
                        for key, val in field:
                            if key == "organizationName":
                                issuer_parts.append(val)
                    result.cert_issuer = ", ".join(issuer_parts) if issuer_parts else "Unknown"

                    # Expiry
                    not_after = cert.get("notAfter", "")
                    if not_after and isinstance(not_after, str):
                        # Parse the ASN.1 UTC time: 'Jul 25 23:59:59 2025 GMT'
                        try:
                            expiry = datetime.strptime(
                                not_after, "%b %d %H:%M:%S %Y %Z"
                            ).replace(tzinfo=timezone.utc)
                        except ValueError:
                            # Some certs use different format
                            try:
                                expiry = datetime.strptime(
                                    not_after, "%b %d %H:%M:%S %Y GMT"
                                ).replace(tzinfo=timezone.utc)
                            except ValueError:
                                expiry = None

                        if expiry:
                            result.cert_expiry = expiry.strftime("%Y-%m-%d")
                            delta = expiry - datetime.now(timezone.utc)
                            result.cert_days_remaining = delta.days
                            result.cert_valid = delta.days > 0

                    # Subject Alternative Names are in cert["subjectAltName"]
        except (socket.timeout, socket.gaierror, ConnectionRefusedError) as e:
            log.debug(f"SSL cert check failed for {domain}: {e}")
            result.cert_valid = False
        except ssl.SSLError as e:
            log.debug(f"SSL error for {domain}: {e}")
            result.cert_valid = False
        except Exception as e:
            log.debug(f"Cert check error for {domain}: {e}")

    def _fetch_https(self, result: SecurityResult) -> Optional[requests.Response]:
        """Fetch the HTTPS page. Returns None on failure."""
        https_url = f"https://{result.domain}"
        try:
            resp = requests.get(
                https_url,
                timeout=self.timeout,
                headers={"User-Agent": self.user_agent},
            )
            resp.raise_for_status()
            # Update URL in case of redirect
            result.url = resp.url
            result.domain = urlparse(resp.url).hostname or result.domain
            return resp
        except requests.exceptions.SSLError as e:
            result.error = f"SSL verification failed: {e}"
            log.warning(f"SSL error for {https_url}: {e}")
            return None
        except requests.exceptions.Timeout:
            result.error = f"HTTPS request timed out after {self.timeout}s"
            log.warning(f"HTTPS timeout for {https_url}")
            return None
        except requests.exceptions.ConnectionError as e:
            result.error = f"HTTPS connection failed: {e}"
            log.warning(f"HTTPS connection error for {https_url}: {e}")
            return None
        except requests.exceptions.HTTPError as e:
            # Still return the response for header checks, even on 4xx/5xx
            return e.response
        except Exception as e:
            result.error = f"HTTPS fetch error: {e}"
            return None

    def _check_security_headers(self, result: SecurityResult, resp: requests.Response):
        """Extract security-related response headers."""
        headers = resp.headers

        # HSTS — Strict-Transport-Security
        result.hsts = headers.get("Strict-Transport-Security", "").strip() or None

        # CSP — Content-Security-Policy (prefer over X-Content-Security-Policy)
        result.csp = headers.get("Content-Security-Policy", "").strip() or None

        # X-Frame-Options
        result.x_frame_options = headers.get("X-Frame-Options", "").strip() or None

        # X-Content-Type-Options
        result.x_content_type_options = headers.get("X-Content-Type-Options", "").strip() or None

        # Referrer-Policy
        result.referrer_policy = headers.get("Referrer-Policy", "").strip() or None

        # Permissions-Policy (new name) or Feature-Policy (legacy)
        result.permissions_policy = (
            headers.get("Permissions-Policy", "").strip()
            or headers.get("Feature-Policy", "").strip()
            or None
        )

    def _check_cookie_security(self, result: SecurityResult, resp: requests.Response):
        """Inspect Set-Cookie headers for security flags."""
        raw_cookies = resp.headers.get("Set-Cookie", "")
        if not raw_cookies:
            return
        # If multiple Set-Cookie headers, requests joins them with comma+space.
        # We need to split carefully.
        cookie_headers = resp.raw.headers.getlist("Set-Cookie") if hasattr(resp.raw, "headers") else []
        if not cookie_headers:
            # Fallback: split the joined header
            cookie_headers = [c.strip() for c in raw_cookies.split("\n") if c.strip()]

        for cookie_str in cookie_headers:
            name = cookie_str.split("=", 1)[0].strip()
            lower = cookie_str.lower()
            result.cookies.append({
                "name": name,
                "secure": "secure" in lower,
                "httponly": "httponly" in lower,
                "samesite": self._extract_samesite(cookie_str),
            })

    @staticmethod
    def _extract_samesite(cookie_str: str) -> Optional[str]:
        """Extract SameSite value from a Set-Cookie string."""
        m = re.search(r"SameSite\s*=\s*(\w+)", cookie_str, re.IGNORECASE)
        if m:
            val = m.group(1).capitalize()
            # Normalize: Lax, Strict, None
            if val.lower() == "strict":
                return "Strict"
            elif val.lower() == "none":
                return "None"
            return val
        return None

    def _check_mixed_content(self, result: SecurityResult, resp: requests.Response):
        """Scan page content for HTTP:// resources loaded on an HTTPS page."""
        # Only meaningful on HTTPS pages
        if not resp.url.startswith("https://"):
            return

        try:
            soup = BeautifulSoup(resp.text, "html.parser")
        except Exception:
            return

        # Tags to check: img src, script src, link href (stylesheet), video/audio src,
        # source src, iframe src, object data, embed src
        checks = {
            "img": "src",
            "script": "src",
            "link": "href",       # stylesheets
            "video": "src",
            "audio": "src",
            "source": "src",
            "iframe": "src",
            "object": "data",
            "embed": "src",
        }

        found = set()  # deduplicate by URL
        for tag_name, attr in checks.items():
            for tag in soup.find_all(tag_name):
                src = tag.get(attr)
                if src:
                    src_str = str(src) if not isinstance(src, str) else src
                    if src_str.lower().startswith("http://"):
                        full_url = urljoin(resp.url, src_str)
                        found.add(full_url)

        result.mixed_content = sorted(found)

    def _check_dns_email(self, result: SecurityResult):
        """Look up SPF, DKIM, and DMARC DNS records for the domain."""
        domain = result.domain

        # ── SPF ─────────────────────────────────────────────────────────
        try:
            answers = dns.resolver.resolve(domain, "TXT", lifetime=self.dns_timeout)
            for rdata in answers:
                txt = "".join(s.decode("utf-8") if isinstance(s, bytes) else s for s in rdata.strings)
                if txt.startswith("v=spf1"):
                    result.spf_record = txt
                    break
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.Timeout,
                dns.resolver.NoNameservers, dns.exception.DNSException) as e:
            log.debug(f"SPF lookup failed for {domain}: {e}")
        except Exception as e:
            log.debug(f"SPF lookup error for {domain}: {e}")

        # ── DKIM ────────────────────────────────────────────────────────
        # Common selectors — not exhaustive, but covers most setups
        dkim_selectors = ["default", "google", "selector1", "selector2", "dkim", "mail"]
        for selector in dkim_selectors:
            try:
                dkim_domain = f"{selector}._domainkey.{domain}"
                answers = dns.resolver.resolve(dkim_domain, "TXT", lifetime=self.dns_timeout)
                for rdata in answers:
                    txt = "".join(
                        s.decode("utf-8") if isinstance(s, bytes) else s for s in rdata.strings
                    )
                    if "v=DKIM1" in txt:
                        result.dkim_records.append({"selector": selector, "record": txt})
            except Exception:
                pass  # Selector doesn't exist — normal

        # ── DMARC ───────────────────────────────────────────────────────
        try:
            dmarc_domain = f"_dmarc.{domain}"
            answers = dns.resolver.resolve(dmarc_domain, "TXT", lifetime=self.dns_timeout)
            for rdata in answers:
                txt = "".join(s.decode("utf-8") if isinstance(s, bytes) else s for s in rdata.strings)
                if txt.startswith("v=DMARC1"):
                    result.dmarc_record = txt
                    break
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.Timeout,
                dns.resolver.NoNameservers, dns.exception.DNSException) as e:
            log.debug(f"DMARC lookup failed for {domain}: {e}")
        except Exception as e:
            log.debug(f"DMARC lookup error for {domain}: {e}")

    def _check_server_disclosure(self, result: SecurityResult, resp: requests.Response):
        """Check for Server and X-Powered-By headers that leak tech stack info."""
        result.server_header = resp.headers.get("Server", "").strip() or None
        result.x_powered_by = resp.headers.get("X-Powered-By", "").strip() or None

    def _check_cors(self, result: SecurityResult, resp: requests.Response):
        """Check CORS-related response headers."""
        headers = resp.headers
        result.cors_allow_origin = headers.get("Access-Control-Allow-Origin", "").strip() or None
        result.cors_allow_methods = headers.get("Access-Control-Allow-Methods", "").strip() or None
        result.cors_allow_credentials = headers.get("Access-Control-Allow-Credentials", "").strip() or None

    def _check_form_security(self, result: SecurityResult, resp: requests.Response):
        """Check if forms submit to HTTPS URLs."""
        try:
            soup = BeautifulSoup(resp.text, "html.parser")
        except Exception:
            return

        for form in soup.find_all("form"):
            action = form.get("action")
            method_raw = form.get("method")
            action_str: str = str(action).strip() if action else ""
            method = str(method_raw).upper() if method_raw else "GET"

            # Resolve relative URLs
            if action_str:
                full_action = urljoin(resp.url, action_str)
            else:
                full_action = resp.url

            # Check if the form action URL is HTTP (not HTTPS)
            parsed = urlparse(full_action)
            if parsed.scheme == "http":
                result.insecure_forms.append({
                    "action": full_action,
                    "method": method,
                })

    def _compute_score(self, result: SecurityResult):
        """Compute a security score and risk level from the findings."""
        issues = 0
        total_checks = 0

        # HTTPS redirect (10 pts)
        total_checks += 1
        if result.http_redirects_to_https is False:
            issues += 1

        # Cert valid (10 pts)
        total_checks += 1
        if result.cert_valid is False:
            issues += 1

        # HSTS present (10 pts)
        total_checks += 1
        if not result.hsts:
            issues += 1

        # CSP present (10 pts)
        total_checks += 1
        if not result.csp:
            issues += 1

        # X-Frame-Options present (5 pts)
        total_checks += 1
        if not result.x_frame_options:
            issues += 1

        # X-Content-Type-Options present (5 pts)
        total_checks += 1
        if not result.x_content_type_options:
            issues += 1

        # Referrer-Policy present (5 pts)
        total_checks += 1
        if not result.referrer_policy:
            issues += 1

        # Mixed content found (15 pts)
        total_checks += 1
        if result.mixed_content:
            issues += 1

        # SPF present (10 pts)
        total_checks += 1
        if not result.spf_record:
            issues += 1

        # DMARC present (10 pts)
        total_checks += 1
        if not result.dmarc_record:
            issues += 1

        # DKIM present (5 pts)
        total_checks += 1
        if not result.dkim_records:
            issues += 1

        # Server header leaking info (5 pts)
        total_checks += 1
        if result.server_header:
            issues += 1

        # Cookie security (each insecure cookie counts)
        for cookie in result.cookies:
            total_checks += 1
            if not cookie["secure"] or not cookie["httponly"] or not cookie["samesite"]:
                issues += 1
        if not result.cookies:
            # No cookies = no cookie issues (neutral)
            pass

        # Insecure forms (10 pts)
        total_checks += 1
        if result.insecure_forms:
            issues += 1

        # CORS — permissive ACAO (5 pts)
        total_checks += 1
        if result.cors_allow_origin == "*":
            issues += 1

        # Permissions-Policy present (5 pts)
        total_checks += 1
        if not result.permissions_policy:
            issues += 1

        result.findings_count = issues

        # Score out of 100
        if total_checks > 0:
            result.score = max(0, 100 - int((issues / total_checks) * 100))
        else:
            result.score = 0

        # Risk level
        if result.score >= 90:
            result.risk_level = "low"
        elif result.score >= 70:
            result.risk_level = "medium"
        elif result.score >= 50:
            result.risk_level = "high"
        else:
            result.risk_level = "critical"

    # ── CSV Export ─────────────────────────────────────────────────────────

    def export_csv(self, output_dir: str):
        """Export all security results to CSV files."""
        os.makedirs(output_dir, exist_ok=True)

        # security-headers.csv
        self._export_headers(output_dir)

        # security-cert.csv
        self._export_cert(output_dir)

        # security-mixed-content.csv
        self._export_mixed_content(output_dir)

        # security-dns.csv
        self._export_dns(output_dir)

        # security-cookies.csv
        self._export_cookies(output_dir)

        # security-summary.csv
        self._export_summary(output_dir)

        log.info(f"Security results exported to {output_dir}")

    def _export_headers(self, output_dir: str):
        path = os.path.join(output_dir, "security-headers.csv")
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow([
                "URL", "HSTS", "CSP", "X-Frame-Options",
                "X-Content-Type-Options", "Referrer-Policy", "Permissions-Policy",
            ])
            for r in self.results:
                w.writerow([
                    r.url,
                    r.hsts or "",
                    r.csp or "",
                    r.x_frame_options or "",
                    r.x_content_type_options or "",
                    r.referrer_policy or "",
                    r.permissions_policy or "",
                ])

    def _export_cert(self, output_dir: str):
        path = os.path.join(output_dir, "security-cert.csv")
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow([
                "URL", "HTTP→HTTPS", "Cert Issuer", "Cert Expiry",
                "Days Remaining", "Cert Valid",
            ])
            for r in self.results:
                w.writerow([
                    r.url,
                    "Yes" if r.http_redirects_to_https else ("No" if r.http_redirects_to_https is False else "Unknown"),
                    r.cert_issuer or "",
                    r.cert_expiry or "",
                    r.cert_days_remaining if r.cert_days_remaining is not None else "",
                    "Yes" if r.cert_valid else ("No" if r.cert_valid is False else "Unknown"),
                ])

    def _export_mixed_content(self, output_dir: str):
        path = os.path.join(output_dir, "security-mixed-content.csv")
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["URL", "HTTP Resource"])
            for r in self.results:
                if r.mixed_content:
                    for resource in r.mixed_content:
                        w.writerow([r.url, resource])
                else:
                    w.writerow([r.url, ""])

    def _export_dns(self, output_dir: str):
        path = os.path.join(output_dir, "security-dns.csv")
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["URL", "SPF Record", "DKIM Records", "DMARC Record"])
            for r in self.results:
                dkim_str = "; ".join(
                    f"{d['selector']}: {d['record'][:100]}" for d in r.dkim_records
                )
                w.writerow([
                    r.url,
                    r.spf_record or "",
                    dkim_str or "",
                    r.dmarc_record or "",
                ])

    def _export_cookies(self, output_dir: str):
        path = os.path.join(output_dir, "security-cookies.csv")
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["URL", "Cookie Name", "Secure", "HttpOnly", "SameSite"])
            for r in self.results:
                if r.cookies:
                    for c in r.cookies:
                        w.writerow([
                            r.url,
                            c["name"],
                            "Yes" if c["secure"] else "No",
                            "Yes" if c["httponly"] else "No",
                            c["samesite"] or "",
                        ])
                else:
                    w.writerow([r.url, "", "", "", ""])

    def _export_summary(self, output_dir: str):
        path = os.path.join(output_dir, "security-summary.csv")
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow([
                "URL", "Score", "Risk Level", "Findings", "Error",
                "HTTP→HTTPS", "Cert Valid", "HSTS", "CSP",
                "Mixed Content Items", "SPF", "DKIM Selectors", "DMARC",
            ])
            for r in self.results:
                w.writerow([
                    r.url,
                    r.score,
                    r.risk_level,
                    r.findings_count,
                    r.error or "",
                    "Yes" if r.http_redirects_to_https else ("No" if r.http_redirects_to_https is False else "?"),
                    "Yes" if r.cert_valid else ("No" if r.cert_valid is False else "?"),
                    "Yes" if r.hsts else "No",
                    "Yes" if r.csp else "No",
                    len(r.mixed_content),
                    "Yes" if r.spf_record else "No",
                    len(r.dkim_records),
                    "Yes" if r.dmarc_record else "No",
                ])


# ─── CLI ────────────────────────────────────────────────────────────────────

def main():
    import argparse

    parser = argparse.ArgumentParser(description="Covered On Security Scanner")
    parser.add_argument("url", help="URL to scan for security issues")
    parser.add_argument("--output", "-o", default="./security-output", help="Output directory for CSV files")
    parser.add_argument("--timeout", "-t", type=int, default=REQUEST_TIMEOUT, help="HTTP request timeout (seconds)")
    args = parser.parse_args()

    scanner = SecurityScanner(timeout=args.timeout)
    results = scanner.analyze([args.url])
    scanner.export_csv(args.output)

    # Print summary
    print(f"\n✓ Security scan complete: {args.url}")
    print(f"  Output: {args.output}")
    for r in results:
        if r.error:
            print(f"  ⚠ ERROR: {r.error}")
        else:
            print(f"  Score: {r.score}/100 | Risk: {r.risk_level} | Findings: {r.findings_count}")
            print(f"  HTTPS redirect: {'Yes' if r.http_redirects_to_https else 'No'}")
            print(f"  Cert valid: {'Yes' if r.cert_valid else 'No'} (expires: {r.cert_expiry or 'unknown'})")
            print(f"  HSTS: {'Present' if r.hsts else 'Missing'}")
            print(f"  CSP: {'Present' if r.csp else 'Missing'}")
            print(f"  Mixed content: {len(r.mixed_content)} HTTP resources")
            print(f"  SPF: {'Present' if r.spf_record else 'Missing'}")
            print(f"  DKIM: {len(r.dkim_records)} selector(s)")
            print(f"  DMARC: {'Present' if r.dmarc_record else 'Missing'}")
            print(f"  Server disclosure: {'Yes' if r.server_header else 'None'}")
            print(f"  Insecure forms: {len(r.insecure_forms)}")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    main()