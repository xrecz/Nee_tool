"""Security headers analysis.

Checks web hosts for missing or misconfigured HTTP security headers.
Generates findings for each missing header.
"""

from __future__ import annotations

import ssl
import urllib.request
import urllib.error

from nee_tool.core.models import Finding, HostInfo, ScanResult, Severity
from nee_tool.scanners.base import BaseScanner

# Headers to check and their expected presence/values
SECURITY_HEADERS = {
    "strict-transport-security": {
        "severity": Severity.HIGH,
        "title": "Fehlender HSTS Header",
        "recommendation": (
            "Strict-Transport-Security Header setzen: "
            "'Strict-Transport-Security: max-age=31536000; includeSubDomains'"
        ),
    },
    "content-security-policy": {
        "severity": Severity.MEDIUM,
        "title": "Fehlende Content Security Policy",
        "recommendation": (
            "Content-Security-Policy Header definieren. "
            "Mindestens: \"default-src 'self'\""
        ),
    },
    "x-content-type-options": {
        "severity": Severity.LOW,
        "title": "Fehlender X-Content-Type-Options Header",
        "recommendation": "Header setzen: 'X-Content-Type-Options: nosniff'",
    },
    "x-frame-options": {
        "severity": Severity.MEDIUM,
        "title": "Fehlender X-Frame-Options Header (Clickjacking)",
        "recommendation": "Header setzen: 'X-Frame-Options: DENY' oder 'SAMEORIGIN'",
    },
    "permissions-policy": {
        "severity": Severity.LOW,
        "title": "Fehlende Permissions-Policy",
        "recommendation": (
            "Permissions-Policy Header setzen um Browser-Features einzuschränken. "
            "Beispiel: 'Permissions-Policy: camera=(), microphone=(), geolocation=()'"
        ),
    },
    "referrer-policy": {
        "severity": Severity.LOW,
        "title": "Fehlende Referrer-Policy",
        "recommendation": "Header setzen: 'Referrer-Policy: strict-origin-when-cross-origin'",
    },
}

# Headers that should NOT be present (information disclosure)
BAD_HEADERS = {
    "server": {
        "severity": Severity.INFO,
        "title": "Server-Version in Header exponiert",
        "recommendation": "Server-Header entfernen oder auf generischen Wert setzen.",
    },
    "x-powered-by": {
        "severity": Severity.LOW,
        "title": "X-Powered-By Header exponiert Technologie",
        "recommendation": "X-Powered-By Header entfernen.",
    },
    "x-aspnet-version": {
        "severity": Severity.LOW,
        "title": "ASP.NET Version exponiert",
        "recommendation": "X-AspNet-Version Header entfernen (web.config: enableVersionHeader=false).",
    },
}


class SecurityHeadersScanner(BaseScanner):
    name = "security_headers"
    description = "Security-Header-Analyse"
    required_tools: list[str] = []

    def scan(self, target: str, previous_results: list[ScanResult]) -> ScanResult:
        # Find web hosts from previous results
        web_hosts: list[str] = []
        for prev in previous_results:
            for host in prev.hosts:
                if host.is_web:
                    web_hosts.append(host.hostname or host.ip)

        if not web_hosts:
            # Fallback: just check the target
            web_hosts = [target]

        all_findings: list[Finding] = []
        all_hosts: list[HostInfo] = []

        for host in web_hosts:
            headers, findings = self._check_host(host)
            all_findings.extend(findings)
            if headers:
                all_hosts.append(HostInfo(
                    hostname=host,
                    headers=headers,
                    is_web=True,
                ))

        return ScanResult(
            scanner_name=self.name,
            hosts=all_hosts,
            findings=all_findings,
        )

    def _check_host(self, host: str) -> tuple[dict[str, str], list[Finding]]:
        """Check security headers for a single host."""
        headers = self._fetch_headers(host)
        if not headers:
            return {}, []

        findings: list[Finding] = []
        header_lower = {k.lower(): v for k, v in headers.items()}

        # Check for missing security headers
        for header_name, info in SECURITY_HEADERS.items():
            if header_name not in header_lower:
                findings.append(Finding(
                    title=f"{info['title']} ({host})",
                    severity=info["severity"],
                    description=f"Der Header '{header_name}' fehlt auf {host}.",
                    evidence=f"Response Headers von {host} enthalten keinen '{header_name}' Header.",
                    recommendation=info["recommendation"],
                    tags=["headers", header_name],
                ))

        # Check for information disclosure headers
        for header_name, info in BAD_HEADERS.items():
            if header_name in header_lower:
                value = header_lower[header_name]
                findings.append(Finding(
                    title=f"{info['title']} ({host})",
                    severity=info["severity"],
                    description=f"Der Header '{header_name}: {value}' gibt Technologie-Informationen preis.",
                    evidence=f"{header_name}: {value}",
                    recommendation=info["recommendation"],
                    tags=["headers", "info-disclosure"],
                ))

        return headers, findings

    def _fetch_headers(self, host: str) -> dict[str, str]:
        """Fetch HTTP headers from a host."""
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        for scheme in ["https", "http"]:
            url = f"{scheme}://{host}"
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "Nee-Tool/0.1"}, method="HEAD")
                handler = urllib.request.HTTPSHandler(context=ctx) if scheme == "https" else urllib.request.HTTPHandler()
                opener = urllib.request.build_opener(handler)
                with opener.open(req, timeout=10) as resp:
                    return dict(resp.headers)
            except Exception:
                continue
        return {}
