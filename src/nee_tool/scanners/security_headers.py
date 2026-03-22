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

        # Validate header VALUES for weak configurations
        findings.extend(self._validate_header_values(host, header_lower))

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

    def _validate_header_values(self, host: str, headers: dict[str, str]) -> list[Finding]:
        """Validate that present security headers have secure values."""
        findings: list[Finding] = []

        # HSTS: Check max-age is sufficient (>= 6 months)
        hsts = headers.get("strict-transport-security", "")
        if hsts:
            import re
            max_age_match = re.search(r'max-age=(\d+)', hsts)
            if max_age_match:
                max_age = int(max_age_match.group(1))
                if max_age < 15768000:  # < 6 months
                    findings.append(Finding(
                        title=f"HSTS max-age zu niedrig ({host})",
                        severity=Severity.MEDIUM,
                        description=f"HSTS max-age ist {max_age}s ({max_age // 86400} Tage). "
                                    f"Empfohlen sind mindestens 6 Monate (15768000s).",
                        evidence=f"Strict-Transport-Security: {hsts}",
                        recommendation="max-age auf mindestens 15768000 (6 Monate) setzen, "
                                      "idealerweise 31536000 (1 Jahr).",
                        tags=["headers", "hsts"],
                    ))
            if "includesubdomains" not in hsts.lower():
                findings.append(Finding(
                    title=f"HSTS ohne includeSubDomains ({host})",
                    severity=Severity.LOW,
                    description="HSTS-Header enthält kein 'includeSubDomains' Direktiv.",
                    evidence=f"Strict-Transport-Security: {hsts}",
                    recommendation="'includeSubDomains' zum HSTS-Header hinzufügen.",
                    tags=["headers", "hsts"],
                ))

        # CSP: Check for unsafe directives
        csp = headers.get("content-security-policy", "")
        if csp:
            unsafe_directives = []
            if "'unsafe-inline'" in csp:
                unsafe_directives.append("unsafe-inline")
            if "'unsafe-eval'" in csp:
                unsafe_directives.append("unsafe-eval")
            if "data:" in csp and "img-src" not in csp.split("data:")[0].split(";")[-1]:
                # data: in default-src or script-src is risky
                unsafe_directives.append("data: URI")

            if unsafe_directives:
                findings.append(Finding(
                    title=f"CSP enthält unsichere Direktiven ({host})",
                    severity=Severity.MEDIUM,
                    description=f"Content-Security-Policy enthält: {', '.join(unsafe_directives)}. "
                                f"Dies schwächt den XSS-Schutz erheblich.",
                    evidence=f"Content-Security-Policy: {csp[:300]}",
                    recommendation="'unsafe-inline' und 'unsafe-eval' durch Nonces oder "
                                  "Hashes ersetzen. data: URIs einschränken.",
                    tags=["headers", "csp"],
                ))

            if "*" in csp.split(";")[0] if ";" in csp else "*" in csp:
                findings.append(Finding(
                    title=f"CSP mit Wildcard-Quelle ({host})",
                    severity=Severity.MEDIUM,
                    description="CSP enthält Wildcard (*), was den Schutz aushebelt.",
                    evidence=f"Content-Security-Policy: {csp[:300]}",
                    recommendation="Wildcard durch explizite Quellen ersetzen.",
                    tags=["headers", "csp"],
                ))

        # X-Frame-Options: Validate value
        xfo = headers.get("x-frame-options", "")
        if xfo:
            xfo_upper = xfo.upper().strip()
            if xfo_upper not in ("DENY", "SAMEORIGIN"):
                if xfo_upper.startswith("ALLOW-FROM"):
                    findings.append(Finding(
                        title=f"X-Frame-Options ALLOW-FROM veraltet ({host})",
                        severity=Severity.LOW,
                        description="ALLOW-FROM wird von modernen Browsern nicht unterstützt.",
                        evidence=f"X-Frame-Options: {xfo}",
                        recommendation="CSP frame-ancestors Direktiv verwenden statt ALLOW-FROM.",
                        tags=["headers", "x-frame-options"],
                    ))

        # Check for Access-Control-Allow-Origin wildcard
        cors = headers.get("access-control-allow-origin", "")
        if cors == "*":
            # Check if credentials are also allowed
            creds = headers.get("access-control-allow-credentials", "").lower()
            severity = Severity.HIGH if creds == "true" else Severity.MEDIUM
            findings.append(Finding(
                title=f"CORS Wildcard-Origin ({host})",
                severity=severity,
                description="Access-Control-Allow-Origin ist auf '*' gesetzt. "
                           + ("In Kombination mit Allow-Credentials ist dies besonders kritisch." if creds == "true" else ""),
                evidence=f"Access-Control-Allow-Origin: {cors}"
                        + (f"\nAccess-Control-Allow-Credentials: {creds}" if creds else ""),
                recommendation="Explizite Origin-Whitelist statt Wildcard verwenden.",
                tags=["headers", "cors"],
            ))

        return findings

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
