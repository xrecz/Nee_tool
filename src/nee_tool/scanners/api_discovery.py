"""API endpoint discovery scanner.

Pure Python scanner that probes discovered web hosts for common
API paths and flags open/unauthenticated API endpoints.
"""

from __future__ import annotations

import ssl
import time
import urllib.error
import urllib.request
from urllib.parse import urlparse

from nee_tool.core.models import Finding, HostInfo, ScanResult, Severity
from nee_tool.scanners.base import BaseScanner, console

# API paths organized by category
API_PATHS = {
    "REST API": [
        "/api",
        "/api/v1",
        "/api/v2",
        "/api/v3",
        "/rest",
        "/rest/api",
        "/_api",
        "/admin/api",
        "/api/admin",
    ],
    "API Documentation": [
        "/swagger.json",
        "/swagger-ui.html",
        "/swagger-ui/",
        "/openapi.json",
        "/openapi.yaml",
        "/api-docs",
        "/api-docs/swagger.json",
        "/v2/api-docs",
        "/v3/api-docs",
        "/redoc",
        "/docs",
        "/docs/api",
    ],
    "GraphQL": [
        "/graphql",
        "/graphiql",
        "/graphql/console",
        "/graphql/playground",
        "/gql",
    ],
    "Health/Monitoring": [
        "/health",
        "/healthz",
        "/status",
        "/metrics",
        "/actuator",
        "/actuator/health",
        "/actuator/info",
        "/actuator/env",
        "/actuator/beans",
        "/actuator/mappings",
        "/actuator/configprops",
        "/_health",
        "/server-status",
        "/server-info",
    ],
    "Well-Known": [
        "/.well-known/openid-configuration",
        "/.well-known/security.txt",
        "/.well-known/change-password",
        "/.well-known/jwks.json",
    ],
    "CMS API": [
        "/wp-json/wp/v2",
        "/wp-json/wp/v2/users",
        "/wp-json/wp/v2/posts",
        "/wp-json/",
        "/jsonapi",
        "/jsonapi/node/article",
    ],
}

# Content-Type patterns that indicate API responses
API_CONTENT_TYPES = [
    "application/json",
    "application/xml",
    "application/graphql",
    "application/openapi",
    "application/swagger",
    "text/json",
    "text/xml",
]

# Rate limit: minimum delay between requests
RATE_LIMIT_DELAY = 0.3


class APIDiscoveryScanner(BaseScanner):
    name = "api_discovery"
    description = "API-Endpunkt-Erkennung (REST, GraphQL, Swagger)"
    required_tools: list[str] = []  # Pure Python

    def __init__(self, config):
        super().__init__(config)
        self._last_request: dict[str, float] = {}

    def _rate_limit(self, host: str) -> None:
        """Enforce rate limiting per host."""
        now = time.time()
        last = self._last_request.get(host, 0)
        wait = RATE_LIMIT_DELAY - (now - last)
        if wait > 0:
            time.sleep(wait)
        self._last_request[host] = time.time()

    def _probe(self, url: str) -> tuple[int, dict, str, int]:
        """Probe a URL and return (status, headers, body_preview, content_length)."""
        parsed = urlparse(url)
        self._rate_limit(parsed.hostname or "")

        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        req = urllib.request.Request(url, headers={
            "User-Agent": "TerraRecon/1.0 Security-Scanner",
            "Accept": "application/json, text/html, */*",
        })

        try:
            response = urllib.request.urlopen(req, timeout=10, context=ctx)
            headers = dict(response.headers)
            body = response.read(5000).decode("utf-8", errors="replace")
            content_length = int(headers.get("Content-Length", len(body)))
            return response.status, headers, body, content_length
        except urllib.error.HTTPError as e:
            headers = dict(e.headers) if e.headers else {}
            body = ""
            try:
                body = e.read(2000).decode("utf-8", errors="replace")
            except Exception:
                pass
            return e.code, headers, body, 0
        except Exception:
            return 0, {}, "", 0

    def _is_api_response(self, status: int, headers: dict, body: str) -> bool:
        """Determine if a response looks like an API endpoint."""
        if status == 0:
            return False

        content_type = headers.get("Content-Type", headers.get("content-type", "")).lower()

        # Check content type
        if any(ct in content_type for ct in API_CONTENT_TYPES):
            return True

        # Check body patterns
        body_stripped = body.strip()
        if body_stripped.startswith("{") or body_stripped.startswith("["):
            return True
        if body_stripped.startswith("<?xml") or body_stripped.startswith("<soap"):
            return True

        # Swagger/OpenAPI indicators
        if any(ind in body.lower() for ind in ["swagger", "openapi", "graphql", "graphiql"]):
            return True

        return False

    def _assess_severity(self, path: str, category: str, status: int, body: str) -> Severity:
        """Assess severity of an exposed API endpoint."""
        path_lower = path.lower()
        body_lower = body.lower()

        # Critical: actuator env/configprops (exposes secrets), user enumeration
        if any(p in path_lower for p in ["/actuator/env", "/actuator/configprops", "/users", "wp-json/wp/v2/users"]):
            return Severity.HIGH

        # High: full API docs, graphql playground
        if any(p in path_lower for p in ["/swagger", "/api-docs", "/graphiql", "/graphql/playground", "/openapi"]):
            return Severity.MEDIUM

        # Medium: general API endpoints
        if status == 200 and category in ("REST API", "GraphQL"):
            return Severity.MEDIUM

        # Low: health/monitoring endpoints
        if category in ("Health/Monitoring", "Well-Known"):
            return Severity.LOW

        return Severity.INFO

    def scan(self, target: str, previous_results: list[ScanResult]) -> ScanResult:
        web_hosts: set[str] = set()
        for prev in previous_results:
            for host in prev.hosts:
                if host.is_web:
                    web_hosts.add(host.hostname or host.ip)

        if not web_hosts:
            web_hosts = {target}

        findings: list[Finding] = []
        hosts_with_apis: set[str] = set()
        total_probes = 0
        total_paths = sum(len(paths) for paths in API_PATHS.values())

        console.print(f"    [dim]Prüfe {len(web_hosts)} Hosts × {total_paths} API-Pfade...[/dim]")

        for hostname in sorted(web_hosts):
            for scheme in ["https", "http"]:
                host_findings = []

                for category, paths in API_PATHS.items():
                    for path in paths:
                        url = f"{scheme}://{hostname}{path}"
                        total_probes += 1

                        status, headers, body, content_length = self._probe(url)

                        if status == 0:
                            continue

                        # Check if this is an actual API endpoint
                        is_api = self._is_api_response(status, headers, body)

                        if status == 200 and is_api:
                            severity = self._assess_severity(path, category, status, body)
                            content_type = headers.get("Content-Type", headers.get("content-type", ""))

                            # Check if authentication is required
                            auth_required = any(
                                h.lower() in headers
                                for h in ["WWW-Authenticate", "www-authenticate"]
                            )

                            description = (
                                f"Ein offener API-Endpunkt wurde unter {url} entdeckt "
                                f"(Kategorie: {category}). "
                            )
                            if not auth_required:
                                description += (
                                    "Der Endpunkt ist ohne Authentifizierung erreichbar "
                                    "und kann sensible Daten oder Funktionen exponieren."
                                )
                            else:
                                description += "Der Endpunkt erfordert Authentifizierung."

                            evidence_parts = [
                                f"URL: {url}",
                                f"Status: HTTP {status}",
                                f"Content-Type: {content_type}",
                                f"Content-Length: {content_length}",
                            ]
                            if body:
                                preview = body[:300].replace("\n", " ")
                                evidence_parts.append(f"Preview: {preview}")

                            host_findings.append(Finding(
                                title=f"API-Endpunkt: {path} ({hostname})",
                                severity=severity,
                                description=description,
                                evidence="\n".join(evidence_parts),
                                recommendation=(
                                    "1. API-Endpunkte nur mit Authentifizierung bereitstellen\n"
                                    "2. API-Dokumentation (Swagger/OpenAPI) nicht öffentlich exponieren\n"
                                    "3. Rate-Limiting und Input-Validierung implementieren\n"
                                    "4. Monitoring-Endpunkte (Actuator, Health) absichern"
                                ),
                                tags=["api-discovery", category.lower().replace(" ", "-"), "unauthenticated" if not auth_required else "authenticated"],
                            ))

                        elif status in (401, 403) and is_api:
                            # Protected but exists — note for recon
                            host_findings.append(Finding(
                                title=f"Geschützter API-Endpunkt: {path} ({hostname})",
                                severity=Severity.INFO,
                                description=f"API-Endpunkt {url} existiert, ist aber geschützt (HTTP {status}).",
                                evidence=f"URL: {url}\nStatus: HTTP {status}",
                                tags=["api-discovery", category.lower().replace(" ", "-"), "protected"],
                            ))

                if host_findings:
                    findings.extend(host_findings)
                    hosts_with_apis.add(hostname)
                    break  # One scheme worked

        console.print(f"    [dim]{total_probes} Probes, {len(findings)} API-Endpunkte gefunden[/dim]")

        return ScanResult(
            scanner_name=self.name,
            findings=findings,
            hosts=[HostInfo(hostname=h, is_web=True) for h in hosts_with_apis],
            data={"probes": total_probes, "endpoints_found": len(findings)},
        )
