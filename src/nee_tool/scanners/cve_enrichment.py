"""CVE enrichment scanner.

Queries the NIST NVD API for known CVEs based on technologies
and service versions detected by previous scanners (tech_detect,
portscan). Generates findings for software with known vulnerabilities.

Uses the public NVD API (no API key required, rate-limited to
5 requests per 30 seconds without key).
"""

from __future__ import annotations

import json
import re
import time
import urllib.error
import urllib.request
from urllib.parse import quote

from nee_tool.core.models import Finding, HostInfo, ScanResult, Severity
from nee_tool.scanners.base import BaseScanner, console

# NVD API base URL
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Map NVD CVSS v3 base score to severity
def _cvss_to_severity(score: float) -> Severity:
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    if score >= 0.1:
        return Severity.LOW
    return Severity.INFO


# Known CPE vendor/product mappings for common technologies
CPE_MAPPINGS: dict[str, tuple[str, str]] = {
    # Web servers
    "Apache": ("apache", "http_server"),
    "nginx": ("nginx", "nginx"),
    "IIS": ("microsoft", "internet_information_services"),
    # CMS
    "WordPress": ("wordpress", "wordpress"),
    "Joomla": ("joomla", "joomla\\!"),
    "Drupal": ("drupal", "drupal"),
    # Frameworks
    "jQuery": ("jquery", "jquery"),
    "Angular": ("google", "angular"),
    "React": ("facebook", "react"),
    "Vue.js": ("vuejs", "vue.js"),
    "Next.js": ("vercel", "next.js"),
    "Laravel": ("laravel", "laravel"),
    # Languages / runtimes
    "PHP": ("php", "php"),
    "ASP.NET": ("microsoft", "asp.net"),
    "Node.js": ("nodejs", "node.js"),
    # Other
    "OpenSSH": ("openbsd", "openssh"),
    "Cloudflare": ("cloudflare", "cloudflare"),
}

# Max CVEs to fetch per technology (keep reports manageable)
MAX_CVES_PER_TECH = 5


class CVEEnrichmentScanner(BaseScanner):
    name = "cve_enrichment"
    description = "CVE-Anreicherung (NVD/NIST API für erkannte Software)"
    required_tools: list[str] = []  # Pure Python, no external tools

    def scan(self, target: str, previous_results: list[ScanResult]) -> ScanResult:
        # Collect technologies and service versions from previous results
        tech_set: set[str] = set()
        service_versions: list[tuple[str, str, str]] = []  # (host, service, version)

        for prev in previous_results:
            for host in prev.hosts:
                for tech in host.technologies:
                    tech_set.add(tech)
                # Extract service versions from port scan
                for port in host.ports:
                    if port.service and port.version:
                        service_versions.append((
                            host.hostname or host.ip,
                            port.service,
                            port.version,
                        ))

        if not tech_set and not service_versions:
            console.print("    [dim]Keine Technologien/Versionen erkannt, überspringe CVE-Abfrage.[/dim]")
            return ScanResult(scanner_name=self.name)

        all_findings: list[Finding] = []

        # Query NVD for known technologies
        console.print(f"    [dim]Prüfe {len(tech_set)} Technologien + {len(service_versions)} Services gegen NVD...[/dim]")

        for tech in sorted(tech_set):
            if tech in CPE_MAPPINGS:
                vendor, product = CPE_MAPPINGS[tech]
                findings = self._query_nvd_keyword(tech, vendor, product)
                all_findings.extend(findings)

        # Query for specific service versions (more precise)
        seen_services: set[str] = set()
        for host, service, version in service_versions:
            key = f"{service}:{version}"
            if key in seen_services:
                continue
            seen_services.add(key)

            findings = self._query_nvd_version(host, service, version)
            all_findings.extend(findings)

        return ScanResult(
            scanner_name=self.name,
            findings=all_findings,
        )

    def _query_nvd_keyword(self, tech: str, vendor: str, product: str) -> list[Finding]:
        """Query NVD API by CPE keyword for a technology."""
        findings: list[Finding] = []

        # Use keywordSearch for broader matches
        params = f"?keywordSearch={quote(f'{vendor} {product}')}&resultsPerPage={MAX_CVES_PER_TECH}&keywordExactMatch"
        url = f"{NVD_API_URL}{params}"

        data = self._fetch_nvd(url)
        if not data:
            return findings

        for vuln in data.get("vulnerabilities", [])[:MAX_CVES_PER_TECH]:
            cve = vuln.get("cve", {})
            finding = self._cve_to_finding(cve, tech)
            if finding:
                findings.append(finding)

        return findings

    def _query_nvd_version(self, host: str, service: str, version: str) -> list[Finding]:
        """Query NVD for a specific service version."""
        findings: list[Finding] = []

        # Extract version number from nmap version string (e.g., "OpenSSH 8.9p1" -> "8.9")
        version_match = re.search(r'(\d+\.\d+(?:\.\d+)?)', version)
        if not version_match:
            return findings

        ver = version_match.group(1)
        search_term = f"{service} {ver}"

        params = f"?keywordSearch={quote(search_term)}&resultsPerPage={MAX_CVES_PER_TECH}"
        url = f"{NVD_API_URL}{params}"

        data = self._fetch_nvd(url)
        if not data:
            return findings

        for vuln in data.get("vulnerabilities", [])[:MAX_CVES_PER_TECH]:
            cve = vuln.get("cve", {})
            finding = self._cve_to_finding(cve, f"{service} {version}", host)
            if finding:
                findings.append(finding)

        return findings

    def _fetch_nvd(self, url: str) -> dict | None:
        """Fetch data from NVD API with rate limiting."""
        try:
            req = urllib.request.Request(url, headers={
                "User-Agent": "Nee-Tool/0.1",
                "Accept": "application/json",
            })
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = json.loads(resp.read().decode())

            # NVD rate limit: 5 requests per 30s without API key
            time.sleep(6.5)
            return data

        except urllib.error.HTTPError as e:
            if e.code == 403:
                console.print("    [yellow]NVD API Rate-Limit erreicht, warte 30s...[/yellow]")
                time.sleep(30)
                return self._fetch_nvd(url)  # Retry once
            console.print(f"    [dim]NVD API Fehler: HTTP {e.code}[/dim]")
            return None
        except Exception as e:
            console.print(f"    [dim]NVD API nicht erreichbar: {e}[/dim]")
            return None

    def _cve_to_finding(self, cve: dict, tech: str, host: str = "") -> Finding | None:
        """Convert a NVD CVE entry into a Finding."""
        cve_id = cve.get("id", "")
        if not cve_id:
            return None

        # Get description (prefer English)
        descriptions = cve.get("descriptions", [])
        desc = ""
        for d in descriptions:
            if d.get("lang") == "en":
                desc = d.get("value", "")
                break
        if not desc and descriptions:
            desc = descriptions[0].get("value", "")

        # Get CVSS score
        score = 0.0
        vector = ""
        metrics = cve.get("metrics", {})

        # Try CVSS v3.1 first, then v3.0, then v2
        for metric_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            metric_list = metrics.get(metric_key, [])
            if metric_list:
                cvss_data = metric_list[0].get("cvssData", {})
                score = cvss_data.get("baseScore", 0.0)
                vector = cvss_data.get("vectorString", "")
                break

        if score == 0.0:
            # Skip CVEs without a score (usually reserved/rejected)
            return None

        severity = _cvss_to_severity(score)

        # Build references
        references = []
        for ref in cve.get("references", [])[:3]:
            url = ref.get("url", "")
            if url:
                references.append(url)
        references.insert(0, f"https://nvd.nist.gov/vuln/detail/{cve_id}")

        title = f"{cve_id} — {tech}"
        if host:
            title = f"{cve_id} — {tech} ({host})"

        return Finding(
            title=title,
            severity=severity,
            description=desc[:500] if desc else f"Bekannte Schwachstelle in {tech}.",
            evidence=f"CVE: {cve_id}\nCVSS: {score} ({vector})\nSoftware: {tech}",
            recommendation=f"Prüfen ob die eingesetzte Version von {tech} betroffen ist. "
                          f"Update auf die neueste gepatchte Version durchführen.",
            references=references,
            tags=["cve", "nvd", cve_id] + ([f"CVSS: {score}"] if score else []),
        )
