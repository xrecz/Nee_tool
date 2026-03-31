"""PDF Report Generator.

Takes a Project with scan results and generates a professional
PDF pentest report using HTML templates and WeasyPrint.

Features:
- Auto-generated executive summary with risk rating
- CVSS score enrichment (from NVD API for CVE findings)
- Severity breakdown and top findings
"""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from datetime import datetime
from pathlib import Path

from jinja2 import Environment, FileSystemLoader

from nee_tool.core.models import Finding, Project, Severity
from nee_tool.report.cvss import calculate as cvss_calculate

TEMPLATE_DIR = Path(__file__).parent / "templates"

# Severity sort order
SEVERITY_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]

# Cache for NVD lookups
_nvd_cache: dict[str, dict] = {}


def _count_findings(findings: list[Finding]) -> dict[str, int]:
    """Count findings by severity."""
    counts = {s.value: 0 for s in Severity}
    for f in findings:
        counts[f.severity.value] += 1
    return counts


def _extract_cve_ids(finding: Finding) -> list[str]:
    """Extract CVE IDs from a finding's tags and description."""
    cve_pattern = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
    sources = [finding.title, finding.description, finding.evidence]
    sources.extend(finding.tags)
    sources.extend(finding.references)

    cves = set()
    for text in sources:
        cves.update(cve_pattern.findall(text.upper()))
    return sorted(cves)


def _fetch_nvd_cvss(cve_id: str, api_key: str = "") -> dict | None:
    """Fetch CVSS score from NVD API for a CVE ID."""
    if cve_id in _nvd_cache:
        return _nvd_cache[cve_id]

    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    headers = {"User-Agent": "TerraRecon/1.0"}
    if api_key:
        headers["apiKey"] = api_key

    req = urllib.request.Request(url, headers=headers)
    try:
        response = urllib.request.urlopen(req, timeout=10)
        data = json.loads(response.read().decode())
        vulnerabilities = data.get("vulnerabilities", [])
        if vulnerabilities:
            cve_data = vulnerabilities[0].get("cve", {})
            metrics = cve_data.get("metrics", {})

            # Try CVSS 3.1 first, then 3.0, then 2.0
            cvss_data = None
            for version in ["cvssMetricV31", "cvssMetricV30"]:
                if version in metrics:
                    cvss_list = metrics[version]
                    if cvss_list:
                        cvss_data = cvss_list[0].get("cvssData", {})
                        break

            if cvss_data:
                result = {
                    "score": cvss_data.get("baseScore", 0),
                    "vector": cvss_data.get("vectorString", ""),
                    "severity": cvss_data.get("baseSeverity", ""),
                }
                _nvd_cache[cve_id] = result
                return result
    except Exception:
        pass

    _nvd_cache[cve_id] = None
    return None


def _extract_cvss_from_tags(finding: Finding) -> dict | None:
    """Extract CVSS info from finding tags (from templates or nuclei)."""
    for tag in finding.tags:
        if tag.startswith("cvss_vector:"):
            vector = tag[len("cvss_vector:"):]
            try:
                result = cvss_calculate(vector)
                return {"score": result.score, "vector": result.vector, "severity": result.severity.value}
            except Exception:
                pass
        if tag.startswith("CVSS:") or tag.startswith("Vector: CVSS:"):
            vector = tag.replace("Vector: ", "")
            try:
                result = cvss_calculate(vector)
                return {"score": result.score, "vector": result.vector, "severity": result.severity.value}
            except Exception:
                pass
        if tag.startswith("CVSS: "):
            try:
                score = float(tag.split(": ")[1])
                return {"score": score, "vector": "", "severity": ""}
            except (ValueError, IndexError):
                pass
    return None


def enrich_findings_with_cvss(findings: list[Finding], api_key: str = "") -> dict[int, dict]:
    """Enrich findings with CVSS scores. Returns mapping of finding index to CVSS data."""
    cvss_map: dict[int, dict] = {}

    for i, finding in enumerate(findings):
        # First check tags for embedded CVSS vector
        cvss_data = _extract_cvss_from_tags(finding)
        if cvss_data:
            cvss_map[i] = cvss_data
            continue

        # Then try NVD lookup for CVE IDs
        cve_ids = _extract_cve_ids(finding)
        if cve_ids:
            for cve_id in cve_ids:
                nvd_data = _fetch_nvd_cvss(cve_id, api_key)
                if nvd_data:
                    cvss_map[i] = nvd_data
                    break

    return cvss_map


def _determine_risk_rating(counts: dict[str, int]) -> tuple[str, str, str]:
    """Determine overall risk rating. Returns (rating, color, description)."""
    if counts.get("critical", 0) > 0:
        return (
            "KRITISCH",
            "#dc3545",
            "Es wurden kritische Schwachstellen identifiziert, die eine sofortige "
            "Ausnutzung ermöglichen und maximalen Schaden verursachen können.",
        )
    elif counts.get("high", 0) > 0:
        return (
            "HOCH",
            "#e67e22",
            "Es wurden Schwachstellen mit hohem Risiko identifiziert, die zeitnah "
            "behoben werden sollten, um erheblichen Schaden zu verhindern.",
        )
    elif counts.get("medium", 0) > 0:
        return (
            "MITTEL",
            "#f39c12",
            "Es wurden Schwachstellen mit moderatem Risiko gefunden. Eine Behebung "
            "wird empfohlen, um die Angriffsfläche zu reduzieren.",
        )
    elif counts.get("low", 0) > 0:
        return (
            "NIEDRIG",
            "#3498db",
            "Es wurden kleinere Schwachstellen identifiziert. Die Behebung kann "
            "bei Gelegenheit erfolgen.",
        )
    else:
        return (
            "INFO",
            "#95a5a6",
            "Es wurden keine sicherheitsrelevanten Schwachstellen identifiziert. "
            "Nur informative Beobachtungen.",
        )


def _generate_recommendations(findings: list[Finding]) -> list[str]:
    """Auto-generate recommendations based on finding categories."""
    recs = []
    tags_found = set()
    for f in findings:
        tags_found.update(t.lower() for t in f.tags)

    if any(t in tags_found for t in ["injection", "sqli", "rce"]):
        recs.append("Input-Validierung und Prepared Statements für alle Benutzereingaben implementieren")
    if any(t in tags_found for t in ["xss"]):
        recs.append("Output-Encoding und Content Security Policy (CSP) implementieren")
    if any(t in tags_found for t in ["default-credentials", "credentials"]):
        recs.append("Alle Standard-Zugangsdaten ändern und starke Passwort-Richtlinien durchsetzen")
    if any(t in tags_found for t in ["ssl", "tls-version", "certificate"]):
        recs.append("TLS-Konfiguration härten: TLS 1.2+ erzwingen, Zertifikate erneuern")
    if any(t in tags_found for t in ["headers", "hsts", "csp"]):
        recs.append("Sicherheits-Header implementieren (HSTS, CSP, X-Frame-Options)")
    if any(t in tags_found for t in ["information-disclosure", "directory-brute"]):
        recs.append("Sensible Dateien und Verzeichnisse aus dem öffentlichen Zugriff entfernen")
    if any(t in tags_found for t in ["misconfiguration"]):
        recs.append("Server- und Anwendungskonfiguration gemäß Security-Best-Practices härten")
    if any(t in tags_found for t in ["api-discovery"]):
        recs.append("API-Endpunkte absichern: Authentifizierung, Rate-Limiting, Dokumentation schützen")
    if any(t in tags_found for t in ["no-waf"]):
        recs.append("Einsatz einer Web Application Firewall (WAF) evaluieren")

    if not recs:
        recs.append("Regelmäßige Sicherheitsüberprüfungen durchführen")

    return recs


def _generate_executive_summary(
    project: Project,
    findings: list[Finding],
    counts: dict[str, int],
    cvss_map: dict[int, dict],
) -> dict:
    """Generate auto-executive summary data."""
    total = sum(counts.values())
    hosts = project.all_hosts()

    risk_rating, risk_color, risk_description = _determine_risk_rating(counts)

    # Top 3 critical findings
    critical_findings = []
    for f in findings:
        if f.severity in (Severity.CRITICAL, Severity.HIGH) and len(critical_findings) < 3:
            critical_findings.append(f)

    recommendations = _generate_recommendations(findings)

    return {
        "total_hosts": len(hosts),
        "total_findings": total,
        "risk_rating": risk_rating,
        "risk_color": risk_color,
        "risk_description": risk_description,
        "top_findings": critical_findings,
        "recommendations": recommendations,
        "counts": counts,
    }


def render_html(
    project: Project,
    client: str = "",
    author: str = "",
    date_range: str = "",
    summary: str = "",
    version: str = "1.0",
    extra_findings: list[Finding] | None = None,
    nvd_api_key: str = "",
) -> str:
    """Render the report as HTML string."""
    env = Environment(loader=FileSystemLoader(str(TEMPLATE_DIR)), autoescape=True)
    template = env.get_template("report.html")

    # Merge pipeline findings with manually added findings
    findings = list(project.all_findings())
    if extra_findings:
        findings.extend(extra_findings)

    # Sort by severity
    findings.sort(key=lambda f: SEVERITY_ORDER.index(f.severity))

    hosts = project.all_hosts()
    subdomains = project.all_subdomains()
    counts = _count_findings(findings)

    # CVSS enrichment
    cvss_map = enrich_findings_with_cvss(findings, nvd_api_key)

    # Executive summary
    exec_summary = _generate_executive_summary(project, findings, counts, cvss_map)

    meta = {
        "client": client or project.name,
        "author": author or "Security Team",
        "date_range": date_range or datetime.now().strftime("%d.%m.%Y"),
        "report_date": datetime.now().strftime("%d.%m.%Y"),
        "summary": summary,
        "version": version,
    }

    return template.render(
        project=project,
        meta=meta,
        findings=findings,
        hosts=hosts,
        subdomains=subdomains,
        counts=counts,
        cvss_map=cvss_map,
        exec_summary=exec_summary,
    )


def generate_pdf(
    project: Project,
    output_path: Path | str,
    client: str = "",
    author: str = "",
    date_range: str = "",
    summary: str = "",
    version: str = "1.0",
    extra_findings: list[Finding] | None = None,
    nvd_api_key: str = "",
) -> Path:
    """Generate a PDF pentest report."""
    from weasyprint import HTML

    html_content = render_html(
        project=project,
        client=client,
        author=author,
        date_range=date_range,
        summary=summary,
        version=version,
        extra_findings=extra_findings,
        nvd_api_key=nvd_api_key,
    )

    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    HTML(string=html_content).write_pdf(str(output_path))
    return output_path


def generate_html(
    project: Project,
    output_path: Path | str,
    **kwargs,
) -> Path:
    """Generate an HTML report (for preview before PDF)."""
    html_content = render_html(project=project, **kwargs)
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(html_content, encoding="utf-8")
    return output_path
