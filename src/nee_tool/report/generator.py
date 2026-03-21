"""PDF Report Generator.

Takes a Project with scan results and generates a professional
PDF pentest report using HTML templates and WeasyPrint.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from jinja2 import Environment, FileSystemLoader

from nee_tool.core.models import Finding, Project, Severity

TEMPLATE_DIR = Path(__file__).parent / "templates"

# Severity sort order
SEVERITY_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]


def _count_findings(findings: list[Finding]) -> dict[str, int]:
    """Count findings by severity."""
    counts = {s.value: 0 for s in Severity}
    for f in findings:
        counts[f.severity.value] += 1
    return counts


def render_html(
    project: Project,
    client: str = "",
    author: str = "",
    date_range: str = "",
    summary: str = "",
    version: str = "1.0",
    extra_findings: list[Finding] | None = None,
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
) -> Path:
    """Generate a PDF pentest report.

    Args:
        project: The project with scan results
        output_path: Where to save the PDF
        client: Client/company name for the cover page
        author: Author name
        date_range: Test period (e.g. "01.03. - 15.03.2026")
        summary: Management summary text (optional, auto-generated if empty)
        version: Report version
        extra_findings: Additional manually created findings to include

    Returns:
        Path to the generated PDF file
    """
    from weasyprint import HTML

    html_content = render_html(
        project=project,
        client=client,
        author=author,
        date_range=date_range,
        summary=summary,
        version=version,
        extra_findings=extra_findings,
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
