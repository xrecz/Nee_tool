"""CLI interface for Nee Tool.

Usage:
    nee scan example.de
    nee scan example.de --name "Kunde-ABC-Q1-2026"
    nee scan example.de --only subdomain,portscan
    nee scan example.de --skip ssl_check
    nee scan example.de --top-ports 100

    nee report scan_result.json --client "Firma XYZ" --author "Max Mustermann"
    nee report scan_result.json --html-only
    nee templates
"""

from __future__ import annotations

from pathlib import Path

import typer
from rich.console import Console

from nee_tool.core.config import Config
from nee_tool.core.orchestrator import PipelineOrchestrator
from nee_tool.output.json_export import export_findings, export_hosts, export_project

app = typer.Typer(
    name="nee",
    help="Nee Tool — Automated Pentest Reconnaissance Toolkit",
    no_args_is_help=True,
)
console = Console()


@app.command()
def scan(
    target: str = typer.Argument(help="Target domain (e.g. example.de)"),
    name: str = typer.Option("", "--name", "-n", help="Project name (default: target domain)"),
    output: str = typer.Option("./output", "--output", "-o", help="Output directory"),
    top_ports: int = typer.Option(1000, "--top-ports", help="Nmap: number of top ports to scan"),
    only: str = typer.Option("", "--only", help="Comma-separated list of scanners to run"),
    skip: str = typer.Option("", "--skip", help="Comma-separated list of scanners to skip"),
    timeout: int = typer.Option(600, "--timeout", help="Timeout per scanner in seconds"),
) -> None:
    """Run the full recon pipeline against a target domain."""
    project_name = name or target.replace(".", "_")

    config = Config.default()
    config.output_dir = output
    config.scan.nmap_top_ports = top_ports
    config.scan.timeout_per_scanner = timeout

    if only:
        config.pipeline.enabled_scanners = [s.strip() for s in only.split(",")]
    elif skip:
        skip_list = [s.strip() for s in skip.split(",")]
        config.pipeline.enabled_scanners = [
            s for s in config.pipeline.enabled_scanners if s not in skip_list
        ]

    orchestrator = PipelineOrchestrator(config)
    project = orchestrator.run(project_name, target)

    # Export results
    out_dir = config.project_dir(project_name)
    project_file = export_project(project, out_dir)
    findings_file = export_findings(project, out_dir)
    hosts_file = export_hosts(project, out_dir)

    console.print()
    console.print(f"[bold green]Ergebnisse gespeichert:[/bold green]")
    console.print(f"  Projekt:  {project_file}")
    console.print(f"  Findings: {findings_file}")
    console.print(f"  Hosts:    {hosts_file}")


@app.command()
def scanners() -> None:
    """List all available scanner modules."""
    from nee_tool.core.orchestrator import SCANNER_REGISTRY

    console.print("[bold]Verfügbare Scanner:[/bold]\n")
    for name, cls in SCANNER_REGISTRY.items():
        scanner = cls(Config.default())
        missing = scanner.check_tools()
        if missing:
            status = f"[yellow]✗ fehlt: {', '.join(missing)}[/yellow]"
        else:
            status = "[green]✓ verfügbar[/green]"
        console.print(f"  [cyan]{name:20}[/cyan] {scanner.description:40} {status}")


@app.command()
def info(
    project_file: str = typer.Argument(help="Path to a project JSON file"),
) -> None:
    """Show summary of a previous scan result."""
    import json

    from nee_tool.core.models import Project

    path = Path(project_file)
    if not path.exists():
        console.print(f"[red]Datei nicht gefunden: {path}[/red]")
        raise typer.Exit(1)

    data = json.loads(path.read_text())
    project = Project(**data)

    console.print(f"[bold]Projekt:[/bold] {project.name}")
    console.print(f"[bold]Target:[/bold]  {project.target}")
    console.print(f"[bold]Erstellt:[/bold] {project.created_at}")
    console.print()

    hosts = project.all_hosts()
    findings = project.all_findings()
    subs = project.all_subdomains()

    console.print(f"Subdomains: {len(subs)}")
    console.print(f"Hosts:      {len(hosts)}")
    console.print(f"Findings:   {len(findings)}")

    for f in findings:
        console.print(f"  [{f.severity.value.upper():8}] {f.title}")


@app.command()
def report(
    project_file: str = typer.Argument(help="Path to a project JSON file from a scan"),
    client: str = typer.Option("", "--client", "-c", help="Client/company name"),
    author: str = typer.Option("Security Team", "--author", "-a", help="Report author"),
    date_range: str = typer.Option("", "--date-range", "-d", help="Test period (e.g. '01.03. - 15.03.2026')"),
    summary: str = typer.Option("", "--summary", help="Management summary text"),
    version: str = typer.Option("1.0", "--version", "-v", help="Report version"),
    output: str = typer.Option("", "--output", "-o", help="Output PDF path (default: next to project file)"),
    html_only: bool = typer.Option(False, "--html-only", help="Generate HTML preview instead of PDF"),
) -> None:
    """Generate a PDF pentest report from scan results."""
    import json

    from nee_tool.core.models import Project
    from nee_tool.report.generator import generate_html, generate_pdf

    path = Path(project_file)
    if not path.exists():
        console.print(f"[red]Datei nicht gefunden: {path}[/red]")
        raise typer.Exit(1)

    data = json.loads(path.read_text())
    project = Project(**data)

    if not output:
        ext = ".html" if html_only else ".pdf"
        output = str(path.with_suffix(ext))

    console.print(f"[bold]Generiere Bericht für:[/bold] {project.name}")
    console.print(f"  Target:  {project.target}")
    console.print(f"  Findings: {len(project.all_findings())}")
    console.print()

    if html_only:
        out = generate_html(
            project, output, client=client, author=author,
            date_range=date_range, summary=summary, version=version,
        )
        console.print(f"[bold green]HTML-Bericht erstellt:[/bold green] {out}")
    else:
        out = generate_pdf(
            project, output, client=client, author=author,
            date_range=date_range, summary=summary, version=version,
        )
        console.print(f"[bold green]PDF-Bericht erstellt:[/bold green] {out}")


@app.command()
def templates() -> None:
    """List all available finding templates."""
    from rich.table import Table

    from nee_tool.report.finding_templates import FINDING_TEMPLATES

    table = Table(title="Finding-Templates", show_header=True)
    table.add_column("Key", style="cyan")
    table.add_column("Severity")
    table.add_column("Title")
    table.add_column("Tags")

    severity_colors = {
        "critical": "red bold",
        "high": "red",
        "medium": "yellow",
        "low": "blue",
        "info": "dim",
    }

    for key, finding in FINDING_TEMPLATES.items():
        style = severity_colors.get(finding.severity.value, "")
        table.add_row(
            key,
            f"[{style}]{finding.severity.value.upper()}[/{style}]",
            finding.title,
            ", ".join(finding.tags[:3]),
        )

    console.print(table)
    console.print(f"\n[bold]{len(FINDING_TEMPLATES)}[/bold] Templates verfügbar")
    console.print("[dim]Nutzung: Aus Pipeline-Findings wird automatisch der passende Template-Text ergänzt.[/dim]")


@app.command()
def demo_report(
    output: str = typer.Option("./output/demo_report.pdf", "--output", "-o", help="Output path"),
    html_only: bool = typer.Option(False, "--html-only", help="Generate HTML instead of PDF"),
) -> None:
    """Generate a demo report with sample data to preview the template."""
    from nee_tool.core.models import Finding, HostInfo, PortInfo, Project, ScanResult, Severity
    from nee_tool.report.finding_templates import create_finding_from_template
    from nee_tool.report.generator import generate_html, generate_pdf

    # Build sample project
    project = Project(
        name="Demo-Pentest",
        target="demo.example.de",
        scope=["demo.example.de", "*.demo.example.de"],
    )

    # Sample scan results
    project.scan_results = [
        ScanResult(
            scanner_name="subdomain",
            subdomains=["demo.example.de", "mail.demo.example.de", "vpn.demo.example.de", "dev.demo.example.de"],
            duration_seconds=12.5,
        ),
        ScanResult(
            scanner_name="portscan",
            hosts=[
                HostInfo(hostname="demo.example.de", ip="203.0.113.10", ports=[
                    PortInfo(port=80, service="http", version="nginx 1.18"),
                    PortInfo(port=443, service="https", version="nginx 1.18"),
                    PortInfo(port=22, service="ssh", version="OpenSSH 8.9"),
                ]),
                HostInfo(hostname="mail.demo.example.de", ip="203.0.113.11", ports=[
                    PortInfo(port=25, service="smtp", version="Postfix"),
                    PortInfo(port=443, service="https"),
                    PortInfo(port=993, service="imaps"),
                ]),
                HostInfo(hostname="dev.demo.example.de", ip="203.0.113.12", ports=[
                    PortInfo(port=80, service="http", version="Apache 2.4.41"),
                    PortInfo(port=8080, service="http-proxy", version="Jenkins 2.319"),
                ]),
            ],
            duration_seconds=85.3,
        ),
        ScanResult(
            scanner_name="web_discovery",
            hosts=[
                HostInfo(hostname="demo.example.de", is_web=True, status_code=200, title="Demo Portal", technologies=["nginx", "React", "Node.js"]),
                HostInfo(hostname="dev.demo.example.de", is_web=True, status_code=200, title="Jenkins Dashboard", technologies=["Apache", "Jenkins", "Java"]),
            ],
            duration_seconds=5.2,
        ),
    ]

    # Sample findings — mix of template-based and manual
    extra_findings = [
        create_finding_from_template(
            "sqli", target="demo.example.de/api/users",
            evidence="POST /api/users?id=1' OR 1=1-- HTTP/1.1\n\nResponse: 200 OK (alle User-Datensätze zurückgegeben)",
        ),
        create_finding_from_template(
            "xss_stored", target="demo.example.de/forum",
            evidence='<script>alert(document.cookie)</script> in Forumsbeitrag\n\nScript wird bei jedem Seitenaufruf ausgeführt.',
        ),
        create_finding_from_template(
            "default_credentials", target="dev.demo.example.de:8080",
            evidence="Jenkins Login: admin/admin → Zugang zum Dashboard",
        ),
        create_finding_from_template("missing_csp", target="demo.example.de"),
        create_finding_from_template("missing_hsts", target="demo.example.de"),
        create_finding_from_template("clickjacking", target="demo.example.de"),
        create_finding_from_template("directory_listing", target="dev.demo.example.de/backup/",
            evidence="GET /backup/ HTTP/1.1\n\nIndex of /backup/\n  db_dump_2026-03-01.sql.gz  14MB\n  config.tar.gz              2.1MB",
        ),
        create_finding_from_template("server_version_exposed", target="dev.demo.example.de",
            evidence="Server: Apache/2.4.41 (Ubuntu)\nX-Powered-By: Express",
        ),
        Finding(
            title="Veraltete Jenkins-Version (dev.demo.example.de)",
            severity=Severity.INFO,
            description="Jenkins 2.319 ist veraltet. Aktuelle Version: 2.440+",
            recommendation="Jenkins auf die aktuelle LTS-Version aktualisieren.",
            tags=["software", "jenkins"],
        ),
    ]

    summary = (
        "Im Rahmen des Penetrationstests der Demo-Infrastruktur wurden insgesamt "
        "9 Schwachstellen identifiziert. Darunter befinden sich eine kritische "
        "SQL-Injection-Schwachstelle in der Benutzer-API sowie Standard-Zugangsdaten "
        "auf dem Jenkins-Server der Entwicklungsumgebung.\n\n"
        "Es wird dringend empfohlen, die kritischen und hohen Schwachstellen "
        "umgehend zu beheben. Die Entwicklungsumgebung sollte nicht öffentlich "
        "erreichbar sein."
    )

    if html_only:
        out = generate_html(
            project, output.replace(".pdf", ".html"),
            client="Demo GmbH", author="Security Team",
            date_range="01.03. - 15.03.2026", summary=summary,
            extra_findings=extra_findings,
        )
        console.print(f"[bold green]Demo HTML-Bericht erstellt:[/bold green] {out}")
    else:
        out = generate_pdf(
            project, output,
            client="Demo GmbH", author="Security Team",
            date_range="01.03. - 15.03.2026", summary=summary,
            extra_findings=extra_findings,
        )
        console.print(f"[bold green]Demo PDF-Bericht erstellt:[/bold green] {out}")


if __name__ == "__main__":
    app()
