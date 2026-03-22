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
    profile: str = typer.Option("", "--profile", "-p", help="Scan profile (quick/standard/deep/compliance/recon)"),
) -> None:
    """Run the full recon pipeline against a target domain."""
    project_name = name or target.replace(".", "_")

    config = Config.default()
    config.output_dir = output

    # Apply profile first (if specified), then overrides
    if profile:
        from nee_tool.core.profiles import SCAN_PROFILES, apply_profile
        try:
            apply_profile(config, profile)
            console.print(f"[bold]Profil:[/bold] {SCAN_PROFILES[profile].name} — {SCAN_PROFILES[profile].description}")
        except KeyError as e:
            console.print(f"[red]{e}[/red]")
            raise typer.Exit(1)

    # CLI overrides take precedence over profile
    if top_ports != 1000:
        config.scan.nmap_top_ports = top_ports
    elif not profile:
        config.scan.nmap_top_ports = top_ports
    if timeout != 600:
        config.scan.timeout_per_scanner = timeout
    elif not profile:
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
def web(
    host: str = typer.Option("127.0.0.1", "--host", "-h", help="Bind address"),
    port: int = typer.Option(8899, "--port", "-p", help="Port"),
    reload: bool = typer.Option(False, "--reload", help="Auto-reload on code changes"),
) -> None:
    """Start the web UI dashboard."""
    import uvicorn

    console.print(f"[bold cyan]Nee Tool Web-UI[/bold cyan] → http://{host}:{port}")
    uvicorn.run("nee_tool.web.app:app", host=host, port=port, reload=reload)


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
def profiles() -> None:
    """List all available scan profiles."""
    from rich.table import Table

    from nee_tool.core.profiles import SCAN_PROFILES

    table = Table(title="Scan-Profile", show_header=True)
    table.add_column("Key", style="cyan")
    table.add_column("Name")
    table.add_column("Beschreibung", max_width=50)
    table.add_column("Scanner", justify="right")
    table.add_column("Ports", justify="right")

    for key, p in SCAN_PROFILES.items():
        table.add_row(key, p.name, p.description, str(len(p.scanners)), str(p.top_ports))

    console.print(table)
    console.print("\n[dim]Nutzung: nee scan target.de --profile quick[/dim]")


@app.command()
def retest(
    original_file: str = typer.Argument(help="Path to original scan project JSON"),
    retest_file: str = typer.Argument(help="Path to re-test scan project JSON"),
    output: str = typer.Option("", "--output", "-o", help="Output JSON path for re-test results"),
) -> None:
    """Compare two scans to identify fixed, persistent, and new findings."""
    import json as json_mod

    from rich.table import Table

    from nee_tool.core.models import Project
    from nee_tool.core.retest import compare_projects

    orig_path = Path(original_file)
    retest_path = Path(retest_file)

    for p in (orig_path, retest_path):
        if not p.exists():
            console.print(f"[red]Datei nicht gefunden: {p}[/red]")
            raise typer.Exit(1)

    original = Project(**json_mod.loads(orig_path.read_text()))
    retest_proj = Project(**json_mod.loads(retest_path.read_text()))

    result = compare_projects(original, retest_proj)
    counts = result.summary_counts()

    console.print(f"\n[bold]Re-Test Vergleich[/bold]")
    console.print(f"  Original:  {result.original_project} ({result.original_date})")
    console.print(f"  Re-Test:   {result.retest_project} ({result.retest_date})")
    console.print()

    # Summary table
    table = Table(title="Ergebnis", show_header=True)
    table.add_column("Status")
    table.add_column("Anzahl", justify="right")

    table.add_row("[green]Behoben[/green]", f"[green]{counts['fixed']}[/green]")
    table.add_row("[red]Offen[/red]", f"[red]{counts['persistent']}[/red]")
    table.add_row("[yellow]Neu[/yellow]", f"[yellow]{counts['new']}[/yellow]")
    table.add_row("[bold]Fix-Rate[/bold]", f"[bold]{result.fix_rate}%[/bold]")
    console.print(table)

    # Detail tables
    if result.fixed:
        console.print("\n[bold green]Behoben:[/bold green]")
        for rf in result.fixed:
            console.print(f"  [green]✓[/green] [{rf.finding.severity.value.upper():8}] {rf.finding.title}")

    if result.persistent:
        console.print("\n[bold red]Noch offen:[/bold red]")
        for rf in result.persistent:
            console.print(f"  [red]✗[/red] [{rf.finding.severity.value.upper():8}] {rf.finding.title}")

    if result.new:
        console.print("\n[bold yellow]Neu gefunden:[/bold yellow]")
        for rf in result.new:
            console.print(f"  [yellow]●[/yellow] [{rf.finding.severity.value.upper():8}] {rf.finding.title}")

    # Export if requested
    if output:
        out_path = Path(output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json_mod.dumps(result.model_dump(mode="json"), indent=2, ensure_ascii=False, default=str))
        console.print(f"\n[bold green]Re-Test-Ergebnis gespeichert:[/bold green] {out_path}")


@app.command()
def compliance(
    project_file: str = typer.Argument(help="Path to a project JSON file"),
) -> None:
    """Show compliance mapping for findings (BSI/ISO 27001/DSGVO)."""
    import json as json_mod

    from rich.table import Table

    from nee_tool.core.compliance import compliance_summary, map_all_findings
    from nee_tool.core.models import Project

    path = Path(project_file)
    if not path.exists():
        console.print(f"[red]Datei nicht gefunden: {path}[/red]")
        raise typer.Exit(1)

    project = Project(**json_mod.loads(path.read_text()))
    findings = project.all_findings()

    if not findings:
        console.print("[yellow]Keine Findings vorhanden.[/yellow]")
        raise typer.Exit(0)

    # Per-framework summary
    summary = compliance_summary(findings)

    for framework, controls in summary.items():
        console.print(f"\n[bold]{framework}[/bold] — {len(controls)} betroffene Controls:")
        for ctrl in controls:
            console.print(f"  [cyan]{ctrl}[/cyan]")

    # Detailed mapping table
    mappings = map_all_findings(findings)
    console.print()

    table = Table(title=f"Compliance-Mapping ({len(mappings)} Findings)", show_header=True)
    table.add_column("Finding", max_width=40)
    table.add_column("BSI", max_width=25)
    table.add_column("ISO 27001", max_width=25)
    table.add_column("DSGVO", max_width=25)

    for mapping in mappings:
        bsi = ", ".join(c.control_id for c in mapping.controls if c.framework == "BSI") or "-"
        iso = ", ".join(c.control_id for c in mapping.controls if c.framework == "ISO27001") or "-"
        dsgvo = ", ".join(c.control_id for c in mapping.controls if c.framework == "DSGVO") or "-"
        table.add_row(mapping.finding_title[:40], bsi, iso, dsgvo)

    console.print(table)


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


# ── GoPhish / Phishing Commands ──────────────────────────────

phish_app = typer.Typer(name="phish", help="GoPhish Phishing-Kampagnen verwalten", no_args_is_help=True)
app.add_typer(phish_app)


@phish_app.command("setup")
def phish_setup(
    host: str = typer.Option("https://localhost:3333", "--host", help="GoPhish server URL"),
    api_key: str = typer.Option(..., "--api-key", "-k", help="GoPhish API key"),
    template_key: str = typer.Option("it_password_reset", "--template", "-t", help="Email template key"),
    smtp_host: str = typer.Option(..., "--smtp-host", help="SMTP server (host:port)"),
    smtp_from: str = typer.Option(..., "--smtp-from", help="Sender address"),
    smtp_user: str = typer.Option("", "--smtp-user", help="SMTP username"),
    smtp_pass: str = typer.Option("", "--smtp-pass", help="SMTP password"),
    targets_csv: str = typer.Option(..., "--targets", help="CSV file with targets (email,first_name,last_name,position)"),
    campaign_name: str = typer.Option(..., "--name", "-n", help="Campaign name"),
    phish_url: str = typer.Option(..., "--url", "-u", help="Phishing URL (GoPhish listener)"),
    landing_redirect: str = typer.Option("https://www.google.com", "--redirect", help="Redirect URL after credential capture"),
) -> None:
    """Set up and launch a complete phishing campaign in one command."""
    from nee_tool.phishing.client import (
        Campaign, EmailTemplate, GoPhishClient, GoPhishConfig,
        GoPhishError, LandingPage, SMTPProfile,
    )
    from nee_tool.phishing.email_templates import get_template

    config = GoPhishConfig(host=host, api_key=api_key)
    client = GoPhishClient(config)

    try:
        # 1. SMTP Profile
        console.print("[bold]1/5[/bold] Erstelle SMTP-Profil...")
        smtp = client.create_smtp(SMTPProfile(
            name=f"{campaign_name}_smtp",
            host=smtp_host,
            from_address=smtp_from,
            username=smtp_user,
            password=smtp_pass,
        ))
        console.print(f"  [green]✓[/green] SMTP-Profil erstellt (ID: {smtp.id})")

        # 2. Email Template
        console.print("[bold]2/5[/bold] Erstelle E-Mail-Template...")
        phish_tpl = get_template(template_key)
        if not phish_tpl:
            console.print(f"  [red]Template '{template_key}' nicht gefunden. Verfügbar: nee phish templates[/red]")
            raise typer.Exit(1)

        email_tpl = client.create_template(EmailTemplate(
            name=f"{campaign_name}_email",
            subject=phish_tpl.subject,
            html=phish_tpl.html,
            text=phish_tpl.text,
        ))
        console.print(f"  [green]✓[/green] E-Mail-Template '{phish_tpl.name}' (ID: {email_tpl.id})")

        # 3. Landing Page
        console.print("[bold]3/5[/bold] Erstelle Landing Page...")
        page = client.create_page(LandingPage(
            name=f"{campaign_name}_page",
            html='<html><body><form method="POST"><input name="username" placeholder="Benutzername"><br><input name="password" type="password" placeholder="Passwort"><br><button type="submit">Anmelden</button></form></body></html>',
            capture_credentials=True,
            capture_passwords=True,
            redirect_url=landing_redirect,
        ))
        console.print(f"  [green]✓[/green] Landing Page erstellt (ID: {page.id})")

        # 4. Target Group
        console.print("[bold]4/5[/bold] Importiere Ziele...")
        group = client.import_targets_csv(f"{campaign_name}_targets", targets_csv)
        console.print(f"  [green]✓[/green] {len(group.targets)} Ziele importiert (ID: {group.id})")

        # 5. Campaign
        console.print("[bold]5/5[/bold] Starte Kampagne...")
        campaign = Campaign(
            name=campaign_name,
            template=email_tpl,
            page=page,
            smtp=smtp,
            groups=[group],
            url=phish_url,
        )
        result = client.create_campaign(campaign)
        console.print(f"  [green]✓[/green] Kampagne gestartet! (ID: {result.get('id')})")
        console.print()
        console.print(f"[bold green]Kampagne '{campaign_name}' läuft![/bold green]")
        console.print(f"  Status prüfen: nee phish status {result.get('id')} --host {host} --api-key <key>")

    except GoPhishError as e:
        console.print(f"[red]GoPhish Fehler: {e}[/red]")
        raise typer.Exit(1)


@phish_app.command("status")
def phish_status(
    campaign_id: int = typer.Argument(help="Campaign ID"),
    host: str = typer.Option("https://localhost:3333", "--host", help="GoPhish server URL"),
    api_key: str = typer.Option(..., "--api-key", "-k", help="GoPhish API key"),
) -> None:
    """Show current status of a phishing campaign."""
    from rich.table import Table

    from nee_tool.phishing.client import GoPhishClient, GoPhishConfig, GoPhishError

    config = GoPhishConfig(host=host, api_key=api_key)
    client = GoPhishClient(config)

    try:
        result = client.get_campaign_results(campaign_id)
    except GoPhishError as e:
        console.print(f"[red]Fehler: {e}[/red]")
        raise typer.Exit(1)

    total = max(result.total_targets, 1)

    console.print(f"[bold]Kampagne:[/bold] {result.name}")
    console.print(f"[bold]Status:[/bold]   {result.status}")
    console.print(f"[bold]Gestartet:[/bold] {result.launch_date}")
    console.print()

    table = Table(title="Ergebnisse", show_header=True)
    table.add_column("Metrik")
    table.add_column("Anzahl", justify="right")
    table.add_column("Rate", justify="right")

    table.add_row("Ziele gesamt", str(result.total_targets), "-")
    table.add_row("E-Mails gesendet", str(result.emails_sent), f"{result.emails_sent/total*100:.1f}%")
    table.add_row("E-Mails geöffnet", str(result.emails_opened), f"{result.emails_opened/total*100:.1f}%")
    table.add_row("[bold yellow]Links geklickt[/bold yellow]", str(result.links_clicked), f"[bold yellow]{result.links_clicked/total*100:.1f}%[/bold yellow]")
    table.add_row("[bold red]Credentials eingegeben[/bold red]", str(result.credentials_submitted), f"[bold red]{result.credentials_submitted/total*100:.1f}%[/bold red]")
    table.add_row("Fehler", str(result.errors), f"{result.errors/total*100:.1f}%")

    console.print(table)


@phish_app.command("report")
def phish_report(
    campaign_id: int = typer.Argument(help="Campaign ID"),
    host: str = typer.Option("https://localhost:3333", "--host", help="GoPhish server URL"),
    api_key: str = typer.Option(..., "--api-key", "-k", help="GoPhish API key"),
    client_name: str = typer.Option("", "--client", "-c", help="Client name for the report"),
    author: str = typer.Option("Security Team", "--author", "-a", help="Report author"),
    output: str = typer.Option("", "--output", "-o", help="Output path"),
    html_only: bool = typer.Option(False, "--html-only", help="Generate HTML instead of PDF"),
) -> None:
    """Generate a PDF report for a phishing campaign."""
    from nee_tool.phishing.client import GoPhishClient, GoPhishConfig, GoPhishError
    from nee_tool.phishing.report import generate_phishing_report

    config = GoPhishConfig(host=host, api_key=api_key)
    gophish = GoPhishClient(config)

    try:
        result = gophish.get_campaign_results(campaign_id)
    except GoPhishError as e:
        console.print(f"[red]Fehler: {e}[/red]")
        raise typer.Exit(1)

    if not output:
        output = f"./output/phishing_{result.name}_{campaign_id}.pdf"

    out = generate_phishing_report(
        result, output, client=client_name, author=author, html_only=html_only,
    )
    console.print(f"[bold green]Phishing-Bericht erstellt:[/bold green] {out}")


@phish_app.command("templates")
def phish_templates() -> None:
    """List all available phishing email templates."""
    from rich.table import Table

    from nee_tool.phishing.email_templates import PHISH_TEMPLATES

    table = Table(title="Phishing E-Mail-Templates", show_header=True)
    table.add_column("Key", style="cyan")
    table.add_column("Kategorie")
    table.add_column("Name")
    table.add_column("Beschreibung", max_width=40)

    for key, tpl in PHISH_TEMPLATES.items():
        table.add_row(key, tpl.category, tpl.name, tpl.description)

    console.print(table)
    console.print(f"\n[bold]{len(PHISH_TEMPLATES)}[/bold] Templates verfügbar")


@phish_app.command("demo-report")
def phish_demo_report(
    output: str = typer.Option("./output/phishing_demo.pdf", "--output", "-o"),
    html_only: bool = typer.Option(False, "--html-only"),
) -> None:
    """Generate a demo phishing report with sample data."""
    from nee_tool.phishing.client import CampaignResult
    from nee_tool.phishing.report import generate_phishing_report

    result = CampaignResult(
        id=42,
        name="Awareness-Test Q1/2026",
        status="Completed",
        created_date="2026-03-01T08:00:00Z",
        launch_date="2026-03-01T09:00:00Z",
        total_targets=150,
        emails_sent=148,
        emails_opened=89,
        links_clicked=34,
        credentials_submitted=12,
        errors=2,
    )

    out = generate_phishing_report(
        result, output, client="Demo GmbH", author="Security Team", html_only=html_only,
    )
    console.print(f"[bold green]Demo Phishing-Bericht erstellt:[/bold green] {out}")


if __name__ == "__main__":
    app()
