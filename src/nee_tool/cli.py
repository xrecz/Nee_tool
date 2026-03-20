"""CLI interface for Nee Tool.

Usage:
    nee scan example.de
    nee scan example.de --name "Kunde-ABC-Q1-2026"
    nee scan example.de --only subdomain,portscan
    nee scan example.de --skip ssl_check
    nee scan example.de --top-ports 100
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


if __name__ == "__main__":
    app()
