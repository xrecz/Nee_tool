"""Pipeline orchestrator.

Manages the execution of scanner modules in sequence,
passing results between stages so each scanner can build
on the previous ones' output.
"""

from __future__ import annotations

from datetime import datetime

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from nee_tool.core.config import Config
from nee_tool.core.models import Project, ScanStatus, Severity
from nee_tool.scanners.base import BaseScanner
from nee_tool.scanners.nuclei import NucleiScanner
from nee_tool.scanners.portscan import PortScanner
from nee_tool.scanners.security_headers import SecurityHeadersScanner
from nee_tool.scanners.ssl_check import SSLCheckScanner
from nee_tool.scanners.subdomain import SubdomainScanner
from nee_tool.scanners.tech_detect import TechDetectScanner
from nee_tool.scanners.web_discovery import WebDiscoveryScanner

console = Console()

# Registry of available scanners
SCANNER_REGISTRY: dict[str, type[BaseScanner]] = {
    "subdomain": SubdomainScanner,
    "portscan": PortScanner,
    "web_discovery": WebDiscoveryScanner,
    "security_headers": SecurityHeadersScanner,
    "ssl_check": SSLCheckScanner,
    "tech_detect": TechDetectScanner,
    "nuclei": NucleiScanner,
}


class PipelineOrchestrator:
    """Runs scanner modules in sequence, feeding results forward."""

    def __init__(self, config: Config | None = None):
        self.config = config or Config.default()

    def run(self, project_name: str, target: str, scope: list[str] | None = None) -> Project:
        """Execute the full recon pipeline."""
        project = Project(
            name=project_name,
            target=target,
            scope=scope or [target, f"*.{target}"],
        )

        enabled = self.config.pipeline.enabled_scanners
        scanners = []
        for name in enabled:
            if name in SCANNER_REGISTRY:
                scanners.append(SCANNER_REGISTRY[name](self.config))
            else:
                console.print(f"[yellow]Unbekannter Scanner: {name}[/yellow]")

        console.print()
        console.print(Panel(
            f"[bold]Target:[/bold] {target}\n"
            f"[bold]Scope:[/bold] {', '.join(project.scope)}\n"
            f"[bold]Scanner:[/bold] {len(scanners)} Module aktiviert",
            title=f"[bold cyan]Nee Tool — {project_name}[/bold cyan]",
            border_style="cyan",
        ))
        console.print()

        for i, scanner in enumerate(scanners, 1):
            console.print(f"[bold][{i}/{len(scanners)}][/bold]", end=" ")
            result = scanner.execute(target, project.scan_results)
            project.scan_results.append(result)

        console.print()
        self._print_summary(project)
        return project

    def _print_summary(self, project: Project) -> None:
        """Print a summary of all scan results."""
        # Scanner status table
        status_table = Table(title="Scanner-Ergebnisse", show_header=True)
        status_table.add_column("Scanner", style="cyan")
        status_table.add_column("Status")
        status_table.add_column("Dauer", justify="right")
        status_table.add_column("Ergebnis")

        for result in project.scan_results:
            status_style = {
                ScanStatus.COMPLETED: "[green]OK[/green]",
                ScanStatus.FAILED: "[red]FEHLER[/red]",
                ScanStatus.SKIPPED: "[yellow]SKIP[/yellow]",
            }.get(result.status, str(result.status))

            parts = []
            if result.hosts:
                parts.append(f"{len(result.hosts)} Hosts")
            if result.subdomains:
                parts.append(f"{len(result.subdomains)} Subdomains")
            if result.findings:
                parts.append(f"{len(result.findings)} Findings")
            if result.error:
                parts.append(result.error[:50])

            status_table.add_row(
                result.scanner_name,
                status_style,
                f"{result.duration_seconds}s",
                ", ".join(parts) if parts else "-",
            )

        console.print(status_table)

        # Hosts overview
        all_hosts = project.all_hosts()
        if all_hosts:
            console.print()
            host_table = Table(title=f"Entdeckte Hosts ({len(all_hosts)})", show_header=True)
            host_table.add_column("Host", style="cyan")
            host_table.add_column("IP")
            host_table.add_column("Ports")
            host_table.add_column("Web")
            host_table.add_column("Technologien")

            for key, host in sorted(all_hosts.items()):
                ports = ", ".join(str(p.port) for p in host.ports[:10])
                if len(host.ports) > 10:
                    ports += f" (+{len(host.ports) - 10})"
                techs = ", ".join(host.technologies[:5])
                web = "[green]Ja[/green]" if host.is_web else "-"

                host_table.add_row(host.hostname, host.ip, ports or "-", web, techs or "-")

            console.print(host_table)

        # Findings overview
        all_findings = project.all_findings()
        if all_findings:
            console.print()
            severity_colors = {
                Severity.CRITICAL: "red bold",
                Severity.HIGH: "red",
                Severity.MEDIUM: "yellow",
                Severity.LOW: "blue",
                Severity.INFO: "dim",
            }

            finding_table = Table(title=f"Findings ({len(all_findings)})", show_header=True)
            finding_table.add_column("Severity")
            finding_table.add_column("Finding")

            # Sort by severity
            severity_order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
            all_findings.sort(key=lambda f: severity_order.index(f.severity))

            for finding in all_findings:
                style = severity_colors.get(finding.severity, "")
                finding_table.add_row(
                    f"[{style}]{finding.severity.value.upper()}[/{style}]",
                    finding.title,
                )

            console.print(finding_table)

        # Quick stats
        console.print()
        subs = project.all_subdomains()
        stats = (
            f"[bold]Zusammenfassung:[/bold] "
            f"{len(subs)} Subdomains, "
            f"{len(all_hosts)} Hosts, "
            f"{sum(len(h.ports) for h in all_hosts.values())} offene Ports, "
            f"{len(all_findings)} Findings"
        )
        console.print(Panel(stats, border_style="green"))
