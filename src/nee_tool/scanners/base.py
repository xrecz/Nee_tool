"""Base class for all scanner modules."""

from __future__ import annotations

import shutil
import subprocess
import time
from abc import ABC, abstractmethod

from rich.console import Console

from nee_tool.core.config import Config
from nee_tool.core.models import ScanResult, ScanStatus

console = Console()


class BaseScanner(ABC):
    """Base class for all scanner plugins.

    Each scanner wraps one or more external tools and produces
    a structured ScanResult. Scanners are designed to be:
    - Self-contained (each module handles its own tool invocation)
    - Graceful (missing tools -> skip with warning, not crash)
    - Chainable (output of one feeds into another via shared Project)
    """

    name: str = "base"
    description: str = ""
    required_tools: list[str] = []

    def __init__(self, config: Config):
        self.config = config

    def check_tools(self) -> list[str]:
        """Check which required tools are available. Returns list of missing tools."""
        missing = []
        for tool in self.required_tools:
            tool_path = getattr(self.config.tools, tool, tool)
            if not shutil.which(tool_path):
                missing.append(tool_path)
        return missing

    def run_command(
        self,
        cmd: list[str],
        timeout: int | None = None,
        stdin_data: str | None = None,
    ) -> subprocess.CompletedProcess:
        """Run an external command and return the result."""
        timeout = timeout or self.config.scan.timeout_per_scanner
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                stdin=subprocess.PIPE if stdin_data else None,
                input=stdin_data,
            )
            return result
        except subprocess.TimeoutExpired:
            console.print(f"  [yellow]Timeout nach {timeout}s für: {' '.join(cmd[:3])}...[/yellow]")
            return subprocess.CompletedProcess(cmd, returncode=-1, stdout="", stderr="TIMEOUT")
        except FileNotFoundError:
            console.print(f"  [red]Tool nicht gefunden: {cmd[0]}[/red]")
            return subprocess.CompletedProcess(cmd, returncode=-1, stdout="", stderr=f"NOT FOUND: {cmd[0]}")

    def execute(self, target: str, previous_results: list[ScanResult] | None = None) -> ScanResult:
        """Execute this scanner with tool checks and timing."""
        missing = self.check_tools()
        if missing:
            console.print(
                f"  [yellow]⚠ Überspringe {self.name}: "
                f"Tool(s) nicht gefunden: {', '.join(missing)}[/yellow]"
            )
            return ScanResult(
                scanner_name=self.name,
                status=ScanStatus.SKIPPED,
                error=f"Missing tools: {', '.join(missing)}",
            )

        console.print(f"  [cyan]▶ {self.name}[/cyan]: {self.description}")
        start = time.time()

        try:
            result = self.scan(target, previous_results or [])
            result.scanner_name = self.name
            result.status = ScanStatus.COMPLETED
            result.duration_seconds = round(time.time() - start, 2)

            host_count = len(result.hosts)
            sub_count = len(result.subdomains)
            finding_count = len(result.findings)
            parts = []
            if host_count:
                parts.append(f"{host_count} Hosts")
            if sub_count:
                parts.append(f"{sub_count} Subdomains")
            if finding_count:
                parts.append(f"{finding_count} Findings")
            summary = ", ".join(parts) if parts else "done"

            console.print(f"  [green]✓ {self.name}[/green] ({result.duration_seconds}s) → {summary}")
            return result

        except Exception as e:
            duration = round(time.time() - start, 2)
            console.print(f"  [red]✗ {self.name}[/red] ({duration}s) → Fehler: {e}")
            return ScanResult(
                scanner_name=self.name,
                status=ScanStatus.FAILED,
                duration_seconds=duration,
                error=str(e),
            )

    @abstractmethod
    def scan(self, target: str, previous_results: list[ScanResult]) -> ScanResult:
        """Implement the actual scan logic. Override this in subclasses."""
        ...
