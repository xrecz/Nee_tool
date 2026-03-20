"""Subdomain enumeration scanner.

Uses subfinder for passive subdomain discovery and falls back
to crt.sh certificate transparency logs if subfinder is unavailable.
"""

from __future__ import annotations

import json
import urllib.request
import urllib.error

from nee_tool.core.models import ScanResult
from nee_tool.scanners.base import BaseScanner, console


class SubdomainScanner(BaseScanner):
    name = "subdomain"
    description = "Subdomain-Enumeration (subfinder + crt.sh)"
    required_tools: list[str] = []  # crt.sh works without tools

    def scan(self, target: str, previous_results: list[ScanResult]) -> ScanResult:
        subdomains: set[str] = set()
        raw_parts: list[str] = []

        # Try subfinder first
        subs_from_subfinder = self._run_subfinder(target)
        if subs_from_subfinder is not None:
            subdomains.update(subs_from_subfinder)
            raw_parts.append(f"subfinder: {len(subs_from_subfinder)} results")

        # Always also try crt.sh for additional coverage
        subs_from_crt = self._query_crtsh(target)
        if subs_from_crt is not None:
            subdomains.update(subs_from_crt)
            raw_parts.append(f"crt.sh: {len(subs_from_crt)} results")

        # Always include the base domain
        subdomains.add(target)

        return ScanResult(
            scanner_name=self.name,
            subdomains=sorted(subdomains),
            raw_output="\n".join(raw_parts),
        )

    def _run_subfinder(self, target: str) -> list[str] | None:
        """Run subfinder for passive subdomain enumeration."""
        import shutil

        if not shutil.which(self.config.tools.subfinder):
            console.print("    [dim]subfinder nicht verfügbar, nutze nur crt.sh[/dim]")
            return None

        cmd = [self.config.tools.subfinder, "-d", target, "-silent", "-json"]
        result = self.run_command(cmd, timeout=120)

        if result.returncode != 0:
            return None

        subs = []
        for line in result.stdout.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                host = data.get("host", "")
                if host:
                    subs.append(host.lower())
            except json.JSONDecodeError:
                # Plain text output (older subfinder versions)
                if "." in line:
                    subs.append(line.lower())
        return subs

    def _query_crtsh(self, target: str) -> list[str] | None:
        """Query crt.sh certificate transparency logs."""
        url = f"https://crt.sh/?q=%.{target}&output=json"
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Nee-Tool/0.1"})
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = json.loads(resp.read().decode())

            subs = set()
            for entry in data:
                name = entry.get("name_value", "")
                for part in name.split("\n"):
                    part = part.strip().lower()
                    if part and "*" not in part and part.endswith(f".{target}") or part == target:
                        subs.add(part)
            return sorted(subs)

        except (urllib.error.URLError, json.JSONDecodeError, TimeoutError) as e:
            console.print(f"    [dim]crt.sh nicht erreichbar: {e}[/dim]")
            return None
