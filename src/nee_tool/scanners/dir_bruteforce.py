"""Directory brute-force scanner.

Uses feroxbuster or ffuf to discover hidden paths, files,
and directories on web targets. Parses JSON output for findings.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from tempfile import NamedTemporaryFile

from nee_tool.core.models import Finding, HostInfo, ScanResult, Severity
from nee_tool.scanners.base import BaseScanner, console

# Interesting status codes and what they mean
INTERESTING_CODES = {200, 201, 301, 302, 307, 308, 401, 403, 405, 500}

# Patterns that indicate sensitive files
SENSITIVE_PATTERNS = [
    ".env", ".git", ".svn", ".htaccess", ".htpasswd",
    "wp-config", "config.php", "config.yml", "config.json",
    "backup", "dump", ".sql", ".bak", ".old", ".swp",
    "phpinfo", "server-status", "server-info",
    ".DS_Store", "Thumbs.db", "web.config",
    "robots.txt", "sitemap.xml", "crossdomain.xml",
    "admin", "login", "dashboard", "phpmyadmin",
    "api/swagger", "api/docs", "graphql",
    "debug", "trace", "test",
]


class DirBruteforceScanner(BaseScanner):
    name = "dir_bruteforce"
    description = "Directory/File Discovery (feroxbuster/ffuf)"
    required_tools: list[str] = []  # Checks dynamically

    def scan(self, target: str, previous_results: list[ScanResult]) -> ScanResult:
        # Find web targets from previous results
        web_targets: set[str] = set()
        for prev in previous_results:
            for host in prev.hosts:
                if host.is_web:
                    hostname = host.hostname or host.ip
                    web_targets.add(hostname)

        if not web_targets:
            web_targets = {target}

        # Check which tool is available
        has_ferox = bool(shutil.which(self.config.tools.feroxbuster))
        has_ffuf = bool(shutil.which("ffuf"))

        if not has_ferox and not has_ffuf:
            console.print("  [yellow]Weder feroxbuster noch ffuf verfügbar, überspringe.[/yellow]")
            return ScanResult(
                scanner_name=self.name,
                error="Missing tools: feroxbuster or ffuf",
            )

        all_findings: list[Finding] = []
        all_hosts: list[HostInfo] = []
        raw_parts: list[str] = []

        for host in sorted(web_targets):
            for scheme in ["https", "http"]:
                url = f"{scheme}://{host}"
                if has_ferox:
                    found, findings = self._run_feroxbuster(url)
                else:
                    found, findings = self._run_ffuf(url)

                if found:
                    all_findings.extend(findings)
                    all_hosts.append(HostInfo(
                        hostname=host,
                        is_web=True,
                        services=[f"{len(found)} paths discovered"],
                    ))
                    raw_parts.append(f"{host}: {len(found)} paths")
                    break  # One scheme worked, skip other

        return ScanResult(
            scanner_name=self.name,
            findings=all_findings,
            hosts=all_hosts,
            raw_output="\n".join(raw_parts),
        )

    def _run_feroxbuster(self, url: str) -> tuple[list[dict], list[Finding]]:
        """Run feroxbuster against a URL."""
        with NamedTemporaryFile(suffix=".json", delete=False) as jf:
            json_output = jf.name

        cmd = [
            self.config.tools.feroxbuster,
            "-u", url,
            "-o", json_output,
            "--json",
            "--quiet",
            "--no-state",
            "--auto-tune",
            "--threads", "20",
            "--timeout", "10",
            "--depth", "2",
            "--status-codes", ",".join(str(c) for c in INTERESTING_CODES),
        ]

        self.run_command(cmd, timeout=self.config.scan.timeout_per_scanner)

        found = []
        findings = []
        try:
            for line in Path(json_output).read_text().strip().splitlines():
                if not line.strip():
                    continue
                try:
                    entry = json.loads(line)
                    if entry.get("type") == "response":
                        found.append(entry)
                        finding = self._entry_to_finding(
                            entry.get("url", ""),
                            entry.get("status", 0),
                            entry.get("content_length", 0),
                            url,
                        )
                        if finding:
                            findings.append(finding)
                except json.JSONDecodeError:
                    continue
        except FileNotFoundError:
            pass

        Path(json_output).unlink(missing_ok=True)
        return found, findings

    def _run_ffuf(self, url: str) -> tuple[list[dict], list[Finding]]:
        """Run ffuf against a URL."""
        with NamedTemporaryFile(suffix=".json", delete=False) as jf:
            json_output = jf.name

        # ffuf needs a wordlist — use a common one
        wordlists = [
            "/usr/share/wordlists/dirb/common.txt",
            "/usr/share/seclists/Discovery/Web-Content/common.txt",
            "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt",
        ]
        wordlist = next((w for w in wordlists if Path(w).exists()), "")
        if not wordlist:
            console.print("    [dim]Keine Wordlist gefunden für ffuf[/dim]")
            return [], []

        cmd = [
            "ffuf",
            "-u", f"{url}/FUZZ",
            "-w", wordlist,
            "-o", json_output,
            "-of", "json",
            "-mc", ",".join(str(c) for c in INTERESTING_CODES),
            "-t", "20",
            "-timeout", "10",
            "-s",  # Silent
        ]

        self.run_command(cmd, timeout=self.config.scan.timeout_per_scanner)

        found = []
        findings = []
        try:
            data = json.loads(Path(json_output).read_text())
            for result in data.get("results", []):
                found.append(result)
                finding = self._entry_to_finding(
                    result.get("url", ""),
                    result.get("status", 0),
                    result.get("length", 0),
                    url,
                )
                if finding:
                    findings.append(finding)
        except (json.JSONDecodeError, FileNotFoundError):
            pass

        Path(json_output).unlink(missing_ok=True)
        return found, findings

    def _entry_to_finding(self, url: str, status: int, size: int, base_url: str) -> Finding | None:
        """Convert a discovered path to a finding if it's interesting."""
        path = url.replace(base_url, "").rstrip("/") or "/"
        lower_path = path.lower()

        # Check for sensitive patterns
        is_sensitive = any(p in lower_path for p in SENSITIVE_PATTERNS)

        if status == 200 and is_sensitive:
            return Finding(
                title=f"Sensible Datei/Pfad exponiert: {path}",
                severity=Severity.MEDIUM if ".env" in lower_path or ".git" in lower_path or "backup" in lower_path else Severity.LOW,
                description=f"Unter {url} wurde eine potentiell sensible Ressource gefunden (HTTP {status}, {size} Bytes).",
                evidence=f"GET {url} → HTTP {status} ({size} Bytes)",
                recommendation="Zugriff auf diese Ressource einschränken oder die Datei aus dem Web-Root entfernen.",
                tags=["directory-brute", "information-disclosure"],
            )

        if status == 401 or status == 403:
            return Finding(
                title=f"Geschützter Pfad entdeckt: {path}",
                severity=Severity.INFO,
                description=f"Unter {url} wurde ein geschützter Bereich entdeckt (HTTP {status}).",
                evidence=f"GET {url} → HTTP {status}",
                tags=["directory-brute"],
            )

        return None
