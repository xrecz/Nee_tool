"""Web crawler scanner.

Crawls web targets to discover endpoints, forms, API routes, and
JavaScript files. Feeds discovered URLs to downstream scanners
(nuclei, dir_bruteforce) for deeper analysis.

Uses katana (preferred) or gospider as external crawlers, with a
basic Python urllib fallback for link extraction.
"""

from __future__ import annotations

import json
import re
import shutil
import ssl
import urllib.error
import urllib.request
from html.parser import HTMLParser
from tempfile import NamedTemporaryFile

from nee_tool.core.models import Finding, HostInfo, ScanResult, Severity
from nee_tool.scanners.base import BaseScanner, console


class _LinkParser(HTMLParser):
    """Simple HTML parser to extract links and form actions."""

    def __init__(self) -> None:
        super().__init__()
        self.links: list[str] = []
        self.forms: list[str] = []
        self.scripts: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attr_dict = dict(attrs)
        if tag == "a" and attr_dict.get("href"):
            self.links.append(attr_dict["href"])
        elif tag == "form" and attr_dict.get("action"):
            self.forms.append(attr_dict["action"])
        elif tag == "script" and attr_dict.get("src"):
            self.scripts.append(attr_dict["src"])
        elif tag == "link" and attr_dict.get("href"):
            self.links.append(attr_dict["href"])


class CrawlerScanner(BaseScanner):
    name = "crawler"
    description = "Web-Crawler (Endpoint/JS/Form Discovery)"
    required_tools: list[str] = []  # Python fallback available

    def scan(self, target: str, previous_results: list[ScanResult]) -> ScanResult:
        # Collect web targets from previous results
        web_targets: set[str] = set()
        for prev in previous_results:
            for host in prev.hosts:
                if host.is_web:
                    hostname = host.hostname or host.ip
                    if any(p.port == 443 for p in host.ports):
                        web_targets.add(f"https://{hostname}")
                    elif any(p.port == 80 for p in host.ports):
                        web_targets.add(f"http://{hostname}")
                    else:
                        web_targets.add(f"https://{hostname}")

        if not web_targets:
            web_targets = {f"https://{target}", f"http://{target}"}

        # Choose crawler tool
        katana_path = getattr(self.config.tools, "katana", "katana")
        gospider_path = getattr(self.config.tools, "gospider", "gospider")

        if shutil.which(katana_path):
            return self._run_katana(sorted(web_targets), katana_path)
        elif shutil.which(gospider_path):
            return self._run_gospider(sorted(web_targets), gospider_path)
        else:
            console.print("    [dim]katana/gospider nicht verfügbar, nutze Python-Fallback[/dim]")
            return self._python_crawl(sorted(web_targets))

    def _run_katana(self, targets: list[str], tool_path: str) -> ScanResult:
        """Use katana for JavaScript-aware crawling."""
        with NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as tf:
            tf.write("\n".join(targets))
            target_file = tf.name

        with NamedTemporaryFile(suffix=".jsonl", delete=False) as jf:
            json_output = jf.name

        cmd = [
            tool_path,
            "-list", target_file,
            "-jsonl",
            "-output", json_output,
            "-silent",
            "-depth", "3",
            "-js-crawl",
            "-known-files", "all",
            "-form-extraction",
            "-timeout", "10",
            "-rate-limit", "50",
            "-concurrency", "10",
        ]

        console.print(f"    [dim]Crawle {len(targets)} Targets mit katana...[/dim]")
        self.run_command(cmd, timeout=self.config.scan.timeout_per_scanner)

        urls, findings = self._parse_katana_output(json_output)

        # Cleanup
        from pathlib import Path
        Path(target_file).unlink(missing_ok=True)
        Path(json_output).unlink(missing_ok=True)

        return ScanResult(
            scanner_name=self.name,
            findings=findings,
            data={"crawled_urls": sorted(urls)[:500]},
        )

    def _parse_katana_output(self, json_path: str) -> tuple[set[str], list[Finding]]:
        """Parse katana JSONL output."""
        urls: set[str] = set()
        findings: list[Finding] = []
        sensitive_patterns = self._get_sensitive_patterns()

        try:
            from pathlib import Path
            content = Path(json_path).read_text()
        except FileNotFoundError:
            return urls, findings

        for line in content.strip().splitlines():
            if not line.strip():
                continue
            try:
                entry = json.loads(line)
                url = entry.get("request", {}).get("endpoint", "") or entry.get("url", "")
                if url:
                    urls.add(url)
                    # Check for sensitive patterns
                    for pattern, desc, sev in sensitive_patterns:
                        if pattern.search(url):
                            findings.append(Finding(
                                title=f"Sensible URL entdeckt: {desc}",
                                severity=sev,
                                description=f"Der Crawler hat eine potenziell sensible URL gefunden.",
                                evidence=f"URL: {url}",
                                recommendation=f"Prüfen ob der Zugriff auf diese Ressource eingeschränkt ist.",
                                tags=["crawler", "sensitive-url"],
                            ))
                            break
            except json.JSONDecodeError:
                # Katana may output plain URLs too
                url = line.strip()
                if url.startswith("http"):
                    urls.add(url)

        return urls, findings

    def _run_gospider(self, targets: list[str], tool_path: str) -> ScanResult:
        """Use gospider for web crawling."""
        all_urls: set[str] = set()
        all_findings: list[Finding] = []

        for target_url in targets:
            cmd = [
                tool_path,
                "-s", target_url,
                "--json",
                "-q",
                "-d", "3",
                "-t", "5",
                "--timeout", "10",
            ]

            result = self.run_command(cmd, timeout=120)
            if result.stdout:
                urls, findings = self._parse_gospider_output(result.stdout)
                all_urls.update(urls)
                all_findings.extend(findings)

        return ScanResult(
            scanner_name=self.name,
            findings=all_findings,
            data={"crawled_urls": sorted(all_urls)[:500]},
        )

    def _parse_gospider_output(self, output: str) -> tuple[set[str], list[Finding]]:
        """Parse gospider JSON output."""
        urls: set[str] = set()
        findings: list[Finding] = []
        sensitive_patterns = self._get_sensitive_patterns()

        for line in output.strip().splitlines():
            try:
                entry = json.loads(line)
                url = entry.get("output", "")
                if url and url.startswith("http"):
                    urls.add(url)
                    for pattern, desc, sev in sensitive_patterns:
                        if pattern.search(url):
                            findings.append(Finding(
                                title=f"Sensible URL entdeckt: {desc}",
                                severity=sev,
                                description=f"Der Crawler hat eine potenziell sensible URL gefunden.",
                                evidence=f"URL: {url}",
                                recommendation=f"Prüfen ob der Zugriff auf diese Ressource eingeschränkt ist.",
                                tags=["crawler", "sensitive-url"],
                            ))
                            break
            except json.JSONDecodeError:
                continue

        return urls, findings

    def _python_crawl(self, targets: list[str]) -> ScanResult:
        """Fallback: Basic Python link extraction from HTML."""
        all_urls: set[str] = set()
        all_findings: list[Finding] = []
        sensitive_patterns = self._get_sensitive_patterns()

        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        for base_url in targets:
            try:
                req = urllib.request.Request(base_url, headers={"User-Agent": "Nee-Tool/0.1"})
                scheme = "https" if base_url.startswith("https") else "http"
                handler = urllib.request.HTTPSHandler(context=ctx) if scheme == "https" else urllib.request.HTTPHandler()
                opener = urllib.request.build_opener(handler)

                with opener.open(req, timeout=15) as resp:
                    body = resp.read(131072).decode("utf-8", errors="replace")

                parser = _LinkParser()
                parser.feed(body)

                from urllib.parse import urljoin

                # Collect and normalize URLs
                for link in parser.links + parser.forms + parser.scripts:
                    if not link or link.startswith("#") or link.startswith("javascript:"):
                        continue
                    full_url = urljoin(base_url, link)
                    all_urls.add(full_url)

                # Check for sensitive patterns in discovered URLs
                for url in all_urls:
                    for pattern, desc, sev in sensitive_patterns:
                        if pattern.search(url):
                            all_findings.append(Finding(
                                title=f"Sensible URL entdeckt: {desc}",
                                severity=sev,
                                description=f"Der Crawler hat eine potenziell sensible URL gefunden.",
                                evidence=f"URL: {url}",
                                recommendation=f"Prüfen ob der Zugriff auf diese Ressource eingeschränkt ist.",
                                tags=["crawler", "sensitive-url"],
                            ))
                            break

                # Also find inline API endpoints via regex
                api_pattern = re.compile(r'["\'](/api/[^"\']+)["\']')
                for match in api_pattern.finditer(body):
                    from urllib.parse import urljoin
                    api_url = urljoin(base_url, match.group(1))
                    all_urls.add(api_url)

                console.print(f"    [dim]{base_url}: {len(parser.links)} Links, "
                             f"{len(parser.scripts)} JS, {len(parser.forms)} Forms[/dim]")

            except Exception:
                continue

        return ScanResult(
            scanner_name=self.name,
            findings=all_findings,
            data={"crawled_urls": sorted(all_urls)[:500]},
        )

    @staticmethod
    def _get_sensitive_patterns() -> list[tuple[re.Pattern, str, Severity]]:
        """Patterns for potentially sensitive URLs."""
        return [
            (re.compile(r'\.env($|\?)', re.I), ".env Datei", Severity.HIGH),
            (re.compile(r'\.git/', re.I), ".git Verzeichnis", Severity.HIGH),
            (re.compile(r'wp-admin|wp-login', re.I), "WordPress Admin", Severity.MEDIUM),
            (re.compile(r'phpmyadmin', re.I), "phpMyAdmin", Severity.MEDIUM),
            (re.compile(r'/admin[/]?$', re.I), "Admin-Panel", Severity.MEDIUM),
            (re.compile(r'swagger|openapi|api-docs', re.I), "API-Dokumentation", Severity.LOW),
            (re.compile(r'graphql', re.I), "GraphQL Endpoint", Severity.LOW),
            (re.compile(r'\.(sql|bak|old|backup|dump)', re.I), "Backup/Dump Datei", Severity.HIGH),
            (re.compile(r'debug|trace|phpinfo', re.I), "Debug-Endpoint", Severity.MEDIUM),
            (re.compile(r'\.config|web\.config', re.I), "Konfigurations-Datei", Severity.MEDIUM),
        ]
