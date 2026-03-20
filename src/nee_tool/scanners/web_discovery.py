"""Web discovery scanner.

Probes discovered hosts for HTTP/HTTPS services using httpx,
with a Python fallback when httpx is not installed.
"""

from __future__ import annotations

import json
import ssl
import urllib.request
import urllib.error

from nee_tool.core.models import HostInfo, ScanResult
from nee_tool.scanners.base import BaseScanner, console


class WebDiscoveryScanner(BaseScanner):
    name = "web_discovery"
    description = "Web-Discovery (HTTP/HTTPS Probing)"
    required_tools: list[str] = []  # Python fallback available

    def scan(self, target: str, previous_results: list[ScanResult]) -> ScanResult:
        # Collect all known hosts/subdomains
        targets = {target}
        for prev in previous_results:
            targets.update(prev.subdomains)
            for host in prev.hosts:
                targets.add(host.hostname or host.ip)

        # Try httpx first, fall back to Python
        import shutil

        if shutil.which(self.config.tools.httpx):
            return self._run_httpx(sorted(targets))
        else:
            console.print("    [dim]httpx nicht verfügbar, nutze Python-Fallback[/dim]")
            return self._python_probe(sorted(targets))

    def _run_httpx(self, targets: list[str]) -> ScanResult:
        """Use httpx for fast HTTP probing."""
        stdin_data = "\n".join(targets)
        cmd = [
            self.config.tools.httpx,
            "-silent",
            "-json",
            "-title",
            "-status-code",
            "-tech-detect",
            "-threads", str(self.config.scan.httpx_threads),
            "-timeout", str(self.config.scan.httpx_timeout),
        ]

        result = self.run_command(cmd, stdin_data=stdin_data, timeout=120)
        hosts = []

        for line in result.stdout.strip().splitlines():
            if not line.strip():
                continue
            try:
                data = json.loads(line)
                host = data.get("input", data.get("host", ""))
                hosts.append(HostInfo(
                    hostname=host,
                    is_web=True,
                    status_code=data.get("status_code", 0),
                    title=data.get("title", ""),
                    technologies=data.get("tech", []),
                ))
            except json.JSONDecodeError:
                continue

        return ScanResult(scanner_name=self.name, hosts=hosts)

    def _python_probe(self, targets: list[str]) -> ScanResult:
        """Fallback: probe with Python urllib."""
        hosts = []
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        for host in targets:
            for scheme in ["https", "http"]:
                url = f"{scheme}://{host}"
                try:
                    req = urllib.request.Request(
                        url,
                        headers={"User-Agent": "Nee-Tool/0.1"},
                        method="GET",
                    )
                    handler = urllib.request.HTTPSHandler(context=ctx) if scheme == "https" else urllib.request.HTTPHandler()
                    opener = urllib.request.build_opener(handler)
                    with opener.open(req, timeout=self.config.scan.httpx_timeout) as resp:
                        body = resp.read(8192).decode("utf-8", errors="replace")
                        title = ""
                        if "<title>" in body.lower():
                            start = body.lower().index("<title>") + 7
                            end = body.lower().index("</title>", start) if "</title>" in body.lower() else start + 100
                            title = body[start:end].strip()

                        hosts.append(HostInfo(
                            hostname=host,
                            is_web=True,
                            status_code=resp.status,
                            title=title,
                        ))
                        break  # HTTPS worked, skip HTTP
                except Exception:
                    continue

        return ScanResult(scanner_name=self.name, hosts=hosts)
