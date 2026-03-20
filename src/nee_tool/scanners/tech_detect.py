"""Technology detection scanner.

Identifies web technologies, frameworks, and CMS systems.
Uses whatweb when available, with a basic Python fallback
that checks common response patterns.
"""

from __future__ import annotations

import json
import re
import shutil
import ssl
import urllib.request

from nee_tool.core.models import HostInfo, ScanResult
from nee_tool.scanners.base import BaseScanner, console

# Simple signature-based detection patterns
TECH_SIGNATURES = [
    # (name, header_pattern, body_pattern)
    ("WordPress", None, re.compile(r'wp-content|wp-includes|wordpress', re.I)),
    ("Joomla", None, re.compile(r'/media/jui/|/components/com_', re.I)),
    ("Drupal", None, re.compile(r'Drupal|sites/default/files', re.I)),
    ("jQuery", None, re.compile(r'jquery[.-][\d.]+(?:\.min)?\.js', re.I)),
    ("Bootstrap", None, re.compile(r'bootstrap[.-][\d.]*(?:\.min)?\.(?:css|js)', re.I)),
    ("React", None, re.compile(r'react(?:\.production|\.development|dom)', re.I)),
    ("Vue.js", None, re.compile(r'vue[.-][\d.]*(?:\.min)?\.js|__vue', re.I)),
    ("Angular", None, re.compile(r'ng-version|angular[.-][\d.]*\.js', re.I)),
    ("PHP", "x-powered-by", re.compile(r'PHP', re.I)),
    ("ASP.NET", "x-powered-by", re.compile(r'ASP\.NET', re.I)),
    ("nginx", "server", re.compile(r'nginx', re.I)),
    ("Apache", "server", re.compile(r'Apache', re.I)),
    ("IIS", "server", re.compile(r'Microsoft-IIS', re.I)),
    ("Cloudflare", "server", re.compile(r'cloudflare', re.I)),
    ("Next.js", None, re.compile(r'_next/static|__NEXT_DATA__', re.I)),
    ("Nuxt.js", None, re.compile(r'__nuxt|_nuxt/', re.I)),
    ("Laravel", None, re.compile(r'laravel', re.I)),
]


class TechDetectScanner(BaseScanner):
    name = "tech_detect"
    description = "Technologie-Erkennung (Frameworks, CMS, Server)"
    required_tools: list[str] = []

    def scan(self, target: str, previous_results: list[ScanResult]) -> ScanResult:
        # Find web hosts
        web_hosts: set[str] = set()
        for prev in previous_results:
            for host in prev.hosts:
                if host.is_web:
                    web_hosts.add(host.hostname or host.ip)

        if not web_hosts:
            web_hosts = {target}

        if shutil.which(self.config.tools.whatweb):
            return self._run_whatweb(sorted(web_hosts))
        else:
            console.print("    [dim]whatweb nicht verfügbar, nutze Signatur-Erkennung[/dim]")
            return self._python_detect(sorted(web_hosts))

    def _run_whatweb(self, hosts: list[str]) -> ScanResult:
        """Use whatweb for detailed technology detection."""
        all_hosts: list[HostInfo] = []

        for host in hosts:
            cmd = [
                self.config.tools.whatweb,
                "--log-json=-",
                "--quiet",
                f"https://{host}",
            ]
            result = self.run_command(cmd, timeout=30)

            if result.returncode != 0:
                # Try HTTP
                cmd[-1] = f"http://{host}"
                result = self.run_command(cmd, timeout=30)

            if result.stdout.strip():
                try:
                    for line in result.stdout.strip().splitlines():
                        data = json.loads(line)
                        plugins = data.get("plugins", {})
                        techs = [name for name in plugins if name not in ("HttpOnly", "IP", "Country", "UncommonHeaders")]
                        all_hosts.append(HostInfo(
                            hostname=host,
                            is_web=True,
                            technologies=techs,
                        ))
                except json.JSONDecodeError:
                    pass

        return ScanResult(scanner_name=self.name, hosts=all_hosts)

    def _python_detect(self, hosts: list[str]) -> ScanResult:
        """Fallback: signature-based detection."""
        all_hosts: list[HostInfo] = []
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        for host in hosts:
            techs: list[str] = []
            headers: dict[str, str] = {}
            body = ""

            for scheme in ["https", "http"]:
                url = f"{scheme}://{host}"
                try:
                    req = urllib.request.Request(url, headers={"User-Agent": "Nee-Tool/0.1"})
                    handler = urllib.request.HTTPSHandler(context=ctx) if scheme == "https" else urllib.request.HTTPHandler()
                    opener = urllib.request.build_opener(handler)
                    with opener.open(req, timeout=10) as resp:
                        headers = {k.lower(): v for k, v in resp.headers.items()}
                        body = resp.read(32768).decode("utf-8", errors="replace")
                        break
                except Exception:
                    continue

            if not headers and not body:
                continue

            for name, header_key, pattern in TECH_SIGNATURES:
                if header_key:
                    header_val = headers.get(header_key, "")
                    if pattern.search(header_val):
                        techs.append(name)
                else:
                    if pattern.search(body):
                        techs.append(name)

            all_hosts.append(HostInfo(
                hostname=host,
                is_web=True,
                technologies=sorted(set(techs)),
            ))

        return ScanResult(scanner_name=self.name, hosts=all_hosts)
