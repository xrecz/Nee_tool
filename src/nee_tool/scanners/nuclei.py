"""Nuclei vulnerability scanner module.

Runs nuclei with community and custom templates against discovered
web targets. Parses JSON output into structured findings with
severity mapping. Auto-updates templates before scanning.

Supports scan intensity levels:
- light: Only critical/high severity templates
- standard: All severities (default)
- aggressive: Include brute-force + fuzzing templates

Nuclei template categories:
- cves: Known CVE checks
- vulnerabilities: Generic vulnerability checks
- misconfiguration: Server/app misconfigurations
- exposures: Sensitive file/data exposure
- default-logins: Default credential checks
- technologies: Technology detection + version-specific issues
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from tempfile import NamedTemporaryFile
from urllib.parse import urlparse

from nee_tool.core.models import Finding, HostInfo, ScanResult, Severity
from nee_tool.scanners.base import BaseScanner, console

# Map nuclei severity strings to our Severity enum
NUCLEI_SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
    "unknown": Severity.INFO,
}

# Template categories available in nuclei
TEMPLATE_CATEGORIES = [
    "cves",
    "vulnerabilities",
    "misconfiguration",
    "exposures",
    "default-logins",
    "technologies",
]

# Scan intensity presets
INTENSITY_PRESETS = {
    "light": {
        "severity_filter": "critical,high",
        "tags": "cve,misconfig,exposure",
        "rate_limit": 150,
        "bulk_size": 50,
        "concurrency": 15,
        "extra_args": [],
    },
    "standard": {
        "severity_filter": "",  # all severities
        "tags": "cve,misconfig,exposure,vuln,default-login,tech",
        "rate_limit": 100,
        "bulk_size": 25,
        "concurrency": 10,
        "extra_args": [],
    },
    "aggressive": {
        "severity_filter": "",
        "tags": "cve,misconfig,exposure,vuln,default-login,tech,brute-force,fuzz,file",
        "rate_limit": 200,
        "bulk_size": 50,
        "concurrency": 25,
        "extra_args": ["-headless"],
    },
}


class NucleiScanner(BaseScanner):
    name = "nuclei"
    description = "Schwachstellen-Scan (Nuclei CVE/Misconfig/Exposure)"
    required_tools = ["nuclei"]

    def __init__(self, config, intensity: str = "standard"):
        super().__init__(config)
        if intensity not in INTENSITY_PRESETS:
            intensity = "standard"
        self.intensity = intensity
        self.preset = INTENSITY_PRESETS[intensity]

    def _update_templates(self) -> None:
        """Auto-update nuclei templates to get latest CVE checks."""
        nuclei_path = self.config.tools.nuclei
        if not shutil.which(nuclei_path):
            return

        console.print("    [dim]Aktualisiere Nuclei-Templates...[/dim]")
        result = self.run_command([nuclei_path, "-update-templates", "-silent"], timeout=120)
        if result.returncode == 0:
            console.print("    [dim]Templates aktuell.[/dim]")
        else:
            console.print("    [yellow]Template-Update fehlgeschlagen, nutze vorhandene.[/yellow]")

    def _count_templates(self) -> int:
        """Count available nuclei templates."""
        nuclei_path = self.config.tools.nuclei
        if not shutil.which(nuclei_path):
            return 0
        result = self.run_command([nuclei_path, "-tl", "-silent"], timeout=30)
        if result.returncode == 0 and result.stdout:
            return len(result.stdout.strip().splitlines())
        return 0

    def _find_custom_templates(self) -> str | None:
        """Look for custom templates directory."""
        # Check configured path first
        nuclei_templates = getattr(self.config.scan, "nuclei_templates", "")
        if nuclei_templates and Path(nuclei_templates).is_dir():
            return nuclei_templates

        # Check common custom template locations
        custom_dirs = [
            Path.home() / "nuclei-templates-custom",
            Path.home() / ".nuclei" / "custom-templates",
            Path("./custom-templates"),
        ]
        for d in custom_dirs:
            if d.is_dir() and any(d.glob("**/*.yaml")):
                return str(d)

        return None

    def scan(self, target: str, previous_results: list[ScanResult]) -> ScanResult:
        # Update templates before scanning for latest CVEs
        self._update_templates()

        # Log template count
        template_count = self._count_templates()
        if template_count:
            console.print(f"    [dim]{template_count} Templates verfügbar[/dim]")

        console.print(f"    [dim]Intensität: {self.intensity}[/dim]")

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
                        web_targets.add(f"http://{hostname}")
            for sub in prev.subdomains:
                web_targets.add(f"https://{sub}")

        if not web_targets:
            web_targets = {f"https://{target}", f"http://{target}"}

        # Write target list
        with NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as tf:
            tf.write("\n".join(sorted(web_targets)))
            target_file = tf.name

        with NamedTemporaryFile(suffix=".jsonl", delete=False) as jf:
            json_output = jf.name

        cmd = [
            self.config.tools.nuclei,
            "-list", target_file,
            "-jsonl", json_output,
            "-silent",
            "-no-color",
            "-tags", self.preset["tags"],
            "-rate-limit", str(self.preset["rate_limit"]),
            "-bulk-size", str(self.preset["bulk_size"]),
            "-concurrency", str(self.preset["concurrency"]),
        ]

        # Add severity filter
        severity_filter = self.preset["severity_filter"]
        nuclei_severity = getattr(self.config.scan, "nuclei_severity", "")
        if nuclei_severity:
            severity_filter = nuclei_severity
        if severity_filter:
            cmd.extend(["-severity", severity_filter])

        # Add custom templates
        custom_dir = self._find_custom_templates()
        if custom_dir:
            cmd.extend(["-t", custom_dir])
            custom_count = len(list(Path(custom_dir).glob("**/*.yaml")))
            console.print(f"    [dim]{custom_count} Custom-Templates geladen aus {custom_dir}[/dim]")

        # Add template categories
        for category in TEMPLATE_CATEGORIES:
            # nuclei uses these as tags already, but ensure they're included
            pass

        # Extra args for aggressive mode
        cmd.extend(self.preset.get("extra_args", []))

        console.print(f"    [dim]Scanne {len(web_targets)} Targets...[/dim]")
        result = self.run_command(cmd, timeout=self.config.scan.timeout_per_scanner)

        findings, hosts = self._parse_results(json_output)

        # Log results
        if findings:
            console.print(f"    [dim]{len(findings)} Findings aus Nuclei-Scan[/dim]")

        # Cleanup
        Path(target_file).unlink(missing_ok=True)
        Path(json_output).unlink(missing_ok=True)

        return ScanResult(
            scanner_name=self.name,
            findings=findings,
            hosts=hosts,
            raw_output=result.stdout[-2000:] if result.stdout else "",
            data={"template_count": template_count, "intensity": self.intensity},
        )

    def _parse_results(self, json_path: str) -> tuple[list[Finding], list[HostInfo]]:
        """Parse nuclei JSONL output into findings and host info."""
        findings: list[Finding] = []
        hosts_map: dict[str, HostInfo] = {}

        try:
            content = Path(json_path).read_text()
        except FileNotFoundError:
            return findings, []

        for line in content.strip().splitlines():
            if not line.strip():
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue

            # Extract finding info
            info = entry.get("info", {})
            template_id = entry.get("template-id", "unknown")
            matched_at = entry.get("matched-at", "")
            host = entry.get("host", "")
            matcher_name = entry.get("matcher-name", "")
            template_url = entry.get("template-url", "")
            timestamp = entry.get("timestamp", "")

            severity_str = info.get("severity", "info").lower()
            severity = NUCLEI_SEVERITY_MAP.get(severity_str, Severity.INFO)

            name = info.get("name", template_id)
            description = info.get("description", "")
            references = info.get("reference", [])
            if isinstance(references, str):
                references = [references] if references else []
            if references is None:
                references = []
            tags = info.get("tags", [])
            if isinstance(tags, str):
                tags = [t.strip() for t in tags.split(",")]
            if tags is None:
                tags = []

            # Build evidence
            evidence_parts = [f"Template: {template_id}"]
            if matched_at:
                evidence_parts.append(f"Matched at: {matched_at}")
            if matcher_name:
                evidence_parts.append(f"Matcher: {matcher_name}")
            if timestamp:
                evidence_parts.append(f"Timestamp: {timestamp}")

            extracted = entry.get("extracted-results", [])
            if extracted:
                evidence_parts.append(f"Extracted: {', '.join(str(e) for e in extracted[:5])}")

            # Include request/response if available
            request = entry.get("request", "")
            response = entry.get("response", "")
            if request:
                evidence_parts.append(f"\nRequest:\n{request[:500]}")
            if response:
                evidence_parts.append(f"\nResponse (truncated):\n{response[:500]}")

            curl_cmd = entry.get("curl-command", "")
            if curl_cmd:
                evidence_parts.append(f"\n{curl_cmd}")

            # Classification data
            classification = info.get("classification", {})
            cvss_metrics = classification.get("cvss-metrics", "")
            cvss_score = classification.get("cvss-score", "")
            cve_id = classification.get("cve-id", "")
            cwe_id = classification.get("cwe-id", "")

            # Remediation
            remediation = info.get("remediation", "")

            # Build title with hostname
            title = name
            if host:
                parsed = urlparse(host)
                hostname = parsed.hostname or host
                title = f"{name} ({hostname})"

            # Build tags
            finding_tags = list(tags)
            if cve_id:
                if isinstance(cve_id, list):
                    finding_tags.extend([f"CVE: {c}" for c in cve_id])
                else:
                    finding_tags.append(f"CVE: {cve_id}")
            if cvss_score:
                finding_tags.append(f"CVSS: {cvss_score}")
            if cwe_id:
                if isinstance(cwe_id, list):
                    finding_tags.extend([f"CWE: {c}" for c in cwe_id])
                else:
                    finding_tags.append(f"CWE: {cwe_id}")
            if cvss_metrics:
                finding_tags.append(f"Vector: {cvss_metrics}")

            # Build references
            finding_refs = [r for r in references if r]
            if template_url:
                finding_refs.append(template_url)

            finding = Finding(
                title=title,
                severity=severity,
                description=description or f"Nuclei Template '{template_id}' hat einen Treffer auf {matched_at} ergeben.",
                evidence="\n".join(evidence_parts),
                recommendation=remediation or f"Siehe Referenzen zum Template '{template_id}' für Behebungsmaßnahmen.",
                references=finding_refs,
                tags=finding_tags,
            )
            findings.append(finding)

            # Track affected hosts
            if host:
                parsed = urlparse(host)
                hostname = parsed.hostname or host
                if hostname not in hosts_map:
                    hosts_map[hostname] = HostInfo(hostname=hostname, is_web=True)

        return findings, list(hosts_map.values())
