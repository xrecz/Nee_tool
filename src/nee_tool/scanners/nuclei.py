"""Nuclei vulnerability scanner module.

Runs nuclei with community and custom templates against discovered
web targets. Parses JSON output into structured findings with
severity mapping.

Nuclei template categories used:
- cves: Known CVE checks
- vulnerabilities: Generic vulnerability checks
- misconfiguration: Server/app misconfigurations
- exposures: Sensitive file/data exposure
- technologies: Technology detection + version-specific issues
"""

from __future__ import annotations

import json
from pathlib import Path
from tempfile import NamedTemporaryFile

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


class NucleiScanner(BaseScanner):
    name = "nuclei"
    description = "Schwachstellen-Scan (Nuclei CVE/Misconfig/Exposure)"
    required_tools = ["nuclei"]

    def scan(self, target: str, previous_results: list[ScanResult]) -> ScanResult:
        # Collect web targets from previous results
        web_targets: set[str] = set()
        for prev in previous_results:
            for host in prev.hosts:
                if host.is_web:
                    hostname = host.hostname or host.ip
                    # Add with scheme based on known ports
                    if any(p.port == 443 for p in host.ports):
                        web_targets.add(f"https://{hostname}")
                    elif any(p.port == 80 for p in host.ports):
                        web_targets.add(f"http://{hostname}")
                    else:
                        web_targets.add(f"https://{hostname}")
                        web_targets.add(f"http://{hostname}")
            # Also add subdomains as https targets
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
            # Scan categories
            "-tags", "cve,misconfig,exposure,vuln",
            # Rate limiting to be polite
            "-rate-limit", "100",
            "-bulk-size", "25",
            "-concurrency", "10",
        ]

        # Add severity filter if configured
        nuclei_severity = getattr(self.config.scan, "nuclei_severity", "")
        if nuclei_severity:
            cmd.extend(["-severity", nuclei_severity])

        # Add custom templates path if configured
        nuclei_templates = getattr(self.config.scan, "nuclei_templates", "")
        if nuclei_templates:
            cmd.extend(["-t", nuclei_templates])

        console.print(f"    [dim]Scanne {len(web_targets)} Targets...[/dim]")
        result = self.run_command(cmd, timeout=self.config.scan.timeout_per_scanner)

        findings, hosts = self._parse_results(json_output)

        # Cleanup
        Path(target_file).unlink(missing_ok=True)
        Path(json_output).unlink(missing_ok=True)

        return ScanResult(
            scanner_name=self.name,
            findings=findings,
            hosts=hosts,
            raw_output=result.stdout[-2000:] if result.stdout else "",
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

            severity_str = info.get("severity", "info").lower()
            severity = NUCLEI_SEVERITY_MAP.get(severity_str, Severity.INFO)

            name = info.get("name", template_id)
            description = info.get("description", "")
            references = info.get("reference", [])
            if isinstance(references, str):
                references = [references] if references else []
            tags = info.get("tags", [])
            if isinstance(tags, str):
                tags = [t.strip() for t in tags.split(",")]

            # Build evidence
            evidence_parts = [f"Template: {template_id}"]
            if matched_at:
                evidence_parts.append(f"Matched at: {matched_at}")
            if matcher_name:
                evidence_parts.append(f"Matcher: {matcher_name}")

            extracted = entry.get("extracted-results", [])
            if extracted:
                evidence_parts.append(f"Extracted: {', '.join(str(e) for e in extracted[:5])}")

            curl_cmd = entry.get("curl-command", "")
            if curl_cmd:
                evidence_parts.append(f"\n{curl_cmd}")

            # Remediation
            remediation = info.get("remediation", "")
            classification = info.get("classification", {})
            cvss_score = classification.get("cvss-score", "")
            cve_id = classification.get("cve-id", "")

            title = name
            if host:
                # Extract hostname from URL
                from urllib.parse import urlparse
                parsed = urlparse(host)
                hostname = parsed.hostname or host
                title = f"{name} ({hostname})"

            finding = Finding(
                title=title,
                severity=severity,
                description=description or f"Nuclei Template '{template_id}' hat einen Treffer auf {matched_at} ergeben.",
                evidence="\n".join(evidence_parts),
                recommendation=remediation or f"Siehe Referenzen zum Template '{template_id}' für Behebungsmaßnahmen.",
                references=[r for r in references if r],
                tags=tags + ([f"CVE: {cve_id}"] if cve_id else []) + ([f"CVSS: {cvss_score}"] if cvss_score else []),
            )
            findings.append(finding)

            # Track affected hosts
            if host:
                from urllib.parse import urlparse
                parsed = urlparse(host)
                hostname = parsed.hostname or host
                if hostname not in hosts_map:
                    hosts_map[hostname] = HostInfo(hostname=hostname, is_web=True)

        return findings, list(hosts_map.values())
