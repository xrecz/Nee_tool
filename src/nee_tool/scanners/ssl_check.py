"""SSL/TLS analysis scanner.

Checks certificates for validity, expiry, and basic TLS configuration.
Uses testssl.sh when available, with a Python ssl fallback.
"""

from __future__ import annotations

import json
import shutil
import socket
import ssl
from datetime import datetime, timezone

from nee_tool.core.models import Finding, HostInfo, ScanResult, Severity
from nee_tool.scanners.base import BaseScanner, console


class SSLCheckScanner(BaseScanner):
    name = "ssl_check"
    description = "SSL/TLS-Analyse"
    required_tools: list[str] = []  # Python fallback available

    def scan(self, target: str, previous_results: list[ScanResult]) -> ScanResult:
        # Find web hosts and their HTTPS ports from previous results
        host_ports: dict[str, list[int]] = {}
        for prev in previous_results:
            for host in prev.hosts:
                if host.is_web:
                    hostname = host.hostname or host.ip
                    ssl_ports = [
                        p.port for p in host.ports
                        if p.port in (443, 8443, 8843, 9443) or p.service in ("https", "ssl")
                    ]
                    # Default to 443 if no specific HTTPS port found
                    if not ssl_ports:
                        ssl_ports = [443]
                    host_ports[hostname] = ssl_ports

        if not host_ports:
            host_ports = {target: [443]}

        all_findings: list[Finding] = []
        all_hosts: list[HostInfo] = []
        first_host = True

        for host in sorted(host_ports.keys()):
            ports = host_ports[host]
            for port in ports:
                if shutil.which(self.config.tools.testssl):
                    # testssl.sh supports host:port syntax
                    host_port = f"{host}:{port}" if port != 443 else host
                    host_info, findings = self._run_testssl(host_port)
                else:
                    if first_host:
                        console.print("    [dim]testssl.sh nicht verfügbar, nutze Python-Fallback[/dim]")
                        first_host = False
                    host_info, findings = self._python_ssl_check(host, port)

                if host_info:
                    all_hosts.append(host_info)
                all_findings.extend(findings)

        return ScanResult(
            scanner_name=self.name,
            hosts=all_hosts,
            findings=all_findings,
        )

    def _run_testssl(self, host: str) -> tuple[HostInfo | None, list[Finding]]:
        """Run testssl.sh for comprehensive TLS analysis."""
        cmd = [
            self.config.tools.testssl,
            "--jsonfile=-",
            "--quiet",
            "--color", "0",
            host,
        ]
        result = self.run_command(cmd, timeout=120)
        findings: list[Finding] = []

        if result.returncode != 0:
            return None, findings

        try:
            data = json.loads(result.stdout)
            for entry in data:
                severity_map = {"CRITICAL": Severity.CRITICAL, "HIGH": Severity.HIGH,
                                "MEDIUM": Severity.MEDIUM, "LOW": Severity.LOW}
                sev = entry.get("severity", "").upper()
                if sev in severity_map:
                    findings.append(Finding(
                        title=f"TLS: {entry.get('id', 'unknown')} ({host})",
                        severity=severity_map[sev],
                        description=entry.get("finding", ""),
                        tags=["ssl", "tls"],
                    ))
        except json.JSONDecodeError:
            pass

        return HostInfo(hostname=host, is_web=True, ssl_info={"checked": True}), findings

    def _python_ssl_check(self, host: str, port: int = 443) -> tuple[HostInfo | None, list[Finding]]:
        """Fallback: Basic SSL check with Python ssl module."""
        findings: list[Finding] = []
        ssl_info: dict = {}
        host_label = f"{host}:{port}" if port != 443 else host

        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    protocol = ssock.version()

                    ssl_info["protocol"] = protocol
                    ssl_info["cipher"] = cipher[0] if cipher else ""

                    # Check certificate expiry
                    not_after = cert.get("notAfter", "")
                    if not_after:
                        expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                        expiry = expiry.replace(tzinfo=timezone.utc)
                        days_left = (expiry - datetime.now(timezone.utc)).days
                        ssl_info["expires"] = not_after
                        ssl_info["days_until_expiry"] = days_left

                        if days_left < 0:
                            findings.append(Finding(
                                title=f"SSL-Zertifikat abgelaufen ({host_label})",
                                severity=Severity.CRITICAL,
                                description=f"Das Zertifikat für {host_label} ist seit {abs(days_left)} Tagen abgelaufen.",
                                evidence=f"notAfter: {not_after}",
                                recommendation="Zertifikat sofort erneuern.",
                                tags=["ssl", "certificate"],
                            ))
                        elif days_left < 30:
                            findings.append(Finding(
                                title=f"SSL-Zertifikat läuft bald ab ({host_label})",
                                severity=Severity.MEDIUM,
                                description=f"Das Zertifikat für {host_label} läuft in {days_left} Tagen ab.",
                                evidence=f"notAfter: {not_after}",
                                recommendation="Zertifikat zeitnah erneuern.",
                                tags=["ssl", "certificate"],
                            ))

                    # Check for old TLS versions
                    if protocol and protocol in ("TLSv1", "TLSv1.1"):
                        findings.append(Finding(
                            title=f"Veraltete TLS-Version ({host_label})",
                            severity=Severity.HIGH,
                            description=f"{host_label} verwendet {protocol}, welches als unsicher gilt.",
                            evidence=f"Protocol: {protocol}",
                            recommendation="Mindestens TLS 1.2 erzwingen, idealerweise TLS 1.3.",
                            tags=["ssl", "tls-version"],
                        ))

                    # Subject info
                    subject = dict(x[0] for x in cert.get("subject", []))
                    ssl_info["subject"] = subject.get("commonName", "")
                    san = [x[1] for x in cert.get("subjectAltName", [])]
                    ssl_info["san"] = san

        except ssl.SSLCertVerificationError as e:
            findings.append(Finding(
                title=f"SSL-Zertifikat ungültig ({host_label})",
                severity=Severity.HIGH,
                description=f"Das Zertifikat für {host_label} konnte nicht verifiziert werden: {e}",
                recommendation="Gültiges Zertifikat von einer vertrauenswürdigen CA installieren.",
                tags=["ssl", "certificate"],
            ))
        except (socket.timeout, ConnectionRefusedError, OSError):
            # No SSL on this host
            return None, []

        return HostInfo(hostname=host, is_web=True, ssl_info=ssl_info), findings
