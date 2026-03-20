"""Port scanning module using nmap.

Scans all discovered subdomains/hosts for open ports and services.
Parses nmap XML output for structured results.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path
from tempfile import NamedTemporaryFile

from nee_tool.core.models import HostInfo, PortInfo, ScanResult
from nee_tool.scanners.base import BaseScanner


class PortScanner(BaseScanner):
    name = "portscan"
    description = "Port-Scan (nmap)"
    required_tools = ["nmap"]

    def scan(self, target: str, previous_results: list[ScanResult]) -> ScanResult:
        # Collect targets: subdomains from previous results + main target
        targets = {target}
        for prev in previous_results:
            targets.update(prev.subdomains)

        target_list = sorted(targets)
        if not target_list:
            return ScanResult(scanner_name=self.name, raw_output="No targets to scan")

        with NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as tf:
            tf.write("\n".join(target_list))
            target_file = tf.name

        with NamedTemporaryFile(suffix=".xml", delete=False) as xf:
            xml_output = xf.name

        top_ports = self.config.scan.nmap_top_ports
        cmd = [
            self.config.tools.nmap,
            "-sV",                      # Service version detection
            "--top-ports", str(top_ports),
            "-T4",                      # Aggressive timing
            "--open",                   # Only show open ports
            "-oX", xml_output,          # XML output for parsing
            "-iL", target_file,         # Target list from file
        ]

        extra = self.config.scan.nmap_extra_args.strip()
        if extra:
            cmd.extend(extra.split())

        result = self.run_command(cmd, timeout=self.config.scan.timeout_per_scanner)
        hosts = self._parse_nmap_xml(xml_output)

        # Cleanup temp files
        Path(target_file).unlink(missing_ok=True)
        Path(xml_output).unlink(missing_ok=True)

        return ScanResult(
            scanner_name=self.name,
            hosts=hosts,
            raw_output=result.stdout[-2000:] if result.stdout else "",
        )

    def _parse_nmap_xml(self, xml_path: str) -> list[HostInfo]:
        """Parse nmap XML output into structured HostInfo objects."""
        hosts = []
        try:
            tree = ET.parse(xml_path)
        except ET.ParseError:
            return hosts

        root = tree.getroot()
        for host_el in root.findall("host"):
            if host_el.find("status") is not None:
                status = host_el.find("status").get("state", "")
                if status != "up":
                    continue

            # Get hostname and IP
            ip = ""
            hostname = ""
            for addr in host_el.findall("address"):
                if addr.get("addrtype") == "ipv4":
                    ip = addr.get("addr", "")

            hostnames_el = host_el.find("hostnames")
            if hostnames_el is not None:
                for hn in hostnames_el.findall("hostname"):
                    hostname = hn.get("name", "")
                    break

            # Get open ports
            ports = []
            ports_el = host_el.find("ports")
            if ports_el is not None:
                for port_el in ports_el.findall("port"):
                    state_el = port_el.find("state")
                    if state_el is None or state_el.get("state") != "open":
                        continue

                    service_el = port_el.find("service")
                    service_name = service_el.get("name", "") if service_el is not None else ""
                    version = ""
                    if service_el is not None:
                        parts = [
                            service_el.get("product", ""),
                            service_el.get("version", ""),
                        ]
                        version = " ".join(p for p in parts if p)

                    ports.append(PortInfo(
                        port=int(port_el.get("portid", 0)),
                        protocol=port_el.get("protocol", "tcp"),
                        state="open",
                        service=service_name,
                        version=version,
                    ))

            if ports:
                hosts.append(HostInfo(
                    hostname=hostname or ip,
                    ip=ip,
                    ports=ports,
                    services=[p.service for p in ports if p.service],
                ))

        return hosts
