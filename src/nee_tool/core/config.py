"""Configuration management."""

from __future__ import annotations

import os
from pathlib import Path
from pydantic import BaseModel, Field


class ToolPaths(BaseModel):
    """Paths to external tools. Auto-detected if not set."""

    nmap: str = "nmap"
    subfinder: str = "subfinder"
    httpx: str = "httpx"
    whatweb: str = "whatweb"
    testssl: str = "testssl.sh"
    nuclei: str = "nuclei"
    feroxbuster: str = "feroxbuster"
    katana: str = "katana"
    gospider: str = "gospider"


class ScanConfig(BaseModel):
    """Scan configuration."""

    # Nmap
    nmap_top_ports: int = 1000
    nmap_extra_args: str = ""

    # Subdomain enumeration
    subdomain_wordlist: str = ""
    subdomain_resolvers: str = ""

    # Web discovery
    httpx_threads: int = 50
    httpx_timeout: int = 10

    # Nuclei
    nuclei_severity: str = ""  # e.g. "critical,high,medium" — empty = all
    nuclei_templates: str = ""  # custom templates path
    nuclei_rate_limit: int = 100
    nuclei_tags: str = "cve,misconfig,exposure,vuln"

    # CVE enrichment — NVD API key (increases rate limit from 5/30s to 50/30s)
    nvd_api_key: str = ""

    # General
    max_concurrent: int = 5
    timeout_per_scanner: int = 600  # 10 min default


class PipelineConfig(BaseModel):
    """Which scanners to run and in what order."""

    enabled_scanners: list[str] = Field(default_factory=lambda: [
        "subdomain",
        "portscan",
        "web_discovery",
        "security_headers",
        "ssl_check",
        "tech_detect",
        "crawler",
        "nuclei",
        "dir_bruteforce",
        "cve_enrichment",
    ])


class Config(BaseModel):
    """Root configuration."""

    tools: ToolPaths = Field(default_factory=ToolPaths)
    scan: ScanConfig = Field(default_factory=ScanConfig)
    pipeline: PipelineConfig = Field(default_factory=PipelineConfig)
    output_dir: str = "./output"

    @classmethod
    def default(cls) -> "Config":
        """Create default config, pulling NVD_API_KEY from environment if set."""
        nvd_key = os.getenv("NVD_API_KEY", "")
        instance = cls()
        if nvd_key:
            instance.scan.nvd_api_key = nvd_key
        return instance

    def project_dir(self, project_name: str) -> Path:
        path = Path(self.output_dir) / project_name
        path.mkdir(parents=True, exist_ok=True)
        return path
