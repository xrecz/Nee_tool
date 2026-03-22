"""Scan profiles (presets).

Pre-defined scanner combinations and settings for different
use cases: quick assessment, standard pentest, deep analysis,
and compliance checks.
"""

from __future__ import annotations

from pydantic import BaseModel

from nee_tool.core.config import Config


class ScanProfile(BaseModel):
    """A scan preset with pre-configured settings."""

    name: str
    description: str
    scanners: list[str]
    top_ports: int = 1000
    timeout_per_scanner: int = 600
    nuclei_severity: str = ""
    nuclei_tags: str = "cve,misconfig,exposure,vuln"


# ── Built-in profiles ──────────────────────────────────────

SCAN_PROFILES: dict[str, ScanProfile] = {
    "quick": ScanProfile(
        name="Quick Scan",
        description="Schnelle Übersicht (~15 Min). Subdomain, Ports, Web-Check, Header.",
        scanners=["subdomain", "portscan", "web_discovery", "security_headers", "ssl_check"],
        top_ports=100,
        timeout_per_scanner=120,
    ),
    "standard": ScanProfile(
        name="Standard Pentest",
        description="Vollständiger Scan (~1-2 Std). Alle Scanner, ausgewogene Tiefe.",
        scanners=[
            "subdomain", "portscan", "web_discovery", "security_headers",
            "ssl_check", "tech_detect", "crawler", "nuclei", "dir_bruteforce",
            "cve_enrichment",
        ],
        top_ports=1000,
        timeout_per_scanner=600,
    ),
    "deep": ScanProfile(
        name="Deep Scan",
        description="Tiefenanalyse (~4+ Std). Maximale Port-Abdeckung, alle Checks.",
        scanners=[
            "subdomain", "portscan", "web_discovery", "security_headers",
            "ssl_check", "tech_detect", "crawler", "nuclei", "dir_bruteforce",
            "cve_enrichment",
        ],
        top_ports=5000,
        timeout_per_scanner=1200,
        nuclei_tags="cve,misconfig,exposure,vuln,tech,default-login,file",
    ),
    "compliance": ScanProfile(
        name="Compliance Check",
        description="Fokus auf Konfigurations- und Header-Compliance (~30 Min).",
        scanners=[
            "subdomain", "web_discovery", "security_headers", "ssl_check",
            "tech_detect", "cve_enrichment",
        ],
        top_ports=100,
        timeout_per_scanner=300,
    ),
    "recon": ScanProfile(
        name="Recon Only",
        description="Nur Reconnaissance, kein aktives Scanning (~20 Min).",
        scanners=["subdomain", "portscan", "web_discovery", "tech_detect"],
        top_ports=1000,
        timeout_per_scanner=300,
    ),
}


def apply_profile(config: Config, profile_name: str) -> Config:
    """Apply a scan profile to a Config instance.

    Args:
        config: The base configuration to modify
        profile_name: Key from SCAN_PROFILES

    Returns:
        Modified Config instance

    Raises:
        KeyError: If profile_name not found
    """
    if profile_name not in SCAN_PROFILES:
        available = ", ".join(SCAN_PROFILES.keys())
        raise KeyError(f"Profil '{profile_name}' nicht gefunden. Verfügbar: {available}")

    profile = SCAN_PROFILES[profile_name]
    config.pipeline.enabled_scanners = list(profile.scanners)
    config.scan.nmap_top_ports = profile.top_ports
    config.scan.timeout_per_scanner = profile.timeout_per_scanner

    if profile.nuclei_severity:
        config.scan.nuclei_severity = profile.nuclei_severity
    if profile.nuclei_tags:
        config.scan.nuclei_tags = profile.nuclei_tags

    return config
