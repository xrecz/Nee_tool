"""Data models for scan results."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from pydantic import BaseModel, Field


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ScanStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


class Finding(BaseModel):
    """A single finding from a scanner."""

    title: str
    severity: Severity
    description: str
    evidence: str = ""
    recommendation: str = ""
    references: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)


class HostInfo(BaseModel):
    """Information about a discovered host."""

    hostname: str
    ip: str = ""
    ports: list[PortInfo] = Field(default_factory=list)
    services: list[str] = Field(default_factory=list)
    technologies: list[str] = Field(default_factory=list)
    headers: dict[str, str] = Field(default_factory=dict)
    ssl_info: dict = Field(default_factory=dict)
    is_web: bool = False
    status_code: int | None = None
    title: str = ""


class PortInfo(BaseModel):
    """Information about an open port."""

    port: int
    protocol: str = "tcp"
    state: str = "open"
    service: str = ""
    version: str = ""
    banner: str = ""


class ScanResult(BaseModel):
    """Result from a single scanner module."""

    scanner_name: str
    status: ScanStatus = ScanStatus.COMPLETED
    started_at: datetime = Field(default_factory=datetime.now)
    finished_at: datetime | None = None
    duration_seconds: float = 0.0
    raw_output: str = ""
    error: str = ""
    hosts: list[HostInfo] = Field(default_factory=list)
    subdomains: list[str] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    data: dict = Field(default_factory=dict)


class Project(BaseModel):
    """A pentest project/engagement."""

    name: str
    target: str
    scope: list[str] = Field(default_factory=list)
    out_of_scope: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=datetime.now)
    scan_results: list[ScanResult] = Field(default_factory=list)

    def all_hosts(self) -> dict[str, HostInfo]:
        """Merge all discovered hosts across scan results."""
        hosts: dict[str, HostInfo] = {}
        for result in self.scan_results:
            for host in result.hosts:
                key = host.hostname or host.ip
                if key in hosts:
                    existing = hosts[key]
                    if host.ip and not existing.ip:
                        existing.ip = host.ip
                    existing.ports.extend(
                        p for p in host.ports if p not in existing.ports
                    )
                    existing.services.extend(
                        s for s in host.services if s not in existing.services
                    )
                    existing.technologies.extend(
                        t for t in host.technologies if t not in existing.technologies
                    )
                    existing.headers.update(host.headers)
                    if host.ssl_info:
                        existing.ssl_info.update(host.ssl_info)
                    if host.is_web:
                        existing.is_web = True
                    if host.status_code and not existing.status_code:
                        existing.status_code = host.status_code
                    if host.title and not existing.title:
                        existing.title = host.title
                else:
                    hosts[key] = host.model_copy()
        return hosts

    def all_findings(self) -> list[Finding]:
        """Collect all findings across scan results."""
        findings = []
        for result in self.scan_results:
            findings.extend(result.findings)
        return findings

    def all_subdomains(self) -> list[str]:
        """Collect all discovered subdomains."""
        subs = set()
        for result in self.scan_results:
            subs.update(result.subdomains)
        return sorted(subs)
