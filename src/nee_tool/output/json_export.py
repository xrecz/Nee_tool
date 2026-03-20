"""JSON export for scan results.

Exports the full project data as structured JSON,
suitable for further processing, report generation,
or MCP tool integration.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from nee_tool.core.models import Project


def export_project(project: Project, output_dir: Path) -> Path:
    """Export full project data as JSON."""
    output_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{project.name}_{timestamp}.json"
    filepath = output_dir / filename

    data = project.model_dump(mode="json")
    filepath.write_text(json.dumps(data, indent=2, ensure_ascii=False, default=str))
    return filepath


def export_findings(project: Project, output_dir: Path) -> Path:
    """Export only findings as a separate JSON file."""
    output_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{project.name}_findings_{timestamp}.json"
    filepath = output_dir / filename

    findings = [f.model_dump(mode="json") for f in project.all_findings()]
    filepath.write_text(json.dumps(findings, indent=2, ensure_ascii=False))
    return filepath


def export_hosts(project: Project, output_dir: Path) -> Path:
    """Export merged host data as JSON."""
    output_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{project.name}_hosts_{timestamp}.json"
    filepath = output_dir / filename

    hosts = {k: v.model_dump(mode="json") for k, v in project.all_hosts().items()}
    filepath.write_text(json.dumps(hosts, indent=2, ensure_ascii=False))
    return filepath
