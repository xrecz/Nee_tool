# CLAUDE.md — Nee Tool Project Guide

## Project Overview

Nee Tool is an automated pentest reconnaissance toolkit written in Python.
It orchestrates external security tools into a pipeline, generates professional
PDF reports, and integrates with GoPhish for phishing campaigns.

**Primary language:** Python 3.10+
**Framework:** CLI via Typer, Web via FastAPI+HTMX, PDF via WeasyPrint, data models via Pydantic

## Project Structure

```
src/nee_tool/
├── cli.py                    # Main CLI (typer app, all commands)
├── core/
│   ├── config.py             # Configuration (tool paths, scan settings, pipeline)
│   ├── models.py             # Data models (Project, Finding, HostInfo, etc.)
│   ├── orchestrator.py       # Pipeline runner, scanner registry
│   ├── profiles.py           # Scan profiles (quick/standard/deep/compliance/recon)
│   ├── retest.py             # Re-test workflow (scan diff, fix tracking)
│   └── compliance.py         # Compliance mapping (BSI/ISO 27001/DSGVO)
├── scanners/
│   ├── base.py               # BaseScanner ABC (all scanners inherit from this)
│   ├── subdomain.py          # Subdomain enumeration (subfinder + crt.sh)
│   ├── portscan.py           # Port scanning (nmap XML parsing)
│   ├── web_discovery.py      # HTTP/HTTPS probing (httpx + urllib fallback)
│   ├── security_headers.py   # HTTP security header checks + value validation
│   ├── ssl_check.py          # SSL/TLS analysis (testssl.sh + ssl fallback, multi-port)
│   ├── tech_detect.py        # Technology detection (whatweb + signatures)
│   ├── crawler.py            # Web crawling (katana/gospider + Python fallback)
│   ├── nuclei.py             # Vulnerability scanning (nuclei JSONL, auto-update templates)
│   ├── dir_bruteforce.py     # Directory/file discovery (feroxbuster/ffuf)
│   └── cve_enrichment.py     # CVE lookup via NVD/NIST API for detected software
├── report/
│   ├── generator.py          # PDF/HTML report generation (WeasyPrint + Jinja2)
│   ├── finding_templates.py  # 20 pre-defined finding templates (OWASP)
│   ├── cvss.py               # CVSS v3.1 base score calculator
│   └── templates/
│       └── report.html       # Jinja2 HTML template for pentest reports
├── phishing/
│   ├── client.py             # GoPhish REST API client
│   ├── email_templates.py    # 5 German phishing email templates
│   └── report.py             # Phishing campaign PDF report generator
├── web/
│   ├── app.py                # FastAPI web application (dashboard, scan, report)
│   ├── templates/            # HTMX/Jinja2 HTML templates for web UI
│   └── static/               # Static assets
└── output/
    └── json_export.py        # JSON export for scan results
```

## Key Architecture Decisions

- **Scanner plugin pattern:** All scanners inherit `BaseScanner` and implement `scan()`.
  Register new scanners in `SCANNER_REGISTRY` in `orchestrator.py`.
- **Graceful degradation:** Every scanner has a Python fallback when external tools
  (nmap, subfinder, httpx, etc.) are not installed. Never crash on missing tools.
- **Pipeline chaining:** Scanners receive `previous_results` and build on them.
  Order matters: subdomain → portscan → web_discovery → headers/ssl/tech → crawler → nuclei → dir_bruteforce → cve_enrichment.
- **Web UI:** FastAPI + HTMX for a lightweight interactive dashboard. No frontend
  framework needed. Templates in `web/templates/`, server-side rendered.
- **Pydantic models:** All data flows through typed models (`Project`, `ScanResult`,
  `Finding`, `HostInfo`). JSON serialization is free via `model_dump()`.

## Commands

```bash
# Install
pip install -e .

# Scan pipeline
nee scan <target> [--name NAME] [--only scanner1,scanner2] [--skip scanner1]
nee scan <target> --profile quick  # Use scan profile (quick/standard/deep/compliance/recon)
nee profiles                       # List available scan profiles

# Re-Test (compare two scans)
nee retest <original.json> <retest.json> [--output retest_result.json]

# Compliance mapping
nee compliance <project.json>      # Show BSI/ISO 27001/DSGVO mapping

# Reports
nee report <project.json> --client "Firma" --author "Name"
nee demo-report                    # Preview with sample data
nee templates                      # List finding templates

# Phishing (GoPhish)
nee phish setup --api-key KEY --name "Campaign" --smtp-host ... --targets file.csv
nee phish status <id> --api-key KEY
nee phish report <id> --api-key KEY --client "Firma"
nee phish templates                # List email templates
nee phish demo-report              # Preview with sample data

# Web UI
nee web                            # Start dashboard on port 8899
nee web --port 3000                # Custom port

# Info
nee scanners                       # Show available scanner modules
nee info <project.json>            # Summarize previous scan
```

## Development Conventions

- **No unnecessary abstractions.** Keep scanners self-contained.
- **German UI text** in CLI output and reports (DACH target market).
- **English code** — variable names, docstrings, comments in English.
- **Type hints** on all function signatures. Use `from __future__ import annotations`.
- **Imports:** stdlib → third-party → local, separated by blank lines.
- **New scanner checklist:**
  1. Create `src/nee_tool/scanners/my_scanner.py` inheriting `BaseScanner`
  2. Set `name`, `description`, `required_tools`
  3. Implement `scan()` returning a `ScanResult`
  4. Register in `SCANNER_REGISTRY` in `orchestrator.py`
  5. Add to default pipeline in `config.py` if it should auto-run

## Dependencies

- **Runtime:** rich, typer, pydantic, jinja2, weasyprint
- **External tools (optional, graceful fallback):** nmap, subfinder, httpx,
  whatweb, testssl.sh, nuclei, feroxbuster, katana, gospider
- **GoPhish:** Separate server, connected via REST API

## Testing

```bash
# Verify imports
python -c "from nee_tool.core.orchestrator import SCANNER_REGISTRY; print(list(SCANNER_REGISTRY.keys()))"

# Run demo reports
nee demo-report --html-only
nee phish demo-report --html-only

# Test scan (safe target)
nee scan example.com --skip portscan --timeout 30
```
