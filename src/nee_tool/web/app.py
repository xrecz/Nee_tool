"""FastAPI web application for Nee Tool.

Internal dashboard for managing scans, findings, and reports.
Uses HTMX for interactive UI without a frontend framework.
"""

from __future__ import annotations

import json
import os
import secrets
import threading
from datetime import datetime
from pathlib import Path

from dotenv import load_dotenv

# Load .env file at startup (before any os.getenv calls)
load_dotenv()

from fastapi import Depends, FastAPI, Form, HTTPException, Request, UploadFile, File
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.staticfiles import StaticFiles
from jinja2 import Environment, FileSystemLoader

from nee_tool.core.compliance import compliance_summary, map_all_findings
from nee_tool.core.config import Config
from nee_tool.core.models import Finding, Project, Severity
from nee_tool.core.orchestrator import SCANNER_REGISTRY, PipelineOrchestrator
from nee_tool.core.profiles import SCAN_PROFILES, apply_profile
from nee_tool.core.retest import compare_projects
from nee_tool.output.json_export import export_project
from nee_tool.report.finding_templates import FINDING_TEMPLATES, create_finding_from_template
from nee_tool.report.generator import generate_html, generate_pdf

TEMPLATE_DIR = Path(__file__).parent / "templates"
OUTPUT_DIR = Path("./output")
SCAN_JOBS_FILE = OUTPUT_DIR / "scan_jobs.json"

app = FastAPI(title="Nee Tool", docs_url="/api/docs")
app.mount("/static", StaticFiles(directory=str(Path(__file__).parent / "static")), name="static")

jinja = Environment(loader=FileSystemLoader(str(TEMPLATE_DIR)), autoescape=True)

# ── HTTP Basic Auth ────────────────────────────────────────

security = HTTPBasic()

_WEB_USERNAME = os.getenv("WEB_USERNAME", "admin")
_WEB_PASSWORD = os.getenv("WEB_PASSWORD", "terrarecon")


def require_auth(credentials: HTTPBasicCredentials = Depends(security)) -> HTTPBasicCredentials:
    """Verify HTTP Basic Auth credentials."""
    correct_user = secrets.compare_digest(credentials.username.encode(), _WEB_USERNAME.encode())
    correct_pass = secrets.compare_digest(credentials.password.encode(), _WEB_PASSWORD.encode())
    if not (correct_user and correct_pass):
        raise HTTPException(
            status_code=401,
            detail="Ungültige Anmeldedaten",
            headers={"WWW-Authenticate": "Basic"},
        )
    return credentials


# ── Scan state persistence ─────────────────────────────────

def _load_scan_jobs() -> dict[str, dict]:
    """Load persisted scan jobs from JSON file."""
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    if SCAN_JOBS_FILE.exists():
        try:
            return json.loads(SCAN_JOBS_FILE.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return {}
    return {}


def _save_scan_jobs(jobs: dict[str, dict]) -> None:
    """Persist scan jobs to JSON file."""
    try:
        OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
        SCAN_JOBS_FILE.write_text(
            json.dumps(jobs, indent=2, ensure_ascii=False, default=str),
            encoding="utf-8",
        )
    except OSError:
        pass  # Non-critical — in-memory state still works


# Load persisted jobs on startup
_scan_jobs: dict[str, dict] = _load_scan_jobs()

# ── Helper functions ────────────────────────────────────────

def _get_projects() -> list[dict]:
    """List all saved project JSON files."""
    projects = []
    if not OUTPUT_DIR.exists():
        return projects
    for d in sorted(OUTPUT_DIR.iterdir(), reverse=True):
        if not d.is_dir():
            continue
        for f in sorted(d.glob("*_*.json"), reverse=True):
            if "_findings_" in f.name or "_hosts_" in f.name:
                continue
            try:
                data = json.loads(f.read_text())
                projects.append({
                    "file": str(f),
                    "name": data.get("name", f.stem),
                    "target": data.get("target", ""),
                    "created": data.get("created_at", "")[:19],
                    "findings": sum(len(r.get("findings", [])) for r in data.get("scan_results", [])),
                    "hosts": sum(len(r.get("hosts", [])) for r in data.get("scan_results", [])),
                })
            except (json.JSONDecodeError, KeyError):
                continue
    return projects


def _load_project(file_path: str) -> Project | None:
    """Load a project from a JSON file."""
    try:
        data = json.loads(Path(file_path).read_text())
        return Project(**data)
    except Exception:
        return None


def _render(template_name: str, **ctx) -> HTMLResponse:
    """Render a Jinja2 template."""
    tpl = jinja.get_template(template_name)
    return HTMLResponse(tpl.render(**ctx))


# ── Routes ────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request, _auth: HTTPBasicCredentials = Depends(require_auth)):
    """Main dashboard showing recent projects and scan status."""
    projects = _get_projects()
    scanners = {name: cls(Config.default()).check_tools() for name, cls in SCANNER_REGISTRY.items()}
    return _render("dashboard.html", projects=projects, scanners=scanners, scan_jobs=_scan_jobs)


@app.get("/scan", response_class=HTMLResponse)
async def scan_form(request: Request, _auth: HTTPBasicCredentials = Depends(require_auth)):
    """Show the scan configuration form."""
    scanners = list(SCANNER_REGISTRY.keys())
    return _render("scan_form.html", scanners=scanners, profiles=SCAN_PROFILES)


@app.post("/scan/start")
async def scan_start(
    target: str = Form(...),
    name: str = Form(""),
    scanners: list[str] = Form(default=[]),
    top_ports: int = Form(1000),
    profile: str = Form(""),
    _auth: HTTPBasicCredentials = Depends(require_auth),
):
    """Start a scan in the background."""
    project_name = name or target.replace(".", "_")
    job_id = f"{project_name}_{datetime.now().strftime('%H%M%S')}"

    _scan_jobs[job_id] = {
        "name": project_name,
        "target": target,
        "status": "running",
        "started": datetime.now().isoformat(),
        "result_file": None,
    }
    _save_scan_jobs(_scan_jobs)

    def _run():
        config = Config.default()
        if profile and profile in SCAN_PROFILES:
            apply_profile(config, profile)
        config.scan.nmap_top_ports = top_ports
        if scanners:
            config.pipeline.enabled_scanners = scanners

        orchestrator = PipelineOrchestrator(config)
        project = orchestrator.run(project_name, target)

        out_dir = config.project_dir(project_name)
        result_file = export_project(project, out_dir)

        _scan_jobs[job_id]["status"] = "completed"
        _scan_jobs[job_id]["result_file"] = str(result_file)
        _scan_jobs[job_id]["findings"] = len(project.all_findings())
        _scan_jobs[job_id]["hosts"] = len(project.all_hosts())
        _save_scan_jobs(_scan_jobs)

    thread = threading.Thread(target=_run, daemon=True)
    thread.start()

    return RedirectResponse(url="/", status_code=303)


# NOTE: /scan/status/{job_id} is intentionally NOT protected by auth
#       so HTMX polling works without re-sending credentials on every request.
@app.get("/scan/status/{job_id}", response_class=HTMLResponse)
async def scan_status(job_id: str):
    """HTMX endpoint: poll scan status (no auth required)."""
    job = _scan_jobs.get(job_id, {})
    if not job:
        return HTMLResponse('<span class="tag is-danger">Nicht gefunden</span>')
    if job["status"] == "running":
        return HTMLResponse('<span class="badge bg-warning">Läuft...</span>')
    return HTMLResponse(
        f'<span class="badge bg-success">Fertig</span> '
        f'<a href="/project?file={job.get("result_file", "")}">Öffnen</a>'
    )


@app.get("/project", response_class=HTMLResponse)
async def project_view(file: str, _auth: HTTPBasicCredentials = Depends(require_auth)):
    """View a project's results."""
    project = _load_project(file)
    if not project:
        return HTMLResponse("<h2>Projekt nicht gefunden</h2>", status_code=404)

    hosts = project.all_hosts()
    findings = project.all_findings()
    findings.sort(key=lambda f: ["critical", "high", "medium", "low", "info"].index(f.severity.value))
    subdomains = project.all_subdomains()

    return _render(
        "project_view.html",
        project=project, hosts=hosts, findings=findings,
        subdomains=subdomains, file=file,
    )


@app.get("/project/add-finding", response_class=HTMLResponse)
async def add_finding_form(file: str, _auth: HTTPBasicCredentials = Depends(require_auth)):
    """Form to add a manual finding to a project."""
    return _render("add_finding.html", file=file, templates=FINDING_TEMPLATES)


@app.post("/project/add-finding")
async def add_finding(
    file: str = Form(...),
    template_key: str = Form(""),
    title: str = Form(""),
    severity: str = Form("medium"),
    description: str = Form(""),
    evidence: str = Form(""),
    recommendation: str = Form(""),
    target_host: str = Form(""),
    _auth: HTTPBasicCredentials = Depends(require_auth),
):
    """Add a manual finding to a project."""
    project = _load_project(file)
    if not project:
        return HTMLResponse("Projekt nicht gefunden", status_code=404)

    if template_key and template_key in FINDING_TEMPLATES:
        finding = create_finding_from_template(template_key, target=target_host, evidence=evidence)
    else:
        finding = Finding(
            title=title,
            severity=Severity(severity),
            description=description,
            evidence=evidence,
            recommendation=recommendation,
        )

    # Add to last scan result or create a new one
    from nee_tool.core.models import ScanResult
    if project.scan_results:
        project.scan_results[-1].findings.append(finding)
    else:
        project.scan_results.append(ScanResult(scanner_name="manual", findings=[finding]))

    # Save back
    Path(file).write_text(json.dumps(project.model_dump(mode="json"), indent=2, ensure_ascii=False, default=str))

    return RedirectResponse(url=f"/project?file={file}", status_code=303)


@app.get("/report/generate")
async def generate_report(
    file: str,
    client: str = "",
    author: str = "Security Team",
    format: str = "pdf",
    date_range: str = "",
    summary: str = "",
    version: str = "1.0",
    _auth: HTTPBasicCredentials = Depends(require_auth),
):
    """Generate a report and return it for download."""
    project = _load_project(file)
    if not project:
        return HTMLResponse("Projekt nicht gefunden", status_code=404)

    out_dir = Path(file).parent
    base_name = Path(file).stem

    if format == "html":
        out_path = out_dir / f"{base_name}_report.html"
        generate_html(
            project, out_path,
            client=client, author=author,
            date_range=date_range, summary=summary, version=version,
        )
        return FileResponse(str(out_path), filename=out_path.name, media_type="text/html")
    else:
        out_path = out_dir / f"{base_name}_report.pdf"
        generate_pdf(
            project, out_path,
            client=client, author=author,
            date_range=date_range, summary=summary, version=version,
        )
        return FileResponse(str(out_path), filename=out_path.name, media_type="application/pdf")


@app.get("/report/form", response_class=HTMLResponse)
async def report_form(file: str, _auth: HTTPBasicCredentials = Depends(require_auth)):
    """Show report generation form."""
    project = _load_project(file)
    if not project:
        return HTMLResponse("Projekt nicht gefunden", status_code=404)
    return _render("report_form.html", project=project, file=file)


@app.get("/templates", response_class=HTMLResponse)
async def templates_view(_auth: HTTPBasicCredentials = Depends(require_auth)):
    """View all finding templates."""
    return _render("templates_view.html", templates=FINDING_TEMPLATES)


# ── Re-Test Routes ─────────────────────────────────────────

@app.get("/retest", response_class=HTMLResponse)
async def retest_form(_auth: HTTPBasicCredentials = Depends(require_auth)):
    """Show re-test comparison form or results."""
    projects = _get_projects()
    return _render("retest.html", projects=projects, result=None)


@app.post("/retest", response_class=HTMLResponse)
async def retest_compare(
    original: str = Form(...),
    retest_scan: str = Form(...),
    _auth: HTTPBasicCredentials = Depends(require_auth),
):
    """Compare two scans and show re-test results."""
    orig_project = _load_project(original)
    retest_project = _load_project(retest_scan)

    if not orig_project or not retest_project:
        return HTMLResponse("Projekt nicht gefunden", status_code=404)

    result = compare_projects(orig_project, retest_project)
    projects = _get_projects()
    return _render("retest.html", projects=projects, result=result)


# ── Compliance Routes ──────────────────────────────────────

@app.get("/compliance", response_class=HTMLResponse)
async def compliance_view(file: str = "", _auth: HTTPBasicCredentials = Depends(require_auth)):
    """Show compliance mapping for a project."""
    if not file:
        projects = _get_projects()
        return _render("compliance.html", projects=projects, summary=None, mappings=None)

    project = _load_project(file)
    if not project:
        return HTMLResponse("Projekt nicht gefunden", status_code=404)

    findings = project.all_findings()
    summary = compliance_summary(findings)
    mappings = map_all_findings(findings)

    return _render("compliance.html", projects=[], summary=summary, mappings=mappings)
