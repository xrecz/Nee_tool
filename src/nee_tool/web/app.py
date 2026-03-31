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

import csv
import io

from fastapi import Depends, FastAPI, Form, HTTPException, Request, UploadFile, File
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse, StreamingResponse
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

# Cancellation flags: job_id -> threading.Event (set = cancel requested)
_cancel_flags: dict[str, threading.Event] = {}

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

    cancel_event = threading.Event()
    _cancel_flags[job_id] = cancel_event

    def _run():
        try:
            config = Config.default()
            if profile and profile in SCAN_PROFILES:
                apply_profile(config, profile)
            config.scan.nmap_top_ports = top_ports
            if scanners:
                config.pipeline.enabled_scanners = scanners

            orchestrator = PipelineOrchestrator(config)
            project = orchestrator.run(project_name, target, cancel_event=cancel_event)

            if cancel_event.is_set():
                _scan_jobs[job_id]["status"] = "cancelled"
                _save_scan_jobs(_scan_jobs)
                return

            out_dir = config.project_dir(project_name)
            result_file = export_project(project, out_dir)

            _scan_jobs[job_id]["status"] = "completed"
            _scan_jobs[job_id]["result_file"] = str(result_file)
            _scan_jobs[job_id]["findings"] = len(project.all_findings())
            _scan_jobs[job_id]["hosts"] = len(project.all_hosts())
            _save_scan_jobs(_scan_jobs)
        except Exception as exc:
            _scan_jobs[job_id]["status"] = "failed"
            _scan_jobs[job_id]["error"] = str(exc)
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
        return HTMLResponse('<span class="badge" style="background:rgba(248,113,113,0.2);color:var(--red);">Nicht gefunden</span>')
    status = job.get("status", "unknown")
    if status == "running":
        return HTMLResponse('<span class="badge badge-running">Läuft...</span>')
    elif status == "completed":
        result_file = job.get("result_file", "")
        return HTMLResponse(
            f'<span class="badge badge-success">Fertig</span> '
            f'<a href="/project?file={result_file}" class="btn btn-sm btn-primary">Öffnen</a>'
        )
    elif status == "cancelled":
        return HTMLResponse('<span class="badge badge-warning">Abgebrochen</span>')
    else:
        err = job.get("error", "")[:60]
        return HTMLResponse(f'<span class="badge" style="background:rgba(248,113,113,0.2);color:var(--red);">Fehler: {err}</span>')


@app.post("/scan/cancel/{job_id}")
async def scan_cancel(job_id: str, _auth: HTTPBasicCredentials = Depends(require_auth)):
    """Cancel a running scan."""
    job = _scan_jobs.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Scan-Job nicht gefunden")
    if job.get("status") != "running":
        raise HTTPException(status_code=400, detail="Scan läuft nicht mehr")

    cancel_event = _cancel_flags.get(job_id)
    if cancel_event:
        cancel_event.set()

    _scan_jobs[job_id]["status"] = "cancelled"
    _save_scan_jobs(_scan_jobs)
    return RedirectResponse(url="/", status_code=303)


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

@app.get("/project/export/csv")
async def export_findings_csv(file: str, _auth: HTTPBasicCredentials = Depends(require_auth)):
    """Export project findings as CSV download."""
    project = _load_project(file)
    if not project:
        raise HTTPException(status_code=404, detail="Projekt nicht gefunden")

    findings = project.all_findings()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Severity", "Title", "Description", "Evidence", "Recommendation", "Tags"])
    for f in findings:
        writer.writerow([
            f.severity.value,
            f.title,
            f.description,
            f.evidence or "",
            f.recommendation or "",
            ", ".join(f.tags) if f.tags else "",
        ])
    output.seek(0)
    filename = Path(file).stem + "_findings.csv"
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.get("/project/export/json")
async def export_findings_json(file: str, _auth: HTTPBasicCredentials = Depends(require_auth)):
    """Export project findings as JSON download."""
    project = _load_project(file)
    if not project:
        raise HTTPException(status_code=404, detail="Projekt nicht gefunden")

    findings = [
        {
            "severity": f.severity.value,
            "title": f.title,
            "description": f.description,
            "evidence": f.evidence,
            "recommendation": f.recommendation,
            "tags": f.tags,
        }
        for f in project.all_findings()
    ]
    payload = json.dumps({"project": project.name, "target": project.target, "findings": findings}, indent=2, ensure_ascii=False)
    filename = Path(file).stem + "_findings.json"
    return StreamingResponse(
        iter([payload]),
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.get("/history", response_class=HTMLResponse)
async def history_view(_auth: HTTPBasicCredentials = Depends(require_auth)):
    """Scan history: list all output projects with severity breakdown."""
    raw_projects = _get_projects()
    # Enrich with severity counts
    enriched = []
    for p in raw_projects:
        sev = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        try:
            data = json.loads(Path(p["file"]).read_text())
            for result in data.get("scan_results", []):
                for f in result.get("findings", []):
                    s = f.get("severity", "info")
                    sev[s] = sev.get(s, 0) + 1
        except Exception:
            pass
        enriched.append({**p, "sev": sev})
    return _render("history.html", projects=enriched)


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


# ── Phishing Routes ────────────────────────────────────────

@app.get("/phishing", response_class=HTMLResponse)
async def phishing_view(_auth: HTTPBasicCredentials = Depends(require_auth)):
    """GoPhish integration dashboard."""
    return _render("phishing.html", config=None)


@app.post("/api/phishing/connect")
async def phishing_connect(request: Request, _auth: HTTPBasicCredentials = Depends(require_auth)):
    """Test GoPhish connection and return status."""
    from nee_tool.phishing.client import GoPhishClient, GoPhishConfig, GoPhishError

    body = await request.json()
    host = body.get("host", "").strip()
    api_key = body.get("api_key", "").strip()

    if not host or not api_key:
        return JSONResponse({"ok": False, "error": "Host und API-Key erforderlich"})

    try:
        client = GoPhishClient(GoPhishConfig(host=host, api_key=api_key))
        campaigns = client.list_campaigns()
        return JSONResponse({"ok": True, "campaign_count": len(campaigns) if isinstance(campaigns, list) else 0})
    except GoPhishError as e:
        return JSONResponse({"ok": False, "error": str(e)})
    except Exception as e:
        return JSONResponse({"ok": False, "error": f"Unerwarteter Fehler: {e}"})


@app.get("/api/phishing/campaigns")
async def phishing_campaigns(
    host: str,
    api_key: str,
    _auth: HTTPBasicCredentials = Depends(require_auth),
):
    """List all GoPhish campaigns."""
    from nee_tool.phishing.client import GoPhishClient, GoPhishConfig, GoPhishError

    try:
        client = GoPhishClient(GoPhishConfig(host=host, api_key=api_key))
        campaigns = client.list_campaigns()
        return JSONResponse({"campaigns": campaigns if isinstance(campaigns, list) else []})
    except GoPhishError as e:
        return JSONResponse({"error": str(e)})
    except Exception as e:
        return JSONResponse({"error": f"Fehler: {e}"})


@app.get("/api/phishing/templates")
async def phishing_templates(
    host: str,
    api_key: str,
    _auth: HTTPBasicCredentials = Depends(require_auth),
):
    """List all GoPhish email templates."""
    from nee_tool.phishing.client import GoPhishClient, GoPhishConfig, GoPhishError

    try:
        client = GoPhishClient(GoPhishConfig(host=host, api_key=api_key))
        items = client.list_templates()
        return JSONResponse({"items": items if isinstance(items, list) else []})
    except GoPhishError as e:
        return JSONResponse({"error": str(e), "items": []})
    except Exception as e:
        return JSONResponse({"error": str(e), "items": []})


@app.get("/api/phishing/groups")
async def phishing_groups(
    host: str,
    api_key: str,
    _auth: HTTPBasicCredentials = Depends(require_auth),
):
    """List all GoPhish target groups."""
    from nee_tool.phishing.client import GoPhishClient, GoPhishConfig, GoPhishError

    try:
        client = GoPhishClient(GoPhishConfig(host=host, api_key=api_key))
        items = client.list_groups()
        return JSONResponse({"items": items if isinstance(items, list) else []})
    except GoPhishError as e:
        return JSONResponse({"error": str(e), "items": []})
    except Exception as e:
        return JSONResponse({"error": str(e), "items": []})


@app.get("/api/phishing/pages")
async def phishing_pages(
    host: str,
    api_key: str,
    _auth: HTTPBasicCredentials = Depends(require_auth),
):
    """List all GoPhish landing pages."""
    from nee_tool.phishing.client import GoPhishClient, GoPhishConfig, GoPhishError

    try:
        client = GoPhishClient(GoPhishConfig(host=host, api_key=api_key))
        items = client.list_pages()
        return JSONResponse({"items": items if isinstance(items, list) else []})
    except GoPhishError as e:
        return JSONResponse({"error": str(e), "items": []})
    except Exception as e:
        return JSONResponse({"error": str(e), "items": []})
