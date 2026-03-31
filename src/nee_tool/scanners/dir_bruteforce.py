"""Directory brute-force scanner.

Uses feroxbuster or ffuf to discover hidden paths, files,
and directories on web targets. Falls back to pure Python
with a comprehensive built-in wordlist.
"""

from __future__ import annotations

import json
import shutil
import ssl
import time
import urllib.error
import urllib.request
from pathlib import Path
from tempfile import NamedTemporaryFile
from urllib.parse import urlparse

from nee_tool.core.models import Finding, HostInfo, ScanResult, Severity
from nee_tool.scanners.base import BaseScanner, console

# Interesting status codes and what they mean
INTERESTING_CODES = {200, 201, 301, 302, 307, 308, 401, 403, 405, 500}

# ── Categorized wordlist ──────────────────────────────────────

WORDLIST_CATEGORIES = {
    "Admin-Panel": [
        "/admin", "/admin/", "/administrator", "/administrator/",
        "/login", "/login/", "/signin", "/dashboard", "/dashboard/",
        "/panel", "/cp", "/controlpanel", "/management",
        "/wp-admin", "/wp-admin/", "/wp-login.php",
        "/manager", "/manager/html", "/admin/login",
        "/user/login", "/phpmyadmin", "/phpmyadmin/",
        "/adminer", "/adminer.php",
    ],
    "API-Endpunkt": [
        "/api", "/api/", "/api/v1", "/api/v2", "/api/v3",
        "/graphql", "/graphiql", "/gql",
        "/rest", "/rest/api", "/_api", "/admin/api",
        "/swagger", "/swagger.json", "/swagger-ui.html", "/swagger-ui/",
        "/api-docs", "/api-docs/", "/v2/api-docs", "/v3/api-docs",
        "/openapi.json", "/openapi.yaml",
        "/redoc", "/docs", "/docs/api",
        "/wp-json/", "/wp-json/wp/v2", "/wp-json/wp/v2/users",
        "/jsonapi",
    ],
    "Sensible Datei": [
        "/.env", "/.env.local", "/.env.production", "/.env.backup",
        "/.htaccess", "/.htpasswd",
        "/config", "/config.php", "/config.yml", "/config.json",
        "/config.xml", "/config.inc.php", "/configuration.php",
        "/wp-config.php", "/wp-config.php.bak", "/wp-config.php.old",
        "/settings.py", "/settings.php", "/local_settings.py",
        "/web.config", "/appsettings.json",
        "/robots.txt", "/sitemap.xml", "/crossdomain.xml",
        "/.well-known/security.txt",
        "/phpinfo.php", "/info.php", "/php_info.php",
        "/server-status", "/server-info",
        "/.DS_Store", "/Thumbs.db",
        "/debug", "/debug/", "/trace", "/test", "/test/",
        "/elmah.axd", "/error_log", "/errors.log",
    ],
    "Backup-Datei": [
        "/backup", "/backup/", "/backups", "/backups/",
        "/backup.zip", "/backup.tar.gz", "/backup.tar", "/backup.sql",
        "/backup.sql.gz", "/backup.rar",
        "/db.sql", "/database.sql", "/dump.sql",
        "/site.zip", "/site.tar.gz", "/www.zip", "/web.zip",
        "/bak", "/bak/", "/.bak",
        "/old", "/old/", "/.old",
        "/temp", "/temp/", "/tmp", "/tmp/",
        "/dump", "/dump/", "/export", "/export/",
        "/archive", "/archive/",
    ],
    "Versionskontrolle": [
        "/.git", "/.git/", "/.git/HEAD", "/.git/config",
        "/.gitignore", "/.gitattributes",
        "/.svn", "/.svn/", "/.svn/entries", "/.svn/wc.db",
        "/.hg", "/.hg/", "/.hg/hgrc",
        "/CVS", "/CVS/Root", "/CVS/Entries",
        "/.bzr", "/.bzr/",
    ],
    "Webserver-Artefakt": [
        "/WEB-INF", "/WEB-INF/web.xml", "/WEB-INF/classes",
        "/META-INF", "/META-INF/MANIFEST.MF",
        "/cgi-bin", "/cgi-bin/",
        "/server-status", "/server-info",
        "/.well-known/", "/.well-known/openid-configuration",
        "/favicon.ico", "/humans.txt",
    ],
    "Monitoring/Health": [
        "/health", "/healthz", "/health/", "/healthcheck",
        "/status", "/status/", "/_status",
        "/metrics", "/metrics/", "/prometheus",
        "/actuator", "/actuator/health", "/actuator/info",
        "/actuator/env", "/actuator/beans", "/actuator/mappings",
        "/info", "/info/",
        "/console", "/console/",
        "/jmx-console", "/jmx-console/",
        "/web-console", "/web-console/",
    ],
    "Content/Upload": [
        "/uploads", "/uploads/", "/upload", "/upload/",
        "/files", "/files/", "/media", "/media/",
        "/images", "/img", "/static", "/static/",
        "/assets", "/assets/", "/public", "/public/",
        "/wp-content", "/wp-content/uploads",
        "/wp-includes", "/wp-includes/",
        "/content", "/content/",
    ],
    "Entwicklung/Debug": [
        "/dev", "/dev/", "/staging", "/staging/",
        "/internal", "/internal/", "/private", "/private/",
        "/secret", "/secret/", "/hidden", "/hidden/",
        "/debug", "/debug/", "/testing",
        "/shell", "/cmd", "/exec",
        "/log", "/log/", "/logs", "/logs/",
        "/db", "/database", "/sql",
    ],
}

# Flat list for tools that need it
BUILTIN_WORDLIST = []
for paths in WORDLIST_CATEGORIES.values():
    BUILTIN_WORDLIST.extend(paths)
# Deduplicate
BUILTIN_WORDLIST = list(dict.fromkeys(BUILTIN_WORDLIST))

# Category lookup for findings
PATH_CATEGORY_MAP = {}
for category, paths in WORDLIST_CATEGORIES.items():
    for path in paths:
        PATH_CATEGORY_MAP[path.lower().rstrip("/")] = category


def _get_category(path: str) -> str:
    """Get the category for a discovered path."""
    normalized = path.lower().rstrip("/")
    if normalized in PATH_CATEGORY_MAP:
        return PATH_CATEGORY_MAP[normalized]
    # Check partial matches
    for cat_path, category in PATH_CATEGORY_MAP.items():
        if cat_path in normalized:
            return category
    return "Sonstiges"


def _get_severity_for_category(category: str, status: int) -> Severity:
    """Determine finding severity based on category and status code."""
    if status in (401, 403):
        return Severity.INFO

    severity_map = {
        "Sensible Datei": Severity.HIGH,
        "Backup-Datei": Severity.HIGH,
        "Versionskontrolle": Severity.HIGH,
        "Admin-Panel": Severity.MEDIUM,
        "API-Endpunkt": Severity.MEDIUM,
        "Monitoring/Health": Severity.MEDIUM,
        "Entwicklung/Debug": Severity.MEDIUM,
        "Webserver-Artefakt": Severity.LOW,
        "Content/Upload": Severity.LOW,
    }
    return severity_map.get(category, Severity.LOW)


def _get_finding_title(category: str, path: str) -> str:
    """Generate descriptive finding title based on category."""
    titles = {
        "Sensible Datei": f"Sensible Datei exponiert: {path}",
        "Backup-Datei": f"Backup-Datei exponiert: {path}",
        "Versionskontrolle": f"Versionskontrolle zugänglich: {path}",
        "Admin-Panel": f"Admin-Panel erreichbar: {path}",
        "API-Endpunkt": f"API-Endpunkt exponiert: {path}",
        "Monitoring/Health": f"Monitoring-Endpunkt exponiert: {path}",
        "Entwicklung/Debug": f"Entwicklungs-/Debug-Pfad exponiert: {path}",
        "Webserver-Artefakt": f"Webserver-Artefakt exponiert: {path}",
        "Content/Upload": f"Upload-/Content-Verzeichnis: {path}",
    }
    return titles.get(category, f"Pfad entdeckt: {path}")


class DirBruteforceScanner(BaseScanner):
    name = "dir_bruteforce"
    description = "Directory/File Discovery (feroxbuster/ffuf/built-in)"
    required_tools: list[str] = []  # Checks dynamically

    def scan(self, target: str, previous_results: list[ScanResult]) -> ScanResult:
        # Find web targets from previous results
        web_targets: set[str] = set()
        for prev in previous_results:
            for host in prev.hosts:
                if host.is_web:
                    hostname = host.hostname or host.ip
                    web_targets.add(hostname)

        if not web_targets:
            web_targets = {target}

        # Check which tool is available
        has_ferox = bool(shutil.which(self.config.tools.feroxbuster))
        has_ffuf = bool(shutil.which("ffuf"))

        all_findings: list[Finding] = []
        all_hosts: list[HostInfo] = []
        raw_parts: list[str] = []

        for host in sorted(web_targets):
            for scheme in ["https", "http"]:
                url = f"{scheme}://{host}"

                if has_ferox:
                    found, findings = self._run_feroxbuster(url)
                elif has_ffuf:
                    found, findings = self._run_ffuf(url)
                else:
                    found, findings = self._run_python_fallback(url)

                if found:
                    all_findings.extend(findings)
                    all_hosts.append(HostInfo(
                        hostname=host,
                        is_web=True,
                        services=[f"{len(found)} paths discovered"],
                    ))
                    raw_parts.append(f"{host}: {len(found)} paths")
                    break  # One scheme worked, skip other

        return ScanResult(
            scanner_name=self.name,
            findings=all_findings,
            hosts=all_hosts,
            raw_output="\n".join(raw_parts),
        )

    def _run_feroxbuster(self, url: str) -> tuple[list[dict], list[Finding]]:
        """Run feroxbuster against a URL."""
        with NamedTemporaryFile(suffix=".json", delete=False) as jf:
            json_output = jf.name

        # Write built-in wordlist to temp file for feroxbuster
        with NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as wf:
            wf.write("\n".join(p.lstrip("/") for p in BUILTIN_WORDLIST))
            wordlist_file = wf.name

        cmd = [
            self.config.tools.feroxbuster,
            "-u", url,
            "-o", json_output,
            "--json",
            "--quiet",
            "--no-state",
            "--auto-tune",
            "--threads", "20",
            "--timeout", "10",
            "--depth", "2",
            "--wordlist", wordlist_file,
            "--status-codes", ",".join(str(c) for c in INTERESTING_CODES),
        ]

        self.run_command(cmd, timeout=self.config.scan.timeout_per_scanner)

        found = []
        findings = []
        try:
            for line in Path(json_output).read_text().strip().splitlines():
                if not line.strip():
                    continue
                try:
                    entry = json.loads(line)
                    if entry.get("type") == "response":
                        found.append(entry)
                        finding = self._entry_to_finding(
                            entry.get("url", ""),
                            entry.get("status", 0),
                            entry.get("content_length", 0),
                            url,
                        )
                        if finding:
                            findings.append(finding)
                except json.JSONDecodeError:
                    continue
        except FileNotFoundError:
            pass

        Path(json_output).unlink(missing_ok=True)
        Path(wordlist_file).unlink(missing_ok=True)
        return found, findings

    def _run_ffuf(self, url: str) -> tuple[list[dict], list[Finding]]:
        """Run ffuf against a URL."""
        with NamedTemporaryFile(suffix=".json", delete=False) as jf:
            json_output = jf.name

        # Write built-in wordlist for ffuf
        with NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as wf:
            wf.write("\n".join(p.lstrip("/") for p in BUILTIN_WORDLIST))
            wordlist_file = wf.name

        # Try system wordlists first, fall back to built-in
        wordlists = [
            "/usr/share/wordlists/dirb/common.txt",
            "/usr/share/seclists/Discovery/Web-Content/common.txt",
            "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt",
        ]
        wordlist = next((w for w in wordlists if Path(w).exists()), wordlist_file)

        cmd = [
            "ffuf",
            "-u", f"{url}/FUZZ",
            "-w", wordlist,
            "-o", json_output,
            "-of", "json",
            "-mc", ",".join(str(c) for c in INTERESTING_CODES),
            "-t", "20",
            "-timeout", "10",
            "-s",  # Silent
        ]

        self.run_command(cmd, timeout=self.config.scan.timeout_per_scanner)

        found = []
        findings = []
        try:
            data = json.loads(Path(json_output).read_text())
            for result in data.get("results", []):
                found.append(result)
                finding = self._entry_to_finding(
                    result.get("url", ""),
                    result.get("status", 0),
                    result.get("length", 0),
                    url,
                )
                if finding:
                    findings.append(finding)
        except (json.JSONDecodeError, FileNotFoundError):
            pass

        Path(json_output).unlink(missing_ok=True)
        Path(wordlist_file).unlink(missing_ok=True)
        return found, findings

    def _run_python_fallback(self, base_url: str) -> tuple[list[dict], list[Finding]]:
        """Pure Python fallback when no external tools are available."""
        console.print(f"    [dim]Python-Fallback: {len(BUILTIN_WORDLIST)} Pfade prüfen...[/dim]")

        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        found = []
        findings = []

        for path in BUILTIN_WORDLIST:
            url = f"{base_url}{path}"
            try:
                req = urllib.request.Request(url, headers={
                    "User-Agent": "TerraRecon/1.0 Security-Scanner",
                })
                response = urllib.request.urlopen(req, timeout=8, context=ctx)
                status = response.status
                content_length = int(response.headers.get("Content-Length", 0))
                response.close()

                if status in INTERESTING_CODES:
                    entry = {"url": url, "status": status, "content_length": content_length}
                    found.append(entry)
                    finding = self._entry_to_finding(url, status, content_length, base_url)
                    if finding:
                        findings.append(finding)

            except urllib.error.HTTPError as e:
                if e.code in (401, 403):
                    entry = {"url": url, "status": e.code, "content_length": 0}
                    found.append(entry)
                    finding = self._entry_to_finding(url, e.code, 0, base_url)
                    if finding:
                        findings.append(finding)
            except Exception:
                pass

            # Rate limiting
            time.sleep(0.05)

        return found, findings

    def _entry_to_finding(self, url: str, status: int, size: int, base_url: str) -> Finding | None:
        """Convert a discovered path to a finding if it's interesting."""
        path = url.replace(base_url, "").rstrip("/") or "/"
        category = _get_category(path)
        severity = _get_severity_for_category(category, status)

        if status == 200:
            title = _get_finding_title(category, path)
            return Finding(
                title=title,
                severity=severity,
                description=(
                    f"Unter {url} wurde eine Ressource entdeckt (Kategorie: {category}, "
                    f"HTTP {status}, {size} Bytes). "
                    f"Diese Ressource sollte auf sensible Inhalte geprüft werden."
                ),
                evidence=f"GET {url} → HTTP {status} ({size} Bytes)\nKategorie: {category}",
                recommendation=(
                    "1. Zugriff auf diese Ressource einschränken oder entfernen\n"
                    "2. Sicherstellen, dass keine sensiblen Daten exponiert werden\n"
                    "3. Webserver-Konfiguration härten"
                ),
                tags=["directory-brute", category.lower().replace(" ", "-"), "information-disclosure"],
            )

        if status in (401, 403):
            return Finding(
                title=f"Geschützter Pfad: {path} ({category})",
                severity=Severity.INFO,
                description=(
                    f"Unter {url} wurde ein geschützter Bereich entdeckt "
                    f"(Kategorie: {category}, HTTP {status})."
                ),
                evidence=f"GET {url} → HTTP {status}\nKategorie: {category}",
                tags=["directory-brute", category.lower().replace(" ", "-")],
            )

        return None
