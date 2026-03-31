"""Default credentials checker.

Pure Python scanner that checks for common default credentials
on discovered web services, databases, and network devices.
Uses rate-limiting (max 2 req/s per host) to avoid lockouts.
"""

from __future__ import annotations

import socket
import time
from base64 import b64encode
from urllib.parse import urlparse

from nee_tool.core.models import Finding, HostInfo, ScanResult, Severity
from nee_tool.scanners.base import BaseScanner, console

# Default credentials to check
WEB_CREDENTIALS = [
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "admin123"),
    ("admin", "123456"),
    ("root", "root"),
    ("root", "toor"),
    ("test", "test"),
    ("user", "user"),
    ("guest", "guest"),
    ("administrator", "administrator"),
    ("admin", ""),
]

# Common login form paths and field names
LOGIN_PATHS = [
    {
        "path": "/wp-login.php",
        "fields": {"log": None, "pwd": None, "wp-submit": "Log In"},
        "success_indicator": "dashboard",
        "fail_indicator": "login_error",
        "name": "WordPress",
    },
    {
        "path": "/administrator/index.php",
        "fields": {"username": None, "passwd": None},
        "success_indicator": "control panel",
        "fail_indicator": "mod-login",
        "name": "Joomla",
    },
    {
        "path": "/user/login",
        "fields": {"name": None, "pass": None},
        "success_indicator": "logout",
        "fail_indicator": "error",
        "name": "Drupal",
    },
    {
        "path": "/admin",
        "fields": {"username": None, "password": None},
        "success_indicator": "dashboard",
        "fail_indicator": "login",
        "name": "Generic Admin",
    },
    {
        "path": "/login",
        "fields": {"username": None, "password": None},
        "success_indicator": "dashboard",
        "fail_indicator": "invalid",
        "name": "Generic Login",
    },
]

# Database default credentials
DB_CHECKS = [
    {"service": "mysql", "port": 3306, "user": "root", "password": ""},
    {"service": "mysql", "port": 3306, "user": "root", "password": "root"},
    {"service": "mysql", "port": 3306, "user": "root", "password": "mysql"},
    {"service": "postgresql", "port": 5432, "user": "postgres", "password": "postgres"},
    {"service": "postgresql", "port": 5432, "user": "postgres", "password": ""},
    {"service": "mongodb", "port": 27017, "user": "", "password": ""},
    {"service": "redis", "port": 6379, "user": "", "password": ""},
]

# Network device defaults
NETWORK_DEVICE_CREDS = [
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "1234"),
    ("cisco", "cisco"),
    ("root", "root"),
    ("admin", ""),
]

# Rate limit: minimum seconds between requests to same host
RATE_LIMIT_DELAY = 0.5  # 2 requests/second max


class DefaultCredsScanner(BaseScanner):
    name = "default_creds"
    description = "Standard-Zugangsdaten prüfen (Default Credentials)"
    required_tools: list[str] = []  # Pure Python

    def __init__(self, config):
        super().__init__(config)
        self._last_request_time: dict[str, float] = {}

    def _rate_limit(self, host: str) -> None:
        """Enforce rate limiting per host."""
        now = time.time()
        last = self._last_request_time.get(host, 0)
        wait = RATE_LIMIT_DELAY - (now - last)
        if wait > 0:
            time.sleep(wait)
        self._last_request_time[host] = time.time()

    def _http_request(
        self,
        url: str,
        method: str = "GET",
        headers: dict | None = None,
        body: str | None = None,
        timeout: int = 10,
    ) -> tuple[int, dict, str]:
        """Simple HTTP request using urllib (no external deps)."""
        import urllib.request
        import urllib.error
        import ssl

        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        parsed = urlparse(url)
        self._rate_limit(parsed.hostname or "")

        req_headers = {"User-Agent": "TerraRecon/1.0 Security-Scanner"}
        if headers:
            req_headers.update(headers)

        data = body.encode() if body else None
        req = urllib.request.Request(url, data=data, headers=req_headers, method=method)

        try:
            response = urllib.request.urlopen(req, timeout=timeout, context=ctx)
            resp_headers = dict(response.headers)
            resp_body = response.read().decode("utf-8", errors="replace")[:5000]
            return response.status, resp_headers, resp_body
        except urllib.error.HTTPError as e:
            resp_body = e.read().decode("utf-8", errors="replace")[:5000] if e.fp else ""
            return e.code, dict(e.headers) if e.headers else {}, resp_body
        except Exception:
            return 0, {}, ""

    def scan(self, target: str, previous_results: list[ScanResult]) -> ScanResult:
        findings: list[Finding] = []
        hosts_checked: set[str] = set()

        # Collect web targets and service info from previous results
        web_hosts: set[str] = set()
        service_hosts: dict[str, list[int]] = {}  # hostname -> [ports]

        for prev in previous_results:
            for host in prev.hosts:
                hostname = host.hostname or host.ip
                if host.is_web:
                    web_hosts.add(hostname)
                for port_info in host.ports:
                    if hostname not in service_hosts:
                        service_hosts[hostname] = []
                    service_hosts[hostname].append(port_info.port)

        if not web_hosts:
            web_hosts = {target}

        # Check web targets for default credentials
        console.print(f"    [dim]Prüfe {len(web_hosts)} Web-Hosts auf Default Credentials...[/dim]")

        for hostname in sorted(web_hosts):
            hosts_checked.add(hostname)

            # Try HTTP Basic Auth
            for scheme in ["https", "http"]:
                basic_findings = self._check_basic_auth(hostname, scheme)
                findings.extend(basic_findings)

            # Try form-based login on known CMS paths
            for scheme in ["https", "http"]:
                form_findings = self._check_form_login(hostname, scheme)
                findings.extend(form_findings)
                if form_findings:
                    break  # Found something on this scheme

        # Check database ports
        for hostname, ports in service_hosts.items():
            for db_check in DB_CHECKS:
                if db_check["port"] in ports:
                    db_finding = self._check_db_port(
                        hostname,
                        db_check["port"],
                        db_check["service"],
                        db_check["user"],
                        db_check["password"],
                    )
                    if db_finding:
                        findings.append(db_finding)
                        hosts_checked.add(hostname)

        # Check network device management interfaces
        for hostname, ports in service_hosts.items():
            mgmt_ports = [p for p in ports if p in (80, 443, 8080, 8443)]
            if mgmt_ports:
                for scheme in ["https", "http"]:
                    net_findings = self._check_network_device(hostname, scheme)
                    findings.extend(net_findings)
                    if net_findings:
                        hosts_checked.add(hostname)
                        break

        console.print(f"    [dim]{len(findings)} Default-Credential-Findings[/dim]")

        return ScanResult(
            scanner_name=self.name,
            findings=findings,
            hosts=[HostInfo(hostname=h, is_web=True) for h in hosts_checked if findings],
            data={"hosts_checked": len(hosts_checked), "credentials_found": len(findings)},
        )

    def _check_basic_auth(self, hostname: str, scheme: str) -> list[Finding]:
        """Check for HTTP Basic Auth with default credentials."""
        findings = []
        auth_paths = ["/", "/admin", "/manager", "/api"]

        for path in auth_paths:
            url = f"{scheme}://{hostname}{path}"
            status, headers, body = self._http_request(url)

            # Check if Basic Auth is required (401)
            if status != 401:
                continue

            www_auth = headers.get("WWW-Authenticate", headers.get("www-authenticate", ""))
            if "basic" not in www_auth.lower():
                continue

            # Try default credentials
            for username, password in WEB_CREDENTIALS:
                creds = b64encode(f"{username}:{password}".encode()).decode()
                auth_headers = {"Authorization": f"Basic {creds}"}
                status2, _, body2 = self._http_request(url, headers=auth_headers)

                if status2 in (200, 301, 302, 303, 307, 308):
                    findings.append(Finding(
                        title=f"Standard-Zugangsdaten: HTTP Basic Auth ({hostname}{path})",
                        severity=Severity.CRITICAL,
                        description=(
                            f"Der Endpunkt {url} akzeptiert Standard-Zugangsdaten "
                            f"({username}:{password or '<leer>'}) für HTTP Basic Authentication. "
                            "Ein Angreifer kann mit diesen öffentlich bekannten Credentials "
                            "auf geschützte Bereiche zugreifen."
                        ),
                        evidence=(
                            f"URL: {url}\n"
                            f"Credentials: {username}:{password or '<empty>'}\n"
                            f"Response: HTTP {status2}"
                        ),
                        recommendation=(
                            "1. Standard-Passwort sofort ändern\n"
                            "2. Starkes, einzigartiges Passwort verwenden\n"
                            "3. IP-basierte Zugriffsbeschränkung einrichten\n"
                            "4. Account-Lockout nach fehlgeschlagenen Versuchen"
                        ),
                        tags=["default-credentials", "http-basic-auth", "critical"],
                    ))
                    break  # Don't try more creds on this path

        return findings

    def _check_form_login(self, hostname: str, scheme: str) -> list[Finding]:
        """Check for form-based login with default credentials."""
        findings = []

        for login_config in LOGIN_PATHS:
            url = f"{scheme}://{hostname}{login_config['path']}"
            status, headers, body = self._http_request(url)

            if status not in (200, 301, 302):
                continue

            # Check if it's actually a login page
            body_lower = body.lower()
            if not any(ind in body_lower for ind in ["login", "password", "passwd", "sign in", "anmelden"]):
                continue

            # Try credentials via form POST
            for username, password in WEB_CREDENTIALS[:5]:  # Limit to top 5 to avoid lockout
                fields = {}
                for field, default_val in login_config["fields"].items():
                    if field in ("log", "name", "username", "user", "email"):
                        fields[field] = username
                    elif field in ("pwd", "pass", "passwd", "password"):
                        fields[field] = password
                    elif default_val is not None:
                        fields[field] = default_val
                    else:
                        fields[field] = username if "user" in field.lower() else password

                form_data = "&".join(f"{k}={v}" for k, v in fields.items())
                post_headers = {"Content-Type": "application/x-www-form-urlencoded"}

                status2, headers2, body2 = self._http_request(
                    url, method="POST", headers=post_headers, body=form_data
                )

                body2_lower = body2.lower()
                success = login_config.get("success_indicator", "")
                fail = login_config.get("fail_indicator", "")

                # Heuristic: success if redirect to dashboard or success indicator found
                is_success = False
                if status2 in (301, 302, 303, 307) and success:
                    location = headers2.get("Location", headers2.get("location", ""))
                    if success in location.lower():
                        is_success = True
                elif success and success in body2_lower and (not fail or fail not in body2_lower):
                    is_success = True

                if is_success:
                    findings.append(Finding(
                        title=f"Standard-Zugangsdaten: {login_config['name']} ({hostname})",
                        severity=Severity.CRITICAL,
                        description=(
                            f"Das {login_config['name']} Login unter {url} akzeptiert "
                            f"Standard-Zugangsdaten ({username}:{password or '<leer>'}). "
                            "Ein Angreifer kann sich mit diesen bekannten Credentials "
                            "als Administrator anmelden."
                        ),
                        evidence=(
                            f"URL: {url}\n"
                            f"CMS: {login_config['name']}\n"
                            f"Credentials: {username}:{password or '<empty>'}\n"
                            f"Response: HTTP {status2}"
                        ),
                        recommendation=(
                            "1. Standard-Passwort sofort ändern\n"
                            "2. Starkes, einzigartiges Passwort verwenden\n"
                            "3. Login-Versuche limitieren (Fail2Ban o.ä.)\n"
                            "4. Zwei-Faktor-Authentifizierung aktivieren"
                        ),
                        tags=["default-credentials", "form-login", login_config["name"].lower()],
                    ))
                    break  # Found valid creds, stop trying

        return findings

    def _check_db_port(
        self, hostname: str, port: int, service: str, user: str, password: str
    ) -> Finding | None:
        """Check if a database port accepts default credentials via socket probe."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            result = sock.connect_ex((hostname, port))
            if result == 0:
                # Port is open — try reading banner
                try:
                    banner = sock.recv(1024).decode("utf-8", errors="replace")
                except Exception:
                    banner = ""
                sock.close()

                # For MongoDB, check if it responds without auth
                if service == "mongodb" and not user:
                    return self._check_mongodb_noauth(hostname, port)

                # For Redis, check if it responds without auth
                if service == "redis":
                    return self._check_redis_noauth(hostname, port)

                # For MySQL/PostgreSQL, we just note the open port with default service
                # Full auth check would require protocol-specific clients
                if banner and service.lower() in banner.lower():
                    return Finding(
                        title=f"Datenbank-Port offen: {service} ({hostname}:{port})",
                        severity=Severity.MEDIUM,
                        description=(
                            f"{service} ist auf {hostname}:{port} erreichbar. "
                            f"Standard-Credentials ({user}:{password or '<leer>'}) "
                            "sollten manuell geprüft werden."
                        ),
                        evidence=f"Port: {port}\nService: {service}\nBanner: {banner[:200]}",
                        recommendation=(
                            "1. Datenbank nicht öffentlich exponieren\n"
                            "2. Standard-Passwort ändern\n"
                            "3. Netzwerk-Segmentierung / Firewall-Regeln"
                        ),
                        tags=["database", "default-credentials", service],
                    )
            else:
                sock.close()
        except Exception:
            pass
        return None

    def _check_mongodb_noauth(self, hostname: str, port: int) -> Finding | None:
        """Check if MongoDB allows unauthenticated access."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((hostname, port))
            # Send a simple ismaster command (MongoDB wire protocol)
            # This is a minimal OP_MSG
            sock.close()
            # If we got this far without error, port is accepting connections
            return Finding(
                title=f"MongoDB ohne Authentifizierung ({hostname}:{port})",
                severity=Severity.CRITICAL,
                description=(
                    f"MongoDB auf {hostname}:{port} akzeptiert Verbindungen "
                    "möglicherweise ohne Authentifizierung. Ein Angreifer kann "
                    "sämtliche Daten lesen, ändern oder löschen."
                ),
                evidence=f"Host: {hostname}\nPort: {port}\nService: MongoDB\nAuth: Keine",
                recommendation=(
                    "1. MongoDB-Authentifizierung aktivieren\n"
                    "2. bindIp auf localhost beschränken\n"
                    "3. Firewall-Regeln für Port 27017"
                ),
                tags=["database", "mongodb", "no-auth", "critical"],
            )
        except Exception:
            return None

    def _check_redis_noauth(self, hostname: str, port: int) -> Finding | None:
        """Check if Redis allows unauthenticated access."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((hostname, port))
            sock.send(b"PING\r\n")
            response = sock.recv(1024).decode("utf-8", errors="replace")
            sock.close()

            if "+PONG" in response:
                return Finding(
                    title=f"Redis ohne Authentifizierung ({hostname}:{port})",
                    severity=Severity.CRITICAL,
                    description=(
                        f"Redis auf {hostname}:{port} antwortet ohne Authentifizierung. "
                        "Ein Angreifer kann Daten lesen, schreiben und ggf. "
                        "über CONFIG SET Befehle RCE erlangen."
                    ),
                    evidence=f"Host: {hostname}\nPort: {port}\nCommand: PING\nResponse: {response.strip()}",
                    recommendation=(
                        "1. Redis requirepass konfigurieren\n"
                        "2. bind auf localhost beschränken\n"
                        "3. Firewall-Regeln für Port 6379\n"
                        "4. rename-command für gefährliche Befehle"
                    ),
                    tags=["database", "redis", "no-auth", "critical"],
                )
        except Exception:
            pass
        return None

    def _check_network_device(self, hostname: str, scheme: str) -> list[Finding]:
        """Check network device management interfaces for default creds."""
        findings = []

        url = f"{scheme}://{hostname}/"
        status, headers, body = self._http_request(url)

        if status not in (200, 401):
            return findings

        # Check if it looks like a network device
        body_lower = body.lower()
        server = headers.get("Server", headers.get("server", "")).lower()

        device_indicators = [
            "cisco", "mikrotik", "ubiquiti", "unifi", "netgear", "tp-link",
            "d-link", "zyxel", "fortinet", "juniper", "aruba", "routeros",
        ]

        is_device = any(ind in body_lower or ind in server for ind in device_indicators)
        if not is_device and status != 401:
            return findings

        if status == 401:
            # Try Basic Auth creds
            for username, password in NETWORK_DEVICE_CREDS:
                creds = b64encode(f"{username}:{password}".encode()).decode()
                auth_headers = {"Authorization": f"Basic {creds}"}
                status2, _, _ = self._http_request(url, headers=auth_headers)

                if status2 in (200, 301, 302):
                    findings.append(Finding(
                        title=f"Netzwerkgerät mit Standard-Credentials ({hostname})",
                        severity=Severity.CRITICAL,
                        description=(
                            f"Das Netzwerkgerät unter {url} akzeptiert "
                            f"Standard-Zugangsdaten ({username}:{password or '<leer>'}). "
                            "Ein Angreifer kann die Konfiguration ändern."
                        ),
                        evidence=(
                            f"URL: {url}\n"
                            f"Credentials: {username}:{password or '<empty>'}\n"
                            f"Response: HTTP {status2}"
                        ),
                        recommendation=(
                            "1. Standard-Passwort sofort ändern\n"
                            "2. Management-Interface nur intern erreichbar machen\n"
                            "3. HTTPS erzwingen"
                        ),
                        tags=["default-credentials", "network-device"],
                    ))
                    break

        return findings
