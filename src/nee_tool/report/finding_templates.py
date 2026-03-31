"""Finding template library.

Pre-defined finding templates for common vulnerability categories.
Saves time by providing ready-made descriptions and recommendations
that only need minor customization per engagement.

Each template includes a CVSS v3.1 vector for automatic scoring.
"""

from __future__ import annotations

from nee_tool.core.models import Finding, Severity

# Each template is a partial Finding — the pentester fills in evidence + target specifics.
# cvss_vector is stored in tags as "cvss_vector:CVSS:3.1/..."
FINDING_TEMPLATES: dict[str, dict] = {
    # ── Critical ──────────────────────────────────────────────
    "sqli": {
        "finding": Finding(
            title="SQL Injection",
            severity=Severity.CRITICAL,
            description=(
                "In der Anwendung wurde eine SQL-Injection-Schwachstelle identifiziert. "
                "Ein Angreifer kann durch manipulierte Eingaben beliebige SQL-Befehle "
                "auf der Datenbank ausführen. Dies ermöglicht das Auslesen, Verändern "
                "oder Löschen sämtlicher Datenbankinhalte sowie ggf. die Übernahme "
                "des Servers."
            ),
            recommendation=(
                "1. Prepared Statements / Parametrisierte Queries verwenden\n"
                "2. Input Validation auf Server-Seite implementieren\n"
                "3. Principle of Least Privilege für Datenbank-User\n"
                "4. WAF-Regeln als zusätzliche Schutzschicht"
            ),
            references=[
                "https://owasp.org/www-community/attacks/SQL_Injection",
                "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
            ],
            tags=["owasp-top10", "injection", "database"],
        ),
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    },
    "rce": {
        "finding": Finding(
            title="Remote Code Execution",
            severity=Severity.CRITICAL,
            description=(
                "Es wurde eine Schwachstelle identifiziert, die einem Angreifer "
                "die Ausführung beliebiger Befehle auf dem Server ermöglicht. "
                "Dies führt zur vollständigen Kompromittierung des Systems."
            ),
            recommendation=(
                "1. Benutzereingaben niemals direkt an System-Befehle übergeben\n"
                "2. Allowlists für erlaubte Eingaben implementieren\n"
                "3. Betroffene Komponente/Bibliothek aktualisieren\n"
                "4. Sandboxing und Least-Privilege-Prinzip anwenden"
            ),
            references=["https://owasp.org/www-community/attacks/Command_Injection"],
            tags=["owasp-top10", "injection", "rce"],
        ),
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
    },
    "auth_bypass": {
        "finding": Finding(
            title="Authentication Bypass",
            severity=Severity.CRITICAL,
            description=(
                "Die Authentifizierung der Anwendung kann umgangen werden. "
                "Ein Angreifer erhält ohne gültige Zugangsdaten Zugriff auf "
                "geschützte Bereiche und Funktionen."
            ),
            recommendation=(
                "1. Authentifizierungsmechanismus grundlegend überprüfen\n"
                "2. Session-Management absichern\n"
                "3. Multi-Factor Authentication implementieren\n"
                "4. Alle Endpunkte auf korrekte Auth-Prüfung testen"
            ),
            references=["https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/"],
            tags=["owasp-top10", "authentication"],
        ),
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
    },

    # ── High ──────────────────────────────────────────────────
    "xss_stored": {
        "finding": Finding(
            title="Stored Cross-Site Scripting (XSS)",
            severity=Severity.HIGH,
            description=(
                "In der Anwendung wurde eine persistente (Stored) XSS-Schwachstelle "
                "gefunden. Eingeschleuster JavaScript-Code wird in der Datenbank "
                "gespeichert und bei jedem Seitenaufruf durch andere Benutzer "
                "ausgeführt. Dies ermöglicht Session-Hijacking, Keylogging und "
                "Phishing-Angriffe."
            ),
            recommendation=(
                "1. Output Encoding für alle dynamischen Inhalte (HTML, JS, CSS, URL)\n"
                "2. Content Security Policy (CSP) implementieren\n"
                "3. Input Validation auf Server-Seite\n"
                "4. HttpOnly und Secure Flags für Session-Cookies"
            ),
            references=["https://owasp.org/www-community/attacks/xss/"],
            tags=["owasp-top10", "xss", "injection"],
        ),
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N",
    },
    "xss_reflected": {
        "finding": Finding(
            title="Reflected Cross-Site Scripting (XSS)",
            severity=Severity.HIGH,
            description=(
                "Es wurde eine reflektierte XSS-Schwachstelle identifiziert. "
                "Benutzereingaben werden ohne ausreichende Sanitisierung in die "
                "Server-Antwort eingebettet. Durch manipulierte Links kann ein "
                "Angreifer JavaScript im Browser des Opfers ausführen."
            ),
            recommendation=(
                "1. Output Encoding für alle dynamischen Inhalte\n"
                "2. Content Security Policy (CSP) implementieren\n"
                "3. Input Validation auf Server-Seite\n"
                "4. HttpOnly und Secure Flags für Session-Cookies"
            ),
            references=["https://owasp.org/www-community/attacks/xss/"],
            tags=["owasp-top10", "xss", "injection"],
        ),
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
    },
    "idor": {
        "finding": Finding(
            title="Insecure Direct Object Reference (IDOR)",
            severity=Severity.HIGH,
            description=(
                "Die Anwendung prüft nicht ausreichend, ob der authentifizierte "
                "Benutzer berechtigt ist, auf das angeforderte Objekt zuzugreifen. "
                "Durch Manipulation von IDs/Referenzen in Anfragen kann auf Daten "
                "anderer Benutzer zugegriffen werden."
            ),
            recommendation=(
                "1. Serverseitige Berechtigungsprüfung für jeden Objektzugriff\n"
                "2. Indirekte Referenzen statt vorhersagbarer IDs verwenden\n"
                "3. Zugriffsmatrix implementieren und testen\n"
                "4. Logging verdächtiger Zugriffsmuster"
            ),
            references=["https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References"],
            tags=["owasp-top10", "broken-access-control"],
        ),
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N",
    },
    "ssl_expired": {
        "finding": Finding(
            title="Abgelaufenes SSL/TLS-Zertifikat",
            severity=Severity.HIGH,
            description=(
                "Das SSL/TLS-Zertifikat des Servers ist abgelaufen. "
                "Benutzer erhalten Sicherheitswarnungen im Browser, und die "
                "verschlüsselte Verbindung ist nicht mehr vertrauenswürdig."
            ),
            recommendation=(
                "1. Zertifikat umgehend erneuern\n"
                "2. Automatische Zertifikatserneuerung einrichten (Let's Encrypt / ACME)\n"
                "3. Monitoring für Zertifikats-Ablaufdaten implementieren"
            ),
            tags=["ssl", "certificate"],
        ),
        "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
    },
    "tls_outdated": {
        "finding": Finding(
            title="Veraltete TLS-Version",
            severity=Severity.HIGH,
            description=(
                "Der Server unterstützt veraltete TLS-Versionen (TLS 1.0/1.1), "
                "die bekannte Schwachstellen aufweisen (BEAST, POODLE). "
                "Verschlüsselte Verbindungen können potentiell entschlüsselt werden."
            ),
            recommendation=(
                "1. TLS 1.0 und 1.1 deaktivieren\n"
                "2. Mindestens TLS 1.2 erzwingen, idealerweise TLS 1.3\n"
                "3. Sichere Cipher Suites konfigurieren"
            ),
            references=["https://www.ncsc.gov.uk/guidance/using-tls-to-protect-data"],
            tags=["ssl", "tls-version"],
        ),
        "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
    },
    "default_credentials": {
        "finding": Finding(
            title="Standard-Zugangsdaten",
            severity=Severity.HIGH,
            description=(
                "Für den Dienst sind Standard-/Werks-Zugangsdaten aktiv. "
                "Ein Angreifer kann mit öffentlich bekannten Credentials "
                "administrativen Zugriff erlangen."
            ),
            recommendation=(
                "1. Standard-Passwörter sofort ändern\n"
                "2. Starke, einzigartige Passwörter verwenden\n"
                "3. Standard-Accounts deaktivieren wenn möglich\n"
                "4. Regelmäßige Prüfung auf Default Credentials einführen"
            ),
            tags=["credentials", "misconfiguration"],
        ),
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    },

    # ── Medium ────────────────────────────────────────────────
    "missing_hsts": {
        "finding": Finding(
            title="Fehlender HTTP Strict Transport Security (HSTS) Header",
            severity=Severity.MEDIUM,
            description=(
                "Der Server sendet keinen HSTS-Header. Ohne HSTS können "
                "Benutzer über HTTP-Downgrade-Angriffe (SSL-Stripping) auf "
                "eine unverschlüsselte Verbindung umgeleitet werden."
            ),
            recommendation=(
                "1. HSTS-Header setzen: Strict-Transport-Security: max-age=31536000; includeSubDomains\n"
                "2. HTTP-zu-HTTPS-Redirect einrichten\n"
                "3. Langfristig: HSTS Preload-Liste beantragen"
            ),
            references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security"],
            tags=["headers", "ssl"],
        ),
        "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N",
    },
    "missing_csp": {
        "finding": Finding(
            title="Fehlende Content Security Policy (CSP)",
            severity=Severity.MEDIUM,
            description=(
                "Die Anwendung definiert keine Content Security Policy. "
                "Ohne CSP gibt es keinen Browser-seitigen Schutz gegen "
                "Cross-Site-Scripting und Data-Injection-Angriffe."
            ),
            recommendation=(
                "1. CSP-Header implementieren, mindestens: default-src 'self'\n"
                "2. Inline-Scripts vermeiden oder per Nonce/Hash erlauben\n"
                "3. report-uri für CSP-Verletzungen einrichten"
            ),
            references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP"],
            tags=["headers", "csp"],
        ),
        "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:L/A:N",
    },
    "ssl_soon_expiring": {
        "finding": Finding(
            title="SSL-Zertifikat läuft bald ab",
            severity=Severity.MEDIUM,
            description=(
                "Das SSL/TLS-Zertifikat läuft in weniger als 30 Tagen ab. "
                "Ohne rechtzeitige Erneuerung werden Benutzer Sicherheitswarnungen "
                "erhalten."
            ),
            recommendation=(
                "1. Zertifikat zeitnah erneuern\n"
                "2. Automatische Erneuerung einrichten (ACME/Let's Encrypt)\n"
                "3. Monitoring für Zertifikats-Ablaufdaten"
            ),
            tags=["ssl", "certificate"],
        ),
        "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
    },
    "clickjacking": {
        "finding": Finding(
            title="Clickjacking (fehlender X-Frame-Options Header)",
            severity=Severity.MEDIUM,
            description=(
                "Die Anwendung setzt keinen X-Frame-Options Header. "
                "Dadurch kann die Seite in einem iframe eingebettet werden, "
                "was Clickjacking-Angriffe ermöglicht."
            ),
            recommendation=(
                "1. X-Frame-Options Header setzen: DENY oder SAMEORIGIN\n"
                "2. Alternativ/zusätzlich: CSP frame-ancestors Direktive nutzen"
            ),
            tags=["headers", "clickjacking"],
        ),
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",
    },
    "cors_misconfigured": {
        "finding": Finding(
            title="CORS Fehlkonfiguration",
            severity=Severity.MEDIUM,
            description=(
                "Die Cross-Origin Resource Sharing (CORS) Konfiguration ist "
                "zu permissiv. Beliebige Domains können auf API-Endpunkte zugreifen, "
                "was den Diebstahl von Benutzerdaten ermöglicht."
            ),
            recommendation=(
                "1. Access-Control-Allow-Origin auf spezifische Domains beschränken\n"
                "2. Wildcard (*) in Kombination mit Credentials vermeiden\n"
                "3. Nur benötigte HTTP-Methoden in Access-Control-Allow-Methods"
            ),
            references=["https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny"],
            tags=["cors", "misconfiguration"],
        ),
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N",
    },
    "directory_listing": {
        "finding": Finding(
            title="Directory Listing aktiviert",
            severity=Severity.MEDIUM,
            description=(
                "Der Webserver zeigt Verzeichnisinhalte an. Dies gibt einem "
                "Angreifer Einblick in die Dateistruktur und kann sensible "
                "Dateien offenlegen (Backups, Konfigurationen, Quellcode)."
            ),
            recommendation=(
                "1. Directory Listing im Webserver deaktivieren\n"
                "   - Apache: Options -Indexes\n"
                "   - nginx: autoindex off;\n"
                "2. Sensible Dateien aus dem Web-Root entfernen"
            ),
            tags=["misconfiguration", "information-disclosure"],
        ),
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    },

    # ── Low ───────────────────────────────────────────────────
    "server_version_exposed": {
        "finding": Finding(
            title="Server-Version in HTTP-Header exponiert",
            severity=Severity.LOW,
            description=(
                "Der Server gibt seine Software-Version in HTTP-Headern preis. "
                "Diese Information erleichtert einem Angreifer die gezielte "
                "Suche nach bekannten Schwachstellen."
            ),
            recommendation=(
                "1. Server-Header entfernen oder generisch setzen\n"
                "   - Apache: ServerTokens Prod\n"
                "   - nginx: server_tokens off;\n"
                "2. X-Powered-By Header entfernen"
            ),
            tags=["headers", "information-disclosure"],
        ),
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    },
    "cookie_flags_missing": {
        "finding": Finding(
            title="Fehlende Cookie-Security-Flags",
            severity=Severity.LOW,
            description=(
                "Session-Cookies werden ohne Secure, HttpOnly oder SameSite "
                "Flags gesetzt. Dies erhöht das Risiko für Session-Hijacking "
                "und Cross-Site-Request-Forgery."
            ),
            recommendation=(
                "1. Secure-Flag setzen (Cookie nur über HTTPS)\n"
                "2. HttpOnly-Flag setzen (kein JavaScript-Zugriff)\n"
                "3. SameSite=Lax oder Strict setzen"
            ),
            tags=["cookies", "session"],
        ),
        "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N",
    },
    "missing_referrer_policy": {
        "finding": Finding(
            title="Fehlende Referrer-Policy",
            severity=Severity.LOW,
            description=(
                "Die Anwendung setzt keinen Referrer-Policy Header. "
                "Dadurch können sensible URL-Parameter an Drittseiten "
                "übermittelt werden."
            ),
            recommendation="Referrer-Policy Header setzen: strict-origin-when-cross-origin",
            tags=["headers", "privacy"],
        ),
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N",
    },

    # ── Info ──────────────────────────────────────────────────
    "outdated_software": {
        "finding": Finding(
            title="Veraltete Software-Version",
            severity=Severity.INFO,
            description=(
                "Es wurde eine veraltete Software-Version identifiziert. "
                "Veraltete Software kann bekannte Schwachstellen enthalten."
            ),
            recommendation=(
                "1. Software auf die aktuelle Version aktualisieren\n"
                "2. Regelmäßigen Patch-Prozess etablieren"
            ),
            tags=["software", "patch-management"],
        ),
        "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N",
    },
    "info_disclosure": {
        "finding": Finding(
            title="Information Disclosure",
            severity=Severity.INFO,
            description=(
                "Die Anwendung gibt technische Informationen preis, die einem "
                "Angreifer bei der Planung weiterer Angriffe helfen können."
            ),
            recommendation="Technische Details (Stacktraces, Debug-Infos, Versionsnummern) in Produktionsumgebungen deaktivieren.",
            tags=["information-disclosure"],
        ),
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    },
}


def get_template(key: str) -> Finding | None:
    """Get a finding template by key."""
    entry = FINDING_TEMPLATES.get(key)
    if entry is None:
        return None
    return entry["finding"]


def get_template_with_cvss(key: str) -> tuple[Finding | None, str]:
    """Get a finding template and its CVSS vector."""
    entry = FINDING_TEMPLATES.get(key)
    if entry is None:
        return None, ""
    return entry["finding"], entry.get("cvss_vector", "")


def list_templates() -> dict[str, Finding]:
    """Return all available templates (Finding objects only)."""
    return {k: v["finding"] for k, v in FINDING_TEMPLATES.items()}


def create_finding_from_template(
    key: str,
    target: str = "",
    evidence: str = "",
    extra_description: str = "",
) -> Finding | None:
    """Create a finding from a template with target-specific details."""
    template = get_template(key)
    if not template:
        return None

    finding = template.model_copy()
    if target:
        finding.title = f"{finding.title} ({target})"
    if evidence:
        finding.evidence = evidence
    if extra_description:
        finding.description = f"{finding.description}\n\n{extra_description}"

    # Add CVSS vector as tag if available
    entry = FINDING_TEMPLATES.get(key)
    if entry and entry.get("cvss_vector"):
        finding.tags = list(finding.tags) + [f"cvss_vector:{entry['cvss_vector']}"]

    return finding
