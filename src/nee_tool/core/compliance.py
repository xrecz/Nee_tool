"""Compliance mapping for findings.

Maps security findings to compliance framework controls:
- BSI IT-Grundschutz (Kompendium 2023)
- ISO 27001:2022 Annex A
- DSGVO Art. 32 (Sicherheit der Verarbeitung)

Used in report generation to show customers which compliance
requirements are affected by discovered vulnerabilities.
"""

from __future__ import annotations

from pydantic import BaseModel, Field

from nee_tool.core.models import Finding


class ComplianceControl(BaseModel):
    """A single compliance framework control."""

    framework: str  # "BSI", "ISO27001", "DSGVO"
    control_id: str  # e.g. "A.8.9", "SYS.1.1.A6"
    title: str
    description: str = ""


class ComplianceMapping(BaseModel):
    """Finding mapped to compliance controls."""

    finding_title: str
    controls: list[ComplianceControl] = Field(default_factory=list)


# ── Compliance control database ─────────────────────────────

# Tag-based mapping: finding tags → relevant controls
_TAG_MAPPINGS: dict[str, list[ComplianceControl]] = {
    # Encryption / SSL/TLS
    "ssl": [
        ComplianceControl(
            framework="BSI",
            control_id="CON.1.A6",
            title="Verschlüsselung und Schlüsselmanagement",
            description="Kryptographische Verfahren müssen dem Stand der Technik entsprechen.",
        ),
        ComplianceControl(
            framework="ISO27001",
            control_id="A.8.24",
            title="Use of Cryptography",
            description="Rules for effective use of cryptography shall be defined and implemented.",
        ),
        ComplianceControl(
            framework="DSGVO",
            control_id="Art. 32 (1)(a)",
            title="Verschlüsselung personenbezogener Daten",
            description="Pseudonymisierung und Verschlüsselung personenbezogener Daten.",
        ),
    ],
    "tls-version": [
        ComplianceControl(
            framework="BSI",
            control_id="CON.1.A15",
            title="Sichere TLS-Konfiguration",
            description="TLS muss mindestens in Version 1.2 eingesetzt werden.",
        ),
        ComplianceControl(
            framework="ISO27001",
            control_id="A.8.24",
            title="Use of Cryptography",
        ),
    ],
    "certificate": [
        ComplianceControl(
            framework="BSI",
            control_id="CON.1.A11",
            title="Zertifikatsmanagement",
            description="Zertifikate müssen rechtzeitig erneuert werden.",
        ),
        ComplianceControl(
            framework="ISO27001",
            control_id="A.8.24",
            title="Use of Cryptography",
        ),
    ],

    # Authentication
    "default-login": [
        ComplianceControl(
            framework="BSI",
            control_id="ORP.4.A2",
            title="Regelung für Passwort-Qualität",
            description="Standard-Zugangsdaten müssen bei Inbetriebnahme geändert werden.",
        ),
        ComplianceControl(
            framework="ISO27001",
            control_id="A.5.17",
            title="Authentication Information",
            description="Allocation of authentication information shall be controlled.",
        ),
        ComplianceControl(
            framework="DSGVO",
            control_id="Art. 32 (1)(b)",
            title="Vertraulichkeit der Systeme",
            description="Fähigkeit, Vertraulichkeit und Integrität sicherzustellen.",
        ),
    ],
    "auth": [
        ComplianceControl(
            framework="BSI",
            control_id="ORP.4.A1",
            title="Identifikation und Authentisierung",
        ),
        ComplianceControl(
            framework="ISO27001",
            control_id="A.8.5",
            title="Secure Authentication",
        ),
    ],

    # Web Security Headers
    "headers": [
        ComplianceControl(
            framework="BSI",
            control_id="APP.3.1.A14",
            title="Schutz vertraulicher Daten bei Webanwendungen",
            description="HTTP-Security-Header müssen korrekt gesetzt sein.",
        ),
        ComplianceControl(
            framework="ISO27001",
            control_id="A.8.9",
            title="Configuration Management",
            description="Configurations shall be established, documented, and maintained.",
        ),
    ],
    "hsts": [
        ComplianceControl(
            framework="BSI",
            control_id="APP.3.1.A14",
            title="Schutz vertraulicher Daten bei Webanwendungen",
        ),
    ],
    "csp": [
        ComplianceControl(
            framework="BSI",
            control_id="APP.3.1.A14",
            title="Schutz vertraulicher Daten bei Webanwendungen",
        ),
        ComplianceControl(
            framework="ISO27001",
            control_id="A.8.9",
            title="Configuration Management",
        ),
    ],
    "cors": [
        ComplianceControl(
            framework="BSI",
            control_id="APP.3.1.A14",
            title="Schutz vertraulicher Daten bei Webanwendungen",
        ),
    ],

    # Injection / Application Security
    "sqli": [
        ComplianceControl(
            framework="BSI",
            control_id="APP.3.1.A4",
            title="Kontrolliertes Einbinden von Inhalten bei Webanwendungen",
            description="Eingabedaten müssen validiert und bereinigt werden.",
        ),
        ComplianceControl(
            framework="ISO27001",
            control_id="A.8.26",
            title="Application Security Requirements",
            description="Information security requirements shall be identified when developing applications.",
        ),
        ComplianceControl(
            framework="DSGVO",
            control_id="Art. 32 (1)(b)",
            title="Integrität der Systeme",
            description="Fähigkeit, Integrität der Systeme und Dienste sicherzustellen.",
        ),
    ],
    "xss": [
        ComplianceControl(
            framework="BSI",
            control_id="APP.3.1.A4",
            title="Kontrolliertes Einbinden von Inhalten bei Webanwendungen",
        ),
        ComplianceControl(
            framework="ISO27001",
            control_id="A.8.26",
            title="Application Security Requirements",
        ),
    ],

    # Information Disclosure
    "info-disclosure": [
        ComplianceControl(
            framework="BSI",
            control_id="APP.3.1.A1",
            title="Absicherung von Webanwendungen",
            description="Technische Informationen dürfen nicht offengelegt werden.",
        ),
        ComplianceControl(
            framework="ISO27001",
            control_id="A.8.12",
            title="Data Leakage Prevention",
        ),
    ],

    # Vulnerability Management / Patching
    "cve": [
        ComplianceControl(
            framework="BSI",
            control_id="OPS.1.1.3.A2",
            title="Festlegung der Verantwortlichkeiten für Patch-Management",
            description="Sicherheitsupdates müssen zeitnah eingespielt werden.",
        ),
        ComplianceControl(
            framework="ISO27001",
            control_id="A.8.8",
            title="Management of Technical Vulnerabilities",
            description="Information about technical vulnerabilities shall be obtained and evaluated.",
        ),
        ComplianceControl(
            framework="DSGVO",
            control_id="Art. 32 (1)(d)",
            title="Regelmäßige Überprüfung",
            description="Verfahren zur regelmäßigen Überprüfung und Bewertung der Wirksamkeit.",
        ),
    ],
    "nvd": [
        ComplianceControl(
            framework="BSI",
            control_id="OPS.1.1.3.A2",
            title="Festlegung der Verantwortlichkeiten für Patch-Management",
        ),
        ComplianceControl(
            framework="ISO27001",
            control_id="A.8.8",
            title="Management of Technical Vulnerabilities",
        ),
    ],
    "software": [
        ComplianceControl(
            framework="BSI",
            control_id="OPS.1.1.3.A7",
            title="Regelmäßige Aktualisierung von Software",
        ),
        ComplianceControl(
            framework="ISO27001",
            control_id="A.8.8",
            title="Management of Technical Vulnerabilities",
        ),
    ],

    # Network / Port Security
    "ports": [
        ComplianceControl(
            framework="BSI",
            control_id="NET.1.1.A4",
            title="Netzsegmentierung",
            description="Nur benötigte Dienste und Ports dürfen erreichbar sein.",
        ),
        ComplianceControl(
            framework="ISO27001",
            control_id="A.8.20",
            title="Network Security",
        ),
    ],

    # Sensitive Files / Directory Listing
    "sensitive-url": [
        ComplianceControl(
            framework="BSI",
            control_id="APP.3.1.A1",
            title="Absicherung von Webanwendungen",
        ),
        ComplianceControl(
            framework="ISO27001",
            control_id="A.8.12",
            title="Data Leakage Prevention",
        ),
        ComplianceControl(
            framework="DSGVO",
            control_id="Art. 32 (1)(b)",
            title="Vertraulichkeit der Systeme",
        ),
    ],
    "dir_bruteforce": [
        ComplianceControl(
            framework="BSI",
            control_id="APP.3.1.A1",
            title="Absicherung von Webanwendungen",
        ),
    ],

    # Cookie Security
    "cookie": [
        ComplianceControl(
            framework="BSI",
            control_id="APP.3.1.A14",
            title="Schutz vertraulicher Daten bei Webanwendungen",
        ),
        ComplianceControl(
            framework="ISO27001",
            control_id="A.8.9",
            title="Configuration Management",
        ),
    ],
}

# Severity-based fallback for findings with no matching tags
_SEVERITY_FALLBACK: dict[str, list[ComplianceControl]] = {
    "critical": [
        ComplianceControl(
            framework="DSGVO",
            control_id="Art. 33",
            title="Meldung von Verletzungen an die Aufsichtsbehörde",
            description="Verletzungen des Schutzes personenbezogener Daten sind "
                       "innerhalb von 72 Stunden zu melden.",
        ),
        ComplianceControl(
            framework="BSI",
            control_id="DER.2.1.A1",
            title="Behandlung von Sicherheitsvorfällen",
        ),
    ],
    "high": [
        ComplianceControl(
            framework="DSGVO",
            control_id="Art. 32 (1)",
            title="Sicherheit der Verarbeitung",
            description="Geeignete technische und organisatorische Maßnahmen treffen.",
        ),
    ],
}


def map_finding_to_controls(finding: Finding) -> list[ComplianceControl]:
    """Map a single finding to relevant compliance controls.

    Matches based on finding tags, falling back to severity-based
    controls if no tags match.
    """
    controls: list[ComplianceControl] = []
    seen: set[str] = set()

    # Match by tags
    for tag in finding.tags:
        tag_lower = tag.lower().strip()
        if tag_lower in _TAG_MAPPINGS:
            for ctrl in _TAG_MAPPINGS[tag_lower]:
                key = f"{ctrl.framework}:{ctrl.control_id}"
                if key not in seen:
                    controls.append(ctrl)
                    seen.add(key)

    # Severity fallback if no tag matches
    if not controls:
        sev = finding.severity.value
        if sev in _SEVERITY_FALLBACK:
            controls.extend(_SEVERITY_FALLBACK[sev])

    return controls


def map_all_findings(findings: list[Finding]) -> list[ComplianceMapping]:
    """Map all findings to compliance controls.

    Returns only findings that have at least one compliance mapping.
    """
    mappings: list[ComplianceMapping] = []
    for finding in findings:
        controls = map_finding_to_controls(finding)
        if controls:
            mappings.append(ComplianceMapping(
                finding_title=finding.title,
                controls=controls,
            ))
    return mappings


def compliance_summary(findings: list[Finding]) -> dict[str, list[str]]:
    """Summarize affected controls per framework.

    Returns a dict like:
        {"BSI": ["CON.1.A6", "APP.3.1.A4"], "ISO27001": [...], "DSGVO": [...]}
    """
    framework_controls: dict[str, set[str]] = {}
    for finding in findings:
        controls = map_finding_to_controls(finding)
        for ctrl in controls:
            if ctrl.framework not in framework_controls:
                framework_controls[ctrl.framework] = set()
            framework_controls[ctrl.framework].add(f"{ctrl.control_id}: {ctrl.title}")

    return {fw: sorted(ctrls) for fw, ctrls in sorted(framework_controls.items())}
