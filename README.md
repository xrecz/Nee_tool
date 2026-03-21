# Nee Tool — Automated Pentest Toolkit

Modulares Pentest-Toolkit das externe Sicherheitstools zu einer automatisierten Pipeline verbindet, professionelle PDF-Berichte generiert und GoPhish-Phishing-Kampagnen steuert.

Entwickelt für Pentest-Dienstleister im DACH-Raum.

## Features

### Recon-Pipeline
Automatisierte Reconnaissance mit 7 verketteten Scanner-Modulen:

| Modul | Funktion | Externe Tools | Fallback |
|-------|----------|---------------|----------|
| `subdomain` | Subdomain-Enumeration | subfinder | crt.sh API |
| `portscan` | Port-Scan + Service-Erkennung | nmap | — |
| `web_discovery` | HTTP/HTTPS Probing | httpx | Python urllib |
| `security_headers` | Security-Header-Analyse | — | Python (6 Security + 3 Info-Disclosure Headers) |
| `ssl_check` | SSL/TLS-Analyse | testssl.sh | Python ssl |
| `tech_detect` | Technologie-Erkennung | whatweb | Signatur-basiert (17 Patterns) |
| `nuclei` | CVE/Schwachstellen-Scan | nuclei | — |

Jeder Scanner baut auf den Ergebnissen der vorherigen auf. Fehlende Tools werden automatisch erkannt und übersprungen.

### Report-Generator
Professionelle PDF-Pentest-Berichte mit:
- Deckblatt mit Vertraulichkeits-Klassifizierung
- Management Summary mit Severity-Statistiken
- Scope & Methodik
- Host-/Dienst-Übersicht
- Detaillierte Finding-Cards (Beschreibung, PoC, Empfehlung, Referenzen)
- CVSS v3.1 Scoring
- Disclaimer

**20 vorgefertigte Finding-Templates** für gängige Schwachstellen (SQLi, XSS, IDOR, Default Credentials, fehlende Headers, etc.)

### GoPhish-Integration
Vollständige Steuerung von Phishing-Kampagnen über die CLI:
- Kampagne in einem Befehl aufsetzen + starten
- 5 deutsche E-Mail-Templates (IT-Support, M365, Bewerbung, Rechnung, DHL)
- Live-Status-Tracking
- Professioneller Kampagnen-Bericht (PDF) mit Conversion-Funnel und Benchmarking

## Installation

### Voraussetzungen
- Python 3.10+
- Optional: Kali Linux oder vergleichbares System mit Pentest-Tools

### Setup

```bash
git clone <repo-url> && cd Nee_tool
pip install -e .
```

### Externe Tools (optional)

Die Pipeline funktioniert auch ohne externe Tools (mit eingeschränktem Funktionsumfang). Für den vollen Umfang:

```bash
# Auf Kali Linux sind die meisten Tools vorinstalliert
# Ansonsten:
sudo apt install nmap
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
sudo apt install whatweb testssl.sh
```

Verfügbarkeit prüfen:
```bash
nee scanners
```

## Nutzung

### Recon-Pipeline

```bash
# Vollständiger Scan
nee scan example.de --name "Kunde-ABC-Q1-2026"

# Nur bestimmte Module
nee scan example.de --only subdomain,portscan,web_discovery

# Module überspringen
nee scan example.de --skip nuclei

# Weniger Ports scannen (schneller)
nee scan example.de --top-ports 100

# Timeout pro Scanner anpassen
nee scan example.de --timeout 300
```

Output: JSON-Dateien in `./output/<projektname>/`

### Berichte generieren

```bash
# PDF-Bericht aus Scan-Ergebnissen
nee report output/kunde_abc/kunde_abc_20260321.json \
    --client "Firma XYZ GmbH" \
    --author "Max Mustermann" \
    --date-range "01.03. - 15.03.2026"

# HTML-Vorschau (schneller, im Browser prüfbar)
nee report output/kunde_abc/kunde_abc_20260321.json --html-only

# Demo-Bericht mit Beispieldaten
nee demo-report
nee demo-report --html-only
```

### Finding-Templates

```bash
# Alle Templates anzeigen
nee templates
```

Templates decken ab: SQL Injection, XSS (Stored/Reflected), IDOR, Auth Bypass, RCE, Default Credentials, fehlende Security Headers, SSL-Probleme, CORS, Directory Listing, Cookie Flags, und mehr.

### Phishing-Kampagnen (GoPhish)

Voraussetzung: Laufende [GoPhish](https://getgophish.com/)-Instanz.

```bash
# Verfügbare E-Mail-Templates anzeigen
nee phish templates

# Kampagne aufsetzen und starten
nee phish setup \
    --api-key "your-api-key" \
    --name "Awareness-Q1-2026" \
    --template it_password_reset \
    --smtp-host "mail.example.de:587" \
    --smtp-from "it-support@example.de" \
    --smtp-user "user" \
    --smtp-pass "pass" \
    --targets mitarbeiter.csv \
    --url "https://phish.example.de"

# Status prüfen
nee phish status 42 --api-key "your-api-key"

# Kampagnen-Bericht als PDF
nee phish report 42 --api-key "your-api-key" --client "Firma XYZ"

# Demo-Bericht
nee phish demo-report
```

**CSV-Format für Targets:**
```csv
email,first_name,last_name,position
max.mustermann@example.de,Max,Mustermann,IT-Leiter
anna.schmidt@example.de,Anna,Schmidt,Buchhaltung
```

## Projektstruktur

```
src/nee_tool/
├── cli.py                     # CLI-Befehle (Typer)
├── core/
│   ├── config.py              # Konfiguration
│   ├── models.py              # Datenmodelle (Pydantic)
│   └── orchestrator.py        # Pipeline-Steuerung
├── scanners/                  # Scanner-Module (Plugin-System)
│   ├── base.py                # Basis-Klasse
│   ├── subdomain.py
│   ├── portscan.py
│   ├── web_discovery.py
│   ├── security_headers.py
│   ├── ssl_check.py
│   ├── tech_detect.py
│   └── nuclei.py
├── report/                    # Pentest-Berichte
│   ├── generator.py           # PDF/HTML-Erzeugung
│   ├── finding_templates.py   # Finding-Vorlagen
│   ├── cvss.py                # CVSS v3.1 Rechner
│   └── templates/report.html  # HTML-Template
├── phishing/                  # GoPhish-Integration
│   ├── client.py              # REST-API-Client
│   ├── email_templates.py     # Phishing-E-Mail-Vorlagen
│   └── report.py              # Kampagnen-Berichte
└── output/
    └── json_export.py         # JSON-Export
```

## Eigene Scanner entwickeln

```python
# src/nee_tool/scanners/my_scanner.py
from nee_tool.core.models import ScanResult
from nee_tool.scanners.base import BaseScanner

class MyScanner(BaseScanner):
    name = "my_scanner"
    description = "Beschreibung des Scanners"
    required_tools = ["toolname"]  # Wird automatisch geprüft

    def scan(self, target: str, previous_results: list[ScanResult]) -> ScanResult:
        # previous_results enthält alle bisherigen Ergebnisse
        # z.B. Subdomains, entdeckte Hosts, etc.
        result = self.run_command(["toolname", target])
        return ScanResult(
            scanner_name=self.name,
            # hosts=[], findings=[], subdomains=[], ...
        )
```

Dann in `orchestrator.py` registrieren:
```python
from nee_tool.scanners.my_scanner import MyScanner
SCANNER_REGISTRY["my_scanner"] = MyScanner
```

## Lizenz

Proprietär — nur für autorisierte Sicherheitstests einsetzen.
