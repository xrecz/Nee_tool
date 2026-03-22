# Nee Tool — Test- & Nutzungsanleitung

Schritt-für-Schritt-Anleitung für die Durchführung eines vollständigen Pentests
mit dem Nee Tool: von der Installation über den Scan bis zum fertigen Bericht.

---

## 1. Vorbereitung

### 1.1 Installation prüfen

```bash
# Nee Tool installieren (einmalig)
pip install -e .

# Prüfen ob CLI funktioniert
nee --help

# Verfügbare Scanner und externe Tools anzeigen
nee scanners
```

Die Ausgabe zeigt für jeden Scanner, ob das zugehörige externe Tool
(nmap, subfinder, httpx, etc.) installiert ist. Scanner ohne Tool
werden automatisch übersprungen oder nutzen einen Python-Fallback.

### 1.2 Empfohlene externe Tools

Auf Kali Linux sind die meisten vorinstalliert. Sonst:

```bash
sudo apt install nmap
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
sudo apt install whatweb testssl.sh feroxbuster
# Optional: gospider als Alternative zu katana
go install github.com/jaeles-project/gospider@latest
```

### 1.3 Scope definieren

Vor jedem Pentest klären:
- **Ziel-Domain(s):** z.B. `kunde.de`, `app.kunde.de`
- **IP-Bereiche:** Falls spezifische Netze im Scope
- **Ausschlüsse:** Systeme die NICHT getestet werden dürfen
- **Zeitfenster:** Wann darf gescannt werden?
- **Autorisierung:** Schriftliche Genehmigung liegt vor!

---

## 2. Recon-Pipeline ausführen

### 2.1 Vollständiger Scan

```bash
nee scan kunde.de --name "Kunde-ABC-Q1-2026"
```

Das startet die komplette Pipeline mit 10 Scannern:

| # | Scanner | Beschreibung |
|---|---------|-------------|
| 1 | **Subdomain-Enumeration** | Findet Subdomains (subfinder + crt.sh) |
| 2 | **Port-Scan** | Offene Ports und Services (nmap) |
| 3 | **Web-Discovery** | HTTP/HTTPS Probing (httpx) |
| 4 | **Security-Headers** | Prüft Header-Präsenz UND Werte (HSTS max-age, CSP unsafe-inline, CORS) |
| 5 | **SSL-Check** | Zertifikat- und TLS-Analyse auf allen erkannten HTTPS-Ports (443, 8443, ...) |
| 6 | **Tech-Detection** | Erkennt eingesetzte Technologien und Versionen (whatweb) |
| 7 | **Web-Crawler** | Entdeckt Endpoints, JS-Dateien, Forms, APIs (katana/gospider) |
| 8 | **Nuclei** | CVE- und Schwachstellen-Scan (Templates werden automatisch aktualisiert) |
| 9 | **Dir-Bruteforce** | Versteckte Pfade/Dateien (feroxbuster/ffuf) |
| 10 | **CVE-Enrichment** | Prüft erkannte Software gegen NVD/NIST-Datenbank auf bekannte CVEs |

### 2.2 Scan-Profile (NEU)

Vorkonfigurierte Presets für verschiedene Szenarien:

```bash
# Profile anzeigen
nee profiles

# Quick Scan (~15 Min) — Schnelle Übersicht
nee scan kunde.de --profile quick

# Standard Pentest (~1-2 Std) — Alle Scanner
nee scan kunde.de --profile standard

# Deep Scan (~4+ Std) — Maximale Abdeckung, 5000 Ports
nee scan kunde.de --profile deep

# Compliance Check (~30 Min) — Header, SSL, CVE-Fokus
nee scan kunde.de --profile compliance

# Recon Only (~20 Min) — Nur Aufklärung, kein aktives Testing
nee scan kunde.de --profile recon
```

| Profil | Scanner | Ports | Timeout | Einsatz |
|--------|---------|-------|---------|---------|
| `quick` | 5 | 100 | 120s | Ersteinschätzung |
| `standard` | 10 | 1000 | 600s | Normaler Pentest |
| `deep` | 10 | 5000 | 1200s | Tiefenanalyse |
| `compliance` | 6 | 100 | 300s | Konfigurations-Audit |
| `recon` | 4 | 1000 | 300s | Passive Aufklärung |

Profile können mit `--top-ports`, `--skip`, `--timeout` überschrieben werden.

### 2.3 Selektiver Scan (manuell)

```bash
# Nur bestimmte Module
nee scan kunde.de --only subdomain,portscan,web_discovery

# Module überspringen (z.B. Nuclei + CVE-Enrichment dauern lang)
nee scan kunde.de --skip nuclei,dir_bruteforce,cve_enrichment

# Weniger Ports = schnellerer Scan
nee scan kunde.de --top-ports 100

# Timeout pro Scanner anpassen (Standard: 600s)
nee scan kunde.de --timeout 300
```

### 2.3 Scan-Ergebnisse prüfen

```bash
# Zusammenfassung eines Scans anzeigen
nee info output/kunde_abc_q1_2026/kunde_abc_q1_2026_*.json
```

Die Ergebnisse liegen als JSON in `./output/<projektname>/`.

---

## 3. Web-Dashboard nutzen (Alternative zur CLI)

```bash
nee web
# → Öffnet http://127.0.0.1:8899
```

Im Dashboard:
1. **Neuer Scan** → Target und Scanner-Module auswählen → Starten
2. **Live-Status** wird automatisch aktualisiert (HTMX-Polling)
3. **Ergebnisse** durchsuchen: Hosts, Ports, Subdomains, Findings
4. **Findings manuell hinzufügen** (aus Templates oder frei)
5. **Bericht generieren** → PDF oder HTML herunterladen

---

## 4. Ergebnisse auswerten

### 4.1 Automatische Findings prüfen

Nach dem Scan die Findings sichten:
- **Critical/High:** Sofort verifizieren und dokumentieren
- **Medium:** Bewerten ob ausnutzbar
- **Low/Info:** Für den Bericht sammeln, Empfehlungen formulieren

**Hinweis zu CVE-Enrichment:** Der CVE-Enrichment-Scanner liefert
potenzielle CVEs basierend auf erkannter Software. Diese müssen
**manuell verifiziert** werden — prüfen ob die exakte Version betroffen ist.

**Hinweis zu Header-Checks:** Security-Header werden jetzt nicht nur auf
Existenz geprüft, sondern auch auf sichere Werte:
- HSTS: max-age ausreichend? includeSubDomains gesetzt?
- CSP: Enthält unsafe-inline/unsafe-eval? Wildcards?
- CORS: Wildcard-Origin mit Credentials?

### 4.2 Manuelle Findings ergänzen

Für manuell gefundene Schwachstellen (z.B. aus Burp Suite, manuellem Testing):

```bash
# Verfügbare Templates anzeigen
nee templates
```

Templates vorhanden für: SQL Injection, XSS (Stored/Reflected), IDOR,
Auth Bypass, RCE, Default Credentials, fehlende Headers, SSL-Probleme,
CORS, Directory Listing, Cookie Flags, und mehr.

Im Web-Dashboard unter **Finding hinzufügen**:
- Template auswählen oder komplett manuell eingeben
- Severity, Beschreibung, Evidence (PoC), Empfehlung eintragen

### 4.3 Compliance-Mapping anzeigen

Findings automatisch auf Compliance-Frameworks mappen:

```bash
nee compliance output/kunde_abc_q1_2026/kunde_abc_q1_2026_20260321.json
```

Zeigt betroffene Controls aus:
- **BSI IT-Grundschutz** (z.B. CON.1.A6, APP.3.1.A4, ORP.4.A2)
- **ISO 27001:2022 Annex A** (z.B. A.8.24, A.8.26, A.5.17)
- **DSGVO Art. 32** (Verschlüsselung, Vertraulichkeit, Integrität)

Auch im **Web-Dashboard** unter dem Menüpunkt **Compliance** verfügbar.

---

## 5. Bericht generieren

### 5.1 PDF-Bericht

```bash
nee report output/kunde_abc_q1_2026/kunde_abc_q1_2026_20260321.json \
    --client "Firma XYZ GmbH" \
    --author "Max Mustermann" \
    --date-range "01.03. - 15.03.2026"
```

Der Bericht enthält:
- Deckblatt mit Vertraulichkeits-Klassifizierung
- Management Summary mit Severity-Statistiken
- Scope & Methodik
- Host-/Dienst-Übersicht
- Detaillierte Finding-Cards (Beschreibung, PoC, Empfehlung, Referenzen)
- CVSS v3.1 Scoring
- Disclaimer

### 5.2 HTML-Vorschau

```bash
# Schneller: HTML im Browser prüfen bevor PDF erzeugt wird
nee report output/kunde_abc_q1_2026/kunde_abc_q1_2026_20260321.json --html-only
```

### 5.3 Demo-Bericht

```bash
# Vorschau mit Beispieldaten (zum Testen der Formatierung)
nee demo-report
nee demo-report --html-only
```

---

## 6. Re-Test Workflow (NEU)

Nach der Behebung von Schwachstellen durch den Kunden: Re-Test durchführen
und automatisch vergleichen.

### 6.1 Re-Test-Scan durchführen

```bash
# Gleicher Scope, neuer Scan
nee scan kunde.de --name "Kunde-ABC-Retest" --profile standard
```

### 6.2 Scans vergleichen

```bash
nee retest \
    output/kunde_abc_q1_2026/kunde_abc_q1_2026_20260321.json \
    output/kunde_abc_retest/kunde_abc_retest_20260415.json \
    --output output/retest_ergebnis.json
```

Die Ausgabe zeigt:
- **Behoben:** Findings die im Re-Test nicht mehr auftreten
- **Offen:** Findings die weiterhin vorhanden sind
- **Neu:** Zusätzlich entdeckte Schwachstellen
- **Fix-Rate:** Prozentsatz behobener Findings

### 6.3 Re-Test im Dashboard

Im Web-Dashboard unter **Re-Test**:
1. Original-Scan und Re-Test-Scan aus Dropdown wählen
2. **Vergleichen** klicken
3. Visuelle Übersicht mit Stat-Cards und Finding-Listen

---

## 7. Phishing-Kampagne (optional)

### 7.1 Voraussetzung

- Laufende [GoPhish](https://getgophish.com/)-Instanz
- API-Key aus GoPhish Admin-Panel
- CSV-Datei mit Ziel-Adressen

### 7.2 CSV-Format

```csv
email,first_name,last_name,position
max.mustermann@kunde.de,Max,Mustermann,IT-Leiter
anna.schmidt@kunde.de,Anna,Schmidt,Buchhaltung
```

### 7.3 Kampagne starten

```bash
# Verfügbare E-Mail-Templates
nee phish templates
# → it_password_reset, m365_shared_document, hr_application,
#   invoice_supplier, delivery_notification

# Kampagne aufsetzen
nee phish setup \
    --api-key "GOPHISH-API-KEY" \
    --name "Awareness-Q1-2026" \
    --template it_password_reset \
    --smtp-host "mail.example.de:587" \
    --smtp-from "it-support@kunde.de" \
    --smtp-user "user" \
    --smtp-pass "pass" \
    --targets mitarbeiter.csv \
    --url "https://phish.example.de"
```

### 7.4 Status & Bericht

```bash
# Live-Status prüfen
nee phish status 42 --api-key "GOPHISH-API-KEY"

# Kampagnen-Bericht als PDF
nee phish report 42 --api-key "GOPHISH-API-KEY" --client "Firma XYZ"

# Demo-Bericht (Vorschau)
nee phish demo-report
```

---

## 8. Typischer Pentest-Workflow

### Kurzübersicht: Ablauf eines Auftrags

```
┌─────────────────────────────────────────────────┐
│  1. VORBEREITUNG                                │
│     • Scope klären, Autorisierung einholen      │
│     • Nee Tool + externe Tools prüfen           │
├─────────────────────────────────────────────────┤
│  2. AUTOMATISIERTER SCAN                        │
│     • nee scan target.de --profile standard     │
│     • Ergebnisse im Dashboard sichten           │
├─────────────────────────────────────────────────┤
│  3. MANUELLE VERIFIKATION                       │
│     • Critical/High Findings verifizieren       │
│     • Manuelle Tests (Burp, sqlmap, etc.)       │
│     • Zusätzliche Findings dokumentieren        │
├─────────────────────────────────────────────────┤
│  4. PHISHING (falls beauftragt)                 │
│     • GoPhish-Kampagne aufsetzen                │
│     • Ergebnisse auswerten                      │
├─────────────────────────────────────────────────┤
│  5. COMPLIANCE-MAPPING                          │
│     • nee compliance project.json               │
│     • BSI/ISO 27001/DSGVO Controls zuordnen     │
├─────────────────────────────────────────────────┤
│  6. BERICHT                                     │
│     • nee report ... → PDF generieren           │
│     • Manuelle Findings + Empfehlungen ergänzen │
│     • QA: Bericht gegenlesen                    │
├─────────────────────────────────────────────────┤
│  7. ABGABE                                      │
│     • Bericht an Kunden übergeben               │
│     • Findings-Besprechung / Präsentation       │
├─────────────────────────────────────────────────┤
│  8. RE-TEST (nach Behebung durch Kunden)        │
│     • nee scan target.de --profile standard     │
│     • nee retest original.json retest.json      │
│     • Fix-Rate dokumentieren                    │
└─────────────────────────────────────────────────┘
```

---

## 9. Schnelltest (Funktionsprüfung)

Um zu prüfen ob alles funktioniert, ohne ein echtes Ziel zu scannen:

```bash
# 1. CLI und Imports prüfen
python -c "from nee_tool.core.orchestrator import SCANNER_REGISTRY; print(list(SCANNER_REGISTRY.keys()))"

# 2. Scanner-Verfügbarkeit
nee scanners

# 3. Demo-Bericht generieren (kein Netzwerk nötig)
nee demo-report --html-only

# 4. Phishing Demo-Bericht (kein GoPhish nötig)
nee phish demo-report --html-only

# 5. Web-Dashboard starten
nee web
# → http://127.0.0.1:8899 im Browser öffnen

# 6. Test-Scan gegen example.com (harmlos, begrenzte Ergebnisse)
nee scan example.com --name "Funktionstest" --skip nuclei --timeout 30
```

---

## 10. Troubleshooting

| Problem | Lösung |
|---------|--------|
| `nee: command not found` | `pip install -e .` im Projektverzeichnis ausführen |
| Scanner wird übersprungen | `nee scanners` → Externes Tool installieren |
| PDF-Generierung fehlerhaft | WeasyPrint-Abhängigkeiten prüfen: `apt install libpango-1.0-0 libharfbuzz0b libffi-dev` |
| GoPhish-Verbindung fehlgeschlagen | API-Key und URL prüfen, GoPhish-Server läuft? |
| Scan dauert zu lange | `--top-ports 100` oder `--skip nuclei,dir_bruteforce,cve_enrichment` |
| CVE-Enrichment liefert nichts | NVD API benötigt Internet; Rate-Limit: 5 Req/30s ohne API-Key |
| Crawler findet wenig | katana oder gospider installieren für JS-Crawling |
| Keine Ergebnisse | Scope/Firewall prüfen, ggf. VPN zum Kunden aktiv? |

---

## 11. Checkliste vor Kundenauftrag

- [ ] Schriftliche Autorisierung (Scope, Zeitraum, Ansprechpartner)
- [ ] Nee Tool aktuell und funktionsfähig (`nee scanners`)
- [ ] Externe Tools installiert (nmap, subfinder, httpx, nuclei, katana, etc.)
- [ ] GoPhish-Instanz bereit (falls Phishing im Scope)
- [ ] SMTP-Zugang für Phishing-Kampagne konfiguriert
- [ ] CSV mit Zieladressen vorbereitet
- [ ] VPN/Netzwerkzugang zum Kunden getestet
- [ ] Demo-Berichte funktionieren (`nee demo-report`)
- [ ] Berichtsvorlage mit Kundendaten angepasst
