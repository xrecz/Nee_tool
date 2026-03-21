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
sudo apt install whatweb testssl.sh feroxbuster
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

Das startet die komplette Pipeline in dieser Reihenfolge:
1. **Subdomain-Enumeration** — Findet Subdomains (subfinder + crt.sh)
2. **Port-Scan** — Offene Ports und Services (nmap)
3. **Web-Discovery** — HTTP/HTTPS Probing (httpx)
4. **Security-Headers** — Prüft fehlende Sicherheits-Header
5. **SSL-Check** — Zertifikat- und TLS-Analyse (testssl.sh)
6. **Tech-Detection** — Erkennt eingesetzte Technologien (whatweb)
7. **Nuclei** — CVE- und Schwachstellen-Scan
8. **Dir-Bruteforce** — Versteckte Pfade/Dateien (feroxbuster/ffuf)

### 2.2 Selektiver Scan

```bash
# Nur bestimmte Module
nee scan kunde.de --only subdomain,portscan,web_discovery

# Module überspringen (z.B. Nuclei dauert lang)
nee scan kunde.de --skip nuclei,dir_bruteforce

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

## 6. Phishing-Kampagne (optional)

### 6.1 Voraussetzung

- Laufende [GoPhish](https://getgophish.com/)-Instanz
- API-Key aus GoPhish Admin-Panel
- CSV-Datei mit Ziel-Adressen

### 6.2 CSV-Format

```csv
email,first_name,last_name,position
max.mustermann@kunde.de,Max,Mustermann,IT-Leiter
anna.schmidt@kunde.de,Anna,Schmidt,Buchhaltung
```

### 6.3 Kampagne starten

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

### 6.4 Status & Bericht

```bash
# Live-Status prüfen
nee phish status 42 --api-key "GOPHISH-API-KEY"

# Kampagnen-Bericht als PDF
nee phish report 42 --api-key "GOPHISH-API-KEY" --client "Firma XYZ"

# Demo-Bericht (Vorschau)
nee phish demo-report
```

---

## 7. Typischer Pentest-Workflow

### Kurzübersicht: Ablauf eines Auftrags

```
┌─────────────────────────────────────────────────┐
│  1. VORBEREITUNG                                │
│     • Scope klären, Autorisierung einholen      │
│     • Nee Tool + externe Tools prüfen           │
├─────────────────────────────────────────────────┤
│  2. AUTOMATISIERTER SCAN                        │
│     • nee scan target.de --name "Projekt"       │
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
│  5. BERICHT                                     │
│     • nee report ... → PDF generieren           │
│     • Manuelle Findings + Empfehlungen ergänzen │
│     • QA: Bericht gegenlesen                    │
├─────────────────────────────────────────────────┤
│  6. ABGABE                                      │
│     • Bericht an Kunden übergeben               │
│     • Findings-Besprechung / Präsentation       │
│     • Re-Test nach Behebung (optional)          │
└─────────────────────────────────────────────────┘
```

---

## 8. Schnelltest (Funktionsprüfung)

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

## 9. Troubleshooting

| Problem | Lösung |
|---------|--------|
| `nee: command not found` | `pip install -e .` im Projektverzeichnis ausführen |
| Scanner wird übersprungen | `nee scanners` → Externes Tool installieren |
| PDF-Generierung fehlerhaft | WeasyPrint-Abhängigkeiten prüfen: `apt install libpango-1.0-0 libharfbuzz0b libffi-dev` |
| GoPhish-Verbindung fehlgeschlagen | API-Key und URL prüfen, GoPhish-Server läuft? |
| Scan dauert zu lange | `--top-ports 100` oder `--skip nuclei,dir_bruteforce` |
| Keine Ergebnisse | Scope/Firewall prüfen, ggf. VPN zum Kunden aktiv? |

---

## 10. Checkliste vor Kundenauftrag

- [ ] Schriftliche Autorisierung (Scope, Zeitraum, Ansprechpartner)
- [ ] Nee Tool aktuell und funktionsfähig (`nee scanners`)
- [ ] Externe Tools installiert (nmap, subfinder, httpx, nuclei, etc.)
- [ ] GoPhish-Instanz bereit (falls Phishing im Scope)
- [ ] SMTP-Zugang für Phishing-Kampagne konfiguriert
- [ ] CSV mit Zieladressen vorbereitet
- [ ] VPN/Netzwerkzugang zum Kunden getestet
- [ ] Demo-Berichte funktionieren (`nee demo-report`)
- [ ] Berichtsvorlage mit Kundendaten angepasst
