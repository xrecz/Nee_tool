# IT-Tool Ideen - Brainstorming

> **Kontext:** Kleines Team (1-5), On-Premise + Clients/Endpoints,
> gutes Ticketsystem vorhanden, Monitoring ausbaufähig,
> Zeitfresser: Monitoring/Troubleshooting & Meetings/Koordination

---

## Kategorie 1: Quick Wins (1-3 Tage Aufwand)

### 1.1 Endpoint Health Dashboard
**Problem:** Überblick über Client-Status fehlt oder ist umständlich.
**Lösung:** Web-Dashboard das per PowerShell/WMI Infos von Clients sammelt:
- Online/Offline-Status aller Rechner
- Festplattenauslastung, RAM, CPU
- Letzte Windows-Updates / Pending Reboots
- Auslaufende Garantien / Alter der Geräte

**Tech:** Python (FastAPI) + HTML/JS Frontend, PowerShell-Agent auf Clients
**Aufwand:** ★★☆☆☆

---

### 1.2 Server-Log-Aggregator mit Alerting
**Problem:** Fehler in Logs werden zu spät bemerkt, manuelles Durchsuchen kostet Zeit.
**Lösung:** Leichtgewichtiger Log-Collector der:
- Windows Event Logs & Linux Syslog einsammelt
- Nach definierten Mustern filtert (Fehler, Warnungen)
- Benachrichtigung per E-Mail/Teams/Webhook schickt
- Einfaches Web-UI zum Durchsuchen

**Tech:** Python + SQLite/PostgreSQL, einfaches Web-Frontend
**Aufwand:** ★★☆☆☆

---

### 1.3 Meeting-Protokoll-Generator
**Problem:** Meetings kosten Zeit, Protokolle schreiben noch mehr.
**Lösung:** Web-Tool in das man während des Meetings Stichpunkte eingibt:
- Strukturierte Eingabemaske (Teilnehmer, Themen, Entscheidungen, TODOs)
- Automatische Formatierung als PDF/Mail
- TODO-Tracking: Wer muss was bis wann erledigen?
- Erinnerungen per E-Mail für offene TODOs

**Tech:** Python (Flask/FastAPI) + Jinja2 Templates
**Aufwand:** ★★☆☆☆

---

### 1.4 Passwort-Reset Self-Service
**Problem:** Häufige Anfragen für Passwort-Resets binden unnötig Zeit.
**Lösung:** Web-Portal für Mitarbeiter zum selbstständigen Passwort-Reset:
- Authentifizierung über alternative Methode (Handy-Verifizierung, Sicherheitsfragen)
- Active Directory Integration per LDAP
- Audit-Log aller Resets

**Tech:** Python + LDAP3-Bibliothek
**Aufwand:** ★★☆☆☆

---

## Kategorie 2: Mittlerer Aufwand (1-2 Wochen)

### 2.1 IT-Inventar & CMDB Light
**Problem:** Kein zentraler Überblick über Hardware, Software, Lizenzen.
**Lösung:** Web-App für IT-Asset-Management:
- Automatischer Hardware-Scan (WMI/SSH)
- Installierte Software erfassen
- Lizenz-Tracking (Ablaufdaten, Kosten)
- Zuordnung: Welcher Mitarbeiter nutzt welches Gerät?
- Export für Budgetplanung (Abteilungsleiter-Hut!)

**Tech:** Python (Django/FastAPI) + PostgreSQL + JS-Frontend
**Aufwand:** ★★★☆☆

---

### 2.2 Projekt-Status-Board
**Problem:** Als Projektmanager + Abteilungsleiter braucht man schnellen Überblick.
**Lösung:** Internes Dashboard das Projekt-Status visualisiert:
- Kanban-Board für laufende Projekte
- Ampelsystem (grün/gelb/rot) pro Projekt
- Meilensteine mit Deadlines
- Ressourcenauslastung des Teams
- Automatische Status-Mail an Stakeholder (wöchentlich)

**Tech:** Node.js/Python Backend + React/Vue Frontend
**Aufwand:** ★★★☆☆

---

### 2.3 Automatisiertes Onboarding/Offboarding
**Problem:** Neuer Mitarbeiter = viele manuelle Schritte (AD-Account, Mailbox, Berechtigungen...)
**Lösung:** Workflow-Tool das per Checkliste alles automatisiert:
- AD-User anlegen mit Gruppenmitgliedschaften
- Mailbox erstellen
- Berechtigungen auf Netzlaufwerke setzen
- Hardware zuweisen (aus Inventar)
- Willkommens-Mail mit allen Zugangsdaten
- Beim Offboarding: Alles rückgängig machen

**Tech:** Python + PowerShell-Scripts + Web-UI
**Aufwand:** ★★★☆☆

---

### 2.4 Monitoring-Dashboard (Ergänzung zum bestehenden System)
**Problem:** Bestehendes Monitoring (schlecht konfiguriert) liefert nicht die richtigen Infos.
**Lösung:** Eigenes Overlay-Dashboard das die wichtigsten Checks bündelt:
- Ping/Port-Checks für kritische Dienste
- Festplatten, Zertifikate, Backups überwachen
- Übersichtliche Status-Seite (auch für Nicht-ITler)
- Eskalationslogik: Erst Mail, dann SMS/Anruf
- Kann parallel zum bestehenden Monitoring laufen

**Tech:** Python + InfluxDB/Prometheus + Grafana oder eigenes Frontend
**Aufwand:** ★★★☆☆

---

## Kategorie 3: Größere Projekte (3-6 Wochen)

### 3.1 Internes IT-Portal / Self-Service Hub
**Problem:** Mitarbeiter kommen mit allem zur IT statt selbst zu lösen.
**Lösung:** Zentrales Web-Portal für die gesamte Firma:
- FAQ / Wissensdatenbank für häufige Probleme
- Self-Service: Passwort-Reset, Software-Anforderung, Drucker einrichten
- Direkter Link zum Ticketsystem
- IT-Status-Seite: "Welche Systeme laufen gerade nicht?"
- Formulare für Standard-Anfragen (neuer Mitarbeiter, Hardware-Bestellung)

**Tech:** Full-Stack (Python/Node.js + React/Vue + DB)
**Aufwand:** ★★★★☆

---

### 3.2 Automatisierte Dokumentation
**Problem:** Dokumentation ist immer veraltet oder existiert nicht.
**Lösung:** System das sich teilweise selbst dokumentiert:
- Netzwerk-Topologie automatisch aus Scans generieren
- Server-Konfigurationen regelmäßig erfassen und versionieren
- Änderungen an Infrastruktur automatisch protokollieren
- Wiki mit Templates für Standard-Dokumentation
- Diff-Ansicht: Was hat sich seit letztem Scan geändert?

**Tech:** Python + Git (für Versionierung) + Web-UI
**Aufwand:** ★★★★☆

---

## Empfehlung: Wo anfangen?

Basierend auf deiner Situation (kleines Team, Monitoring als Zeitfresser):

| Priorität | Tool | Begründung |
|-----------|------|------------|
| 1 | **Endpoint Health Dashboard** | Schneller Überblick, erspart tägliches Prüfen |
| 2 | **Meeting-Protokoll-Generator** | Spart sofort Zeit bei jedem Meeting |
| 3 | **Monitoring-Dashboard** | Ergänzt das schlecht konfigurierte System |
| 4 | **IT-Inventar** | Basis für viele weitere Optimierungen |

---

## Nächste Schritte

- [ ] Priorisierung: Welche Tools haben den größten Impact?
- [ ] Erstes Tool auswählen und als MVP umsetzen
- [ ] Feedback sammeln und iterieren
