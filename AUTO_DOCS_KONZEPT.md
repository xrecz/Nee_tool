# Automatisierte IT-Dokumentation - Deep Dive

> **Umgebung:** 30+ Server (Windows/Linux), Active Directory, Managed Switches/VLANs,
> Firewall-Appliance, VPN, bestehende manuelle Doku vorhanden

---

## Ehrliche Einschätzung: Was kann AUTOMATISCH erfasst werden?

### Vollautomatisch erfassbar (90-100% Abdeckung)

| Was | Wie | Beispiel-Output |
|-----|-----|-----------------|
| **Server-Inventar** | WMI (Win) / SSH+dmidecode (Linux) | "SRV-DC01: Dell R740, 64GB RAM, 2x Xeon, 4x 1TB SSD" |
| **Betriebssysteme & Patches** | WMI / apt/yum history | "Windows Server 2022, Build 20348, letztes Update: 15.03.2026" |
| **Installierte Dienste/Rollen** | PowerShell Get-WindowsFeature / systemctl | "DC, DNS, DHCP, File Server" |
| **Netzwerk-Interfaces & IPs** | WMI / ip addr / SNMP | "eth0: 10.10.1.5/24, VLAN 10, Gateway 10.10.1.1" |
| **AD-Struktur** | LDAP-Queries | OUs, Gruppen, GPOs, Benutzer, Gruppenmitgliedschaften |
| **DNS-Zonen & Records** | PowerShell DNS-Cmdlets | Alle Zonen, A/CNAME/MX/PTR Records |
| **DHCP-Scopes** | PowerShell DHCP-Cmdlets | Scopes, Reservierungen, Lease-Dauer |
| **Dateifreigaben & Berechtigungen** | PowerShell Get-SmbShare + Get-Acl | "\\SRV-FS01\Abteilung$ → Gruppe-Buchhaltung: Vollzugriff" |
| **Geplante Tasks / Cronjobs** | schtasks / crontab -l | Alle geplanten Aufgaben mit Zeitplan |
| **Zertifikate** | PowerShell Cert-Store / openssl | "*.firma.de läuft ab am 01.06.2026" |
| **Firewall-Regeln (Host)** | PowerShell / iptables-save | Alle aktiven Regeln |
| **Installierte Software** | WMI Win32_Product / dpkg/rpm | Softwareliste mit Versionen |
| **Laufende Dienste** | Get-Service / systemctl | Status aller Services |

### Teilautomatisch erfassbar (50-80% Abdeckung)

| Was | Wie | Was fehlt |
|-----|-----|-----------|
| **Netzwerk-Topologie** | SNMP-Walk auf Switches, ARP-Tabellen, CDP/LLDP | Physische Verkabelung, Patchfeld-Zuordnung |
| **VLAN-Konfiguration** | SNMP auf Managed Switches | Zweck/Beschreibung der VLANs muss manuell ergänzt werden |
| **Firewall-Regeln (Appliance)** | API (pfSense/OPNsense haben REST-APIs), SSH-Scraping | Kontext: WARUM existiert eine Regel? |
| **VPN-Konfiguration** | API/Config-Export der Firewall | Geschäftlicher Kontext (welcher Standort/Partner) |
| **Backup-Status** | Backup-Software API/Logs parsen | Backup-Konzept, RTO/RPO Anforderungen |
| **Drucker & Peripherie** | SNMP, WMI Print-Server | Standort, Zuordnung zu Abteilungen |
| **Virtualisierung** | VMware vSphere API / Proxmox API / Hyper-V WMI | Ressourcenplanung, Migrationspläne |

### NICHT automatisch erfassbar (manuell nötig)

| Was | Warum nicht? |
|-----|-------------|
| **Geschäftskontext** | "Warum gibt es diesen Server?" — Maschinen kennen ihren Zweck nicht |
| **Architektur-Entscheidungen** | "Warum haben wir uns für X statt Y entschieden?" |
| **Abhängigkeiten zwischen Systemen** | "App X braucht DB Y und Dienst Z" — teilweise erkennbar, aber nicht zuverlässig |
| **Notfallpläne / Runbooks** | "Was tun wenn Server X ausfällt?" — reines Erfahrungswissen |
| **Verantwortlichkeiten** | "Wer ist Ansprechpartner für System X?" |
| **Verträge & SLAs** | Lizenzen, Wartungsverträge, Support-Kontakte |
| **Physische Infrastruktur** | Rackbelegung, Verkabelung, USV-Kapazität, Klimatisierung |
| **Passwörter & Zugangsdaten** | Gehören in einen Passwort-Manager, nicht in Doku-Tool |

---

## Architektur-Konzept: Modularer Aufbau

```
┌─────────────────────────────────────────────────────┐
│                    Web-Frontend                      │
│  Dashboard │ Diff-Ansicht │ Suche │ Manuell-Editor  │
└──────────────────────┬──────────────────────────────┘
                       │
┌──────────────────────┴──────────────────────────────┐
│                   API-Backend                        │
│            (Python FastAPI + PostgreSQL)             │
└──────┬───────┬───────┬───────┬──────┬───────────────┘
       │       │       │       │      │
┌──────┴──┐ ┌──┴───┐ ┌─┴──┐ ┌─┴──┐ ┌─┴────┐
│ Windows │ │Linux │ │ AD │ │Net │ │ FW   │  ← Collector-Module
│Collector│ │Coll. │ │Coll│ │Coll│ │Coll. │     (Plugins)
└────┬────┘ └──┬───┘ └─┬──┘ └─┬──┘ └─┬────┘
     │         │       │      │      │
   WMI/      SSH    LDAP   SNMP   REST-API
  WinRM                           /SSH
```

### Kernprinzip: Collector-Module als Plugins

Jedes Modul ist eigenständig und kann einzeln entwickelt/aktiviert werden.
So kannst du **schrittweise** starten und nach und nach erweitern.

---

## Phasenplan: Vom MVP zum Vollausbau

### Phase 1 — MVP (1-2 Wochen) ★★★☆☆
**Ziel:** Server-Grunddaten automatisch erfassen + Web-Ansicht

Module:
- [ ] **Windows-Collector:** Hostname, OS, Hardware, IPs, Dienste, Software
- [ ] **Linux-Collector:** Gleiche Daten via SSH
- [ ] **Web-Dashboard:** Übersicht aller Server mit Details
- [ ] **Diff-Engine:** Was hat sich seit letztem Scan geändert?
- [ ] **Git-Versionierung:** Jeder Scan-Lauf = ein Commit → volle Historie

**Ergebnis:** Du öffnest die Seite und siehst alle 30+ Server mit aktuellem Stand.
Änderungen werden automatisch erkannt und hervorgehoben.

---

### Phase 2 — Active Directory & Netzwerk (+1-2 Wochen) ★★★☆☆
**Ziel:** AD und Netzwerk-Infrastruktur dokumentieren

Module:
- [ ] **AD-Collector:** OUs, User, Gruppen, GPOs, Gruppenmitgliedschaften
- [ ] **DNS/DHCP-Collector:** Zonen, Records, Scopes
- [ ] **Netzwerk-Collector:** Switch-Ports, VLANs, MAC-Tabellen via SNMP
- [ ] **Berechtigungs-Report:** Wer hat Zugriff auf welche Freigaben?

**Ergebnis:** Kompletter AD-Überblick. "Zeig mir alle Mitglieder der Domain Admins"
mit einem Klick. Neue GPOs oder Gruppenänderungen werden automatisch erkannt.

---

### Phase 3 — Firewall, VPN & Zertifikate (+1 Woche) ★★★☆☆
**Ziel:** Sicherheitsrelevante Konfiguration erfassen

Module:
- [ ] **Firewall-Collector:** Regeln, NAT, Aliases (via API)
- [ ] **VPN-Collector:** Tunnel-Status, Konfiguration
- [ ] **Zertifikats-Collector:** Alle Zertifikate mit Ablaufdaten
- [ ] **Alerting:** Warnung wenn Zertifikate < 30 Tage gültig

**Ergebnis:** Nie wieder ein abgelaufenes Zertifikat übersehen.
Firewall-Regeln sind dokumentiert und Änderungen werden getrackt.

---

### Phase 4 — Manueller Kontext & Wiki (+1-2 Wochen) ★★★★☆
**Ziel:** Die Lücke schließen — Geschäftskontext zu automatischen Daten

Features:
- [ ] **Annotations:** Manuell Notizen an jedes Objekt hängen
        ("Dieser Server ist der ERP-Server, Ansprechpartner: Hr. Müller")
- [ ] **Runbook-Templates:** Vorgefertigte Vorlagen für Notfallpläne
- [ ] **Abhängigkeits-Graph:** Manuell definieren: "App X → DB Y → Server Z"
- [ ] **Vertrags-Tracker:** Wartungsverträge, Support-Kontakte, Ablaufdaten
- [ ] **Tagging-System:** Server nach Funktion/Abteilung/Kritikalität taggen

**Ergebnis:** Automatische Daten + menschliches Wissen an einem Ort.

---

### Phase 5 — Reporting & Compliance (+1 Woche) ★★★☆☆
**Ziel:** Doku für Audits und Management nutzbar machen

Features:
- [ ] **PDF-Export:** Gesamtdokumentation auf Knopfdruck
- [ ] **Änderungsprotokoll:** Wer hat was wann geändert (für Audits)
- [ ] **Compliance-Checks:** "Haben alle Server aktuelle Updates?"
- [ ] **Dashboard für Geschäftsführung:** Vereinfachte Ansicht

---

## Realistische Gesamt-Einschätzung

| Aspekt | Einschätzung |
|--------|-------------|
| **Automatisierungsgrad** | ~60-70% der Infrastruktur-Doku automatisierbar |
| **Die anderen 30-40%** | Geschäftskontext, Entscheidungen, Runbooks — EINMALIG manuell, danach nur Pflege |
| **Killer-Feature** | Die **Diff-Ansicht**: "Was hat sich seit gestern geändert?" |
| **MVP bis produktiv** | 1-2 Wochen für Phase 1 |
| **Vollausbau** | 6-8 Wochen bei allen 5 Phasen |
| **Wartungsaufwand danach** | Gering — Scans laufen per Cronjob, nur manuelle Notizen pflegen |

### Der entscheidende Vorteil gegenüber manueller Doku:

> **Manuelle Doku ist am Tag nach dem Schreiben schon veraltet.**
> Automatische Doku ist immer aktuell — und zeigt dir genau, was sich geändert hat.

---

## Technologie-Stack (Vorschlag)

| Komponente | Technologie | Warum |
|-----------|-------------|-------|
| Backend | Python (FastAPI) | Kannst du bereits, async, schnell |
| Datenbank | PostgreSQL | Robust, JSON-Support für flexible Daten |
| Collectors | Python + Paramiko (SSH) + pywinrm + ldap3 + pysnmp | Alle Protokolle abgedeckt |
| Versionierung | Git (automatische Commits) | Diff/Historie geschenkt |
| Frontend | HTML/JS (HTMX oder Vue.js) | Leichtgewichtig, schnell gebaut |
| Scheduling | APScheduler oder systemd-Timer | Regelmäßige Scans |
| Auth | LDAP gegen euer AD | Single Sign-On mit bestehenden Accounts |
