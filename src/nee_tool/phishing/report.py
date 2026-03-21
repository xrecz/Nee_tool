"""Phishing campaign report generator.

Generates professional PDF reports from GoPhish campaign results,
including click rates, credential submission stats, and timeline analysis.
"""

from __future__ import annotations

from pathlib import Path

from jinja2 import Environment, BaseLoader

from nee_tool.phishing.client import CampaignResult

PHISHING_REPORT_TEMPLATE = """<!DOCTYPE html>
<html lang="de">
<head>
<meta charset="utf-8">
<title>Phishing-Kampagnen Bericht — {{ result.name }}</title>
<style>
  @page { size: A4; margin: 2.5cm 2cm; }
  @page :first { margin-top: 0; }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: "Segoe UI", Arial, sans-serif; font-size: 10.5pt; line-height: 1.5; color: #222; }

  .cover {
    page-break-after: always; height: 100vh; display: flex; flex-direction: column;
    justify-content: center; padding: 3cm 2cm; color: white; margin: -2.5cm -2cm;
    background: linear-gradient(135deg, #2c3e50 0%, #3498db 100%);
  }
  .cover h1 { font-size: 30pt; margin-bottom: 0.3em; }
  .cover .subtitle { font-size: 16pt; font-weight: 300; opacity: 0.9; margin-bottom: 2em; }
  .cover .meta { font-size: 11pt; line-height: 2; opacity: 0.8; }
  .cover .classification { margin-top: 3em; padding: 0.8em 1.2em; border: 2px solid rgba(255,255,255,0.3); display: inline-block; font-size: 12pt; letter-spacing: 2px; text-transform: uppercase; }

  h2 { font-size: 18pt; color: #2c3e50; border-bottom: 3px solid #2c3e50; padding-bottom: 0.2em; margin: 1.5em 0 0.8em 0; }
  h3 { font-size: 13pt; color: #34495e; margin: 1.2em 0 0.5em 0; }

  .stats-grid { display: flex; gap: 1em; margin: 1.5em 0; flex-wrap: wrap; }
  .stat-card { flex: 1; min-width: 100px; text-align: center; padding: 1em; border-radius: 8px; color: white; }
  .stat-card .number { font-size: 28pt; display: block; font-weight: 700; }
  .stat-card .label { font-size: 9pt; text-transform: uppercase; letter-spacing: 1px; }
  .bg-total { background: #34495e; }
  .bg-sent { background: #3498db; }
  .bg-opened { background: #f39c12; }
  .bg-clicked { background: #e67e22; }
  .bg-creds { background: #e74c3c; }
  .bg-error { background: #95a5a6; }

  .rate-bar { height: 30px; border-radius: 4px; overflow: hidden; margin: 0.5em 0; display: flex; }
  .rate-bar div { display: flex; align-items: center; justify-content: center; color: white; font-size: 9pt; font-weight: 600; }

  table { width: 100%; border-collapse: collapse; margin: 1em 0; font-size: 10pt; }
  th { background: #2c3e50; color: white; padding: 0.6em 0.8em; text-align: left; }
  td { padding: 0.5em 0.8em; border-bottom: 1px solid #e0e0e0; }
  tr:nth-child(even) { background: #f8f9fa; }

  .summary-box { background: #f8f9fa; border-left: 4px solid #2c3e50; padding: 1.2em 1.5em; margin: 1em 0; }
  .risk-high { color: #e74c3c; font-weight: 700; }
  .risk-med { color: #f39c12; font-weight: 700; }
  .risk-low { color: #27ae60; font-weight: 700; }

  .recommendation { background: #e8f5e9; border-left: 3px solid #4caf50; padding: 0.8em 1em; margin: 0.5em 0; }
</style>
</head>
<body>

<div class="cover">
  <h1>Social Engineering Assessment</h1>
  <div class="subtitle">{{ result.name }}</div>
  <div class="meta">
    <strong>Auftraggeber:</strong> {{ client }}<br>
    <strong>Kampagne gestartet:</strong> {{ result.launch_date[:10] if result.launch_date else "N/A" }}<br>
    <strong>Bericht erstellt:</strong> {{ report_date }}<br>
    <strong>Autor:</strong> {{ author }}<br>
  </div>
  <div class="classification">VERTRAULICH</div>
</div>

<h2>1. Management Summary</h2>

<div class="summary-box">
{% if cred_rate > 30 %}
<p class="risk-high">HOHES RISIKO: {{ "%.1f"|format(cred_rate) }}% der Mitarbeiter haben ihre Zugangsdaten auf einer Phishing-Seite eingegeben.</p>
{% elif click_rate > 30 %}
<p class="risk-med">MITTLERES RISIKO: {{ "%.1f"|format(click_rate) }}% der Mitarbeiter haben auf den Phishing-Link geklickt.</p>
{% else %}
<p class="risk-low">GERINGES RISIKO: Die Klickrate lag bei {{ "%.1f"|format(click_rate) }}%. Die Sensibilisierung zeigt Wirkung.</p>
{% endif %}
<p style="margin-top:0.5em;">Von {{ result.total_targets }} angegriffenen Personen haben {{ result.links_clicked }} auf den Link geklickt
und {{ result.credentials_submitted }} ihre Zugangsdaten eingegeben.</p>
</div>

<div class="stats-grid">
  <div class="stat-card bg-total"><span class="number">{{ result.total_targets }}</span><span class="label">Ziele</span></div>
  <div class="stat-card bg-sent"><span class="number">{{ result.emails_sent }}</span><span class="label">E-Mails</span></div>
  <div class="stat-card bg-opened"><span class="number">{{ result.emails_opened }}</span><span class="label">Geöffnet</span></div>
  <div class="stat-card bg-clicked"><span class="number">{{ result.links_clicked }}</span><span class="label">Geklickt</span></div>
  <div class="stat-card bg-creds"><span class="number">{{ result.credentials_submitted }}</span><span class="label">Credentials</span></div>
  <div class="stat-card bg-error"><span class="number">{{ result.errors }}</span><span class="label">Fehler</span></div>
</div>

<h2>2. Ergebnisse im Detail</h2>

<h3>2.1 Conversion Funnel</h3>
<table>
  <tr><th>Schritt</th><th>Anzahl</th><th>Rate</th><th>Bewertung</th></tr>
  <tr>
    <td>E-Mails zugestellt</td><td>{{ result.emails_sent }}</td>
    <td>{{ "%.1f"|format(sent_rate) }}%</td><td>-</td>
  </tr>
  <tr>
    <td>E-Mails geöffnet</td><td>{{ result.emails_opened }}</td>
    <td>{{ "%.1f"|format(open_rate) }}%</td>
    <td>{% if open_rate > 60 %}<span class="risk-high">Hoch</span>{% elif open_rate > 30 %}<span class="risk-med">Mittel</span>{% else %}<span class="risk-low">Niedrig</span>{% endif %}</td>
  </tr>
  <tr>
    <td>Links geklickt</td><td>{{ result.links_clicked }}</td>
    <td>{{ "%.1f"|format(click_rate) }}%</td>
    <td>{% if click_rate > 30 %}<span class="risk-high">Hoch</span>{% elif click_rate > 15 %}<span class="risk-med">Mittel</span>{% else %}<span class="risk-low">Niedrig</span>{% endif %}</td>
  </tr>
  <tr>
    <td>Credentials eingegeben</td><td>{{ result.credentials_submitted }}</td>
    <td>{{ "%.1f"|format(cred_rate) }}%</td>
    <td>{% if cred_rate > 15 %}<span class="risk-high">Hoch</span>{% elif cred_rate > 5 %}<span class="risk-med">Mittel</span>{% else %}<span class="risk-low">Niedrig</span>{% endif %}</td>
  </tr>
</table>

{% if result.total_targets > 0 %}
<h3>2.2 Visueller Funnel</h3>
<div class="rate-bar">
  <div class="bg-sent" style="flex:{{ result.emails_sent }}">Zugestellt</div>
  {% if result.emails_opened %}<div class="bg-opened" style="flex:{{ result.emails_opened }}">Geöffnet</div>{% endif %}
  {% if result.links_clicked %}<div class="bg-clicked" style="flex:{{ result.links_clicked }}">Geklickt</div>{% endif %}
  {% if result.credentials_submitted %}<div class="bg-creds" style="flex:{{ result.credentials_submitted }}">Credentials</div>{% endif %}
</div>
{% endif %}

<h2>3. Empfehlungen</h2>

<h3>3.1 Sofortmaßnahmen</h3>
<div class="recommendation">
{% if result.credentials_submitted > 0 %}
1. <strong>Passwort-Reset</strong> für alle {{ result.credentials_submitted }} Personen, die Credentials eingegeben haben<br>
2. Prüfung auf verdächtige Logins in den Accounts der betroffenen Personen<br>
{% endif %}
3. Awareness-Schulung für alle Mitarbeiter, die auf den Link geklickt haben<br>
4. E-Mail-Filter auf die verwendeten Phishing-Indikatoren prüfen
</div>

<h3>3.2 Langfristige Maßnahmen</h3>
<div class="recommendation">
1. Regelmäßige Phishing-Simulationen (quartalsweise empfohlen)<br>
2. Security-Awareness-Training als Pflichtschulung einführen<br>
3. Multi-Faktor-Authentifizierung für alle externen Dienste aktivieren<br>
4. Meldeprozess für verdächtige E-Mails etablieren (Phishing-Button in Outlook)<br>
5. E-Mail-Banner für externe E-Mails aktivieren ("Diese E-Mail kommt von extern")
</div>

<h2>4. Benchmarking</h2>
<table>
  <tr><th>Metrik</th><th>Ihr Ergebnis</th><th>Branchendurchschnitt*</th></tr>
  <tr><td>Klickrate</td><td>{{ "%.1f"|format(click_rate) }}%</td><td>15-25%</td></tr>
  <tr><td>Credential-Eingabe</td><td>{{ "%.1f"|format(cred_rate) }}%</td><td>5-15%</td></tr>
  <tr><td>Öffnungsrate</td><td>{{ "%.1f"|format(open_rate) }}%</td><td>40-60%</td></tr>
</table>
<p style="font-size:9pt;color:#999;">* Branchenwerte basieren auf aggregierten Daten aus Phishing-Simulationen im DACH-Raum.</p>

</body>
</html>"""


def generate_phishing_report(
    result: CampaignResult,
    output_path: str | Path,
    client: str = "",
    author: str = "Security Team",
    html_only: bool = False,
) -> Path:
    """Generate a phishing campaign report as PDF or HTML."""
    from datetime import datetime

    total = max(result.total_targets, 1)  # Avoid division by zero
    sent_rate = (result.emails_sent / total) * 100
    open_rate = (result.emails_opened / total) * 100
    click_rate = (result.links_clicked / total) * 100
    cred_rate = (result.credentials_submitted / total) * 100

    env = Environment(loader=BaseLoader(), autoescape=True)
    template = env.from_string(PHISHING_REPORT_TEMPLATE)

    html_content = template.render(
        result=result,
        client=client or "Kunde",
        author=author,
        report_date=datetime.now().strftime("%d.%m.%Y"),
        sent_rate=sent_rate,
        open_rate=open_rate,
        click_rate=click_rate,
        cred_rate=cred_rate,
    )

    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    if html_only:
        output_path = output_path.with_suffix(".html")
        output_path.write_text(html_content, encoding="utf-8")
    else:
        from weasyprint import HTML
        output_path = output_path.with_suffix(".pdf")
        HTML(string=html_content).write_pdf(str(output_path))

    return output_path
