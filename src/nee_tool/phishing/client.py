"""GoPhish API client.

Provides a Python interface to the GoPhish REST API for managing
phishing campaigns, sending profiles, landing pages, and email templates.

GoPhish API docs: https://docs.getgophish.com/api-documentation/
"""

from __future__ import annotations

import json
import urllib.request
import urllib.error
import ssl
from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class GoPhishConfig:
    """GoPhish server connection settings."""

    host: str = "https://localhost:3333"
    api_key: str = ""
    verify_ssl: bool = False  # GoPhish often uses self-signed certs


@dataclass
class SMTPProfile:
    """GoPhish sending profile (SMTP settings)."""

    name: str
    host: str  # e.g. "mail.example.de:587"
    from_address: str  # e.g. "it-support@example.de"
    username: str = ""
    password: str = ""
    ignore_cert_errors: bool = True
    id: int | None = None


@dataclass
class EmailTemplate:
    """GoPhish email template."""

    name: str
    subject: str
    html: str
    text: str = ""
    envelope_sender: str = ""
    attachments: list[dict] = field(default_factory=list)
    id: int | None = None


@dataclass
class LandingPage:
    """GoPhish landing page (phishing site)."""

    name: str
    html: str
    capture_credentials: bool = True
    capture_passwords: bool = False
    redirect_url: str = ""  # Where to redirect after submission
    id: int | None = None


@dataclass
class Target:
    """A single phishing target."""

    email: str
    first_name: str = ""
    last_name: str = ""
    position: str = ""


@dataclass
class TargetGroup:
    """A group of phishing targets."""

    name: str
    targets: list[Target] = field(default_factory=list)
    id: int | None = None


@dataclass
class Campaign:
    """GoPhish campaign configuration."""

    name: str
    template: EmailTemplate | None = None
    page: LandingPage | None = None
    smtp: SMTPProfile | None = None
    groups: list[TargetGroup] = field(default_factory=list)
    url: str = ""  # Phishing URL (GoPhish listener)
    launch_date: str = ""  # ISO format, empty = immediate
    send_by_date: str = ""  # Spread emails over time
    id: int | None = None


@dataclass
class CampaignResult:
    """Results from a GoPhish campaign."""

    id: int
    name: str
    status: str
    created_date: str
    launch_date: str
    total_targets: int = 0
    emails_sent: int = 0
    emails_opened: int = 0
    links_clicked: int = 0
    credentials_submitted: int = 0
    errors: int = 0
    timeline: list[dict] = field(default_factory=list)


class GoPhishClient:
    """REST API client for GoPhish."""

    def __init__(self, config: GoPhishConfig):
        self.config = config
        self.base_url = config.host.rstrip("/")
        self._ssl_ctx = ssl.create_default_context()
        if not config.verify_ssl:
            self._ssl_ctx.check_hostname = False
            self._ssl_ctx.verify_mode = ssl.CERT_NONE

    def _request(self, method: str, endpoint: str, data: dict | None = None) -> dict | list:
        """Make an authenticated API request to GoPhish."""
        url = f"{self.base_url}/api/{endpoint}?api_key={self.config.api_key}"
        headers = {"Content-Type": "application/json"}

        body = json.dumps(data).encode() if data else None
        req = urllib.request.Request(url, data=body, headers=headers, method=method)
        handler = urllib.request.HTTPSHandler(context=self._ssl_ctx)
        opener = urllib.request.build_opener(handler)

        try:
            with opener.open(req, timeout=30) as resp:
                return json.loads(resp.read().decode())
        except urllib.error.HTTPError as e:
            error_body = e.read().decode() if e.fp else ""
            raise GoPhishError(f"HTTP {e.code}: {error_body}") from e
        except urllib.error.URLError as e:
            raise GoPhishError(f"Connection failed: {e.reason}") from e

    def _get(self, endpoint: str) -> dict | list:
        return self._request("GET", endpoint)

    def _post(self, endpoint: str, data: dict) -> dict:
        return self._request("POST", endpoint, data)

    def _put(self, endpoint: str, data: dict) -> dict:
        return self._request("PUT", endpoint, data)

    def _delete(self, endpoint: str) -> dict:
        return self._request("DELETE", endpoint)

    # ── SMTP Profiles ─────────────────────────────────────

    def create_smtp(self, profile: SMTPProfile) -> SMTPProfile:
        """Create a sending profile."""
        data = {
            "name": profile.name,
            "host": profile.host,
            "from_address": profile.from_address,
            "username": profile.username,
            "password": profile.password,
            "ignore_cert_errors": profile.ignore_cert_errors,
        }
        result = self._post("smtp/", data)
        profile.id = result.get("id")
        return profile

    def list_smtp(self) -> list[dict]:
        """List all sending profiles."""
        return self._get("smtp/")

    # ── Email Templates ───────────────────────────────────

    def create_template(self, template: EmailTemplate) -> EmailTemplate:
        """Create an email template."""
        data = {
            "name": template.name,
            "subject": template.subject,
            "html": template.html,
            "text": template.text,
            "envelope_sender": template.envelope_sender,
            "attachments": template.attachments,
        }
        result = self._post("templates/", data)
        template.id = result.get("id")
        return template

    def list_templates(self) -> list[dict]:
        """List all email templates."""
        return self._get("templates/")

    # ── Landing Pages ─────────────────────────────────────

    def create_page(self, page: LandingPage) -> LandingPage:
        """Create a landing page."""
        data = {
            "name": page.name,
            "html": page.html,
            "capture_credentials": page.capture_credentials,
            "capture_passwords": page.capture_passwords,
            "redirect_url": page.redirect_url,
        }
        result = self._post("pages/", data)
        page.id = result.get("id")
        return page

    def list_pages(self) -> list[dict]:
        """List all landing pages."""
        return self._get("pages/")

    # ── Target Groups ─────────────────────────────────────

    def create_group(self, group: TargetGroup) -> TargetGroup:
        """Create a target group."""
        data = {
            "name": group.name,
            "targets": [
                {
                    "email": t.email,
                    "first_name": t.first_name,
                    "last_name": t.last_name,
                    "position": t.position,
                }
                for t in group.targets
            ],
        }
        result = self._post("groups/", data)
        group.id = result.get("id")
        return group

    def list_groups(self) -> list[dict]:
        """List all target groups."""
        return self._get("groups/")

    def import_targets_csv(self, group_name: str, csv_path: str) -> TargetGroup:
        """Import targets from a CSV file (email,first_name,last_name,position)."""
        import csv
        from pathlib import Path

        targets = []
        with Path(csv_path).open(newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                targets.append(Target(
                    email=row.get("email", row.get("Email", "")),
                    first_name=row.get("first_name", row.get("First Name", "")),
                    last_name=row.get("last_name", row.get("Last Name", "")),
                    position=row.get("position", row.get("Position", "")),
                ))

        group = TargetGroup(name=group_name, targets=targets)
        return self.create_group(group)

    # ── Campaigns ─────────────────────────────────────────

    def create_campaign(self, campaign: Campaign) -> dict:
        """Create and launch a phishing campaign."""
        data: dict = {"name": campaign.name, "url": campaign.url}

        if campaign.template and campaign.template.id:
            data["template"] = {"id": campaign.template.id}
        if campaign.page and campaign.page.id:
            data["page"] = {"id": campaign.page.id}
        if campaign.smtp and campaign.smtp.id:
            data["smtp"] = {"id": campaign.smtp.id}
        if campaign.groups:
            data["groups"] = [{"id": g.id} for g in campaign.groups if g.id]
        if campaign.launch_date:
            data["launch_date"] = campaign.launch_date
        if campaign.send_by_date:
            data["send_by_date"] = campaign.send_by_date

        return self._post("campaigns/", data)

    def list_campaigns(self) -> list[dict]:
        """List all campaigns."""
        return self._get("campaigns/")

    def get_campaign(self, campaign_id: int) -> dict:
        """Get campaign details and results."""
        return self._get(f"campaigns/{campaign_id}")

    def get_campaign_results(self, campaign_id: int) -> CampaignResult:
        """Get campaign results as a structured object."""
        data = self.get_campaign(campaign_id)
        stats = data.get("stats", {})
        return CampaignResult(
            id=data.get("id", campaign_id),
            name=data.get("name", ""),
            status=data.get("status", ""),
            created_date=data.get("created_date", ""),
            launch_date=data.get("launch_date", ""),
            total_targets=stats.get("total", 0),
            emails_sent=stats.get("sent", 0),
            emails_opened=stats.get("opened", 0),
            links_clicked=stats.get("clicked", 0),
            credentials_submitted=stats.get("submitted_data", 0),
            errors=stats.get("error", 0),
            timeline=data.get("timeline", []),
        )

    def complete_campaign(self, campaign_id: int) -> dict:
        """Mark a campaign as complete."""
        return self._get(f"campaigns/{campaign_id}/complete")

    def delete_campaign(self, campaign_id: int) -> dict:
        """Delete a campaign."""
        return self._delete(f"campaigns/{campaign_id}")


class GoPhishError(Exception):
    """GoPhish API error."""
    pass
