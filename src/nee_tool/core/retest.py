"""Re-Test workflow.

Compares two project scans (old vs new) to identify:
- Fixed findings (present in old, absent in new)
- Persistent findings (still present)
- New findings (only in new scan)

Generates a re-test summary for customer reports.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum

from pydantic import BaseModel, Field

from nee_tool.core.models import Finding, Project, Severity


class FindingStatus(str, Enum):
    FIXED = "fixed"
    PERSISTENT = "persistent"
    NEW = "new"


class RetestFinding(BaseModel):
    """A finding with re-test status."""

    finding: Finding
    status: FindingStatus
    original_severity: Severity | None = None
    notes: str = ""


class RetestResult(BaseModel):
    """Result of comparing two scans."""

    original_project: str
    retest_project: str
    original_date: str = ""
    retest_date: str = ""
    fixed: list[RetestFinding] = Field(default_factory=list)
    persistent: list[RetestFinding] = Field(default_factory=list)
    new: list[RetestFinding] = Field(default_factory=list)

    @property
    def total_original(self) -> int:
        return len(self.fixed) + len(self.persistent)

    @property
    def fix_rate(self) -> float:
        total = self.total_original
        if total == 0:
            return 100.0
        return round(len(self.fixed) / total * 100, 1)

    def summary_counts(self) -> dict[str, int]:
        return {
            "fixed": len(self.fixed),
            "persistent": len(self.persistent),
            "new": len(self.new),
            "total_original": self.total_original,
        }


def _finding_key(finding: Finding) -> str:
    """Create a comparison key for a finding.

    Uses title (normalized) as primary key. Strips host-specific
    suffixes like '(host.example.de)' for better matching.
    """
    import re
    title = finding.title.strip().lower()
    # Remove trailing host identifiers like (host.example.de) or (host:port)
    title = re.sub(r'\s*\([^)]*\)\s*$', '', title)
    return title


def _finding_key_strict(finding: Finding) -> str:
    """Strict key including severity for exact matching."""
    return f"{_finding_key(finding)}|{finding.severity.value}"


def compare_projects(
    original: Project,
    retest: Project,
) -> RetestResult:
    """Compare two project scans to determine fix status.

    Args:
        original: The initial pentest scan results
        retest: The re-test scan results

    Returns:
        RetestResult with categorized findings
    """
    original_findings = original.all_findings()
    retest_findings = retest.all_findings()

    # Build lookup maps
    original_keys = {}
    for f in original_findings:
        key = _finding_key(f)
        if key not in original_keys:
            original_keys[key] = f

    retest_keys = {}
    for f in retest_findings:
        key = _finding_key(f)
        if key not in retest_keys:
            retest_keys[key] = f

    result = RetestResult(
        original_project=original.name,
        retest_project=retest.name,
        original_date=original.created_at.strftime("%d.%m.%Y"),
        retest_date=retest.created_at.strftime("%d.%m.%Y"),
    )

    # Fixed: in original but not in retest
    for key, finding in original_keys.items():
        if key not in retest_keys:
            result.fixed.append(RetestFinding(
                finding=finding,
                status=FindingStatus.FIXED,
                original_severity=finding.severity,
            ))

    # Persistent: in both
    for key, finding in original_keys.items():
        if key in retest_keys:
            retest_f = retest_keys[key]
            result.persistent.append(RetestFinding(
                finding=retest_f,
                status=FindingStatus.PERSISTENT,
                original_severity=finding.severity,
            ))

    # New: in retest but not in original
    for key, finding in retest_keys.items():
        if key not in original_keys:
            result.new.append(RetestFinding(
                finding=finding,
                status=FindingStatus.NEW,
            ))

    # Sort each list by severity
    severity_order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
    for lst in (result.fixed, result.persistent, result.new):
        lst.sort(key=lambda rf: severity_order.index(rf.finding.severity))

    return result
