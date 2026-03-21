"""CVSS v3.1 calculator.

Calculates CVSS Base Score from a vector string.
Reference: https://www.first.org/cvss/v3.1/specification-document
"""

from __future__ import annotations

from dataclasses import dataclass

from nee_tool.core.models import Severity

# Metric value weights per CVSS v3.1 spec
WEIGHTS: dict[str, dict[str, float]] = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20},
    "AC": {"L": 0.77, "H": 0.44},
    "PR": {
        "N": 0.85, "L": 0.62, "H": 0.27,
        # Changed scope values
        "L_C": 0.68, "H_C": 0.50,
    },
    "UI": {"N": 0.85, "R": 0.62},
    "S": {"U": False, "C": True},
    "C": {"H": 0.56, "L": 0.22, "N": 0.0},
    "I": {"H": 0.56, "L": 0.22, "N": 0.0},
    "A": {"H": 0.56, "L": 0.22, "N": 0.0},
}

METRIC_NAMES = {
    "AV": "Attack Vector",
    "AC": "Attack Complexity",
    "PR": "Privileges Required",
    "UI": "User Interaction",
    "S": "Scope",
    "C": "Confidentiality",
    "I": "Integrity",
    "A": "Availability",
}

METRIC_VALUE_NAMES = {
    "AV": {"N": "Network", "A": "Adjacent", "L": "Local", "P": "Physical"},
    "AC": {"L": "Low", "H": "High"},
    "PR": {"N": "None", "L": "Low", "H": "High"},
    "UI": {"N": "None", "R": "Required"},
    "S": {"U": "Unchanged", "C": "Changed"},
    "C": {"H": "High", "L": "Low", "N": "None"},
    "I": {"H": "High", "L": "Low", "N": "None"},
    "A": {"H": "High", "L": "Low", "N": "None"},
}


@dataclass
class CVSSResult:
    score: float
    severity: Severity
    vector: str

    @property
    def severity_text(self) -> str:
        return self.severity.value.upper()


def _roundup(value: float) -> float:
    """CVSS spec roundup function."""
    import math
    return math.ceil(value * 10) / 10


def parse_vector(vector: str) -> dict[str, str]:
    """Parse a CVSS v3.1 vector string into metric:value pairs."""
    vector = vector.strip()
    if vector.startswith("CVSS:3.1/"):
        vector = vector[9:]
    elif vector.startswith("CVSS:3.0/"):
        vector = vector[9:]

    metrics = {}
    for part in vector.split("/"):
        if ":" in part:
            key, val = part.split(":", 1)
            metrics[key.upper()] = val.upper()
    return metrics


def calculate(vector: str) -> CVSSResult:
    """Calculate CVSS v3.1 base score from a vector string.

    Example vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
    """
    metrics = parse_vector(vector)

    required = ["AV", "AC", "PR", "UI", "S", "C", "I", "A"]
    for m in required:
        if m not in metrics:
            raise ValueError(f"Missing metric: {m}")

    scope_changed = WEIGHTS["S"][metrics["S"]]

    # Get weights
    av = WEIGHTS["AV"][metrics["AV"]]
    ac = WEIGHTS["AC"][metrics["AC"]]
    ui = WEIGHTS["UI"][metrics["UI"]]

    # PR depends on scope
    pr_key = metrics["PR"]
    if scope_changed and pr_key in ("L", "H"):
        pr = WEIGHTS["PR"][f"{pr_key}_C"]
    else:
        pr = WEIGHTS["PR"][pr_key]

    c = WEIGHTS["C"][metrics["C"]]
    i = WEIGHTS["I"][metrics["I"]]
    a = WEIGHTS["A"][metrics["A"]]

    # Impact Sub-Score
    iss = 1 - ((1 - c) * (1 - i) * (1 - a))

    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss

    # Exploitability
    exploitability = 8.22 * av * ac * pr * ui

    if impact <= 0:
        score = 0.0
    elif scope_changed:
        score = _roundup(min(1.08 * (impact + exploitability), 10))
    else:
        score = _roundup(min(impact + exploitability, 10))

    severity = score_to_severity(score)

    # Reconstruct clean vector
    clean_vector = f"CVSS:3.1/AV:{metrics['AV']}/AC:{metrics['AC']}/PR:{metrics['PR']}/UI:{metrics['UI']}/S:{metrics['S']}/C:{metrics['C']}/I:{metrics['I']}/A:{metrics['A']}"

    return CVSSResult(score=score, severity=severity, vector=clean_vector)


def score_to_severity(score: float) -> Severity:
    """Convert CVSS score to severity rating."""
    if score >= 9.0:
        return Severity.CRITICAL
    elif score >= 7.0:
        return Severity.HIGH
    elif score >= 4.0:
        return Severity.MEDIUM
    elif score > 0.0:
        return Severity.LOW
    else:
        return Severity.INFO
