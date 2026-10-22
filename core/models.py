"""
core/models.py
--------------
Shared data types used across all scanner modules.
"""

from typing import NamedTuple


class Finding(NamedTuple):
    """One security finding returned by any of the core scanners."""
    rule_id: str         # short code, e.g. "SQL-001"; used in SARIF ruleId
    severity: str        # CRITICAL | HIGH | MEDIUM | LOW
    owasp_category: str  # e.g. "A03 Injection"
    message: str         # human-readable description of the issue
    line_number: int = 0 # 1-indexed; 0 means unknown / not applicable


# Severity ranking used for sorting and --fail-on threshold comparisons
SEVERITY_ORDER: dict[str, int] = {
    "CRITICAL": 0,
    "HIGH":     1,
    "MEDIUM":   2,
    "LOW":      3,
}
