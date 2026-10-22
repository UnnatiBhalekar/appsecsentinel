"""
test_quality.py
---------------
Quality gate for the OWASP scanner.

Runs every labelled test case through the core scanner and asserts that the
combined precision and recall stay above the minimum thresholds.  CI will fail
if a code change makes the scanner meaningfully worse.

Thresholds:
  Precision >= 0.95  (no more than 1 false positive per 20 scans)
  Recall    >= 0.90  (catch at least 9 out of 10 real vulnerabilities)
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.scanner import scan_code, format_findings
from tests.test_scanner import CASES, HARD_CASES

CLEAN_PREFIX = "✅ No OWASP Top 10"
MIN_PRECISION = 0.95
MIN_RECALL    = 0.90


def _was_flagged(code: str, language: str) -> bool:
    findings = scan_code(code, language)
    report = format_findings(findings, language)
    return not report.strip().startswith(CLEAN_PREFIX)


def _score(cases) -> tuple[float, float, list]:
    tp = fp = fn = tn = 0
    failures = []
    for name, code, language, should_flag in cases:
        flagged = _was_flagged(code, language)
        if should_flag and flagged:
            tp += 1
        elif should_flag and not flagged:
            fn += 1
            failures.append(f"  FN (missed):     {name}")
        elif not should_flag and flagged:
            fp += 1
            failures.append(f"  FP (false alarm): {name}")
        else:
            tn += 1
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall    = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    return precision, recall, failures


def test_combined_precision_and_recall():
    """
    Combined precision and recall across EASY + HARD cases must stay above
    the minimum thresholds so quality regressions are caught in CI.
    """
    all_cases = list(CASES) + list(HARD_CASES)
    precision, recall, failures = _score(all_cases)

    detail = "\n".join(failures) if failures else "  (none)"
    msg = (
        f"\nScanner quality check failed on {len(all_cases)} cases:\n"
        f"  Precision: {precision:.1%}  (min {MIN_PRECISION:.0%})\n"
        f"  Recall:    {recall:.1%}  (min {MIN_RECALL:.0%})\n"
        f"Wrong cases:\n{detail}"
    )

    assert precision >= MIN_PRECISION, msg
    assert recall    >= MIN_RECALL,    msg
