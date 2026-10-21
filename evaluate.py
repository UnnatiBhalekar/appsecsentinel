"""
evaluate.py
-----------
Runs every case in tests/test_scanner.py through scan_owasp_vulnerabilities()
and prints a full accuracy report:

  - True Positives  (TP): scanner flagged a genuinely vulnerable snippet
  - False Positives (FP): scanner flagged a safe snippet (over-detection)
  - False Negatives (FN): scanner missed a vulnerable snippet (under-detection)
  - True Negatives  (TN): scanner correctly cleared a safe snippet

  Precision = TP / (TP + FP)  — "of everything flagged, how much is real?"
  Recall    = TP / (TP + FN)  — "of everything real, how much was caught?"
"""

import sys
import os

# Allow importing from the project root without installing as a package
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from server import scan_owasp_vulnerabilities
from tests.test_scanner import CASES

# ---------------------------------------------------------------------------
# Helper: decide if a result counts as "flagged"
# The scanner returns the clean message when nothing is found,
# so anything NOT starting with the clean prefix is a finding.
# ---------------------------------------------------------------------------
CLEAN_PREFIX = "✅ No OWASP Top 10"

def was_flagged(result: str) -> bool:
    """Return True if the scanner reported at least one finding."""
    return not result.strip().startswith(CLEAN_PREFIX)


def run_evaluation():
    tp = []  # (name) — correctly flagged
    fp = []  # (name) — wrongly flagged (safe code)
    fn = []  # (name) — missed (vulnerable code)
    tn = []  # (name) — correctly cleared

    wrong = []  # (name, expected, got, result_snippet) for the detailed wrong list

    print("Running evaluation…")
    print(f"Total cases: {len(CASES)}\n")

    for name, code, language, should_flag in CASES:
        result = scan_owasp_vulnerabilities(code, language)
        flagged = was_flagged(result)

        if should_flag and flagged:
            tp.append(name)
        elif should_flag and not flagged:
            fn.append(name)
            wrong.append((name, "FLAGGED", "CLEAN", result))
        elif not should_flag and flagged:
            fp.append(name)
            wrong.append((name, "CLEAN", "FLAGGED", result))
        else:  # not should_flag and not flagged
            tn.append(name)

    # ── Summary numbers ────────────────────────────────────────────────────
    total     = len(CASES)
    n_tp      = len(tp)
    n_fp      = len(fp)
    n_fn      = len(fn)
    n_tn      = len(tn)

    precision = n_tp / (n_tp + n_fp) if (n_tp + n_fp) > 0 else 0.0
    recall    = n_tp / (n_tp + n_fn) if (n_tp + n_fn) > 0 else 0.0

    print("=" * 60)
    print("SCANNER ACCURACY REPORT — AppSecSentinel v1 baseline")
    print("=" * 60)
    print(f"Total test cases  : {total}")
    print(f"True  Positives   : {n_tp}  (vulnerable snippets correctly flagged)")
    print(f"False Positives   : {n_fp}  (safe snippets wrongly flagged)")
    print(f"False Negatives   : {n_fn}  (vulnerable snippets missed)")
    print(f"True  Negatives   : {n_tn}  (safe snippets correctly cleared)")
    print(f"Precision         : {precision:.1%}  (TP / (TP + FP))")
    print(f"Recall            : {recall:.1%}  (TP / (TP + FN))")
    print()

    # ── Wrong results detail ───────────────────────────────────────────────
    if wrong:
        print(f"WRONG RESULTS ({len(wrong)}):")
        print("-" * 60)
        for name, expected, got, snippet in wrong:
            # Trim the result to the first 120 chars so the output is readable
            short = snippet.strip()[:120].replace("\n", " | ")
            print(f"  [{got}]  {name}")
            print(f"    Expected : {expected}")
            print(f"    Scanner  : {short}…")
            print()
    else:
        print("All cases correct — no wrong results.")

    # Return data for the markdown writer
    return {
        "total": total, "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "precision": precision, "recall": recall, "wrong": wrong,
    }


if __name__ == "__main__":
    run_evaluation()
