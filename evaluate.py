"""
evaluate.py
-----------
Runs every case in tests/test_scanner.py through scan_owasp_vulnerabilities()
and prints a full accuracy report.

Groups:
  EASY  — original 39 cases (CASES list)
  HARD  — 15 harder cases (HARD_CASES list)

Metrics per group and combined:
  TP = vulnerable snippet correctly flagged
  FP = safe snippet wrongly flagged (over-detection)
  FN = vulnerable snippet missed (under-detection)
  TN = safe snippet correctly cleared

  Precision = TP / (TP + FP)
  Recall    = TP / (TP + FN)
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from server import scan_owasp_vulnerabilities
from tests.test_scanner import CASES, HARD_CASES

CLEAN_PREFIX = "✅ No OWASP Top 10"


def was_flagged(result: str) -> bool:
    return not result.strip().startswith(CLEAN_PREFIX)


def evaluate_group(cases, group_name: str) -> dict:
    """Run all cases in `cases` and return accuracy stats."""
    tp, fp, fn, tn = [], [], [], []
    wrong = []

    for name, code, language, should_flag in cases:
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
        else:
            tn.append(name)

    n_tp, n_fp, n_fn, n_tn = len(tp), len(fp), len(fn), len(tn)
    precision = n_tp / (n_tp + n_fp) if (n_tp + n_fp) > 0 else 0.0
    recall    = n_tp / (n_tp + n_fn) if (n_tp + n_fn) > 0 else 0.0

    print(f"\n{'─' * 60}")
    print(f"GROUP: {group_name}  ({len(cases)} cases)")
    print(f"{'─' * 60}")
    print(f"  True  Positives : {n_tp}")
    print(f"  False Positives : {n_fp}")
    print(f"  False Negatives : {n_fn}")
    print(f"  True  Negatives : {n_tn}")
    print(f"  Precision       : {precision:.1%}")
    print(f"  Recall          : {recall:.1%}")

    if wrong:
        print(f"\n  Wrong ({len(wrong)}):")
        for name, expected, got, snippet in wrong:
            short = snippet.strip()[:100].replace("\n", " | ")
            print(f"    [{got}] {name}")
            print(f"      expected={expected}  scanner={short}…")

    return {"total": len(cases), "tp": n_tp, "fp": n_fp, "fn": n_fn, "tn": n_tn,
            "precision": precision, "recall": recall, "wrong": wrong}


def run_evaluation():
    print("=" * 60)
    print("SCANNER ACCURACY REPORT — AppSecSentinel")
    print("=" * 60)

    easy = evaluate_group(CASES,      "EASY (original 39)")
    hard = evaluate_group(HARD_CASES, "HARD (new 15)")

    # Combined totals
    tp = easy["tp"] + hard["tp"]
    fp = easy["fp"] + hard["fp"]
    fn = easy["fn"] + hard["fn"]
    tn = easy["tn"] + hard["tn"]
    total = easy["total"] + hard["total"]
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall    = tp / (tp + fn) if (tp + fn) > 0 else 0.0

    print(f"\n{'═' * 60}")
    print(f"COMBINED  ({total} cases)")
    print(f"{'═' * 60}")
    print(f"  True  Positives : {tp}")
    print(f"  False Positives : {fp}")
    print(f"  False Negatives : {fn}")
    print(f"  True  Negatives : {tn}")
    print(f"  Precision       : {precision:.1%}")
    print(f"  Recall          : {recall:.1%}")

    return {"easy": easy, "hard": hard,
            "combined": {"tp": tp, "fp": fp, "fn": fn, "tn": tn,
                         "precision": precision, "recall": recall}}


if __name__ == "__main__":
    run_evaluation()
