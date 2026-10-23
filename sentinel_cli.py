"""
sentinel_cli.py
---------------
Command-line interface for AppSecSentinel's OWASP scanner.

Usage:
    python sentinel_cli.py scan <path> [--format text|sarif]
                                       [--fail-on CRITICAL|HIGH|MEDIUM|LOW|NONE]
                                       [--exclude <fragment> ...]

Options:
    --format    Output format: human-readable 'text' (default) or 'sarif' (SARIF 2.1.0 JSON)
    --fail-on   Exit with code 1 if any finding at or above this severity is found.
                Use 'NONE' to always exit 0 regardless of findings (default: NONE).
    --exclude   Skip any file whose path contains one of these substrings.
                Can be repeated: --exclude demo --exclude tests

Scans every .py, .java, and .js file under the given path.
"""

import argparse
import json
import sys
from pathlib import Path

from core.scanner import scan_code, format_findings
from core.models  import Finding, SEVERITY_ORDER


# File extensions this CLI scans
_SCAN_EXTENSIONS = {".py", ".java", ".js"}

# Maps file extension to a language label used in reports
_EXT_TO_LANG = {".py": "python", ".java": "java", ".js": "javascript"}

# SARIF severity levels
_SARIF_LEVEL = {
    "CRITICAL": "error",
    "HIGH":     "error",
    "MEDIUM":   "warning",
    "LOW":      "note",
}


def _collect_files(root: Path, excludes: list[str] | None = None) -> list[Path]:
    """Return all scannable files under root, sorted for deterministic output.

    excludes — list of path fragment strings; any file whose absolute path
               contains one of them is skipped (e.g. ["demo", "tests"]).
    """
    excludes = excludes or []
    if root.is_file():
        if root.suffix not in _SCAN_EXTENSIONS:
            return []
        if any(ex in str(root) for ex in excludes):
            return []
        return [root]
    return sorted(
        p for p in root.rglob("*")
        if p.suffix in _SCAN_EXTENSIONS
        and not any(ex in str(p) for ex in excludes)
    )


def _scan_all(files: list[Path]) -> list[tuple[Path, list[Finding]]]:
    """Scan each file and return (path, findings) pairs."""
    results = []
    for path in files:
        try:
            code = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        lang = _EXT_TO_LANG.get(path.suffix, "generic")
        findings = scan_code(code, lang)
        results.append((path, findings))
    return results


def _output_text(results: list[tuple[Path, list[Finding]]], root: Path) -> str:
    """Format all results as human-readable text."""
    lines = []
    total_findings = 0
    for path, findings in results:
        rel = path.relative_to(root) if root.is_dir() else path
        lang = _EXT_TO_LANG.get(path.suffix, "generic")
        if findings:
            total_findings += len(set(f.rule_id for f in findings))
            lines.append(f"\n{'=' * 60}")
            lines.append(f"FILE: {rel}")
            lines.append("=" * 60)
            lines.append(format_findings(findings, lang))
        else:
            lines.append(f"✅ {rel} — clean")
    lines.append(f"\n{'─' * 60}")
    lines.append(f"Total unique findings across all files: {total_findings}")
    return "\n".join(lines)


def _output_sarif(results: list[tuple[Path, list[Finding]]], root: Path) -> str:
    """Format all results as SARIF 2.1.0 JSON."""
    sarif_results = []
    for path, findings in results:
        try:
            rel = str(path.relative_to(root))
        except ValueError:
            rel = str(path)
        for f in findings:
            sarif_results.append({
                "ruleId": f.rule_id,
                "level": _SARIF_LEVEL.get(f.severity, "note"),
                "message": {"text": f.message},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": rel},
                            "region": {"startLine": max(f.line_number, 1)},
                        }
                    }
                ],
            })

    sarif_doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "AppSecSentinel",
                        "version": "1.0.0",
                        "informationUri": "https://owasp.org/Top10",
                    }
                },
                "results": sarif_results,
            }
        ],
    }
    return json.dumps(sarif_doc, indent=2)


def _should_fail(results: list[tuple[Path, list[Finding]]], fail_on: str) -> bool:
    """Return True if any finding meets or exceeds the --fail-on threshold."""
    if fail_on == "NONE":
        return False
    threshold = SEVERITY_ORDER[fail_on]
    for _, findings in results:
        for f in findings:
            if SEVERITY_ORDER.get(f.severity, 9) <= threshold:
                return True
    return False


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sentinel_cli",
        description="AppSecSentinel — OWASP Top 10 scanner for .py/.java/.js files",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    scan_parser = sub.add_parser("scan", help="Scan files under a path")
    scan_parser.add_argument(
        "paths", nargs="+", type=Path,
        metavar="PATH",
        help="One or more files or directories to scan",
    )
    scan_parser.add_argument(
        "--format", choices=["text", "sarif"], default="text",
        dest="fmt", help="Output format (default: text)"
    )
    scan_parser.add_argument(
        "--fail-on",
        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"],
        default="NONE",
        dest="fail_on",
        help="Exit 1 if any finding at or above this severity (default: NONE)",
    )
    scan_parser.add_argument(
        "--exclude",
        action="append",
        default=[],
        metavar="FRAGMENT",
        help="Skip files whose path contains FRAGMENT (repeatable)",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    """Entry point; returns the process exit code."""
    parser = _build_parser()
    args = parser.parse_args(argv)

    # Resolve all paths and validate existence
    roots: list[Path] = []
    for p in args.paths:
        resolved = p.resolve()
        if not resolved.exists():
            print(f"Error: path does not exist: {resolved}", file=sys.stderr)
            return 2
        roots.append(resolved)

    # Collect all files across every supplied path (deduplicated, sorted)
    seen: set[Path] = set()
    all_files: list[Path] = []
    for root in roots:
        for f in _collect_files(root, args.exclude):
            if f not in seen:
                seen.add(f)
                all_files.append(f)
    all_files.sort()

    if not all_files:
        print(f"No scannable files ({', '.join(_SCAN_EXTENSIONS)}) found.")
        return 0

    results = _scan_all(all_files)

    # Use the working directory as the SARIF base so URIs are repo-relative
    sarif_root = Path.cwd()

    if args.fmt == "sarif":
        print(_output_sarif(results, sarif_root))
    else:
        # For text output use the first supplied root for relative display
        print(_output_text(results, roots[0] if len(roots) == 1 else sarif_root))

    return 1 if _should_fail(results, args.fail_on) else 0


if __name__ == "__main__":
    sys.exit(main())
