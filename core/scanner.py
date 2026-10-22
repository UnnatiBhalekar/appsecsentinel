"""
core/scanner.py
---------------
OWASP Top 10 pattern-based scanner for source code.

Two scanning strategies are combined:
  1. AST scan   (Python only) — understands variable assignments and call sites
  2. Regex scan (all languages) — catches patterns the AST can't see (Java,
     JavaScript, XML) and provides fallback for non-parseable Python

The AST scanner takes priority: if it fires for a rule, the corresponding
regex rule is skipped to avoid duplicate findings.
"""

import re
from collections import defaultdict
from .models import Finding, SEVERITY_ORDER
from .python_ast_scanner import scan_python


# ---------------------------------------------------------------------------
# Regex patterns — one entry per rule
# Each tuple: (rule_id, owasp_category, severity, label, compiled_regex)
# ---------------------------------------------------------------------------
OWASP_PATTERNS: list[tuple[str, str, str, str, re.Pattern]] = [

    # A03 — SQL injection via string building
    ("SQL-001", "A03 Injection", "CRITICAL",
     "SQL Injection pattern",
     re.compile(
         r"(?i)(select|insert|update|delete|drop|union)\s.*(from|where|into|values)"
         r".*(\+\s*['\"]|\$\{|%s|format\(|f['\"])",
         re.DOTALL,
     )),

    # A03 — Command injection
    ("CMD-001", "A03 Injection", "CRITICAL",
     "Command Injection (os.system / shell=True / Runtime.exec)",
     re.compile(
         r"(?i)(os\.system\s*\(|subprocess\.(call|run|Popen)\s*\(.*shell\s*=\s*True"
         r"|Runtime\.getRuntime\(\)\.exec)",
     )),

    # A03 — XSS sinks (label corrected: XSS is A03 Injection per OWASP Top 10 2021)
    # Negative lookahead on innerHTML= skips DOMPurify.sanitize(…) on the RHS
    ("XSS-001", "A03 Injection", "HIGH",
     "Cross-Site Scripting sink (innerHTML / document.write / eval)",
     re.compile(
         r"(?i)(innerHTML\s*=(?!\s*DOMPurify\.sanitize\s*\()"
         r"|document\.write\s*\(|eval\s*\(|setTimeout\s*\(\s*['\"])",
     )),

    # A02 — Weak hashing
    ("HASH-001", "A02 Cryptographic Failures", "HIGH",
     "Weak hashing algorithm (MD5 / SHA-1)",
     re.compile(
         r"(?i)(md5\s*\(|MessageDigest\.getInstance\(['\"]MD5['\"]"
         r"|hashlib\.md5|SHA[-_]?1\b|hashlib\.sha1)"
     )),

    # A02 — Insecure cipher modes
    ("CRYPTO-001", "A02 Cryptographic Failures", "HIGH",
     "Insecure cipher mode (DES / RC4 / ECB)",
     re.compile(r"(?i)(DES\b|RC4\b|AES/ECB|Cipher\.getInstance\(['\"]AES['\"])")),

    # A08 — Unsafe deserialisation
    # yaml pattern: match only single-argument form; a comma stops the match so
    # yaml.load(x, Loader=yaml.SafeLoader) is skipped
    ("DESER-001", "A08 Insecure Deserialisation", "CRITICAL",
     "Unsafe deserialisation (pickle.loads / yaml.load / ObjectInputStream)",
     re.compile(
         r"(?i)(pickle\.loads?\s*\(|yaml\.load\s*\(\s*[^,)]+\s*\)"
         r"|new\s+ObjectInputStream\s*\()",
     )),

    # A01 — Path traversal
    ("PATH-001", "A01 Broken Access Control", "HIGH",
     "Path traversal pattern (../)",
     re.compile(r"(\.\.[/\\]){1,}")),

    # A05 — XXE
    ("XXE-001", "A05 Security Misconfiguration / XXE", "CRITICAL",
     "XML External Entity (XXE) pattern",
     re.compile(r"(?i)(<!ENTITY\s|SYSTEM\s+['\"]|DOCTYPE\s+\S+\s+SYSTEM)")),

    # A02 — Hardcoded secrets
    ("SECRET-001", "A02 Cryptographic Failures", "CRITICAL",
     "Hardcoded AWS Access Key",
     re.compile(r"AKIA[0-9A-Z]{16}")),

    ("SECRET-002", "A02 Cryptographic Failures", "HIGH",
     "Hardcoded password / secret in code",
     re.compile(r"(?i)(password|passwd|secret|api_?key)\s*[:=]\s*['\"][^'\"]{4,}")),

    ("SECRET-003", "A02 Cryptographic Failures", "CRITICAL",
     "Private key material in source",
     re.compile(r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----")),

    # A02 — Insecure randomness (corrected from A09; weak entropy is a crypto failure)
    ("RAND-001", "A02 Cryptographic Failures", "MEDIUM",
     "Insecure randomness for security-sensitive context (Math.random / random.random)",
     re.compile(r"(?i)(Math\.random\s*\(\)|random\.random\s*\(\))")),
]

# Maps each AST rule_id to the regex rule_id it supersedes.
# When the AST fires for a rule, the corresponding regex is skipped.
_AST_COVERS: dict[str, str] = {
    "SQL-002":   "SQL-001",
    "CMD-002":   "CMD-001",
    "CMD-003":   "CMD-001",
    "DESER-002": "DESER-001",
    "DESER-003": "DESER-001",
    "HASH-002":  "HASH-001",
    "HASH-003":  "HASH-001",
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def scan_code(code: str, language: str = "generic") -> list[Finding]:
    """
    Scan source code for OWASP Top 10 patterns and return structured findings.

    Strategy:
      1. Run the AST scanner (Python only; falls back silently on SyntaxError)
      2. Skip the regex rule whenever the AST already covered the same class
      3. Run remaining regex rules against the raw text
    """
    findings: list[Finding] = []

    # --- AST scan (Python only) ---------------------------------------------
    ast_results = scan_python(code)
    findings.extend(ast_results)

    # Which regex rule_ids are now covered by the AST?
    ast_covered = {_AST_COVERS[f.rule_id] for f in ast_results if f.rule_id in _AST_COVERS}

    # --- Regex scan for everything not covered by AST -----------------------
    for rule_id, category, severity, label, pattern in OWASP_PATTERNS:
        if rule_id in ast_covered:
            continue  # AST already found this class; skip to avoid duplicates
        for match in pattern.finditer(code):
            line_no = code[: match.start()].count("\n") + 1
            findings.append(Finding(
                rule_id=rule_id,
                severity=severity,
                owasp_category=category,
                message=label,
                line_number=line_no,
            ))

    return findings


def format_findings(findings: list[Finding], language: str) -> str:
    """
    Convert a list of structured findings into a human-readable text report.
    Groups by rule_id and counts matches so the output matches the original format.
    """
    if not findings:
        return (
            f"✅ No OWASP Top 10 vulnerability patterns detected in the provided "
            f"{language} code.\n\n"
            "Note: This is a pattern-based scan, not a full SAST analysis. "
            "Always validate with a dedicated tool (e.g. SonarCloud) before production."
        )

    # Group findings by rule_id to count matches per rule
    groups: dict[str, list[Finding]] = defaultdict(list)
    for f in findings:
        groups[f.rule_id].append(f)

    # Sort groups by severity (CRITICAL first)
    sorted_groups = sorted(
        groups.values(),
        key=lambda fs: SEVERITY_ORDER.get(fs[0].severity, 9),
    )

    lines = [f"⚠️  OWASP VULNERABILITY SCAN REPORT  ({language.upper()})"]
    lines.append("=" * 52)

    current_severity = None
    for group in sorted_groups:
        rep = group[0]  # representative finding for label/category
        if rep.severity != current_severity:
            lines.append(f"\n[{rep.severity}]")
            current_severity = rep.severity
        lines.append(f"  • {rep.message}")
        lines.append(f"    Category : {rep.owasp_category}")
        lines.append(f"    Matches  : {len(group)}")

    lines.append(
        f"\n{'─' * 52}\n"
        f"Total findings: {len(groups)}\n\n"
        "Recommendation: Prioritise CRITICAL findings immediately. "
        "Review against OWASP Top 10 (owasp.org/Top10) and enforce "
        "remediations via SonarCloud security gates in your CI/CD pipeline."
    )

    return "\n".join(lines)
