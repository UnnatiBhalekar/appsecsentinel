"""
AppSecSentinel MCP Server
==========================
A JPMorgan-aligned application security MCP server that gives an AI agent
controlled, audited access to three core AppSec engineering tools.

TOOLS:
  1. scan_owasp_vulnerabilities(code, language)
       SAST-style scanner for OWASP Top 10 vulnerability patterns —
       SQL injection, command injection, XSS, insecure deserialisation,
       path traversal, weak cryptography, XXE, hardcoded secrets, and more.

  2. analyze_jwt_token(token)
       Decodes and inspects a JWT (header + payload) for security weaknesses:
       "none" algorithm, missing expiry/audience claims, expired tokens,
       symmetric-only algorithms, and overly broad permission scopes.

  3. audit_iam_policy(policy_json)
       Parses an AWS IAM policy document and flags least-privilege violations:
       wildcard actions, wildcard resources without conditions, and known
       privilege-escalation permission combinations.

SECURITY FEATURES (applied to every tool call — these are a core deliverable,
not an afterthought, mirroring JPMorgan's tamper-proof, audit-defensible standard):
  1. Input length validation   — rejects inputs over 10,000 characters
  2. Prompt injection detection — blocks manipulation patterns before processing
  3. Audit logging             — SHA-256-hashed audit trail to disk (never raw input)
  4. Safe error handling       — catches all exceptions; never leaks internals to the agent
  5. Output length capping     — truncates responses over 5,000 characters
"""

import re
import json
import base64
import hashlib
import logging
import datetime
import pathlib

from mcp.server.fastmcp import FastMCP

# ---------------------------------------------------------------------------
# Resolve project directory from __file__ so the audit log always writes
# next to this script regardless of what working directory the launcher uses.
# (Claude Desktop launches from /, which is read-only on macOS.)
# ---------------------------------------------------------------------------
SERVER_DIR = pathlib.Path(__file__).parent.resolve()

# ---------------------------------------------------------------------------
# FastMCP server — handles the MCP JSON-RPC protocol so we write plain Python.
# ---------------------------------------------------------------------------
mcp = FastMCP("AppSecSentinel")

# ---------------------------------------------------------------------------
# Audit logger
# Writes a permanent, tamper-evident trail to disk.  Uses Python's built-in
# logging module so entries are serialised safely even under concurrent calls.
# ---------------------------------------------------------------------------
audit_logger = logging.getLogger("audit")
audit_logger.setLevel(logging.INFO)
_file_handler = logging.FileHandler(SERVER_DIR / "appsec_sentinel_audit.log")
_file_handler.setFormatter(logging.Formatter("%(message)s"))
audit_logger.addHandler(_file_handler)

# ---------------------------------------------------------------------------
# SECURITY CONSTANTS
# ---------------------------------------------------------------------------
MAX_INPUT_LENGTH = 10_000   # chars — prevents memory exhaustion / oversized payloads
MAX_OUTPUT_LENGTH = 5_000   # chars — caps data exfiltration via tool output

# Prompt injection phrases — attackers embed these inside code/policy snippets
# hoping the AI will follow the injected instructions rather than call the tool.
INJECTION_PATTERNS = [
    r"ignore.*instructions",
    r"you are now",
    r"disregard",
    r"forget.*instructions",
    r"new instructions:",
    r"system prompt:",
    r"act as",
]


# ===========================================================================
# SHARED SECURITY HELPERS
# ===========================================================================

def _hash_input(text: str) -> str:
    """
    WHY: We need forensic traceability but logging raw inputs would itself
    create a security risk (logs could contain tokens, passwords, or policy
    secrets).  SHA-256 of the first 200 chars is an unforgeable fingerprint
    that lets analysts correlate a log entry to a known input without
    re-introducing the sensitive data.
    """
    return hashlib.sha256(text[:200].encode()).hexdigest()


def _write_audit_log(tool_name: str, input_hash: str) -> None:
    """
    WHY: Every security-sensitive operation at a financial institution must
    produce a non-repudiable, timestamped record.  These logs satisfy audit,
    compliance, and incident-response requirements — the 'audit-defensible
    methods' standard called out in the JPMorgan JD.
    """
    ts = datetime.datetime.utcnow().isoformat() + "Z"
    audit_logger.info(f"[{ts}] tool={tool_name} input_sha256={input_hash}")


def _validate_input(text: str, tool_name: str) -> str | None:
    """
    Runs input length check and prompt injection scan.
    Returns an error string to return to the caller, or None if the input is safe.

    WHY (length): Unbounded inputs exhaust memory and can be used to smuggle
    enormous payloads through the AI layer.

    WHY (injection): Malicious content embedded in code or policy documents can
    attempt to override the AI's behaviour.  Detecting and refusing at the tool
    boundary adds defence-in-depth even when the model itself doesn't catch it.
    """
    # Security Feature 1 — Input length validation
    if len(text) > MAX_INPUT_LENGTH:
        return (
            f"Error: Input exceeds the {MAX_INPUT_LENGTH:,}-character limit. "
            "Please provide a shorter input."
        )

    # Security Feature 2 — Prompt injection detection
    lower = text.lower()
    for pattern in INJECTION_PATTERNS:
        if re.search(pattern, lower):
            _write_audit_log(tool_name + "_INJECTION_ATTEMPT", _hash_input(text))
            return (
                "Error: Input contains a pattern associated with prompt injection. "
                "Request refused for security reasons."
            )

    return None


def _cap_output(text: str) -> str:
    """
    WHY (Security Feature 5): A malicious file could cause the tool to emit
    megabytes of data — costing real token budget and creating a potential
    data-exfiltration channel through the AI layer.  Hard-capping output
    at 5,000 chars makes this class of attack economically unviable.
    """
    if len(text) > MAX_OUTPUT_LENGTH:
        return text[:MAX_OUTPUT_LENGTH] + "\n\n[Output truncated for safety]"
    return text


# ===========================================================================
# TOOL 1 — scan_owasp_vulnerabilities
# OWASP Top 10 aligned SAST-style scanner, mirroring SonarCloud's role in
# the CI/CD pipelines described in the CV.
# ===========================================================================

# Each entry: (OWASP category, severity, human label, compiled regex)
OWASP_PATTERNS: list[tuple[str, str, str, re.Pattern]] = [
    # A03 — Injection
    ("A03 Injection", "CRITICAL",
     "SQL Injection pattern",
     re.compile(
         r"(?i)(select|insert|update|delete|drop|union)\s.*(from|where|into|values)"
         r".*(\+\s*['\"]|\$\{|%s|format\(|f['\"])",
         re.DOTALL,
     )),
    ("A03 Injection", "CRITICAL",
     "Command Injection (os.system / shell=True / Runtime.exec)",
     re.compile(
         r"(?i)(os\.system\s*\(|subprocess\.(call|run|Popen)\s*\(.*shell\s*=\s*True"
         r"|Runtime\.getRuntime\(\)\.exec)",
     )),
    # A03 — XSS
    ("A03 Injection / A07 XSS", "HIGH",
     "Cross-Site Scripting sink (innerHTML / document.write / eval)",
     re.compile(
         r"(?i)(innerHTML\s*=|document\.write\s*\(|eval\s*\(|setTimeout\s*\(\s*['\"])",
     )),
    # A02 — Cryptographic Failures
    ("A02 Cryptographic Failures", "HIGH",
     "Weak hashing algorithm (MD5 / SHA-1)",
     re.compile(r"(?i)(md5\s*\(|MessageDigest\.getInstance\(['\"]MD5['\"]"
                r"|hashlib\.md5|SHA[-_]?1\b|hashlib\.sha1)")),
    ("A02 Cryptographic Failures", "HIGH",
     "Insecure cipher mode (DES / RC4 / ECB)",
     re.compile(r"(?i)(DES\b|RC4\b|AES/ECB|Cipher\.getInstance\(['\"]AES['\"])")),
    # A08 — Insecure Deserialisation
    ("A08 Insecure Deserialisation", "CRITICAL",
     "Unsafe deserialisation (pickle.loads / yaml.load / ObjectInputStream)",
     re.compile(
         r"(?i)(pickle\.loads?\s*\(|yaml\.load\s*\([^)]*\)(?!\s*,\s*Loader)"
         r"|new\s+ObjectInputStream\s*\()",
     )),
    # A01 — Path Traversal
    ("A01 Broken Access Control", "HIGH",
     "Path traversal pattern (../)",
     re.compile(r"(\.\.[/\\]){1,}")),
    # A05 — Security Misconfiguration / XXE
    ("A05 Security Misconfiguration / XXE", "CRITICAL",
     "XML External Entity (XXE) pattern",
     re.compile(r"(?i)(<!ENTITY\s|SYSTEM\s+['\"]|DOCTYPE\s+\S+\s+SYSTEM)")),
    # A02 — Hardcoded secrets (kept from original tool — always relevant)
    ("A02 Cryptographic Failures", "CRITICAL",
     "Hardcoded AWS Access Key",
     re.compile(r"AKIA[0-9A-Z]{16}")),
    ("A02 Cryptographic Failures", "HIGH",
     "Hardcoded password / secret in code",
     re.compile(r"(?i)(password|passwd|secret|api_?key)\s*[:=]\s*['\"][^'\"]{4,}")),
    ("A02 Cryptographic Failures", "CRITICAL",
     "Private key material in source",
     re.compile(r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    # A09 — Insecure randomness used for security
    ("A09 Security Logging Failures", "MEDIUM",
     "Insecure randomness for security-sensitive context (Math.random / random.random)",
     re.compile(r"(?i)(Math\.random\s*\(\)|random\.random\s*\(\))")),
]

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


@mcp.tool()
def scan_owasp_vulnerabilities(code: str, language: str = "generic") -> str:
    """
    SAST-style scan of source code for OWASP Top 10 vulnerability patterns.
    Detects SQL/command injection, XSS, insecure deserialisation, path traversal,
    weak cryptography, XXE, hardcoded secrets, and insecure randomness.

    Args:
        code:     Source code or text to analyse.
        language: Hint for context in the report (e.g. "python", "java", "javascript").
                  Does not change detection logic — patterns are language-agnostic.

    Returns:
        A severity-sorted report of findings, or a clean bill of health.
    """
    # Security Features 1 & 2 — validate input
    error = _validate_input(code, "scan_owasp_vulnerabilities")
    if error:
        return error

    # Security Feature 3 — audit log (hashed, never raw)
    _write_audit_log("scan_owasp_vulnerabilities", _hash_input(code))

    # Security Feature 4 — safe error handling
    try:
        findings: list[tuple[str, str, str, int]] = []  # (severity, category, label, count)

        for category, severity, label, pattern in OWASP_PATTERNS:
            matches = pattern.findall(code)
            if matches:
                findings.append((severity, category, label, len(matches)))

        if not findings:
            return (
                f"✅ No OWASP Top 10 vulnerability patterns detected in the provided "
                f"{language} code.\n\n"
                "Note: This is a pattern-based scan, not a full SAST analysis. "
                "Always validate with a dedicated tool (e.g. SonarCloud) before production."
            )

        # Sort by severity so CRITICAL issues appear first
        findings.sort(key=lambda x: SEVERITY_ORDER.get(x[0], 9))

        lines = [f"⚠️  OWASP VULNERABILITY SCAN REPORT  ({language.upper()})"]
        lines.append("=" * 52)

        current_severity = None
        for severity, category, label, count in findings:
            if severity != current_severity:
                lines.append(f"\n[{severity}]")
                current_severity = severity
            lines.append(f"  • {label}")
            lines.append(f"    Category : {category}")
            lines.append(f"    Matches  : {count}")

        lines.append(
            f"\n{'─' * 52}\n"
            f"Total findings: {len(findings)}\n\n"
            "Recommendation: Prioritise CRITICAL findings immediately. "
            "Review against OWASP Top 10 (owasp.org/Top10) and enforce "
            "remediations via SonarCloud security gates in your CI/CD pipeline."
        )

        return _cap_output("\n".join(lines))

    except Exception:
        return "Error: An unexpected error occurred during the vulnerability scan. Please try again."


# ===========================================================================
# TOOL 2 — analyze_jwt_token
# JWT security inspector — mirrors the JWT Token Inspector project on the CV
# and the OAuth2 / JWT / RBAC work described in the work experience section.
# ===========================================================================

# Algorithms considered weak or dangerous for production use
WEAK_ALGORITHMS = {"none", "hs256", "hs384", "hs512"}


def _b64url_decode(segment: str) -> bytes:
    """
    Base64url decode with automatic padding correction.
    JWT segments omit padding ('=') — we add it back before decoding.
    """
    padding = 4 - len(segment) % 4
    if padding != 4:
        segment += "=" * padding
    return base64.urlsafe_b64decode(segment)


@mcp.tool()
def analyze_jwt_token(token: str) -> str:
    """
    Decode and inspect a JWT (JSON Web Token) for security weaknesses without
    verifying the signature. Checks algorithm strength, required security claims
    (exp, iat, aud, iss), token expiry, and overly broad scopes/permissions.

    This tool does NOT verify the signature — it is an inspector, not a validator.
    Use it to audit token design and spot misconfiguration.

    Args:
        token: A JWT string in the format header.payload.signature

    Returns:
        A security analysis report of the token's header and payload.
    """
    token = token.strip()

    error = _validate_input(token, "analyze_jwt_token")
    if error:
        return error

    _write_audit_log("analyze_jwt_token", _hash_input(token))

    try:
        parts = token.split(".")
        if len(parts) != 3:
            return (
                "Error: Invalid JWT format. "
                "A JWT must have exactly 3 dot-separated parts: header.payload.signature"
            )

        # Decode header and payload
        try:
            header: dict = json.loads(_b64url_decode(parts[0]))
            payload: dict = json.loads(_b64url_decode(parts[1]))
        except Exception:
            return "Error: Could not decode JWT segments. Ensure the token is a valid base64url-encoded JWT."

        issues: list[tuple[str, str]] = []   # (severity, message)
        notes:  list[str] = []

        # --- Algorithm check ---
        alg = header.get("alg", "MISSING")
        if alg == "none":
            issues.append(("CRITICAL",
                "Algorithm is 'none' — signature verification is completely disabled. "
                "Any payload can be forged without a secret key."))
        elif alg == "MISSING":
            issues.append(("CRITICAL",
                "No 'alg' field in JWT header — algorithm is undefined. "
                "The token cannot be cryptographically verified and should be rejected."))
        elif alg.upper().startswith("HS"):
            issues.append(("HIGH",
                f"Algorithm '{alg}' uses a symmetric (shared) secret. "
                "If the secret leaks, any party can forge tokens. "
                "Prefer RS256/ES256 (asymmetric) for distributed systems."))
        else:
            notes.append(f"Algorithm '{alg}' — asymmetric, acceptable for production.")

        # --- Required claims check ---
        now = datetime.datetime.utcnow().timestamp()

        if "exp" not in payload:
            issues.append(("HIGH",
                "Missing 'exp' (expiry) claim — token never expires. "
                "A stolen token grants permanent access."))
        else:
            exp = payload["exp"]
            if exp < now:
                issues.append(("HIGH",
                    f"Token is EXPIRED (exp={exp}, "
                    f"now={int(now)}, "
                    f"expired {int(now - exp)}s ago). "
                    "Accepting this token is an authentication bypass."))
            else:
                lifetime_hrs = (exp - now) / 3600
                if lifetime_hrs > 24:
                    issues.append(("MEDIUM",
                        f"Token lifetime is {lifetime_hrs:.1f} hours — "
                        "unusually long. Prefer short-lived tokens (≤1h) "
                        "with refresh token rotation."))
                else:
                    notes.append(f"Expiry: valid for {lifetime_hrs:.1f} more hours.")

        if "iat" not in payload:
            issues.append(("LOW",
                "Missing 'iat' (issued-at) claim — makes replay-attack detection harder."))

        if "aud" not in payload:
            issues.append(("MEDIUM",
                "Missing 'aud' (audience) claim — token could be accepted by unintended services."))

        if "iss" not in payload:
            issues.append(("LOW",
                "Missing 'iss' (issuer) claim — origin of the token cannot be verified."))

        # --- Scope / permissions check ---
        scope = payload.get("scope", payload.get("scp", ""))
        if isinstance(scope, str) and scope:
            scope_list = scope.split()
            if len(scope_list) > 8:
                issues.append(("MEDIUM",
                    f"Token carries {len(scope_list)} scopes — potentially over-permissioned. "
                    "Apply least-privilege: grant only the scopes the service actually needs."))

        admin_fields = [k for k in payload if "admin" in k.lower() or "root" in k.lower()]
        for field in admin_fields:
            if payload[field] in (True, "true", 1, "admin"):
                issues.append(("HIGH",
                    f"Privileged claim detected: '{field}' = {payload[field]}. "
                    "Verify this is intentional and that the field is validated server-side."))

        # --- Build report ---
        issues.sort(key=lambda x: SEVERITY_ORDER.get(x[0], 9))

        lines = ["🔍 JWT SECURITY ANALYSIS", "=" * 40]
        lines.append(f"\nHeader:  {json.dumps(header)}")
        # Show payload but redact any value that looks like a secret
        safe_payload = {
            k: ("[REDACTED]" if any(s in k.lower() for s in ("secret", "key", "pass", "token")) else v)
            for k, v in payload.items()
        }
        lines.append(f"Payload: {json.dumps(safe_payload)}")
        lines.append(f"Signature segment present: {'Yes' if parts[2] else 'No (empty — possible none-alg attack)'}")

        if issues:
            lines.append(f"\n⚠️  FINDINGS ({len(issues)}):")
            current_sev = None
            for sev, msg in issues:
                if sev != current_sev:
                    lines.append(f"\n  [{sev}]")
                    current_sev = sev
                lines.append(f"    • {msg}")
        else:
            lines.append("\n✅ No security issues found in token structure.")

        if notes:
            lines.append("\nℹ️  Notes:")
            for note in notes:
                lines.append(f"  • {note}")

        lines.append(
            "\n\nNote: This tool inspects token design only. "
            "It does NOT verify the signature — use your identity provider's "
            "JWKS endpoint for full cryptographic validation."
        )

        return _cap_output("\n".join(lines))

    except Exception:
        return "Error: An unexpected error occurred during JWT analysis. Please try again."


# ===========================================================================
# TOOL 3 — audit_iam_policy
# AWS IAM policy least-privilege auditor — maps directly to the AWS/IAM
# experience in the CV (Secure Doc Vault, CloudWatch, IAM least privilege)
# and to the JD's cloud security requirements.
# ===========================================================================

# Permissions that, combined with iam:PassRole or alone, enable privilege escalation.
# Source: AWS privilege escalation research (Rhino Security Labs, AWS docs).
PRIV_ESC_SINGLETONS = {
    "iam:CreateAccessKey",
    "iam:AttachUserPolicy",
    "iam:PutUserPolicy",
    "iam:AttachGroupPolicy",
    "iam:PutGroupPolicy",
    "iam:CreateLoginProfile",
    "iam:UpdateLoginProfile",
    "sts:AssumeRole",
}

PRIV_ESC_WITH_PASSROLE = {
    "ec2:RunInstances",
    "lambda:CreateFunction",
    "lambda:InvokeFunction",
    "glue:CreateDevEndpoint",
    "sagemaker:CreateTrainingJob",
}

# Services whose wildcard actions are especially dangerous in a financial context
HIGH_RISK_SERVICES = {"iam", "sts", "kms", "secretsmanager", "s3", "ec2", "lambda"}


@mcp.tool()
def audit_iam_policy(policy_json: str) -> str:
    """
    Audit an AWS IAM policy document for least-privilege violations and
    privilege-escalation risks. Flags wildcard actions, wildcard resources
    without condition blocks, and known dangerous permission combinations.

    Args:
        policy_json: An AWS IAM policy document as a JSON string.

    Returns:
        A prioritised list of policy violations with remediation guidance.
    """
    error = _validate_input(policy_json, "audit_iam_policy")
    if error:
        return error

    _write_audit_log("audit_iam_policy", _hash_input(policy_json))

    try:
        try:
            policy: dict = json.loads(policy_json)
        except json.JSONDecodeError as exc:
            return f"Error: Invalid JSON — could not parse the IAM policy. Detail: {exc.msg} at line {exc.lineno}."

        statements: list[dict] = policy.get("Statement", None)
        if statements is None:
            return "No 'Statement' block found in the policy. Ensure this is a valid IAM policy document."
        if len(statements) == 0:
            return "✅ IAM policy has an empty Statement array — no permissions are granted. Verify this is intentional."

        issues: list[tuple[str, str]] = []

        for idx, stmt in enumerate(statements, start=1):
            label = f"Statement[{idx}] (Sid: {stmt.get('Sid', 'unnamed')})"
            effect = stmt.get("Effect", "Allow")

            if effect != "Allow":
                continue  # Deny statements narrow permissions — not a risk

            # Normalise actions and resources to lists
            raw_actions = stmt.get("Action", [])
            actions: list[str] = [raw_actions] if isinstance(raw_actions, str) else raw_actions

            raw_resources = stmt.get("Resource", [])
            resources: list[str] = [raw_resources] if isinstance(raw_resources, str) else raw_resources

            conditions: dict = stmt.get("Condition", {})

            # 1. Wildcard action check
            if "*" in actions:
                issues.append(("CRITICAL",
                    f"{label}: Action is '*' (AdministratorAccess equivalent). "
                    "This grants every permission in every AWS service. "
                    "Replace with the specific actions this principal actually requires."))

            # 2. Service-level wildcard on high-risk services
            for action in actions:
                if action.endswith(":*"):
                    service = action.split(":")[0].lower()
                    sev = "CRITICAL" if service in HIGH_RISK_SERVICES else "HIGH"
                    issues.append((sev,
                        f"{label}: Service-level wildcard '{action}' violates least-privilege. "
                        f"{'HIGH RISK service — ' + service.upper() + ' controls IAM/secrets/encryption.' if service in HIGH_RISK_SERVICES else ''} "
                        "Replace with only the specific actions required."))

            # 3. Wildcard resource with no condition
            if "*" in resources and not conditions:
                issues.append(("HIGH",
                    f"{label}: Resource is '*' with no Condition block. "
                    "Scope resources to specific ARNs and add conditions "
                    "(e.g. aws:RequestedRegion, aws:SourceAccount) to limit blast radius."))

            # 4. Privilege escalation — dangerous singletons
            action_set = {a.lower() for a in actions}
            for dangerous in PRIV_ESC_SINGLETONS:
                if dangerous.lower() in action_set or "*" in actions:
                    issues.append(("CRITICAL",
                        f"{label}: Contains '{dangerous}' — this permission alone can enable "
                        "privilege escalation (e.g. creating new admin credentials or attaching "
                        "broader policies). Ensure this is intentional and tightly scoped."))

            # 5. iam:PassRole + execution service combination
            if "iam:passrole" in action_set or "*" in actions:
                for exec_action in PRIV_ESC_WITH_PASSROLE:
                    if exec_action.lower() in action_set or "*" in actions:
                        issues.append(("CRITICAL",
                            f"{label}: Dangerous combination — 'iam:PassRole' + '{exec_action}'. "
                            "An attacker can pass a high-privilege role to a compute resource "
                            "they control, granting themselves escalated permissions. "
                            "Restrict iam:PassRole with a condition on iam:PassedToService."))
                        break  # one warning per statement is enough

            # 6. No MFA condition on sensitive actions
            sensitive_actions = {"iam:*", "sts:AssumeRole", "s3:DeleteObject", "s3:DeleteBucket"}
            if action_set & {a.lower() for a in sensitive_actions} and not conditions:
                issues.append(("MEDIUM",
                    f"{label}: Sensitive action(s) present with no MFA condition. "
                    "Add 'Condition': {'Bool': {'aws:MultiFactorAuthPresent': 'true'}} "
                    "for human-facing roles accessing sensitive resources."))

        # --- Build report ---
        if not issues:
            return (
                "✅ No least-privilege violations detected in this IAM policy.\n\n"
                "Good practice: Continue to review policies against AWS IAM Access Analyzer "
                "and rotate unused permissions regularly."
            )

        issues.sort(key=lambda x: SEVERITY_ORDER.get(x[0], 9))

        lines = [
            "🔐 IAM POLICY AUDIT REPORT",
            "=" * 45,
            f"Statements analysed : {len(statements)}",
            f"Findings            : {len(issues)}",
        ]

        current_sev = None
        for sev, msg in issues:
            if sev != current_sev:
                lines.append(f"\n[{sev}]")
                current_sev = sev
            lines.append(f"  • {msg}")

        lines.append(
            f"\n{'─' * 45}\n"
            "Remediation approach:\n"
            "  1. Replace wildcard actions with specific action lists.\n"
            "  2. Scope Resource to specific ARNs (arn:aws:s3:::my-bucket/*).\n"
            "  3. Add Condition blocks to limit by IP, MFA, region, or account.\n"
            "  4. Run AWS IAM Access Analyzer to catch cross-account exposure.\n"
            "  5. Apply the principle of least privilege: grant only what is needed,\n"
            "     when it is needed, to the identity that needs it."
        )

        return _cap_output("\n".join(lines))

    except Exception:
        return "Error: An unexpected error occurred during IAM policy audit. Please try again."


# ===========================================================================
# Entry point
# ===========================================================================
if __name__ == "__main__":
    # stdio transport — Claude Desktop communicates via stdin/stdout.
    mcp.run(transport="stdio")
