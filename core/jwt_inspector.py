"""
core/jwt_inspector.py
---------------------
Decode and inspect a JWT (JSON Web Token) for security weaknesses.
Does NOT verify the signature — this is an inspector, not a validator.

Returns structured Finding objects so callers (server.py, sentinel_cli.py)
can process results programmatically before formatting them as text.
"""

import json
import base64
from datetime import datetime, timezone
from .models import Finding, SEVERITY_ORDER


class JWTError(Exception):
    """Raised when the token is structurally invalid."""


# Algorithms that should not be used in production
_WEAK_ALGORITHMS: set[str] = {"none", "hs256", "hs384", "hs512"}


def _b64url_decode(segment: str) -> bytes:
    """Base64url decode with automatic padding correction (JWTs omit '=')."""
    padding = 4 - len(segment) % 4
    if padding != 4:
        segment += "=" * padding
    return base64.urlsafe_b64decode(segment)


def inspect_jwt(token: str) -> tuple[list[Finding], dict]:
    """
    Parse a JWT and return (findings, metadata).

    metadata keys:
      header             — decoded header dict
      payload            — decoded payload dict (secrets redacted)
      signature_present  — True if the third segment is non-empty
      notes              — list of informational strings (no issue found)

    Raises JWTError when the token cannot be decoded.
    """
    parts = token.split(".")
    if len(parts) != 3:
        raise JWTError(
            "Error: Invalid JWT format. "
            "A JWT must have exactly 3 dot-separated parts: header.payload.signature"
        )

    try:
        header: dict  = json.loads(_b64url_decode(parts[0]))
        payload: dict = json.loads(_b64url_decode(parts[1]))
    except Exception:
        raise JWTError(
            "Error: Could not decode JWT segments. "
            "Ensure the token is a valid base64url-encoded JWT."
        )

    issues:  list[tuple[str, str, str]] = []  # (rule_id, severity, message)
    notes:   list[str]                  = []

    # --- Algorithm check ---
    alg = header.get("alg", "MISSING")
    if alg == "none":
        issues.append(("JWT-001", "CRITICAL",
            "Algorithm is 'none' — signature verification is completely disabled. "
            "Any payload can be forged without a secret key."))
    elif alg == "MISSING":
        issues.append(("JWT-001", "CRITICAL",
            "No 'alg' field in JWT header — algorithm is undefined. "
            "The token cannot be cryptographically verified and should be rejected."))
    elif alg.upper().startswith("HS"):
        issues.append(("JWT-002", "HIGH",
            f"Algorithm '{alg}' uses a symmetric (shared) secret. "
            "If the secret leaks, any party can forge tokens. "
            "Prefer RS256/ES256 (asymmetric) for distributed systems."))
    else:
        notes.append(f"Algorithm '{alg}' — asymmetric, acceptable for production.")

    # --- Claim checks ---
    now = datetime.now(timezone.utc).timestamp()

    if "exp" not in payload:
        issues.append(("JWT-003", "HIGH",
            "Missing 'exp' (expiry) claim — token never expires. "
            "A stolen token grants permanent access."))
    else:
        exp = payload["exp"]
        if exp < now:
            issues.append(("JWT-003", "HIGH",
                f"Token is EXPIRED (exp={exp}, now={int(now)}, "
                f"expired {int(now - exp)}s ago). "
                "Accepting this token is an authentication bypass."))
        else:
            lifetime_hrs = (exp - now) / 3600
            if lifetime_hrs > 24:
                issues.append(("JWT-004", "MEDIUM",
                    f"Token lifetime is {lifetime_hrs:.1f} hours — unusually long. "
                    "Prefer short-lived tokens (≤1h) with refresh token rotation."))
            else:
                notes.append(f"Expiry: valid for {lifetime_hrs:.1f} more hours.")

    if "iat" not in payload:
        issues.append(("JWT-005", "LOW",
            "Missing 'iat' (issued-at) claim — makes replay-attack detection harder."))

    if "aud" not in payload:
        issues.append(("JWT-006", "MEDIUM",
            "Missing 'aud' (audience) claim — token could be accepted by unintended services."))

    if "iss" not in payload:
        issues.append(("JWT-007", "LOW",
            "Missing 'iss' (issuer) claim — origin of the token cannot be verified."))

    # --- Scope / privilege checks ---
    scope = payload.get("scope", payload.get("scp", ""))
    if isinstance(scope, str) and scope:
        scope_list = scope.split()
        if len(scope_list) > 8:
            issues.append(("JWT-008", "MEDIUM",
                f"Token carries {len(scope_list)} scopes — potentially over-permissioned. "
                "Apply least-privilege: grant only the scopes the service actually needs."))

    admin_fields = [k for k in payload if "admin" in k.lower() or "root" in k.lower()]
    for field in admin_fields:
        if payload[field] in (True, "true", 1, "admin"):
            issues.append(("JWT-009", "HIGH",
                f"Privileged claim detected: '{field}' = {payload[field]}. "
                "Verify this is intentional and that the field is validated server-side."))

    # Convert to Finding objects
    findings = [
        Finding(rule_id=rid, severity=sev, owasp_category="A02 Cryptographic Failures",
                message=msg, line_number=0)
        for rid, sev, msg in sorted(issues, key=lambda x: SEVERITY_ORDER.get(x[1], 9))
    ]

    # Redact sensitive-sounding keys in payload before surfacing to caller
    safe_payload = {
        k: ("[REDACTED]"
            if any(s in k.lower() for s in ("secret", "key", "pass", "token"))
            else v)
        for k, v in payload.items()
    }

    metadata = {
        "header": header,
        "payload": safe_payload,
        "signature_present": bool(parts[2]),
        "notes": notes,
    }

    return findings, metadata


def format_jwt_report(findings: list[Finding], metadata: dict) -> str:
    """Render JWT inspection results as a human-readable text report."""
    lines = ["🔍 JWT SECURITY ANALYSIS", "=" * 40]
    lines.append(f"\nHeader:  {json.dumps(metadata['header'])}")
    lines.append(f"Payload: {json.dumps(metadata['payload'])}")
    sig_note = (
        "Yes" if metadata["signature_present"]
        else "No (empty — possible none-alg attack)"
    )
    lines.append(f"Signature segment present: {sig_note}")

    if findings:
        lines.append(f"\n⚠️  FINDINGS ({len(findings)}):")
        current_sev = None
        for f in findings:
            if f.severity != current_sev:
                lines.append(f"\n  [{f.severity}]")
                current_sev = f.severity
            lines.append(f"    • {f.message}")
    else:
        lines.append("\n✅ No security issues found in token structure.")

    if metadata["notes"]:
        lines.append("\nℹ️  Notes:")
        for note in metadata["notes"]:
            lines.append(f"  • {note}")

    lines.append(
        "\n\nNote: This tool inspects token design only. "
        "It does NOT verify the signature — use your identity provider's "
        "JWKS endpoint for full cryptographic validation."
    )

    return "\n".join(lines)
