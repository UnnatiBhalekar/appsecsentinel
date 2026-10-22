"""
AppSecSentinel MCP Server
==========================
A FastMCP server that gives an AI agent controlled, audited access to three
core application-security tools.

TOOLS:
  1. scan_owasp_vulnerabilities(code, language)
       SAST-style scanner for OWASP Top 10 vulnerability patterns.

  2. analyze_jwt_token(token)
       Decodes and inspects a JWT for security weaknesses.

  3. audit_iam_policy(policy_json)
       Parses an AWS IAM policy and flags least-privilege violations.

SECURITY FEATURES (applied to every tool call):
  1. Input length validation   — rejects inputs over 10,000 characters
  2. Prompt injection detection — blocks manipulation patterns
  3. Audit logging             — SHA-256-hashed trail to disk (never raw input)
  4. Safe error handling       — never leaks internals to the agent
  5. Output length capping     — truncates responses over 5,000 characters
"""

from mcp.server.fastmcp import FastMCP

from core.guardrails  import validate_input, write_audit_log, hash_input, cap_output
from core.scanner     import scan_code, format_findings
from core.jwt_inspector import inspect_jwt, format_jwt_report, JWTError
from core.iam_auditor  import audit_policy, format_iam_report, PolicyError

mcp = FastMCP("AppSecSentinel")


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
    error = validate_input(code, "scan_owasp_vulnerabilities")
    if error:
        return error

    write_audit_log("scan_owasp_vulnerabilities", hash_input(code))

    try:
        findings = scan_code(code, language)
        return cap_output(format_findings(findings, language))
    except Exception:
        return "Error: An unexpected error occurred during the vulnerability scan. Please try again."


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

    error = validate_input(token, "analyze_jwt_token")
    if error:
        return error

    write_audit_log("analyze_jwt_token", hash_input(token))

    try:
        findings, metadata = inspect_jwt(token)
        return cap_output(format_jwt_report(findings, metadata))
    except JWTError as exc:
        return str(exc)
    except Exception:
        return "Error: An unexpected error occurred during JWT analysis. Please try again."


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
    error = validate_input(policy_json, "audit_iam_policy")
    if error:
        return error

    write_audit_log("audit_iam_policy", hash_input(policy_json))

    try:
        findings, metadata = audit_policy(policy_json)
        return cap_output(format_iam_report(findings, metadata))
    except PolicyError as exc:
        return str(exc)
    except Exception:
        return "Error: An unexpected error occurred during IAM policy audit. Please try again."


if __name__ == "__main__":
    mcp.run(transport="stdio")
