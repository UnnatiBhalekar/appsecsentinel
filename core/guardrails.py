"""
core/guardrails.py
------------------
Security plumbing applied to every tool call:
  1. Input length validation  — reject oversized payloads
  2. Prompt injection detection — refuse manipulation phrases
  3. Input hashing             — SHA-256 fingerprint for audit trail
  4. Audit logging             — timestamped, hashed-only log to disk
  5. Output capping            — prevent large data-exfiltration responses

Nothing in this file touches business logic; it only enforces the security
boundary around tool inputs and outputs.
"""

import re
import hashlib
import logging
import pathlib
from datetime import datetime, timezone

# Resolve the project root from this file's location so the audit log always
# lands next to the project files, regardless of what cwd the launcher uses.
_PROJECT_ROOT = pathlib.Path(__file__).parent.parent.resolve()

MAX_INPUT_LENGTH  = 10_000   # characters — prevents memory exhaustion
MAX_OUTPUT_LENGTH = 5_000    # characters — caps data exfiltration via output

# Phrases that indicate an attempt to override the AI's behaviour via injected
# text inside a code snippet, policy document, or token.
_INJECTION_PATTERNS: list[str] = [
    r"ignore.*instructions",
    r"you are now",
    r"disregard",
    r"forget.*instructions",
    r"new instructions:",
    r"system prompt:",
    r"act as",
]

# ---------------------------------------------------------------------------
# Audit logger — writes to project root, never raw input
# ---------------------------------------------------------------------------
_audit_logger = logging.getLogger("appsec_audit")
_audit_logger.setLevel(logging.INFO)
_audit_logger.propagate = False  # don't bubble up to root logger

if not _audit_logger.handlers:
    _handler = logging.FileHandler(_PROJECT_ROOT / "appsec_sentinel_audit.log")
    _handler.setFormatter(logging.Formatter("%(message)s"))
    _audit_logger.addHandler(_handler)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def hash_input(text: str) -> str:
    """
    SHA-256 of the first 200 characters of text.
    Gives a forensic fingerprint without storing sensitive content.
    """
    return hashlib.sha256(text[:200].encode()).hexdigest()


def write_audit_log(tool_name: str, input_hash: str) -> None:
    """Append one tamper-evident audit entry: timestamp, tool name, input hash."""
    ts = datetime.now(timezone.utc).isoformat()
    _audit_logger.info(f"[{ts}] tool={tool_name} input_sha256={input_hash}")


def validate_input(text: str, tool_name: str) -> str | None:
    """
    Run length check and prompt-injection scan.
    Returns an error string if the input should be rejected, None if it is safe.
    """
    if len(text) > MAX_INPUT_LENGTH:
        return (
            f"Error: Input exceeds the {MAX_INPUT_LENGTH:,}-character limit. "
            "Please provide a shorter input."
        )

    lower = text.lower()
    for pattern in _INJECTION_PATTERNS:
        if re.search(pattern, lower):
            write_audit_log(tool_name + "_INJECTION_ATTEMPT", hash_input(text))
            return (
                "Error: Input contains a pattern associated with prompt injection. "
                "Request refused for security reasons."
            )

    return None  # input is safe


def cap_output(text: str) -> str:
    """Truncate output to MAX_OUTPUT_LENGTH to prevent data-exfiltration via tool response."""
    if len(text) > MAX_OUTPUT_LENGTH:
        return text[:MAX_OUTPUT_LENGTH] + "\n\n[Output truncated for safety]"
    return text
