"""
core/guardrails.py
------------------
Security plumbing applied to every tool call:
  1. Input length validation  — reject oversized payloads
  2. Prompt injection detection — refuse manipulation phrases
  3. Input hashing             — SHA-256 fingerprint for audit trail
  4. Audit logging             — one JSON line per call, never raw input
  5. Output capping            — prevent large data-exfiltration responses

Logging destination (chosen at each call, not at import):
  AWS Lambda  (AWS_LAMBDA_FUNCTION_NAME is set) → stdout via StreamHandler
  Local / MCP (env-var absent)                  → file next to the project root
"""

import json
import logging
import os
import re
import hashlib
import pathlib
import sys
from datetime import datetime, timezone

_PROJECT_ROOT = pathlib.Path(__file__).parent.parent.resolve()
_LOG_FILE     = _PROJECT_ROOT / "appsec_sentinel_audit.log"

MAX_INPUT_LENGTH  = 10_000
MAX_OUTPUT_LENGTH = 5_000

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
# Audit logger — handler is chosen lazily so tests can control it via env-var
# ---------------------------------------------------------------------------
_audit_logger = logging.getLogger("appsec_audit")
_audit_logger.setLevel(logging.INFO)
_audit_logger.propagate = False

# Track which handler mode is currently attached so we swap only when needed.
_current_handler_mode: str | None = None  # "stream" | "file" | None


def _ensure_handler() -> None:
    """
    Attach the right handler for the current environment.
    Called on every write so tests can switch modes by changing os.environ.
    """
    global _current_handler_mode

    mode = "stream" if os.environ.get("AWS_LAMBDA_FUNCTION_NAME") else "file"
    if mode == _current_handler_mode:
        return  # already correct — nothing to do

    # Remove whatever handler is attached now
    for h in list(_audit_logger.handlers):
        _audit_logger.removeHandler(h)
        h.close()

    fmt = logging.Formatter("%(message)s")

    if mode == "stream":
        handler = logging.StreamHandler(sys.stdout)
    else:
        handler = logging.FileHandler(_LOG_FILE)

    handler.setFormatter(fmt)
    _audit_logger.addHandler(handler)
    _current_handler_mode = mode


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def hash_input(text: str) -> str:
    """SHA-256 of the first 200 characters — forensic fingerprint, no raw data."""
    return hashlib.sha256(text[:200].encode()).hexdigest()


def write_audit_log(tool_name: str, input_hash: str, input_length: int = 0) -> None:
    """
    Emit one JSON audit line.  Never logs raw input.

    JSON keys: timestamp, tool, input_length, input_sha256
    """
    _ensure_handler()
    record = {
        "timestamp":    datetime.now(timezone.utc).isoformat(),
        "tool":         tool_name,
        "input_length": input_length,
        "input_sha256": input_hash,
    }
    _audit_logger.info(json.dumps(record))


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
            write_audit_log(
                tool_name + "_INJECTION_ATTEMPT",
                hash_input(text),
                len(text),
            )
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
