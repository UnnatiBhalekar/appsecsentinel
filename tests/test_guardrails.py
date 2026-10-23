"""
test_guardrails.py
------------------
Tests for core/guardrails.py audit-logging behaviour.

Two modes are tested in isolation:
  stream mode  — AWS_LAMBDA_FUNCTION_NAME is set → JSON lines to stdout
  file mode    — env-var absent                  → JSON lines to a log file

Each test resets the module-level handler state so the modes do not bleed
into each other within a single pytest run.
"""

import json
import logging
import os
import sys
import importlib
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _reset_handler(monkeypatch, lambda_name: str | None, log_file: Path | None = None):
    """
    Clear the audit logger's handlers and force the module to re-detect its mode
    on the next write_audit_log call.

    lambda_name — set AWS_LAMBDA_FUNCTION_NAME to this value (or unset if None)
    log_file    — if given, patch _LOG_FILE so file-mode writes here (not the real log)
    """
    import core.guardrails as grd

    # Remove every handler attached to the logger
    for h in list(grd._audit_logger.handlers):
        grd._audit_logger.removeHandler(h)
        h.close()

    # Force _ensure_handler() to re-attach on the next call
    grd._current_handler_mode = None

    if lambda_name is None:
        monkeypatch.delenv("AWS_LAMBDA_FUNCTION_NAME", raising=False)
    else:
        monkeypatch.setenv("AWS_LAMBDA_FUNCTION_NAME", lambda_name)

    if log_file is not None:
        monkeypatch.setattr(grd, "_LOG_FILE", log_file)


def _parse_json_line(line: str) -> dict:
    return json.loads(line.strip())


# ---------------------------------------------------------------------------
# Stream mode (Lambda)
# ---------------------------------------------------------------------------

def test_stream_mode_writes_to_stdout(monkeypatch, capsys):
    """When AWS_LAMBDA_FUNCTION_NAME is set, audit lines go to stdout as JSON."""
    _reset_handler(monkeypatch, lambda_name="my-lambda")

    from core.guardrails import write_audit_log, hash_input
    h = hash_input("hello")
    write_audit_log("test_tool", h, input_length=5)

    captured = capsys.readouterr()
    assert captured.out.strip(), "Expected a line on stdout"

    record = _parse_json_line(captured.out)
    assert record["tool"] == "test_tool"
    assert record["input_sha256"] == h
    assert record["input_length"] == 5
    assert "timestamp" in record


def test_stream_mode_never_logs_raw_input(monkeypatch, capsys):
    """The raw input string must not appear anywhere in the output."""
    _reset_handler(monkeypatch, lambda_name="my-lambda")

    secret = "super_secret_password_12345"
    from core.guardrails import write_audit_log, hash_input
    write_audit_log("test_tool", hash_input(secret), input_length=len(secret))

    captured = capsys.readouterr()
    assert secret not in captured.out


def test_stream_mode_outputs_valid_json_per_line(monkeypatch, capsys):
    """Every line emitted in stream mode must be parseable JSON."""
    _reset_handler(monkeypatch, lambda_name="my-lambda")

    from core.guardrails import write_audit_log, hash_input
    for i in range(3):
        write_audit_log(f"tool_{i}", hash_input(f"input_{i}"), input_length=i)

    lines = [l for l in capsys.readouterr().out.splitlines() if l.strip()]
    assert len(lines) == 3
    for line in lines:
        obj = _parse_json_line(line)
        assert "timestamp" in obj
        assert "tool" in obj
        assert "input_sha256" in obj
        assert "input_length" in obj


# ---------------------------------------------------------------------------
# File mode (local / MCP)
# ---------------------------------------------------------------------------

def test_file_mode_writes_to_log_file(monkeypatch, tmp_path):
    """Without AWS_LAMBDA_FUNCTION_NAME, audit lines are written to the log file."""
    log_file = tmp_path / "audit.log"
    _reset_handler(monkeypatch, lambda_name=None, log_file=log_file)

    from core.guardrails import write_audit_log, hash_input
    h = hash_input("hello")
    write_audit_log("file_tool", h, input_length=5)

    # Flush the handler so the line is on disk
    import core.guardrails as grd
    for handler in grd._audit_logger.handlers:
        handler.flush()

    assert log_file.exists(), "Log file was not created"
    lines = [l for l in log_file.read_text().splitlines() if l.strip()]
    assert len(lines) == 1

    record = _parse_json_line(lines[0])
    assert record["tool"] == "file_tool"
    assert record["input_sha256"] == h
    assert record["input_length"] == 5
    assert "timestamp" in record


def test_file_mode_never_logs_raw_input(monkeypatch, tmp_path):
    """The raw input must not appear in the log file."""
    log_file = tmp_path / "audit.log"
    _reset_handler(monkeypatch, lambda_name=None, log_file=log_file)

    secret = "super_secret_password_12345"
    from core.guardrails import write_audit_log, hash_input
    write_audit_log("file_tool", hash_input(secret), input_length=len(secret))

    import core.guardrails as grd
    for handler in grd._audit_logger.handlers:
        handler.flush()

    assert secret not in log_file.read_text()


def test_file_mode_outputs_valid_json_per_line(monkeypatch, tmp_path):
    """Every line in the log file must be parseable JSON."""
    log_file = tmp_path / "audit.log"
    _reset_handler(monkeypatch, lambda_name=None, log_file=log_file)

    from core.guardrails import write_audit_log, hash_input
    for i in range(3):
        write_audit_log(f"tool_{i}", hash_input(f"input_{i}"), input_length=i)

    import core.guardrails as grd
    for handler in grd._audit_logger.handlers:
        handler.flush()

    lines = [l for l in log_file.read_text().splitlines() if l.strip()]
    assert len(lines) == 3
    for line in lines:
        obj = _parse_json_line(line)
        assert "timestamp" in obj
        assert "tool" in obj


# ---------------------------------------------------------------------------
# Mode switching
# ---------------------------------------------------------------------------

def test_handler_switches_mode_when_env_var_changes(monkeypatch, tmp_path, capsys):
    """
    If the env-var changes between calls (e.g. during testing), the logger
    must switch to the new handler and not keep writing to the old one.
    """
    log_file = tmp_path / "audit.log"

    # Start in file mode
    _reset_handler(monkeypatch, lambda_name=None, log_file=log_file)
    from core.guardrails import write_audit_log, hash_input
    write_audit_log("file_call", hash_input("a"), input_length=1)

    # Switch to stream mode
    _reset_handler(monkeypatch, lambda_name="lambda-fn")
    write_audit_log("stream_call", hash_input("b"), input_length=1)

    import core.guardrails as grd
    for handler in grd._audit_logger.handlers:
        handler.flush()

    # File should have exactly one line (the file-mode call)
    file_lines = [l for l in log_file.read_text().splitlines() if l.strip()]
    assert len(file_lines) == 1
    assert _parse_json_line(file_lines[0])["tool"] == "file_call"

    # Stdout should have exactly one line (the stream-mode call)
    stdout_lines = [l for l in capsys.readouterr().out.splitlines() if l.strip()]
    assert len(stdout_lines) == 1
    assert _parse_json_line(stdout_lines[0])["tool"] == "stream_call"
