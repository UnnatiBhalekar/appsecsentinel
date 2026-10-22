"""
test_cli.py
-----------
Tests for sentinel_cli.py.

Each test writes a temporary .py file, calls main() directly (no subprocess),
and checks the returned exit code and/or the output format.
"""

import json
import sys
import os
import tempfile
from pathlib import Path

# Allow importing from the project root without installing as a package
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sentinel_cli import main


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _write_temp_py(code: str) -> Path:
    """Write code to a temporary .py file and return its Path."""
    tmp = tempfile.NamedTemporaryFile(suffix=".py", delete=False, mode="w")
    tmp.write(code)
    tmp.close()
    return Path(tmp.name)


# ---------------------------------------------------------------------------
# Exit-code tests
# ---------------------------------------------------------------------------

def test_exit_0_on_clean_code():
    """A file with no vulnerabilities should exit 0 even with --fail-on CRITICAL."""
    safe = "def greet(name):\n    return f'Hello, {name}'\n"
    path = _write_temp_py(safe)
    try:
        code = main(["scan", str(path), "--fail-on", "CRITICAL"])
        assert code == 0, f"Expected exit 0 for clean code, got {code}"
    finally:
        path.unlink(missing_ok=True)


def test_exit_1_on_critical():
    """A file with a critical vulnerability should exit 1 when --fail-on CRITICAL."""
    dangerous = "import os\nos.system(user_cmd)\n"
    path = _write_temp_py(dangerous)
    try:
        code = main(["scan", str(path), "--fail-on", "CRITICAL"])
        assert code == 1, f"Expected exit 1 for CRITICAL finding, got {code}"
    finally:
        path.unlink(missing_ok=True)


def test_fail_on_none_always_exits_0():
    """--fail-on NONE must always exit 0, even for critical vulnerabilities."""
    dangerous = "import os\nos.system(user_cmd)\n"
    path = _write_temp_py(dangerous)
    try:
        code = main(["scan", str(path), "--fail-on", "NONE"])
        assert code == 0, f"Expected exit 0 with --fail-on NONE, got {code}"
    finally:
        path.unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# SARIF structure test
# ---------------------------------------------------------------------------

def test_sarif_structure(capsys):
    """SARIF output must be valid 2.1.0 with the required top-level fields."""
    dangerous = "import os\nos.system(user_cmd)\n"
    path = _write_temp_py(dangerous)
    try:
        main(["scan", str(path), "--format", "sarif"])
        captured = capsys.readouterr().out
        doc = json.loads(captured)

        assert doc["version"] == "2.1.0", "SARIF version must be '2.1.0'"
        assert "$schema" in doc, "SARIF must have a $schema field"
        assert "runs" in doc and len(doc["runs"]) == 1, "SARIF must have exactly one run"

        run = doc["runs"][0]
        assert run["tool"]["driver"]["name"] == "AppSecSentinel"
        assert "results" in run, "Run must contain a results array"

        # At least one result — file has os.system with a variable arg
        assert len(run["results"]) >= 1, "Expected at least one finding"

        # Check required fields on the first result
        result = run["results"][0]
        assert "ruleId" in result
        assert result["level"] in ("error", "warning", "note")
        assert "message" in result and "text" in result["message"]
        assert "locations" in result and len(result["locations"]) >= 1

        loc = result["locations"][0]["physicalLocation"]
        assert "artifactLocation" in loc
        assert "uri" in loc["artifactLocation"]
        assert "region" in loc and "startLine" in loc["region"]
    finally:
        path.unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# Run directly for quick manual checks
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import pytest
    sys.exit(pytest.main([__file__, "-v"]))
