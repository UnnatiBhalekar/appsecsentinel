# AppSecSentinel

**Live demo:** https://x05wq6yn5c.execute-api.us-east-1.amazonaws.com

**Walkthrough:** https://sentinel-security-story.lovable.app/

A static analysis tool for detecting OWASP Top 10 vulnerabilities. It runs as an MCP server (Claude integration), a REST API deployable to AWS Lambda, and a standalone CLI that produces SARIF output for CI/CD security gates.

---

## What it detects

12 regex rules cover SQL injection, command injection, XSS sinks, weak hashing (MD5/SHA-1), insecure ciphers (DES/RC4/AES-ECB), unsafe deserialisation (pickle/yaml/ObjectInputStream), path traversal, XXE, hardcoded secrets, and insecure randomness.

For Python code, an AST scanner runs first and handles variable indirection — it resolves tainted variables through assignments, f-strings, `%`-formatting, and `.format()` calls. When the AST fires for a rule, the corresponding regex rule is skipped to prevent duplicate findings.

OWASP categories covered: A01 Broken Access Control, A02 Cryptographic Failures, A03 Injection, A05 Security Misconfiguration, A08 Insecure Deserialisation.

---

## Accuracy

Measured on a labelled test suite of 54 cases (39 easy, 15 hard). All cases were written by hand for this project; real-world accuracy will be lower.

**Easy set** (straightforward patterns, single-function snippets):

| Stage | Precision | Recall |
|---|---|---|
| Regex-only baseline | 92.3% | 96.0% |
| AST + regex (current) | 100% | 96.0% |

**Hard set** (variable indirection, aliased calls, multi-step taint):

| Stage | Precision | Recall |
|---|---|---|
| Regex-only baseline | 66.7% | 57.1% |
| AST + regex (current) | 100% | 100% |

**Combined:**

| Stage | Precision | Recall |
|---|---|---|
| Regex-only baseline | 87.5% | 87.5% |
| AST + regex (current) | 100% | 96.9% |

The one remaining false negative is `sql_fstring_inline`: the snippet constructs a tainted SQL string but does not call `execute()`, so the AST correctly does not flag it as an injection site. The quality gate enforces precision ≥ 0.95 and recall ≥ 0.90 on every CI run.

---

## Architecture

```
server.py          — MCP server (FastMCP, stdio transport)
api/app.py         — FastAPI application
api/lambda_handler.py — Mangum ASGI adapter for AWS Lambda
sentinel_cli.py    — CLI with SARIF output
core/
  scanner.py       — regex rules + AST dispatch
  python_ast_scanner.py — AST scanner (Python only)
  jwt_inspector.py — JWT analysis
  iam_auditor.py   — IAM policy audit
  guardrails.py    — input validation, output capping, audit logging
  models.py        — shared Finding type
ui/
  index.html       — single-page interface
  app.js           — fetch calls, textContent rendering
tests/
  test_quality.py  — precision/recall gate
  test_api.py      — API endpoint tests (13)
  test_cli.py      — CLI exit codes and SARIF structure (6)
  test_guardrails.py — audit log stream/file modes (7)
.github/
  workflows/security-gate.yml — runs on every PR and push to main
  workflows/demo-gate.yml     — manual workflow; expected to fail on demo/
  dependabot.yml              — weekly SHA-pin updates for Actions
```

---

## Three interfaces

### MCP server

Runs over stdio. Exposes three tools to Claude:

- `scan_owasp_vulnerabilities(code, language)` — returns a text report of findings
- `analyze_jwt_token(token)` — checks algorithm, expiry, lifetime, and privileged claims
- `audit_iam_policy(policy_json)` — checks for wildcard actions, missing MFA conditions, and privilege escalation paths

Start the server:

```bash
poetry run python server.py
```

Claude Desktop configuration (`~/Library/Application Support/Claude/claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "AppSecSentinel": {
      "command": "/Users/<your-username>/Library/Caches/pypoetry/virtualenvs/<env-name>/bin/python",
      "args": ["/Users/<your-username>/MCP Project/server.py"]
    }
  }
}
```

Get the exact Python path with `poetry env info --executable` inside the project directory.

### REST API

```bash
poetry run uvicorn api.app:app --reload
```

Endpoints:

| Method | Path | Body field | Description |
|---|---|---|---|
| POST | `/api/scan` | `code`, `language` | OWASP scan |
| POST | `/api/jwt` | `token` | JWT analysis |
| POST | `/api/iam` | `policy_json` | IAM policy audit |
| GET | `/api/health` | — | Health check |
| GET | `/` | — | Serves `ui/index.html` |

Input larger than 10,000 characters returns 413. Injection phrases in the input return 400. All responses set `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, and a restrictive `Content-Security-Policy`. CORS is restricted to the origin in `ALLOWED_ORIGIN` (default: `http://localhost:8000`).

The web UI is at `http://localhost:8000` after starting the server. It has three tabs (Scan, JWT, IAM). All findings are rendered with `textContent`; no `innerHTML` is used.

### CLI

```bash
# Scan one or more paths
poetry run python sentinel_cli.py scan core/ api/ server.py sentinel_cli.py

# Text output (default)
poetry run python sentinel_cli.py scan demo/

# SARIF output, fail CI on CRITICAL findings
poetry run python sentinel_cli.py scan core/ --format sarif --fail-on CRITICAL > results.sarif

# Exclude paths containing a fragment
poetry run python sentinel_cli.py scan . --exclude python_ast_scanner.py --exclude core/scanner.py
```

Exit codes: 0 = no findings at or above the threshold, 1 = findings found, 2 = usage error.

`--fail-on` accepts: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`.

---

## AWS Lambda deployment

The function runs on arm64 with Python 3.13. Install dependencies for that platform before packaging:

```bash
pip install -r requirements-deploy.txt \
  --target build \
  --platform manylinux2014_aarch64 \
  --python-version 3.13 \
  --only-binary=:all: \
  --implementation cp
cp -r core api ui build/
cd build && zip -r ../appsentinel.zip .
```

Handler: `api.lambda_handler.handler`. Set `ALLOWED_ORIGIN` to your frontend's origin.

The audit log writes to stdout when `AWS_LAMBDA_FUNCTION_NAME` is set (for CloudWatch), and to a local file otherwise. Each log line is a JSON object: `{"timestamp", "tool", "input_length", "input_sha256"}`. Raw input is never logged.

### Deployment

- **API Gateway:** HTTP API with throttling — default route rate 5 req/s, burst 10.
- **Lambda:** arm64, Python 3.13, basic execution role that allows only `logs:CreateLogGroup`, `logs:CreateLogStream`, and `logs:PutLogEvents`.
- **Logs:** CloudWatch log group `/aws/lambda/<function-name>`.

---

## CI/CD security gate

The `security-gate` workflow runs on every PR and push to `main`. It:

1. Runs the full test suite (`pytest tests/ -v`)
2. Self-scans the project source with `--fail-on CRITICAL` (`python_ast_scanner.py` and `core/scanner.py` are excluded because they contain the literal pattern strings the scanner searches for)
3. Uploads SARIF to GitHub code scanning

All three Actions are pinned to full commit SHAs. Dependabot opens a PR every Monday when a newer SHA is available.

The `demo-gate` workflow is triggered manually. It scans `demo/vulnerable_example.py`, which contains three intentionally vulnerable snippets, and is expected to fail.

---

## Security guardrails

All inputs are validated before reaching the scanner.

| Guardrail | Value |
|---|---|
| Max input length | 10,000 characters |
| Max output length | 5,000 characters |
| Injection phrase check | Phrase list; returns 400 on match |
| Audit log content | Timestamp, tool name, input length, SHA-256 of first 200 chars — never raw input |
| HTTP security headers | `X-Content-Type-Options`, `X-Frame-Options`, `Content-Security-Policy` |
| CORS | Restricted to `ALLOWED_ORIGIN` env var |
| UI rendering | `textContent` only — no `innerHTML` |
| SARIF Actions | SHA-pinned; Dependabot updates weekly |

---

## Known limitations

- The AST scanner covers Python only. Non-Python code uses regex rules exclusively.
- The injection filter is a phrase list, not semantic analysis. Obfuscated input may bypass it.
- JWT analysis does not verify the token's signature. It only inspects the header and claims.
- The self-scan excludes `python_ast_scanner.py` and `core/scanner.py` to avoid false positives from the tool's own pattern strings.
- The audit log is appended to, but not tamper-proof. It records what was scanned, not whether findings were acted on.
- No authentication is implemented on the API.

---

## Running the tests

```bash
poetry install --with dev
poetry run pytest tests/ -v
```

27 tests total: 13 API, 6 CLI, 7 guardrails, 1 quality gate.

---

## Setup

```bash
git clone <repo-url>
cd "MCP Project"
poetry install
poetry run uvicorn api.app:app --reload   # API + UI
poetry run python server.py               # MCP server
```

Python 3.13. Dependencies managed with Poetry.

<!-- TODO: Add demo recording URL once captured -->
<!-- TODO: Add screenshots to docs/screenshots/ and link them here -->
