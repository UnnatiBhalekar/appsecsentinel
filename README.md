# SecuritySentinel MCP Server

A security-focused MCP (Model Context Protocol) server that gives Claude controlled,
audited access to three security tools:

1. **`scan_for_secrets`** — detects hardcoded credentials in code
2. **`analyze_failed_logins`** — flags suspicious IPs in auth logs
3. **`lookup_cve`** — fetches CVE details from the NIST NVD API

Every tool call is protected by five security layers: input length validation,
prompt injection detection, audit logging, safe error handling, and output capping.

---

## Prerequisites

- Python 3.11 or newer
- [Poetry](https://python-poetry.org/) (dependency manager)
- Claude Desktop app installed

---

## Setup

### Step 1 — Install Poetry (if not already installed)

```bash
curl -sSL https://install.python-poetry.org | python3 -
```

Then add Poetry to your PATH (add this line to `~/.zshrc` or `~/.bashrc`):

```bash
export PATH="/Users/YOUR_USERNAME/.local/bin:$PATH"
```

Reload your shell:

```bash
source ~/.zshrc   # or source ~/.bashrc
```

### Step 2 — Install dependencies

```bash
cd "/Users/unnatibhalekar/MCP Project"
poetry install
```

This creates an isolated virtual environment and installs `mcp` and `requests`.

### Step 3 — Verify the server starts

```bash
poetry run python server.py
```

The server will appear to hang (no output) — that is correct behaviour.
It is waiting for a stdio connection from Claude Desktop.
Press `Ctrl+C` to stop it.

---

## Connecting to Claude Desktop

### Step 4 — Find your Claude Desktop config file

| Platform | Path |
|----------|------|
| macOS    | `~/Library/Application Support/Claude/claude_desktop_config.json` |
| Windows  | `%APPDATA%\Claude\claude_desktop_config.json` |

### Step 5 — Get your Poetry Python path

Run this command to get the exact Python executable path for your virtual environment:

```bash
cd "/Users/unnatibhalekar/MCP Project" && poetry env info --executable
```

It will print something like:

```
/Users/unnatibhalekar/Library/Caches/pypoetry/virtualenvs/security-sentinel-XXXXXXXX-py3.13/bin/python
```

Copy that path — you need it in the next step.

### Step 6 — Edit claude_desktop_config.json

Open the config file and add the `mcpServers` block below.
Replace `/FULL/PATH/TO/PYTHON` with the path from Step 5,
and replace `/FULL/PATH/TO/server.py` with the absolute path to your `server.py`.

```json
{
  "mcpServers": {
    "SecuritySentinel": {
      "command": "/Users/unnatibhalekar/Library/Caches/pypoetry/virtualenvs/security-sentinel-8B2q6DWq-py3.13/bin/python",
      "args": ["/Users/unnatibhalekar/MCP Project/server.py"]
    }
  }
}
```

> **If you already have other MCP servers in the config**, add the `"SecuritySentinel"` entry
> inside the existing `"mcpServers"` object — don't create a second one.

### Step 7 — Restart Claude Desktop

Fully quit and reopen Claude Desktop (Cmd+Q on Mac, not just close the window).

### Step 8 — Verify the connection

In Claude Desktop, click the **tools icon** (hammer/wrench) in the bottom-left of the
chat input box. You should see three tools listed:

- `scan_for_secrets`
- `analyze_failed_logins`
- `lookup_cve`

If you don't see them, check the [Troubleshooting](#troubleshooting) section below.

---

## Testing Each Tool

### Test scan_for_secrets

Type this to Claude Desktop:

> "Use the scan_for_secrets tool to check this text:
> `AWS_KEY = "AKIAIOSFODNN7EXAMPLE"` and `password = "hunter2"`"

**Expected:** A warning listing AWS Access Key and Password matches.

---

### Test analyze_failed_logins

Open `sample_logs.txt` in this folder, copy all the text, then say to Claude:

> "Use analyze_failed_logins to check this log content: [paste the log here]"

**Expected:** A list of suspicious IPs sorted by failure count.

---

### Test lookup_cve

> "Use lookup_cve to look up CVE-2021-44228"

**Expected:** Description of the Log4Shell vulnerability with a CVSS score of 10.0 (CRITICAL).

---

## Where the Audit Log Appears

Every tool call writes a line to:

```
/Users/unnatibhalekar/MCP Project/security_sentinel_audit.log
```

The file is created automatically on the first tool call.
Each line looks like:

```
[2024-06-01T10:23:45.123456Z] tool=scan_for_secrets input_sha256=a3f1c9...
```

Raw inputs are **never** logged — only a SHA-256 hash of the first 200 characters.

---

## Troubleshooting

| Problem | Fix |
|---------|-----|
| Tools don't appear in Claude Desktop | Fully quit and restart (Cmd+Q). Check the JSON is valid (no trailing commas). |
| `command not found` error in Claude logs | Double-check the Python path from `poetry env info --executable`. |
| CVE lookup returns timeout | The NVD API is occasionally slow. Try again or check your internet connection. |
| `ModuleNotFoundError: mcp` | You ran `python server.py` directly instead of `poetry run python server.py`. |

To view Claude Desktop's MCP logs on macOS:

```bash
tail -f ~/Library/Logs/Claude/mcp-server-SecuritySentinel.log
```

---

## File Structure

```
MCP Project/
├── server.py                      # The MCP server — all tools and security logic
├── requirements.txt               # pip-compatible dependency list
├── pyproject.toml                 # Poetry project file (auto-generated)
├── sample_logs.txt                # Realistic fake auth log for testing
├── test_inputs.md                 # Sample inputs for every tool
├── README.md                      # This file
└── security_sentinel_audit.log   # Created automatically on first tool call
```
