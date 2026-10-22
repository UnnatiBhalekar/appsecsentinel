"""
api/app.py
----------
FastAPI web application wrapping the AppSecSentinel core/ scanners.

Endpoints:
  POST /api/scan     — OWASP Top 10 code scanner
  POST /api/jwt      — JWT security inspector
  POST /api/iam      — IAM policy auditor
  GET  /api/health   — liveness probe

Security controls on every request:
  - Input length capped at MAX_INPUT_CHARS; oversized input → 413
  - Prompt injection phrases → 400 with a generic message
  - Audit log: tool name, input length, SHA-256 hash only (never raw input)
  - Security headers on every response (CSP, X-Frame-Options, etc.)
  - CORS restricted to ALLOWED_ORIGIN env-var (defaults to localhost)
  - Generic error messages only — no stack traces in responses
"""

import logging
import os
from datetime import datetime, timezone

from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, field_validator

# ---------------------------------------------------------------------------
# sys.path bootstrap so this module can be run from any working directory
# ---------------------------------------------------------------------------
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

_UI_DIR = Path(__file__).parent.parent / "ui"

from core.scanner      import scan_code, format_findings
from core.jwt_inspector import inspect_jwt, format_jwt_report, JWTError
from core.iam_auditor   import audit_policy, format_iam_report, PolicyError
from core.guardrails    import hash_input, write_audit_log

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
MAX_INPUT_CHARS: int = 10_000
ALLOWED_ORIGIN: str  = os.environ.get("ALLOWED_ORIGIN", "http://localhost:8000")

# ---------------------------------------------------------------------------
# Logging — structured, no raw inputs ever
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s — %(message)s",
)
logger = logging.getLogger("api")

# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------
app = FastAPI(
    title="AppSecSentinel API",
    description="OWASP scanner, JWT inspector, IAM auditor",
    version="1.0.0",
    # Disable default /docs and /redoc in production would go here;
    # keeping them enabled for development convenience.
)

# Serve the UI at / (static files must be mounted before routes)
if _UI_DIR.exists():
    app.mount("/ui", StaticFiles(directory=str(_UI_DIR)), name="ui")

    @app.get("/", include_in_schema=False)
    async def serve_ui():
        return FileResponse(str(_UI_DIR / "index.html"))


# CORS — only the configured origin may call this API from a browser
app.add_middleware(
    CORSMiddleware,
    allow_origins=[ALLOWED_ORIGIN],
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)


# ---------------------------------------------------------------------------
# Security headers middleware
# ---------------------------------------------------------------------------
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response: Response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    # CSP: only scripts from the same origin; no inline scripts, no eval
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
        "object-src 'none'; frame-ancestors 'none';"
    )
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response


# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------
class ScanRequest(BaseModel):
    code: str
    language: str = "generic"

    @field_validator("code")
    @classmethod
    def code_length(cls, v: str) -> str:
        if len(v) > MAX_INPUT_CHARS:
            raise ValueError("oversized")
        return v


class JWTRequest(BaseModel):
    token: str

    @field_validator("token")
    @classmethod
    def token_length(cls, v: str) -> str:
        if len(v) > MAX_INPUT_CHARS:
            raise ValueError("oversized")
        return v


class IAMRequest(BaseModel):
    policy_json: str

    @field_validator("policy_json")
    @classmethod
    def policy_length(cls, v: str) -> str:
        if len(v) > MAX_INPUT_CHARS:
            raise ValueError("oversized")
        return v


# ---------------------------------------------------------------------------
# Validation error handler — turn Pydantic 413-worthy errors into 413 responses
# ---------------------------------------------------------------------------
from fastapi.exceptions import RequestValidationError

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    # Check if any error is our "oversized" marker
    for error in exc.errors():
        if "oversized" in str(error.get("msg", "")):
            return JSONResponse(
                status_code=413,
                content={"error": "Input exceeds the maximum allowed size."},
            )
    return JSONResponse(
        status_code=422,
        content={"error": "Invalid request body."},
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _audit(tool: str, text: str) -> None:
    """Log tool name, input length and SHA-256 hash. Never the raw input."""
    write_audit_log(tool, hash_input(text))
    logger.info("tool=%s input_len=%d input_sha256=%s", tool, len(text), hash_input(text))


def _injection_check(text: str) -> bool:
    """Return True if the text contains prompt-injection phrases."""
    import re
    patterns = [
        r"ignore.*instructions", r"you are now", r"disregard",
        r"forget.*instructions", r"new instructions:", r"system prompt:", r"act as",
    ]
    lower = text.lower()
    return any(re.search(p, lower) for p in patterns)


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.get("/api/health")
async def health():
    return {"status": "ok", "timestamp": datetime.now(timezone.utc).isoformat()}


@app.post("/api/scan")
async def scan(req: ScanRequest):
    if _injection_check(req.code):
        _audit("scan_injection_attempt", req.code)
        return JSONResponse(
            status_code=400,
            content={"error": "Input refused for security reasons."},
        )
    _audit("scan_owasp", req.code)
    try:
        findings = scan_code(req.code, req.language)
        report   = format_findings(findings, req.language)
        return {
            "findings": [f._asdict() for f in findings],
            "report":   report,
        }
    except Exception:
        logger.exception("scan_owasp internal error")
        return JSONResponse(
            status_code=500,
            content={"error": "An unexpected error occurred. Please try again."},
        )


@app.post("/api/jwt")
async def jwt_inspect(req: JWTRequest):
    token = req.token.strip()
    if _injection_check(token):
        _audit("jwt_injection_attempt", token)
        return JSONResponse(
            status_code=400,
            content={"error": "Input refused for security reasons."},
        )
    _audit("jwt_inspect", token)
    try:
        findings, metadata = inspect_jwt(token)
        report = format_jwt_report(findings, metadata)
        return {
            "findings": [f._asdict() for f in findings],
            "metadata": metadata,
            "report":   report,
        }
    except JWTError as exc:
        return JSONResponse(status_code=400, content={"error": str(exc)})
    except Exception:
        logger.exception("jwt_inspect internal error")
        return JSONResponse(
            status_code=500,
            content={"error": "An unexpected error occurred. Please try again."},
        )


@app.post("/api/iam")
async def iam_audit(req: IAMRequest):
    if _injection_check(req.policy_json):
        _audit("iam_injection_attempt", req.policy_json)
        return JSONResponse(
            status_code=400,
            content={"error": "Input refused for security reasons."},
        )
    _audit("iam_audit", req.policy_json)
    try:
        findings, metadata = audit_policy(req.policy_json)
        report = format_iam_report(findings, metadata)
        return {
            "findings": [f._asdict() for f in findings],
            "metadata": metadata,
            "report":   report,
        }
    except PolicyError as exc:
        return JSONResponse(status_code=400, content={"error": str(exc)})
    except Exception:
        logger.exception("iam_audit internal error")
        return JSONResponse(
            status_code=500,
            content={"error": "An unexpected error occurred. Please try again."},
        )
