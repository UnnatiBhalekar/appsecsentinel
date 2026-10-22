"""
api/lambda_handler.py
---------------------
AWS Lambda entry point using Mangum.

Mangum wraps the FastAPI ASGI app so it can receive API Gateway HTTP events
and return responses in the format Lambda/API Gateway expects.

Deploy:
  Set the Lambda handler to: api.lambda_handler.handler
  Set ALLOWED_ORIGIN env var to your CloudFront/API Gateway domain.

The same app.py runs locally (uvicorn) and on Lambda — no code differences.
"""

from mangum import Mangum
from api.app import app

# Mangum translates API Gateway v1 (REST) and v2 (HTTP) events into ASGI.
handler = Mangum(app, lifespan="off")
