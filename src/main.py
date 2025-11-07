"""FastAPI server for Verisage - Multi-LLM Oracle (with external settlement webhook support)."""

import asyncio
import hmac
import hashlib
import json
import logging
import os
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from typing import Any, Optional

from fastapi import APIRouter, FastAPI, HTTPException, Request, Response, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.openapi.docs import get_swagger_ui_html
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address
from x402.types import HTTPInputSchema, PaywallConfig

from src.config import settings
from src.job_store import job_store
from src.models import (
    JobResponse,
    JobResultResponse,
    JobStatus,
    OracleQuery,
    OracleResult,
)
from src.workers import process_oracle_query
from src.x402_custom_middleware import require_payment_async_settle

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# ------------------------------------------------------------------------------
# Global health status (updated by background task every minute).
# ------------------------------------------------------------------------------
health_status = {"status": "healthy", "last_check": None}

# Optional: HMAC verification for webhook
FACILITATOR_WEBHOOK_SECRET = os.getenv("FACILITATOR_WEBHOOK_SECRET", "").strip()

# ------------------------------------------------------------------------------
# Custom CSS for Swagger (unchanged)
# ------------------------------------------------------------------------------
CUSTOM_SWAGGER_CSS = """
/* ... (keep your existing CSS exactly as-is) ... */
"""

# OpenAPI tags (unchanged)
tags_metadata = [
    {"name": "Oracle (Paid)", "description": "Submit queries to the multi-LLM oracle. **Requires payment via x402 protocol.**"},
    {"name": "Oracle", "description": "Check status and retrieve results for oracle queries."},
    {"name": "Public Feed", "description": "Browse recent fact verifications submitted by the community."},
    {"name": "System", "description": "Health checks and system status."},
]

# ------------------------------------------------------------------------------
# Lifespan / background health updater
# ------------------------------------------------------------------------------
@asynccontextmanager
async def lifespan(app: FastAPI):
    if settings.debug_payments or settings.debug_mock:
        logger.warning("=" * 80)
        if settings.debug_payments:
            logger.warning("WARNING: Running with DEBUG_PAYMENTS=true - NO PAYMENT REQUIRED!")
        if settings.debug_mock:
            logger.warning("WARNING: Running with DEBUG_MOCK=true - USING MOCK LLM CLIENTS!")
        logger.warning("=" * 80)

    task = asyncio.create_task(update_health_status_periodically())

    try:
        yield
    finally:
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass

# ------------------------------------------------------------------------------
# FastAPI app
# ------------------------------------------------------------------------------
app = FastAPI(
    title="Verisage",
    description=(
        "Verifiable Multi-LLM Truth Oracle running on Oasis ROFL. "
        "Trustless fact verification powered by multiple independent AI providers (Claude, Gemini, OpenAI). "
        "All responses are cryptographically signed inside the ROFL TEE using SECP256K1 keys. "
        "Public keys can be verified against on-chain attested state at https://github.com/ptrus/rofl-registry"
    ),
    version="0.1.0",
    docs_url=None,
    redoc_url=None,
    openapi_tags=tags_metadata,
    swagger_ui_parameters={"syntaxHighlight.theme": "nord", "defaultModelsExpandDepth": 1},
    lifespan=lifespan,
)

# ------------------------------------------------------------------------------
# Rate limiting + CORS
# ------------------------------------------------------------------------------
def get_client_ip(request: Request) -> str:
    if settings.behind_cloudflare:
        cf_ip = request.headers.get("CF-Connecting-IP")
        if cf_ip:
            return cf_ip
    return get_remote_address(request)

limiter = Limiter(key_func=get_client_ip)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.get_cors_origins(),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ------------------------------------------------------------------------------
# Background health updater
# ------------------------------------------------------------------------------
async def update_health_status_periodically():
    global health_status
    while True:
        try:
            await asyncio.sleep(60)
            stats = job_store.get_recent_job_stats(limit=10)
            queued_count = job_store.get_queued_job_count()

            status = "healthy"
            status_details = {}

            if queued_count > 100:
                status = "unhealthy"
                status_details["queue_status"] = "overloaded"
                status_details["queued_jobs"] = queued_count
            elif stats["total"] > 0:
                failure_rate = stats["failed"] / stats["total"]
                if failure_rate > 0.5:
                    status = "degraded"

            health_status = {
                "status": status,
                "last_check": datetime.now(UTC).isoformat(),
                "recent_jobs": {"total": stats["total"], "failed": stats["failed"]},
                "queued_jobs": queued_count,
                **status_details,
            }
        except Exception as e:
            logger.error(f"Health status update failed: {e}", exc_info=True)
            health_status = {"status": "unhealthy", "last_check": datetime.now(UTC).isoformat(), "error": str(e)}

# ------------------------------------------------------------------------------
# Static + API router
# ------------------------------------------------------------------------------
app.mount("/static", StaticFiles(directory="static"), name="static")
api_v1 = APIRouter(prefix="/api/v1")

# ------------------------------------------------------------------------------
# Payment middleware (x402) + settlement callbacks
# ------------------------------------------------------------------------------
if not settings.debug_payments:
    if not settings.x402_payment_address:
        raise ValueError(
            "X402_PAYMENT_ADDRESS is required when DEBUG_PAYMENTS=false. "
            "Set DEBUG_PAYMENTS=true for testing without payments."
        )

    facilitator_config = None
    if settings.environment == "production":
        if settings.facilitator_url:
            from x402.facilitator import FacilitatorConfig
            facilitator_config = FacilitatorConfig(url=settings.facilitator_url)
            logger.info(f"✓ Using custom facilitator URL: {settings.facilitator_url}")
        else:
            from cdp.x402 import create_facilitator_config
            facilitator_config = create_facilitator_config(
                api_key_id=settings.cdp_api_key_id,
                api_key_secret=settings.cdp_api_key_secret,
            )
            logger.info("✓ CDP facilitator configured for production payment verification")

    async def on_settlement_success(request: Request, payment, payment_requirements):
        """Async-settle path (works with CDP and any facilitator that calls back through middleware)."""
        try:
            if hasattr(request.state, "job_id") and hasattr(request.state, "query"):
                job_id = request.state.job_id
                query = request.state.query
                logger.info(f"[settlement:middleware] success → queue job {job_id}")
                process_oracle_query(job_id, query)
        except Exception as e:
            logger.error(f"[settlement:middleware] failed to queue job: {e}", exc_info=True)

    async def on_settlement_failure(request: Request, payment, payment_requirements, error_reason: str):
        try:
            if hasattr(request.state, "job_id"):
                job_id = request.state.job_id
                job_store.update_job_error(job_id, "Payment settlement failed")
                logger.warning(f"[settlement:middleware] failed for job {job_id}: {error_reason}")
        except Exception:
            logger.warning(f"[settlement:middleware] failure path error (no job_id?) reason={error_reason}")

    payment_middleware = require_payment_async_settle(
        path="/api/v1/query",
        price=settings.x402_price,
        pay_to_address=settings.x402_payment_address,
        network=settings.x402_network,
        description=(
            "Verifiable Multi-LLM Truth Oracle - Trustless fact verification powered by multiple "
            "independent AI providers (Claude, Gemini, OpenAI). Cryptographically signed responses "
            "from code running in Oasis ROFL TEE."
        ),
        paywall_config=PaywallConfig(app_name="Verisage.xyz", app_logo="/static/logo.png"),
        input_schema=HTTPInputSchema(
            body_type="json",
            body_fields={
                "query": {
                    "type": "string",
                    "description": "Question to verify (YES/NO). Be specific with dates, names, and facts.",
                    "minLength": 10,
                    "maxLength": 256,
                    "pattern": r'^[a-zA-Z0-9\s.,?!\-\'"":;()/@#$%&+=]+$',
                }
            },
            query_params={},
            header_fields={},
        ),
        output_schema=JobResponse.model_json_schema(),
        facilitator_config=facilitator_config,
        on_settlement_success=on_settlement_success,
        on_settlement_failure=on_settlement_failure,
    )

    @app.middleware("http")
    async def payment_with_cors(request: Request, call_next):
        if request.method == "OPTIONS":
            return await call_next(request)

        response = await payment_middleware(request, call_next)

        # Ensure CORS headers on 402 responses (browser fetch)
        if response.status_code == 402:
            origin = request.headers.get("origin")
            allowed = settings.get_cors_origins()
            if origin and origin in allowed:
                response.headers["Access-Control-Allow-Origin"] = origin
                response.headers["Access-Control-Allow-Credentials"] = "true"
                response.headers["Access-Control-Allow-Methods"] = "*"
                response.headers["Access-Control-Allow-Headers"] = "*"
        return response

# ------------------------------------------------------------------------------
# Swagger docs route (unchanged)
# ------------------------------------------------------------------------------
@app.get("/docs", include_in_schema=False)
async def custom_swagger_ui_html():
    html = get_swagger_ui_html(
        openapi_url=app.openapi_url,
        title=app.title + " - API Documentation",
        swagger_js_url="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui-bundle.js",
        swagger_css_url="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui.css",
    )
    html_str = html.body.decode().replace("</head>", f"<style>{CUSTOM_SWAGGER_CSS}</style></head>")
    return HTMLResponse(content=html_str)

# ------------------------------------------------------------------------------
# Oracle endpoints
# ------------------------------------------------------------------------------
@api_v1.post("/query", response_model=JobResponse, tags=["Oracle (Paid)"])
@limiter.limit("100/minute")
async def query_oracle(query: OracleQuery, request: Request) -> JobResponse:
    if health_status.get("status") == "unhealthy":
        raise HTTPException(
            status_code=503,
            detail={
                "error": "Service temporarily overloaded",
                "queue_status": health_status.get("queue_status"),
                "queued_jobs": health_status.get("queued_jobs"),
                "message": "The job queue is currently full. Please try again in a few minutes.",
            },
        )

    payer_address = None
    tx_hash = None
    network = None

    try:
        if hasattr(request.state, "verify_response"):
            verify_resp = request.state.verify_response
            if hasattr(verify_resp, "payer"):
                payer_address = verify_resp.payer

        if hasattr(request.state, "payment_details"):
            payment_details = request.state.payment_details
            if hasattr(payment_details, "network"):
                network = payment_details.network
    except Exception as e:
        logger.warning(f"Failed to extract payment info: {e}", exc_info=True)

    # Create job now (settlement may happen later via middleware or webhook)
    job_id, created_at = job_store.create_job(
        query.query,
        payer_address=payer_address,
        tx_hash=tx_hash,
        network=network,
    )

    # Stash so the async-settle callback can queue the job
    request.state.job_id = job_id
    request.state.query = query.query

    # In debug mode, process immediately
    if settings.debug_payments:
        process_oracle_query(job_id, query.query)

    return JobResponse(job_id=job_id, status=JobStatus.PENDING, query=query.query, created_at=created_at)

@api_v1.get("/query/{job_id}", response_model=JobResultResponse, tags=["Oracle"])
@limiter.limit("100/minute")
async def get_query_result(job_id: str, request: Request) -> JobResultResponse:
    job_data = job_store.get_job(job_id)
    if job_data is None:
        raise HTTPException(status_code=404, detail="Job not found")

    result = None
    if job_data["result_json"]:
        result = OracleResult.model_validate_json(job_data["result_json"])

    return JobResultResponse(
        job_id=job_data["id"],
        status=JobStatus(job_data["status"]),
        query=job_data["query"],
        result=result,
        error=job_data["error"],
        created_at=datetime.fromisoformat(job_data["created_at"]),
        completed_at=(datetime.fromisoformat(job_data["completed_at"]) if job_data["completed_at"] else None),
        payer_address=job_data.get("payer_address"),
        tx_hash=job_data.get("tx_hash"),
        network=job_data.get("network"),
    )

@api_v1.get("/recent", tags=["Public Feed"])
@limiter.limit("100/minute")
async def get_recent_jobs(request: Request, limit: int = 5, exclude_uncertain: bool = True):
    limit = min(limit, 20)
    jobs_data = job_store.get_recent_completed_jobs(limit, exclude_uncertain)

    jobs = []
    for job_data in jobs_data:
        result = None
        if job_data["result_json"]:
            result = OracleResult.model_validate_json(job_data["result_json"])

        jobs.append(
            JobResultResponse(
                job_id=job_data["id"],
                status=JobStatus(job_data["status"]),
                query=job_data["query"],
                result=result,
                error=job_data["error"],
                created_at=datetime.fromisoformat(job_data["created_at"]),
                completed_at=(datetime.fromisoformat(job_data["completed_at"]) if job_data["completed_at"] else None),
                payer_address=job_data.get("payer_address"),
                tx_hash=job_data.get("tx_hash"),
                network=job_data.get("network"),
            )
        )
    return jobs

# ------------------------------------------------------------------------------
# External settlement webhook (Daydreams / x402.rs friendly)
# ------------------------------------------------------------------------------
@api_v1.post("/settle", tags=["Oracle"])
async def settlement_webhook(
    request: Request,
    x_facilitator_signature: Optional[str] = Header(default=None, alias="X-Facilitator-Signature"),
):
    """
    Generic settlement webhook for facilitators that POST back out-of-band.
    We attempt to verify (optional HMAC) and extract a job_id from multiple common shapes:

    - payload["job_id"]
    - payload["metadata"]["job_id"]
    - payload["payment"]["metadata"]["job_id"]
    - payload["request"]["headers"]["x-job-id"]
    - payload["settlement"]["job_id"]

    Then we queue the corresponding job.
    """
    raw = await request.body()
    body_text = raw.decode("utf-8", errors="ignore") if raw else "{}"

    # Optional HMAC verification if secret provided and header present
    if FACILITATOR_WEBHOOK_SECRET and x_facilitator_signature:
        try:
            # Accept formats "sha256=<hex>" or plain hex
            supplied = x_facilitator_signature.split("=", 1)[-1].strip()
            digest = hmac.new(
                FACILITATOR_WEBHOOK_SECRET.encode("utf-8"),
                raw,
                hashlib.sha256,
            ).hexdigest()
            if not hmac.compare_digest(digest, supplied):
                logger.warning("[settlement:webhook] HMAC mismatch")
                return JSONResponse({"status": "error", "message": "invalid signature"}, status_code=401)
        except Exception as e:
            logger.warning(f"[settlement:webhook] HMAC verification error: {e}")
            return JSONResponse({"status": "error", "message": "signature error"}, status_code=401)

    try:
        payload: Any = json.loads(body_text or "{}")
    except Exception:
        payload = {}

    logger.info(f"[settlement:webhook] received payload: {json.dumps(payload)[:2000]}")

    # Extract a job_id from common locations
    job_id = (
        payload.get("job_id")
        or (payload.get("metadata") or {}).get("job_id")
        or ((payload.get("payment") or {}).get("metadata") or {}).get("job_id")
        or ((payload.get("request") or {}).get("headers") or {}).get("x-job-id")
        or ((payload.get("settlement") or {}).get("job_id"))
    )

    if not job_id:
        logger.warning("[settlement:webhook] no job_id found in payload")
        return JSONResponse({"status": "error", "message": "job_id missing"}, status_code=400)

    # Confirm the job exists
    job = job_store.get_job(job_id)
    if not job:
        logger.warning(f"[settlement:webhook] job not found: {job_id}")
        return JSONResponse({"status": "error", "message": "job not found"}, status_code=404)

    # If already finished, acknowledge idempotently
    if job["status"] in (JobStatus.COMPLETED.value, JobStatus.FAILED.value):
        logger.info(f"[settlement:webhook] job {job_id} already finalized, ack")
        return JSONResponse({"status": "ok", "message": "already finalized"})

    # Queue processing
    try:
        logger.info(f"[settlement:webhook] success → queue job {job_id}")
        process_oracle_query(job_id, job["query"])
        return JSONResponse({"status": "ok"})
    except Exception as e:
        logger.error(f"[settlement:webhook] failed to queue job {job_id}: {e}", exc_info=True)
        return JSONResponse({"status": "error", "message": "queue failed"}, status_code=500)

# ------------------------------------------------------------------------------
# System endpoints
# ------------------------------------------------------------------------------
@api_v1.get("/health", tags=["System"])
@limiter.limit("100/minute")
async def health_check(request: Request):
    return health_status

@api_v1.get("/info", tags=["System"])
@limiter.limit("100/minute")
async def get_info(request: Request):
    return {
        "payment_address": settings.x402_payment_address,
        "network": settings.x402_network,
        "price": settings.x402_price,
    }

# Mount router last
app.include_router(api_v1)

# ------------------------------------------------------------------------------
# Dev entrypoint
# ------------------------------------------------------------------------------
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("src.main:app", host="0.0.0.0", port=8000, reload=True)
