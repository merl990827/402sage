"""FastAPI server for sage402 - Multi-LLM Oracle."""

import asyncio
import logging
from contextlib import asynccontextmanager
from datetime import UTC, datetime

from fastapi import APIRouter, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.openapi.docs import get_swagger_ui_html
from fastapi.responses import HTMLResponse
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

# --------------------------------------------------------------------------------------
# Global health
# --------------------------------------------------------------------------------------
health_status = {"status": "healthy", "last_check": None}

# (You can keep your original long CSS; a short one is fine too.)
CUSTOM_SWAGGER_CSS = """
body { background: #0a0a0a; }
.swagger-ui { font-family: Inter, sans-serif; }
.swagger-ui .topbar { background: #111; border-bottom: 1px solid #222; }
.swagger-ui .info .title { color: #e4e4e7; }
"""

tags_metadata = [
    {"name": "Oracle (Paid)", "description": "Submit queries using the x402 protocol."},
    {"name": "Oracle", "description": "Check job results."},
    {"name": "Public Feed", "description": "Browse recent fact checks."},
    {"name": "System", "description": "Health and service info."},
]


@asynccontextmanager
async def lifespan(app: FastAPI):
    # show debug banners
    if settings.debug_payments or settings.debug_mock:
        logger.warning("=" * 80)
        if settings.debug_payments:
            logger.warning("WARNING: DEBUG_PAYMENTS=true (no payment required)")
        if settings.debug_mock:
            logger.warning("WARNING: DEBUG_MOCK=true (mock LLM clients)")
        logger.warning("=" * 80)

    # background health updater
    health_task = asyncio.create_task(update_health_status_periodically())
    try:
        yield
    finally:
        health_task.cancel()
        try:
            await health_task
        except asyncio.CancelledError:
            pass


# --------------------------------------------------------------------------------------
# App + CORS
# --------------------------------------------------------------------------------------
app = FastAPI(
    title="sage402",
    version="0.1.0",
    docs_url=None,
    redoc_url=None,
    openapi_tags=tags_metadata,
    swagger_ui_parameters={"syntaxHighlight.theme": "nord", "defaultModelsExpandDepth": 1},
    lifespan=lifespan,
)

ALLOWED_ORIGINS = [
    "https://loyal-courtesy-production-617e.up.railway.app",
    "https://402sage-production.up.railway.app",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=[
        "content-type",
        "x-402-pricing",
        "x-402-payment-method",
        "x-402-invoice",
        "x-402-signature",
        "x-402-payment-pointer",
        "x-402-settlement-token",
    ],
    expose_headers=[
        "x-402-pricing",
        "x-402-invoice",
        "x-402-signature",
        "x-402-payment-method",
        "x-402-settlement-token",
    ],
)


# --------------------------------------------------------------------------------------
# Rate limiting
# --------------------------------------------------------------------------------------
def get_client_ip(request: Request) -> str:
    if settings.behind_cloudflare:
        cf_ip = request.headers.get("CF-Connecting-IP")
        if cf_ip:
            return cf_ip
    return get_remote_address(request)


limiter = Limiter(key_func=get_client_ip)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)


# --------------------------------------------------------------------------------------
# Background health task
# --------------------------------------------------------------------------------------
async def update_health_status_periodically():
    global health_status
    while True:
        await asyncio.sleep(60)
        try:
            stats = job_store.get_recent_job_stats(limit=10)
            queued = job_store.get_queued_job_count()

            status = "healthy"
            if queued > 100:
                status = "unhealthy"
            elif stats["total"] > 0:
                failure_rate = stats["failed"] / stats["total"]
                if failure_rate > 0.5:
                    status = "degraded"

            health_status = {
                "status": status,
                "last_check": datetime.now(UTC).isoformat(),
                "recent_jobs": stats,
                "queued_jobs": queued,
            }
        except Exception as e:
            logger.error("Health update failed", exc_info=True)
            health_status = {
                "status": "unhealthy",
                "last_check": datetime.now(UTC).isoformat(),
                "error": str(e),
            }


# --------------------------------------------------------------------------------------
# Static + Router
# --------------------------------------------------------------------------------------
app.mount("/static", StaticFiles(directory="static"), name="static")
api_v1 = APIRouter(prefix="/api/v1")


# --------------------------------------------------------------------------------------
# x402 payment middleware (skip entirely when DEBUG_PAYMENTS=true)
# --------------------------------------------------------------------------------------
if not settings.debug_payments:
    if not settings.x402_payment_address:
        raise ValueError("X402_PAYMENT_ADDRESS is required when DEBUG_PAYMENTS=false.")

    facilitator_config = None
    if settings.environment == "production":
        if settings.facilitator_url:
            from x402.facilitator import FacilitatorConfig

            facilitator_config = FacilitatorConfig(url=settings.facilitator_url)
        else:
            # Coinbase CDP facilitator
            from cdp.x402 import create_facilitator_config

            facilitator_config = create_facilitator_config(
                api_key_id=settings.cdp_api_key_id,
                api_key_secret=settings.cdp_api_key_secret,
            )

    async def on_settlement_success(request: Request, payment, payment_requirements):
        job_id = getattr(request.state, "job_id", None)
        query = getattr(request.state, "query", None)
        if job_id and query:
            logger.info(f"Settlement succeeded — queuing job {job_id}")
            process_oracle_query(job_id, query)

    async def on_settlement_failure(request: Request, payment, payment_requirements, error_reason: str):
        job_id = getattr(request.state, "job_id", None)
        if job_id:
            logger.warning(f"Settlement failed for job {job_id}: {error_reason}")
            job_store.update_job_error(job_id, "Payment settlement failed")

    payment_middleware = require_payment_async_settle(
        path="/api/v1/query",
        price=settings.x402_price,
        pay_to_address=settings.x402_payment_address,
        network=settings.x402_network,
        description="Verifiable Multi-LLM Truth Oracle",
        paywall_config=PaywallConfig(app_name="sage402", app_logo="/static/logo.png"),
        input_schema=HTTPInputSchema(
            body_type="json",
            body_fields={
                "query": {
                    "type": "string",
                    "description": "Question to verify; be specific.",
                    "minLength": 10,
                    "maxLength": 256,
                }
            },
        ),
        output_schema=JobResponse.model_json_schema(),
        facilitator_config=facilitator_config,
        on_settlement_success=on_settlement_success,
        on_settlement_failure=on_settlement_failure,
    )

    @app.middleware("http")
    async def payment_with_cors(request: Request, call_next):
        # Allow CORS preflight to pass through
        if request.method == "OPTIONS":
            return await call_next(request)
        return await payment_middleware(request, call_next)


# --------------------------------------------------------------------------------------
# Swagger UI (styled)
# --------------------------------------------------------------------------------------
@app.get("/docs", include_in_schema=False)
async def custom_swagger_ui_html():
    html = get_swagger_ui_html(
        openapi_url=app.openapi_url,
        title=app.title + " - API Docs",
        swagger_js_url="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui-bundle.js",
        swagger_css_url="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui.css",
    )
    html_str = html.body.decode()
    html_str = html_str.replace("</head>", f"<style>{CUSTOM_SWAGGER_CSS}</style></head>")
    return HTMLResponse(content=html_str)


# --------------------------------------------------------------------------------------
# API Endpoints
# --------------------------------------------------------------------------------------
@api_v1.post("/query", response_model=JobResponse, tags=["Oracle (Paid)"])
@limiter.limit("100/minute")
async def query_oracle(query: OracleQuery, request: Request) -> JobResponse:
    # Optional: backpressure
    if health_status.get("status") == "unhealthy":
        raise HTTPException(status_code=503, detail="Service temporarily overloaded")

    payer_address = None
    network = None

    try:
        vr = getattr(request.state, "verify_response", None)
        if vr is not None:
            payer_address = getattr(vr, "payer", None)
            network = getattr(vr, "network", None)
    except Exception:
        pass

    job_id, created_at = job_store.create_job(
        query.query,
        payer_address=payer_address,
        tx_hash=None,
        network=network,
    )

    # Available to settlement callbacks
    request.state.job_id = job_id
    request.state.query = query.query

    # In DEBUG_PAYMENTS, run immediately
    if settings.debug_payments:
        process_oracle_query(job_id, query.query)

    return JobResponse(
        job_id=job_id,
        status=JobStatus.PENDING,
        query=query.query,
        created_at=created_at,
    )


@api_v1.get("/query/{job_id}", response_model=JobResultResponse, tags=["Oracle"])
@limiter.limit("100/minute")
async def get_query_result(job_id: str, request: Request) -> JobResultResponse:
    job_data = job_store.get_job(job_id)
    if not job_data:
        raise HTTPException(status_code=404, detail="Job not found")

    result = None
    if job_data.get("result_json"):
        result = OracleResult.model_validate_json(job_data["result_json"])

    return JobResultResponse(
        job_id=job_data["id"],
        status=JobStatus(job_data["status"]),
        query=job_data["query"],
        result=result,
        error=job_data["error"],
        created_at=datetime.fromisoformat(job_data["created_at"]),
        completed_at=(
            datetime.fromisoformat(job_data["completed_at"])
            if job_data["completed_at"]
            else None
        ),
        payer_address=job_data.get("payer_address"),
        tx_hash=job_data.get("tx_hash"),
        network=job_data.get("network"),
    )


@api_v1.get("/recent", tags=["Public Feed"])
@limiter.limit("100/minute")
async def get_recent_jobs(request: Request, limit: int = 5, exclude_uncertain: bool = True):
    jobs_data = job_store.get_recent_completed_jobs(min(limit, 20), exclude_uncertain)
    out: list[JobResultResponse] = []

    for row in jobs_data:
        result = (
            OracleResult.model_validate_json(row["result_json"])
            if row.get("result_json")
            else None
        )
        out.append(
            JobResultResponse(
                job_id=row["id"],
                status=JobStatus(row["status"]),
                query=row["query"],
                result=result,
                error=row["error"],
                created_at=datetime.fromisoformat(row["created_at"]),
                completed_at=(
                    datetime.fromisoformat(row["completed_at"])
                    if row["completed_at"]
                    else None
                ),
                payer_address=row.get("payer_address"),
                tx_hash=row.get("tx_hash"),
                network=row.get("network"),
            )
        )

    return out


# Mount router
app.include_router(api_v1)


# --------------------------------------------------------------------------------------
# System endpoints
# --------------------------------------------------------------------------------------
@app.get("/health", tags=["System"])
@limiter.limit("100/minute")
async def health_check(request: Request):
    return health_status


@app.get("/info", tags=["System"])
@limiter.limit("100/minute")
async def get_info(request: Request):
    return {
        "payment_address": settings.x402_payment_address,
        "network": settings.x402_network,
        "price": settings.x402_price,
    }


# --------------------------------------------------------------------------------------
# Dev run
# --------------------------------------------------------------------------------------
if __name__ == "__main__":
    import uvicorn

    uvicorn.run("src.main:app", host="0.0.0.0", port=8000, reload=True)
