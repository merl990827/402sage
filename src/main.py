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
    Base,
    JobResponse,
    JobResultResponse,
    JobStatus,
    OracleQuery,
    OracleResult,
)
from src.workers import process_oracle_query
from src.x402_custom_middleware import require_payment_async_settle

logger = logging.getLogger(__name__)

# ------------------------------------------------------------------------------
# ✅ Auto-create DB tables (NO ALEMBIC REQUIRED)
# ------------------------------------------------------------------------------
from sqlalchemy import create_engine

def _init_db_autocreate() -> None:
    """
    Automatically creates missing DB tables on startup.
    Works with SQLAlchemy Base, and falls back to SQLModel if present.
    """
    from src.config import settings as _settings

    database_url = _settings.DATABASE_URL or "sqlite:///./data.db"

    engine_kwargs = {"pool_pre_ping": True}
    connect_args = {}

    # Needed for SQLite
    if database_url.startswith("sqlite"):
        connect_args = {"check_same_thread": False}

    engine = create_engine(database_url, connect_args=connect_args, **engine_kwargs)

    # Try SQLAlchemy Base
    try:
        Base.metadata.create_all(engine)
        print("✅ DB tables created / checked (SQLAlchemy Base)")
        return
    except Exception as e:
        print(f"⚠️ DB: Base metadata failed: {e}")

    # Try SQLModel if present
    try:
        from sqlmodel import SQLModel
        import src.models  # noqa
        SQLModel.metadata.create_all(engine)
        print("✅ DB tables created / checked (SQLModel)")
        return
    except Exception as e:
        print(f"⚠️ DB: SQLModel metadata failed: {e}")

    print("❌ DB could not initialize automatically!")


# ------------------------------------------------------------------------------
# Global
# ------------------------------------------------------------------------------

health_status = {"status": "healthy", "last_check": None}

CUSTOM_SWAGGER_CSS = """(same as your existing CSS unchanged)"""

tags_metadata = [
    {
        "name": "Oracle (Paid)",
        "description": "Submit queries to the multi-LLM oracle. **Requires payment via x402 protocol.**",
    },
    {
        "name": "Oracle",
        "description": "Check status and retrieve results for oracle queries.",
    },
    {
        "name": "Public Feed",
        "description": "Browse recent fact verifications submitted by the community.",
    },
    {
        "name": "System",
        "description": "Health checks and system status.",
    },
]


@asynccontextmanager
async def lifespan(app: FastAPI):
    health_task = None
    if settings.debug_payments or settings.debug_mock:
        logger.warning("=" * 80)
        if settings.debug_payments:
            logger.warning("WARNING: Running with DEBUG_PAYMENTS=true - NO PAYMENT REQUIRED!")
        if settings.debug_mock:
            logger.warning("WARNING: Running with DEBUG_MOCK=true - USING MOCK LLM CLIENTS!")
        logger.warning("=" * 80)

    # Start background health task
    health_task = asyncio.create_task(update_health_status_periodically())

    try:
        yield
    finally:
        if health_task:
            health_task.cancel()
            try:
                await health_task
            except asyncio.CancelledError:
                pass


# ------------------------------------------------------------------------------
# FastAPI app
# ------------------------------------------------------------------------------

app = FastAPI(
    title="sage402",
    description=(
        "Verifiable Multi-LLM Truth Oracle running on Oasis ROFL. "
        "Trustless fact verification powered by multiple independent AI providers."
    ),
    version="0.1.0",
    docs_url=None,
    redoc_url=None,
    openapi_tags=tags_metadata,
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
    allow_headers=["*"],
)


# ------------------------------------------------------------------------------
# Rate limiting
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


# ------------------------------------------------------------------------------
# background health
# ------------------------------------------------------------------------------

async def update_health_status_periodically():
    """Updates health status every 60 sec."""
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
                "recent_jobs": {
                    "total": stats["total"],
                    "failed": stats["failed"],
                },
                "queued_jobs": queued_count,
                **status_details,
            }

        except Exception as e:
            logger.error(f"Health update failed: {e}", exc_info=True)


# ------------------------------------------------------------------------------
# Static
# ------------------------------------------------------------------------------

app.mount("/static", StaticFiles(directory="static"), name="static")


# ------------------------------------------------------------------------------
# x402 payment middleware
# ------------------------------------------------------------------------------

if not settings.debug_payments:
    if not settings.x402_payment_address:
        raise ValueError(
            "X402_PAYMENT_ADDRESS is required when DEBUG_PAYMENTS=false."
        )

    facilitator_config = None
    if settings.environment == "production":
        if settings.facilitator_url:
            from x402.facilitator import FacilitatorConfig
            facilitator_config = FacilitatorConfig(url=settings.facilitator_url)
        else:
            from cdp.x402 import create_facilitator_config
            facilitator_config = create_facilitator_config(
                api_key_id=settings.cdp_api_key_id,
                api_key_secret=settings.cdp_api_key_secret,
            )

    async def on_settlement_success(request: Request, payment, payment_requirements):
        if hasattr(request.state, "job_id") and hasattr(request.state, "query"):
            job_id = request.state.job_id
            query = request.state.query
            logger.info(f"Settlement succeeded — queuing job {job_id}")
            process_oracle_query(job_id, query)

    async def on_settlement_failure(request: Request, payment, payment_requirements, error_reason: str):
        if hasattr(request.state, "job_id"):
            job_id = request.state.job_id
            logger.warning(f"Settlement failed for job {job_id}: {error_reason}")
            job_store.update_job_error(job_id, "Payment settlement failed")

    payment_middleware = require_payment_async_settle(
        path="/api/v1/query",
        price=settings.x402_price,
        pay_to_address=settings.x402_payment_address,
        network=settings.x402_network,
        description="Verifiable Multi-LLM Oracle.",
        paywall_config=PaywallConfig(app_name="sage402", app_logo="/static/logo.png"),
        input_schema=HTTPInputSchema(body_type="json"),
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
        return response


# ------------------------------------------------------------------------------
# API V1
# ------------------------------------------------------------------------------

api_v1 = APIRouter(prefix="/api/v1")


@api_v1.post("/query", response_model=JobResponse, tags=["Oracle (Paid)"])
@limiter.limit("100/minute")
async def query_oracle(query: OracleQuery, request: Request) -> JobResponse:

    payer_address = None
    network = None
    try:
        if hasattr(request.state, "verify_response"):
            verify = request.state.verify_response
            payer_address = getattr(verify, "payer", None)
            network = getattr(verify, "network", None)
    except:
        pass

    job_id, created_at = job_store.create_job(
        query.query,
        payer_address=payer_address,
        tx_hash=None,
        network=network,
    )

    request.state.job_id = job_id
    request.state.query = query.query

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
            if job_data["completed_at"] else None
        ),
        payer_address=job_data.get("payer_address"),
        tx_hash=job_data.get("tx_hash"),
        network=job_data.get("network"),
    )


@api_v1.get("/recent", tags=["Public Feed"])
@limiter.limit("100/minute")
async def get_recent_jobs(request: Request, limit: int = 5, exclude_uncertain: bool = True):
    jobs_data = job_store.get_recent_completed_jobs(min(limit, 20), exclude_uncertain)

    jobs = []
    for row in jobs_data:
        result = None
        if row.get("result_json"):
            result = OracleResult.model_validate_json(row["result_json"])

        jobs.append(
            JobResultResponse(
                job_id=row["id"],
                status=JobStatus(row["status"]),
                query=row["query"],
                result=result,
                error=row["error"],
                created_at=datetime.fromisoformat(row["created_at"]),
                completed_at=(
                    datetime.fromisoformat(row["completed_at"])
                    if row["completed_at"] else None
                ),
                payer_address=row.get("payer_address"),
                tx_hash=row.get("tx_hash"),
                network=row.get("network"),
            )
        )

    return jobs


app.include_router(api_v1)


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


@app.get("/docs", include_in_schema=False)
async def custom_swagger_ui_html():
    html = get_swagger_ui_html(
        openapi_url=app.openapi_url,
        title=app.title + " - API Documentation",
        swagger_js_url="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui-bundle.js",
        swagger_css_url="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui.css",
    )
    html_str = html.body.decode()
    html_str = html_str.replace("</head>", f"<style>{CUSTOM_SWAGGER_CSS}</style></head>")
    return HTMLResponse(content=html_str)


# ------------------------------------------------------------------------------
# ✅ Startup hook — auto-create DB
# ------------------------------------------------------------------------------

@app.on_event("startup")
async def _autocreate_db_on_startup():
    _init_db_autocreate()
    print("✅ Startup complete. DB ready.")


# ------------------------------------------------------------------------------
# Run
# ------------------------------------------------------------------------------

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "src.main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
    )
