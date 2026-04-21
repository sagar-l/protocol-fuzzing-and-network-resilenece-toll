# ============================================================================
# FuzzStrike C2 Orchestrator — FastAPI Application Entry Point
# ============================================================================
# This is the main application module that:
#   1. Creates and configures the FastAPI application instance
#   2. Registers all route modules
#   3. Configures CORS middleware
#   4. Initializes the database on startup
#   5. Provides health check and root info endpoints
#
# Run locally:
#   uvicorn app.main:app --host 0.0.0.0 --port 9000 --reload
#
# Run in Docker:
#   Handled by the CMD in Dockerfile
# ============================================================================

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from loguru import logger

from app.config import get_settings
from app.database import init_db
from app.routes import campaigns, payloads, telemetry


# ============================================================================
# Application Lifecycle — Startup & Shutdown Events
# ============================================================================
@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application lifecycle manager.

    Startup:
      - Initialize the SQLite database (create tables if needed)
      - Log the configuration summary

    Shutdown:
      - Cleanup resources (DB connections are managed by SQLAlchemy)
    """
    settings = get_settings()

    # ── Startup ────────────────────────────────────────────────────────
    logger.info("=" * 60)
    logger.info(f"🚀 {settings.app_name} v{settings.app_version}")
    logger.info(f"   Environment : {settings.env}")
    logger.info(f"   Database    : {settings.db_path}")
    logger.info(f"   Mutations   : {settings.default_mutation_count} per seed")
    logger.info(f"   Batch Size  : {settings.dispatch_batch_size}")
    logger.info("=" * 60)

    # Initialize database schema
    init_db()
    logger.info("Database initialized successfully")

    yield  # Application runs here

    # ── Shutdown ───────────────────────────────────────────────────────
    logger.info("FuzzStrike C2 shutting down...")


# ============================================================================
# FastAPI Application Instance
# ============================================================================
settings = get_settings()

app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description=(
        "Command & Control orchestrator for the FuzzStrike distributed "
        "protocol fuzzing platform. Manages campaigns, generates mutated "
        "payloads, dispatches them to attack nodes, and ingests crash "
        "telemetry from monitored target environments."
    ),
    docs_url="/docs",          # Swagger UI at /docs
    redoc_url="/redoc",        # ReDoc at /redoc
    lifespan=lifespan,
)


# ============================================================================
# Middleware — CORS Configuration
# ============================================================================
# In Docker, the Nginx reverse proxy handles CORS, so this is primarily
# for local development where the dashboard runs on a different port.
# ============================================================================
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ============================================================================
# Route Registration
# ============================================================================
# Each route module defines its own APIRouter with its own prefix.
# We include them here to compose the full API surface.
# ============================================================================
app.include_router(campaigns.router)
app.include_router(payloads.router)
app.include_router(telemetry.router)


# ============================================================================
# Root & Health Endpoints
# ============================================================================

@app.get("/", tags=["System"])
def root():
    """
    Root endpoint — returns application identity and version.
    Useful for quick runtime verification.
    """
    return {
        "name": settings.app_name,
        "version": settings.app_version,
        "status": "operational",
        "docs": "/docs",
    }


@app.get("/health", tags=["System"])
def health_check():
    """
    Health check endpoint for Docker health probes and load balancers.

    Returns HTTP 200 with a simple status payload. The Docker
    HEALTHCHECK directive in docker-compose.yml hits this endpoint
    every 10 seconds.
    """
    return {"status": "healthy", "service": "c2-orchestrator"}
