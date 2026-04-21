# ============================================================================
# FuzzStrike C2 Orchestrator — Centralized Configuration
# ============================================================================
# Uses pydantic-settings for type-safe, environment-variable-driven config.
# Every setting has a sensible default but can be overridden via env vars
# prefixed with FUZZSTRIKE_ (e.g., FUZZSTRIKE_DB_PATH=/custom/path.db).
#
# Design Decision: We use a singleton pattern via lru_cache to ensure
# configuration is parsed exactly once at startup, not on every request.
# ============================================================================

from functools import lru_cache
from pathlib import Path
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """
    Application-wide configuration.

    All fields can be overridden via environment variables with the
    FUZZSTRIKE_ prefix. For example:
        FUZZSTRIKE_DB_PATH=/data/prod.db
        FUZZSTRIKE_LOG_LEVEL=DEBUG
    """

    # ── Application Identity ──────────────────────────────────────────────
    app_name: str = "FuzzStrike C2 Orchestrator"
    app_version: str = "1.0.0"
    env: str = "development"  # development | docker | production

    # ── Database ──────────────────────────────────────────────────────────
    # SQLite file path. In Docker, this is mounted to a persistent volume.
    db_path: str = "./data/fuzzstrike.db"

    # ── Server ────────────────────────────────────────────────────────────
    host: str = "0.0.0.0"
    port: int = 9000
    log_level: str = "INFO"

    # ── Mutation Engine ───────────────────────────────────────────────────
    # Default number of mutated payloads to generate per seed
    default_mutation_count: int = 50
    # Maximum payload size in bytes (for safety limits)
    max_payload_size_bytes: int = 5 * 1024 * 1024  # 5 MB
    # Batch size for dispatching to attack nodes
    dispatch_batch_size: int = 50

    # ── Attack Node Communication ─────────────────────────────────────────
    # Timeout for HTTP calls to/from attack nodes (in seconds)
    attack_node_timeout: float = 10.0

    # ── CORS ──────────────────────────────────────────────────────────────
    # Allowed origins for the dashboard. In production, restrict this.
    cors_origins: list[str] = ["*"]

    class Config:
        env_prefix = "FUZZSTRIKE_"
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = False


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """
    Singleton accessor for application settings.

    The @lru_cache ensures we parse environment variables exactly once.
    FastAPI's Depends() system will call this, but it returns the
    cached instance after the first invocation.

    Returns:
        Settings: The frozen application configuration.
    """
    settings = Settings()

    # Ensure the database directory exists
    db_dir = Path(settings.db_path).parent
    db_dir.mkdir(parents=True, exist_ok=True)

    return settings
