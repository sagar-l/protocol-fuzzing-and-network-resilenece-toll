# ============================================================================
# FuzzStrike C2 Orchestrator — Dockerfile
# ============================================================================
# Multi-stage build for a slim, production-ready FastAPI container.
# Stage 1: Install dependencies in a builder image.
# Stage 2: Copy only the runtime artifacts into a minimal image.
# ============================================================================

# ---------------------------------------------------------------------------
# Stage 1: Dependency installation
# ---------------------------------------------------------------------------
FROM python:3.12-slim AS builder

WORKDIR /build

# Install system-level build dependencies (needed for some pip packages)
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy and install Python dependencies first (Docker layer caching)
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# ---------------------------------------------------------------------------
# Stage 2: Runtime image
# ---------------------------------------------------------------------------
FROM python:3.12-slim AS runtime

# Security: Run as non-root user
RUN groupadd -r fuzzstrike && useradd -r -g fuzzstrike fuzzstrike

WORKDIR /app

# Copy installed packages from builder
COPY --from=builder /install /usr/local

# Copy application source code
COPY app/ ./app/

# Create data directory for SQLite persistence
RUN mkdir -p /app/data && chown -R fuzzstrike:fuzzstrike /app

# Install curl for healthcheck
RUN apt-get update && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

# Switch to non-root user
USER fuzzstrike

# Expose the C2 API port
EXPOSE 9000

# Environment defaults
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV FUZZSTRIKE_ENV=docker

# Startup command — Uvicorn with production-safe defaults
# - host 0.0.0.0: bind to all interfaces (required inside Docker)
# - port 9000: the C2 API port
# - workers 2: balance concurrency vs. SQLite write-lock constraints
CMD ["python", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "9000", "--workers", "1", "--log-level", "info"]
