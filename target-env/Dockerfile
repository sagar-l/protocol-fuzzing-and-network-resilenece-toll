# ============================================================================
# FuzzStrike Target Environment — Dockerfile
# ============================================================================
# Builds the vulnerable target TCP server and the telemetry agent.
# Uses supervisord to run both processes inside a single container:
#   1. target_server.py — The intentionally vulnerable TCP server
#   2. agent.py         — The crash-monitoring telemetry agent
#
# The target server will throw an OutOfMemoryError-equivalent when it
# receives a payload larger than 1MB, simulating a real-world crash.
# ============================================================================

FROM python:3.12-slim

WORKDIR /app

# Install supervisord to manage both processes in one container
RUN apt-get update && apt-get install -y --no-install-recommends \
    supervisor \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy dependency file and install Python packages
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application scripts
COPY target_server.py .
COPY agent.py .

# Copy supervisord configuration
COPY supervisord.conf /etc/supervisor/conf.d/fuzzstrike.conf

# Expose the target TCP server port
EXPOSE 7777

# Environment defaults
ENV PYTHONUNBUFFERED=1
ENV TARGET_PORT=7777
ENV C2_TELEMETRY_URL=http://c2-orchestrator:9000/api/v1/telemetry/crash
ENV MEMORY_POLL_INTERVAL_MS=500

# Start supervisord which manages both target_server and agent
CMD ["supervisord", "-c", "/etc/supervisor/conf.d/fuzzstrike.conf"]
