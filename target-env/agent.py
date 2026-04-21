# ============================================================================
# FuzzStrike Target Environment — Telemetry Agent
# ============================================================================
# A lightweight monitoring agent that runs alongside the vulnerable target
# server inside the Docker container. Its responsibilities:
#
#   1. Poll the target process health every 500ms (CPU, memory)
#   2. Detect when the target process crashes or exits
#   3. Read the state file to identify the triggering payload
#   4. POST a crash report to the C2 orchestrator's telemetry endpoint
#   5. Monitor for process restarts (if supervisord restarts it)
#
# IPC Mechanism:
#   The target server writes its state to /tmp/target_state.json.
#   When the agent detects a crash (process exit), it reads this file
#   to extract the last payload that was being processed.
#
# Exit Behavior:
#   The agent exits after reporting a crash, since the target container
#   is configured with restart: "no" in docker-compose.yml.
# ============================================================================

import json
import os
import platform
import signal
import sys
import time
import traceback
from datetime import datetime, timezone

import psutil
import requests

# ── Configuration ──────────────────────────────────────────────────────────

# URL of the C2 orchestrator's crash telemetry endpoint
C2_TELEMETRY_URL = os.environ.get(
    "C2_TELEMETRY_URL",
    "http://c2-orchestrator:9000/api/v1/telemetry/crash"
)

# How often to poll the target process (milliseconds)
POLL_INTERVAL_MS = int(os.environ.get("MEMORY_POLL_INTERVAL_MS", 500))
POLL_INTERVAL_SEC = POLL_INTERVAL_MS / 1000.0

# Path to the shared state file written by target_server.py
STATE_FILE = "/tmp/target_state.json"

# Target server process name pattern (for discovery)
TARGET_PROCESS_NAME = "target_server.py"

# Maximum number of C2 report retries
MAX_REPORT_RETRIES = 5

# How long to wait before starting monitoring (let the target start up)
STARTUP_DELAY_SEC = 3

# ── Logging Helper ─────────────────────────────────────────────────────────

def log(level: str, message: str):
    """Structured logging to stdout."""
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    print(f"[{timestamp}] [{level:>5}] [telemetry_agent] {message}", flush=True)


# ── Process Discovery ──────────────────────────────────────────────────────

def find_target_process() -> psutil.Process | None:
    """
    Find the target server process by scanning running processes.

    Searches for a Python process whose command line contains
    'target_server.py'. Returns the psutil.Process object or None.

    Returns:
        psutil.Process or None: The target process if found.
    """
    for proc in psutil.process_iter(["pid", "name", "cmdline"]):
        try:
            cmdline = proc.info.get("cmdline") or []
            cmdline_str = " ".join(cmdline)
            if TARGET_PROCESS_NAME in cmdline_str and proc.pid != os.getpid():
                return proc
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    return None


# ── State File Reading ─────────────────────────────────────────────────────

def read_state_file() -> dict:
    """
    Read the target server's state file.

    The target writes its state to STATE_FILE whenever it processes
    a payload or encounters an error. This file is the IPC bridge
    between the target and the agent.

    Returns:
        dict: The state data, or an empty dict if the file is unreadable.
    """
    try:
        if os.path.exists(STATE_FILE):
            with open(STATE_FILE, "r") as f:
                return json.load(f)
    except (json.JSONDecodeError, IOError) as e:
        log("WARN", f"Failed to read state file: {e}")
    return {}


# ── Crash Reporting ────────────────────────────────────────────────────────

def report_crash_to_c2(
    process_info: dict,
    state: dict,
    exit_code: int | None = None,
) -> bool:
    """
    Send a crash report to the C2 orchestrator.

    Constructs a CrashReportIn payload and POSTs it to the
    telemetry endpoint. Retries on failure with exponential backoff.

    Args:
        process_info: Last known process metrics (CPU, memory).
        state: Contents of the state file at time of crash.
        exit_code: The process exit code (137 = OOM kill, etc.)

    Returns:
        bool: True if the report was successfully delivered to C2.
    """
    # Determine error type from the state file or exit code
    error_type = state.get("error_type", "UnknownCrash")
    if exit_code == 137:
        error_type = "OutOfMemoryError (OOM Kill)"
    elif exit_code == 139:
        error_type = "SegmentationFault (SIGSEGV)"

    # Build the crash report payload
    crash_report = {
        "campaign_id": None,  # C2 will auto-link to active campaign
        "trigger_payload": state.get("last_payload"),
        "trigger_payload_size": state.get("last_payload_size") or state.get("payload_size"),
        "process_pid": process_info.get("pid"),
        "memory_rss_mb": process_info.get("memory_rss_mb"),
        "memory_vms_mb": process_info.get("memory_vms_mb"),
        "cpu_percent": process_info.get("cpu_percent"),
        "error_type": error_type,
        "error_message": state.get("error_message") or state.get("message") or f"Process exited with code {exit_code}",
        "stack_trace": state.get("stack_trace"),
        "hostname": platform.node(),
    }

    log("WARN", f"Reporting crash to C2: {error_type}")
    log("INFO", f"  Payload size: {crash_report['trigger_payload_size']} bytes")
    log("INFO", f"  Memory RSS: {crash_report['memory_rss_mb']} MB")
    log("INFO", f"  PID: {crash_report['process_pid']}")

    # Retry with exponential backoff
    for attempt in range(1, MAX_REPORT_RETRIES + 1):
        try:
            response = requests.post(
                C2_TELEMETRY_URL,
                json=crash_report,
                timeout=10,
                headers={"Content-Type": "application/json"},
            )

            if response.status_code == 201:
                log("INFO", f"✅ Crash report delivered to C2 (attempt {attempt})")
                log("INFO", f"  Response: {response.json()}")
                return True
            else:
                log("WARN", f"C2 returned HTTP {response.status_code}: {response.text}")

        except requests.exceptions.ConnectionError:
            log("WARN", f"C2 unreachable (attempt {attempt}/{MAX_REPORT_RETRIES})")
        except requests.exceptions.Timeout:
            log("WARN", f"C2 request timed out (attempt {attempt}/{MAX_REPORT_RETRIES})")
        except Exception as e:
            log("ERROR", f"Unexpected error reporting to C2: {e}")

        # Exponential backoff: 1s, 2s, 4s, 8s, 16s
        backoff = min(2 ** (attempt - 1), 16)
        log("INFO", f"Retrying in {backoff}s...")
        time.sleep(backoff)

    log("ERROR", f"Failed to deliver crash report after {MAX_REPORT_RETRIES} attempts")
    return False


# ── Monitoring Loop ────────────────────────────────────────────────────────

def collect_process_metrics(process: psutil.Process) -> dict:
    """
    Collect current CPU and memory metrics for the target process.

    Args:
        process: The psutil.Process object for the target.

    Returns:
        dict: Metrics including PID, RSS, VMS, and CPU percent.
    """
    try:
        mem_info = process.memory_info()
        cpu_percent = process.cpu_percent(interval=None)

        return {
            "pid": process.pid,
            "memory_rss_mb": round(mem_info.rss / (1024 * 1024), 2),
            "memory_vms_mb": round(mem_info.vms / (1024 * 1024), 2),
            "cpu_percent": round(cpu_percent, 2),
            "status": process.status(),
        }
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return {"pid": process.pid, "status": "dead"}


def monitor_loop():
    """
    Main monitoring loop.

    1. Find the target process
    2. Poll its health every POLL_INTERVAL_MS
    3. If the process dies, read the state file and report to C2
    4. Exit after reporting (the container is done)
    """
    log("INFO", "=" * 55)
    log("INFO", "FuzzStrike Telemetry Agent v1.0.0")
    log("INFO", f"  C2 Telemetry URL  : {C2_TELEMETRY_URL}")
    log("INFO", f"  Poll Interval     : {POLL_INTERVAL_MS}ms")
    log("INFO", f"  Target Process    : {TARGET_PROCESS_NAME}")
    log("INFO", f"  Hostname          : {platform.node()}")
    log("INFO", "=" * 55)

    # Wait for the target server to start up
    log("INFO", f"Waiting {STARTUP_DELAY_SEC}s for target server to start...")
    time.sleep(STARTUP_DELAY_SEC)

    # ── Step 1: Find the target process ────────────────────────────────
    target_proc = None
    find_attempts = 0
    max_find_attempts = 30  # 30 * 2s = 60 seconds max wait

    while target_proc is None and find_attempts < max_find_attempts:
        target_proc = find_target_process()
        if target_proc is None:
            find_attempts += 1
            log("WARN", f"Target process not found (attempt {find_attempts}/{max_find_attempts})")
            time.sleep(2)

    if target_proc is None:
        log("ERROR", "Target process never appeared. Exiting.")
        sys.exit(1)

    log("INFO", f"Target process found: PID {target_proc.pid}")

    # ── Step 2: Initialize CPU monitoring ──────────────────────────────
    # First call to cpu_percent() returns 0.0 (it needs a previous sample)
    try:
        target_proc.cpu_percent(interval=None)
    except psutil.NoSuchProcess:
        pass

    # Store the last known metrics for crash reporting
    last_metrics = {"pid": target_proc.pid}
    poll_count = 0

    # ── Step 3: Monitoring loop ────────────────────────────────────────
    log("INFO", "Monitoring started. Polling every {}ms...".format(POLL_INTERVAL_MS))

    while True:
        try:
            # Check if the process is still alive
            if not target_proc.is_running():
                raise psutil.NoSuchProcess(target_proc.pid)

            # Collect metrics
            metrics = collect_process_metrics(target_proc)
            last_metrics = metrics
            poll_count += 1

            # Log metrics every 10 polls (5 seconds at 500ms interval)
            if poll_count % 10 == 0:
                log("INFO",
                    f"Target health: PID={metrics['pid']} "
                    f"RSS={metrics.get('memory_rss_mb', '?')}MB "
                    f"CPU={metrics.get('cpu_percent', '?')}% "
                    f"Status={metrics.get('status', '?')}"
                )

            # Check for high memory usage (early warning)
            rss_mb = metrics.get("memory_rss_mb", 0)
            if rss_mb > 200:
                log("WARN", f"⚠️  High memory usage: {rss_mb}MB RSS")

        except psutil.NoSuchProcess:
            # ══════════════════════════════════════════════════════════
            # CRASH DETECTED — The target process has died
            # ══════════════════════════════════════════════════════════
            log("ERROR", "🔥 TARGET PROCESS HAS DIED!")
            log("ERROR", f"  Last known PID: {target_proc.pid}")

            # Try to get the exit code
            exit_code = None
            try:
                exit_code = target_proc.wait(timeout=1)
                log("ERROR", f"  Exit code: {exit_code}")
            except Exception:
                log("WARN", "  Could not retrieve exit code")

            # Read the state file for crash context
            state = read_state_file()
            log("INFO", f"  State file contents: {json.dumps(state, indent=2)}")

            # Report the crash to C2
            report_crash_to_c2(last_metrics, state, exit_code)

            # Exit the agent — the container's job is done
            log("INFO", "Telemetry agent exiting after crash report.")
            sys.exit(0)

        except psutil.AccessDenied:
            log("WARN", "Access denied when reading target process metrics")

        except Exception as e:
            log("ERROR", f"Monitoring error: {e}")
            log("ERROR", traceback.format_exc())

        # Sleep until next poll
        time.sleep(POLL_INTERVAL_SEC)


# ── Entry Point ────────────────────────────────────────────────────────────

def handle_sigterm(signum, frame):
    """Handle SIGTERM from supervisord/Docker for graceful shutdown."""
    log("INFO", "Received SIGTERM — shutting down gracefully")
    sys.exit(0)


if __name__ == "__main__":
    # Register signal handlers
    signal.signal(signal.SIGTERM, handle_sigterm)

    try:
        monitor_loop()
    except KeyboardInterrupt:
        log("INFO", "Agent interrupted (KeyboardInterrupt)")
    except Exception as e:
        log("ERROR", f"Agent fatal error: {e}")
        log("ERROR", traceback.format_exc())
        sys.exit(1)
