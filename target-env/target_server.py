# ============================================================================
# FuzzStrike Target Environment — Vulnerable TCP Server
# ============================================================================
# An INTENTIONALLY VULNERABLE TCP server designed to simulate a real-world
# target application with exploitable weaknesses.
#
# Vulnerability Profile:
#   1. OutOfMemoryError when payload exceeds 1MB (primary crash trigger)
#   2. No input validation or sanitization
#   3. Unbounded buffer accumulation
#   4. Single-threaded — one bad payload blocks all connections
#
# Protocol:
#   - Accepts raw TCP connections on TARGET_PORT (default: 7777)
#   - Reads incoming data until the client closes the connection
#   - Attempts to parse the data as JSON
#   - Sends back a simple ACK or ERROR response
#   - Crashes spectacularly on payloads > 1MB
#
# WARNING: This server is INTENTIONALLY insecure. It exists solely to be
# fuzzed. Never deploy this in any environment other than an isolated
# Docker container within the FuzzStrike test network.
# ============================================================================

import json
import os
import signal
import socket
import sys
import threading
import time
import traceback
from datetime import datetime, timezone

# ── Configuration ──────────────────────────────────────────────────────────
TARGET_PORT = int(os.environ.get("TARGET_PORT", 7777))
BIND_HOST = "0.0.0.0"

# The size threshold that triggers a simulated OutOfMemoryError.
# Any payload larger than this will cause the server to crash.
CRASH_THRESHOLD_BYTES = 1 * 1024 * 1024  # 1 MB

# Maximum bytes to read per recv() call
RECV_BUFFER_SIZE = 65536  # 64 KB chunks

# Global state for telemetry agent to read
LAST_PAYLOAD = None
LAST_PAYLOAD_SIZE = 0
SERVER_PID = os.getpid()

# Shared file for inter-process communication with agent.py
STATE_FILE = "/tmp/target_state.json"

# ── Logging Helper ─────────────────────────────────────────────────────────

def log(level: str, message: str):
    """Structured logging to stdout (captured by supervisord)."""
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    print(f"[{timestamp}] [{level:>5}] [target_server] {message}", flush=True)


# ── State Persistence (for agent.py) ──────────────────────────────────────

def write_state(state: dict):
    """
    Write the current server state to a shared JSON file.

    The telemetry agent reads this file to know what payload was
    being processed when a crash occurred. This is a simple IPC
    mechanism that works within a single container.
    """
    global LAST_PAYLOAD, LAST_PAYLOAD_SIZE

    state.update({
        "pid": SERVER_PID,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "last_payload_size": LAST_PAYLOAD_SIZE,
    })

    # Write the last payload content (truncated for safety)
    if LAST_PAYLOAD:
        # Store at most 10KB of the payload for crash analysis
        state["last_payload"] = LAST_PAYLOAD[:10240]

    try:
        with open(STATE_FILE, "w") as f:
            json.dump(state, f)
    except Exception as e:
        log("WARN", f"Failed to write state file: {e}")


# ── Payload Processing (Intentionally Vulnerable) ─────────────────────────

def process_payload(data: bytes) -> str:
    """
    Process an incoming payload. This is where the vulnerabilities live.

    The function intentionally:
    1. Accumulates the entire payload in memory (no streaming)
    2. Attempts to allocate a massive buffer on large payloads
    3. Has no timeout or size limit enforcement
    4. Performs no input sanitization

    Args:
        data: Raw bytes received from the TCP connection.

    Returns:
        str: Response message to send back to the client.

    Raises:
        MemoryError: When payload exceeds CRASH_THRESHOLD_BYTES.
    """
    global LAST_PAYLOAD, LAST_PAYLOAD_SIZE

    payload_size = len(data)
    LAST_PAYLOAD_SIZE = payload_size

    try:
        payload_str = data.decode("utf-8", errors="replace")
    except Exception:
        payload_str = str(data)

    LAST_PAYLOAD = payload_str

    # Write state for the telemetry agent
    write_state({
        "status": "processing",
        "payload_size": payload_size,
    })

    log("INFO", f"Received payload: {payload_size} bytes")

    # ══════════════════════════════════════════════════════════════════
    # VULNERABILITY #1: OutOfMemoryError on large payloads
    # ══════════════════════════════════════════════════════════════════
    # When the payload exceeds 1MB, we simulate what happens in many
    # real-world applications: attempting to process an oversized input
    # causes uncontrolled memory allocation and an OOM crash.
    # ══════════════════════════════════════════════════════════════════
    if payload_size > CRASH_THRESHOLD_BYTES:
        log("ERROR", f"PAYLOAD TOO LARGE: {payload_size} bytes exceeds "
                      f"threshold of {CRASH_THRESHOLD_BYTES} bytes")

        # Simulate memory exhaustion by allocating a massive list
        # This will trigger a MemoryError or cause the OS to OOM-kill us
        write_state({
            "status": "crashing",
            "error_type": "OutOfMemoryError",
            "payload_size": payload_size,
            "message": f"Payload of {payload_size} bytes exceeded "
                       f"maximum of {CRASH_THRESHOLD_BYTES} bytes",
        })

        log("ERROR", "!!! SIMULATING OutOfMemoryError — ALLOCATING MASSIVE BUFFER !!!")

        # Force a crash by raising MemoryError directly
        # In a real scenario, this would be: massive_list = [0] * (10**9)
        raise MemoryError(
            f"OutOfMemoryError: Payload of {payload_size} bytes caused "
            f"uncontrolled memory allocation. Server is crashing."
        )

    # ── Normal processing path ─────────────────────────────────────────
    # Try to parse as JSON (many real protocols use JSON)
    try:
        parsed = json.loads(payload_str)
        key_count = len(parsed) if isinstance(parsed, dict) else "N/A"

        log("INFO", f"Parsed JSON payload: {key_count} keys, {payload_size} bytes")

        write_state({
            "status": "healthy",
            "payload_size": payload_size,
            "parsed_keys": key_count,
        })

        return f"ACK|OK|{payload_size}|keys={key_count}"

    except json.JSONDecodeError as e:
        log("WARN", f"Invalid JSON payload ({payload_size} bytes): {str(e)[:100]}")

        write_state({
            "status": "healthy",
            "payload_size": payload_size,
            "parse_error": str(e)[:200],
        })

        return f"ACK|PARSE_ERROR|{payload_size}|{str(e)[:100]}"


# ── Connection Handler ─────────────────────────────────────────────────────

def handle_connection(client_socket: socket.socket, address: tuple):
    """
    Handle a single TCP connection.

    Reads all data from the client, processes it, and sends a response.
    Each connection is handled in a separate thread.

    Args:
        client_socket: The connected client socket.
        address: The (host, port) tuple of the remote client.
    """
    log("INFO", f"Connection from {address[0]}:{address[1]}")

    try:
        # Accumulate all incoming data
        # WARNING: This is intentionally unbounded — a vulnerability!
        data = b""
        client_socket.settimeout(5.0)  # 5 second read timeout per chunk

        while True:
            try:
                chunk = client_socket.recv(RECV_BUFFER_SIZE)
                if not chunk:
                    break  # Client closed the connection
                data += chunk
            except socket.timeout:
                break  # No more data coming
            except ConnectionResetError:
                log("WARN", f"Connection reset by {address[0]}:{address[1]}")
                return

        if not data:
            log("DEBUG", f"Empty payload from {address[0]}:{address[1]}")
            return

        # Process the accumulated payload
        response = process_payload(data)

        # Send response back to client
        try:
            client_socket.sendall(response.encode("utf-8"))
        except BrokenPipeError:
            log("WARN", "Client disconnected before response could be sent")

    except MemoryError as e:
        # ════════════════════════════════════════════════════════════
        # CRASH PATH — This is the intentional vulnerability trigger
        # ════════════════════════════════════════════════════════════
        log("ERROR", f"!!! FATAL: {e} !!!")
        log("ERROR", "Server is crashing due to memory exhaustion!")

        # Try to send an error response before dying
        try:
            error_response = f"ERROR|CRASH|OutOfMemoryError|{str(e)}"
            client_socket.sendall(error_response.encode("utf-8"))
        except Exception:
            pass

        # Write crash state for the telemetry agent
        write_state({
            "status": "crashed",
            "error_type": "OutOfMemoryError",
            "error_message": str(e),
            "stack_trace": traceback.format_exc(),
        })

        # Exit with error code — supervisord and agent.py will detect this
        log("ERROR", "Exiting with code 137 (OOM Kill simulation)")
        os._exit(137)  # 137 = 128 + 9 (SIGKILL) — standard OOM kill exit code

    except Exception as e:
        log("ERROR", f"Unexpected error processing payload: {e}")
        log("ERROR", traceback.format_exc())

        write_state({
            "status": "error",
            "error_type": type(e).__name__,
            "error_message": str(e),
            "stack_trace": traceback.format_exc(),
        })

        try:
            error_response = f"ERROR|EXCEPTION|{type(e).__name__}|{str(e)[:200]}"
            client_socket.sendall(error_response.encode("utf-8"))
        except Exception:
            pass

    finally:
        try:
            client_socket.close()
        except Exception:
            pass


# ── Main Server Loop ───────────────────────────────────────────────────────

def main():
    """
    Start the vulnerable TCP server.

    Binds to BIND_HOST:TARGET_PORT and accepts connections in a loop.
    Each connection is handled in a separate thread (intentionally
    unbounded thread creation — another vulnerability).
    """
    log("INFO", "=" * 55)
    log("INFO", "FuzzStrike Vulnerable Target Server v1.0.0")
    log("INFO", f"  Listening on {BIND_HOST}:{TARGET_PORT}")
    log("INFO", f"  Crash threshold: {CRASH_THRESHOLD_BYTES:,} bytes (1 MB)")
    log("INFO", f"  PID: {SERVER_PID}")
    log("INFO", "  ⚠️  THIS SERVER IS INTENTIONALLY VULNERABLE")
    log("INFO", "=" * 55)

    # Write initial state
    write_state({"status": "starting"})

    # Create the TCP server socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        server_socket.bind((BIND_HOST, TARGET_PORT))
        server_socket.listen(128)  # Backlog of 128 pending connections

        log("INFO", f"Server listening on {BIND_HOST}:{TARGET_PORT}")
        write_state({"status": "healthy"})

        # Accept connections forever
        while True:
            try:
                client_socket, address = server_socket.accept()

                # Handle each connection in a new thread
                thread = threading.Thread(
                    target=handle_connection,
                    args=(client_socket, address),
                    daemon=True,
                )
                thread.start()

            except KeyboardInterrupt:
                log("INFO", "Server shutting down (KeyboardInterrupt)")
                break
            except Exception as e:
                log("ERROR", f"Error accepting connection: {e}")

    except OSError as e:
        log("ERROR", f"Failed to bind to {BIND_HOST}:{TARGET_PORT}: {e}")
        sys.exit(1)
    finally:
        server_socket.close()
        write_state({"status": "stopped"})
        log("INFO", "Server stopped")


if __name__ == "__main__":
    main()
