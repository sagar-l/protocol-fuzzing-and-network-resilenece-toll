# ============================================================================
# FuzzStrike Target Environment — Vulnerable TCP/UDP Server
# ============================================================================
# An INTENTIONALLY VULNERABLE server designed to simulate a real-world
# target application with exploitable weaknesses.
#
# Vulnerability Profile:
#   1. OutOfMemoryError when payload exceeds 1MB (TCP)
#   2. No input validation or sanitization
#   3. Unbounded buffer accumulation
#   4. DNS label parsing crash on oversized labels (UDP)
#   5. DHCP magic cookie validation crash (UDP)
#   6. Protocol parser crashes on malformed packets (UDP)
#
# Protocols:
#   - TCP (port 7777) — Raw JSON payload processing
#   - UDP (port 5353) — DNS/DHCP/RADIUS packet processing
#
# WARNING: This server is INTENTIONALLY insecure. It exists solely to be
# fuzzed. Never deploy this in any environment other than an isolated
# Docker container within the FuzzStrike test network.
# ============================================================================

import struct
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
UDP_PORT = int(os.environ.get("UDP_PORT", 5353))
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


# ── UDP Protocol Packet Processing (Intentionally Vulnerable) ─────────────

def process_protocol_packet(data: bytes, addr: tuple) -> bytes:
    """
    Process a raw binary protocol packet. This simulates a network device
    that parses DNS/DHCP/RADIUS packets with intentional vulnerabilities.

    Vulnerabilities:
        - DNS: Crashes on labels > 63 bytes (spec violation)
        - DHCP: Crashes on invalid magic cookie
        - Generic: Crashes on packets > 64KB
    """
    global LAST_PAYLOAD, LAST_PAYLOAD_SIZE

    packet_size = len(data)
    LAST_PAYLOAD_SIZE = packet_size
    LAST_PAYLOAD = data.hex()[:10240]

    log("INFO", f"UDP packet from {addr[0]}:{addr[1]} — {packet_size} bytes")

    write_state({
        "status": "processing_udp",
        "payload_size": packet_size,
        "source": f"{addr[0]}:{addr[1]}",
    })

    # ══════════════════════════════════════════════════════════════════
    # VULNERABILITY: Crash on oversized packets (> 64KB)
    # ══════════════════════════════════════════════════════════════════
    if packet_size > 65535:
        log("ERROR", f"!!! UDP PACKET TOO LARGE: {packet_size} bytes !!!")
        write_state({
            "status": "crashed",
            "error_type": "BufferOverflowError",
            "error_message": f"UDP packet of {packet_size} bytes exceeded 64KB limit",
        })
        os._exit(139)  # SIGSEGV simulation

    # ── Try DNS parsing ─────────────────────────────────────────────
    if packet_size >= 12:
        try:
            # Parse DNS header
            txn_id, flags, qd_count = struct.unpack("!HHH", data[:6])

            # Parse question section labels
            offset = 12
            while offset < len(data):
                label_len = data[offset]
                if label_len == 0:
                    break  # End of domain name

                # VULNERABILITY: Crash on labels > 63 bytes
                # RFC 1035 says max label is 63 bytes. Real parsers crash here.
                if label_len > 63:
                    log("ERROR", f"!!! DNS LABEL OVERFLOW: label_len={label_len} > 63 !!!")
                    write_state({
                        "status": "crashed",
                        "error_type": "DNSLabelOverflow",
                        "error_message": f"DNS label length {label_len} exceeds max 63 bytes",
                    })
                    os._exit(134)  # SIGABRT simulation

                offset += 1 + label_len

            log("INFO", f"DNS query parsed: txn_id={txn_id:#06x}, questions={qd_count}")
            return struct.pack("!HH", txn_id, 0x8180)  # Valid response flags

        except (struct.error, IndexError):
            log("WARN", "Malformed DNS packet — parse failed")

    # ── Try DHCP parsing ────────────────────────────────────────────
    if packet_size >= 240:
        try:
            # Check DHCP magic cookie at offset 236
            cookie = data[236:240]
            valid_cookie = b"\x63\x82\x53\x63"

            if cookie != valid_cookie:
                # VULNERABILITY: Crash on invalid magic cookie
                log("ERROR", f"!!! DHCP INVALID MAGIC COOKIE: {cookie.hex()} !!!")
                write_state({
                    "status": "crashed",
                    "error_type": "DHCPMagicCookieError",
                    "error_message": f"Invalid DHCP magic cookie: {cookie.hex()}",
                })
                os._exit(136)  # Simulated crash

            log("INFO", f"DHCP packet parsed: op={data[0]}, htype={data[1]}")
            return b"\x02"  # BOOTREPLY

        except (IndexError, struct.error):
            log("WARN", "Malformed DHCP packet — parse failed")

    # ── Generic binary response ─────────────────────────────────────
    write_state({"status": "healthy", "payload_size": packet_size})
    return b"ACK"


def run_udp_server():
    """
    Run the UDP server for protocol-specific packet processing.
    Handles DNS, DHCP, and RADIUS fuzzed packets.
    """
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        udp_socket.bind((BIND_HOST, UDP_PORT))
        log("INFO", f"UDP server listening on {BIND_HOST}:{UDP_PORT}")

        while True:
            try:
                data, addr = udp_socket.recvfrom(65536)
                if data:
                    response = process_protocol_packet(data, addr)
                    if response:
                        udp_socket.sendto(response, addr)
            except Exception as e:
                log("ERROR", f"UDP error: {e}")

    except OSError as e:
        log("ERROR", f"Failed to bind UDP to {BIND_HOST}:{UDP_PORT}: {e}")
    finally:
        udp_socket.close()


# ── Main Server Loop ───────────────────────────────────────────────────────

def main():
    """
    Start both TCP and UDP vulnerable servers.
    TCP handles raw JSON payloads, UDP handles protocol packets.
    """
    log("INFO", "=" * 55)
    log("INFO", "FuzzStrike Vulnerable Target Server v1.0.0")
    log("INFO", f"  TCP Listening on {BIND_HOST}:{TARGET_PORT}")
    log("INFO", f"  UDP Listening on {BIND_HOST}:{UDP_PORT}")
    log("INFO", f"  Crash threshold: {CRASH_THRESHOLD_BYTES:,} bytes (1 MB)")
    log("INFO", f"  PID: {SERVER_PID}")
    log("INFO", "  ⚠️  THIS SERVER IS INTENTIONALLY VULNERABLE")
    log("INFO", "  Supported: TCP, DNS, DHCP, OSPF, LLDP, RADIUS")
    log("INFO", "=" * 55)

    # Write initial state
    write_state({"status": "starting"})

    # ── Start UDP server in a background thread ────────────────────
    udp_thread = threading.Thread(target=run_udp_server, daemon=True)
    udp_thread.start()
    log("INFO", "UDP protocol server started in background thread")

    # ── Start TCP server (main thread) ─────────────────────────────
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        server_socket.bind((BIND_HOST, TARGET_PORT))
        server_socket.listen(128)

        log("INFO", f"TCP server listening on {BIND_HOST}:{TARGET_PORT}")
        write_state({"status": "healthy"})

        while True:
            try:
                client_socket, address = server_socket.accept()
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
        log("ERROR", f"Failed to bind TCP to {BIND_HOST}:{TARGET_PORT}: {e}")
        sys.exit(1)
    finally:
        server_socket.close()
        write_state({"status": "stopped"})
        log("INFO", "Server stopped")


if __name__ == "__main__":
    main()
