// ============================================================================
// FuzzStrike Attack Node — Application Entry Point
// ============================================================================
// Main class that bootstraps the entire attack node:
//   1. Parse configuration from environment variables
//   2. Wait for the C2 server to become healthy
//   3. Initialize the Netty TCP client
//   4. Start the payload dispatcher loop
//   5. Register shutdown hooks for graceful cleanup
//
// Environment Variables:
//   C2_BASE_URL       — Base URL of the C2 orchestrator (default: http://localhost:9000)
//   TARGET_HOST       — Target hostname (default: localhost) [used as fallback]
//   TARGET_PORT       — Target TCP port (default: 7777) [used as fallback]
//   BATCH_SIZE        — Payloads per batch (default: 50)
//   POLL_INTERVAL_MS  — Polling interval in ms (default: 2000)
//   WORKER_THREADS    — Netty I/O threads (default: 0 = auto)
// ============================================================================

package com.fuzzstrike.attacknode;

import com.fuzzstrike.attacknode.client.NettyTcpClient;
import com.fuzzstrike.attacknode.client.PayloadDispatcher;
import com.fuzzstrike.attacknode.service.C2ApiClient;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Application entry point for the FuzzStrike Attack Node.
 *
 * <p>This class performs the following startup sequence:
 * <ol>
 *   <li>Read configuration from environment variables</li>
 *   <li>Wait for the C2 orchestrator to become reachable</li>
 *   <li>Initialize the Netty TCP client (EventLoopGroup)</li>
 *   <li>Create and start the PayloadDispatcher</li>
 *   <li>Register a JVM shutdown hook for graceful cleanup</li>
 * </ol>
 *
 * <p>The main thread blocks on the dispatcher loop. Shutdown is
 * triggered via SIGTERM/SIGINT (Docker stop) or JVM shutdown.</p>
 */
public class AttackNodeApplication {

    private static final Logger log = LoggerFactory.getLogger(AttackNodeApplication.class);

    // ── Banner ────────────────────────────────────────────────────────────

    private static final String BANNER = """
            
            ╔═══════════════════════════════════════════════════════╗
            ║       FuzzStrike Attack Node v1.0.0                  ║
            ║       High-Throughput Async TCP Payload Engine        ║
            ║       Powered by Netty 4.1 / Java 17                 ║
            ╚═══════════════════════════════════════════════════════╝
            """;

    // ── Main Entry Point ──────────────────────────────────────────────────

    public static void main(String[] args) {
        System.out.println(BANNER);

        // ── Step 1: Parse configuration ───────────────────────────────
        String c2BaseUrl = getEnv("C2_BASE_URL", "http://localhost:9000");
        int batchSize = getEnvInt("BATCH_SIZE", 50);
        long pollIntervalMs = getEnvLong("POLL_INTERVAL_MS", 2000);
        int workerThreads = getEnvInt("WORKER_THREADS", 0);

        log.info("Configuration:");
        log.info("  C2 Base URL      : {}", c2BaseUrl);
        log.info("  Batch Size       : {}", batchSize);
        log.info("  Poll Interval    : {}ms", pollIntervalMs);
        log.info("  Worker Threads   : {}", workerThreads == 0 ? "auto" : workerThreads);

        // ── Step 2: Wait for C2 to become healthy ─────────────────────
        C2ApiClient c2Client = new C2ApiClient(c2BaseUrl, batchSize);
        waitForC2(c2Client);

        // ── Step 3: Initialize Netty TCP client ───────────────────────
        NettyTcpClient nettyClient = new NettyTcpClient(workerThreads);

        // ── Step 4: Create the dispatcher ─────────────────────────────
        PayloadDispatcher dispatcher = new PayloadDispatcher(c2Client, nettyClient, pollIntervalMs);

        // ── Step 5: Register shutdown hook ─────────────────────────────
        // This ensures graceful cleanup when Docker sends SIGTERM
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            log.info("Shutdown signal received — cleaning up...");
            dispatcher.stop();
            nettyClient.shutdown();
            log.info("Shutdown complete. Goodbye!");
        }, "shutdown-hook"));

        // ── Step 6: Start the dispatcher (blocks this thread) ─────────
        log.info("Starting payload dispatcher...");
        dispatcher.start();
    }

    // ── Helper Methods ────────────────────────────────────────────────────

    /**
     * Wait for the C2 orchestrator to become healthy.
     *
     * <p>Retries the health check every 3 seconds up to 60 attempts
     * (3 minutes total). This handles the Docker startup ordering
     * where the C2 container may not be ready yet.</p>
     *
     * @param c2Client The C2 API client to health-check with.
     */
    private static void waitForC2(C2ApiClient c2Client) {
        log.info("Waiting for C2 orchestrator to become healthy...");

        int maxAttempts = 60;
        int sleepMs = 3000;

        for (int attempt = 1; attempt <= maxAttempts; attempt++) {
            if (c2Client.isC2Healthy()) {
                log.info("C2 orchestrator is healthy! (attempt {}/{})", attempt, maxAttempts);
                return;
            }

            log.info("C2 not ready (attempt {}/{}), retrying in {}ms...",
                    attempt, maxAttempts, sleepMs);

            try {
                Thread.sleep(sleepMs);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                log.error("Interrupted while waiting for C2");
                System.exit(1);
            }
        }

        log.error("C2 orchestrator did not become healthy after {} attempts. Exiting.", maxAttempts);
        System.exit(1);
    }

    /**
     * Read a string environment variable with a default fallback.
     */
    private static String getEnv(String name, String defaultValue) {
        String value = System.getenv(name);
        return (value != null && !value.isEmpty()) ? value : defaultValue;
    }

    /**
     * Read an integer environment variable with a default fallback.
     */
    private static int getEnvInt(String name, int defaultValue) {
        String value = System.getenv(name);
        if (value != null && !value.isEmpty()) {
            try {
                return Integer.parseInt(value);
            } catch (NumberFormatException e) {
                log.warn("Invalid integer for env var {}: '{}', using default {}", name, value, defaultValue);
            }
        }
        return defaultValue;
    }

    /**
     * Read a long environment variable with a default fallback.
     */
    private static long getEnvLong(String name, long defaultValue) {
        String value = System.getenv(name);
        if (value != null && !value.isEmpty()) {
            try {
                return Long.parseLong(value);
            } catch (NumberFormatException e) {
                log.warn("Invalid long for env var {}: '{}', using default {}", name, value, defaultValue);
            }
        }
        return defaultValue;
    }
}
