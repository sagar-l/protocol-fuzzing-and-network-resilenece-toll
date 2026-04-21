// ============================================================================
// FuzzStrike Attack Node — PayloadDispatcher
// ============================================================================
// The main operational loop that coordinates between the C2 server and
// the Netty TCP client. This is the "brain" of the attack node.
//
// Operational Flow:
//   1. Poll the C2 server for the active campaign's pending payloads
//   2. If payloads are available, dispatch them via NettyTcpClient
//   3. Collect results from the ResponseCollector
//   4. ACK the delivered payloads back to the C2 server
//   5. Sleep and repeat
//
// The dispatcher runs in its own thread and can be started/stopped
// cleanly via the running flag.
// ============================================================================

package com.fuzzstrike.attacknode.client;

import com.fuzzstrike.attacknode.handler.ResponseCollector;
import com.fuzzstrike.attacknode.model.PayloadBatch;
import com.fuzzstrike.attacknode.service.C2ApiClient;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;

/**
 * Orchestrates the polling → dispatch → acknowledge loop.
 *
 * <p>The dispatcher runs continuously, polling the C2 server for
 * pending payloads and dispatching them to the target via the
 * Netty TCP client. It handles the full lifecycle including
 * error recovery and graceful shutdown.</p>
 *
 * <p>Usage:
 * <pre>{@code
 * PayloadDispatcher dispatcher = new PayloadDispatcher(c2Client, nettyClient, 2000);
 * Thread dispatcherThread = new Thread(dispatcher::start);
 * dispatcherThread.start();
 * // ... later ...
 * dispatcher.stop();
 * }</pre>
 */
public class PayloadDispatcher {

    private static final Logger log = LoggerFactory.getLogger(PayloadDispatcher.class);

    // ── Dependencies ──────────────────────────────────────────────────────

    /** HTTP client for communicating with the C2 orchestrator */
    private final C2ApiClient c2Client;

    /** Netty TCP client for firing payloads at the target */
    private final NettyTcpClient nettyClient;

    /** Time between polling attempts (milliseconds) */
    private final long pollIntervalMs;

    /** Flag to control the polling loop */
    private volatile boolean running = false;

    // ── Constructor ───────────────────────────────────────────────────────

    /**
     * Create a new PayloadDispatcher.
     *
     * @param c2Client       Client for C2 API communication
     * @param nettyClient    Netty TCP client for payload delivery
     * @param pollIntervalMs Milliseconds between C2 polling attempts
     */
    public PayloadDispatcher(C2ApiClient c2Client, NettyTcpClient nettyClient, long pollIntervalMs) {
        this.c2Client = c2Client;
        this.nettyClient = nettyClient;
        this.pollIntervalMs = pollIntervalMs;
    }

    // ── Public API ────────────────────────────────────────────────────────

    /**
     * Start the polling → dispatch → acknowledge loop.
     *
     * <p>This method blocks the calling thread. It should be run in
     * a dedicated thread or executor. The loop continues until
     * {@link #stop()} is called.</p>
     *
     * <p>The loop is resilient to transient failures:
     * <ul>
     *   <li>C2 unreachable → Log and retry after poll interval</li>
     *   <li>Empty batch → Log and retry after poll interval</li>
     *   <li>Dispatch failure → Log, skip ACK, retry next cycle</li>
     * </ul>
     */
    public void start() {
        running = true;
        log.info("PayloadDispatcher started (poll interval: {}ms)", pollIntervalMs);

        while (running) {
            try {
                // ── Step 1: Discover active campaigns ─────────────────
                List<Integer> activeCampaignIds = c2Client.getActiveCampaignIds();

                if (activeCampaignIds.isEmpty()) {
                    log.debug("No active campaigns found, sleeping...");
                    sleep();
                    continue;
                }

                // ── Step 2: Process each active campaign ──────────────
                for (int campaignId : activeCampaignIds) {
                    if (!running) break;

                    processCampaign(campaignId);
                }

            } catch (Exception e) {
                // Top-level catch — never let the dispatcher thread die
                log.error("Dispatcher loop error: {}", e.getMessage(), e);
            }

            // ── Step 3: Sleep before next poll ────────────────────────
            sleep();
        }

        log.info("PayloadDispatcher stopped");
    }

    /**
     * Signal the dispatcher to stop after the current iteration.
     *
     * <p>The dispatcher will complete any in-progress batch dispatch
     * before stopping. This is a cooperative shutdown — it does not
     * forcefully interrupt the dispatcher thread.</p>
     */
    public void stop() {
        log.info("PayloadDispatcher stop requested");
        running = false;
    }

    /**
     * Check if the dispatcher is currently running.
     */
    public boolean isRunning() {
        return running;
    }

    // ── Internal Methods ──────────────────────────────────────────────────

    /**
     * Process a single campaign: fetch payloads, dispatch, acknowledge.
     *
     * @param campaignId The campaign to process.
     */
    private void processCampaign(int campaignId) {
        try {
            // Fetch a batch of pending payloads
            PayloadBatch batch = c2Client.fetchPayloadBatch(campaignId);

            if (batch == null || batch.isEmpty()) {
                log.debug("Campaign {} has no pending payloads", campaignId);
                return;
            }

            log.info("Processing campaign {}: {} payloads in batch",
                    campaignId, batch.size());

            // Dispatch the batch via Netty
            ResponseCollector collector = nettyClient.fireBatch(batch);

            // Build the ACK lists from the results
            List<Integer> deliveredIds = collector.getDeliveredPayloadIds();
            List<Integer> crashedIds = collector.getCrashedPayloadIds();

            // Also include connection_reset / connection_refused as "delivered"
            // since we did attempt to send them
            List<Integer> allAttemptedIds = collector.getResults().stream()
                    .map(r -> r.getPayloadId())
                    .collect(java.util.stream.Collectors.toList());

            // Send acknowledgment back to C2
            if (!allAttemptedIds.isEmpty()) {
                c2Client.acknowledgePayloads(campaignId, allAttemptedIds, crashedIds);
                log.info("ACK sent: campaign={}, delivered={}, crashes={}",
                        campaignId, allAttemptedIds.size(), crashedIds.size());
            }

            // Log the batch summary
            log.info("Campaign {} batch result: {}", campaignId, collector.getSummary());

        } catch (Exception e) {
            log.error("Error processing campaign {}: {}", campaignId, e.getMessage(), e);
        }
    }

    /**
     * Sleep for the configured poll interval.
     * Exits early if the running flag is cleared.
     */
    private void sleep() {
        try {
            Thread.sleep(pollIntervalMs);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            log.debug("Sleep interrupted");
        }
    }
}
