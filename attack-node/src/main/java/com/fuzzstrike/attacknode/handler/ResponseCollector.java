// ============================================================================
// FuzzStrike Attack Node — ResponseCollector
// ============================================================================
// Thread-safe aggregator for collecting AttackResult instances from
// multiple concurrent AttackChannelHandler instances.
//
// The collector is created for each batch dispatch and provides:
//   1. Concurrent result collection (ConcurrentLinkedQueue)
//   2. A CountDownLatch for the dispatcher to await batch completion
//   3. Summary statistics for logging and ACK payload construction
//
// Thread-safety: Fully thread-safe. Multiple Netty EventLoop threads
// will call addResult() concurrently.
// ============================================================================

package com.fuzzstrike.attacknode.handler;

import com.fuzzstrike.attacknode.model.AttackResult;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

/**
 * Collects and aggregates results from parallel payload deliveries.
 *
 * <p>One ResponseCollector is created per batch dispatch. It uses a
 * CountDownLatch to allow the dispatcher to block until all payloads
 * in the batch have been delivered (or timed out).</p>
 *
 * <p>Usage:
 * <pre>{@code
 * ResponseCollector collector = new ResponseCollector(batchSize);
 * // ... dispatch payloads, each handler references this collector ...
 * collector.awaitCompletion(30, TimeUnit.SECONDS);
 * List<AttackResult> results = collector.getResults();
 * }</pre>
 */
public class ResponseCollector {

    private static final Logger log = LoggerFactory.getLogger(ResponseCollector.class);

    // ── Thread-safe Collection ────────────────────────────────────────────

    /**
     * Lock-free queue for concurrent result insertion.
     * ConcurrentLinkedQueue is chosen over synchronized lists because:
     * - Non-blocking: No thread contention under high concurrency
     * - Unbounded: Handles bursts without capacity planning
     * - FIFO ordering: Results appear in delivery-completion order
     */
    private final ConcurrentLinkedQueue<AttackResult> results = new ConcurrentLinkedQueue<>();

    /**
     * Latch that counts down as each payload result arrives.
     * The dispatcher thread blocks on this until the entire batch
     * is complete or the timeout expires.
     */
    private final CountDownLatch completionLatch;

    /** Expected number of results (for progress tracking) */
    private final int expectedCount;

    // ── Constructor ───────────────────────────────────────────────────────

    /**
     * Create a collector expecting a specific number of results.
     *
     * @param expectedCount The number of payloads in the batch.
     *                      The completion latch is initialized to this value.
     */
    public ResponseCollector(int expectedCount) {
        this.expectedCount = expectedCount;
        this.completionLatch = new CountDownLatch(expectedCount);
    }

    // ── Public API ────────────────────────────────────────────────────────

    /**
     * Add a result from a completed payload delivery.
     *
     * <p>Called by AttackChannelHandler from Netty EventLoop threads.
     * This method is fully thread-safe and non-blocking.</p>
     *
     * @param result The delivery result to record.
     */
    public void addResult(AttackResult result) {
        results.add(result);
        completionLatch.countDown();

        long remaining = completionLatch.getCount();
        if (remaining % 10 == 0 && remaining > 0) {
            log.debug("Batch progress: {}/{} payloads complete",
                    expectedCount - remaining, expectedCount);
        }
    }

    /**
     * Block until all expected results have arrived or timeout expires.
     *
     * @param timeout  Maximum time to wait.
     * @param unit     Time unit for the timeout.
     * @return true if all results arrived, false if timeout expired.
     * @throws InterruptedException if the waiting thread is interrupted.
     */
    public boolean awaitCompletion(long timeout, TimeUnit unit) throws InterruptedException {
        log.info("Awaiting batch completion ({} payloads, timeout={}{})",
                expectedCount, timeout, unit.toString().toLowerCase());

        boolean completed = completionLatch.await(timeout, unit);

        if (completed) {
            log.info("Batch complete: all {} payloads delivered", expectedCount);
        } else {
            long received = expectedCount - completionLatch.getCount();
            log.warn("Batch timeout: {}/{} payloads delivered", received, expectedCount);
        }

        return completed;
    }

    /**
     * Get all collected results as an unmodifiable list.
     *
     * <p>Should be called after awaitCompletion() returns.
     * Results are in delivery-completion order (not payload ID order).</p>
     *
     * @return Unmodifiable list of all collected results.
     */
    public List<AttackResult> getResults() {
        return Collections.unmodifiableList(new ArrayList<>(results));
    }

    /**
     * Get the IDs of all delivered payloads (regardless of target response).
     *
     * @return List of payload IDs that were successfully sent.
     */
    public List<Integer> getDeliveredPayloadIds() {
        return results.stream()
                .filter(AttackResult::isDelivered)
                .map(AttackResult::getPayloadId)
                .collect(Collectors.toList());
    }

    /**
     * Get the IDs of payloads that likely caused a crash.
     *
     * <p>A "likely crash" is determined by the AttackChannelHandler
     * based on connection behavior (reset, refused, etc.).</p>
     *
     * @return List of payload IDs associated with likely crashes.
     */
    public List<Integer> getCrashedPayloadIds() {
        return results.stream()
                .filter(AttackResult::isLikelyCrash)
                .map(AttackResult::getPayloadId)
                .collect(Collectors.toList());
    }

    /**
     * Get a summary of the batch results for logging.
     *
     * @return Formatted summary string.
     */
    public String getSummary() {
        long delivered = results.stream().filter(AttackResult::isDelivered).count();
        long crashes = results.stream().filter(AttackResult::isLikelyCrash).count();
        long errors = results.stream()
                .filter(r -> r.getStatus() == AttackResult.Status.INTERNAL_ERROR)
                .count();
        double avgLatency = results.stream()
                .mapToLong(AttackResult::getLatencyMs)
                .average()
                .orElse(0.0);

        return String.format(
            "BatchSummary{total=%d, delivered=%d, crashes=%d, errors=%d, avgLatency=%.1fms}",
            results.size(), delivered, crashes, errors, avgLatency
        );
    }
}
