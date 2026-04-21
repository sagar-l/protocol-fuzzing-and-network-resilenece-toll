// ============================================================================
// FuzzStrike Attack Node — PayloadBatch Model
// ============================================================================
// Data Transfer Object representing a batch of mutated payloads received
// from the C2 orchestrator. This is the deserialized form of the JSON
// response from GET /api/v1/campaigns/{id}/payloads.
//
// This class is intentionally a simple POJO with no framework dependencies.
// Gson handles serialization/deserialization via reflection.
// ============================================================================

package com.fuzzstrike.attacknode.model;

import java.util.List;
import java.util.Collections;

/**
 * Represents a batch of payloads dispatched by the C2 orchestrator.
 *
 * <p>Each batch is tied to a specific campaign and contains the target
 * connection information along with the actual payload contents to fire.</p>
 *
 * <p>Thread-safety: Instances are effectively immutable once constructed
 * by Gson. The payloads list is defensively copied on access.</p>
 */
public class PayloadBatch {

    // ── Fields (mapped from C2 JSON response) ─────────────────────────────
    
    /** The campaign this batch belongs to */
    private int campaign_id;

    /** Target host to send payloads to */
    private String target_host;

    /** Target TCP port */
    private int target_port;

    /** The individual payloads in this batch */
    private List<PayloadItem> payloads;

    // ── Inner class: Individual payload ───────────────────────────────────

    /**
     * Represents a single mutated payload within a batch.
     * Maps to the PayloadOut schema from the C2 API.
     */
    public static class PayloadItem {
        private int id;
        private int campaign_id;
        private String content;
        private String mutation_type;
        private int size_bytes;
        private String status;

        // ── Getters ───────────────────────────────────────────────────────

        public int getId() { return id; }
        public int getCampaignId() { return campaign_id; }
        public String getContent() { return content; }
        public String getMutationType() { return mutation_type; }
        public int getSizeBytes() { return size_bytes; }
        public String getStatus() { return status; }

        @Override
        public String toString() {
            return String.format(
                "PayloadItem{id=%d, type='%s', size=%d bytes}",
                id, mutation_type, size_bytes
            );
        }
    }

    // ── Getters ───────────────────────────────────────────────────────────

    public int getCampaignId() { return campaign_id; }
    public String getTargetHost() { return target_host; }
    public int getTargetPort() { return target_port; }

    /**
     * Returns a defensive copy of the payload list.
     * This prevents external code from mutating our internal state.
     */
    public List<PayloadItem> getPayloads() {
        return payloads != null 
            ? Collections.unmodifiableList(payloads) 
            : Collections.emptyList();
    }

    /**
     * Check if this batch has any payloads to deliver.
     * Used by the polling loop to decide whether to dispatch.
     */
    public boolean isEmpty() {
        return payloads == null || payloads.isEmpty();
    }

    /**
     * Get the count of payloads in this batch.
     */
    public int size() {
        return payloads != null ? payloads.size() : 0;
    }

    @Override
    public String toString() {
        return String.format(
            "PayloadBatch{campaign=%d, target='%s:%d', payloads=%d}",
            campaign_id, target_host, target_port, size()
        );
    }
}
