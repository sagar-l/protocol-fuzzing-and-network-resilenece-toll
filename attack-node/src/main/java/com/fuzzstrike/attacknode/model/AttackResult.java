// ============================================================================
// FuzzStrike Attack Node — AttackResult Model
// ============================================================================
// Captures the outcome of delivering a single payload to the target.
// This is used to build the acknowledgment request back to the C2 server.
//
// Design: We use an enum for result status rather than boolean flags,
// making it extensible for future result classifications (e.g., TIMEOUT,
// PARTIAL_RESPONSE, etc.)
// ============================================================================

package com.fuzzstrike.attacknode.model;

/**
 * Represents the result of delivering a single payload to the target.
 *
 * <p>Created by {@code AttackChannelHandler} after each payload delivery
 * attempt and collected by {@code ResponseCollector} for batch ACK.</p>
 */
public class AttackResult {

    /**
     * Possible outcomes of a payload delivery attempt.
     */
    public enum Status {
        /** Payload was delivered and target responded normally */
        SUCCESS,
        
        /** Payload was delivered but target returned an error response */
        TARGET_ERROR,
        
        /** Connection to target was refused (target may be down) */
        CONNECTION_REFUSED,
        
        /** Connection timed out before payload could be delivered */
        TIMEOUT,
        
        /** Target disconnected abruptly (possible crash) */
        CONNECTION_RESET,
        
        /** An unexpected error occurred during delivery */
        INTERNAL_ERROR
    }

    // ── Fields ────────────────────────────────────────────────────────────

    /** The ID of the payload from the C2 database */
    private final int payloadId;

    /** The campaign this payload belongs to */
    private final int campaignId;

    /** The outcome of the delivery attempt */
    private final Status status;

    /** Time taken to deliver this payload (in milliseconds) */
    private final long latencyMs;

    /** Any response data received from the target (may be null) */
    private final String responseData;

    /** Error message if delivery failed (may be null) */
    private final String errorMessage;

    /** Whether this result indicates a likely crash */
    private final boolean likelyCrash;

    // ── Constructor (Builder pattern below) ───────────────────────────────

    private AttackResult(Builder builder) {
        this.payloadId = builder.payloadId;
        this.campaignId = builder.campaignId;
        this.status = builder.status;
        this.latencyMs = builder.latencyMs;
        this.responseData = builder.responseData;
        this.errorMessage = builder.errorMessage;
        this.likelyCrash = builder.likelyCrash;
    }

    // ── Getters ───────────────────────────────────────────────────────────

    public int getPayloadId() { return payloadId; }
    public int getCampaignId() { return campaignId; }
    public Status getStatus() { return status; }
    public long getLatencyMs() { return latencyMs; }
    public String getResponseData() { return responseData; }
    public String getErrorMessage() { return errorMessage; }
    public boolean isLikelyCrash() { return likelyCrash; }

    /**
     * Determines if this result represents a successful delivery
     * (regardless of target response).
     */
    public boolean isDelivered() {
        return status == Status.SUCCESS || status == Status.TARGET_ERROR;
    }

    @Override
    public String toString() {
        return String.format(
            "AttackResult{payload=%d, status=%s, latency=%dms, crash=%s}",
            payloadId, status, latencyMs, likelyCrash
        );
    }

    // ============================================================================
    // Builder Pattern — For clean, readable construction
    // ============================================================================

    /**
     * Builder for constructing AttackResult instances.
     *
     * <p>Usage:
     * <pre>{@code
     * AttackResult result = new AttackResult.Builder(payloadId, campaignId)
     *     .status(Status.CONNECTION_RESET)
     *     .latencyMs(150)
     *     .likelyCrash(true)
     *     .errorMessage("Connection reset by peer")
     *     .build();
     * }</pre>
     */
    public static class Builder {
        // Required params
        private final int payloadId;
        private final int campaignId;

        // Optional params with defaults
        private Status status = Status.SUCCESS;
        private long latencyMs = 0;
        private String responseData = null;
        private String errorMessage = null;
        private boolean likelyCrash = false;

        public Builder(int payloadId, int campaignId) {
            this.payloadId = payloadId;
            this.campaignId = campaignId;
        }

        public Builder status(Status status) {
            this.status = status;
            return this;
        }

        public Builder latencyMs(long latencyMs) {
            this.latencyMs = latencyMs;
            return this;
        }

        public Builder responseData(String responseData) {
            this.responseData = responseData;
            return this;
        }

        public Builder errorMessage(String errorMessage) {
            this.errorMessage = errorMessage;
            return this;
        }

        public Builder likelyCrash(boolean likelyCrash) {
            this.likelyCrash = likelyCrash;
            return this;
        }

        public AttackResult build() {
            return new AttackResult(this);
        }
    }
}
