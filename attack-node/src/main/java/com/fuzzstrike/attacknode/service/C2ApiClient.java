// ============================================================================
// FuzzStrike Attack Node — C2ApiClient
// ============================================================================
// HTTP client for communicating with the C2 orchestrator's REST API.
// Uses Java's built-in HttpClient (Java 11+) — no external HTTP library needed.
//
// Responsibilities:
//   1. Discover active campaigns (GET /api/v1/campaigns/?status=running)
//   2. Fetch payload batches (GET /api/v1/campaigns/{id}/payloads)
//   3. Acknowledge deliveries (POST /api/v1/campaigns/{id}/payloads/ack)
//
// Design Decision: We use the built-in java.net.http.HttpClient rather
// than adding Apache HttpClient or OkHttp as dependencies. This keeps
// the dependency tree minimal and is sufficient for our simple REST calls.
// ============================================================================

package com.fuzzstrike.attacknode.service;

import com.fuzzstrike.attacknode.model.PayloadBatch;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonParser;
import com.google.gson.reflect.TypeToken;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.lang.reflect.Type;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.*;

/**
 * REST client for the C2 orchestrator API.
 *
 * <p>This client handles all HTTP communication between the attack node
 * and the C2 server. It uses Java's built-in HttpClient for HTTP/1.1
 * requests with JSON serialization via Gson.</p>
 *
 * <p>Thread-safety: HttpClient is thread-safe. Gson instances are
 * thread-safe. This class is fully thread-safe.</p>
 */
public class C2ApiClient {

    private static final Logger log = LoggerFactory.getLogger(C2ApiClient.class);

    // ── Configuration ─────────────────────────────────────────────────────

    /** Base URL of the C2 orchestrator (e.g., http://c2-orchestrator:9000) */
    private final String baseUrl;

    /** Batch size for payload fetching */
    private final int batchSize;

    // ── HTTP Client ───────────────────────────────────────────────────────

    /**
     * Java's built-in HttpClient, configured with:
     * - HTTP/1.1 protocol (for compatibility)
     * - Connection timeout
     * - Follow redirects
     */
    private final HttpClient httpClient;

    /** Gson instance for JSON serialization/deserialization */
    private final Gson gson;

    // ── Constructor ───────────────────────────────────────────────────────

    /**
     * Create a new C2 API client.
     *
     * @param baseUrl   The C2 orchestrator's base URL (no trailing slash).
     * @param batchSize Number of payloads to request per batch.
     */
    public C2ApiClient(String baseUrl, int batchSize) {
        // Strip trailing slash for consistent URL construction
        this.baseUrl = baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;
        this.batchSize = batchSize;

        this.httpClient = HttpClient.newBuilder()
                .version(HttpClient.Version.HTTP_1_1)
                .connectTimeout(Duration.ofSeconds(10))
                .followRedirects(HttpClient.Redirect.NORMAL)
                .build();

        this.gson = new GsonBuilder()
                .setPrettyPrinting()
                .create();

        log.info("C2ApiClient initialized: baseUrl={}, batchSize={}", baseUrl, batchSize);
    }

    // ── Public API ────────────────────────────────────────────────────────

    /**
     * Discover active (RUNNING) campaigns on the C2 server.
     *
     * @return List of campaign IDs that are currently running.
     *         Empty list if no campaigns are active or on error.
     */
    public List<Integer> getActiveCampaignIds() {
        String url = baseUrl + "/api/v1/campaigns/?status=running&limit=10";

        try {
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(url))
                    .header("Accept", "application/json")
                    .GET()
                    .timeout(Duration.ofSeconds(5))
                    .build();

            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

            if (response.statusCode() != 200) {
                log.warn("Failed to fetch campaigns: HTTP {}", response.statusCode());
                return Collections.emptyList();
            }

            // Parse the JSON array of campaign objects
            JsonArray campaigns = JsonParser.parseString(response.body()).getAsJsonArray();
            List<Integer> ids = new ArrayList<>();

            for (JsonElement element : campaigns) {
                int id = element.getAsJsonObject().get("id").getAsInt();
                ids.add(id);
            }

            log.debug("Found {} active campaigns: {}", ids.size(), ids);
            return ids;

        } catch (IOException | InterruptedException e) {
            log.error("Error fetching active campaigns: {}", e.getMessage());
            if (e instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }
            return Collections.emptyList();
        }
    }

    /**
     * Fetch a batch of pending payloads for a specific campaign.
     *
     * @param campaignId The campaign to fetch payloads for.
     * @return A PayloadBatch containing the pending payloads, or null on error.
     */
    public PayloadBatch fetchPayloadBatch(int campaignId) {
        String url = String.format(
                "%s/api/v1/campaigns/%d/payloads?batch_size=%d",
                baseUrl, campaignId, batchSize
        );

        try {
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(url))
                    .header("Accept", "application/json")
                    .GET()
                    .timeout(Duration.ofSeconds(10))
                    .build();

            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

            if (response.statusCode() == 409) {
                // Campaign is not running — this is expected during stop
                log.debug("Campaign {} is not running (409)", campaignId);
                return null;
            }

            if (response.statusCode() != 200) {
                log.warn("Failed to fetch payloads for campaign {}: HTTP {}",
                        campaignId, response.statusCode());
                return null;
            }

            PayloadBatch batch = gson.fromJson(response.body(), PayloadBatch.class);
            log.debug("Fetched batch for campaign {}: {}", campaignId, batch);
            return batch;

        } catch (IOException | InterruptedException e) {
            log.error("Error fetching payload batch for campaign {}: {}",
                    campaignId, e.getMessage());
            if (e instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }
            return null;
        }
    }

    /**
     * Acknowledge payload delivery results back to the C2 server.
     *
     * <p>This tells the C2 which payloads were sent and which ones
     * appeared to trigger crashes (based on connection behavior).</p>
     *
     * @param campaignId  The campaign these payloads belong to.
     * @param payloadIds  All payload IDs that were attempted.
     * @param crashedIds  Subset of payloadIds that likely caused crashes.
     */
    public void acknowledgePayloads(int campaignId, List<Integer> payloadIds, List<Integer> crashedIds) {
        String url = String.format(
                "%s/api/v1/campaigns/%d/payloads/ack",
                baseUrl, campaignId
        );

        // Build the ACK request body
        Map<String, Object> body = new HashMap<>();
        body.put("payload_ids", payloadIds);
        body.put("crashed_ids", crashedIds);

        String jsonBody = gson.toJson(body);

        try {
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(url))
                    .header("Content-Type", "application/json")
                    .header("Accept", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(jsonBody))
                    .timeout(Duration.ofSeconds(10))
                    .build();

            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

            if (response.statusCode() == 200) {
                log.info("ACK successful for campaign {}: {} payloads, {} crashes",
                        campaignId, payloadIds.size(), crashedIds.size());
            } else {
                log.warn("ACK failed for campaign {}: HTTP {} — {}",
                        campaignId, response.statusCode(), response.body());
            }

        } catch (IOException | InterruptedException e) {
            log.error("Error acknowledging payloads for campaign {}: {}",
                    campaignId, e.getMessage());
            if (e instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }
        }
    }

    /**
     * Check if the C2 server is reachable (health check).
     *
     * @return true if the C2 server responds to /health, false otherwise.
     */
    public boolean isC2Healthy() {
        String url = baseUrl + "/health";

        try {
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(url))
                    .GET()
                    .timeout(Duration.ofSeconds(3))
                    .build();

            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            return response.statusCode() == 200;

        } catch (Exception e) {
            return false;
        }
    }
}
