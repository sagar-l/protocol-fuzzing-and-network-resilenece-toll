// ============================================================================
// FuzzStrike Attack Node — AttackChannelHandler
// ============================================================================
// Netty ChannelInboundHandler that manages the lifecycle of a single
// payload delivery to the target. This handler is added to the Netty
// pipeline for each outbound connection.
//
// Lifecycle:
//   1. channelActive()    → Connection established, send the payload
//   2. channelRead()      → Target responded, capture the response
//   3. exceptionCaught()  → Error occurred, classify and record
//   4. channelInactive()  → Connection closed, finalize the result
//
// Thread-safety: Each handler instance is bound to a single channel
// and executed by a single EventLoop thread. No synchronization needed.
// ============================================================================

package com.fuzzstrike.attacknode.handler;

import com.fuzzstrike.attacknode.model.AttackResult;
import com.fuzzstrike.attacknode.model.PayloadBatch;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.util.CharsetUtil;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;

/**
 * Handles the lifecycle of a single payload delivery attempt.
 *
 * <p>This handler is NOT shareable — a new instance is created for
 * each connection. This is by design: each handler tracks state
 * specific to its payload delivery (timing, response data, etc.).</p>
 *
 * <p>The handler writes the payload to the channel as soon as the
 * connection is active, then waits for a response or error.</p>
 */
public class AttackChannelHandler extends ChannelInboundHandlerAdapter {

    private static final Logger log = LoggerFactory.getLogger(AttackChannelHandler.class);

    // ── Instance State ────────────────────────────────────────────────────

    /** The payload being delivered by this handler */
    private final PayloadBatch.PayloadItem payload;

    /** The collector that aggregates results from all handlers */
    private final ResponseCollector collector;

    /** Timestamp when the connection was established (for latency calc) */
    private long startTimeMs;

    /** Accumulated response data from the target */
    private final StringBuilder responseBuffer = new StringBuilder();

    /** Whether we've already reported a result (prevent double-reporting) */
    private boolean resultReported = false;

    // ── Constructor ───────────────────────────────────────────────────────

    /**
     * Create a handler for delivering a specific payload.
     *
     * @param payload   The payload item to deliver
     * @param collector The response collector to report results to
     */
    public AttackChannelHandler(PayloadBatch.PayloadItem payload, ResponseCollector collector) {
        this.payload = payload;
        this.collector = collector;
    }

    // ── Netty Lifecycle Callbacks ─────────────────────────────────────────

    /**
     * Called when the TCP connection to the target is established.
     *
     * <p>We immediately write the payload content to the channel.
     * The write is flushed to ensure it's sent immediately rather
     * than waiting for more data to batch.</p>
     */
    @Override
    public void channelActive(ChannelHandlerContext ctx) {
        startTimeMs = System.currentTimeMillis();

        log.debug(
            "Channel active → sending payload {} ({} bytes) to {}",
            payload.getId(), payload.getSizeBytes(),
            ctx.channel().remoteAddress()
        );

        // Convert payload content to a ByteBuf and send it
        byte[] payloadBytes = payload.getContent().getBytes(StandardCharsets.UTF_8);
        ByteBuf buffer = Unpooled.wrappedBuffer(payloadBytes);

        // writeAndFlush ensures the data is sent immediately
        // addListener(CLOSE) closes the channel after the write completes
        ctx.writeAndFlush(buffer).addListener(future -> {
            if (!future.isSuccess()) {
                log.warn(
                    "Failed to send payload {}: {}",
                    payload.getId(),
                    future.cause() != null ? future.cause().getMessage() : "unknown"
                );
                reportResult(
                    AttackResult.Status.INTERNAL_ERROR,
                    null,
                    future.cause() != null ? future.cause().getMessage() : "Write failed"
                );
                ctx.close();
            }
        });
    }

    /**
     * Called when data is received from the target.
     *
     * <p>We accumulate response data in a StringBuilder. The target
     * may send its response in multiple chunks, so we don't finalize
     * the result here — we wait for channelInactive().</p>
     */
    @Override
    public void channelRead(ChannelHandlerContext ctx, Object msg) {
        if (msg instanceof ByteBuf) {
            ByteBuf buf = (ByteBuf) msg;
            try {
                responseBuffer.append(buf.toString(CharsetUtil.UTF_8));
            } finally {
                // CRITICAL: Release the ByteBuf to prevent memory leaks.
                // Netty uses reference counting for buffer management.
                buf.release();
            }
        }
    }

    /**
     * Called after the last channelRead() in a read batch.
     *
     * <p>We close the channel after reading the response. In a fuzzing
     * scenario, we don't need to keep connections open — fire and forget.</p>
     */
    @Override
    public void channelReadComplete(ChannelHandlerContext ctx) {
        // Close the channel after reading the response
        ctx.close();
    }

    /**
     * Called when the channel becomes inactive (connection closed).
     *
     * <p>This is where we finalize the result. If we received response
     * data, it's a SUCCESS. If no data came through, it might indicate
     * the target crashed before it could respond.</p>
     */
    @Override
    public void channelInactive(ChannelHandlerContext ctx) {
        if (!resultReported) {
            String response = responseBuffer.toString();

            if (response.isEmpty()) {
                // No response — target may have crashed or rejected silently
                reportResult(
                    AttackResult.Status.CONNECTION_RESET,
                    null,
                    "Connection closed without response (possible crash)"
                );
            } else {
                // Got a response — check if it indicates an error
                boolean isError = response.contains("ERROR") ||
                                  response.contains("Exception") ||
                                  response.contains("CRASH");

                reportResult(
                    isError ? AttackResult.Status.TARGET_ERROR : AttackResult.Status.SUCCESS,
                    response,
                    null
                );
            }
        }
    }

    /**
     * Called when an exception occurs in the pipeline.
     *
     * <p>We classify the exception to determine the most likely cause:
     * - ConnectException → Target is down (CONNECTION_REFUSED)
     * - IOException with "reset" → Target crashed (CONNECTION_RESET)
     * - Other → Generic internal error</p>
     */
    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
        String message = cause.getMessage() != null ? cause.getMessage() : cause.getClass().getSimpleName();

        log.warn("Exception on payload {}: {}", payload.getId(), message);

        // Classify the exception
        AttackResult.Status status;
        boolean likelyCrash = false;

        if (cause instanceof java.net.ConnectException) {
            status = AttackResult.Status.CONNECTION_REFUSED;
            likelyCrash = true;  // Target may have crashed
        } else if (message.toLowerCase().contains("reset")) {
            status = AttackResult.Status.CONNECTION_RESET;
            likelyCrash = true;  // Connection reset often indicates crash
        } else if (cause instanceof java.util.concurrent.TimeoutException ||
                   message.toLowerCase().contains("timeout")) {
            status = AttackResult.Status.TIMEOUT;
        } else {
            status = AttackResult.Status.INTERNAL_ERROR;
        }

        reportResult(status, null, message);

        // Close the channel
        ctx.close();
    }

    // ── Internal Helpers ──────────────────────────────────────────────────

    /**
     * Report the delivery result to the ResponseCollector.
     *
     * <p>Uses a flag to ensure we only report once per payload,
     * even if multiple lifecycle callbacks fire.</p>
     */
    private void reportResult(AttackResult.Status status, String responseData, String errorMessage) {
        if (resultReported) return;
        resultReported = true;

        long latencyMs = System.currentTimeMillis() - startTimeMs;
        boolean likelyCrash = (status == AttackResult.Status.CONNECTION_RESET ||
                               status == AttackResult.Status.CONNECTION_REFUSED);

        AttackResult result = new AttackResult.Builder(payload.getId(), payload.getCampaignId())
                .status(status)
                .latencyMs(latencyMs)
                .responseData(responseData)
                .errorMessage(errorMessage)
                .likelyCrash(likelyCrash)
                .build();

        collector.addResult(result);

        log.debug("Payload {} → {} ({}ms, crash={})",
                payload.getId(), status, latencyMs, likelyCrash);
    }
}
