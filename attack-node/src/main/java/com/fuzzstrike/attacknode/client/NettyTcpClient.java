// ============================================================================
// FuzzStrike Attack Node — NettyTcpClient
// ============================================================================
// The core async TCP client built on Netty 4.1. Manages the EventLoopGroup
// and Bootstrap for creating outbound connections to the target.
//
// Architecture:
//   - Uses NioEventLoopGroup for non-blocking I/O multiplexing
//   - Each payload gets its own short-lived TCP connection
//   - Connections are created concurrently within the EventLoop
//   - The client is reusable across multiple batches (stateless core)
//
// Design Decision: We create a new connection per payload rather than
// multiplexing on a single connection because:
//   1. We're testing the target's connection handling, not just data handling
//   2. Connection storms are a valid attack vector
//   3. It's simpler and matches real-world protocol fuzzing patterns
// ============================================================================

package com.fuzzstrike.attacknode.client;

import com.fuzzstrike.attacknode.handler.AttackChannelHandler;
import com.fuzzstrike.attacknode.handler.ResponseCollector;
import com.fuzzstrike.attacknode.model.AttackResult;
import com.fuzzstrike.attacknode.model.PayloadBatch;

import io.netty.bootstrap.Bootstrap;
import io.netty.channel.*;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioSocketChannel;
import io.netty.handler.timeout.ReadTimeoutHandler;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.concurrent.TimeUnit;

/**
 * High-throughput asynchronous TCP client for payload delivery.
 *
 * <p>This client manages a shared NioEventLoopGroup (thread pool) and
 * creates individual connections for each payload in a batch. All
 * connections run concurrently on the EventLoop threads.</p>
 *
 * <p>Lifecycle:
 * <ol>
 *   <li>{@link #NettyTcpClient(int)} — Create with N worker threads</li>
 *   <li>{@link #fireBatch(PayloadBatch)} — Send a batch of payloads</li>
 *   <li>{@link #shutdown()} — Gracefully shut down the EventLoopGroup</li>
 * </ol>
 *
 * <p>Thread-safety: This class is thread-safe. The EventLoopGroup handles
 * all concurrency internally.</p>
 */
public class NettyTcpClient {

    private static final Logger log = LoggerFactory.getLogger(NettyTcpClient.class);

    // ── Configuration Constants ───────────────────────────────────────────

    /** Timeout for individual payload delivery (seconds) */
    private static final int READ_TIMEOUT_SECONDS = 10;

    /** Connection timeout (milliseconds) */
    private static final int CONNECT_TIMEOUT_MS = 5000;

    // ── Netty Components ──────────────────────────────────────────────────

    /**
     * The EventLoopGroup is Netty's thread pool for I/O operations.
     * NioEventLoopGroup uses Java NIO (epoll on Linux) for non-blocking I/O.
     * All channel operations (connect, read, write) execute on these threads.
     */
    private final EventLoopGroup workerGroup;

    /**
     * Bootstrap is Netty's client configuration template.
     * We configure it once and reuse it for all connections.
     */
    private final Bootstrap bootstrap;

    // ── Constructor ───────────────────────────────────────────────────────

    /**
     * Create a new Netty TCP client with the specified number of worker threads.
     *
     * @param workerThreads Number of I/O threads in the EventLoopGroup.
     *                      Recommended: 2 * CPU cores for I/O bound workloads.
     *                      Use 0 to let Netty auto-detect (defaults to 2 * cores).
     */
    public NettyTcpClient(int workerThreads) {
        log.info("Initializing NettyTcpClient with {} worker threads",
                workerThreads == 0 ? "auto" : workerThreads);

        this.workerGroup = new NioEventLoopGroup(workerThreads);

        this.bootstrap = new Bootstrap()
                .group(workerGroup)
                .channel(NioSocketChannel.class)
                // TCP_NODELAY: Disable Nagle's algorithm for low-latency sends
                .option(ChannelOption.TCP_NODELAY, true)
                // SO_KEEPALIVE: Detect dead connections
                .option(ChannelOption.SO_KEEPALIVE, false)
                // Connection timeout
                .option(ChannelOption.CONNECT_TIMEOUT_MILLIS, CONNECT_TIMEOUT_MS)
                // Allocator: Use pooled allocator for better memory efficiency
                .option(ChannelOption.ALLOCATOR, io.netty.buffer.PooledByteBufAllocator.DEFAULT);

        log.info("NettyTcpClient initialized successfully");
    }

    // ── Public API ────────────────────────────────────────────────────────

    /**
     * Fire an entire batch of payloads at the target concurrently.
     *
     * <p>This method:
     * <ol>
     *   <li>Creates a ResponseCollector for the batch</li>
     *   <li>Opens a TCP connection for each payload (concurrently)</li>
     *   <li>Waits for all deliveries to complete (or timeout)</li>
     *   <li>Returns the aggregated results</li>
     * </ol>
     *
     * <p>All connections are initiated asynchronously — this method does
     * NOT block on each individual connection. The only blocking point
     * is the awaitCompletion() call on the ResponseCollector.</p>
     *
     * @param batch The payload batch from the C2 server.
     * @return The ResponseCollector containing all delivery results.
     * @throws InterruptedException if the waiting thread is interrupted.
     */
    public ResponseCollector fireBatch(PayloadBatch batch) throws InterruptedException {
        List<PayloadBatch.PayloadItem> payloads = batch.getPayloads();
        String targetHost = batch.getTargetHost();
        int targetPort = batch.getTargetPort();

        log.info("Firing batch: {} payloads → {}:{}",
                payloads.size(), targetHost, targetPort);

        // Create a collector that expects results from all payloads
        ResponseCollector collector = new ResponseCollector(payloads.size());

        // Fire each payload as a separate async connection
        for (PayloadBatch.PayloadItem payload : payloads) {
            firePayload(targetHost, targetPort, payload, collector);
        }

        // Wait for all deliveries to complete (30 second batch timeout)
        collector.awaitCompletion(30, TimeUnit.SECONDS);

        log.info("Batch complete: {}", collector.getSummary());

        return collector;
    }

    /**
     * Gracefully shut down the Netty EventLoopGroup.
     *
     * <p>This waits for all pending I/O operations to complete before
     * releasing resources. Called once at application shutdown.</p>
     */
    public void shutdown() {
        log.info("Shutting down NettyTcpClient...");
        workerGroup.shutdownGracefully(0, 5, TimeUnit.SECONDS);
        log.info("NettyTcpClient shut down complete");
    }

    // ── Internal Methods ──────────────────────────────────────────────────

    /**
     * Fire a single payload by opening a new TCP connection.
     *
     * <p>The connection setup and payload delivery are fully asynchronous.
     * The pipeline is configured with:
     * <ul>
     *   <li>ReadTimeoutHandler — Auto-close after N seconds of no response</li>
     *   <li>AttackChannelHandler — Sends payload, captures response</li>
     * </ul>
     *
     * @param host      Target hostname
     * @param port      Target port
     * @param payload   The payload to deliver
     * @param collector The collector to report results to
     */
    private void firePayload(
            String host,
            int port,
            PayloadBatch.PayloadItem payload,
            ResponseCollector collector
    ) {
        // Configure the pipeline for this specific connection
        // Note: We use a new handler() call each time because
        // ChannelInitializer creates a fresh pipeline per connection
        Bootstrap payloadBootstrap = bootstrap.clone()
                .handler(new ChannelInitializer<SocketChannel>() {
                    @Override
                    protected void initChannel(SocketChannel ch) {
                        ChannelPipeline pipeline = ch.pipeline();

                        // Stage 1: Read timeout — closes channel if target
                        //          doesn't respond within the timeout
                        pipeline.addLast("readTimeout",
                                new ReadTimeoutHandler(READ_TIMEOUT_SECONDS));

                        // Stage 2: Attack handler — sends payload, captures response
                        pipeline.addLast("attackHandler",
                                new AttackChannelHandler(payload, collector));
                    }
                });

        // Initiate the async connection
        ChannelFuture future = payloadBootstrap.connect(host, port);

        // Add a listener to handle connection failures asynchronously
        future.addListener((ChannelFutureListener) f -> {
            if (!f.isSuccess()) {
                Throwable cause = f.cause();
                log.debug("Connection failed for payload {}: {}",
                        payload.getId(),
                        cause != null ? cause.getMessage() : "unknown");

                // Report the failure via the collector
                AttackResult result = new AttackResult.Builder(payload.getId(), payload.getCampaignId())
                        .status(AttackResult.Status.CONNECTION_REFUSED)
                        .errorMessage(cause != null ? cause.getMessage() : "Connection failed")
                        .likelyCrash(true)
                        .build();

                collector.addResult(result);
            }
        });
    }
}
