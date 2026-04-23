// ============================================================================
// FuzzStrike Attack Node — NettyUdpClient
// ============================================================================
// Asynchronous UDP client built on Netty 4.1 for sending fuzzed packets
// to targets using UDP-based protocols (DNS, DHCP, RADIUS).
//
// Unlike TCP, UDP is connectionless — we fire datagrams without
// establishing a connection. This enables extremely high throughput
// (millions of packets) since there's no handshake overhead.
//
// Key Design Decisions:
//   - Uses NioDatagramChannel for async I/O
//   - PooledByteBufAllocator for memory efficiency at scale
//   - Fire-and-forget: no response waiting (fuzzing, not scanning)
//   - Hex-decoded payload from C2 (binary protocol packets)
// ============================================================================

package com.fuzzstrike.attacknode.client;

import com.fuzzstrike.attacknode.handler.ResponseCollector;
import com.fuzzstrike.attacknode.model.AttackResult;
import com.fuzzstrike.attacknode.model.PayloadBatch;

import io.netty.bootstrap.Bootstrap;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.PooledByteBufAllocator;
import io.netty.buffer.Unpooled;
import io.netty.channel.*;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.DatagramPacket;
import io.netty.channel.socket.nio.NioDatagramChannel;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.InetSocketAddress;
import java.util.concurrent.TimeUnit;

/**
 * High-throughput async UDP client for protocol fuzzing.
 *
 * <p>Sends hex-encoded binary payloads (DNS, DHCP, RADIUS packets) as
 * UDP datagrams to the target. Designed for fire-and-forget operation
 * at millions-of-packets-per-second throughput.</p>
 *
 * <p>Thread safety: This class is thread-safe. The internal Netty
 * EventLoop handles all I/O operations asynchronously.</p>
 */
public class NettyUdpClient {

    private static final Logger log = LoggerFactory.getLogger(NettyUdpClient.class);

    private final EventLoopGroup workerGroup;
    private Channel channel;

    /**
     * Create a UDP client with the specified number of I/O threads.
     *
     * @param ioThreads Number of Netty I/O threads (default: 4)
     */
    public NettyUdpClient(int ioThreads) {
        this.workerGroup = new NioEventLoopGroup(ioThreads);
    }

    /**
     * Initialize the UDP channel.
     * Must be called before fireBatch().
     */
    public void init() throws InterruptedException {
        Bootstrap bootstrap = new Bootstrap()
                .group(workerGroup)
                .channel(NioDatagramChannel.class)
                .option(ChannelOption.ALLOCATOR, PooledByteBufAllocator.DEFAULT)
                .option(ChannelOption.SO_SNDBUF, 1048576)  // 1MB send buffer
                .handler(new SimpleChannelInboundHandler<DatagramPacket>() {
                    @Override
                    protected void channelRead0(ChannelHandlerContext ctx, DatagramPacket msg) {
                        // Fire-and-forget: we don't process responses for fuzzing
                        log.trace("Received UDP response ({} bytes)", msg.content().readableBytes());
                    }

                    @Override
                    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
                        log.warn("UDP channel error: {}", cause.getMessage());
                    }
                });

        ChannelFuture future = bootstrap.bind(0).sync();
        this.channel = future.channel();
        log.info("UDP client initialized on {}", channel.localAddress());
    }

    /**
     * Fire a batch of fuzzed packets as UDP datagrams.
     *
     * <p>Each payload content is expected to be a hex-encoded string representing
     * the raw binary packet (e.g., a malformed DNS query). The hex string is
     * decoded to bytes and wrapped in a DatagramPacket.</p>
     *
     * @param batch The payload batch from the C2 orchestrator.
     * @return ResponseCollector with delivery results.
     */
    public ResponseCollector fireBatch(PayloadBatch batch) {
        ResponseCollector collector = new ResponseCollector(batch.size());

        String targetHost = batch.getTargetHost();
        int targetPort = batch.getTargetPort();
        int campaignId = batch.getCampaignId();
        InetSocketAddress targetAddr = new InetSocketAddress(targetHost, targetPort);

        log.info("UDP fire: {} packets → {}:{} [{}]",
                batch.size(), targetHost, targetPort,
                batch.getProtocol().toUpperCase());

        for (PayloadBatch.PayloadItem payload : batch.getPayloads()) {
            try {
                long startTime = System.currentTimeMillis();

                // Decode hex-encoded binary payload to raw bytes
                byte[] rawBytes = hexStringToBytes(payload.getContent());
                ByteBuf data = Unpooled.wrappedBuffer(rawBytes);
                DatagramPacket packet = new DatagramPacket(data, targetAddr);

                // Send the datagram asynchronously
                channel.writeAndFlush(packet).addListener((ChannelFutureListener) future -> {
                    long latency = System.currentTimeMillis() - startTime;

                    if (future.isSuccess()) {
                        AttackResult result = new AttackResult.Builder(payload.getId(), campaignId)
                                .status(AttackResult.Status.SUCCESS)
                                .latencyMs(latency)
                                .build();
                        collector.addResult(result);
                    } else {
                        AttackResult result = new AttackResult.Builder(payload.getId(), campaignId)
                                .status(AttackResult.Status.INTERNAL_ERROR)
                                .latencyMs(latency)
                                .errorMessage(future.cause() != null ? future.cause().getMessage() : "UDP send failed")
                                .likelyCrash(true)
                                .build();
                        collector.addResult(result);
                        log.warn("UDP send failed for payload {}: {}",
                                payload.getId(), future.cause() != null ? future.cause().getMessage() : "unknown");
                    }
                });

            } catch (Exception e) {
                log.error("Failed to send UDP payload {}: {}", payload.getId(), e.getMessage());
                AttackResult result = new AttackResult.Builder(payload.getId(), campaignId)
                        .status(AttackResult.Status.INTERNAL_ERROR)
                        .errorMessage(e.getMessage())
                        .likelyCrash(true)
                        .build();
                collector.addResult(result);
            }
        }

        // Wait for all packets to be sent (with timeout)
        try {
            boolean completed = collector.awaitCompletion(30, TimeUnit.SECONDS);
            if (!completed) {
                log.warn("UDP batch timed out — some packets may not have been sent");
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }

        log.info("UDP batch complete: {}", collector.getSummary());
        return collector;
    }

    /**
     * Shut down the UDP client and release resources.
     */
    public void shutdown() {
        log.info("Shutting down UDP client...");
        if (channel != null) {
            channel.close();
        }
        workerGroup.shutdownGracefully();
        log.info("UDP client shut down");
    }

    /**
     * Convert a hex-encoded string to a byte array.
     * Used to decode binary protocol packets from the C2 JSON response.
     */
    private static byte[] hexStringToBytes(String hex) {
        if (hex == null || hex.isEmpty()) {
            return new byte[0];
        }
        int len = hex.length();
        byte[] bytes = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            bytes[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                    + Character.digit(hex.charAt(i + 1), 16));
        }
        return bytes;
    }
}
