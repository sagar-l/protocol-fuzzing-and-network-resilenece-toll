# ============================================================================
# FuzzStrike Attack Node — Dockerfile
# ============================================================================
# Multi-stage build:
#   Stage 1 (builder): Compile Java source with Maven, produce fat JAR.
#   Stage 2 (runtime): Run the fat JAR on a minimal Eclipse Temurin JRE 17.
# ============================================================================

# ---------------------------------------------------------------------------
# Stage 1: Build with Maven
# ---------------------------------------------------------------------------
FROM maven:3.9-eclipse-temurin-17 AS builder

WORKDIR /build

# Copy POM first for dependency caching (Docker layer optimization)
COPY pom.xml .
RUN mvn dependency:go-offline -B

# Copy source and build the fat JAR
COPY src/ ./src/
RUN mvn clean package -DskipTests -B

# ---------------------------------------------------------------------------
# Stage 2: Minimal runtime image
# ---------------------------------------------------------------------------
FROM eclipse-temurin:17-jre-alpine AS runtime

# Security: Run as non-root user
RUN addgroup -S fuzzstrike && adduser -S fuzzstrike -G fuzzstrike

WORKDIR /app

# Copy the fat JAR from builder stage
COPY --from=builder /build/target/attack-node-1.0.0-SNAPSHOT.jar ./attack-node.jar

# Switch to non-root user
USER fuzzstrike

# JVM tuning flags for containerized environments:
#   -XX:+UseContainerSupport     : Respect cgroup memory limits
#   -XX:MaxRAMPercentage=75.0    : Use at most 75% of container memory
#   -XX:+UseG1GC                 : Low-latency garbage collector
#   -Dio.netty.leakDetection=simple : Netty buffer leak detection
ENV JAVA_OPTS="-XX:+UseContainerSupport \
               -XX:MaxRAMPercentage=75.0 \
               -XX:+UseG1GC \
               -Dio.netty.leakDetection=simple"

# Startup command
ENTRYPOINT ["sh", "-c", "java $JAVA_OPTS -jar /app/attack-node.jar"]
