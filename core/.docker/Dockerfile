# ARES V3 Sandbox Environment
# Multi-stage build with Rust, Solana CLI, Anchor, and Trident

# ==========================================
# Builder stage: compile ARES CLI
# ==========================================
FROM rust:1.75-slim-bookworm AS builder

WORKDIR /usr/src/ares

# Install build dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    libudev-dev \
    git \
    && rm -rf /var/lib/apt/lists/*

# Copy workspace
COPY Cargo.toml Cargo.lock ./
COPY crates/ ./crates/

# Build release binary
RUN cargo build --release --bin ares

# ==========================================
# Runtime stage: Solana tooling + ARES
# ==========================================
FROM debian:bookworm-slim

LABEL maintainer="ARES Team"
LABEL description="ARES V3 — Autonomous Solana Security Auditor Sandbox"

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    curl \
    wget \
    git \
    ca-certificates \
    libssl3 \
    libudev1 \
    python3 \
    python3-pip \
    nodejs \
    npm \
    && rm -rf /var/lib/apt/lists/*

# Install Solana CLI
ENV SOLANA_VERSION=1.18.18
RUN curl -sSfL https://release.solana.com/v${SOLANA_VERSION}/solana-install-init-x86_64-unknown-linux-gnu -o /usr/local/bin/solana-install-init \
    && chmod +x /usr/local/bin/solana-install-init \
    && solana-install-init ${SOLANA_VERSION} \
    && rm /usr/local/bin/solana-install-init
ENV PATH="/root/.local/share/solana/install/active_release/bin:${PATH}"

# Install Anchor CLI
RUN cargo install --git https://github.com/coral-xyz/anchor avm \
    && avm install latest \
    && avm use latest

# Install Trident CLI
RUN cargo install trident-cli

# Install Node.js tooling for Anchor tests
RUN npm install -g yarn

# Copy ARES binary from builder
COPY --from=builder /usr/src/ares/target/release/ares /usr/local/bin/ares
RUN chmod +x /usr/local/bin/ares

# Create workspace directories
RUN mkdir -p /workspace/program /workspace/ares-output /workspace/dataset
WORKDIR /workspace

# Copy default configs
COPY ares.toml.template /workspace/ares.toml
COPY ares-policy.toml.template /workspace/ares-policy.toml

# Set up Solana config for local testing
RUN solana config set --url localhost

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD ares doctor || exit 1

# Default entrypoint
ENTRYPOINT ["ares"]
CMD ["--help"]

# ==========================================
# Security notes:
# - This container runs as root for tooling convenience
# - In production, run with --read-only + tmpfs mounts
# - Network access is restricted by host firewall rules
# - Git remote operations are disabled by policy
# ==========================================
