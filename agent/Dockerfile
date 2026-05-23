# ─────────────────────────────────────────────────────────────────────────────
# IronClaw Shade Agent — Production Dockerfile
#
# Multi-stage build:
#   Stage 1 (builder): Full Rust toolchain — compiles the release binary.
#   Stage 2 (runtime): Minimal Debian slim — ships ONLY the binary + CA certs.
#
# The final image is ~30–40 MB and has zero build tools, making it suitable
# for running inside a Phala Network TDX enclave or any OCI-compatible TEE.
#
# Build:
#   docker build -t ironclaw-agent:latest .
#
# Run (simulation mode — local dev):
#   docker run --rm -p 8080:8080 \
#     -e TEE_SIMULATION=true \
#     -e IRONCLAW_AGENT_API_KEY=dev-key \
#     -e LLM_API_KEY=sk-... \
#     -e ALLOWED_ORIGIN=http://localhost:5173 \
#     ironclaw-agent:latest
#
# Run (production — TEE sealed key):
#   docker run --rm -p 8080:8080 \
#     -e TEE_SEALED_KEY=<64-char-hex> \
#     -e IRONCLAW_AGENT_API_KEY=<prod-key> \
#     -e LLM_API_KEY=<llm-key> \
#     -e ALLOWED_ORIGIN=https://aipassports.xyz \
#     ironclaw-agent:latest
# ─────────────────────────────────────────────────────────────────────────────

# ── Stage 1: Builder ──────────────────────────────────────────────────────────
FROM rust:1.82-slim-bookworm AS builder

# Install only what cargo needs to link against OpenSSL for reqwest
RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Layer cache: copy manifests first so cargo fetch is cached unless deps change
COPY Cargo.toml Cargo.lock ./

# Create a dummy main to allow `cargo build --release` to cache dependency compilation
RUN mkdir -p src && echo 'fn main() {}' > src/main.rs \
    && cargo build --release \
    && rm -f target/release/deps/shade_agent*

# Now copy real source and build the actual binary
COPY src/ src/
RUN cargo build --release

# ── Stage 2: Runtime ──────────────────────────────────────────────────────────
FROM debian:bookworm-slim AS runtime

# Install CA certificates (reqwest needs them for HTTPS to Walrus and NEAR RPC)
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create a non-root user — the agent binary does not need root access
RUN useradd --no-create-home --shell /bin/false agent

WORKDIR /app

# Copy only the release binary from the builder stage
COPY --from=builder /build/target/release/shade-agent /app/shade-agent

# Ensure the binary is executable by the agent user
RUN chown agent:agent /app/shade-agent

USER agent

# Default port — overridable via PORT env var
EXPOSE 8080

# Environment defaults (all required vars must be injected at runtime)
# TEE_SIMULATION=false by default → requires TEE_SEALED_KEY in production
ENV PORT=8080 \
    TEE_SIMULATION=false

ENTRYPOINT ["/app/shade-agent"]
