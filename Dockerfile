# syntax=docker/dockerfile:1.7
#
# Multi-stage build for marlinspike-dpi. Produces a slim runtime image
# (~30 MB on top of debian:bookworm-slim) carrying the CLI binary plus
# the ICS-defense-corpus validator.
#
# Build:    docker build -t marlinspike-dpi:latest .
# Run:      docker run --rm -v "$PWD/cap.pcap:/in.pcap:ro" marlinspike-dpi:latest --input /in.pcap --pretty
# OCSF:     docker run --rm -v "$PWD/cap.pcap:/in.pcap:ro" marlinspike-dpi:latest --input /in.pcap --format ocsf
# Influx:   docker run --rm -v "$PWD/cap.pcap:/in.pcap:ro" marlinspike-dpi:latest --input /in.pcap --format influx

ARG RUST_VERSION=1.85

# ── Stage 1: build ────────────────────────────────────────────────────────
FROM rust:${RUST_VERSION}-bookworm AS builder

WORKDIR /build

# Cache dependency compile by pulling Cargo.toml/Cargo.lock first.
# (The dummy main.rs gets overwritten when the real source is copied.)
COPY Cargo.toml Cargo.lock ./
COPY vendor ./vendor
RUN mkdir -p src && echo "fn main() {}" > src/main.rs && \
    echo "// dummy lib" > src/lib.rs && \
    cargo build --release --bin marlinspike-dpi 2>/dev/null || true

# Now copy the real source and build for real.
COPY src ./src
COPY benches ./benches
COPY tests ./tests
COPY examples ./examples
COPY build.rs ./build.rs

RUN cargo build --release --bin marlinspike-dpi --bin ics-defense-corpus

# Strip debug symbols for the slim image.
RUN strip target/release/marlinspike-dpi target/release/ics-defense-corpus

# ── Stage 2: runtime ──────────────────────────────────────────────────────
FROM debian:bookworm-slim AS runtime

# ca-certificates only — we don't need libpcap (pure-Rust DPI) and we
# don't talk HTTP from the engine itself, but having CA roots available
# is useful for the quickstart fetch script if a user runs it via docker.
RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates && \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/target/release/marlinspike-dpi /usr/local/bin/marlinspike-dpi
COPY --from=builder /build/target/release/ics-defense-corpus /usr/local/bin/ics-defense-corpus

# Bake the ICS-defense corpus manifest into the image so the corpus binary
# has its config without needing a bind mount.
COPY corpus /opt/marlinspike-dpi/corpus

# Non-root user.
RUN useradd --system --no-create-home --shell /usr/sbin/nologin marlinspike
USER marlinspike

WORKDIR /work

ENTRYPOINT ["marlinspike-dpi"]
CMD ["--help"]

LABEL org.opencontainers.image.title="marlinspike-dpi" \
      org.opencontainers.image.description="Pure-Rust passive deep packet inspection for OT/ICS and IT — PCAP/PCAPNG → Bronze v2 / OCSF / InfluxDB" \
      org.opencontainers.image.source="https://github.com/eris-ot/marlinspike-dpi" \
      org.opencontainers.image.licenses="AGPL-3.0-or-later" \
      org.opencontainers.image.documentation="https://github.com/eris-ot/marlinspike-dpi/blob/main/README.md"
