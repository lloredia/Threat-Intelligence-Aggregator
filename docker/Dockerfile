# Build stage - use nightly for edition2024 support
FROM rustlang/rust:nightly-bookworm AS builder

WORKDIR /app

# Copy manifests
COPY Cargo.toml ./

# Create src directory structure
RUN mkdir -p src/models src/api src/storage src/enrichment src/collectors && \
    echo "fn main() { println!(\"placeholder\"); }" > src/main.rs && \
    echo "pub mod ioc_utils;" > src/models/mod.rs && \
    echo "" > src/models/ioc_utils.rs && \
    echo "" > src/api/mod.rs && \
    echo "" > src/storage/mod.rs && \
    echo "pub mod geoip; pub mod dns; pub mod whois; pub mod abuseipdb; pub mod virustotal;" > src/enrichment/mod.rs && \
    echo "" > src/enrichment/geoip.rs && \
    echo "" > src/enrichment/dns.rs && \
    echo "" > src/enrichment/whois.rs && \
    echo "" > src/enrichment/abuseipdb.rs && \
    echo "" > src/enrichment/virustotal.rs && \
    echo "pub mod honeytrap; pub mod alienvault; pub mod emerging_threats;" > src/collectors/mod.rs && \
    echo "" > src/collectors/honeytrap.rs && \
    echo "" > src/collectors/alienvault.rs && \
    echo "" > src/collectors/emerging_threats.rs && \
    cargo build --release 2>&1 || true

# Copy actual source code
COPY src ./src

# Build the actual application
RUN cargo build --release

# Runtime stage
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy binary from builder
COPY --from=builder /app/target/release/sentinelforge /app/sentinelforge

# Create data directory
RUN mkdir -p /data

EXPOSE 8080

CMD ["/app/sentinelforge", "--migrate"]