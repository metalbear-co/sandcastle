FROM rust:1.87-slim AS builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*

COPY . .

RUN cargo build --release -p sandcastle

# ── Runtime image ─────────────────────────────────────────────────────────────
FROM debian:bookworm-slim

RUN apt-get update \
 && apt-get install -y ca-certificates \
 && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/sandcastle /usr/local/bin/sandcastle

ENV PORT=8080
EXPOSE 8080

CMD ["sandcastle"]
