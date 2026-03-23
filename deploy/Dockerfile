FROM rust:1.87-slim AS builder

WORKDIR /app

RUN apt-get update && apt-get install -y pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*

COPY . .

RUN cargo build --release -p sandcastle

FROM gcr.io/distroless/cc-debian12

COPY --from=builder /app/target/release/sandcastle /sandcastle

ENV PORT=8080
EXPOSE 8080

CMD ["/sandcastle"]
