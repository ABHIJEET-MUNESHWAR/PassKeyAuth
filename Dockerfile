# ---- Build stage ----
# The runnable artifact is the off-chain identity service node (its own workspace
# in ./offchain). Pin to the same stable Rust the CI uses; bookworm matches the
# glibc of the runtime base image.
FROM rust:1.95-slim-bookworm AS builder
WORKDIR /build
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc g++ make pkg-config && rm -rf /var/lib/apt/lists/*

COPY offchain/ .
RUN cargo build --release --bin passkeyauth-node

# ---- Runtime stage ----
FROM debian:bookworm-slim AS runtime
RUN useradd -r -u 10001 passkeyauth
COPY --from=builder /build/target/release/passkeyauth-node /usr/local/bin/passkeyauth-node
USER passkeyauth
EXPOSE 8080
ENTRYPOINT ["passkeyauth-node"]
CMD ["--bind", "0.0.0.0:8080"]
