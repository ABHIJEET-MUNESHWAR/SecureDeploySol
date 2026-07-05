# SecureDeploySol off-chain audit service — multi-stage production image.
#
# Builds the `securedeploy-node` binary with the `postgres` feature and ships it
# on a slim non-root Debian base.

FROM rust:1.89-slim-bookworm AS build
RUN apt-get update \
    && apt-get install -y --no-install-recommends pkg-config libssl-dev \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY crates/ crates/
# Build only the off-chain workspace (anchor/ is a separate workspace).
RUN cargo build --release -p securedeploy-node \
    && strip target/release/securedeploy-node

FROM debian:bookworm-slim AS runtime
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --uid 10001 --user-group --home-dir /nonexistent --no-create-home securedeploy
COPY --from=build /app/target/release/securedeploy-node /usr/local/bin/securedeploy-node
USER 10001
EXPOSE 8080
ENV SD_BIND_ADDR=0.0.0.0:8080 RUST_LOG=info
ENTRYPOINT ["/usr/local/bin/securedeploy-node"]
CMD ["serve"]
