# syntax=docker/dockerfile:1
# --- build ---
FROM rust:1.99.0-slim-bookworm AS build
WORKDIR /app

# Cache de dependências: compila um main vazio primeiro.
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo "fn main() {}" > src/main.rs && touch src/lib.rs \
    && cargo build --release --locked \
    && rm -rf src

COPY src ./src
RUN touch src/main.rs src/lib.rs && cargo build --release --locked

# --- runtime ---
FROM debian:bookworm-slim AS runtime
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --no-create-home --shell /usr/sbin/nologin vibeshield

COPY --from=build /app/target/release/vibeshield-api /usr/local/bin/vibeshield-api

USER 10001:10001
ENV PORT=8080 RUST_LOG=info
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/vibeshield-api"]
