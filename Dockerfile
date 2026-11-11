# syntax=docker/dockerfile:1

# ---- web UI ---------------------------------------------------------------
# Node 24 / npm 11: the lockfile is npm-11 generated; npm 10.9 hangs on it.
FROM node:24.15.0-bookworm-slim AS web
WORKDIR /src/web
COPY web/package.json web/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY web/ ./
RUN npm run build

# ---- server binary --------------------------------------------------------
FROM rust:1.99-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked -p copperhound \
 && cp target/release/copperhound /copperhound

# ---- runtime --------------------------------------------------------------
FROM debian:bookworm-slim
RUN useradd --system --uid 10001 --home-dir /data copperhound \
 && mkdir -p /data /app \
 && chown copperhound:copperhound /data
COPY --from=build /copperhound /usr/local/bin/copperhound
COPY --from=web /src/web/dist /app/web
ENV COPPERHOUND_LISTEN=0.0.0.0:8080 \
    COPPERHOUND_DATA_DIR=/data \
    COPPERHOUND_WEB_DIR=/app/web \
    RUST_LOG=info,tower_http=warn
USER copperhound
VOLUME ["/data"]
EXPOSE 8080
HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=3 CMD ["copperhound", "healthcheck"]
ENTRYPOINT ["copperhound"]
CMD ["serve"]
