# syntax=docker/dockerfile:1.7
FROM rust:1.97-alpine AS builder
RUN apk add --no-cache build-base clang cmake lld musl-dev perl \
    && rustup target add x86_64-unknown-linux-musl
WORKDIR /src
COPY . .
RUN cargo build --release --locked --target x86_64-unknown-linux-musl -p wormholed \
    && strip target/x86_64-unknown-linux-musl/release/wormholed

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=builder /src/target/x86_64-unknown-linux-musl/release/wormholed /usr/local/bin/wormholed
VOLUME ["/etc/wormhole", "/var/lib/wormhole"]
EXPOSE 80/tcp 443/tcp 443/udp 10000-20000/tcp
ENTRYPOINT ["/usr/local/bin/wormholed"]
CMD ["serve", "--config", "/etc/wormhole/wormholed.toml"]
