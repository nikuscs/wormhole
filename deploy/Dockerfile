# syntax=docker/dockerfile:1.7
FROM --platform=$TARGETPLATFORM rust:1.97-alpine AS builder
RUN apk add --no-cache build-base clang cmake lld musl-dev perl
WORKDIR /src
COPY . .
RUN cargo build --release --locked -p wormholed \
    && strip target/release/wormholed \
    && mkdir -p /image/var/lib/wormhole/authorized_keys

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=builder /src/target/release/wormholed /usr/local/bin/wormholed
COPY --from=builder --chown=65532:65532 /image/var/lib/wormhole /var/lib/wormhole
VOLUME ["/etc/wormhole", "/var/lib/wormhole"]
EXPOSE 80/tcp 443/tcp 443/udp 10000-20000/tcp
ENTRYPOINT ["/usr/local/bin/wormholed"]
CMD ["serve"]
