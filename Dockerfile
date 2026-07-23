# kappa-registry conforming /v2/ registry.
#
# Build:
#   cargo build --release --target x86_64-unknown-linux-musl
#   docker build -t kappa-registry .
#
# Run:
#   docker run --rm -p 8080:8080 \
#     -v ./data:/data \
#     -e KAPPA_STORE_ROOT=/data \
#     -e KAPPA_LISTEN_ADDR=0.0.0.0:8080 \
#     kappa-registry

ARG RUST_TARGET=x86_64-unknown-linux-musl
FROM scratch
COPY target/${RUST_TARGET}/release/kappa-registry /kappa-registry
ENTRYPOINT ["/kappa-registry"]
