# kappa-registry conforming /v2/ registry.
#
# Build:
#   cargo build --release -p kappa-server
#   docker build -t kappa-registry .
#
# Run:
#   docker run --rm -p 5000:5000 \
#     -v ./data:/data \
#     -e KAPPA_STORE_ROOT=/data \
#     -e KAPPA_LISTEN_ADDR=0.0.0.0:5000 \
#     kappa-registry

FROM scratch
COPY target/release/kappa-server /kappa-server
ENTRYPOINT ["/kappa-server"]
