# SereS (Rust backend) as a container. The data (database with pictures and
# attachments) lives in the volume /data, the settings come from .env (see
# .env.example).

# Build the backend.
FROM rust:1-bookworm AS build
WORKDIR /build
COPY src/backend-rs/ ./
RUN cargo build --release --locked && mkdir /data

# Small runtime image: glibc, OpenSSL and CA certificates, no shell.
FROM gcr.io/distroless/cc-debian12
COPY --from=build /build/target/release/seres-backend /usr/local/bin/seres-backend
COPY src/public/ /app/public/
COPY --from=build --chown=1000:1000 /data /data

# Doesn't run as root. UID 1000 so files in ./data belong to the usual first
# user on the host.
USER 1000:1000
# HOST, PORT and SERES_EXTRA_HOST (e.g. ::1) can be changed in .env.
ENV SERES_DATA_DIR=/data \
    SERES_PUBLIC_DIR=/app/public \
    HOST=127.0.0.1 \
    PORT=2222

EXPOSE 2222
CMD ["/usr/local/bin/seres-backend"]
