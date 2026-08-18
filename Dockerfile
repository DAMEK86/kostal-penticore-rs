################
##### Builder
FROM rust:bookworm AS builder

WORKDIR /app

COPY Cargo.toml ./
RUN mkdir -p src && echo "fn main() {}" > src/main.rs && cargo fetch

COPY src ./src
RUN touch src/main.rs && cargo build --release

################
##### Runtime
FROM debian:bookworm-slim AS runtime

ARG UID=1001
ARG USER=app
ARG GID=1001
ARG GROUP=app
ENV WORKINGDIR=/app

EXPOSE 8080

RUN apt-get update && \
    apt-get install -y --no-install-recommends adduser ca-certificates && \
    apt-get purge -y --autoremove && \
    apt-get clean -qy && \
    rm -rf /var/lib/apt/lists/*

WORKDIR $WORKINGDIR
RUN addgroup --gid $GID $GROUP && \
    adduser --uid $UID --gid $GID --disabled-password --gecos "" $USER && \
    mkdir -p /app/config && \
    chown -R $USER:$GROUP /app

COPY --from=builder /app/target/release/kostal-plenticore-rs /app
COPY config/default.json config/default.toml /app/config/

USER $USER
ENV RUST_LOG=info
ENV ROCKET_PORT=8080
ENV ROCKET_ADDRESS=0.0.0.0

CMD ["./kostal-plenticore-rs"]
