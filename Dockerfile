################
##### Builder
FROM rust:1.83-bookworm as builder

WORKDIR /app

ADD --chown=rust:rust ./Cargo.toml ./

RUN mkdir -p ./src && touch ./src/main.rs && cargo fetch

ADD --chown=rust:rust ./src ./src

# This is a dummy build to get the dependencies cached.
RUN cargo build --release

################
##### Runtime
FROM debian:bookworm-slim AS runtime

ARG UID=1001
ARG USER=app
ARG GID=1001
ENV WORKINGDIR /app

EXPOSE 8080

RUN apt-get update && \
    apt-get install -y --no-install-recommends adduser openssl && \
    apt-get purge -y --autoremove && \
    apt-get clean -qy && \
    rm -rf /var/lib/apt/lists/*

WORKDIR $WORKINGDIR
RUN addgroup --gid $GID $USER && \
    adduser --uid $UID --gid $GID $USER && \
    mkdir -p /app &&\
    chown -R $USER:$GROUP /app

# Copy application binary from builder image
COPY --from=builder /app/target/release/kostal-plenticore-rs /app

USER $USER
ENV RUST_LOG=info
ENV ROCKET_PORT=8080
ENV ROCKET_ADDRESS=0.0.0.0

# Run the application
CMD ./kostal-plenticore-rs