################
##### Builder
FROM ekidd/rust-musl-builder as builder

ADD --chown=rust:rust ./Cargo.toml ./

RUN mkdir -p ./src && touch ./src/main.rs && cargo fetch

ADD --chown=rust:rust ./src ./src

# This is a dummy build to get the dependencies cached.
RUN cargo build --release

################
##### Runtime
FROM alpine:3 AS runtime

ARG UID=1001
ARG USER=app
ARG GID=1001
ARG GROUP=app
ENV WORKINGDIR /app

EXPOSE 8080

RUN apk --no-cache add ca-certificates

WORKDIR $WORKINGDIR
RUN addgroup -g $GID -S $GROUP && adduser -u $UID -S $USER -G $GROUP && \
    mkdir -p /app &&\
    chown -R $USER:$GROUP /app

# Copy application binary from builder image
COPY --from=builder /home/rust/src/target/x86_64-unknown-linux-musl/release/kostal-plenticore-rs /app

USER $USER
ENV RUST_LOG=info
ENV ROCKET_PORT=8080
ENV ROCKET_ADDRESS=0.0.0.0

# Run the application
CMD ./kostal-plenticore-rs