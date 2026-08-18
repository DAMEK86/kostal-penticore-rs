# Contributing

## Toolchain

Docker and CI are pinned to **Rust 1.97**. `Cargo.lock` is gitignored, so
`cargo build` resolves latest crates — some need edition 2024 (Rust >= 1.88).
The old `rust:1.83` image fails with `feature edition2024 is required`.

```bash
rustup toolchain install stable --profile minimal -c clippy -c rustfmt
rustup default stable
cargo fetch
```

## Commands

```bash
cargo build
cargo clippy
cargo fmt --check
cargo test
cargo run
```

Rocket defaults to port **8000**. The Dockerfile sets `ROCKET_PORT=8080` and
`ROCKET_ADDRESS=0.0.0.0`. For logs: `RUST_LOG=info`.

`cargo test` is in-process and only hits `GET /health`. It does not need an
inverter or InfluxDB.

## Config

See `README.md`. Baseline is `config/default.json`. Override with
`config/local.{toml,json,...}` (gitignored), a `RUN_MODE` file, or `APP_`
env vars.

## Running without hardware

Placeholder inverter URLs in the default config will fail auth. In **dev**,
that panics only the poll task; the health server keeps running. In
**release**, `panic = 'abort'` kills the process.

To serve health only:

```toml
# config/local.toml
polling_interval_sec = 5
inverters = []

[influx]
url = "http://localhost"
port = 8086
db = "influx-db"
user = "root"
password = ""
```

Then:

```bash
RUST_LOG=info ROCKET_PORT=8080 ROCKET_ADDRESS=127.0.0.1 cargo run
curl -i http://127.0.0.1:8080/health   # 200 OK
```

Full export still needs a reachable Plenticore API and InfluxDB. Those are
not part of this repository.
