# AGENTS.md

## Cursor Cloud specific instructions

This repo is a single Rust binary: `kostal-plenticore-rs`, an exporter that polls Kostal
Plenticore solar inverters and writes metrics to InfluxDB, while serving a minimal Rocket
`GET /health` endpoint.

### Toolchain caveat (important)

`Cargo.lock` is gitignored (see `.gitignore`), so dependencies always resolve to the latest
compatible versions. Some transitive crates now require Rust edition 2024 (Rust >= 1.88). The
base image ships Rust 1.83, which is too old and fails with `feature edition2024 is required`.
The startup update script installs the latest `stable` toolchain and sets it as the rustup
default, so a plain `cargo build`/`cargo run` works. If you ever see an `edition2024` error,
run `rustup default stable` (or `rustup toolchain install stable`).

### Standard commands

- Build (dev): `cargo build`
- Lint: `cargo clippy` (a couple of pre-existing warnings are expected)
- Format check: `cargo fmt --check`
- Test: `cargo test` (single in-process test hitting the Rocket `/health` route)
- Run (dev): `cargo run`

Rocket binds to port 8000 by default. The Dockerfile runs it on 8080 via env vars; to match
that locally use `ROCKET_PORT=8080 ROCKET_ADDRESS=0.0.0.0 cargo run`. Set `RUST_LOG=info` for
request/startup logs.

### Configuration and running end-to-end

Config uses [config-rs]: `config/default.json` is the baseline; override it with
`config/local.{toml,json,...}` (gitignored), a `RUN_MODE`-named file, or `APP_`-prefixed env
vars. The default config contains placeholder inverter/InfluxDB values.

Full data-export E2E requires real Kostal Plenticore inverter hardware plus an InfluxDB
instance, neither of which is available in the cloud environment. With placeholder inverter
config, the per-inverter background poll tasks fail authentication:
- In the dev profile a failing task panics but only kills that task, so the `/health` server
  keeps running.
- In the release profile `panic = 'abort'` would terminate the whole process.

For a clean local run without hardware, create `config/local.toml` with an empty inverter list
(`inverters = []`); the health server then starts with no background tasks. The exporter's only
externally observable runtime action without hardware is the `GET /health` endpoint returning
`200 OK`.
