# kostal-plenticore-rs

This is a single Rust binary that authenticates to one or more Kostal Plenticore
inverters, polls process data, and writes time-series points to InfluxDB. It
also serves `GET /health` so a process that cannot reach an inverter is still
probeable.

The goal is a small, obvious exporter: config in, metrics out. There is no
dashboard, no extra in-repo service, and no glue layer. Operators run this next
to real hardware; agents working here should keep that shape.

## Current status

The capsule already exists: Plenticore SCRAM-like auth, process-data polling,
InfluxDB writes, Rocket health, Docker image, and a CI build/test/publish
pipeline. What does not exist in this repository is the rest of a monitoring
stack (InfluxDB, Grafana) or a fake inverter. Those are external.

`Cargo.lock` is gitignored on purpose. Builds resolve to whatever the latest
compatible crates are. That is a fact of this repo, not an accident to "fix"
by committing a lockfile unless we explicitly decide to.

## Who this document is talking to

- *you* — the agent reading this and changing this repository.
- *we* / *us* — humans contributing to this exporter.
- *operators* — people who run the binary against real inverters and InfluxDB.
  They are the users. They are not you.

## How to think while working here

### Keep the binary boring

This project is an exporter, not a platform. When a change wants a new
service, a UI, or a second binary, push back. The obvious shape is still:
read config, poll inverters, write Influx, answer `/health`.

### Design for operators who already have hardware

Auth, polling, and writes assume a real Plenticore REST API and a real
InfluxDB. Do not invent a bundled mock stack "so the repo is self-contained"
unless we ask for that. Absence of hardware is an environment constraint, not
a product gap.

### Make the operator-default true

Config already has a default file, optional `RUN_MODE` files, gitignored
`config/local.*`, and `APP_` environment overrides. Prefer those over new
config channels. If an operator would assume "put secrets in `config/local.toml`",
that should keep working.

### Don't hide process death

Background poll tasks `unwrap` auth and I/O. In the release profile,
`panic = 'abort'` kills the whole process. That is the current contract.
Do not paper over it with silent retries unless we decide the contract
should change.

### Fight for the obvious solution

Avoid clever indirection. An agent (or operator) should be able to guess
where auth lives (`src/plenticore.rs`), where Influx writes live
(`src/app.rs`), and where config is loaded (`src/cfg.rs`) without a tour.

## Rules

These steer. They are not laws. If you need to break one, say so loudly
before doing it.

- preserve the single-binary exporter; do not grow a service mesh
- treat inverter + InfluxDB as external; this repo does not vendor them
- keep `config/local.*` gitignored; never commit operator secrets
- leave `Cargo.lock` uncommitted unless we explicitly change that policy
- require a current stable Rust toolchain; the Dockerfile's `1.83` pin is
  a publish image, not a guarantee that latest crates still compile on 1.83
- an empty `inverters` list is a valid way to run only the health server
- `/health` staying up while a poll task dies is a *dev-profile* accident
  of task isolation, not a release guarantee
- commands, toolchain install, and local run recipes live in
  `CONTRIBUTING.md` — do not duplicate them here
