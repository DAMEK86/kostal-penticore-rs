# kostal-penticore-rs

## config

config is based on awesome [config-rs crate](https://github.com/mehcode/config-rs).

for local development: create `config/local.{toml,json,..}` and override values  
config is able to work with different run modes, e.g. Prod by setting `RUN_MODE` environment variable
furthermore, you can override settings by using prefix `APP_`, e.g. `APP_INVERTER_URL=...`.

