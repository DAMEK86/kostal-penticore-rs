use crate::plenticore::InverterCfg;
use config::{Config, ConfigError, Environment, File};
use serde::Deserialize;

const DEFAULT_CONFIG_FILE_PATH: &str = "config/default.json";
const CONFIG_FILE_PREFIX: &str = "config/";

#[derive(Debug, Deserialize)]
pub struct InfluxDB {
    pub url: String,
    pub port: String,
    pub db: String,
    pub user: String,
    pub password: String,
}

#[derive(Debug, Deserialize)]
pub struct Inverter {
    pub inverter: InverterCfg,
    pub influx_id: String,
}

#[derive(Debug, Deserialize)]
#[allow(unused)]
pub struct Settings {
    pub influx: InfluxDB,
    pub inverters: Vec<Inverter>,
    pub polling_interval_sec: u64,
}

impl Settings {
    pub fn new() -> Result<Self, ConfigError> {
        let run_mode = std::env::var("RUN_MODE").unwrap_or_else(|_| "Development".into());
        let s = Config::builder()
            .add_source(vec![
                File::with_name(DEFAULT_CONFIG_FILE_PATH),
                File::with_name(&format!("{}{}", CONFIG_FILE_PREFIX, run_mode)).required(false),
                File::with_name(&format!("{}{}", CONFIG_FILE_PREFIX, "local")).required(false),
            ])
            .add_source(Environment::with_prefix("app"))
            .build()?;
        s.try_deserialize()
    }
}
