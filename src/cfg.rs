use serde::Deserialize;
use config::{Config, ConfigError, Environment, File};

const DEFAULT_CONFIG_FILE_PATH: &str = "config/default.toml";
const CONFIG_FILE_PREFIX: &str = "config/";

#[derive(Debug, Deserialize)]
pub struct InfluxDB {
    pub url: String,
    pub db: String,
    pub user: String,
    pub password: String
}

#[derive(Debug, Deserialize)]
pub struct Inverter {
    pub username: String,
    pub password: String,
    /// Inverter URL
    /// # Examples
    /// ```
    /// http://192.168.178.100
    /// ```
    pub url: String,
}

#[derive(Debug, Deserialize)]
#[allow(unused)]
pub struct Settings {
    pub influx: InfluxDB,
    pub inverter: Inverter,
    pub polling_interval_sec: u64,
}

impl Settings {
    pub fn new() -> Result<Self, ConfigError> {
        let run_mode = std::env::var("RUN_MODE").unwrap_or_else(|_| "Development".into());
        let s = Config::builder()
            .add_source(vec![
                File::with_name(DEFAULT_CONFIG_FILE_PATH),
                File::with_name(&format!("{}{}", CONFIG_FILE_PREFIX, run_mode))
                    .required(false),
                File::with_name(&format!("{}{}", CONFIG_FILE_PREFIX, "local"))
                    .required(false),
            ])
            .add_source(Environment::with_prefix("app"))
            .build()?;
        s.try_deserialize()
}
}