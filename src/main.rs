extern crate core;
#[macro_use]
extern crate rocket;

use influx_db_client::point;
use log::info;
use rocket::{Build, Rocket};
use serde::Deserialize;
use std::process::exit;
use std::thread::sleep;
use std::time::Duration;

mod client;
mod app;
mod cfg;

#[rocket::get("/health")]
fn health() {}

#[launch]
async fn rocket() -> _ {
    env_logger::init();
    let cfg = match cfg::Settings::new() {
        Ok(cfg) => cfg,
        Err(error) => {
            error!("can not load config: {error}");
            exit(1)
        }
    };

    let influx_client = app::get_infux_db_client(&cfg.influx).unwrap();

    let collector = tokio::spawn(async move {
        let mut client = client::Client::new(&cfg.inverter);
        let server_final_data = client.get_server_trust().await.unwrap();
        info!("{:?}", server_final_data);
        client.set_session_id(&server_final_data);
        loop {
            let mut data = client.get_process_data_module("scb:statistic:EnergyFlow").await.unwrap();
            let dev_local = client.get_process_data_module("devices:local").await.unwrap();
            data.extend(dev_local);
            app::write_data(&influx_client, &data).await;

            sleep(Duration::from_secs(cfg.polling_interval_sec))
        }
    });

    serve_rest_service()
}

fn serve_rest_service() -> Rocket<Build> {
    info!("start serving health endpoint");
    rocket::build().mount("/", routes![health])
}

#[cfg(test)]
mod tests {
    use rocket::http::Status;

    use super::*;

    #[test]
    fn test_health() {
        use rocket::local::blocking::Client;
        let client = Client::tracked(serve_rest_service()).unwrap();
        let resp = client.get("/health").dispatch();
        assert_eq!(resp.status(), Status::Ok);
    }
}
