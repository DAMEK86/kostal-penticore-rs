#[macro_use]
extern crate rocket;
extern crate core;

use std::process::exit;
use log::info;
use rocket::{Build, Rocket};
use std::thread::sleep;
use std::time::Duration;

mod client;
mod cfg;

#[rocket::get("/health")]
fn health() {}

#[launch]
async fn rocket() -> _ {
    env_logger::init();
    let cfg = match cfg::Settings::new() {
        Ok(cfg) => cfg,
        Err(error) => {
            eprintln!("can not load config: {error}");
            exit(1)
        }
    };

    let _collector = tokio::spawn(async move {
        let mut client = client::Client::new(&cfg.inverter);
        let server_final_data = client.get_server_trust().await.unwrap();
        info!("{:?}", server_final_data);
        client.set_session_id(&server_final_data);
        loop {
            match client
                .get_process_data_module("scb:statistic:EnergyFlow")
                .await
            {
                Ok(res) => {
                    if res.len() != 0 {
                        for data in res.iter() {
                            info!("{}", data);
                        }
                    }
                }
                Err(e) => {
                    eprintln!("{}", e)
                }
            }

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
    use super::*;
    use rocket::http::Status;

    #[test]
    fn test_health() {
        use rocket::local::blocking::Client;
        let client = Client::tracked(serve_rest_service()).unwrap();
        let resp = client.get("/health").dispatch();
        assert_eq!(resp.status(), Status::Ok);
    }
}
