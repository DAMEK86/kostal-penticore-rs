extern crate core;
#[macro_use]
extern crate rocket;

use influx_db_client::client;
use log::info;
use rocket::{Build, Rocket};
use std::ops::Deref;
use std::process::exit;
use std::sync::Arc;
use std::thread::sleep;
use std::time::Duration;

mod app;
mod cfg;
mod plenticore;

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

    let influx_client: Arc<influx_db_client::Client> =
        Arc::new(app::get_infux_db_client(&cfg.influx).unwrap());

    for inverter_cfg in cfg.inverters {
        let db_client = Arc::clone(&influx_client);
        tokio::spawn(async move {
            init_and_run(db_client, cfg.polling_interval_sec, &inverter_cfg).await;
        });
    }

    serve_rest_service()
}

async fn init_and_run(
    influx_client: Arc<influx_db_client::Client>,
    polling_interval_sec: u64,
    inverter_cfg: &cfg::Inverter,
) {
    let mut client = plenticore::Client::new(&inverter_cfg.inverter);
    let server_final_data = client.get_server_trust().await.unwrap();
    info!("session established to inverter {}", inverter_cfg.influx_id);
    client.set_session_id(&server_final_data);
    loop {
        collect_and_upload(influx_client.deref(), &client, &inverter_cfg.influx_id).await;
        sleep(Duration::from_secs(polling_interval_sec))
    }
}

async fn collect_and_upload(
    influx_client: &client::Client,
    plenticore: &plenticore::Client<'_>,
    influx_id: &str,
) {
    let mut data = plenticore
        .get_process_data_module("scb:statistic:EnergyFlow")
        .await
        .unwrap();
    let dev_local = plenticore
        .get_process_data_module("devices:local")
        .await
        .unwrap();
    data.extend(dev_local);

    let pv_string1 = "devices:local:pv1";
    data.extend(plenticore::Client::extend_process_data_value(
        pv_string1,
        plenticore
            .get_process_data_module(pv_string1)
            .await
            .unwrap(),
    ));

    let pv_string2 = "devices:local:pv2";
    data.extend(plenticore::Client::extend_process_data_value(
        pv_string2,
        plenticore
            .get_process_data_module(pv_string2)
            .await
            .unwrap(),
    ));
    let _ = app::write_data_with_point_name(influx_client, influx_id, &data).await;
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
