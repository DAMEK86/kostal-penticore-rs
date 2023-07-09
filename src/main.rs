extern crate core;
#[macro_use]
extern crate rocket;
use influx_db_client::client;
use log::info;
use rocket::{Build, Rocket};
use std::process::exit;
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

    let influx_client = app::get_infux_db_client(&cfg.influx).unwrap();

    let _ = tokio::spawn(async move {
        let mut client = plenticore::Client::new(&cfg.inverters[0].inverter);
        let server_final_data = client.get_server_trust().await.unwrap();
        info!("{:?}", server_final_data);
        client.set_session_id(&server_final_data);
        loop {
            collect_and_upload(&influx_client, client, &cfg.inverters[0].influx_id).await;

            sleep(Duration::from_secs(cfg.polling_interval_sec))
        }
    });

    serve_rest_service()
}

async fn collect_and_upload(
    influx_client: &client::Client,
    plenticore: plenticore::Client<'_>,
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
