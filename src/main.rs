#[macro_use]
extern crate rocket;
extern crate core;
use log::info;
use rocket::{Build, Rocket};
use serde::Deserialize;

mod client;

#[derive(Deserialize, Debug)]
struct Configuration {
    #[serde(default = "default_user")]
    username: String,
    password: String,
    /// Inverter URL
    /// # Examples
    /// ```
    /// http://192.168.178.100
    /// ```
    inverter_url: String,
}

fn default_user() -> String {
    "user".to_string()
}

#[rocket::get("/health")]
fn health() {}

#[launch]
async fn rocket() -> _ {
    env_logger::init();
    let cfg = envy::from_env::<Configuration>().unwrap();

    let mut client = client::Client::new(&cfg.inverter_url, &cfg.username, &cfg.password);
    let server_final_data = client.get_server_trust().await;
    info!("{:?}", server_final_data);

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
