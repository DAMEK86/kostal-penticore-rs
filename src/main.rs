#[macro_use] extern crate rocket;

#[rocket::get("/health")]
pub fn health() {}

#[launch]
fn rocket() -> _ {
    let figment = rocket::Config::figment()
        .merge(("port", 8080))
        .merge(("address", "0.0.0.0"));

    rocket::custom(figment)
        .mount("/", routes![health])
}

#[cfg(test)]
mod tests {
    use super::*;
    use rocket::http::Status;

    #[test]
    fn test_health() {
        use rocket::local::blocking::Client;
        let client = Client::tracked(rocket()).unwrap();
        let resp = client.get("/health").dispatch();
        assert_eq!(resp.status(), Status::Ok);
    }
}
