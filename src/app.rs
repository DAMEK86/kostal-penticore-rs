use crate::plenticore::ProcessDataValues;
use influx_db_client::{point, Client, Point, Precision};
use log::info;

pub fn get_infux_db_client(
    cfg: &crate::cfg::InfluxDB,
) -> Result<Client, Box<dyn std::error::Error>> {
    let client = Client::new(
        format!("{}:{}", cfg.url, cfg.port).parse().unwrap(),
        cfg.db.as_str(),
    )
    .set_authentication(cfg.user.as_str(), cfg.password.as_str());
    Ok(client)
}

pub async fn write_data_with_point_name(
    client: &Client,
    influx_id: &str,
    process_values: &[ProcessDataValues],
) -> Result<(), Box<dyn std::error::Error>> {
    let mut point = point!(influx_id);
    for values in process_values.iter() {
        for data in &values.process_data {
            point = point.add_field(data.id.as_str(), data.value as f64);
        }
    }
    let field_count = point.fields.len();
    if !point.fields.is_empty() {
        client
            .write_point(point, Some(Precision::Seconds), None)
            .await?;
    }
    info!("{field_count} fields written to point {influx_id}");
    Ok(())
}

#[deprecated(since = "0.2.0", note = "use `write_data_with_point_name` instead")]
pub async fn write_data(
    client: &Client,
    process_values: &[ProcessDataValues],
) -> Result<(), Box<dyn std::error::Error>> {
    write_data_with_point_name(client, "pvwr", process_values).await
}
