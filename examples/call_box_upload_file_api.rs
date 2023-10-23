extern crate box_sdk;

use anyhow::Result;
use env_logger::Builder;
use log::LevelFilter;

#[tokio::main]
async fn main() -> Result<()> {
    Builder::new().filter(None, LevelFilter::Debug).init();

    let client = box_sdk::create_https_client();
    let token = box_sdk::get_box_token(&client).await?;
    let data = box_sdk::get_multipart_form_data_from_file(
        "111111111111",
        "sample.txt",
        box_sdk::ContentType::TextPlain,
    )?;

    box_sdk::call_box_upload_file_api(&client, &token, data).await?;

    Ok(())
}
