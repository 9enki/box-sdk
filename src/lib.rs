use anyhow::{Context, Result};
use dotenv::dotenv;
use hyper::{client::HttpConnector, Body, Client, Request, Uri};
use hyper_tls::HttpsConnector;
use log::{error, info};
use std::fs::File;
use std::io::prelude::*;
use std::path::Path;

pub type HttpsClient = hyper::Client<HttpsConnector<HttpConnector>>;
const BOUNDARY: &'static str = "--------------------------acebdf13572468";

#[allow(dead_code)]
pub enum ContentType {
    TextPlain,
    ApplicationPdf,
    ApplicationZip,
}

impl ContentType {
    fn to_str(&self) -> &str {
        match self {
            ContentType::TextPlain => "text/plain",
            ContentType::ApplicationPdf => "application/pdf",
            ContentType::ApplicationZip => "application/zip",
        }
    }
}

pub fn create_https_client() -> HttpsClient {
    let https = HttpsConnector::new();
    let client = Client::builder().build::<_, hyper::Body>(https);

    client
}

pub fn get_multipart_form_data(
    parent_id: &str,
    file_path: &str,
    content_type: ContentType,
) -> Result<Vec<u8>> {
    let path = Path::new(file_path);
    let file_name = path.file_name().unwrap().to_str().unwrap();

    let mut file = match File::open(file_path) {
        Ok(f) => f,
        Err(e) => {
            error!("Failed to open file: {}", file_path);
            return Err(e.into());
        }
    };

    let mut data = Vec::new();

    write!(
        data,
        "--{}\r\n\
        Content-Disposition: form-data; name=\"attributes\"\r\n\
        \r\n\
        {{\"name\":\"{}\", \"parent\":{{\"id\":\"{}\"}}}}\r\n\
        --{}\r\n\
        Content-Disposition: form-data; name=\"file\"; filename=\"{}\"\r\n\
        Content-Type: {}\r\n\
        \r\n",
        BOUNDARY,
        file_name,
        parent_id,
        BOUNDARY,
        file_name,
        content_type.to_str()
    )?;
    file.read_to_end(&mut data)?;
    write!(data, "\r\n--{}--\r\n", BOUNDARY)?;

    Ok(data)
}

pub async fn get_box_token(client: &HttpsClient) -> Result<String> {
    dotenv().ok();

    let box_client_id = std::env::var("BOX_CLIENT_ID").unwrap();
    let box_client_secret = std::env::var("BOX_CLIENT_SECRET").unwrap();
    let box_enterprise_id = std::env::var("BOX_ENTERPRISE_ID").unwrap();

    let body = format!(
        "client_id={}&client_secret={}&grant_type=client_credentials&box_subject_type=enterprise&box_subject_id={}",
        box_client_id, box_client_secret, box_enterprise_id);

    let req = Request::builder()
        .method("POST")
        .uri(Uri::from_static("https://api.box.com/oauth2/token"))
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(hyper::Body::from(body))
        .unwrap();

    let res = client.request(req).await?;

    info!("\ntoken api response: {:?}\n", res);

    let status = res.status();
    let buf = hyper::body::to_bytes(res)
        .await
        .context("Can not to_bytes res.body")?;

    if status.is_success() {
        info!(
            "\nPOST https://api.box.com/oauth2/token\nstatus: {}\nbody: {:?}\n",
            status, buf
        );

        let json_data = std::str::from_utf8(&buf)?;

        let v: serde_json::Value = serde_json::from_str(json_data)
            .context(format!("Can not desirialize this string: {}", json_data))?;

        let token = v.get("access_token").unwrap().as_str().unwrap();

        Ok(token.to_string())
    } else {
        Err(anyhow::anyhow!(
            "\nstatus code: {}\nresponse body message: {:?}\n",
            status,
            buf
        ))
    }
}

pub async fn call_box_upload_file_api(
    client: &HttpsClient,
    token: &str,
    multipart_form_data: Vec<u8>,
) -> Result<()> {
    let req = Request::builder()
        .method("POST")
        .uri(Uri::from_static(
            "https://upload.box.com/api/2.0/files/content",
        ))
        .header("Authorization", format!("Bearer {}", token))
        .header(
            "Content-Type",
            format!("multipart/form-data; boundary={}", BOUNDARY),
        )
        .body(Body::from(multipart_form_data))
        .unwrap();

    let res = client.request(req).await?;

    info!("\nupload api response: {:?}\n", res);

    let status = res.status();
    let buf = hyper::body::to_bytes(res)
        .await
        .context("Can not to_bytes res.body")?;

    if status.is_success() {
        info!(
            "\nPOST https://api.box.com/oauth2/token\nstatus: {}\nbody: {:?}\n",
            status, buf
        );
    } else {
        error!(
            "\nstatus code: {}\nresponse body message: {:?}\n",
            status, buf
        );
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_multipart_form_data() {
        let parent_id = "11446498";
        let file_path = "fixtures/actual_multipart_form_data.txt";
        let content_type = ContentType::TextPlain;

        let mut expected_data = Vec::new();
        let expected_file_name = "fixtures/expected_multipart_form_data.txt";
        File::open(expected_file_name)
            .unwrap()
            .read_to_end(&mut expected_data)
            .unwrap();

        let actual_data = get_multipart_form_data(parent_id, file_path, content_type).unwrap();

        assert_eq!(expected_data, actual_data);
    }
}