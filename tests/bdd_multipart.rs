use super::BddWorld;
use cucumber::{then, when};
use http::StatusCode;

fn client() -> reqwest::Client {
    let mut headers = http::HeaderMap::new();
    headers.insert(
        "authorization",
        http::HeaderValue::from_static("Bearer bdd-multipart"),
    );
    headers.insert(
        "x-amz-content-sha256",
        http::HeaderValue::from_static("UNSIGNED-PAYLOAD"),
    );
    reqwest::Client::builder()
        .default_headers(headers)
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .expect("multipart HTTP client")
}

fn completion(parts: &[(u32, &str)]) -> String {
    let mut xml = String::from("<CompleteMultipartUpload>");
    for (number, etag) in parts {
        xml.push_str(&format!(
            "<Part><PartNumber>{number}</PartNumber><ETag>{etag}</ETag></Part>"
        ));
    }
    xml.push_str("</CompleteMultipartUpload>");
    xml
}

async fn put(
    client: &reqwest::Client,
    url: &str,
    upload: &str,
    number: u32,
    bytes: Vec<u8>,
) -> String {
    let response = client
        .put(url)
        .query(&[("uploadId", upload), ("partNumber", &number.to_string())])
        .body(bytes)
        .send()
        .await
        .expect("upload numbered part");
    let status = response.status();
    let etag = response.headers().get("etag").cloned();
    let body = response.text().await.expect("part response body");
    assert_eq!(status, StatusCode::OK, "part {number} response: {body}");
    etag.expect("part ETag")
        .to_str()
        .expect("ETag text")
        .to_owned()
}

/// Status and body of a response; the body is read before any assertion so
/// a failing status reports the server's error document.
async fn outcome(response: reqwest::Response) -> (StatusCode, String) {
    let status = response.status();
    let body = response.text().await.expect("multipart response body");
    (status, body)
}

#[when("I complete an S3 upload with replaced and selectively assembled numbered parts")]
async fn numbered_upload(w: &mut BddWorld) {
    let app = w.app.as_ref().expect("registry application");
    let url = format!("{}/bdd-multipart/object", app.base_url);
    let client = client();
    let response = client
        .post(&url)
        .query(&[("uploads", "")])
        .send()
        .await
        .expect("initiate multipart");
    let (status, xml) = outcome(response).await;
    assert_eq!(status, StatusCode::OK, "initiation response: {xml}");
    let upload = xml
        .split_once("<UploadId>")
        .expect("upload ID start")
        .1
        .split_once("</UploadId>")
        .expect("upload ID end")
        .0;
    let stale = put(&client, &url, upload, 9, b"old".to_vec()).await;
    let first_bytes = vec![0x61; 5 * 1024 * 1024];
    let first = put(&client, &url, upload, 2, first_bytes.clone()).await;
    put(&client, &url, upload, 5, b"unselected".to_vec()).await;
    let last = put(&client, &url, upload, 9, b"replacement".to_vec()).await;
    assert_eq!(last, "\"f5300127f646a4550bc4a04fbe393e79\"");
    assert_ne!(stale, last);
    let response = client
        .get(&url)
        .query(&[("uploadId", upload), ("max-parts", "2")])
        .send()
        .await
        .expect("list numbered parts");
    let (status, xml) = outcome(response).await;
    assert_eq!(status, StatusCode::OK, "list parts response: {xml}");
    assert!(xml.contains("<PartNumber>2</PartNumber>"), "{xml}");
    assert!(xml.contains("<PartNumber>5</PartNumber>"), "{xml}");
    assert!(!xml.contains("<PartNumber>9</PartNumber>"), "{xml}");
    assert!(
        xml.contains("<NextPartNumberMarker>5</NextPartNumberMarker>"),
        "{xml}"
    );
    let response = client
        .get(&url)
        .query(&[("uploadId", upload), ("part-number-marker", "5")])
        .send()
        .await
        .expect("next parts page");
    let (status, xml) = outcome(response).await;
    assert_eq!(status, StatusCode::OK, "next parts response: {xml}");
    assert!(xml.contains("<PartNumber>9</PartNumber>"), "{xml}");
    assert!(!xml.contains("<PartNumber>2</PartNumber>"), "{xml}");
    let wrong = format!("{}/bdd-multipart/other-object", app.base_url);
    let response = client
        .put(&wrong)
        .query(&[("uploadId", upload), ("partNumber", "1")])
        .body("foreign")
        .send()
        .await
        .expect("wrong object request");
    let (status, xml) = outcome(response).await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "wrong object response: {xml}"
    );
    assert!(xml.contains("<Code>NoSuchUpload</Code>"), "{xml}");
    let response = client
        .post(&url)
        .query(&[("uploadId", upload)])
        .body(completion(&[(2, &first), (9, &stale)]))
        .send()
        .await
        .expect("stale ETag completion");
    let (status, xml) = outcome(response).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "stale completion: {xml}");
    assert!(xml.contains("<Code>InvalidPart</Code>"), "{xml}");
    let response = client
        .post(&url)
        .query(&[("uploadId", upload)])
        .body(completion(&[(2, &first), (9, &last)]))
        .send()
        .await
        .expect("selected completion");
    let (status, xml) = outcome(response).await;
    assert_eq!(status, StatusCode::OK, "selected completion: {xml}");
    assert!(xml.contains("-2"), "{xml}");
    let mut expected = first_bytes;
    expected.extend_from_slice(b"replacement");
    w.blob_content = expected;
}

#[then("the selected S3 object bytes are exact through HTTP")]
async fn object_reads(w: &mut BddWorld) {
    let app = w.app.as_ref().expect("registry application");
    let response = client()
        .get(format!("{}/bdd-multipart/object", app.base_url))
        .send()
        .await
        .expect("read multipart object");
    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        response
            .headers()
            .get("etag")
            .expect("object ETag")
            .to_str()
            .expect("ETag text")
            .ends_with("-2\"")
    );
    assert_eq!(
        response.bytes().await.expect("object bytes").as_ref(),
        w.blob_content
    );
}
