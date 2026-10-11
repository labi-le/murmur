use std::collections::HashMap;
use std::time::Duration;

use anyhow::{anyhow, Result};
use http_body_util::BodyExt;
use tokio_util::sync::CancellationToken;

use murmur_component_http::http as murmur_http;

pub(crate) const DEFAULT_HTTP_TIMEOUT: Duration = Duration::from_secs(90);

// cancel-safe: it reads one response body into memory and touches no shared state.
pub(crate) async fn download_for_bytes(url: &str) -> Result<Vec<u8>> {
    let ctx = CancellationToken::new();
    let timeout_ctx = ctx.clone();
    tokio::spawn(async move {
        tokio::time::sleep(DEFAULT_HTTP_TIMEOUT).await;
        timeout_ctx.cancel();
    });

    let resp = murmur_http::http_request(&ctx, url, "GET", &HashMap::new(), None, &[])
        .await
        .map_err(|err| anyhow!("{}", murmur_http::url_error_text("GET", url, &err)))?;
    let body = resp.into_body().collect().await?.to_bytes();
    Ok(body.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The download returns the error its HTTP client built, and `POST /upgrade/ui` puts that
    /// text on the wire verbatim.
    #[tokio::test]
    async fn download_errors_carry_url_error_text() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let port = listener.local_addr().expect("local addr").port();
        drop(listener);
        let url = format!("http://127.0.0.1:{port}/ui.zip");

        let err = download_for_bytes(&url).await.expect_err("a closed port fails");
        let text = err.to_string();
        assert!(text.starts_with(&format!("Get \"{url}\": ")), "{text}");
    }
}
