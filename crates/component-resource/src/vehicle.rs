use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, LazyLock};
use std::time::Duration;

use anyhow::Result;
use async_trait::async_trait;
use http_body_util::BodyExt;
use parking_lot::RwLock;
use tokio_util::sync::CancellationToken;

use murmur_common::utils::hash::{make_hash, HashType};
use murmur_component_http::http as murmur_http;
use murmur_component_profile::cachefile::cache::cache;
use murmur_component_profile::cachefile::etag::EtagWithHash;
use murmur_constant::provider::interface::{SubscriptionReadCallback, Vehicle, VehicleType};

pub const DEFAULT_HTTP_TIMEOUT: Duration = Duration::from_secs(20);

#[cfg_attr(not(unix), allow(dead_code))]
const FILE_MODE: u32 = 0o666;
#[cfg_attr(not(unix), allow(dead_code))]
const DIR_MODE: u32 = 0o755;

static ETAG: LazyLock<RwLock<bool>> = LazyLock::new(|| RwLock::new(false));

pub fn etag() -> bool {
    *ETAG.read()
}

pub fn set_etag(b: bool) {
    *ETAG.write() = b;
}

/// Reads a response body in bounded chunks, stopping once `limit` bytes are in hand, so the
/// declared tail of an oversized body is never allocated. The reference truncates, so the first
/// `limit` bytes are what the caller keeps.
async fn read_body_bounded<B>(body: B, limit: Option<usize>) -> Result<Vec<u8>>
where
    B: hyper::body::Body<Data = hyper::body::Bytes> + Unpin,
    B::Error: std::error::Error + Send + Sync + 'static,
{
    let mut body = body;
    let mut buf: Vec<u8> = Vec::new();
    while let Some(frame) = body.frame().await {
        let Ok(data) = frame?.into_data() else {
            continue;
        };
        let remaining = limit.map_or(data.len(), |limit| limit.saturating_sub(buf.len()));
        if remaining == 0 {
            break;
        }
        let take = data.len().min(remaining);
        buf.extend_from_slice(data.get(..take).unwrap_or_else(|| data.as_ref()));
        if limit.is_some_and(|limit| buf.len() >= limit) {
            break;
        }
    }
    Ok(buf)
}

fn safe_write(path: &str, buf: &[u8]) -> Result<()> {
    let path = Path::new(path);
    let dir = path.parent().unwrap_or_else(|| Path::new(""));

    if !dir.as_os_str().is_empty() && !dir.exists() {
        create_dir_all(dir)?;
    }

    write_file(path, buf)?;
    Ok(())
}

#[cfg(unix)]
fn create_dir_all(dir: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;

    std::fs::DirBuilder::new().recursive(true).mode(DIR_MODE).create(dir)
}

#[cfg(not(unix))]
fn create_dir_all(dir: &Path) -> std::io::Result<()> {
    std::fs::DirBuilder::new().recursive(true).create(dir)
}

#[cfg(unix)]
fn write_file(path: &Path, buf: &[u8]) -> std::io::Result<()> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt;

    let mut file = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(FILE_MODE).open(path)?;
    file.write_all(buf)
}

#[cfg(not(unix))]
fn write_file(path: &Path, buf: &[u8]) -> std::io::Result<()> {
    std::fs::write(path, buf)
}

#[derive(Debug)]
pub struct FileVehicle {
    path: String,
}

#[async_trait]
impl Vehicle for FileVehicle {
    fn type_(&self) -> VehicleType {
        VehicleType::FILE
    }

    fn path(&self) -> String {
        self.path.clone()
    }

    fn url(&self) -> String {
        format!("file://{}", self.path)
    }

    async fn read(&self, _ctx: &CancellationToken, _old_hash: HashType) -> Result<(Vec<u8>, HashType)> {
        let buf = tokio::fs::read(&self.path).await?;
        let hash = make_hash(&buf);
        Ok((buf, hash))
    }

    fn proxy(&self) -> String {
        String::new()
    }

    fn write(&self, buf: &[u8]) -> Result<()> {
        safe_write(&self.path, buf)
    }
}

impl FileVehicle {
    #[must_use]
    pub fn new(path: &str) -> Self {
        Self { path: path.to_owned() }
    }
}

pub struct HTTPVehicle {
    url: String,
    path: String,
    proxy: String,
    header: HashMap<String, Vec<String>>,
    timeout: Duration,
    size_limit: i64,
    in_read: RwLock<Option<Arc<dyn Fn(&hyper::Response<hyper::body::Incoming>) + Send + Sync>>>,
}

impl core::fmt::Debug for HTTPVehicle {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("HTTPVehicle")
            .field("url", &self.url)
            .field("path", &self.path)
            .field("proxy", &self.proxy)
            .field("header", &self.header)
            .field("timeout", &self.timeout)
            .field("size_limit", &self.size_limit)
            .field("in_read", &self.in_read.read().is_some())
            .finish_non_exhaustive()
    }
}

impl SubscriptionReadCallback for HTTPVehicle {
    fn set_in_read(&self, f: Arc<dyn Fn(&hyper::Response<hyper::body::Incoming>) + Send + Sync>) {
        *self.in_read.write() = Some(f);
    }
}

#[async_trait]
impl Vehicle for HTTPVehicle {
    fn url(&self) -> String {
        self.url.clone()
    }

    fn type_(&self) -> VehicleType {
        VehicleType::HTTP
    }

    fn path(&self) -> String {
        self.path.clone()
    }

    fn proxy(&self) -> String {
        self.proxy.clone()
    }

    fn write(&self, buf: &[u8]) -> Result<()> {
        safe_write(&self.path, buf)
    }

    async fn read(&self, ctx: &CancellationToken, old_hash: HashType) -> Result<(Vec<u8>, HashType)> {
        let ctx = ctx.child_token();
        let timeout_ctx = ctx.clone();
        let timeout = self.timeout;
        tokio::spawn(async move {
            tokio::time::sleep(timeout).await;
            timeout_ctx.cancel();
        });

        let mut header = self.header.clone();
        let mut set_if_none_match = false;
        if etag() && old_hash.is_valid() {
            let etag_with_hash = cache().get_etag_with_hash(&self.url);
            if old_hash.equal(etag_with_hash.hash) && !etag_with_hash.etag.is_empty() {
                header.insert("If-None-Match".to_owned(), vec![etag_with_hash.etag]);
                set_if_none_match = true;
            }
        }

        let options = [murmur_http::with_special_proxy(self.proxy.clone())];
        let resp = murmur_http::http_request(&ctx, &self.url, "GET", &header, None, &options)
            .await
            .map_err(|err| anyhow::anyhow!("{}", murmur_http::url_error_text("GET", &self.url, &err)))?;

        if let Some(in_read) = self.in_read.read().as_ref() {
            in_read(&resp);
        }

        let status = resp.status();
        if !(200..=299).contains(&status.as_u16()) {
            if set_if_none_match && status == hyper::StatusCode::NOT_MODIFIED {
                return Ok((Vec::new(), old_hash));
            }
            return Err(anyhow::anyhow!("{status}"));
        }

        let resp_header = resp.headers().clone();
        let limit = if self.size_limit > 0 {
            Some(
                usize::try_from(self.size_limit)
                    .map_err(|_| anyhow::anyhow!("size limit {} does not fit this platform", self.size_limit))?,
            )
        } else {
            None
        };
        let buf = read_body_bounded(resp.into_body(), limit).await?;
        let hash = make_hash(&buf);

        if etag() {
            let etag_value = resp_header.get("ETag").and_then(|v| v.to_str().ok()).unwrap_or_default().to_owned();
            cache().set_etag_with_hash(&self.url, EtagWithHash { hash, etag: etag_value, time: chrono::Utc::now() });
        }

        Ok((buf, hash))
    }

    fn as_subscription_read_callback(&self) -> Option<&dyn SubscriptionReadCallback> {
        Some(self)
    }
}

impl HTTPVehicle {
    #[must_use]
    pub fn new(
        url: &str,
        path: &str,
        proxy: &str,
        header: HashMap<String, Vec<String>>,
        timeout: Duration,
        size_limit: i64,
    ) -> Self {
        Self {
            url: url.to_owned(),
            path: path.to_owned(),
            proxy: proxy.to_owned(),
            header,
            timeout,
            size_limit,
            in_read: RwLock::new(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The request's error is returned unchanged, in the `Get "<url>": ...` text the geo updaters
    /// and their callers expect.
    #[tokio::test]
    async fn read_errors_carry_url_error_text() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let port = listener.local_addr().expect("local addr").port();
        drop(listener);
        let url = format!("http://127.0.0.1:{port}/geoip.dat");
        let path = std::env::temp_dir().join(format!("murmur-vehicle-url-error-{}", std::process::id()));

        let vehicle = HTTPVehicle::new(&url, &path.to_string_lossy(), "", HashMap::new(), Duration::from_secs(5), 0);
        let err = vehicle.read(&CancellationToken::new(), HashType::default()).await.expect_err("a closed port fails");
        let text = err.to_string();
        assert!(text.starts_with(&format!("Get \"{url}\": ")), "{text}");
    }

    /// `size-limit` bounds what is read, not only what is kept: collecting the whole body before
    /// truncating leaves an unbounded response able to exhaust memory. The server declares a body
    /// far past the limit and reports whether it pushed all of it; with the read capped at the
    /// limit, the client stops before the body arrives in full.
    #[tokio::test]
    async fn read_stops_reading_at_the_size_limit_instead_of_buffering_the_body() {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        const BODY: usize = 32 * 1024 * 1024;
        const LIMIT: usize = 64 * 1024;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let port = listener.local_addr().expect("local addr").port();
        let url = format!("http://127.0.0.1:{port}/geoip.dat");

        let (tx, rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let Ok((mut sock, _)) = listener.accept().await else { return };
            let mut head = [0u8; 4096];
            let _ = sock.read(&mut head).await;
            let header = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {BODY}\r\nConnection: close\r\n\r\n"
            );
            if sock.write_all(header.as_bytes()).await.is_err() {
                let _ = tx.send(false);
                return;
            }
            let chunk = [0u8; 64 * 1024];
            let complete = tokio::time::timeout(Duration::from_secs(3), async {
                let mut sent = 0usize;
                while sent < BODY {
                    let n = (BODY - sent).min(chunk.len());
                    if sock.write_all(&chunk[..n]).await.is_err() {
                        return false;
                    }
                    sent += n;
                }
                true
            })
            .await
            .unwrap_or(false);
            let _ = tx.send(complete);
        });

        let path = std::env::temp_dir().join(format!("murmur-vehicle-size-limit-{}", std::process::id()));
        let vehicle =
            HTTPVehicle::new(&url, &path.to_string_lossy(), "", HashMap::new(), Duration::from_secs(10), LIMIT as i64);
        let (buf, _hash) = vehicle.read(&CancellationToken::new(), HashType::default()).await.expect("read succeeds");
        assert_eq!(buf.len(), LIMIT, "the kept body is the first {LIMIT} bytes");

        let sent_whole_body = rx.await.expect("server reports");
        assert!(!sent_whole_body, "the client buffered the whole {BODY}-byte body despite size_limit={LIMIT}");
    }
}
