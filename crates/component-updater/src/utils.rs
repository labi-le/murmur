use std::collections::HashMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{anyhow, Result};
use futures_util::StreamExt;
use tokio_util::sync::CancellationToken;

use murmur_component_http::http as murmur_http;

use crate::update_core::MAX_PACKAGE_FILE_SIZE;

pub(crate) const DEFAULT_HTTP_TIMEOUT: Duration = Duration::from_secs(90);

/// Ceiling on one unpacked member of a package or UI archive. Deflate reaches roughly 1032:1, so
/// `MAX_PACKAGE_FILE_SIZE` alone bounds nothing on the way out; a release binary compresses about
/// 3:1, so eight times the compressed cap cannot clip a legitimate package.
pub(crate) const MAX_UNPACKED_FILE_SIZE: usize = 8 * MAX_PACKAGE_FILE_SIZE;

/// Fails closed once the wrapped decoder has produced more than `limit` bytes.
pub(crate) struct BoundedReader<R> {
    inner: R,
    limit: usize,
    produced: usize,
}

impl<R: Read> BoundedReader<R> {
    pub(crate) fn new(inner: R, limit: usize) -> Self {
        Self { inner, limit, produced: 0 }
    }
}

impl<R: Read> Read for BoundedReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let limit = self.limit;
        let remaining = limit - self.produced;
        let read = self.inner.read(buf)?;
        if read > remaining {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("decompressed data exceeds MAX_UNPACKED_FILE_SIZE ({limit}) bytes"),
            ));
        }
        self.produced += read;
        Ok(read)
    }
}

/// Whether `fpath` stays inside `dest` once `..` and `.` are resolved away lexically.
pub(crate) fn in_dest(fpath: &Path, dest: &Path) -> bool {
    let cleaned_fpath = lexical_clean(fpath);
    let cleaned_dest = lexical_clean(dest);
    match cleaned_fpath.strip_prefix(&cleaned_dest) {
        Ok(rel) => rel.components().next() != Some(std::path::Component::ParentDir) && !rel.is_absolute(),
        Err(_) => false,
    }
}

fn lexical_clean(path: &Path) -> PathBuf {
    let mut out: Vec<std::path::Component<'_>> = Vec::new();
    for component in path.components() {
        match component {
            std::path::Component::ParentDir => match out.last() {
                Some(std::path::Component::Normal(_)) => {
                    out.pop();
                }
                _ => out.push(component),
            },
            std::path::Component::CurDir => {}
            std::path::Component::Prefix(_) | std::path::Component::RootDir | std::path::Component::Normal(_) => {
                out.push(component);
            }
        }
    }
    let mut buf = PathBuf::new();
    for component in out {
        buf.push(component.as_os_str());
    }
    if buf.as_os_str().is_empty() {
        PathBuf::from(".")
    } else {
        buf
    }
}

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

    let mut body: Vec<u8> = Vec::new();
    let mut stream = http_body_util::BodyDataStream::new(resp.into_body());
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|err| anyhow!("copy: {err}"))?;
        if body.len() + chunk.len() > MAX_PACKAGE_FILE_SIZE {
            return Err(anyhow!("ui archive exceeds MAX_PACKAGE_FILE_SIZE ({MAX_PACKAGE_FILE_SIZE}) bytes"));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

#[cfg(test)]
mod tests {
    use std::io::Write as _;

    use super::*;

    fn gz_of_zeros(len: usize) -> Vec<u8> {
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        let chunk = vec![0u8; 64 * 1024];
        let mut written = 0;
        while written < len {
            let n = (len - written).min(chunk.len());
            encoder.write_all(&chunk[..n]).expect("gzip write");
            written += n;
        }
        encoder.finish().expect("gzip finish")
    }

    #[test]
    fn bounded_reader_admits_a_stream_that_ends_at_the_limit() {
        let data = gz_of_zeros(64 * 1024);
        let decoder = flate2::read::GzDecoder::new(data.as_slice());
        let mut out = Vec::new();
        BoundedReader::new(decoder, 64 * 1024).read_to_end(&mut out).expect("a stream at the limit passes");
        assert_eq!(64 * 1024, out.len());
    }

    #[test]
    fn bounded_reader_stops_a_stream_that_inflates_past_the_limit() {
        let data = gz_of_zeros(256 * 1024);
        let decoder = flate2::read::GzDecoder::new(data.as_slice());
        let mut out = Vec::new();
        let err = BoundedReader::new(decoder, 64 * 1024)
            .read_to_end(&mut out)
            .expect_err("a stream past the limit must fail closed");
        assert!(err.to_string().contains("MAX_UNPACKED_FILE_SIZE"), "{err}");
        assert!(out.len() <= 64 * 1024, "{} bytes were read past the limit", out.len());
    }

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

    /// `in_dest` is the containment check the gzip unpack path needs; an absolute name and a `..`
    /// name both leave the destination, a normal name does not.
    #[test]
    fn in_dest_rejects_a_name_that_leaves_the_destination() {
        let dest = Path::new("/tmp/meta-update");
        assert!(in_dest(&dest.join("murmur-linux-amd64-1.0"), dest));
        assert!(in_dest(&dest.join("sub/dir/file"), dest));
        assert!(!in_dest(&dest.join("../escaped.bin"), dest));
        assert!(!in_dest(&dest.join("sub/../../escaped.bin"), dest));
        assert!(!in_dest(Path::new("/etc/passwd"), dest));
    }

    /// The download path is a remote-triggered buffering path: it must stop reading the body at the
    /// cap instead of collecting an unbounded response first, so the server is left mid-body.
    #[tokio::test]
    async fn download_for_bytes_stops_reading_at_the_package_cap() {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        const BODY: usize = 2 * MAX_PACKAGE_FILE_SIZE;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let port = listener.local_addr().expect("local addr").port();

        let (tx, rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let Ok((mut sock, _)) = listener.accept().await else { return };
            let mut head = [0u8; 4096];
            let _ = sock.read(&mut head).await;
            let header = format!("HTTP/1.1 200 OK\r\nContent-Length: {BODY}\r\nConnection: close\r\n\r\n");
            if sock.write_all(header.as_bytes()).await.is_err() {
                let _ = tx.send(false);
                return;
            }
            let chunk = [0u8; 64 * 1024];
            let complete = tokio::time::timeout(Duration::from_secs(2), async {
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

        let url = format!("http://127.0.0.1:{port}/ui.zip");
        let err = download_for_bytes(&url).await.expect_err("an oversized body must fail closed");
        assert!(err.to_string().contains("MAX_PACKAGE_FILE_SIZE"), "{err}");

        let pushed_whole_body = rx.await.expect("server reports progress");
        assert!(!pushed_whole_body, "the reader collected the whole body before rejecting it");
    }
}
