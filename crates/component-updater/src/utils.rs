use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{anyhow, Result};
use http_body_util::BodyExt;
use tokio_util::sync::CancellationToken;

use murmur_component_http::http as murmur_http;

pub(crate) const DEFAULT_HTTP_TIMEOUT: Duration = Duration::from_secs(90);

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
}
