//! The platform spelling baked into release asset names has no exact Rust equivalent.
//!
//! `release_os`/`release_arch` translate `std::env::consts::OS`/`ARCH` into the spelling for the
//! two values this file's platform switches actually distinguish (`darwin` vs `macos`, and the
//! architecture strings in the release filenames).
//!
//! A `tokio::sync::Mutex` (not `parking_lot`) guards the whole update, because it is held across
//! the async HTTP download. Zip unpacking uses the pinned `zip` crate.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{anyhow, Result};
use futures_util::StreamExt;
use http_body_util::BodyExt;

use murmur_component_ca as ca;
use murmur_component_http::http as murmur_http;
use murmur_constant::version::VERSION;
use murmur_constant_features::{AMD64_LEVEL, ARM_VERSION, MIPS_FLOAT};
use murmur_log::{debugln, errorln, infoln, warnln};

const BASE_RELEASE_URL: &str = "https://github.com/labi-le/murmur/releases/latest/download/";
const VERSION_RELEASE_URL: &str = "https://github.com/labi-le/murmur/releases/latest/download/version.txt";

const BASE_ALPHA_URL: &str = "https://github.com/labi-le/murmur/releases/download/Prerelease-Alpha/";
const VERSION_ALPHA_URL: &str = "https://github.com/labi-le/murmur/releases/download/Prerelease-Alpha/version.txt";

pub const MAX_PACKAGE_FILE_SIZE: usize = 32 * 1024 * 1024;

pub const RELEASE_CHANNEL: &str = "release";
pub const ALPHA_CHANNEL: &str = "alpha";

#[derive(Debug)]
pub struct CoreUpdater {
    mu: tokio::sync::Mutex<()>,
}

pub static DEFAULT_CORE_UPDATER: CoreUpdater = CoreUpdater { mu: tokio::sync::Mutex::const_new(()) };

struct CleanupGuard {
    dir: PathBuf,
}

impl Drop for CleanupGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn release_os() -> &'static str {
    match std::env::consts::OS {
        "macos" => "darwin",
        other => other,
    }
}

fn release_arch() -> &'static str {
    match std::env::consts::ARCH {
        "x86" => "386",
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        "mipsel" => "mipsle",
        "mips64el" => "mips64le",
        "powerpc64" => "ppc64",
        "powerpc64le" => "ppc64le",
        "loongarch64" => "loong64",
        other => other,
    }
}

#[cfg(unix)]
fn file_permission_bits(metadata: &std::fs::Metadata) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    metadata.permissions().mode() & 0o777
}

#[cfg(not(unix))]
fn file_permission_bits(_metadata: &std::fs::Metadata) -> u32 {
    0o644
}

fn mkdir_mode(path: &Path, mode: u32) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new().mode(mode).create(path)
    }
    #[cfg(not(unix))]
    {
        let _ = mode;
        std::fs::DirBuilder::new().create(path)
    }
}

fn open_write_mode(path: &Path, mode: u32) -> std::io::Result<std::fs::File> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(mode).open(path)
    }
    #[cfg(not(unix))]
    {
        let _ = mode;
        std::fs::OpenOptions::new().write(true).create(true).truncate(true).open(path)
    }
}

fn write_file_mode(path: &Path, data: &[u8], mode: u32) -> std::io::Result<()> {
    use std::io::Write as _;
    let mut file = open_write_mode(path, mode)?;
    file.write_all(data)
}

async fn mkdir_mode_async(path: &Path, mode: u32) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        tokio::fs::DirBuilder::new().mode(mode).create(path).await
    }
    #[cfg(not(unix))]
    {
        let _ = mode;
        tokio::fs::DirBuilder::new().create(path).await
    }
}

async fn open_write_mode_async(path: &Path, mode: u32) -> std::io::Result<tokio::fs::File> {
    #[cfg(unix)]
    {
        tokio::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(mode).open(path).await
    }
    #[cfg(not(unix))]
    {
        let _ = mode;
        tokio::fs::OpenOptions::new().write(true).create(true).truncate(true).open(path).await
    }
}

/// Spelled field by field so a field added to [`ca::config::Option`] later cannot silently take
/// its default in an update request.
fn zero_trust_ca_option() -> ca::config::Option {
    let ca::config::Option { tls_config, fingerprint, name_cert_verify, certificate, private_key, .. } =
        ca::config::Option::default();
    ca::config::Option { tls_config, fingerprint, name_cert_verify, zero_trust: true, certificate, private_key }
}

impl CoreUpdater {
    pub fn core_base_name(&self) -> String {
        let os = release_os();
        let arch = release_arch();
        match arch {
            "arm" => format!("murmur-{os}-{arch}v{ARM_VERSION}"),
            "arm64" => {
                if os == "android" {
                    format!("murmur-{os}-{arch}-v8")
                } else {
                    format!("murmur-{os}-{arch}")
                }
            }
            "mips" | "mipsle" => format!("murmur-{os}-{arch}-{MIPS_FLOAT}"),
            "amd64" => {
                if os == "android" {
                    format!("murmur-{os}-{arch}")
                } else {
                    format!("murmur-{os}-{arch}-{AMD64_LEVEL}")
                }
            }
            _ => format!("murmur-{os}-{arch}"),
        }
    }

    // NOT cancel-safe: a cancelled update drops `CleanupGuard`, which removes the update directory
    // while the replacement step may still be running on the blocking pool.
    pub async fn update(&self, current_exe_path: &str, channel: &str, force: bool) -> Result<()> {
        let _guard = self.mu.lock().await;

        let info = tokio::fs::metadata(current_exe_path)
            .await
            .map_err(|err| anyhow!("check currentExePath {current_exe_path:?}: {err}"))?;

        let (mut base_url, mut version_url) = (BASE_ALPHA_URL, VERSION_ALPHA_URL);
        match channel.to_lowercase().as_str() {
            RELEASE_CHANNEL => {
                base_url = BASE_RELEASE_URL;
                version_url = VERSION_RELEASE_URL;
            }
            ALPHA_CHANNEL => {}
            _ => {
                if !VERSION.starts_with("alpha") {
                    base_url = BASE_RELEASE_URL;
                    version_url = VERSION_RELEASE_URL;
                }
            }
        }

        let latest_version =
            self.get_latest_version(version_url).await.map_err(|err| anyhow!("get latest version: {err}"))?;
        infoln!("current version {VERSION}, latest version {latest_version}");

        if latest_version == VERSION && !force {
            return Err(anyhow!("update error: already using latest version {VERSION}"));
        }

        let result = self.update_locked(current_exe_path, &info, base_url, &latest_version).await;
        match &result {
            Err(err) => errorln!("updater: failed: {err}"),
            Ok(()) => infoln!("updater: finished"),
        }
        result
    }

    // NOT cancel-safe: the guard removes the update directory even if the blocking replacement step
    // is still reading from it.
    async fn update_locked(
        &self,
        current_exe_path: &str,
        info: &std::fs::Metadata,
        base_url: &str,
        latest_version: &str,
    ) -> Result<()> {
        let murmur_base_name = self.core_base_name();
        let mut package_name = format!("{murmur_base_name}-{latest_version}");
        package_name.push_str(if cfg!(target_os = "windows") { ".zip" } else { ".gz" });
        let package_url = format!("{base_url}{package_name}");
        infoln!("updater: updating using url: {package_url}");

        let current_exe_path = Path::new(current_exe_path);
        let work_dir = current_exe_path.parent().unwrap_or_else(|| Path::new(""));
        let backup_dir = work_dir.join("meta-backup");
        let update_dir = work_dir.join("meta-update");
        let package_path = update_dir.join(&package_name);

        let mut update_exe_name = murmur_base_name;
        if cfg!(target_os = "windows") {
            update_exe_name.push_str(".exe");
        }
        infoln!("updateExeName: {update_exe_name}");
        let update_exe_path = update_dir.join(&update_exe_name);
        let backup_exe_path = backup_dir.join(current_exe_path.file_name().unwrap_or_default());

        let _cleanup = CleanupGuard { dir: update_dir.clone() };

        self.download(&update_dir, &package_path, &package_url).await.map_err(|err| anyhow!("downloading: {err}"))?;

        let file_mode = file_permission_bits(info);
        let exe_path = current_exe_path.to_path_buf();
        tokio::task::spawn_blocking(move || -> Result<()> {
            unpack(&update_dir, &package_path, file_mode).map_err(|err| anyhow!("unpacking: {err}"))?;
            backup(&exe_path, &backup_exe_path, &backup_dir).map_err(|err| anyhow!("backuping: {err}"))?;
            copy_file(&update_exe_path, &exe_path).map_err(|err| anyhow!("replacing: {err}"))?;
            Ok(())
        })
        .await??;

        Ok(())
    }

    // cancel-safe: it reads one version string and keeps no state.
    async fn get_latest_version(&self, version_url: &str) -> Result<String> {
        let ctx = tokio_util::sync::CancellationToken::new();
        let timeout_ctx = ctx.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(5)).await;
            timeout_ctx.cancel();
        });

        let options = [murmur_http::with_ca_option(zero_trust_ca_option())];
        let resp = murmur_http::http_request(&ctx, version_url, "GET", &HashMap::new(), None, &options).await?;
        let body = resp.into_body().collect().await?.to_bytes();
        Ok(String::from_utf8_lossy(&body).trim_end_matches('\n').to_owned())
    }

    // cancel-safe: a partial package file stays in the update directory, which the caller's guard
    // removes on drop.
    async fn download(&self, update_dir: &Path, package_path: &Path, package_url: &str) -> Result<()> {
        let ctx = tokio_util::sync::CancellationToken::new();
        let timeout_ctx = ctx.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(90)).await;
            timeout_ctx.cancel();
        });

        let options = [murmur_http::with_ca_option(zero_trust_ca_option())];
        let resp = murmur_http::http_request(&ctx, package_url, "GET", &HashMap::new(), None, &options)
            .await
            .map_err(|err| anyhow!("http request failed: {}", murmur_http::url_error_text("GET", package_url, &err)))?;

        debugln!("updateDir {}", update_dir.display());
        mkdir_mode_async(update_dir, 0o755).await.map_err(|err| anyhow!("mkdir error: {err}"))?;

        debugln!("updater: saving package to file {}", package_path.display());
        let mut wc = open_write_mode_async(package_path, 0o755)
            .await
            .map_err(|err| anyhow!("os.OpenFile({}): {err}", package_path.display()))?;

        debugln!("updater: reading http body");
        let mut stream = http_body_util::BodyDataStream::new(resp.into_body());
        let mut n: usize = 0;
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|err| anyhow!("copy: {err}"))?;
            let remaining = MAX_PACKAGE_FILE_SIZE - n;
            if remaining == 0 {
                break;
            }
            let slice = chunk.get(..remaining).unwrap_or(&chunk);
            tokio::io::AsyncWriteExt::write_all(&mut wc, slice).await.map_err(|err| anyhow!("copy: {err}"))?;
            n += slice.len();
        }
        drop(wc);
        if n == MAX_PACKAGE_FILE_SIZE {
            return Err(anyhow!("attempted to read more than {MAX_PACKAGE_FILE_SIZE} bytes"));
        }
        debugln!("updater: downloaded package to file {}", package_path.display());

        Ok(())
    }
}

fn unpack(update_dir: &Path, package_path: &Path, file_mode: u32) -> Result<()> {
    infoln!("updater: unpacking package");
    let package_str = package_path.to_string_lossy();
    if package_str.ends_with(".zip") {
        zip_file_unpack(package_path, update_dir, file_mode).map_err(|err| anyhow!(".zip unpack failed: {err}"))?;
    } else if package_str.ends_with(".gz") {
        gz_file_unpack(package_path, update_dir, file_mode).map_err(|err| anyhow!(".gz unpack failed: {err}"))?;
    } else {
        return Err(anyhow!("unknown package extension"));
    }
    Ok(())
}

fn backup(current_exe_path: &Path, backup_exe_path: &Path, backup_dir: &Path) -> Result<()> {
    infoln!("updater: backing up current ExecFile:{} to {}", current_exe_path.display(), backup_exe_path.display());
    let _ = mkdir_mode(backup_dir, 0o755);

    if cfg!(target_os = "windows") {
        std::fs::rename(current_exe_path, backup_exe_path)?;
    } else {
        copy_file(current_exe_path, backup_exe_path)?;
    }
    Ok(())
}

fn gz_file_unpack(gzfile: &Path, out_dir: &Path, file_mode: u32) -> Result<PathBuf> {
    let f = std::fs::File::open(gzfile).map_err(|err| anyhow!("os.Open(): {err}"))?;
    let mut gz_reader = flate2::read::GzDecoder::new(f);

    let original_name = gz_reader
        .header()
        .and_then(|header| header.filename())
        .map(|bytes| String::from_utf8_lossy(bytes).into_owned())
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| {
            let base = gzfile.file_name().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default();
            base.strip_suffix(".gz").map(str::to_owned).unwrap_or(base)
        });

    let output_name = out_dir.join(&original_name);
    let mut wc = open_write_mode(&output_name, file_mode)
        .map_err(|err| anyhow!("os.OpenFile({}): {err}", output_name.display()))?;
    std::io::copy(&mut gz_reader, &mut wc).map_err(|err| anyhow!("copy: {err}"))?;

    Ok(output_name)
}

fn zip_file_unpack(zipfile: &Path, out_dir: &Path, file_mode: u32) -> Result<PathBuf> {
    let file = std::fs::File::open(zipfile).map_err(|err| anyhow!("zip.OpenReader(): {err}"))?;
    let mut archive = zip::ZipArchive::new(file).map_err(|err| anyhow!("zip.OpenReader(): {err}"))?;
    if archive.is_empty() {
        return Err(anyhow!("no files in the zip archive"));
    }

    let mut zf = archive.by_index(0).map_err(|err| anyhow!("zip file Open(): {err}"))?;
    if zf.is_dir() {
        return Err(anyhow!("the target file is a directory"));
    }

    let name = zf.name().to_owned();
    let base_name = Path::new(&name).file_name().map_or_else(|| name.clone(), |s| s.to_string_lossy().into_owned());
    let output_name = out_dir.join(&base_name);
    let mut data = Vec::new();
    std::io::Read::read_to_end(&mut zf, &mut data).map_err(|err| anyhow!("copy: {err}"))?;
    write_file_mode(&output_name, &data, file_mode).map_err(|err| anyhow!("os.OpenFile(): {err}"))?;

    Ok(output_name)
}

fn copy_file(src: &Path, dst: &Path) -> Result<()> {
    let mut rc = std::fs::File::open(src).map_err(|err| anyhow!("os.Open({}): {err}", src.display()))?;
    let metadata = rc.metadata().map_err(|err| anyhow!("rc.Stat(): {err}"))?;
    let mode = file_permission_bits(&metadata);

    let mut wc = if let Ok(f) = open_write_mode(dst, mode) {
        f
    } else {
        std::fs::remove_file(dst).map_err(|err| anyhow!("os.Remove({}): {err}", dst.display()))?;
        open_write_mode(dst, mode).map_err(|err| anyhow!("os.OpenFile({}): {err}", dst.display()))?
    };

    std::io::copy(&mut rc, &mut wc).map_err(|err| anyhow!("copy: {err}"))?;
    drop(wc);

    if cfg!(target_os = "macos") {
        match std::process::Command::new("/usr/bin/codesign").arg("--sign").arg("-").arg(dst).status() {
            Ok(status) if !status.success() => warnln!("codesign failed: exit status {status}"),
            Err(err) => warnln!("codesign failed: {err}"),
            Ok(_) => {}
        }
    }

    infoln!("updater: copy: {} to {}", src.display(), dst.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    /// Expected value derived from `CoreUpdater::core_base_name`: `murmur-<os>-<arch>-<AMD64_LEVEL>`
    /// for the `amd64` non-android case, with `AMD64_LEVEL` empty unless that env var was set at
    /// build time.
    #[test]
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    fn core_base_name_matches_release_asset_format() {
        use super::DEFAULT_CORE_UPDATER;

        let expected = format!("murmur-linux-amd64-{}", murmur_constant_features::AMD64_LEVEL);
        assert_eq!(expected, DEFAULT_CORE_UPDATER.core_base_name());
    }
}
