//! `unzip` uses the pinned `zip` crate and `untgz` uses the pinned `tar` crate (over `flate2`'s
//! gzip decoder).
//!
//! Entry-type handling is deliberate: `unzip` skips symlink entries, and `untgz` materialises only
//! directory and regular-file entries, silently ignoring every other tar entry type.
//!
//! A `tokio::sync::Mutex` (not `parking_lot`) guards the download, which awaits network I/O while
//! the lock is held.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{anyhow, Result};
use arc_swap::ArcSwapOption;

use murmur_constant::path::{join_ui_path, PATH};
use murmur_log::{debugln, errorln, infoln, warnln};

use super::utils::download_for_bytes;

#[derive(Debug)]
pub struct UIUpdater {
    external_ui_url: String,
    external_ui_path: String,
    auto_download_ui: bool,

    mutex: tokio::sync::Mutex<()>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CompressionType {
    Unknown,
    Zip,
    TarGzip,
}

impl std::fmt::Display for CompressionType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Zip => "zip",
            Self::TarGzip => "tar.gz",
            Self::Unknown => "unknown",
        })
    }
}

/// `DefaultUiUpdater`, the package-level pointer reassigned on every `ApplyConfig`.
///
/// `ArcSwapOption` is this crate's equivalent of a swappable global pointer (see
/// `listener::shadowsocks::tcp::LISTENER` for the same pattern).
pub static DEFAULT_UI_UPDATER: ArcSwapOption<UIUpdater> = ArcSwapOption::const_empty();

/// Installs `updater` as the current [`DEFAULT_UI_UPDATER`] and returns it.
///
/// The caller can thus also act on the same instance (`hub::executor::executor::update_updater`
/// calls `auto_download_ui` on it right after installing).
pub fn install_ui_updater(updater: UIUpdater) -> Arc<UIUpdater> {
    let updater = Arc::new(updater);
    DEFAULT_UI_UPDATER.store(Some(Arc::clone(&updater)));
    updater
}

/// The current [`DEFAULT_UI_UPDATER`], or an empty one matching the `&UIUpdater{}` zero value if
/// no config has been applied yet.
pub fn ui_updater() -> Arc<UIUpdater> {
    DEFAULT_UI_UPDATER.load_full().unwrap_or_else(|| {
        Arc::new(UIUpdater {
            external_ui_url: String::new(),
            external_ui_path: String::new(),
            auto_download_ui: false,
            mutex: tokio::sync::Mutex::const_new(()),
        })
    })
}

pub fn new_ui_updater(external_ui: &str, external_ui_url: &str, external_ui_name: &str) -> UIUpdater {
    let mut auto_download_ui = false;
    let mut external_ui_path = if external_ui.is_empty() {
        join_ui_path(&PATH.home_dir(), "ui")
    } else {
        auto_download_ui = true;
        PATH.resolve(external_ui)
    };

    if !external_ui_name.is_empty() {
        auto_download_ui = true;
        external_ui_path = join_ui_path(&external_ui_path, external_ui_name);
    }

    UIUpdater {
        external_ui_url: external_ui_url.to_owned(),
        external_ui_path,
        auto_download_ui,
        mutex: tokio::sync::Mutex::const_new(()),
    }
}

impl UIUpdater {
    // NOT cancel-safe: a drop releases the mutex while the install keeps running on the blocking
    // pool, so a later call can start a second install over the same folder.
    pub async fn auto_download_ui(&self) {
        let _guard = self.mutex.lock().await;
        if self.auto_download_ui {
            let has_entries = match tokio::fs::read_dir(&self.external_ui_path).await {
                Ok(mut entries) => !matches!(entries.next_entry().await, Ok(None)),
                Err(_) => false,
            };
            if has_entries {
                infoln!("UI already exists, skip downloading");
            } else {
                infoln!("External UI downloading ...");
                if let Err(err) = self.download_ui_locked().await {
                    errorln!("Error downloading UI: {err}");
                }
            }
        }
    }

    // NOT cancel-safe: a drop releases the mutex while the install keeps running on the blocking
    // pool, so a later call can start a second install over the same folder.
    pub async fn download_ui(&self) -> Result<()> {
        let _guard = self.mutex.lock().await;
        self.download_ui_locked().await
    }

    // NOT cancel-safe: a drop releases the mutex while the blocking install keeps writing into the
    // UI folder.
    async fn download_ui_locked(&self) -> Result<()> {
        let data =
            download_for_bytes(&self.external_ui_url).await.map_err(|err| anyhow!("can't download file: {err}"))?;
        let ui_path = self.external_ui_path.clone();
        tokio::task::spawn_blocking(move || install_ui(&data, &ui_path)).await??;
        Ok(())
    }
}

fn install_ui(data: &[u8], ui_path: &str) -> Result<()> {
    let tmp_dir = PATH.resolve("downloadUI.tmp");
    let _ = std::fs::remove_dir_all(&tmp_dir);

    debugln!("extractedFolder: {tmp_dir}");
    if let Err(err) = extract(data, Path::new(&tmp_dir)) {
        let _ = std::fs::remove_dir_all(&tmp_dir);
        return Err(anyhow!("can't extract compressed file: {err}"));
    }

    debugln!("cleanupFolder: {ui_path}");
    if let Err(err) = cleanup(Path::new(ui_path)) {
        if err.kind() != std::io::ErrorKind::NotFound {
            let _ = std::fs::remove_dir_all(&tmp_dir);
            return Err(anyhow!("cleanup exist file error: {err}"));
        }
    }

    prepare_ui_path(ui_path);

    debugln!("moveFolder from {tmp_dir} to {ui_path}");
    let move_result = move_dir(Path::new(&tmp_dir), Path::new(ui_path));
    let _ = std::fs::remove_dir_all(&tmp_dir);
    move_result.map_err(|err| anyhow!("move UI folder failed: {err}"))?;

    Ok(())
}

fn prepare_ui_path(ui_path: &str) {
    if std::fs::metadata(ui_path).is_err() {
        infoln!("dir {ui_path} does not exist, creating");
        if let Err(err) = std::fs::create_dir_all(ui_path) {
            warnln!("create dir {ui_path} error: {err}");
        }
    }
}

fn detect_file_type(data: &[u8]) -> CompressionType {
    if data.len() < 4 {
        return CompressionType::Unknown;
    }

    if data.starts_with(&[0x50, 0x4B, 0x03, 0x04]) {
        return CompressionType::Zip;
    }

    if data.starts_with(&[0x1F, 0x8B]) {
        return CompressionType::TarGzip;
    }

    CompressionType::Unknown
}

fn unzip(data: &[u8], dest: &Path) -> Result<()> {
    let mut archive = zip::ZipArchive::new(std::io::Cursor::new(data)).map_err(|err| anyhow!("{err}"))?;

    for i in 0..archive.len() {
        let mut entry = archive.by_index(i).map_err(|err| anyhow!("{err}"))?;
        let name = entry.name().to_owned();
        let fpath = dest.join(&name);

        if !in_dest(&fpath, dest) {
            return Err(anyhow!("invalid file path: {}", fpath.display()));
        }
        if entry.is_dir() {
            std::fs::create_dir_all(&fpath)?;
            continue;
        }
        let is_symlink = entry.unix_mode().is_some_and(|mode| mode & 0o170_000 == 0o120_000);
        if is_symlink {
            continue;
        }
        if let Some(parent) = fpath.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mode = entry.unix_mode().map_or(0o644, |mode| mode & 0o777);
        let mut file_data = Vec::new();
        std::io::Read::read_to_end(&mut entry, &mut file_data)?;
        write_file_mode(&fpath, &file_data, mode)?;
    }

    Ok(())
}

fn untgz(data: &[u8], dest: &Path) -> Result<()> {
    let gz_reader = flate2::read::GzDecoder::new(data);
    let mut archive = tar::Archive::new(gz_reader);

    for entry in archive.entries()? {
        let mut entry = entry?;
        let entry_type = entry.header().entry_type();
        let mode = entry.header().mode()?;
        let path = entry.path()?.into_owned();
        let fpath = dest.join(&path);

        if !in_dest(&fpath, dest) {
            return Err(anyhow!("invalid file path: {}", fpath.display()));
        }

        if entry_type.is_dir() {
            std::fs::create_dir_all(&fpath)?;
        } else if entry_type.is_file() {
            if let Some(parent) = fpath.parent() {
                std::fs::create_dir_all(parent)?;
            }
            let mut file_data = Vec::new();
            std::io::Read::read_to_end(&mut entry, &mut file_data)?;
            write_file_mode(&fpath, &file_data, mode & 0o777)?;
        }
    }

    Ok(())
}

fn extract(data: &[u8], dest: &Path) -> Result<()> {
    let file_type = detect_file_type(data);
    debugln!("compression Type: {file_type}");
    match file_type {
        CompressionType::Zip => unzip(data, dest),
        CompressionType::TarGzip => untgz(data, dest),
        CompressionType::Unknown => Err(anyhow!("unknown or unsupported file type")),
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

fn cleanup(root: &Path) -> std::io::Result<()> {
    for entry in std::fs::read_dir(root)? {
        let entry = entry?;
        let path = root.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            std::fs::remove_dir_all(&path)?;
        } else {
            std::fs::remove_file(&path)?;
        }
    }
    Ok(())
}

/// The rename error is compared against the named `libc::EXDEV` constant rather than the
/// equivalent hard-coded errno.
fn move_dir(src: &Path, dst: &Path) -> std::io::Result<()> {
    let mut entries: Vec<_> = std::fs::read_dir(src)?.collect::<std::io::Result<_>>()?;

    let single_root = if let [entry] = entries.as_slice() {
        if entry.file_type()?.is_dir() {
            Some(entry.file_name())
        } else {
            None
        }
    } else {
        None
    };
    let src = if let Some(root_name) = single_root {
        let src = src.join(root_name);
        debugln!("match the singleRoot: {}", src.display());
        entries = std::fs::read_dir(&src)?.collect::<std::io::Result<_>>()?;
        src
    } else {
        src.to_path_buf()
    };

    for entry in entries {
        let src_path = src.join(entry.file_name());
        let dst_path = dst.join(entry.file_name());
        if let Err(err) = std::fs::rename(&src_path, &dst_path) {
            if err.raw_os_error() == Some(libc::EXDEV) {
                copy_all(&src_path, &dst_path)?;
                let _ = std::fs::remove_dir_all(&src_path);
            } else {
                return Err(err);
            }
        }
    }
    Ok(())
}

fn copy_all(src: &Path, dst: &Path) -> std::io::Result<()> {
    for entry in walk_dir(src)? {
        let entry = entry?;
        let path = entry.path();
        let rel = path.strip_prefix(src).unwrap_or(&path);
        let new_path = dst.join(rel);
        let file_type = entry.file_type()?;

        if file_type.is_dir() {
            std::fs::create_dir_all(&new_path)?;
        } else if file_type.is_symlink() {
            let target = std::fs::read_link(&path)?;
            #[cfg(unix)]
            std::os::unix::fs::symlink(&target, &new_path)?;
            #[cfg(not(unix))]
            {
                let _ = target;
                return Err(std::io::Error::from(std::io::ErrorKind::Unsupported));
            }
        } else {
            std::fs::copy(&path, &new_path)?;
        }
    }
    Ok(())
}

fn walk_dir(root: &Path) -> std::io::Result<Vec<std::io::Result<walkdir_entry::Entry>>> {
    walkdir_entry::walk(root)
}

mod walkdir_entry {
    use std::path::{Path, PathBuf};

    pub(super) struct Entry {
        path: PathBuf,
    }

    impl Entry {
        pub(super) fn path(&self) -> PathBuf {
            self.path.clone()
        }

        pub(super) fn file_type(&self) -> std::io::Result<std::fs::FileType> {
            Ok(std::fs::symlink_metadata(&self.path)?.file_type())
        }
    }

    pub(super) fn walk(root: &Path) -> std::io::Result<Vec<std::io::Result<Entry>>> {
        let mut out = vec![Ok(Entry { path: root.to_path_buf() })];
        walk_into(root, &mut out)?;
        Ok(out)
    }

    fn walk_into(dir: &Path, out: &mut Vec<std::io::Result<Entry>>) -> std::io::Result<()> {
        let Ok(read_dir) = std::fs::read_dir(dir) else {
            return Ok(());
        };
        for entry in read_dir {
            let entry = entry?;
            let path = entry.path();
            let file_type = entry.file_type()?;
            out.push(Ok(Entry { path: path.clone() }));
            if file_type.is_dir() {
                walk_into(&path, out)?;
            }
        }
        Ok(())
    }
}

fn in_dest(fpath: &Path, dest: &Path) -> bool {
    let cleaned_fpath = lexical_clean(fpath);
    let cleaned_dest = lexical_clean(dest);
    match cleaned_fpath.strip_prefix(&cleaned_dest) {
        Ok(rel) => rel.components().next() != Some(std::path::Component::ParentDir) && !rel.is_absolute(),
        Err(_) => false,
    }
}

fn write_file_mode(path: &Path, data: &[u8], mode: u32) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::io::Write as _;
        use std::os::unix::fs::OpenOptionsExt as _;
        let mut file = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(mode).open(path)?;
        file.write_all(data)
    }
    #[cfg(not(unix))]
    {
        let _ = mode;
        std::fs::write(path, data)
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write as _;

    use super::{install_ui_updater, new_ui_updater, ui_updater, untgz, unzip};
    use murmur_constant::path::PATH;

    fn build_zip(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut buf = Vec::new();
        {
            let mut writer = zip::ZipWriter::new(std::io::Cursor::new(&mut buf));
            let options = zip::write::SimpleFileOptions::default();
            for (name, data) in entries {
                writer.start_file(*name, options).expect("start_file");
                writer.write_all(data).expect("write_all");
            }
            writer.finish().expect("finish");
        }
        buf
    }

    /// Builds a `.tar.gz` with attacker-controlled entry names, bypassing the `tar` crate's own
    /// `Header::set_path` validation (which itself refuses `..`) by writing the name field
    /// directly, the way a maliciously crafted third-party archive would.
    fn build_targz(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut tar_bytes = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut tar_bytes);
            for (name, data) in entries {
                let mut header = tar::Header::new_gnu();
                header.set_size(data.len() as u64);
                header.set_mode(0o644);
                let name_bytes = name.as_bytes();
                header.as_mut_bytes()[0..name_bytes.len()].copy_from_slice(name_bytes);
                header.set_cksum();
                builder.append(&header, *data).expect("append");
            }
            builder.finish().expect("finish");
        }
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(&tar_bytes).expect("gzip write");
        encoder.finish().expect("gzip finish")
    }

    #[test]
    fn unzip_extracts_regular_entry_and_rejects_traversal() {
        let dest = std::env::temp_dir().join(format!("murmur-unzip-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dest);
        std::fs::create_dir_all(&dest).expect("create dest");

        let data = build_zip(&[("hello.txt", b"hello from zip")]);
        unzip(&data, &dest).expect("unzip ok entry");
        let content = std::fs::read(dest.join("hello.txt")).expect("read extracted file");
        assert_eq!(content, b"hello from zip");

        let escaping = build_zip(&[("../evil.txt", b"evil")]);
        let err = unzip(&escaping, &dest).expect_err("traversal entry must be rejected");
        assert!(err.to_string().contains("invalid file path"));
        assert!(!dest.parent().unwrap().join("evil.txt").exists());

        let _ = std::fs::remove_dir_all(&dest);
    }

    #[test]
    fn untgz_extracts_regular_entry_and_rejects_traversal() {
        let dest = std::env::temp_dir().join(format!("murmur-untgz-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dest);
        std::fs::create_dir_all(&dest).expect("create dest");

        let data = build_targz(&[("hello.txt", b"hello from tar")]);
        untgz(&data, &dest).expect("untgz ok entry");
        let content = std::fs::read(dest.join("hello.txt")).expect("read extracted file");
        assert_eq!(content, b"hello from tar");

        let escaping = build_targz(&[("../evil.txt", b"evil")]);
        let err = untgz(&escaping, &dest).expect_err("traversal entry must be rejected");
        assert!(err.to_string().contains("invalid file path"));
        assert!(!dest.parent().unwrap().join("evil.txt").exists());

        let _ = std::fs::remove_dir_all(&dest);
    }

    /// The updater is replaced on every `ApplyConfig`, so `POST /upgrade/ui` downloads whatever
    /// `external-ui-url` was last configured. Before this fix `hub::route::upgrade::update_ui`
    /// read an immutable `DEFAULT_UI_UPDATER` with an empty URL that `install_ui_updater` could
    /// never replace, so an upgrade request always failed downloading `""`.
    #[test]
    fn install_ui_updater_replaces_what_ui_updater_returns() {
        let installed = install_ui_updater(new_ui_updater("/tmp/murmur-test-ui", "https://example.com/ui.zip", ""));
        assert_eq!(installed.external_ui_url, "https://example.com/ui.zip");

        let current = ui_updater();
        assert!(std::sync::Arc::ptr_eq(&current, &installed));
        assert_eq!(current.external_ui_url, "https://example.com/ui.zip");
    }

    /// The name is only ever appended: the absolute-looking and mixed-separator names below do
    /// not take the path out of the base. This is defense in depth on top of
    /// `parse_controller`'s `is_local_path` gate, not a substitute for it: the real guarantee
    /// against every rejected name is that gate, since not every name it rejects is caught here
    /// (a name with a single `..` segment ahead of the base can still escape).
    #[test]
    fn new_ui_updater_keeps_the_name_under_the_base() {
        let base = std::env::temp_dir().join("murmur-ui").to_string_lossy().into_owned();
        let resolved = PATH.resolve(&base);
        let mut names = vec!["/etc/passwd", r"\\?\GLOBALROOT\Device\HarddiskVolume1\evil", r"C:\Windows\System32"];
        if cfg!(windows) {
            names.extend([r"a\b/../..", r"a\b\c/../../.."]);
        }
        for name in names {
            let got = new_ui_updater(&base, "", name).external_ui_path;
            assert!(got.starts_with(&resolved), "name {name:?} must stay under {resolved:?}, got {got:?}");
        }
    }

    /// The updater renders its error as the response message, so the download path has to answer
    /// the `can't download file: <error>` text.
    #[tokio::test]
    async fn download_ui_reports_url_error_text() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let port = listener.local_addr().expect("local addr").port();
        drop(listener);
        let url = format!("http://127.0.0.1:{port}/ui.zip");
        let base = std::env::temp_dir().join(format!("murmur-ui-url-error-{}", std::process::id()));

        let updater = new_ui_updater(&base.to_string_lossy(), &url, "");
        let err = updater.download_ui().await.expect_err("a closed port fails");
        let text = err.to_string();
        assert!(text.starts_with(&format!("can't download file: Get \"{url}\": ")), "{text}");
    }
}
