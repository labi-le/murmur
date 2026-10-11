use std::fmt;
use std::sync::LazyLock;

use anyhow::{anyhow, Result};
use parking_lot::RwLock;

use murmur_common::utils::hash::make_hash;
use murmur_constant_features::CMFA;

pub const NAME: &str = "murmur";

pub static GEOSITE_NAME: LazyLock<RwLock<String>> = LazyLock::new(|| RwLock::new("GeoSite.dat".to_owned()));

pub static GEOIP_NAME: LazyLock<RwLock<String>> = LazyLock::new(|| RwLock::new("GeoIP.dat".to_owned()));

pub static ASN_NAME: LazyLock<RwLock<String>> = LazyLock::new(|| RwLock::new("ASN.mmdb".to_owned()));

pub static BUNDLE_MRS_NAME: LazyLock<RwLock<String>> = LazyLock::new(|| RwLock::new("BundleMRS.7z".to_owned()));

/// `Path`, initialized once from the environment like the package-level `var`.
pub static PATH: LazyLock<Path> = LazyLock::new(|| {
    #[cfg(test)]
    let mut home_dir = test_home_dir();
    #[cfg(not(test))]
    let mut home_dir = match user_home_dir() {
        Ok(home_dir) => home_dir,
        Err(_) => std::env::current_dir().map(|dir| dir.to_string_lossy().into_owned()).unwrap_or_default(),
    };
    home_dir = normalize_separators(&home_dir);
    let unsafe_path_allowed = parse_bool(&std::env::var("SKIP_SAFE_PATH_CHECK").unwrap_or_default());
    home_dir = join_path(&[&home_dir, ".config", NAME]);

    if std::fs::metadata(&home_dir).is_err() {
        if let Ok(config_home) = std::env::var("XDG_CONFIG_HOME") {
            home_dir = join_path(&[&normalize_separators(&config_home), NAME]);
        }
    }

    let mut safe_paths = Vec::new();
    for safe_path in split_list(&std::env::var("SAFE_PATHS").unwrap_or_default()) {
        let safe_path = safe_path.trim();
        if safe_path.is_empty() {
            continue;
        }
        safe_paths.push(normalize_separators(safe_path));
    }

    Path {
        home_dir: RwLock::new(home_dir),
        config_file: RwLock::new("config.yaml".to_owned()),
        unsafe_path_allowed,
        safe_paths,
    }
});

#[derive(Debug)]
pub struct Path {
    home_dir: RwLock<String>,
    config_file: RwLock<String>,
    unsafe_path_allowed: bool,
    safe_paths: Vec<String>,
}

#[derive(Debug)]
pub struct ErrNotSafePath {
    pub path: String,
    pub safe_paths: Vec<String>,
}

impl fmt::Display for ErrNotSafePath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "path is not subpath of home directory or SAFE_PATHS: {} \n allowed paths: [{}]",
            self.path,
            self.safe_paths.join(" ")
        )
    }
}

impl std::error::Error for ErrNotSafePath {}

impl Path {
    pub fn set_home_dir(&self, root: &str) {
        *self.home_dir.write() = normalize_separators(root);
    }

    pub fn set_config(&self, file: &str) {
        file.clone_into(&mut self.config_file.write());
    }

    pub fn home_dir(&self) -> String {
        self.home_dir.read().clone()
    }

    pub fn config(&self) -> String {
        self.config_file.read().clone()
    }

    pub fn resolve(&self, path: &str) -> String {
        if !is_abs_path(path) {
            return join_path(&[&self.home_dir(), &normalize_separators(path)]);
        }
        normalize_separators(path)
    }

    pub fn is_safe_path(&self, path: &str) -> bool {
        if self.unsafe_path_allowed || CMFA {
            return true;
        }
        let path = self.resolve(path);
        for safe_path in self.safe_paths() {
            if let Ok(rel) = rel_path(&safe_path, &path) {
                if is_local_path(&rel) {
                    return true;
                }
            }
        }
        false
    }

    pub fn safe_paths(&self) -> Vec<String> {
        let mut paths = vec![self.home_dir()];
        paths.extend(self.safe_paths.iter().cloned());
        paths
    }

    pub fn err_not_safe_path(&self, path: &str) -> ErrNotSafePath {
        ErrNotSafePath { path: path.to_owned(), safe_paths: self.safe_paths() }
    }

    pub fn get_path_by_hash(&self, prefix: &str, name: &str) -> String {
        let hash = make_hash(name.as_bytes());
        let filename = hash.string();
        join_path(&[&self.home_dir(), prefix, &filename])
    }

    pub fn mmdb(&self) -> String {
        let home_dir = self.home_dir();
        let Some(files) = read_dir_names(&home_dir) else {
            return String::new();
        };
        for name in files {
            if name.eq_ignore_ascii_case("Country.mmdb")
                || name.eq_ignore_ascii_case("geoip.db")
                || name.eq_ignore_ascii_case("geoip.metadb")
            {
                (*GEOIP_NAME.write()).clone_from(&name);
                return join_path(&[&home_dir, &name]);
            }
        }
        join_path(&[&home_dir, "geoip.metadb"])
    }

    pub fn asn(&self) -> String {
        let home_dir = self.home_dir();
        let Some(files) = read_dir_names(&home_dir) else {
            return String::new();
        };
        for name in files {
            if name.eq_ignore_ascii_case("ASN.mmdb") {
                (*ASN_NAME.write()).clone_from(&name);
                return join_path(&[&home_dir, &name]);
            }
        }
        join_path(&[&home_dir, &ASN_NAME.read()])
    }

    pub fn bundle_mrs(&self) -> String {
        let home_dir = self.home_dir();
        let Some(files) = read_dir_names(&home_dir) else {
            return String::new();
        };
        for name in files {
            if name.eq_ignore_ascii_case("BundleMRS.7z") {
                (*BUNDLE_MRS_NAME.write()).clone_from(&name);
                return join_path(&[&home_dir, &name]);
            }
        }
        join_path(&[&home_dir, &BUNDLE_MRS_NAME.read()])
    }

    pub fn old_cache(&self) -> String {
        join_path(&[&self.home_dir(), ".cache"])
    }

    pub fn cache(&self) -> String {
        join_path(&[&self.home_dir(), "cache.db"])
    }

    pub fn geo_ip(&self) -> String {
        let home_dir = self.home_dir();
        let Some(files) = read_dir_names(&home_dir) else {
            return String::new();
        };
        for name in files {
            if name.eq_ignore_ascii_case("GeoIP.dat") {
                (*GEOIP_NAME.write()).clone_from(&name);
                return join_path(&[&home_dir, &name]);
            }
        }
        join_path(&[&home_dir, "GeoIP.dat"])
    }

    pub fn geo_site(&self) -> String {
        let home_dir = self.home_dir();
        let Some(files) = read_dir_names(&home_dir) else {
            return String::new();
        };
        for name in files {
            if name.eq_ignore_ascii_case("GeoSite.dat") {
                (*GEOSITE_NAME.write()).clone_from(&name);
                return join_path(&[&home_dir, &name]);
            }
        }
        join_path(&[&home_dir, "GeoSite.dat"])
    }

    pub fn get_asset_location(&self, file: &str) -> String {
        join_path(&[&self.home_dir(), file])
    }

    pub fn get_executable_full_path(&self) -> String {
        let Ok(exe_path) = std::env::current_exe() else {
            return "murmur".to_owned();
        };
        std::fs::canonicalize(exe_path).map(|res| res.to_string_lossy().into_owned()).unwrap_or_default()
    }
}

/// Resolves the user's home directory: Unix (and this build's other non-Windows targets) reads
/// `$HOME`, Windows reads `%USERPROFILE%`; Android and iOS fall back to a fixed path when the
/// variable is unset or empty. A Plan 9-style `$home` fallback is omitted: this crate has no Plan 9
/// target.
#[cfg_attr(test, allow(dead_code))] // only called from PATH's `#[cfg(not(test))]` init branch; dead in test builds, which use `test_home_dir` instead
fn user_home_dir() -> std::result::Result<String, String> {
    user_home_dir_with(|key| std::env::var(key).ok())
}

fn user_home_dir_with(getenv: impl Fn(&str) -> Option<String>) -> std::result::Result<String, String> {
    let (env, enverr) = if cfg!(windows) { ("USERPROFILE", "%userprofile%") } else { ("HOME", "$HOME") };
    if let Some(value) = getenv(env) {
        if !value.is_empty() {
            return Ok(value);
        }
    }
    if cfg!(target_os = "android") {
        return Ok("/sdcard".to_owned());
    }
    if cfg!(target_os = "ios") {
        return Ok("/".to_owned());
    }
    Err(format!("{enverr} is not defined"))
}

/// Test-only home root: a private, per-process temporary directory pre-populated with the same
/// `.config/<NAME>` layout `PATH`'s init closure joins onto it, so `cargo test` never opens the
/// real `$HOME/.config/murmur/cache.db` (every concurrently running test binary on the same host
/// would otherwise fight over that one file's lock) and never leaves files under the real home or
/// inside the repository checkout. `PATH` realizes this once per process (`LazyLock`), matching
/// the "once per process" requirement directly.
#[cfg(test)]
fn test_home_dir() -> String {
    static TEST_HOME: LazyLock<String> = LazyLock::new(|| {
        let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_nanos();
        let root = std::env::temp_dir().join(format!("murmur-test-{}-{nanos}", std::process::id()));
        std::fs::create_dir_all(root.join(".config").join(NAME)).expect("create per-process test home directory");
        root.to_string_lossy().into_owned()
    });
    TEST_HOME.clone()
}

/// Parses a boolean; the caller discards the error, so an unparsable value is `false`.
fn parse_bool(value: &str) -> bool {
    matches!(value, "1" | "t" | "T" | "TRUE" | "true" | "True")
}

/// Splits a `PATH`-style list, yielding nothing for an empty value. The list separator is `:` on
/// Unix and `;` on Windows; Windows additionally preserves `;` inside a double-quoted run and
/// strips the quotes from each element afterwards.
#[cfg(windows)]
fn split_list(value: &str) -> Vec<String> {
    if value.is_empty() {
        return Vec::new();
    }
    let mut list = Vec::new();
    let mut start = 0;
    let mut quoted = false;
    for (i, c) in value.char_indices() {
        match c {
            '"' => quoted = !quoted,
            ';' if !quoted => {
                list.push(value.get(start..i).unwrap_or_default().replace('"', ""));
                start = i + 1;
            }
            _ => {}
        }
    }
    list.push(value.get(start..).unwrap_or_default().replace('"', ""));
    list
}
#[cfg(not(windows))]
fn split_list(value: &str) -> Vec<String> {
    if value.is_empty() {
        return Vec::new();
    }
    value.split(':').map(str::to_owned).collect()
}

/// Whether the path is absolute. Unix only recognises a leading `/`; Windows additionally
/// recognises a drive-letter (`C:\`) or UNC (`\\host\share`) prefix, which `Path::is_absolute`
/// already implements per-platform, so Windows delegates to it instead of hand-rolling
/// volume-name parsing.
#[cfg(windows)]
fn is_abs_path(path: &str) -> bool {
    std::path::Path::new(path).is_absolute()
}
#[cfg(not(windows))]
fn is_abs_path(path: &str) -> bool {
    path.starts_with('/')
}

/// Windows accepts both `\` and `/` as path separators; the byte-level helpers in this file
/// (`clean_path`, `rel_path`, `is_local_path`) only recognise `/`, so any
/// `\`-separated input (native Windows paths, `PathBuf`-joined test paths, `SAFE_PATHS` entries)
/// is normalised to `/` before it reaches them. A no-op elsewhere: `\` is an ordinary filename
/// character on Unix, not a separator. `\\?\` and `\\.\` DOS device-path prefixes are passed to
/// Win32 verbatim (per Microsoft's path-format docs, only the canonical backslash form suppresses
/// normalisation), so they are left untouched rather than rewritten into a form Win32 would
/// silently re-normalise and lose the `MAX_PATH` exemption for.
#[cfg(windows)]
fn normalize_separators(path: &str) -> String {
    if path.starts_with(r"\\?\") || path.starts_with(r"\\.\") {
        return path.to_owned();
    }
    path.replace('\\', "/")
}
#[cfg(not(windows))]
fn normalize_separators(path: &str) -> String {
    path.to_owned()
}

/// Windows folds case when comparing path elements; Unix compares bytes exactly.
#[cfg(windows)]
fn same_word(a: &str, b: &str) -> bool {
    a.to_lowercase() == b.to_lowercase()
}
#[cfg(not(windows))]
fn same_word(a: &str, b: &str) -> bool {
    a == b
}

/// Volume-name length, restricted to the drive-letter (`C:`) and UNC (`//host/share`, already
/// `/`-normalised by `normalize_separators`) prefixes; `\\?\`/`\\.\` device paths keep their
/// backslashes per `normalize_separators`'s own carve-out and so never reach here as `/`-led input,
/// matching this file's existing scope limit for those forms. Returns 0 on non-Windows.
#[cfg(windows)]
fn volume_name_len(path: &str) -> usize {
    let bytes = path.as_bytes();
    if bytes.get(1) == Some(&b':') {
        return 2;
    }
    if bytes.first() != Some(&b'/') {
        return 0;
    }
    if bytes.get(1) == Some(&b'/') {
        return unc_len(path, 2);
    }
    0
}
#[cfg(not(windows))]
fn volume_name_len(_path: &str) -> usize {
    0
}

#[cfg(windows)]
fn unc_len(path: &str, prefix_len: usize) -> usize {
    let bytes = path.as_bytes();
    let mut count = 0;
    let mut i = prefix_len;
    while i < bytes.len() {
        if bytes.get(i) == Some(&b'/') {
            count += 1;
            if count == 2 {
                return i;
            }
        }
        i += 1;
    }
    bytes.len()
}

/// The Windows join: unlike the Unix variant below, it strips leading separators from the next
/// element once the buffer already ends in one, and does not add a separator after an element
/// ending in `:` (so a drive-relative join like `join_path(&["C:", "f"])` stays `"C:f"`, not
/// `"C:/f"`). Without this, a root first element (`join_path(&["/", "x"])`) turns into a UNC path
/// (`"//x"`) once the final clean preserves rather than collapses a doubled leading separator. The
/// `\??\` Root Local Device special-case is out of this file's scope (see `volume_name_len`'s doc
/// comment) and is skipped.
#[cfg(windows)]
fn join_path(elem: &[&str]) -> String {
    let mut buf = String::new();
    let mut last_char: Option<u8> = None;
    for &item in elem {
        let mut e = item;
        if buf.is_empty() {
            // first non-empty element is added unchanged below
        } else if last_char == Some(b'/') {
            e = e.trim_start_matches('/');
        } else if last_char == Some(b':') {
            // path ends in a drive-relative ':': no separator, keep e (and its leading '/', if
            // any) verbatim
        } else {
            buf.push('/');
            last_char = Some(b'/');
        }
        if !e.is_empty() {
            buf.push_str(e);
            last_char = e.as_bytes().last().copied();
        }
    }
    if buf.is_empty() {
        return String::new();
    }
    clean_path_native(&buf)
}

/// The Unix join: join the elements with `/`, then clean.
#[cfg(not(windows))]
fn join_path(elem: &[&str]) -> String {
    let size: usize = elem.iter().map(|e| e.len()).sum();
    if size == 0 {
        return String::new();
    }
    let mut buf = String::with_capacity(size + elem.len().saturating_sub(1));
    for e in elem {
        if !buf.is_empty() || !e.is_empty() {
            if !buf.is_empty() {
                buf.push('/');
            }
            buf.push_str(e);
        }
    }
    clean_path_native(&buf)
}

/// Joins `external-ui-name` onto the UI directory for the UI updater.
///
/// DEVIATION: a `/`-only join would let a name such as `a\b/../..` pass the locality check
/// `parse_controller` applies yet climb out of the base, and a UNC base would lose its volume.
/// Folding the name's separators and using the volume-aware join (see `join_path`) keeps every name
/// the check accepted under the base. On Unix the two joins are the same.
#[must_use]
pub fn join_ui_path(base: &str, name: &str) -> String {
    join_path(&[base, &normalize_separators(name)])
}

/// The lexical-cleaning loop shared by `clean_path` and the Windows volume-aware
/// `clean_path_windows`: both clean a volume-free path the same way, and only differ in how they
/// special-case an empty result and a leading volume.
fn clean_core(path: &str) -> Vec<u8> {
    let rooted = path.starts_with('/');

    let bytes = path.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let (mut rest, mut dotdot) = if rooted {
        out.push(b'/');
        (bytes.split_at(1).1, 1usize)
    } else {
        (bytes, 0usize)
    };

    while let Some(&c) = rest.first() {
        if c == b'/' || (c == b'.' && (rest.len() == 1 || rest.get(1) == Some(&b'/'))) {
            rest = rest.split_at(1).1;
        } else if rest.starts_with(b"..") && (rest.len() == 2 || rest.get(2) == Some(&b'/')) {
            rest = rest.split_at(2).1;
            if out.len() > dotdot {
                // Rewind past the separator too: `a/b/..` is `a`, not `a/`.
                while let Some(c) = out.pop() {
                    if out.len() <= dotdot || c == b'/' {
                        break;
                    }
                }
            } else if !rooted {
                if !out.is_empty() {
                    out.push(b'/');
                }
                out.push(b'.');
                out.push(b'.');
                dotdot = out.len();
            }
        } else {
            if (rooted && out.len() != 1) || (!rooted && !out.is_empty()) {
                out.push(b'/');
            }
            let (word, tail) = match rest.iter().position(|&b| b == b'/') {
                Some(i) => rest.split_at(i),
                None => (rest, &[][..]),
            };
            out.extend_from_slice(word);
            rest = tail;
        }
    }
    out
}

#[must_use]
pub fn clean_path(path: &str) -> String {
    if path.is_empty() {
        return ".".to_owned();
    }
    let out = clean_core(path);
    if out.is_empty() {
        return ".".to_owned();
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// The Windows lexical clean, restricted like `volume_name_len` to the drive-letter and UNC
/// prefixes this file's `/`-normalised inputs can carry. Unlike `clean_path`, the volume prefix
/// (`path[..vol_len]`) is kept byte-for-byte and the lexical clean only runs on the remainder, so a
/// slice at `vol_len` into the cleaned result always lands on the same boundary it did in the raw
/// input.
#[cfg(windows)]
fn clean_path_windows(path: &str) -> String {
    let vol_len = volume_name_len(path);
    let rest = path.get(vol_len..).unwrap_or_default();
    if rest.is_empty() {
        let bytes = path.as_bytes();
        if vol_len > 1 && matches!(bytes, [b'/', b'/', ..]) {
            return path.to_owned();
        }
        return format!("{path}.");
    }

    let mut cleaned_rest = clean_core(rest);
    if cleaned_rest.is_empty() {
        cleaned_rest.push(b'.');
    }
    // The guard is "cleaning never had to diverge from the original bytes it was reading", a
    // byte-prefix relationship (cleaning can still legitimately drop a trailing separator or `.`
    // element), not byte-for-byte equality with the whole remainder.
    if vol_len == 0 && !rest.as_bytes().starts_with(&cleaned_rest) {
        for &b in &cleaned_rest {
            if b == b'/' {
                break;
            }
            if b == b':' {
                cleaned_rest.splice(0..0, *b"./");
                break;
            }
        }
    }
    format!("{}{}", path.get(..vol_len).unwrap_or(path), String::from_utf8_lossy(&cleaned_rest))
}

/// The platform-appropriate clean this file's public helpers (`join_path`, `rel_path`) run on
/// Windows-facing paths: `clean_path` elsewhere, `clean_path_windows` on Windows so a volume prefix
/// is preserved rather than mangled by `clean_path`'s `//`-collapsing.
#[cfg(windows)]
fn clean_path_native(path: &str) -> String {
    clean_path_windows(path)
}
#[cfg(not(windows))]
fn clean_path_native(path: &str) -> String {
    clean_path(path)
}

/// The relative-path computation, failing only when the two paths cannot be compared.
fn rel_path(basepath: &str, targpath: &str) -> Result<String> {
    let base_vol_len = volume_name_len(basepath);
    let targ_vol_len = volume_name_len(targpath);
    let base_vol = basepath.get(..base_vol_len).unwrap_or(basepath);
    let targ_vol = targpath.get(..targ_vol_len).unwrap_or(targpath);
    let base = clean_path_native(basepath);
    let targ = clean_path_native(targpath);
    if same_word(&targ, &base) {
        return Ok(".".to_owned());
    }
    let base = base.get(base_vol_len.min(base.len())..).unwrap_or_default();
    let targ = targ.get(targ_vol_len.min(targ.len())..).unwrap_or_default();
    let base = if base == "." {
        String::new()
    } else if base.is_empty() && volume_name_len(base_vol) > 2 {
        "/".to_owned()
    } else {
        base.to_owned()
    };

    let base_slashed = base.starts_with('/');
    let targ_slashed = targ.starts_with('/');
    if base_slashed != targ_slashed || !same_word(base_vol, targ_vol) {
        return Err(anyhow!("Rel: can't make {targpath} relative to {basepath}"));
    }

    let base: Vec<char> = base.chars().collect();
    let targ: Vec<char> = targ.chars().collect();
    let bl = base.len();
    let tl = targ.len();
    let (mut b0, mut bi, mut t0, mut ti) = (0usize, 0usize, 0usize, 0usize);
    loop {
        // The reference relative-path walk spins forever when both cursors reach this state: once
        // they are exhausted the trailing `same_word("", "")` compare is always true, so the loop
        // keeps re-comparing two empty slices without ever advancing. Two fully consumed paths with
        // no mismatch found means the remainders are equal, i.e. the same directory, so this
        // deliberately diverges and fails closed by returning `.` instead of spinning.
        if b0 == bl && t0 == tl {
            return Ok(".".to_owned());
        }
        while bi < bl && base.get(bi) != Some(&'/') {
            bi += 1;
        }
        while ti < tl && targ.get(ti) != Some(&'/') {
            ti += 1;
        }
        let base_word: String = base.get(b0..bi).unwrap_or_default().iter().collect();
        let targ_word: String = targ.get(t0..ti).unwrap_or_default().iter().collect();
        if !same_word(&targ_word, &base_word) {
            break;
        }
        if bi < bl {
            bi += 1;
        }
        if ti < tl {
            ti += 1;
        }
        b0 = bi;
        t0 = ti;
    }

    if base.get(b0..bi).is_some_and(|word| word == ['.', '.']) {
        return Err(anyhow!("Rel: can't make {targpath} relative to {basepath}"));
    }
    if b0 != bl {
        let seps = base.get(b0..bl).unwrap_or_default().iter().filter(|c| **c == '/').count();
        let mut buf = String::new();
        buf.push_str("..");
        for _ in 0..seps {
            buf.push('/');
            buf.push_str("..");
        }
        if t0 != tl {
            buf.push('/');
            buf.extend(targ.get(t0..).unwrap_or_default());
        }
        return Ok(buf);
    }
    Ok(targ.get(t0..).unwrap_or_default().iter().collect())
}

/// Whether the path is local.
///
/// The leading-separator check runs on the raw, un-normalised input:
/// Windows treats `\\?\...`/`\\.\...` device paths and `\\host\share` UNC roots as
/// separator-led too, and `normalize_separators` deliberately leaves the `\\?\`/`\\.\`
/// prefixes untouched, so checking only after normalising would miss them. `normalize_separators`
/// still folds `\` to `/` before the remaining lexical checks so the same body works on both
/// platforms.
#[must_use]
pub fn is_local_path(path: &str) -> bool {
    let Some(&first) = path.as_bytes().first() else {
        return false;
    };
    #[cfg(windows)]
    let rooted = first == b'\\' || first == b'/';
    #[cfg(not(windows))]
    let rooted = first == b'/';
    if rooted {
        return false;
    }
    #[cfg(windows)]
    if path.contains(':') {
        return false;
    }
    let normalized = normalize_separators(path);
    let mut has_dots = false;
    for part in normalized.split('/') {
        if part == "." || part == ".." {
            has_dots = true;
        }
        #[cfg(windows)]
        if is_reserved_name(part) {
            return false;
        }
    }
    let cleaned = if has_dots { clean_path(&normalized) } else { normalized };
    !(cleaned == ".." || cleaned.starts_with("../"))
}

/// Whether the name is a reserved Windows device name.
///
/// A reserved name followed by an extension
/// (`CON.txt`) is also reserved on Windows 11 via the `RtlIsDosDeviceName_U` syscall, which this
/// crate does not link since `unsafe_code` is denied crate-wide; treating any name sharing a
/// reserved device's base as reserved on every Windows version is the fail-closed choice that gap
/// leaves.
#[cfg(windows)]
#[must_use]
pub fn is_reserved_name(name: &str) -> bool {
    let base = match name.find(['.', ':']) {
        Some(idx) => name.get(..idx).unwrap_or(name),
        None => name,
    };
    let base = base.trim_end_matches(' ');
    if base.len() == 3 && matches!(base.to_ascii_uppercase().as_str(), "CON" | "PRN" | "AUX" | "NUL") {
        return true;
    }
    if base.len() >= 4 && base.is_char_boundary(3) {
        let prefix = base.get(..3).unwrap_or_default().to_ascii_uppercase();
        if prefix == "COM" || prefix == "LPT" {
            let suffix = base.get(3..).unwrap_or_default();
            let is_digit_suffix =
                suffix.len() == 1 && suffix.as_bytes().first().is_some_and(|d| (b'1'..=b'9').contains(d));
            if is_digit_suffix || matches!(suffix, "\u{b2}" | "\u{b3}" | "\u{b9}") {
                return true;
            }
        }
    }
    base.eq_ignore_ascii_case("CONIN$") || base.eq_ignore_ascii_case("CONOUT$")
}

/// Reads a directory's entry names, sorted by filename.
fn read_dir_names(home_dir: &str) -> Option<Vec<String>> {
    let entries = std::fs::read_dir(home_dir).ok()?;
    let mut names = Vec::new();
    for entry in entries.flatten() {
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        if file_type.is_dir() {
            continue;
        }
        names.push(entry.file_name().to_string_lossy().into_owned());
    }
    names.sort();
    Some(names)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn new_path(home_dir: &str, safe_paths: &[&str]) -> Path {
        Path {
            home_dir: RwLock::new(home_dir.to_owned()),
            config_file: RwLock::new("config.yaml".to_owned()),
            unsafe_path_allowed: false,
            safe_paths: safe_paths.iter().map(|p| (*p).to_owned()).collect(),
        }
    }

    #[test]
    fn clean_path_drops_the_separator_when_rewinding_dotdot() {
        // Expected values follow the lexical clean-path rules for these inputs.
        for (input, want) in [
            ("a/b/..", "a"),
            ("a/b/../c", "a/c"),
            ("/a/b/..", "/a"),
            ("x/yz/../w", "x/w"),
            ("../a/b/..", "../a"),
            ("//a//b/./../c/", "/a/c"),
            ("./a/b/c/../../d", "a/d"),
            ("/a/b/c/../../..", "/"),
            ("a/b/../../..", ".."),
        ] {
            assert_eq!(clean_path(input), want, "clean_path({input:?})");
        }
    }

    #[test]
    fn is_safe_path_only_accepts_subpaths_of_the_home_directory_or_safe_paths() {
        if cfg!(feature = "cmfa") {
            // `cmfa` makes `is_safe_path` short-circuit to `true` unconditionally (mirrors the
            // `p.allowUnsafePath || features.CMFA`); the path-relative assertions below assume
            // that check is off, so under `--all-features` (which turns `cmfa` on) this is the
            // one observable contract left to check.
            assert!(new_path("", &[]).is_safe_path("/usr/share/murmur-ui/"));
            return;
        }

        assert!(!new_path("", &[]).is_safe_path("/usr/share/murmur-ui/"));
        assert!(new_path("", &["/usr/share/murmur-ui"]).is_safe_path("/usr/share/murmur-ui/"));

        assert!(!new_path("", &[]).is_safe_path("../murmur-ui/"));
        assert!(new_path("/usr/share/murmur", &["/usr/share/murmur-ui"]).is_safe_path("../murmur-ui/"));
        assert!(!new_path("/usr/share/murmur", &["/usr/share/ycad"]).is_safe_path("../murmur-ui/"));

        assert!(!new_path("", &[]).is_safe_path("/opt/mykeys/key1.key"));
        assert!(new_path("", &["/opt/mykeys"]).is_safe_path("/opt/mykeys/key1.key"));
        assert!(new_path("", &["/opt/mykeys/"]).is_safe_path("/opt/mykeys/key1.key"));
        assert!(new_path("", &["/opt/mykeys/key1.key"]).is_safe_path("/opt/mykeys/key1.key"));

        assert!(new_path("", &[]).is_safe_path("key1.key"));
        assert!(new_path("", &[]).is_safe_path("./key1.key"));
        assert!(new_path("", &[]).is_safe_path("./mykey/key1.key"));
        assert!(new_path("", &[]).is_safe_path("./mykey/../key1.key"));
        assert!(!new_path("", &[]).is_safe_path("./mykey/../../key1.key"));
    }

    /// Different drive letters are incomparable (fail closed) and drive-letter case is folded
    /// (`c:` and `C:` are the same volume); `rel_path` is only volume-aware on Windows
    /// (`volume_name_len` is a no-op elsewhere), so this only applies there.
    #[cfg(windows)]
    #[test]
    fn rel_path_rejects_paths_on_different_drive_letters() {
        assert!(rel_path("C:/Users/foo", "D:/Users/bar").is_err());
        assert_eq!(rel_path("c:/Users/foo", "C:/Users/foo/bar").unwrap(), "bar");
    }

    /// The relative-path and clean helpers are volume-aware on Windows, unlike `clean_path`'s
    /// `/`-only cleaning; the UNC cases below pin that: `rel_path("//h/s", "//h/s/x")` = `"x"`,
    /// joining a `//nas/share/murmur` base keeps its volume, and `clean_path_native("C:/../aé")` =
    /// `C:/aé` (no panic).
    #[cfg(windows)]
    #[test]
    fn rel_path_and_clean_path_are_volume_aware_on_unc_and_drive_paths() {
        assert_eq!(rel_path("//h/s", "//h/s/x").unwrap(), "x");

        assert!(new_path("//nas/share/murmur", &[]).is_safe_path("a.yaml"));

        assert_eq!(clean_path_native("C:/../aé"), "C:/aé");
        assert_eq!(rel_path("C:/home", "C:/../aé").unwrap(), "../aé");
    }

    /// `clean_path_windows`'s post-clean guard fires only when cleaning had to diverge from the
    /// original bytes, not merely when it drops a trailing separator or `.` element: `"ab:/"` and
    /// `"ab:/."` both give `"ab:"`, not `".\ab:"`. `ab:` is not a drive-letter volume (the colon
    /// isn't at byte index 1), so this exercises the `vol_len == 0` guard directly.
    #[cfg(windows)]
    #[test]
    fn clean_path_windows_only_guards_leading_colons_it_actually_introduced() {
        assert_eq!(clean_path_native("ab:/"), "ab:");
        assert_eq!(clean_path_native("ab:/."), "ab:");
        assert_eq!(rel_path("ab:/", "ab:/x").unwrap(), "x");
    }

    /// The Windows join strips leading separators from the next element once the buffer already
    /// ends in one, so joining a bare root with more elements does not turn into a UNC path
    /// (translating `\` to `/`, this build's separator): `join_path(&["/", "x"])` = `"/x"`,
    /// `join_path(&["/", ".config", "murmur"])` = `"/.config/murmur"`, `join_path(&["C:", "f"])` =
    /// `"C:f"`, and `join_path(&["C:", "/f"])` = `"C:/f"`.
    #[cfg(windows)]
    #[test]
    fn join_path_does_not_turn_a_root_first_element_into_a_unc_path() {
        assert_eq!(join_path(&["/", "x"]), "/x");
        assert_eq!(join_path(&["/", ".config", "murmur"]), "/.config/murmur");
        assert_eq!(join_path(&["C:", "f"]), "C:f");
        assert_eq!(join_path(&["C:", "/f"]), "C:/f");
    }

    /// The reference relative-path walk hangs forever on `Rel("//nas/share", "//nas/share/")`
    /// because once both element cursors are exhausted the trailing empty-slice compare is always
    /// true and the loop never advances. `rel_path` deliberately diverges: exhausted cursors mean
    /// the remainders are equal (the same directory), so it fails closed by returning `.` instead
    /// of hanging.
    #[cfg(windows)]
    #[test]
    fn rel_path_does_not_hang_on_a_share_root_versus_its_trailing_slash() {
        assert_eq!(rel_path("//nas/share", "//nas/share/").unwrap(), ".");
    }

    #[test]
    fn is_local_path_rejects_absolute_and_dotdot_paths_on_every_platform() {
        assert!(is_local_path("assets/logo.png"));
        assert!(is_local_path("a/../b"));
        assert!(!is_local_path(""));
        assert!(!is_local_path("/etc/passwd"));
        assert!(!is_local_path(".."));
        assert!(!is_local_path("../../etc/passwd"));
        assert!(!is_local_path("a/../../etc/passwd"));
    }

    /// A `\`-separated `..` escape, a drive-relative name, a UNC root and a reserved device name
    /// are all non-local, where the pre-fix `config::config::is_local_path` (POSIX-only, `/`-split)
    /// let every one of these through because it never recognised `\` as a separator.
    #[cfg(windows)]
    #[test]
    fn is_local_path_rejects_windows_specific_escapes() {
        assert!(!is_local_path(r"..\..\..\Users\foo\AppData\Roaming\Startup"));
        assert!(!is_local_path(r"C:\Users\foo"));
        assert!(!is_local_path(r"\\host\share\x"));
        assert!(!is_local_path("a:b"));
        assert!(!is_local_path("CON"));
        assert!(!is_local_path(r"a\CON\b"));
        assert!(!is_local_path("COM1"));
        assert!(is_local_path(r"assets\logo.png"));
    }

    /// `\\?\` and `\\.\` device-path prefixes are `normalize_separators`' one deliberate carve-out
    /// (left untouched rather than folded to `/`), so a leading-separator check that only runs
    /// after normalising missed them; this checks the raw first byte instead.
    #[cfg(windows)]
    #[test]
    fn is_local_path_rejects_device_and_unc_prefixes() {
        assert!(!is_local_path(r"\\?\C:\Users\foo"));
        assert!(!is_local_path(r"\\.\pipe\x"));
        assert!(!is_local_path(r"\\?\UNC\h\s"));
        assert!(!is_local_path(r"\\?\GLOBALROOT\Device\HarddiskVolume1\x"));
    }

    #[cfg(windows)]
    #[test]
    fn user_home_dir_reads_userprofile_on_windows() {
        assert_eq!(
            user_home_dir_with(|key| (key == "USERPROFILE").then(|| r"C:\Users\test".to_owned())).unwrap(),
            r"C:\Users\test"
        );
        assert_eq!(
            user_home_dir_with(|key| (key == "USERPROFILE").then(String::new)).unwrap_err(),
            "%userprofile% is not defined"
        );
        assert_eq!(user_home_dir_with(|_| None).unwrap_err(), "%userprofile% is not defined");
    }

    #[cfg(not(windows))]
    #[test]
    fn user_home_dir_reads_home_on_unix() {
        assert_eq!(user_home_dir_with(|key| (key == "HOME").then(|| "/home/test".to_owned())).unwrap(), "/home/test");

        let empty = user_home_dir_with(|key| (key == "HOME").then(String::new));
        if cfg!(target_os = "android") {
            assert_eq!(empty.unwrap(), "/sdcard");
        } else if cfg!(target_os = "ios") {
            assert_eq!(empty.unwrap(), "/");
        } else {
            assert_eq!(empty.unwrap_err(), "$HOME is not defined");
        }

        let unset = user_home_dir_with(|_| None);
        if cfg!(target_os = "android") {
            assert_eq!(unset.unwrap(), "/sdcard");
        } else if cfg!(target_os = "ios") {
            assert_eq!(unset.unwrap(), "/");
        } else {
            assert_eq!(unset.unwrap_err(), "$HOME is not defined");
        }
    }
}
