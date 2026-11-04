/// Normalizes the configured path root into `"/<segment>"` form.
///
/// It is intentionally strict: only a single path segment is allowed, consisting of
/// `[A-Za-z0-9_-]`. Invalid inputs are treated as empty (disabled).
pub(crate) fn normalize_path_root(root: &str) -> String {
    let root = root.trim();
    let root = root.trim_matches('/');
    if root.is_empty() {
        return String::new();
    }
    for c in root.bytes() {
        match c {
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'_' | b'-' => {}
            _ => return String::new(),
        }
    }
    format!("/{root}")
}

pub(crate) fn join_path_root(root: &str, path: &str) -> String {
    let root = normalize_path_root(root);
    if root.is_empty() {
        return path.to_owned();
    }
    if path.is_empty() {
        return root;
    }
    if path.starts_with('/') {
        format!("{root}{path}")
    } else {
        format!("{root}/{path}")
    }
}

pub(crate) fn strip_path_root(root: &str, full_path: &str) -> (String, bool) {
    let root = normalize_path_root(root);
    if root.is_empty() {
        return (full_path.to_owned(), true);
    }
    let prefix = format!("{root}/");
    if !full_path.starts_with(&prefix) {
        return (String::new(), false);
    }
    let Some(stripped) = full_path.strip_prefix(&root) else {
        return (String::new(), false);
    };
    (stripped.to_owned(), true)
}
