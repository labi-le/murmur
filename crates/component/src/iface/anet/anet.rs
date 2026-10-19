#[must_use]
pub fn is_force_anet() -> bool {
    match std::env::var("FORCE_ANET") {
        Ok(v) => parse_bool(&v),
        Err(_) => false,
    }
}

/// Parses the env-var boolean; an unrecognised value leaves the variable unset, since the parse
/// error is ignored.
fn parse_bool(s: &str) -> bool {
    matches!(s, "1" | "t" | "T" | "TRUE" | "true" | "True")
}
