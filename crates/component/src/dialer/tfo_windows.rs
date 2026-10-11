use murmur_constant_features as features;

/// The `init` this file holds: according to MSDN, `TCP_FASTOPEN_CONNECT` is available since
/// Windows 10, 1607.
pub(crate) fn disable_tfo() -> bool {
    *features::WINDOWS_MAJOR_VERSION < 10
        || (*features::WINDOWS_MAJOR_VERSION == 10 && *features::WINDOWS_BUILD_NUMBER < 14393)
}
