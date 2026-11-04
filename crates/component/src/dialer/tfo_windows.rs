use murmur_constant_features as features;

/// MSDN's IPPROTO_TCP socket options make `TCP_FASTOPEN` available from Windows 10 1607 (build
/// 14393); older builds refuse the option the Windows dialer arm sets.
pub(crate) fn disable_tfo() -> bool {
    *features::WINDOWS_MAJOR_VERSION < 10
        || (*features::WINDOWS_MAJOR_VERSION == 10 && *features::WINDOWS_BUILD_NUMBER < 14393)
}
