use murmur_constant_features as features;

use super::config::{set_disable_system_ca, CA_CERTIFICATES};

/// Called by [`super::config`] before it builds the certificate pool: there is no package
/// initialiser that would run it automatically.
pub(crate) fn init() {
    // Certificate validation on Windows before version 10 cannot validate an IP address in the
    // subject alternative name, so the system CA store is dropped there.
    if *features::WINDOWS_MAJOR_VERSION < 10 && !CA_CERTIFICATES.is_empty() {
        set_disable_system_ca();
    }
}
