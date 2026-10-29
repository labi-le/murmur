//! System wall-clock adjustment on platforms without a supported implementation.

use chrono::{DateTime, Utc};

pub(crate) fn set_system_time(_now_time: DateTime<Utc>) -> std::io::Result<()> {
    Err(std::io::Error::from(std::io::ErrorKind::InvalidInput))
}
