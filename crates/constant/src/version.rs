pub static META: bool = true;

pub static VERSION: &str = "1.10.0";

pub static BUILD_TIME: &str = "unknown time";

pub static PROJECT_NAME: &str = "murmur";

/// User agent this project identifies itself with where a client string is required.
pub static USER_AGENT: &str = concat!("murmur/", env!("CARGO_PKG_VERSION"));
