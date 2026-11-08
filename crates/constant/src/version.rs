pub static META: bool = true;

pub static VERSION: &str = "1.10.0";

pub static BUILD_TIME: &str = "unknown time";

/// Short hash of the checkout the binary was built from, `unknown` when the build carried no git
/// metadata. `-v` and `/version` report it so two builds of the same `VERSION` stay distinct.
pub static GIT_COMMIT: &str = env!("GIT_COMMIT");

pub static PROJECT_NAME: &str = "murmur";

/// User agent this project identifies itself with where a client string is required.
pub static USER_AGENT: &str = concat!("murmur/", env!("CARGO_PKG_VERSION"));
