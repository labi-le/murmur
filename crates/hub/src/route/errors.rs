use serde::Serialize;

/// The custom HTTP error type this API returns.
#[derive(Clone, Debug, Serialize)]
pub(crate) struct HttpError {
    pub(crate) message: String,
}

impl std::fmt::Display for HttpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for HttpError {}

impl HttpError {
    pub(crate) fn new(msg: impl Into<String>) -> Self {
        Self { message: msg.into() }
    }
}

pub(crate) fn err_unauthorized() -> HttpError {
    HttpError::new("Unauthorized")
}

pub(crate) fn err_bad_request() -> HttpError {
    HttpError::new("Body invalid")
}

pub(crate) fn err_not_found() -> HttpError {
    HttpError::new("Resource not found")
}

pub(crate) fn err_request_timeout() -> HttpError {
    HttpError::new("Timeout")
}
