use std::io;

#[derive(Clone, Debug)]
pub(crate) struct ErrInfo {
    kind: io::ErrorKind,
    msg: String,
}

impl ErrInfo {
    pub(crate) fn from_io(err: &io::Error) -> Self {
        Self { kind: err.kind(), msg: err.to_string() }
    }

    pub(crate) fn to_io(&self) -> io::Error {
        io::Error::new(self.kind, self.msg.clone())
    }
}

pub(crate) fn err_invalid_version() -> io::Error {
    io::Error::other("invalid protocol version")
}

pub(crate) fn err_invalid_msg_type() -> io::Error {
    io::Error::other("invalid msg type")
}

pub(crate) fn err_streams_exhausted() -> io::Error {
    io::Error::other("streams exhausted")
}

pub(crate) fn err_duplicate_stream() -> io::Error {
    io::Error::other("duplicate stream initiated")
}

pub(crate) fn err_recv_window_exceeded(remain: u32, recv: u32) -> io::Error {
    io::Error::other(format!("receive window exceeded (remain: {remain}, recv: {recv})"))
}

pub(crate) fn err_timeout() -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, "i/o deadline reached")
}

pub(crate) fn err_stream_closed() -> io::Error {
    io::Error::other("stream closed")
}

pub(crate) fn err_stream_reset() -> io::Error {
    io::Error::other("stream reset")
}

pub(crate) fn err_connection_write_timeout() -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, "connection write timeout")
}

pub(crate) fn err_keepalive_timeout() -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, "keepalive timeout")
}

pub(crate) fn err_session_shutdown() -> io::Error {
    go_away_error(crate::frame::GO_AWAY_NORMAL, false)
}

pub(crate) fn go_away_error(code: u32, remote: bool) -> io::Error {
    if remote {
        io::Error::other(format!("remote sent go away, code: {code}"))
    } else {
        io::Error::other(format!("sent go away, code: {code}"))
    }
}

pub(crate) fn stream_error(code: u32, remote: bool) -> io::Error {
    if remote {
        io::Error::other(format!("stream reset by remote, error code: {code}"))
    } else {
        io::Error::other(format!("stream reset, error code: {code}"))
    }
}
