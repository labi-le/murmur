use std::io;

use murmur_common_net::deadline::pipe::{make_pipe_deadline, PipeDeadline};
use murmur_std_compat::net::deadline_time;

pub(crate) struct PipeDeadlines {
    pub(crate) read: PipeDeadline,
    pub(crate) write: PipeDeadline,
}

pub(crate) fn new_pipe_deadlines() -> PipeDeadlines {
    PipeDeadlines { read: make_pipe_deadline(), write: make_pipe_deadline() }
}

impl PipeDeadlines {
    #[expect(
        clippy::unnecessary_wraps,
        reason = "a pipe deadline write cannot fail; the `Conn` setters that forward this return `io::Result`"
    )]
    pub(crate) fn set_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        let t = deadline_time(deadline);
        self.read.set(t);
        self.write.set(t);
        Ok(())
    }

    #[expect(
        clippy::unnecessary_wraps,
        reason = "a pipe deadline write cannot fail; the `Conn` setters that forward this return `io::Result`"
    )]
    pub(crate) fn set_read_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        self.read.set(deadline_time(deadline));
        Ok(())
    }

    #[expect(
        clippy::unnecessary_wraps,
        reason = "a pipe deadline write cannot fail; the `Conn` setters that forward this return `io::Result`"
    )]
    pub(crate) fn set_write_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        self.write.set(deadline_time(deadline));
        Ok(())
    }
}
