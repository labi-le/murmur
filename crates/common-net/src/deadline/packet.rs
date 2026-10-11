use std::any::Any;
use std::fmt;
use std::future::Future;
use std::io;
use std::sync::Arc;

use async_trait::async_trait;
use tokio::time::Instant;

use crate::io::DeadlineToken;
use crate::packet::packet::{ReaderWithUpstream, WithUpstream, WriterWithUpstream};
use murmur_common::atomic::type_::Bool;
use murmur_std_compat::net::{Addr, PacketConn};

use super::conn::err_deadline_exceeded;

pub struct NetPacketConn {
    pub(crate) packet_conn: Arc<dyn PacketConn>,
    pub(crate) has_deadline: Bool,
    pub(crate) deadline_token: DeadlineToken,
    pub(crate) disable_pipe: Bool,
    pub(crate) in_read: Bool,
}

impl fmt::Debug for NetPacketConn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NetPacketConn").finish_non_exhaustive()
    }
}

impl NetPacketConn {
    pub(crate) fn new(packet_conn: Arc<dyn PacketConn>) -> Self {
        Self {
            packet_conn,
            has_deadline: Bool::default(),
            deadline_token: DeadlineToken::new(),
            disable_pipe: Bool::default(),
            in_read: Bool::default(),
        }
    }

    /// the `select` over the pipe deadline, around a read the caller drives.
    pub(crate) async fn with_read_deadline<T, F>(&self, read: F) -> io::Result<T>
    where
        F: Future<Output = io::Result<T>>,
    {
        // NOT cancel-safe: dropping this future drops the caller's read, and the `!has_deadline`
        // branch can leave `in_read` latched.
        if self.disable_pipe.load() {
            return read.await;
        }
        if !self.has_deadline.load() {
            self.in_read.store(true);
            let result = read.await;
            self.in_read.store(false);
            return result;
        }

        let token = self.deadline_token.token();
        if token.is_cancelled() {
            return Err(err_deadline_exceeded());
        }
        tokio::select! {
            result = read => result,
            () = token.cancelled() => Err(err_deadline_exceeded()),
        }
    }

    pub const fn need_additional_read_deadline(&self) -> bool {
        false
    }
}

/// Wraps a packet conn in the deadline layer.
///
/// The caller picks [`crate::deadline::packet_enhance::new_enhance_packet_conn`],
/// [`crate::deadline::packet_sing::new_sing_packet_conn`] or
/// [`crate::deadline::packet_sing::new_enhance_sing_packet_conn`] from the type it holds.
pub fn new_net_packet_conn(pc: Arc<dyn PacketConn>) -> Arc<dyn PacketConn> {
    Arc::new(NetPacketConn::new(pc))
}

#[async_trait]
impl PacketConn for NetPacketConn {
    async fn read_from(&self, p: &mut [u8]) -> io::Result<(usize, Box<dyn Addr>)> {
        self.with_read_deadline(self.packet_conn.read_from(p)).await
    }

    async fn write_to(&self, p: &[u8], addr: &dyn Addr) -> io::Result<usize> {
        self.packet_conn.write_to(p, addr).await
    }

    fn local_addr(&self) -> io::Result<Box<dyn Addr>> {
        self.packet_conn.local_addr()
    }

    fn close(&self) -> io::Result<()> {
        self.packet_conn.close()
    }

    fn set_deadline(&self, deadline: Option<Instant>) -> io::Result<()> {
        self.packet_conn.set_deadline(deadline)
    }

    fn set_write_deadline(&self, deadline: Option<Instant>) -> io::Result<()> {
        self.packet_conn.set_write_deadline(deadline)
    }

    /// Sets the read deadline. Note that, unlike `deadline::conn::Conn`'s
    /// equivalent, this never arms `deadline_token`, so `with_read_deadline`'s race never actually
    /// times out; a pre-existing defect, reported rather than fixed per the refactor contract.
    fn set_read_deadline(&self, deadline: Option<Instant>) -> io::Result<()> {
        if self.disable_pipe.load() {
            return self.packet_conn.set_read_deadline(deadline);
        } else if self.in_read.load() {
            self.disable_pipe.store(true);
            return self.packet_conn.set_read_deadline(deadline);
        }
        self.has_deadline.store(deadline.is_some());
        Ok(())
    }
}

impl WithUpstream for NetPacketConn {
    fn upstream(&self) -> Option<&dyn Any> {
        Some(self.packet_conn.as_ref())
    }
}

impl ReaderWithUpstream for NetPacketConn {
    fn reader_replaceable(&self) -> bool {
        self.disable_pipe.load() || !self.has_deadline.load()
    }
}

impl WriterWithUpstream for NetPacketConn {
    fn writer_replaceable(&self) -> bool {
        true
    }
}
