use std::io;
use std::sync::Arc;

use rand::Rng;

use super::auth::Aead;
use super::header::PacketHeader;
use super::listener::IoWriter;
use super::segment::{read_segment, Segment};

const MAX_NONCE_SIZE: usize = 32;

pub(crate) struct PacketReader {
    pub(crate) security: Option<Arc<dyn Aead>>,
    pub(crate) header: Option<Box<dyn PacketHeader>>,
}

impl PacketReader {
    pub(crate) fn read(&self, b: &[u8]) -> Vec<Segment> {
        let mut b = b;
        if let Some(header) = &self.header {
            let header_size = header.size();
            if b.len() <= header_size {
                return Vec::new();
            }
            b = b.get(header_size..).unwrap_or_default();
        }

        let mut decrypted = Vec::new();
        if let Some(security) = &self.security {
            let nonce_size = security.nonce_size();
            let overhead = security.overhead();
            if b.len() <= nonce_size + overhead {
                return Vec::new();
            }
            let Some((nonce, body)) = b.split_at_checked(nonce_size) else {
                return Vec::new();
            };
            if security.open(&mut decrypted, nonce, body, &[]).is_err() {
                return Vec::new();
            }
            b = &decrypted;
        }

        let mut segments = Vec::new();
        while !b.is_empty() {
            let Some((seg, extra)) = read_segment(b) else {
                break;
            };
            segments.push(seg);
            b = extra;
        }
        segments
    }
}

pub(crate) struct PacketWriter {
    pub(crate) security: Option<Arc<dyn Aead>>,
    pub(crate) header: Option<Box<dyn PacketHeader>>,
    pub(crate) writer: Box<dyn IoWriter>,
}

impl PacketWriter {
    pub(crate) fn overhead(&self) -> usize {
        let Some(security) = &self.security else {
            return match &self.header {
                Some(header) => header.size(),
                None => 0,
            };
        };
        let mut overhead = security.overhead();
        if let Some(header) = &self.header {
            overhead += header.size();
        }
        overhead
    }

    pub(crate) fn security_overhead(&self) -> usize {
        self.security.as_ref().map_or(0, |security| security.overhead())
    }

    pub(crate) async fn write_segment(&mut self, seg: &Segment) -> io::Result<()> {
        let mut payload = vec![0u8; seg.byte_size()];
        seg.serialize(&mut payload);

        let header_size = match &self.header {
            Some(header) => header.size(),
            None => 0,
        };
        let mut out = Vec::with_capacity(header_size + payload.len() + self.security_overhead() + 3);
        out.resize(header_size, 0);
        if header_size > 0 {
            if let Some(header) = &mut self.header {
                let (head, _) = out.split_at_mut(header_size);
                header.serialize(head);
            }
        }

        match &self.security {
            Some(security) => {
                let nonce_size = security.nonce_size();
                let mut nonce_buf = [0u8; MAX_NONCE_SIZE];
                let Some(nonce) = nonce_buf.get_mut(..nonce_size) else {
                    return Err(io::Error::other("mkcp: unsupported nonce size"));
                };
                rand::rng().fill(nonce);
                out.extend_from_slice(nonce);
                security.seal(&mut out, nonce, &payload, &[]).map_err(io::Error::other)?;
            }
            None => out.extend_from_slice(&payload),
        }

        self.writer.write(&out).await.map(|_| ())
    }
}
