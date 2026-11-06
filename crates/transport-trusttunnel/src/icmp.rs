use std::net::IpAddr;
use std::sync::Arc;

use murmur_compat::sing_buf::new_size;

use super::protocol::{build_padding_ip, parse16_bytes_ip, BodyCursor, HttpConn};

pub struct IcmpConn {
    pub(crate) inner: Arc<HttpConn>,
}

impl std::fmt::Debug for IcmpConn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IcmpConn").finish_non_exhaustive()
    }
}

impl IcmpConn {
    pub(crate) const fn new(inner: Arc<HttpConn>) -> Self {
        Self { inner }
    }

    pub async fn write_ping(
        &self,
        id: u16,
        destination: IpAddr,
        sequence_number: u16,
        ttl: u8,
        size: u16,
    ) -> anyhow::Result<()> {
        let mut request = new_size(2 + 16 + 2 + 1 + 2);
        let result = async {
            request.write_bytes(&id.to_be_bytes())?;
            let destination_address = build_padding_ip(destination);
            request.write_bytes(&destination_address)?;
            request.write_bytes(&sequence_number.to_be_bytes())?;
            request.write_bytes(&ttl.to_be_bytes())?;
            request.write_bytes(&size.to_be_bytes())?;
            let result = self.inner.write_flush(request.bytes()).await;
            result.map(|_| ()).map_err(anyhow::Error::from)
        }
        .await;
        request.release();
        result
    }

    pub async fn read_ping(&self) -> anyhow::Result<(u16, IpAddr, u8, u8, u16)> {
        self.inner.wait_created().await?;
        let mut response = new_size(2 + 16 + 1 + 1 + 2);
        let cap = response.cap();
        let result: anyhow::Result<(u16, IpAddr, u8, u8, u16)> = async {
            response.read_full_from(&mut BodyCursor(&self.inner), cap).await?;
            let id = u16::from_be_bytes(response.read_bytes(2)?.try_into()?);
            let source_address_buffer: [u8; 16] = response.read_bytes(16)?.try_into()?;
            let source_address = parse16_bytes_ip(source_address_buffer);
            let icmp_type = response.read_byte()?;
            let code = response.read_byte()?;
            let sequence_number = u16::from_be_bytes(response.read_bytes(2)?.try_into()?);
            Ok((id, source_address, icmp_type, code, sequence_number))
        }
        .await;
        response.release();
        result
    }

    #[expect(
        clippy::unused_async,
        reason = "kept `async` to match the async conn-close surface the packet and stream conns expose"
    )]
    pub async fn close(&self) -> std::io::Result<()> {
        self.inner.close()
    }

    pub async fn read_ping_request(&self) -> anyhow::Result<(u16, IpAddr, u16, u8, u16)> {
        self.inner.wait_created().await?;
        let mut request = new_size(2 + 16 + 2 + 1 + 2);
        let cap = request.cap();
        let result: anyhow::Result<(u16, IpAddr, u16, u8, u16)> = async {
            request.read_full_from(&mut BodyCursor(&self.inner), cap).await?;
            let id = u16::from_be_bytes(request.read_bytes(2)?.try_into()?);
            let destination_address_buffer: [u8; 16] = request.read_bytes(16)?.try_into()?;
            let destination = parse16_bytes_ip(destination_address_buffer);
            let sequence_number = u16::from_be_bytes(request.read_bytes(2)?.try_into()?);
            let ttl = request.read_byte()?;
            let size = u16::from_be_bytes(request.read_bytes(2)?.try_into()?);
            Ok((id, destination, sequence_number, ttl, size))
        }
        .await;
        request.release();
        result
    }

    pub async fn write_ping_response(
        &self,
        id: u16,
        source_address: IpAddr,
        icmp_type: u8,
        code: u8,
        sequence_number: u16,
    ) -> anyhow::Result<()> {
        let mut response = new_size(2 + 16 + 1 + 1 + 2);
        let result = async {
            response.write_bytes(&id.to_be_bytes())?;
            let source_address_bytes = build_padding_ip(source_address);
            response.write_bytes(&source_address_bytes)?;
            response.write_bytes(&icmp_type.to_be_bytes())?;
            response.write_bytes(&code.to_be_bytes())?;
            response.write_bytes(&sequence_number.to_be_bytes())?;
            let result = self.inner.write_flush(response.bytes()).await;
            result.map(|_| ()).map_err(anyhow::Error::from)
        }
        .await;
        response.release();
        result
    }
}
